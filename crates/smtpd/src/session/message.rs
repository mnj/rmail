//! DATA and BDAT: reading the message, content checks, scanning, sender
//! authentication (SPF/DKIM/DMARC/ARC) and the final reply.

use anyhow::Result;
use bytes::Bytes;
use rmail_common::config::ScannerFailureAction;
use rmail_common::mail_auth::AuthenticationResults;
use rmail_common::metrics;
use rmail_common::scanner::{ScanAction, ScanEnvelope};
use tokio::io::AsyncWriteExt;

use super::delivery::DeliveryReport;
use super::{Flow, Session, SmtpReader, reply, send, session_log};
use crate::data::{
    DataReadResult, read_exact_chunk, read_smtp_data, received_header, valid_text_message_form,
};
use crate::limits::record_submission_message;
use crate::protocol::{self, MailBody};
use crate::trace::emit_tracking;
use crate::{MAX_MESSAGE_BYTES, SmtpService};

impl Session {
    /// DATA (`bdat` is `None`) or one BDAT chunk.
    pub(super) async fn message(
        &mut self,
        reader: &mut SmtpReader,
        bdat: Option<&str>,
    ) -> Result<Flow> {
        if self.tx.rcpts.is_empty() {
            return reply(reader, b"503 5.5.1 RCPT required before DATA\r\n").await;
        }
        let incoming = match bdat {
            None => {
                if self.tx.bdat_started {
                    return reply(reader, b"503 5.5.1 DATA not permitted after BDAT\r\n").await;
                }
                if self.tx.body == MailBody::BinaryMime {
                    return reply(reader, b"503 5.5.1 BODY=BINARYMIME requires BDAT\r\n").await;
                }
                session_log!(self, "debug", "data_started", { "recipient_count": self.tx.rcpts.len() });
                send(reader, b"354 End data with <CR><LF>.<CR><LF>\r\n").await?;
                read_smtp_data(reader).await?
            }
            Some(args) => match self.bdat_chunk(reader, args).await? {
                Intake::Message(incoming) => incoming,
                Intake::Handled(flow) => return Ok(flow),
            },
        };

        let mut data = match incoming {
            DataReadResult::Complete(data) => match self.check_content(data) {
                Ok(data) => data,
                Err(status) => return self.fail_message(reader, status).await,
            },
            DataReadResult::TooLarge => {
                return self
                    .fail_message(reader, "552 5.3.4 Message size exceeds fixed maximum")
                    .await;
            }
            DataReadResult::LineTooLong => {
                return self
                    .fail_message(reader, "500 5.5.2 Line too long in data")
                    .await;
            }
            DataReadResult::InvalidLineEnding => {
                return self
                    .fail_message(reader, "554 5.6.0 DATA lines must end with CRLF")
                    .await;
            }
            DataReadResult::AmbiguousTerminator => {
                // The bytes after a non-canonical end-of-data sequence may be
                // a smuggled transaction; never parse them as commands.
                session_log!(self, "warn", "data_ambiguous_terminator", { "message_id": self.message_id });
                self.complete_message(
                    reader,
                    "554 5.5.2 Bare CR or LF in end-of-data sequence; closing connection",
                )
                .await?;
                self.abort_transaction();
                return Ok(Flow::Close);
            }
            DataReadResult::Timeout => {
                let writer = reader.get_mut();
                let _ = writer.write_all(b"421 4.4.2 Timeout\r\n").await;
                let _ = writer.flush().await;
                return Ok(Flow::Close);
            }
            DataReadResult::Eof => return Ok(Flow::Close),
        };

        let mut event = self.trace.event(
            self.peer,
            self.message_id.clone(),
            "message",
            "content_received",
        );
        event.detail = Some(format!("{} recipients", self.tx.rcpts.len()));
        emit_tracking(event);

        if self.service == SmtpService::Submission
            && self.security.submission_require_from_alignment
            && !self
                .authenticated_user
                .as_deref()
                .is_some_and(|user| rmail_common::mail_auth::submission_from_matches(&data, user))
        {
            send(
                reader,
                b"553 5.7.1 From address not owned by authenticated user\r\n",
            )
            .await?;
            self.abort_transaction();
            return Ok(Flow::Continue);
        }

        // RFC 4865: a held message is submitted again, as its sender, when
        // its release time comes; scanning and delivery happen then.
        if let Some(release_at) = self.tx.release_at {
            return self.hold_message(reader, data, release_at).await;
        }

        let mut quarantine = false;
        if self.security.scanners_enabled() {
            match self.scan(data.clone()).await {
                Scan::Deliver(scanned) => data = scanned,
                Scan::Quarantine(scanned) => {
                    data = scanned;
                    quarantine = true;
                }
                Scan::Reject(status) => return self.fail_message(reader, status).await,
                Scan::Accept => {}
            }
        }

        metrics::add_bytes_received(data.len() as u64);
        session_log!(self, "info", "message_received", { "message_id": self.message_id, "bytes": data.len(), "recipient_count": self.tx.rcpts.len() });
        let auth = self.authenticate_sender(&data).await;
        if self.service == SmtpService::Mta && self.authenticated_user.is_none() {
            self.report_dmarc(&auth, &data).await;
        }
        if self.enforce_dmarc && auth.dmarc.as_deref() == Some("reject") {
            return self
                .fail_message(reader, "554 5.7.1 Message rejected by DMARC policy")
                .await;
        }

        let report = self.deliver(&data, quarantine, &auth.dmarc).await;
        self.finish_message(reader, &report).await?;
        self.reset_transaction();
        Ok(Flow::Continue)
    }

    /// Read one BDAT chunk; the message is complete after the LAST chunk.
    async fn bdat_chunk(&mut self, reader: &mut SmtpReader, args: &str) -> Result<Intake> {
        let Some(chunk) = protocol::parse_bdat_args(args) else {
            return Ok(Intake::Handled(
                reply(reader, b"501 5.5.2 Syntax: BDAT chunk-size [LAST]\r\n").await?,
            ));
        };
        self.tx.bdat_started = true;
        let retain = self
            .tx
            .bdat_buffer
            .len()
            .checked_add(chunk.size)
            .is_some_and(|total| total <= MAX_MESSAGE_BYTES);
        let Some(bytes) = read_exact_chunk(reader, chunk.size, retain).await? else {
            let writer = reader.get_mut();
            let _ = writer
                .write_all(b"421 4.4.2 Timeout while reading BDAT chunk\r\n")
                .await;
            let _ = writer.flush().await;
            return Ok(Intake::Handled(Flow::Close));
        };
        if !retain {
            // Oversized chunks are drained so the stream stays in sync.
            return Ok(Intake::Handled(
                self.fail_message(reader, "552 5.3.4 Message size exceeds fixed maximum")
                    .await?,
            ));
        }
        self.tx.bdat_buffer.extend_from_slice(&bytes);
        if !chunk.last {
            return Ok(Intake::Handled(
                reply(reader, b"250 2.0.0 BDAT chunk received\r\n").await?,
            ));
        }
        Ok(Intake::Message(DataReadResult::Complete(std::mem::take(
            &mut self.tx.bdat_buffer,
        ))))
    }

    /// Validate the declared body type against the content and prepend the
    /// Received header. Errors carry the rejection status.
    fn check_content(&self, mut data: Vec<u8>) -> std::result::Result<Bytes, &'static str> {
        let body = self.tx.body;
        if self.tx.bdat_started && body != MailBody::BinaryMime && !valid_text_message_form(&data) {
            return Err("554 5.6.0 BDAT content requires canonical CRLF lines or BODY=BINARYMIME");
        }
        if data.contains(&0) && body != MailBody::BinaryMime {
            return Err("554 5.6.3 NUL requires BINARYMIME");
        }
        if body == MailBody::SevenBit && data.iter().any(|byte| !byte.is_ascii()) {
            return Err("554 5.6.3 8-bit content requires BODY=8BITMIME");
        }
        let header_end = data
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map_or(data.len(), |position| position + 4);
        if !self.tx.smtp_utf8 && data[..header_end].iter().any(|byte| !byte.is_ascii()) {
            return Err("554 5.6.7 UTF-8 headers require SMTPUTF8");
        }
        let mut traced = received_header(
            self.peer,
            self.helo_name.as_deref(),
            self.service,
            self.extended_smtp,
            self.encrypted,
            self.authenticated_user.is_some(),
            self.tx.mt_priority,
        );
        traced.append(&mut data);
        Ok(Bytes::from(traced))
    }

    async fn scan(&self, data: Bytes) -> Scan {
        let envelope = ScanEnvelope {
            mail_from: self.tx.mail_from.clone(),
            rcpts: self.tx.rcpts.clone(),
            peer_ip: self.peer.map(|peer| peer.ip()),
            helo: self.helo_name.clone(),
            hostname: self.helo_name.clone(),
            user: self.authenticated_user.clone(),
        };
        match rmail_common::scanner::scan_message(&self.security, data.clone(), &envelope).await {
            Ok(verdict) => match verdict.action {
                ScanAction::Clean if verdict.headers.is_empty() => Scan::Deliver(data),
                ScanAction::Clean => Scan::Deliver(rmail_common::scanner::prepend_scan_headers(
                    data,
                    &verdict.headers,
                )),
                ScanAction::Quarantine => Scan::Quarantine(
                    rmail_common::scanner::prepend_scan_headers(data, &verdict.headers),
                ),
                ScanAction::Defer => {
                    session_log!(self, "info", "message_deferred_by_scanner", { "message_id": self.message_id, "reason": verdict.reason });
                    Scan::Reject("451 4.7.1 Greylisted, please try again later")
                }
                ScanAction::Reject => {
                    session_log!(self, "warn", "message_rejected_by_scanner", { "message_id": self.message_id, "reason": verdict.reason });
                    Scan::Reject("554 5.7.1 Message rejected: malware detected")
                }
            },
            Err(error) => {
                session_log!(self, "error", "scanner_failed", { "message_id": self.message_id, "error": error.to_string() });
                match self.security.scanner_failure_action {
                    ScannerFailureAction::Accept => Scan::Accept,
                    ScannerFailureAction::Reject => {
                        Scan::Reject("554 5.7.1 Message rejected: scanner unavailable")
                    }
                    ScannerFailureAction::Tempfail => {
                        Scan::Reject("451 4.7.1 Message scanner unavailable")
                    }
                }
            }
        }
    }

    /// Record the DMARC result for aggregate reports and, when enabled and
    /// asked for, queue failure reports (RFC 6591).
    async fn report_dmarc(&self, auth: &AuthenticationResults, data: &Bytes) {
        let (Some(db_path), Some(domain)) = (self.db_path.clone(), auth.dmarc_domain.clone())
        else {
            return;
        };
        let event = (
            db_path,
            domain,
            auth.header_from.clone(),
            self.tx.mail_from.clone(),
            self.peer.map(|peer| peer.ip().to_string()),
            auth.dkim.clone(),
            auth.spf.clone(),
            auth.dmarc.clone(),
        );
        let recorded = tokio::task::spawn_blocking(move || {
            let (db, domain, from, envelope, ip, dkim, spf, dmarc) = event;
            rmail_common::db::add_dmarc_event(
                db,
                &domain,
                from.as_deref(),
                envelope.as_deref(),
                ip.as_deref(),
                dkim.as_deref(),
                spf.as_deref(),
                dmarc.as_deref(),
                None,
            )
        })
        .await;
        if !matches!(recorded, Ok(Ok(_))) {
            session_log!(self, "warn", "dmarc_event_record_failed", { "message_id": self.message_id });
        }

        let Some(request) = auth.failure_report.as_ref() else {
            return;
        };
        if !self.security.dmarc_failure_reports
            || auth.dmarc.as_deref() == Some("pass")
            || !crate::limits::failure_report_allowed(&request.domain)
        {
            return;
        }
        let candidates = request
            .recipients
            .iter()
            .map(|(address, _)| address.clone())
            .collect();
        let authorized =
            rmail_common::mail_auth::authorized_report_destinations(&request.domain, candidates)
                .await;
        let mail_root = std::path::PathBuf::from(&self.mail_root);
        for recipient in authorized {
            let message = rmail_common::mail_auth::failure_report_message(
                &rmail_common::mail_auth::FailureReport {
                    request,
                    reporting_mta: crate::server_hostname(),
                    recipient: &recipient,
                    source_ip: self.peer.map(|peer| peer.ip()),
                    original_mail_from: self
                        .tx
                        .mail_from
                        .as_deref()
                        .filter(|from| !from.is_empty()),
                    arrival: chrono::Utc::now(),
                    dkim: auth.dkim.as_deref(),
                    spf: auth.spf.as_deref(),
                    message: data,
                },
            );
            // ruf may carry a size limit (e.g. mailto:a@b!10k).
            let max_size = request
                .recipients
                .iter()
                .find(|(address, _)| *address == recipient)
                .map_or(0, |(_, size)| *size);
            if max_size > 0 && message.len() > max_size {
                continue;
            }
            let mail_root = mail_root.clone();
            let queued = tokio::task::spawn_blocking(move || {
                rmail_common::outbound::queue_outbound(&mail_root, &recipient, &message, None)
            })
            .await;
            if !matches!(queued, Ok(Ok(_))) {
                session_log!(self, "warn", "dmarc_failure_report_queue_failed", { "message_id": self.message_id, "domain": request.domain });
            }
        }
    }

    /// SPF, DKIM, DMARC and ARC evaluation, recorded in metrics.
    async fn authenticate_sender(&self, data: &Bytes) -> AuthenticationResults {
        let auth = match rmail_common::mail_auth::analyze_message(
            data,
            self.peer.map(|peer| peer.ip()),
            self.helo_name.as_deref(),
            "localhost",
            self.tx.mail_from.as_deref(),
        )
        .await
        {
            Ok(results) => results,
            Err(error) => {
                session_log!(self, "warn", "mail_auth_failed", { "message_id": self.message_id, "error": error.to_string() });
                AuthenticationResults::default()
            }
        };
        match auth.arc.as_deref() {
            Some("pass") => metrics::inc_arc_pass(),
            Some("none") => {}
            _ => metrics::inc_arc_fail(),
        }
        match auth.dkim.as_deref() {
            Some(result) if result.starts_with("pass") => metrics::inc_dkim_pass(),
            Some(_) => metrics::inc_dkim_fail(),
            None => {}
        }
        match auth.spf.as_deref() {
            Some("pass") => metrics::inc_spf_pass(),
            Some(_) => metrics::inc_spf_fail(),
            None => {}
        }
        match auth.dmarc.as_deref() {
            Some("pass") => metrics::inc_dmarc_pass(),
            Some("quarantine") => metrics::inc_dmarc_quarantine(),
            Some("reject") => metrics::inc_dmarc_reject(),
            _ => {}
        }
        auth
    }

    /// Final reply. LMTP answers once per accepted RCPT, aggregating alias
    /// targets back to the address the client used.
    async fn hold_message(
        &mut self,
        reader: &mut SmtpReader,
        data: Bytes,
        release_at: i64,
    ) -> Result<Flow> {
        let user = self.authenticated_user.clone().unwrap_or_default();
        let held = rmail_common::hold::Held {
            id: String::new(),
            mail_from: self.tx.mail_from.clone().unwrap_or_else(|| user.clone()),
            user,
            recipients: self.tx.given_rcpts.clone(),
            release_at,
            submission_id: None,
            last_error: None,
        };
        let mail_root = std::path::PathBuf::from(&self.mail_root);
        let stored =
            tokio::task::spawn_blocking(move || rmail_common::hold::hold(&mail_root, held, &data))
                .await;
        match stored {
            Ok(Ok(held)) => {
                session_log!(self, "info", "message_held", { "message_id": self.message_id, "hold_id": held.id, "release_at": release_at, "recipient_count": held.recipients.len() });
                let status = format!(
                    "250 2.0.0 Message held until {}",
                    chrono::DateTime::from_timestamp(release_at, 0)
                        .unwrap_or_default()
                        .format("%Y-%m-%dT%H:%M:%SZ")
                );
                self.complete_message(reader, &status).await?;
            }
            _ => {
                session_log!(self, "error", "message_hold_failed", { "message_id": self.message_id });
                self.complete_message(reader, "451 4.3.0 Could not hold the message")
                    .await?;
            }
        }
        self.abort_transaction();
        Ok(Flow::Continue)
    }

    async fn finish_message(&self, reader: &mut SmtpReader, report: &DeliveryReport) -> Result<()> {
        let writer = reader.get_mut();
        if self.service == SmtpService::Lmtp {
            let groups = self
                .lmtp_recipient_groups
                .iter()
                .filter(|(generation, _, _)| *generation == self.generation);
            if report.any_accepted {
                let mut event =
                    self.trace
                        .event(self.peer, self.message_id.clone(), "message", "accepted");
                event.detail = Some(format!(
                    "lmtp recipients={} partial_failures={}",
                    groups.clone().count(),
                    report.any_rejected
                ));
                event.smtp_code = Some(250);
                emit_tracking(event);
                metrics::inc_lmtp_message_received(self.peer);
            }
            for (_, original, targets) in groups {
                let statuses = targets
                    .iter()
                    .filter_map(|target| report.lmtp_status.get(target))
                    .copied()
                    .collect::<Vec<_>>();
                let status = if !statuses.is_empty()
                    && statuses.iter().all(|status| status.starts_with("250 "))
                {
                    "250 2.1.5 Delivered"
                } else if let Some(status) = statuses
                    .iter()
                    .find(|status| status.starts_with(['4', '5']))
                {
                    status
                } else {
                    "451 4.3.0 Temporary delivery failure"
                };
                writer
                    .write_all(format!("{status} <{original}>\r\n").as_bytes())
                    .await?;
            }
        } else if report.any_accepted {
            let mut event =
                self.trace
                    .event(self.peer, self.message_id.clone(), "message", "accepted");
            event.detail = Some(format!(
                "accepted recipients={} partial_failures={}",
                self.tx.rcpts.len(),
                report.any_rejected
            ));
            event.smtp_code = Some(250);
            emit_tracking(event);
            metrics::inc_smtp_message_received(
                self.peer,
                self.implicit_tls,
                self.encrypted,
                self.extended_smtp,
            );
            if self.service == SmtpService::Submission
                && let Some(user) = self.authenticated_user.as_deref()
            {
                record_submission_message(
                    user,
                    self.security.submission_max_messages_per_user_per_day,
                    self.security.submission_max_messages_per_domain_per_hour,
                );
            }
            session_log!(self, "info", "data_completed", { "message_id": self.message_id, "result": if report.any_rejected { "partially_accepted" } else { "accepted" } });
            writer.write_all(b"250 2.0.0 Message accepted\r\n").await?;
        } else if report.any_rejected {
            session_log!(self, "warn", "data_completed", { "message_id": self.message_id, "result": "temporary_failure", "quota_exceeded": report.any_quota_exceeded });
            if report.any_quota_exceeded {
                writer
                    .write_all(b"452 4.2.2 Mailbox storage limit exceeded\r\n")
                    .await?;
            } else {
                writer
                    .write_all(b"451 4.3.0 Temporary delivery failure\r\n")
                    .await?;
            }
        } else {
            session_log!(self, "info", "data_completed", { "message_id": self.message_id, "result": "no_recipients" });
            writer.write_all(b"250 2.0.0 Message accepted\r\n").await?;
        }
        writer.flush().await?;
        Ok(())
    }
}

enum Intake {
    Message(DataReadResult),
    /// A reply was already sent (chunk accepted, or an error).
    Handled(Flow),
}

enum Scan {
    /// Clean; deliver (possibly with scanner headers added).
    Deliver(Bytes),
    /// Deliver to the Junk folder.
    Quarantine(Bytes),
    /// Scanner failed and policy says accept anyway.
    Accept,
    Reject(&'static str),
}
