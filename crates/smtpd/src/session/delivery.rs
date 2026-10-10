//! Per-recipient delivery: local mailboxes (INBOX or Junk) or the outbound
//! queue, with ARC sealing for forwarded mail.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use bytes::Bytes;
use rmail_common::{imap_state, maildir, metrics};

use super::{Session, session_log};
use crate::SmtpService;
use crate::dsn::queue_local_success_notification;

#[derive(Default)]
pub(super) struct DeliveryReport {
    pub any_accepted: bool,
    pub any_rejected: bool,
    pub any_quota_exceeded: bool,
    /// LMTP: per-target final status.
    pub lmtp_status: HashMap<String, &'static str>,
}

/// Alias/catchall targets of the current transaction are forwarded mail.
pub(crate) fn is_forwarded_recipient(
    recipients: &HashMap<String, u64>,
    recipient: &str,
    transaction_generation: u64,
) -> bool {
    recipients
        .get(recipient)
        .is_some_and(|generation| *generation == transaction_generation)
}

/// What running the account's Sieve script did with a message.
struct SieveOutcome {
    /// The message was handled (stored, forwarded or discarded).
    stored: bool,
    /// It was stored in one of the account's own mailboxes.
    kept: bool,
}

impl Session {
    pub(super) async fn deliver(
        &self,
        data: &Bytes,
        quarantine: bool,
        dmarc: &Option<String>,
    ) -> DeliveryReport {
        let quarantine = quarantine || dmarc.as_deref() == Some("quarantine");
        let mut report = DeliveryReport {
            lmtp_status: self
                .tx
                .rcpts
                .iter()
                .map(|recipient| (recipient.clone(), "451 4.3.0 Temporary delivery failure"))
                .collect(),
            ..DeliveryReport::default()
        };
        // Forwarded copies share one ARC-sealed rendition of the message.
        let mut arc_sealed: Option<Vec<u8>> = None;
        let mail_root = PathBuf::from(&self.mail_root);
        for rcpt in &self.tx.rcpts {
            let Some((local, domain)) = rcpt.split_once('@') else {
                continue;
            };
            if let Some(mailbox) = self.local_mailbox(rcpt).await {
                let delivered = self
                    .deliver_local(
                        &mail_root,
                        rcpt,
                        local,
                        domain,
                        mailbox.quota_bytes,
                        data,
                        quarantine,
                        dmarc,
                        &mut report,
                    )
                    .await;
                if delivered {
                    self.notify_success(&mail_root, rcpt);
                }
                continue;
            }
            if self.service == SmtpService::Lmtp {
                report.any_rejected = true;
                report.lmtp_status.insert(
                    rcpt.clone(),
                    "550 5.1.1 LMTP recipient is not a local mailbox",
                );
                continue;
            }
            // Direct authenticated relay is queued as-is; alias/catchall
            // targets are server-side forwarding and carry an ARC set.
            let forwarded =
                is_forwarded_recipient(&self.forwarded_recipient, rcpt, self.generation);
            if forwarded && arc_sealed.is_none() {
                match self.arc_seal(data).await {
                    Ok(sealed) => arc_sealed = Some(sealed),
                    Err(error) => {
                        report.any_rejected = true;
                        session_log!(self, "error", "arc_seal_failed", { "message_id": self.message_id, "rcpt": rcpt, "error": format!("{error:#}") });
                        continue;
                    }
                }
            }
            let body = if forwarded {
                arc_sealed.as_deref().unwrap_or(data).to_vec()
            } else {
                data.to_vec()
            };
            self.queue_remote(&mail_root, rcpt, body, forwarded, &mut report)
                .await;
        }
        report
    }

    async fn local_mailbox(&self, rcpt: &str) -> Option<rmail_common::db::Mailbox> {
        let db_path = self.db_path.clone()?;
        let rcpt = rcpt.to_string();
        tokio::task::spawn_blocking(move || rmail_common::db::get_mailbox(&db_path, &rcpt))
            .await
            .ok()
            .and_then(Result::ok)
            .flatten()
    }

    /// Returns true when the message was stored.
    async fn deliver_local(
        &self,
        mail_root: &Path,
        rcpt: &str,
        local: &str,
        domain: &str,
        quota_bytes: Option<u64>,
        data: &Bytes,
        quarantine: bool,
        dmarc: &Option<String>,
        report: &mut DeliveryReport,
    ) -> bool {
        if !quarantine
            && let Some(outcome) = self
                .deliver_with_sieve(
                    mail_root,
                    rcpt,
                    local,
                    domain,
                    quota_bytes,
                    data,
                    dmarc,
                    report,
                )
                .await
        {
            // No out-of-office reply for mail the script discarded or only
            // forwarded elsewhere.
            if outcome.kept {
                self.jmap_vacation(mail_root, rcpt, data).await;
            }
            return outcome.stored;
        }
        let started = Instant::now();
        let (folder, result) = if quarantine {
            (
                "Junk",
                maildir::deliver_quarantine(mail_root, domain, local, data).map(|_| None),
            )
        } else {
            (
                "INBOX",
                imap_state::set_storage_quota(mail_root, domain, local, quota_bytes)
                    .and_then(|()| imap_state::deliver_message(mail_root, domain, local, data))
                    .map(|(_uidvalidity, uid)| Some(uid)),
            )
        };
        let stored = self
            .finish_local(
                mail_root,
                rcpt,
                folder,
                result,
                data.len(),
                started,
                dmarc,
                report,
            )
            .await;
        if stored && !quarantine {
            self.jmap_vacation(mail_root, rcpt, data).await;
        }
        stored
    }

    /// Answer with the account's JMAP vacation response (RFC 8621 section
    /// 8) when it is on. It runs next to the account's own Sieve script and
    /// follows Sieve vacation's rules (RFC 5230): one reply per sender per
    /// week, none to lists, automated mail or the account itself.
    async fn jmap_vacation(&self, mail_root: &Path, rcpt: &str, data: &Bytes) {
        let Some(db_path) = self.db_path.clone() else {
            return;
        };
        let account = rcpt.to_string();
        let Ok(Ok(response)) = tokio::task::spawn_blocking(move || {
            rmail_common::db::get_vacation_response(&db_path, &account)
        })
        .await
        else {
            return;
        };
        if !response.active_at(chrono::Utc::now().timestamp()) {
            return;
        }
        let text = response.text_body.clone().unwrap_or_default();
        let (reason, mime) = match &response.html_body {
            None => (text, false),
            Some(html) => {
                let boundary = format!("=_vacation_{:032x}", rand::random::<u128>());
                (
                    format!(
                        "Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n\
                         --{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\
                         Content-Transfer-Encoding: 8bit\r\n\r\n{text}\r\n\
                         --{boundary}\r\nContent-Type: text/html; charset=utf-8\r\n\
                         Content-Transfer-Encoding: 8bit\r\n\r\n{html}\r\n--{boundary}--\r\n"
                    ),
                    true,
                )
            }
        };
        let vacation = rmail_sieve::Vacation {
            reason,
            subject: response.subject.clone(),
            from: None,
            days: 7,
            addresses: Vec::new(),
            mime,
            handle: Some("jmap-vacation-response".to_string()),
        };
        let message =
            rmail_sieve::Message::new(data, self.tx.mail_from.as_deref().unwrap_or(""), rcpt);
        self.sieve_vacation(mail_root, rcpt, &vacation, &message)
            .await;
    }

    /// Record the outcome of one local store in the delivery report, metrics
    /// and log. Returns true when the message was stored.
    async fn finish_local(
        &self,
        mail_root: &Path,
        rcpt: &str,
        folder: &str,
        result: Result<Option<u64>>,
        bytes: usize,
        started: Instant,
        dmarc: &Option<String>,
        report: &mut DeliveryReport,
    ) -> bool {
        match result {
            Ok(uid) => {
                report.any_accepted = true;
                report
                    .lmtp_status
                    .insert(rcpt.to_string(), "250 2.1.5 Delivered");
                metrics::inc_deliveries();
                metrics::add_delivered_bytes(bytes as u64);
                metrics::observe_delivery_latency_us(started.elapsed().as_micros() as u64);
                session_log!(self, "info", "delivered", { "message_id": self.message_id, "rcpt": rcpt, "folder": folder, "uid": uid, "bytes": bytes, "dmarc": dmarc });
                if let Err(error) = increment_delivery_counter(mail_root).await {
                    session_log!(self, "warn", "delivery_counter_failed", { "error": error.to_string() });
                }
                true
            }
            Err(error) => {
                report.any_rejected = true;
                if error
                    .downcast_ref::<imap_state::StorageQuotaExceeded>()
                    .is_some()
                {
                    report.any_quota_exceeded = true;
                    report
                        .lmtp_status
                        .insert(rcpt.to_string(), "452 4.2.2 Mailbox storage limit exceeded");
                }
                metrics::inc_failed_deliveries();
                session_log!(self, "error", "delivery_failed", { "message_id": self.message_id, "rcpt": rcpt, "folder": folder, "error": error.to_string() });
                false
            }
        }
    }

    /// Run the recipient's active Sieve script and carry out its actions.
    /// `None` means there is no usable script and the caller should deliver
    /// to INBOX as usual (also the fallback for scripts that fail to parse
    /// or exceed limits, so mail is never lost to a broken filter).
    async fn deliver_with_sieve(
        &self,
        mail_root: &Path,
        rcpt: &str,
        local: &str,
        domain: &str,
        quota_bytes: Option<u64>,
        data: &Bytes,
        dmarc: &Option<String>,
        report: &mut DeliveryReport,
    ) -> Option<SieveOutcome> {
        use rmail_sieve::{Action, Message, Script};

        let db_path = self.db_path.clone()?;
        let account = rcpt.to_string();
        let source = tokio::task::spawn_blocking(move || {
            rmail_common::db::get_active_sieve_script(&db_path, &account)
        })
        .await
        .ok()?
        .ok()??;
        let script = match Script::parse(&source) {
            Ok(script) => script,
            Err(error) => {
                session_log!(self, "warn", "sieve_script_invalid", { "rcpt": rcpt, "error": error.to_string() });
                return None;
            }
        };
        let message = Message::new(data, self.tx.mail_from.as_deref().unwrap_or(""), rcpt);
        let actions = match script.run(&message) {
            Ok(actions) => actions,
            Err(error) => {
                session_log!(self, "warn", "sieve_script_failed", { "rcpt": rcpt, "error": error.to_string() });
                return None;
            }
        };

        let mut stored = false;
        // Stored in one of the account's own mailboxes (not discarded or
        // only forwarded).
        let mut kept = false;
        // Redirecting to oneself is a keep, unless the script already keeps.
        let keeps = actions
            .iter()
            .any(|action| matches!(action, Action::Keep { .. }));
        for action in actions {
            let started = Instant::now();
            match action {
                Action::Redirect { address } if is_own_address(&address, rcpt) => {
                    if keeps {
                        continue;
                    }
                    let result = self.sieve_store(
                        mail_root,
                        domain,
                        local,
                        quota_bytes,
                        "INBOX",
                        data,
                        Vec::new(),
                    );
                    let local = self
                        .finish_local(
                            mail_root,
                            rcpt,
                            "INBOX",
                            result,
                            data.len(),
                            started,
                            dmarc,
                            report,
                        )
                        .await;
                    stored |= local;
                    kept |= local;
                }
                Action::Keep { flags } => {
                    let result = self.sieve_store(
                        mail_root,
                        domain,
                        local,
                        quota_bytes,
                        "INBOX",
                        data,
                        flags,
                    );
                    let local = self
                        .finish_local(
                            mail_root,
                            rcpt,
                            "INBOX",
                            result,
                            data.len(),
                            started,
                            dmarc,
                            report,
                        )
                        .await;
                    stored |= local;
                    kept |= local;
                }
                Action::FileInto { folder, flags } => {
                    let mut target = folder.clone();
                    let mut result = self.sieve_file_into(
                        mail_root,
                        domain,
                        local,
                        quota_bytes,
                        &folder,
                        data,
                        flags.clone(),
                    );
                    // A folder that cannot be used falls back to the inbox
                    // (RFC 5228 section 4.1); a full mailbox does not.
                    if let Err(error) = &result
                        && error
                            .downcast_ref::<imap_state::StorageQuotaExceeded>()
                            .is_none()
                    {
                        session_log!(self, "warn", "sieve_fileinto_failed", { "rcpt": rcpt, "folder": folder, "error": format!("{error:#}") });
                        target = "INBOX".to_string();
                        result = self.sieve_store(
                            mail_root,
                            domain,
                            local,
                            quota_bytes,
                            "INBOX",
                            data,
                            flags,
                        );
                    }
                    let local = self
                        .finish_local(
                            mail_root,
                            rcpt,
                            &target,
                            result,
                            data.len(),
                            started,
                            dmarc,
                            report,
                        )
                        .await;
                    stored |= local;
                    kept |= local;
                }
                Action::Discard => {
                    report.any_accepted = true;
                    report
                        .lmtp_status
                        .insert(rcpt.to_string(), "250 2.1.5 Delivered");
                    session_log!(self, "info", "sieve_discarded", { "message_id": self.message_id, "rcpt": rcpt });
                    stored = true;
                }
                Action::Redirect { address } => {
                    // Redirected mail is forwarded mail: ARC-seal it like an alias.
                    let body = match self.arc_seal(data).await {
                        Ok(sealed) => sealed,
                        Err(error) => {
                            report.any_rejected = true;
                            session_log!(self, "error", "arc_seal_failed", { "message_id": self.message_id, "rcpt": rcpt, "error": format!("{error:#}") });
                            continue;
                        }
                    };
                    session_log!(self, "info", "sieve_redirect", { "message_id": self.message_id, "rcpt": rcpt, "to": address });
                    if self
                        .queue_remote(mail_root, &address, body, true, report)
                        .await
                    {
                        // LMTP otherwise keeps its temporary failure and the
                        // client retries, forwarding another copy each time.
                        report
                            .lmtp_status
                            .insert(rcpt.to_string(), "250 2.1.5 Delivered");
                        stored = true;
                    }
                }
                Action::Vacation(vacation) => {
                    self.sieve_vacation(mail_root, rcpt, &vacation, &message)
                        .await;
                }
            }
        }
        Some(SieveOutcome { stored, kept })
    }

    fn sieve_store(
        &self,
        mail_root: &Path,
        domain: &str,
        local: &str,
        quota_bytes: Option<u64>,
        folder: &str,
        data: &Bytes,
        flags: Vec<String>,
    ) -> Result<Option<u64>> {
        imap_state::set_storage_quota(mail_root, domain, local, quota_bytes)
            .and_then(|()| {
                imap_state::deliver_message_to(mail_root, domain, local, folder, data, flags)
            })
            .map(|(_uidvalidity, uid)| Some(uid))
    }

    /// `fileinto`: create the folder when it is missing, then store.
    fn sieve_file_into(
        &self,
        mail_root: &Path,
        domain: &str,
        local: &str,
        quota_bytes: Option<u64>,
        folder: &str,
        data: &Bytes,
        flags: Vec<String>,
    ) -> Result<Option<u64>> {
        if !imap_state::folder_exists(mail_root, domain, local, folder)? {
            imap_state::create_folder(mail_root, domain, local, folder)?;
        }
        self.sieve_store(mail_root, domain, local, quota_bytes, folder, data, flags)
    }

    /// Send a vacation auto-reply at most once per sender and period.
    async fn sieve_vacation(
        &self,
        mail_root: &Path,
        rcpt: &str,
        vacation: &rmail_sieve::Vacation,
        message: &rmail_sieve::Message<'_>,
    ) {
        let Some(db_path) = self.db_path.clone() else {
            return;
        };
        let Some(target) = vacation.reply_target(message) else {
            return;
        };
        if is_own_address(&target, rcpt) {
            return;
        }
        let claim = {
            let (account, target, key, days) = (
                rcpt.to_string(),
                target.clone(),
                vacation.dedupe_key(),
                vacation.days,
            );
            tokio::task::spawn_blocking(move || {
                rmail_common::db::vacation_claim_reply(&db_path, &account, &target, &key, days)
            })
            .await
        };
        if !matches!(claim, Ok(Ok(true))) {
            return;
        }
        let reply = vacation.build_reply(
            message,
            rcpt,
            &target,
            &chrono::Utc::now().to_rfc2822(),
            &format!(
                "<{:x}.{:x}@{}>",
                chrono::Utc::now().timestamp_micros(),
                rand::random::<u32>(),
                crate::server_hostname()
            ),
        );
        let mail_root = mail_root.to_path_buf();
        let recipient = target.clone();
        // Auto-replies use the null reverse-path so they can never bounce back.
        let queued = tokio::task::spawn_blocking(move || {
            rmail_common::outbound::queue_outbound(&mail_root, &recipient, &reply, None)
        })
        .await;
        match queued {
            Ok(Ok(_)) => {
                session_log!(self, "info", "sieve_vacation_sent", { "rcpt": rcpt, "to": target });
            }
            _ => {
                session_log!(self, "error", "sieve_vacation_failed", { "rcpt": rcpt, "to": target });
            }
        }
    }

    /// DSN SUCCESS notification when the sender requested one.
    fn notify_success(&self, mail_root: &Path, rcpt: &str) {
        if let Some(sender) = self.tx.mail_from.as_deref()
            && let Some((generation, dsn)) = self.recipient_dsn.get(rcpt)
            && *generation == self.generation
            && let Err(error) = queue_local_success_notification(mail_root, sender, rcpt, dsn)
        {
            session_log!(self, "error", "dsn_queue_failed", { "message_id": self.message_id, "rcpt": rcpt, "error": error.to_string() });
        }
    }

    async fn arc_seal(&self, data: &Bytes) -> Result<Vec<u8>> {
        let peer_ip = self
            .peer
            .map(|address| address.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let sealed = rmail_common::mail_auth::seal_forwarded(
            self.db_path.as_deref().map(Path::new),
            data,
            peer_ip,
            self.helo_name.as_deref().unwrap_or("unknown"),
            "localhost",
            self.tx.mail_from.as_deref(),
        )
        .await?;
        Ok(sealed.into_owned())
    }

    async fn queue_remote(
        &self,
        mail_root: &Path,
        rcpt: &str,
        body: Vec<u8>,
        forwarded: bool,
        report: &mut DeliveryReport,
    ) -> bool {
        let bytes = body.len();
        let options = rmail_common::outbound::QueueOptions {
            require_tls: self.tx.require_tls,
            tracking_id: self.message_id.clone(),
            dsn: self
                .recipient_dsn
                .get(rcpt)
                .filter(|(generation, _)| *generation == self.generation)
                .map(|(_, options)| options.clone())
                .unwrap_or_default(),
            mt_priority: self.tx.mt_priority,
            deliver_by: self.tx.deliver_by,
        };
        let mail_root = mail_root.to_path_buf();
        let recipient = rcpt.to_string();
        let sender = self.tx.mail_from.clone();
        let srs_domain = forwarded
            .then(|| self.security.srs_domain.trim().to_ascii_lowercase())
            .filter(|domain| !domain.is_empty());
        let db_path = self.db_path.clone();
        let queued = tokio::task::spawn_blocking(move || {
            let sender = match (sender, srs_domain, db_path) {
                (Some(sender), Some(srs_domain), Some(db_path)) if !sender.is_empty() => {
                    srs_sender(&db_path, &sender, &srs_domain)?
                }
                (sender, _, _) => sender,
            };
            rmail_common::outbound::queue_outbound_with_options(
                &mail_root,
                &recipient,
                &body,
                sender.as_deref(),
                options,
            )
        })
        .await;
        match queued {
            Ok(Ok(path)) => {
                report.any_accepted = true;
                session_log!(self, "info", "queued_outbound", { "message_id": self.message_id, "rcpt": rcpt, "queue_file": path.file_name().map(|name| name.to_string_lossy().into_owned()), "bytes": bytes });
                true
            }
            Ok(Err(error)) => {
                report.any_rejected = true;
                session_log!(self, "error", "queue_outbound_failed", { "message_id": self.message_id, "rcpt": rcpt, "error": error.to_string() });
                false
            }
            Err(error) => {
                report.any_rejected = true;
                session_log!(self, "error", "queue_outbound_failed", { "message_id": self.message_id, "rcpt": rcpt, "error": error.to_string() });
                false
            }
        }
    }
}

/// True when `address` names the recipient itself. Recipients are already
/// canonical (ASCII domain), so `address` is compared in that form too.
fn is_own_address(address: &str, rcpt: &str) -> bool {
    address.eq_ignore_ascii_case(rcpt)
        || rmail_common::domain::canonicalize_mailbox_address(address)
            .is_ok_and(|address| address.eq_ignore_ascii_case(rcpt))
}

/// Increment the on-disk delivered-message counter shown in the admin UI.
/// Written via a temporary file so concurrent writers never corrupt it.
async fn increment_delivery_counter(mail_root: &Path) -> Result<()> {
    let path = rmail_common::runtime::delivered_count_path(mail_root);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let count = tokio::fs::read_to_string(&path)
        .await
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .unwrap_or(0)
        .saturating_add(1);
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, count.to_string()).await?;
    tokio::fs::rename(&tmp, &path).await?;
    Ok(())
}

/// The envelope sender for forwarding mail from `sender` (SRS). Senders in
/// hosted domains are kept: their SPF already covers this server.
fn srs_sender(db_path: &str, sender: &str, srs_domain: &str) -> anyhow::Result<Option<String>> {
    let domain = sender.rsplit_once('@').map_or("", |(_, domain)| domain);
    let hosted = rmail_common::db::local_domains(db_path)?
        .iter()
        .any(|local| local.eq_ignore_ascii_case(domain));
    if hosted {
        return Ok(Some(sender.to_string()));
    }
    rmail_common::srs::forward(sender, srs_domain, crate::srs_key()).map(Some)
}
