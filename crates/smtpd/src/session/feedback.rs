//! Recording abuse feedback (ARF) reports sent to the configured feedback
//! loop addresses, and DMARC aggregate reports about hosted domains. The
//! report is delivered like any other message first; recording is a side
//! effect that never changes the SMTP reply.

use bytes::Bytes;
use rmail_common::dmarc_reports;
use rmail_common::feedback;
use rmail_common::mail_auth::AuthenticationResults;

use super::{Session, session_log};

impl Session {
    /// With no feedback address configured, count genuine reports that
    /// arrive anyway, so the console can suggest configuring the address
    /// they went to.
    async fn note_unrecorded_feedback(&self, data: &Bytes, auth: &AuthenticationResults) {
        let (Some(db_path), Some(recipient)) = (
            self.db_path.clone(),
            self.tx
                .given_rcpts
                .iter()
                .chain(&self.tx.rcpts)
                .next()
                .cloned(),
        ) else {
            return;
        };
        // Forged reports must not be able to prompt the suggestion.
        if auth.dmarc.as_deref() != Some("pass") {
            return;
        }
        let data = data.clone();
        let noted = tokio::task::spawn_blocking(move || {
            if feedback::parse(&data).is_none() {
                return Ok(false);
            }
            feedback::note_unrecorded(
                std::path::Path::new(&db_path),
                &recipient.to_lowercase(),
                chrono::Utc::now().timestamp(),
            )?;
            anyhow::Ok(true)
        })
        .await;
        match noted {
            Ok(Ok(true)) => {
                session_log!(self, "info", "feedback_report_unrecorded", { "message_id": self.message_id, "reason": "no feedback address is configured" });
            }
            Ok(Ok(false)) => {}
            Ok(Err(error)) => {
                session_log!(self, "warn", "feedback_report_record_failed", { "message_id": self.message_id, "error": format!("{error:#}") });
            }
            Err(error) => {
                session_log!(self, "warn", "feedback_report_record_failed", { "message_id": self.message_id, "error": error.to_string() });
            }
        }
    }

    /// When the accepted message is a DMARC aggregate report about a hosted
    /// domain, keep its totals. Like feedback reports, it is delivered
    /// first and recording never changes the SMTP reply.
    pub(super) async fn record_dmarc_report(&self, data: &Bytes, auth: &AuthenticationResults) {
        if self.authenticated_user.is_some() {
            return;
        }
        let Some(db_path) = self.db_path.clone() else {
            return;
        };
        // Kept either way, but only authenticated reports count: anyone can
        // mail a forged one.
        let authenticated = auth.dmarc.as_deref() == Some("pass");
        let data = data.clone();
        let stored = tokio::task::spawn_blocking(move || {
            let Some(report) = dmarc_reports::parse(&data) else {
                return Ok(None);
            };
            // Reports about domains hosted elsewhere are none of our business.
            if !rmail_common::db::local_domains(&db_path)?.contains(&report.domain) {
                return Ok(None);
            }
            let new = dmarc_reports::record(
                std::path::Path::new(&db_path),
                &report,
                authenticated,
                chrono::Utc::now().timestamp(),
            )?;
            anyhow::Ok(Some((report, new)))
        })
        .await;
        match stored {
            Ok(Ok(Some((report, new)))) => {
                session_log!(self, "info", if new { "dmarc_report_recorded" } else { "dmarc_report_duplicate" }, {
                    "message_id": self.message_id,
                    "reporter": report.reporter,
                    "domain": report.domain,
                    "messages": report.messages,
                    "passed": report.passed,
                    "authenticated": authenticated,
                });
            }
            Ok(Ok(None)) => {}
            Ok(Err(error)) => {
                session_log!(self, "warn", "dmarc_report_record_failed", { "message_id": self.message_id, "error": format!("{error:#}") });
            }
            Err(error) => {
                session_log!(self, "warn", "dmarc_report_record_failed", { "message_id": self.message_id, "error": error.to_string() });
            }
        }
    }

    /// When the accepted message went to a feedback address and is an ARF
    /// report, store it tied to the local sender, and warn when that
    /// account crosses the complaint threshold.
    pub(super) async fn record_feedback(&self, data: &Bytes, auth: &AuthenticationResults) {
        let configured = &self.security.feedback_addresses;
        // Only mail from outside: a local account must not be able to file
        // complaints against another.
        if self.authenticated_user.is_some() {
            return;
        }
        if configured.is_empty() {
            self.note_unrecorded_feedback(data, auth).await;
            return;
        }
        let Some(recipient) = self
            .tx
            .given_rcpts
            .iter()
            .chain(&self.tx.rcpts)
            .find(|rcpt| feedback::is_feedback_address(rcpt, configured))
            .cloned()
        else {
            return;
        };
        let Some(db_path) = self.db_path.clone() else {
            return;
        };
        // Reports that fail DMARC are kept but marked: anyone can forge one.
        let authenticated = auth.dmarc.as_deref() == Some("pass");
        let data = data.clone();
        let threshold = self.security.feedback_complaint_threshold;
        let stored = tokio::task::spawn_blocking(move || {
            let Some(report) = feedback::parse(&data) else {
                return Ok(None);
            };
            let local_domains = rmail_common::db::local_domains(&db_path)?;
            let attribution = feedback::attribute(
                &report,
                |address| {
                    rmail_common::db::get_mailbox(&db_path, address)
                        .ok()
                        .flatten()
                        .is_some()
                },
                |domain| local_domains.iter().any(|local| local == domain),
            );
            let now = chrono::Utc::now().timestamp();
            let path = std::path::Path::new(&db_path);
            let Some(id) =
                feedback::record(path, &recipient, &report, &attribution, authenticated, now)?
            else {
                return Ok(Some((report, attribution, None, 0)));
            };
            let complaints = match &attribution.account {
                Some(account)
                    if authenticated
                        && threshold > 0
                        && feedback::is_complaint(&report.feedback_type) =>
                {
                    feedback::account_complaints(
                        path,
                        account,
                        now - feedback::THRESHOLD_WINDOW_SECS,
                    )?
                }
                _ => 0,
            };
            anyhow::Ok(Some((report, attribution, Some(id), complaints)))
        })
        .await;
        match stored {
            Ok(Ok(Some((report, attribution, Some(id), complaints)))) => {
                feedback::count_received(&report.feedback_type);
                session_log!(self, "info", "feedback_report_recorded", {
                    "message_id": self.message_id,
                    "report_id": id,
                    "feedback_type": report.feedback_type,
                    "reporter": report.reporter,
                    "account": attribution.account,
                    "domain": attribution.domain,
                    "attributed_by": attribution.method,
                    "authenticated": authenticated,
                });
                if threshold > 0 && complaints >= threshold {
                    session_log!(self, "warn", "feedback_complaint_threshold", {
                        "account": attribution.account,
                        "complaints": complaints,
                        "threshold": threshold,
                        "window_secs": feedback::THRESHOLD_WINDOW_SECS,
                    });
                }
            }
            Ok(Ok(Some((report, _, None, _)))) => {
                session_log!(self, "info", "feedback_report_duplicate", { "message_id": self.message_id, "report_message_id": report.report_message_id });
            }
            Ok(Ok(None)) => {}
            Ok(Err(error)) => {
                session_log!(self, "warn", "feedback_report_record_failed", { "message_id": self.message_id, "error": format!("{error:#}") });
            }
            Err(error) => {
                session_log!(self, "warn", "feedback_report_record_failed", { "message_id": self.message_id, "error": error.to_string() });
            }
        }
    }
}
