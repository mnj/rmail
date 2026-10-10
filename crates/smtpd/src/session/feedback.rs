//! Recording abuse feedback (ARF) reports sent to the configured feedback
//! loop addresses. The report is delivered like any other message first;
//! recording is a side effect that never changes the SMTP reply.

use bytes::Bytes;
use rmail_common::feedback;
use rmail_common::mail_auth::AuthenticationResults;

use super::{Session, session_log};

impl Session {
    /// When the accepted message went to a feedback address and is an ARF
    /// report, store it tied to the local sender, and warn when that
    /// account crosses the complaint threshold.
    pub(super) async fn record_feedback(&self, data: &Bytes, auth: &AuthenticationResults) {
        let configured = &self.security.feedback_addresses;
        // Only mail from outside: a local account must not be able to file
        // complaints against another.
        if configured.is_empty() || self.authenticated_user.is_some() {
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
