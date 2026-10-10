//! Calendar invitations, cancellations and replies (iMIP, RFC 6047) in
//! delivered mail also go to the account's CalDAV schedule inbox. This is
//! a side effect of delivery: the message is stored either way, and a
//! calendar part that cannot be read is only logged.

use std::path::Path;

use bytes::Bytes;
use rmail_common::dav::imip::{self, Outcome, Verified};
use rmail_common::mail_auth::AuthenticationResults;

use super::{Session, session_log};

impl Session {
    /// Who this delivery vouches the message is from, for applying replies:
    /// the submitting account when the `From` header names it, else the
    /// `From` domain when DMARC passed for it.
    pub(super) fn itip_sender(&self, data: &Bytes, auth: &AuthenticationResults) -> Verified {
        if let Some(user) = &self.authenticated_user {
            return if rmail_common::mail_auth::submission_from_matches(data, user) {
                Verified::Address(user.clone())
            } else {
                Verified::Nobody
            };
        }
        match (auth.dmarc.as_deref(), auth.header_from.as_deref()) {
            (Some("pass"), Some(from)) => from
                .rsplit_once('@')
                .map_or(Verified::Nobody, |(_, domain)| {
                    Verified::Domain(domain.to_ascii_lowercase())
                }),
            _ => Verified::Nobody,
        }
    }

    /// Keep an iTIP message delivered to `rcpt` in its schedule inbox.
    pub(super) async fn receive_itip(
        &self,
        mail_root: &Path,
        rcpt: &str,
        local: &str,
        domain: &str,
        data: &Bytes,
        verified: &Verified,
    ) {
        let (mail_root, account, local, domain, data, verified) = (
            mail_root.to_path_buf(),
            rcpt.to_string(),
            local.to_string(),
            domain.to_string(),
            data.clone(),
            verified.clone(),
        );
        let received = tokio::task::spawn_blocking(move || {
            imip::receive(&mail_root, &domain, &local, &account, &data, &verified)
        })
        .await;
        match received {
            Ok(Ok(Outcome::None)) => {}
            Ok(Ok(Outcome::Skipped(reason))) => {
                session_log!(self, "info", "imip_skipped", { "message_id": self.message_id, "rcpt": rcpt, "reason": reason });
            }
            Ok(Ok(Outcome::Deposited {
                method,
                applied,
                why,
            })) => {
                session_log!(self, "info", "imip_received", { "message_id": self.message_id, "rcpt": rcpt, "method": method.as_str(), "applied": applied, "reason": why });
            }
            Ok(Err(error)) => {
                session_log!(self, "warn", "imip_failed", { "message_id": self.message_id, "rcpt": rcpt, "error": format!("{error:#}") });
            }
            Err(error) => {
                session_log!(self, "warn", "imip_failed", { "message_id": self.message_id, "rcpt": rcpt, "error": error.to_string() });
            }
        }
    }
}
