//! RCPT TO: resolving a recipient to local mailboxes, alias or catchall
//! targets, or an authenticated relay destination.

use anyhow::Result;
use rmail_common::db;
use rmail_common::outbound::DsnOptions;

use super::{Flow, Session, SmtpReader, reply, session_log};
use crate::SmtpService;
use crate::protocol::{self, parse_rcpt_to_args};

const TEMPORARY_ERROR: &[u8] = b"451 4.3.0 Temporary local error\r\n";
const TOO_MANY_RECIPIENTS: &[u8] = b"452 4.5.3 Too many recipients\r\n";

/// Outcome of resolving one RCPT address.
enum Decision {
    Accept {
        targets: Vec<String>,
        /// Alias/catchall expansion (server-side forwarding).
        forwarded: bool,
    },
    Reject(&'static [u8]),
}

impl Session {
    pub(super) async fn rcpt(&mut self, reader: &mut SmtpReader, args: &str) -> Result<Flow> {
        if !self.tx.active {
            return reply(reader, b"503 5.5.1 MAIL required before RCPT\r\n").await;
        }
        let parsed = match parse_rcpt_to_args(args, self.tx.smtp_utf8) {
            Ok(parsed) => parsed,
            Err(protocol::EnvelopeError::UnsupportedParameter) => {
                return reply(reader, b"555 5.5.4 Unsupported RCPT TO parameter\r\n").await;
            }
            Err(protocol::EnvelopeError::Syntax) => {
                return reply(reader, b"501 5.5.2 Syntax: RCPT TO:<address>\r\n").await;
            }
        };
        let address = parsed.recipient;
        let dsn = DsnOptions {
            envelope_id: self.tx.dsn.envelope_id.clone(),
            return_content: self.tx.dsn.return_content,
            notify: parsed.dsn_notify,
            original_recipient: parsed.original_recipient,
        };
        let (targets, forwarded) = match self.resolve_recipient(&address).await {
            Decision::Reject(rejection) => return reply(reader, rejection).await,
            Decision::Accept { targets, forwarded } => (targets, forwarded),
        };
        if let Some(retry) = self.greylist_defer(&address) {
            session_log!(self, "info", "rcpt_greylisted", { "rcpt": address, "retry_after_secs": retry });
            return reply(reader, b"451 4.7.1 Greylisted, please try again later\r\n").await;
        }
        if self.service == SmtpService::Lmtp {
            self.lmtp_recipient_groups
                .push((self.generation, address.clone(), targets.clone()));
        }
        self.tx.given_rcpts.push(address.clone());
        for target in targets {
            if forwarded {
                self.forwarded_recipient
                    .insert(target.clone(), self.generation);
            }
            self.recipient_dsn
                .insert(target.clone(), (self.generation, dsn.clone()));
            self.tx.rcpts.push(target);
        }
        session_log!(self, "info", "rcpt_accepted", { "rcpt": address, "recipient_count": self.tx.rcpts.len() });
        reply(reader, b"250 2.1.5 Recipient OK\r\n").await
    }

    /// Greylisting applies only to unauthenticated inbound SMTP from a known
    /// peer; authenticated submission and LMTP are never delayed.
    fn greylist_defer(&self, address: &str) -> Option<u64> {
        if !self.security.greylist_enabled
            || self.service != SmtpService::Mta
            || self.authenticated_user.is_some()
        {
            return None;
        }
        let ip = self.peer?.ip();
        if ip.is_loopback() {
            return None;
        }
        let from = self.tx.mail_from.as_deref().unwrap_or("");
        match rmail_common::greylist::global().check(
            ip,
            from,
            address,
            std::time::Duration::from_secs(self.security.greylist_delay_secs),
        ) {
            rmail_common::greylist::GreylistDecision::Accept => None,
            rmail_common::greylist::GreylistDecision::Defer { retry_after_secs } => {
                Some(retry_after_secs)
            }
        }
    }

    /// Mailbox first, then alias, then the domain catchall; anything else is
    /// relayed only for authenticated clients.
    async fn resolve_recipient(&self, address: &str) -> Decision {
        let Some(db_path) = self.db_path.clone() else {
            return Decision::Reject(b"451 4.3.0 Recipient database unavailable\r\n");
        };
        let room = self.max_recipients.saturating_sub(self.tx.rcpts.len());

        let mailbox = self
            .lookup(address, "mailbox", {
                let db_path = db_path.clone();
                let address = address.to_string();
                move || {
                    if address.contains('@') {
                        db::get_mailbox(db_path, &address)
                    } else {
                        db::find_mailbox_by_localpart(db_path, &address)
                    }
                }
            })
            .await;
        match mailbox {
            Err(()) => return Decision::Reject(TEMPORARY_ERROR),
            Ok(Some(_)) if room == 0 => return Decision::Reject(TOO_MANY_RECIPIENTS),
            Ok(Some(mailbox)) => {
                return Decision::Accept {
                    targets: vec![mailbox.address.to_ascii_lowercase()],
                    forwarded: false,
                };
            }
            Ok(None) => {}
        }

        let Some((_, domain)) = address.split_once('@') else {
            return Decision::Reject(b"550 5.1.3 Bad destination address\r\n");
        };

        // A bounce to an address SRS rewrote goes back to the original sender.
        let srs_domain = self.security.srs_domain.trim();
        if !srs_domain.is_empty()
            && domain.eq_ignore_ascii_case(srs_domain)
            && let Some((local, _)) = address.rsplit_once('@')
            && rmail_common::srs::is_srs(local)
        {
            return match rmail_common::srs::reverse(local, crate::srs_key()) {
                Ok(_) if room == 0 => Decision::Reject(TOO_MANY_RECIPIENTS),
                Ok(original) => Decision::Accept {
                    targets: vec![original],
                    forwarded: true,
                },
                Err(error) => {
                    session_log!(self, "info", "srs_rejected", { "rcpt": address, "reason": format!("{error:#}") });
                    Decision::Reject(b"550 5.1.1 Invalid or expired return address\r\n")
                }
            };
        }

        let alias = self
            .lookup(address, "alias", {
                let db_path = db_path.clone();
                let address = address.to_string();
                move || db::get_alias_targets(&db_path, &address)
            })
            .await;
        match alias {
            Err(()) => return Decision::Reject(TEMPORARY_ERROR),
            Ok(Some(targets)) => {
                session_log!(self, "info", "rcpt_alias", { "rcpt": address, "targets": targets });
                let lmtp = self.service == SmtpService::Lmtp;
                return if lmtp && targets.len() != 1 {
                    Decision::Reject(b"550 5.1.1 LMTP alias must resolve to one local mailbox\r\n")
                } else if lmtp && !self.all_local(&targets).await {
                    Decision::Reject(b"550 5.1.1 LMTP alias has a non-local target\r\n")
                } else if targets.is_empty() {
                    Decision::Reject(b"550 5.1.1 Alias has no targets\r\n")
                } else if targets.len() > room {
                    Decision::Reject(TOO_MANY_RECIPIENTS)
                } else {
                    Decision::Accept {
                        targets: targets
                            .into_iter()
                            .map(|target| target.to_ascii_lowercase())
                            .collect(),
                        forwarded: true,
                    }
                };
            }
            Ok(None) => {}
        }

        let catchall = self
            .lookup(address, "catchall", {
                let domain = domain.to_string();
                move || db::get_catchall(db_path, &domain)
            })
            .await;
        match catchall {
            Err(()) => Decision::Reject(TEMPORARY_ERROR),
            Ok(Some(target)) => {
                session_log!(self, "info", "rcpt_catchall", { "rcpt": address, "target": target });
                if self.service == SmtpService::Lmtp
                    && !self.all_local(std::slice::from_ref(&target)).await
                {
                    Decision::Reject(b"550 5.1.1 LMTP catchall has a non-local target\r\n")
                } else if room == 0 {
                    Decision::Reject(TOO_MANY_RECIPIENTS)
                } else {
                    Decision::Accept {
                        targets: vec![target.to_ascii_lowercase()],
                        forwarded: true,
                    }
                }
            }
            // Not local: relay only for authenticated clients.
            Ok(None) if self.authenticated_user.is_some() => {
                if room == 0 {
                    Decision::Reject(TOO_MANY_RECIPIENTS)
                } else {
                    Decision::Accept {
                        targets: vec![address.to_string()],
                        forwarded: false,
                    }
                }
            }
            Ok(None) => Decision::Reject(b"550 5.1.1 No such user\r\n"),
        }
    }

    /// Run a blocking database lookup, logging failures.
    async fn lookup<T, F>(&self, address: &str, lookup: &str, work: F) -> Result<T, ()>
    where
        T: Send + 'static,
        F: FnOnce() -> anyhow::Result<T> + Send + 'static,
    {
        match tokio::task::spawn_blocking(work).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => {
                session_log!(self, "error", "recipient_lookup_failed", { "rcpt": address, "lookup": lookup, "error": error.to_string() });
                Err(())
            }
            Err(error) => {
                session_log!(self, "error", "recipient_lookup_failed", { "rcpt": address, "lookup": "task", "error": error.to_string() });
                Err(())
            }
        }
    }

    /// Every target is a local mailbox (LMTP never relays).
    async fn all_local(&self, targets: &[String]) -> bool {
        let Some(db_path) = self.db_path.clone() else {
            return false;
        };
        let targets = targets.to_vec();
        tokio::task::spawn_blocking(move || {
            targets.iter().all(|target| {
                db::get_mailbox(&db_path, target).is_ok_and(|mailbox| mailbox.is_some())
            })
        })
        .await
        .unwrap_or(false)
    }
}
