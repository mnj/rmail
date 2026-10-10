//! ETRN (RFC 1985): a client asks this server to start delivering the mail
//! it holds for a domain, typically that domain's own server coming back
//! online.
//!
//! The command is offered on the inbound service only. A queue run is
//! requested from the outbound worker (`rmail_common::etrn`) and the reply
//! sent at once, as section 5.1 asks. Runs are rate-limited per client and
//! per node (`crate::limits`), and replies to unauthenticated clients never
//! say whether or how much mail is waiting: they get 250 whether or not
//! the queue holds anything for the node. Authenticated clients get the
//! counting replies 251 and 253.

use std::path::PathBuf;

use anyhow::Result;
use rmail_common::etrn::Node;

use super::{Flow, Session, SmtpReader, reply, session_log};
use crate::SmtpService;
use crate::limits::{etrn_client_allowed, etrn_node_due};
use crate::protocol::{self, EtrnArgs};

impl Session {
    pub(super) async fn etrn(&mut self, reader: &mut SmtpReader, args: &str) -> Result<Flow> {
        if self.service != SmtpService::Mta {
            return reply(
                reader,
                b"502 5.5.1 ETRN is not available on this service\r\n",
            )
            .await;
        }
        let node = match protocol::parse_etrn_args(args) {
            Some(EtrnArgs::Node(node)) => node,
            Some(EtrnArgs::Queue(queue)) => {
                let line = format!(
                    "459 4.7.1 Node #{queue} not allowed: named queues are not supported\r\n"
                );
                return reply(reader, line.as_bytes()).await;
            }
            None => return reply(reader, b"501 5.5.4 Syntax: ETRN [@]domain\r\n").await,
        };
        let shown = node.display();
        if self
            .peer
            .is_some_and(|peer| !etrn_client_allowed(peer.ip()))
        {
            session_log!(self, "warn", "etrn_rate_limited", { "node": shown });
            let line = format!(
                "458 4.7.0 Unable to queue messages for node {shown}: too many requests\r\n"
            );
            return reply(reader, line.as_bytes()).await;
        }
        // Mail for hosted domains is delivered on arrival, never queued.
        if self.hosts_domain(node.domain()).await {
            let line =
                format!("459 4.7.1 Node {shown} not allowed: mail for it is delivered here\r\n");
            return reply(reader, line.as_bytes()).await;
        }
        let mail_root = PathBuf::from(&self.mail_root);
        let waiting = if self.authenticated_user.is_some() {
            let (root, counted) = (mail_root.clone(), node.clone());
            match tokio::task::spawn_blocking(move || {
                rmail_common::etrn::queued_count(&root, &counted)
            })
            .await
            {
                Ok(Ok(0)) => {
                    let line = format!("251 2.0.0 OK, no messages waiting for node {shown}\r\n");
                    return reply(reader, line.as_bytes()).await;
                }
                Ok(Ok(count)) => Some(count),
                _ => None,
            }
        } else {
            None
        };
        // A run started for this node a moment ago covers this request too.
        if etrn_node_due(&shown) && !self.request_queue_run(mail_root, node).await {
            let line = format!("458 4.3.0 Unable to queue messages for node {shown}\r\n");
            return reply(reader, line.as_bytes()).await;
        }
        session_log!(self, "info", "etrn_accepted", { "node": shown, "authenticated_user": self.authenticated_user });
        let line = match waiting {
            Some(count) => {
                format!("253 2.0.0 OK, {count} pending messages for node {shown} started\r\n")
            }
            None => format!("250 2.0.0 OK, queuing for node {shown} started\r\n"),
        };
        reply(reader, line.as_bytes()).await
    }

    /// The domain is one of this server's own (hosted) domains.
    async fn hosts_domain(&self, domain: &str) -> bool {
        let Some(db_path) = self.db_path.clone() else {
            return false;
        };
        let domain = domain.to_string();
        tokio::task::spawn_blocking(move || {
            rmail_common::db::local_domains(&db_path).is_ok_and(|domains| {
                domains
                    .iter()
                    .any(|local| local.eq_ignore_ascii_case(&domain))
            })
        })
        .await
        .unwrap_or(false)
    }

    async fn request_queue_run(&self, mail_root: PathBuf, node: Node) -> bool {
        match tokio::task::spawn_blocking(move || rmail_common::etrn::request(&mail_root, &node))
            .await
        {
            Ok(Ok(accepted)) => accepted,
            Ok(Err(error)) => {
                session_log!(self, "error", "etrn_request_failed", { "error": format!("{error:#}") });
                false
            }
            Err(error) => {
                session_log!(self, "error", "etrn_request_failed", { "error": error.to_string() });
                false
            }
        }
    }
}
