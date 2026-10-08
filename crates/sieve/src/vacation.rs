//! Vacation auto-reply rules (RFC 5230) and reply construction.

use crate::ast::Vacation;
use crate::message::{Message, parse_addresses, split_address};

impl Vacation {
    /// Key for "already replied to this sender" tracking: the handle if given,
    /// otherwise derived from the reply content.
    pub fn dedupe_key(&self) -> String {
        match &self.handle {
            Some(handle) => handle.clone(),
            None => format!(
                "{}\n{}\n{}",
                self.subject.as_deref().unwrap_or(""),
                self.mime,
                self.reason
            ),
        }
    }

    /// The address to reply to, or `None` when RFC 5230 section 4.6 and 4.5
    /// say not to reply: null or system senders, lists and bulk mail,
    /// automatic messages, or mail not addressed to the user.
    pub fn reply_target(&self, msg: &Message<'_>) -> Option<String> {
        let sender = msg.envelope_from.trim();
        if sender.is_empty() || !sender.contains('@') {
            return None;
        }
        let local = split_address(sender).0.to_ascii_lowercase();
        let system_sender = matches!(
            local.as_str(),
            "mailer-daemon" | "postmaster" | "majordomo" | "listserv" | "root" | "nobody"
        ) || local.starts_with("owner-")
            || local.starts_with("bounce")
            || ["-request", "-relay", "-owner", "-bounce", "-bounces"]
                .iter()
                .any(|suffix| local.ends_with(suffix));
        if system_sender {
            return None;
        }
        if msg
            .first_header("auto-submitted")
            .is_some_and(|v| !v.trim().eq_ignore_ascii_case("no"))
        {
            return None;
        }
        if msg.first_header("precedence").is_some_and(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "bulk" | "list" | "junk"
            )
        }) {
            return None;
        }
        if ["list-id", "list-unsubscribe", "list-post"]
            .iter()
            .any(|h| msg.has_header(h))
        {
            return None;
        }
        if msg
            .first_header("x-spam-flag")
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("yes"))
        {
            return None;
        }
        // Only reply when one of the user's addresses is a direct recipient.
        let mine: Vec<String> = std::iter::once(msg.envelope_to.clone())
            .chain(self.addresses.iter().cloned())
            .map(|a| a.to_ascii_lowercase())
            .collect();
        let direct = ["to", "cc"]
            .iter()
            .flat_map(|h| msg.header_values(h))
            .flat_map(parse_addresses)
            .any(|a| mine.contains(&a.to_ascii_lowercase()));
        direct.then(|| sender.to_string())
    }

    /// The reply message. `my_address` is the From unless `:from` is set;
    /// `date` and `message_id` are supplied by the caller.
    pub fn build_reply(
        &self,
        msg: &Message<'_>,
        my_address: &str,
        to: &str,
        date: &str,
        message_id: &str,
    ) -> Vec<u8> {
        let clean = |s: &str| s.replace(['\r', '\n'], " ");
        let subject = self
            .subject
            .clone()
            .unwrap_or_else(|| format!("Auto: {}", msg.first_header("subject").unwrap_or("")));
        let from = self.from.as_deref().unwrap_or(my_address);
        let mut out = format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\nDate: {}\r\nMessage-ID: {}\r\n",
            clean(from),
            clean(to),
            clean(&subject),
            clean(date),
            clean(message_id)
        );
        if let Some(original) = msg.first_header("message-id") {
            out.push_str(&format!(
                "In-Reply-To: {}\r\nReferences: {}\r\n",
                clean(original),
                clean(original)
            ));
        }
        out.push_str("Auto-Submitted: auto-replied\r\nPrecedence: bulk\r\nMIME-Version: 1.0\r\n");
        let reason = self.reason.replace("\r\n", "\n").replace('\n', "\r\n");
        if self.mime {
            // The reason already carries its own MIME headers and body.
            out.push_str(&reason);
        } else {
            out.push_str("Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n");
            out.push_str(&reason);
            if !reason.ends_with("\r\n") {
                out.push_str("\r\n");
            }
        }
        out.into_bytes()
    }
}
