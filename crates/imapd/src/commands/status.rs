use std::path::Path;

use crate::{
    mailbox, parser,
    response::{Response, Status, StatusLine},
};

pub(crate) fn handle(
    tag: &str,
    raw_args: &str,
    mail_root: &Path,
    address: &str,
    utf8_accept: bool,
    selected_mailbox: Option<&str>,
) -> Response {
    let request = match parser::parse_status_request(raw_args) {
        Ok(request) => request,
        Err(_) => return bad(tag, "Invalid STATUS item or arguments"),
    };
    let mailbox_name = match mailbox::decode_wire_mailbox_name(&request.mailbox, utf8_accept) {
        Ok(name) => name,
        Err(_) => return bad(tag, "Invalid mailbox name"),
    };
    let (local, domain) = match mailbox::address_parts(address) {
        Ok(parts) => parts,
        Err(error) => return unavailable(tag, error),
    };
    let summary =
        match rmail_common::imap_state::folder_summary(mail_root, &domain, &local, &mailbox_name) {
            Ok(Some(summary)) => summary,
            Ok(None) => {
                return Response::new().status(
                    StatusLine::tagged(tag, Status::No, "No such mailbox").with_code("NONEXISTENT"),
                );
            }
            Err(error) => return unavailable(tag, error),
        };

    let recent =
        match rmail_common::imap_state::recent_count(mail_root, &domain, &local, &mailbox_name) {
            Ok(recent) => recent,
            Err(error) => return unavailable(tag, error),
        };
    let values = status_values(&summary, recent, &request.items);
    let mut completion = StatusLine::tagged(tag, Status::Ok, "STATUS completed");
    if selected_mailbox.is_some_and(|selected| selected.eq_ignore_ascii_case(&summary.folder.name))
    {
        completion = completion.with_code("CLIENTBUG");
    }
    Response::new()
        .data(format!(
            "STATUS {} ({})",
            mailbox::quote_wire_mailbox_name(&summary.folder.name, utf8_accept),
            values.join(" ")
        ))
        .status(completion)
}

pub(crate) fn status_values(
    summary: &rmail_common::imap_state::FolderSummary,
    recent: usize,
    items: &[parser::StatusItem],
) -> Vec<String> {
    let mut values = Vec::new();
    let requested = |item| items.contains(&item);
    if requested(parser::StatusItem::Messages) {
        values.push(format!("MESSAGES {}", summary.messages));
    }
    if requested(parser::StatusItem::UidNext) {
        values.push(format!("UIDNEXT {}", summary.folder.uidnext));
    }
    if requested(parser::StatusItem::UidValidity) {
        values.push(format!("UIDVALIDITY {}", summary.folder.uidvalidity));
    }
    if requested(parser::StatusItem::Unseen) {
        values.push(format!("UNSEEN {}", summary.unseen));
    }
    if requested(parser::StatusItem::Recent) {
        values.push(format!("RECENT {recent}"));
    }
    if requested(parser::StatusItem::HighestModSeq) {
        values.push(format!("HIGHESTMODSEQ {}", summary.folder.highest_modseq));
    }
    if requested(parser::StatusItem::Size) {
        values.push(format!("SIZE {}", summary.size));
    }
    values
}

fn bad(tag: &str, text: &str) -> Response {
    Response::new().status(StatusLine::tagged(tag, Status::Bad, text))
}

fn unavailable(tag: &str, error: impl std::fmt::Display) -> Response {
    Response::new().status(
        StatusLine::tagged(tag, Status::No, format!("STATUS failed: {error}"))
            .with_code("UNAVAILABLE"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_status_target_is_nonexistent_without_creation() {
        let temp = tempfile::tempdir().unwrap();
        let response = handle(
            "A1",
            "Missing (MESSAGES UIDNEXT)",
            temp.path(),
            "user@example.test",
            false,
            None,
        )
        .encode();
        assert_eq!(response, "A1 NO [NONEXISTENT] No such mailbox\r\n");
        assert!(
            !rmail_common::imap_state::folder_exists(
                temp.path(),
                "example.test",
                "user",
                "Missing"
            )
            .unwrap()
        );
    }

    #[test]
    fn status_uses_canonical_order_and_marks_selected_usage() {
        let temp = tempfile::tempdir().unwrap();
        let response = handle(
            "A1",
            "INBOX (SIZE MESSAGES RECENT)",
            temp.path(),
            "user@example.test",
            false,
            Some("inbox"),
        )
        .encode();
        assert!(response.starts_with("* STATUS \"INBOX\" (MESSAGES 0 RECENT 0 SIZE 0)\r\n"));
        assert!(response.ends_with("A1 OK [CLIENTBUG] STATUS completed\r\n"));
    }

    #[test]
    fn status_items_must_be_atoms() {
        let temp = tempfile::tempdir().unwrap();
        let response = handle(
            "A1",
            "INBOX (\"MESSAGES\")",
            temp.path(),
            "user@example.test",
            false,
            None,
        )
        .encode();
        assert_eq!(response, "A1 BAD Invalid STATUS item or arguments\r\n");
    }
}
