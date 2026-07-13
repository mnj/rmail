use std::path::Path;

use crate::{
    commands::search::compress_ids,
    mailbox::{self, SelectedMailbox},
    parser,
    response::{Response, Status, StatusLine},
};

pub(crate) struct Outcome {
    pub(crate) response: Response,
    pub(crate) refresh_selected: bool,
}

pub(crate) async fn handle(
    tag: &str,
    command_name: &str,
    raw_args: &str,
    mail_root: &str,
    address: &str,
    selected: &SelectedMailbox,
    saved_uids: &[u64],
    uid_mode: bool,
    utf8_accept: bool,
) -> Outcome {
    let move_messages = command_name.ends_with("MOVE");
    let request = match parser::parse_transfer_request(raw_args) {
        Ok(request) => request,
        Err(_) => return failure(bad(tag, format!("Invalid {command_name} arguments"))),
    };
    if move_messages && selected.read_only {
        return failure(Response::new().status(StatusLine::tagged(
            tag,
            Status::No,
            "Mailbox is read-only",
        )));
    }
    let destination = match mailbox::decode_wire_mailbox_name(&request.destination, utf8_accept) {
        Ok(destination) => destination,
        Err(_) => return failure(bad(tag, "Invalid mailbox name".to_string())),
    };
    let source_uids = resolve_uids(&request.message_set, selected, saved_uids, uid_mode);
    let root = mail_root.to_string();
    let domain = selected.domain.clone();
    let local = selected.local.clone();
    let source_mailbox = selected.mailbox.clone();
    let destination_for_task = destination.clone();
    let transfer_uids = source_uids.clone();
    let mappings = match tokio::task::spawn_blocking(move || {
        rmail_common::imap_state::transfer_messages_by_uid(
            Path::new(&root),
            &domain,
            &local,
            &source_mailbox,
            &transfer_uids,
            &destination_for_task,
            move_messages,
        )
    })
    .await
    {
        Ok(Ok(mappings)) => mappings,
        Ok(Err(error)) => return failure(storage_operation_error(tag, command_name, error)),
        Err(error) => return failure(storage_error(tag, command_name, error)),
    };
    let (local, domain) = match mailbox::address_parts(address) {
        Ok(parts) => parts,
        Err(error) => return failure(storage_error(tag, command_name, error)),
    };
    let root = mail_root.to_string();
    let destination_for_summary = destination.clone();
    let destination_summary = match tokio::task::spawn_blocking(move || {
        rmail_common::imap_state::folder_summary(
            Path::new(&root),
            &domain,
            &local,
            &destination_for_summary,
        )
    })
    .await
    {
        Ok(Ok(Some(summary))) => summary,
        Ok(Ok(None)) => {
            return failure(
                Response::new().status(
                    StatusLine::tagged(tag, Status::No, "Destination mailbox does not exist")
                        .with_code("TRYCREATE"),
                ),
            );
        }
        Ok(Err(error)) => return failure(storage_operation_error(tag, command_name, error)),
        Err(error) => return failure(storage_error(tag, command_name, error)),
    };

    let mapped_source_uids = mappings.iter().map(|mapping| mapping.0).collect::<Vec<_>>();
    let destination_uids = mappings.iter().map(|mapping| mapping.1).collect::<Vec<_>>();
    let mut response = Response::new();
    if move_messages {
        let mut sequences = mapped_source_uids
            .iter()
            .filter_map(|uid| {
                selected
                    .msgs
                    .iter()
                    .position(|(candidate, _, _, _)| candidate == uid)
                    .map(|index| index + 1)
            })
            .collect::<Vec<_>>();
        sequences.sort_unstable_by(|left, right| right.cmp(left));
        for sequence in sequences {
            response = response.data(format!("{sequence} EXPUNGE"));
        }
    }
    let mut completion = StatusLine::tagged(tag, Status::Ok, format!("{command_name} completed"));
    if !mapped_source_uids.is_empty() {
        completion = completion.with_code(format!(
            "COPYUID {} {} {}",
            destination_summary.folder.uidvalidity,
            compress_ids(&mapped_source_uids),
            compress_ids(&destination_uids)
        ));
    }
    Outcome {
        response: response.status(completion),
        refresh_selected: move_messages,
    }
}

fn resolve_uids(
    message_set: &str,
    selected: &SelectedMailbox,
    saved_uids: &[u64],
    uid_mode: bool,
) -> Vec<u64> {
    if message_set == "$" {
        return saved_uids
            .iter()
            .copied()
            .filter(|uid| selected.msgs.iter().any(|message| message.0 == *uid))
            .collect();
    }
    if uid_mode {
        parser::uids_from_set(message_set, &selected.msgs)
    } else {
        parser::seqs_from_set(message_set, selected.msgs.len())
            .into_iter()
            .filter_map(|sequence| selected.msgs.get(sequence.checked_sub(1)?))
            .map(|message| message.0)
            .collect()
    }
}

fn bad(tag: &str, text: String) -> Response {
    Response::new().status(StatusLine::tagged(tag, Status::Bad, text))
}

fn storage_error(tag: &str, command_name: &str, error: impl std::fmt::Display) -> Response {
    let message = error.to_string();
    let mut line = StatusLine::tagged(tag, Status::No, format!("{command_name} failed: {message}"));
    if message.contains("does not exist") {
        line = line.with_code("TRYCREATE");
    }
    Response::new().status(line)
}

fn storage_operation_error(tag: &str, command_name: &str, error: anyhow::Error) -> Response {
    if error
        .downcast_ref::<rmail_common::imap_state::StorageQuotaExceeded>()
        .is_some()
    {
        return Response::new().status(
            StatusLine::tagged(
                tag,
                Status::No,
                format!("{command_name} exceeds storage quota"),
            )
            .with_code("OVERQUOTA"),
        );
    }
    storage_error(tag, command_name, error)
}

fn failure(response: Response) -> Outcome {
    Outcome {
        response,
        refresh_selected: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_parser_supports_quoted_destinations_and_rejects_trailing_data() {
        assert_eq!(
            parser::parse_transfer_request("1:3 \"Archive 2026\"").unwrap(),
            parser::TransferRequest {
                message_set: "1:3".to_string(),
                destination: "Archive 2026".to_string(),
            }
        );
        assert!(parser::parse_transfer_request("1 Archive trailing").is_err());
    }

    #[tokio::test]
    async fn move_emits_descending_expunges_and_copyuid() {
        let temp = tempfile::tempdir().unwrap();
        for subject in ["one", "two"] {
            rmail_common::imap_state::append_message(
                temp.path(),
                "example.test",
                "user",
                "INBOX",
                format!("Subject: {subject}\r\n\r\nbody").as_bytes(),
                Vec::new(),
            )
            .unwrap();
        }
        let selected = mailbox::load_selected_mailbox(
            temp.path().to_str().unwrap(),
            "user@example.test",
            "INBOX",
        )
        .await
        .unwrap();
        let outcome = handle(
            "A1",
            "MOVE",
            "1:2 Archive",
            temp.path().to_str().unwrap(),
            "user@example.test",
            &selected,
            &[],
            false,
            false,
        )
        .await;
        let response = outcome.response.encode();
        assert!(response.starts_with("* 2 EXPUNGE\r\n* 1 EXPUNGE\r\n"));
        assert!(response.contains("A1 OK [COPYUID "));
        assert!(response.ends_with(" MOVE completed\r\n"));
        assert!(outcome.refresh_selected);
        assert!(
            rmail_common::imap_state::load_folder(temp.path(), "example.test", "user", "INBOX")
                .unwrap()
                .1
                .is_empty()
        );
    }
}
