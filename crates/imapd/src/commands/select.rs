use crate::{
    commands::search::compress_ids,
    mailbox::{self, SelectedMailbox},
    parser,
    response::{Response, Status, StatusLine},
};

pub(crate) struct Outcome {
    pub(crate) response: Response,
    pub(crate) selected: Option<SelectedMailbox>,
}

pub(crate) async fn handle(
    tag: &str,
    command_name: &str,
    raw_args: &str,
    mail_root: &str,
    address: &str,
    utf8_accept: bool,
    condstore_enabled: bool,
    qresync_enabled: bool,
    had_selected_mailbox: bool,
) -> Outcome {
    let request = match parser::parse_select_request(raw_args) {
        Ok(request) => request,
        Err(_) => return failure(bad(tag, format!("Invalid {command_name} arguments"))),
    };
    if request.qresync.is_some() && !qresync_enabled {
        return failure(bad(tag, "QRESYNC is not enabled".to_string()));
    }
    let mailbox_name = match mailbox::decode_wire_mailbox_name(&request.mailbox, utf8_accept) {
        Ok(name) => name,
        Err(_) => return failure(bad(tag, "Invalid mailbox name".to_string())),
    };
    let (local, domain) = match mailbox::address_parts(address) {
        Ok(parts) => parts,
        Err(error) => return failure(unavailable(tag, command_name, error)),
    };
    let root = mail_root.to_string();
    let lookup_name = mailbox_name.clone();
    let exists = match tokio::task::spawn_blocking(move || {
        rmail_common::imap_state::folder_exists(
            std::path::Path::new(&root),
            &domain,
            &local,
            &lookup_name,
        )
    })
    .await
    {
        Ok(Ok(exists)) => exists,
        Ok(Err(error)) => return failure(unavailable(tag, command_name, error)),
        Err(error) => return failure(unavailable(tag, command_name, error)),
    };
    if !exists {
        return failure(Response::new().status(
            StatusLine::tagged(tag, Status::No, "Mailbox does not exist").with_code("NONEXISTENT"),
        ));
    }
    let mut selected = match mailbox::load_selected_mailbox(mail_root, address, &mailbox_name).await
    {
        Ok(selected) => selected,
        Err(error) => return failure(unavailable(tag, command_name, error)),
    };
    let read_only = command_name == "EXAMINE";
    selected.read_only = read_only;
    let condstore_requested = request.condstore || condstore_enabled;
    let qresync_changes = if let Some(qresync) = request.qresync.as_ref() {
        if qresync.uidvalidity == selected.uidvalidity {
            match load_qresync_changes(mail_root, &selected, qresync).await {
                Ok(changes) => Some(changes),
                Err(error) => return failure(unavailable(tag, command_name, error)),
            }
        } else {
            None
        }
    } else {
        None
    };

    let mut response = Response::new();
    if had_selected_mailbox && qresync_enabled {
        response = response.status(
            StatusLine::untagged(Status::Ok, "Previous mailbox closed").with_code("CLOSED"),
        );
    }
    response = response.data("FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)");
    response = if read_only {
        response.status(
            StatusLine::untagged(Status::Ok, "No permanent flags permitted")
                .with_code("PERMANENTFLAGS ()"),
        )
    } else {
        response.status(
            StatusLine::untagged(Status::Ok, "Flags permitted")
                .with_code("PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft \\*)"),
        )
    };
    response = response
        .data(format!("{} EXISTS", selected.msgs.len()))
        .data("0 RECENT")
        .status(
            StatusLine::untagged(Status::Ok, "UIDs valid")
                .with_code(format!("UIDVALIDITY {}", selected.uidvalidity)),
        )
        .status(
            StatusLine::untagged(Status::Ok, "Predicted next UID")
                .with_code(format!("UIDNEXT {}", selected.uidnext)),
        )
        .status(
            StatusLine::untagged(Status::Ok, "First unseen")
                .with_code(format!("UNSEEN {}", mailbox::first_unseen(&selected))),
        );
    if condstore_requested {
        response = response.status(
            StatusLine::untagged(Status::Ok, "Highest")
                .with_code(format!("HIGHESTMODSEQ {}", selected.highest_modseq)),
        );
    }
    if let Some(changes) = qresync_changes {
        if !changes.vanished_uids.is_empty() {
            response = response.data(format!(
                "VANISHED (EARLIER) {}",
                compress_ids(&changes.vanished_uids)
            ));
        }
        for message in changes.changed_messages {
            if let Some(sequence) = selected
                .msgs
                .iter()
                .position(|(uid, _, _, _)| *uid == message.uid)
            {
                response = response.data(format!(
                    "{} FETCH (UID {} FLAGS ({}) MODSEQ ({}))",
                    sequence + 1,
                    message.uid,
                    message.flags.join(" "),
                    message.modseq
                ));
            }
        }
    }
    response = response.status(
        StatusLine::tagged(tag, Status::Ok, format!("{command_name} completed"))
            .with_code(if read_only { "READ-ONLY" } else { "READ-WRITE" }),
    );
    Outcome {
        response,
        selected: Some(selected),
    }
}

async fn load_qresync_changes(
    mail_root: &str,
    selected: &SelectedMailbox,
    request: &parser::QresyncRequest,
) -> anyhow::Result<rmail_common::imap_state::QresyncChanges> {
    let root = mail_root.to_string();
    let domain = selected.domain.clone();
    let local = selected.local.clone();
    let mailbox_name = selected.mailbox.clone();
    let since = request.modseq;
    let known = request.known_uids.clone();
    let sample_endpoints = request
        .sample
        .as_ref()
        .and_then(|(sequences, uids)| {
            parser::SequenceSet::qresync_sample_endpoints(sequences, uids)
        })
        .unwrap_or_default();
    let mut changes = tokio::task::spawn_blocking(move || {
        rmail_common::imap_state::qresync_changes(
            std::path::Path::new(&root),
            &domain,
            &local,
            &mailbox_name,
            since,
            None,
        )
    })
    .await??;
    if let Some(known) = &known {
        changes.vanished_uids.retain(|uid| known.contains(*uid));
        changes
            .changed_messages
            .retain(|message| known.contains(message.uid));
    }
    for (_, sampled_uid) in sample_endpoints {
        let known_allows = known
            .as_ref()
            .is_none_or(|known| known.contains(sampled_uid));
        if sampled_uid < selected.uidnext
            && known_allows
            && !selected.msgs.iter().any(|message| message.0 == sampled_uid)
        {
            changes.vanished_uids.push(sampled_uid);
        }
    }
    changes.vanished_uids.sort_unstable();
    changes.vanished_uids.dedup();
    Ok(changes)
}

fn bad(tag: &str, text: String) -> Response {
    Response::new().status(StatusLine::tagged(tag, Status::Bad, text))
}

fn unavailable(tag: &str, command_name: &str, error: impl std::fmt::Display) -> Response {
    Response::new().status(
        StatusLine::tagged(tag, Status::No, format!("{command_name} failed: {error}"))
            .with_code("UNAVAILABLE"),
    )
}

fn failure(response: Response) -> Outcome {
    Outcome {
        response,
        selected: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_mailbox_fails_and_clears_selection_outcome() {
        let temp = tempfile::tempdir().unwrap();
        let outcome = handle(
            "A1",
            "SELECT",
            "Missing",
            temp.path().to_str().unwrap(),
            "user@example.test",
            false,
            false,
            false,
            true,
        )
        .await;
        assert!(outcome.selected.is_none());
        assert_eq!(
            outcome.response.encode(),
            "A1 NO [NONEXISTENT] Mailbox does not exist\r\n"
        );
    }

    #[tokio::test]
    async fn examine_has_no_permanent_flags_and_is_read_only() {
        let temp = tempfile::tempdir().unwrap();
        let outcome = handle(
            "A1",
            "EXAMINE",
            "INBOX",
            temp.path().to_str().unwrap(),
            "user@example.test",
            false,
            false,
            false,
            false,
        )
        .await;
        assert!(outcome.selected.as_ref().unwrap().read_only);
        let response = outcome.response.encode();
        assert!(response.contains("* OK [PERMANENTFLAGS ()] No permanent flags permitted"));
        assert!(response.ends_with("A1 OK [READ-ONLY] EXAMINE completed\r\n"));
    }
}
