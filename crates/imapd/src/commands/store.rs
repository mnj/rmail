use std::path::Path;

use crate::{
    commands::search::compress_ids,
    mailbox::SelectedMailbox,
    parser::{self, StoreMode},
    response::{Response, Status, StatusLine},
};

pub(crate) struct Outcome {
    pub(crate) response: Response,
    pub(crate) refresh_selected: bool,
}

pub(crate) async fn handle(
    tag: &str,
    raw_args: &str,
    mail_root: &str,
    selected: &SelectedMailbox,
    saved_uids: &[u64],
    uid_mode: bool,
) -> Outcome {
    let command = if uid_mode { "UID STORE" } else { "STORE" };
    let request = match parser::parse_store_request(raw_args) {
        Ok(request) => request,
        Err(_) => return outcome(bad(tag, format!("Invalid {command} arguments")), false),
    };
    if selected.read_only {
        return outcome(
            Response::new().status(StatusLine::tagged(tag, Status::No, "Mailbox is read-only")),
            false,
        );
    }
    let targets = if uid_mode {
        uid_targets(&request.message_set, selected, saved_uids)
    } else {
        sequence_targets(&request.message_set, selected, saved_uids)
    };
    let mut modified = Vec::new();
    let mut updates = Vec::new();
    for (sequence, uid, current_flags, modseq) in targets {
        if request
            .unchanged_since
            .is_some_and(|threshold| modseq > threshold)
        {
            modified.push(if uid_mode { uid } else { sequence as u64 });
            continue;
        }
        updates.push((
            sequence,
            uid,
            apply_operation(current_flags, request.mode, &request.flags),
        ));
    }
    let flag_updates = updates
        .iter()
        .map(|(_, uid, flags)| (*uid, flags.clone()))
        .collect::<Vec<_>>();
    let root = mail_root.to_string();
    let domain = selected.domain.clone();
    let local = selected.local.clone();
    let mailbox = selected.mailbox.clone();
    let modseqs = match tokio::task::spawn_blocking(move || {
        rmail_common::imap_state::set_uid_flags_batch(
            Path::new(&root),
            &domain,
            &local,
            &mailbox,
            &flag_updates,
        )
    })
    .await
    {
        Ok(Ok(modseqs)) => modseqs,
        Ok(Err(error)) => {
            return outcome(
                Response::new().status(
                    StatusLine::tagged(tag, Status::No, format!("{command} failed: {error}"))
                        .with_code("UNAVAILABLE"),
                ),
                false,
            );
        }
        Err(error) => {
            return outcome(
                Response::new().status(
                    StatusLine::tagged(tag, Status::No, format!("{command} task failed: {error}"))
                        .with_code("UNAVAILABLE"),
                ),
                false,
            );
        }
    };
    let mut response = Response::new();
    if !request.silent {
        for ((sequence, uid, flags), (_, modseq)) in updates.iter().zip(modseqs.iter()) {
            response = response.data(format!(
                "{sequence} FETCH (FLAGS ({}) UID {uid} MODSEQ ({modseq}))",
                flags.join(" ")
            ));
        }
    }
    let mut completion = StatusLine::tagged(tag, Status::Ok, format!("{command} completed"));
    if !modified.is_empty() {
        completion = completion.with_code(format!("MODIFIED {}", compress_ids(&modified)));
    }
    outcome(response.status(completion), true)
}

fn sequence_targets(
    set: &str,
    selected: &SelectedMailbox,
    saved_uids: &[u64],
) -> Vec<(usize, u64, Vec<String>, u64)> {
    let sequences = if set == "$" {
        selected
            .msgs
            .iter()
            .enumerate()
            .filter_map(|(index, (uid, _, _, _))| {
                saved_uids.binary_search(uid).is_ok().then_some(index + 1)
            })
            .collect()
    } else {
        parser::seqs_from_set(set, selected.msgs.len())
    };
    sequences
        .into_iter()
        .filter_map(|sequence| {
            selected
                .msgs
                .get(sequence.checked_sub(1)?)
                .map(|(uid, _, flags, modseq)| (sequence, *uid, flags.clone(), *modseq))
        })
        .collect()
}

fn uid_targets(
    set: &str,
    selected: &SelectedMailbox,
    saved_uids: &[u64],
) -> Vec<(usize, u64, Vec<String>, u64)> {
    let uids = if set == "$" {
        saved_uids.to_vec()
    } else {
        parser::uids_from_set(set, &selected.msgs)
    };
    uids.into_iter()
        .filter_map(|uid| {
            selected
                .msgs
                .iter()
                .enumerate()
                .find(|(_, (candidate, _, _, _))| *candidate == uid)
                .map(|(index, (_, _, flags, modseq))| (index + 1, uid, flags.clone(), *modseq))
        })
        .collect()
}

fn apply_operation(existing: Vec<String>, mode: StoreMode, requested: &[String]) -> Vec<String> {
    let mut flags = match mode {
        StoreMode::Replace => requested.to_vec(),
        StoreMode::Add => {
            let mut flags = existing;
            flags.extend(requested.iter().cloned());
            flags
        }
        StoreMode::Remove => existing
            .into_iter()
            .filter(|flag| !requested.iter().any(|requested| requested == flag))
            .collect(),
    };
    flags.sort();
    flags.dedup();
    flags
}

fn bad(tag: &str, text: String) -> Response {
    Response::new().status(StatusLine::tagged(tag, Status::Bad, text))
}

fn outcome(response: Response, refresh_selected: bool) -> Outcome {
    Outcome {
        response,
        refresh_selected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_modes_are_deterministic() {
        let existing = vec!["\\Seen".to_string(), "old".to_string()];
        assert_eq!(
            apply_operation(existing.clone(), StoreMode::Add, &["new".to_string()]),
            vec!["\\Seen", "new", "old"]
        );
        assert_eq!(
            apply_operation(existing.clone(), StoreMode::Remove, &["old".to_string()]),
            vec!["\\Seen"]
        );
        assert_eq!(
            apply_operation(existing, StoreMode::Replace, &["new".to_string()]),
            vec!["new"]
        );
    }

    #[tokio::test]
    async fn conditional_and_silent_store_have_correct_transaction_results() {
        let temp = tempfile::tempdir().unwrap();
        rmail_common::imap_state::append_message(
            temp.path(),
            "example.test",
            "user",
            "INBOX",
            b"Subject: test\r\n\r\nbody",
            Vec::new(),
        )
        .unwrap();
        let selected = crate::mailbox::load_selected_mailbox(
            temp.path().to_str().unwrap(),
            "user@example.test",
            "INBOX",
        )
        .await
        .unwrap();
        let uid = selected.msgs[0].0;

        let rejected = handle(
            "A1",
            "1 (UNCHANGEDSINCE 0) +FLAGS.SILENT (\\Seen)",
            temp.path().to_str().unwrap(),
            &selected,
            &[],
            false,
        )
        .await;
        assert_eq!(
            rejected.response.encode(),
            "A1 OK [MODIFIED 1] STORE completed\r\n"
        );
        assert!(
            rmail_common::imap_state::load_folder(temp.path(), "example.test", "user", "INBOX")
                .unwrap()
                .1[0]
                .flags
                .is_empty()
        );

        let committed = handle(
            "A2",
            &format!("{uid} +FLAGS.SILENT (\\Seen)"),
            temp.path().to_str().unwrap(),
            &selected,
            &[],
            true,
        )
        .await;
        assert_eq!(committed.response.encode(), "A2 OK UID STORE completed\r\n");
        assert_eq!(
            rmail_common::imap_state::load_folder(temp.path(), "example.test", "user", "INBOX")
                .unwrap()
                .1[0]
                .flags,
            vec!["\\SEEN"]
        );
    }
}
