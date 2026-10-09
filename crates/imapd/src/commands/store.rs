use std::collections::HashMap;
use std::path::Path;

use crate::{
    commands::search::compress_ids,
    mailbox::SelectedMailbox,
    parser::{self, StoreMode},
    response::{Response, Status, StatusLine},
};

/// Session state that shapes STORE responses.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct StoreContext {
    pub(crate) condstore: bool,
    pub(crate) imap4rev2: bool,
    /// RFC 9586: responses are UIDFETCH.
    pub(crate) uidonly: bool,
    /// RFC 9738 MESSAGELIMIT.
    pub(crate) message_limit: Option<usize>,
}

pub(crate) struct Outcome {
    pub(crate) response: Response,
    /// Flags this STORE changed as (uid, flags, modseq).
    pub(crate) flag_updates: Vec<(u64, Vec<String>, u64)>,
    /// UNCHANGEDSINCE enables CONDSTORE (RFC 7162 §3.1).
    pub(crate) condstore_activated: bool,
}

pub(crate) async fn handle(
    tag: &str,
    raw_args: &str,
    mail_root: &str,
    selected: &SelectedMailbox,
    saved_uids: &[u64],
    uid_mode: bool,
    context: StoreContext,
) -> Outcome {
    let command = if uid_mode { "UID STORE" } else { "STORE" };
    let request = match parser::parse_store_request(raw_args) {
        Ok(request) => request,
        Err(_) => return outcome(bad(tag, format!("Invalid {command} arguments"))),
    };
    let condstore_activated = request.unchanged_since.is_some();
    let condstore = context.condstore || condstore_activated;
    if selected.read_only {
        return Outcome {
            condstore_activated,
            ..outcome(Response::new().status(StatusLine::tagged(
                tag,
                Status::No,
                "Mailbox is read-only",
            )))
        };
    }
    let mut targets = if uid_mode {
        uid_targets(&request.message_set, selected, saved_uids)
    } else {
        sequence_targets(&request.message_set, selected, saved_uids)
    };
    let limited =
        crate::commands::limit::truncate_by(&mut targets, context.message_limit, |target| target.1);
    if limited.is_some() {
        // Back in sequence order for the FETCH responses.
        targets.sort_unstable_by_key(|target| target.0);
    }
    let mut modified = Vec::new();
    let mut updates = Vec::new();
    let requested_flags = request
        .flags
        .iter()
        .filter(|flag| !flag.eq_ignore_ascii_case("\\Recent"))
        .cloned()
        .collect::<Vec<_>>();
    // RFC 4314 section 4: a STORE succeeds if the rights allow changing any
    // of the requested flags, and fails if they allow none.
    if !requested_flags.is_empty()
        && !requested_flags
            .iter()
            .any(|flag| crate::shared::permitted_flag(selected.rights, flag))
    {
        return Outcome {
            condstore_activated,
            ..outcome(Response::new().status(
                StatusLine::tagged(tag, Status::No, "Permission denied").with_code("NOPERM"),
            ))
        };
    }
    for (sequence, uid, current_flags, modseq) in targets {
        // Messages expunged by another session keep their sequence number
        // until the expunge is reported; there is nothing left to store.
        if selected.is_expunged(uid) {
            continue;
        }
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
            apply_permitted(
                current_flags,
                request.mode,
                &requested_flags,
                selected.rights,
            ),
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
        Ok(Ok(modseqs)) => modseqs.into_iter().collect::<HashMap<_, _>>(),
        Ok(Err(error)) => {
            return Outcome {
                condstore_activated,
                ..outcome(
                    Response::new().status(
                        StatusLine::tagged(tag, Status::No, format!("{command} failed: {error}"))
                            .with_code("UNAVAILABLE"),
                    ),
                )
            };
        }
        Err(error) => {
            return Outcome {
                condstore_activated,
                ..outcome(
                    Response::new().status(
                        StatusLine::tagged(
                            tag,
                            Status::No,
                            format!("{command} task failed: {error}"),
                        )
                        .with_code("UNAVAILABLE"),
                    ),
                )
            };
        }
    };
    let mut response = Response::new();
    let mut applied = Vec::new();
    for (sequence, uid, flags) in &updates {
        // Storage skips messages that vanished meanwhile.
        let Some(modseq) = modseqs.get(uid) else {
            continue;
        };
        applied.push((*uid, flags.clone(), *modseq));
        // RFC 9586 §3.3: UIDFETCH starts with the UID instead.
        let (prefix, uid_item) = if context.uidonly {
            (format!("{uid} UIDFETCH"), String::new())
        } else {
            (format!("{sequence} FETCH"), format!("UID {uid}"))
        };
        let modseq_item = condstore.then(|| format!("MODSEQ ({modseq})"));
        if request.silent {
            // RFC 7162 §3.1.3: a silent STORE still reports the new
            // mod-sequence once CONDSTORE is enabled.
            if let Some(modseq_item) = modseq_item {
                let items = [uid_item, modseq_item]
                    .into_iter()
                    .filter(|item| !item.is_empty())
                    .collect::<Vec<_>>();
                response = response.data(format!("{prefix} ({})", items.join(" ")));
            }
            continue;
        }
        let mut response_flags = flags.clone();
        if !context.imap4rev2 && selected.recent_uids.contains(uid) {
            response_flags.push("\\Recent".to_string());
            response_flags.sort();
            response_flags.dedup();
        }
        let items = [
            Some(format!("FLAGS ({})", response_flags.join(" "))),
            Some(uid_item),
            modseq_item,
        ]
        .into_iter()
        .flatten()
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
        response = response.data(format!("{prefix} ({})", items.join(" ")));
    }
    let mut completion = StatusLine::tagged(tag, Status::Ok, format!("{command} completed"));
    if !modified.is_empty() {
        completion = completion.with_code(format!("MODIFIED {}", compress_ids(&modified)));
    }
    let mut response = response.status(completion);
    if let Some(code) = limited {
        response = response.with_message_limit(code);
    }
    Outcome {
        response,
        flag_updates: applied,
        condstore_activated,
    }
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

/// Apply a STORE, leaving alone the flags the rights do not allow changing
/// (RFC 4314 section 4: a STORE succeeds if any requested flag may change).
fn apply_permitted(
    existing: Vec<String>,
    mode: StoreMode,
    requested: &[String],
    rights: rmail_common::acl::Rights,
) -> Vec<String> {
    if rights == rmail_common::acl::Rights::ALL {
        return apply_operation(existing, mode, requested);
    }
    let permitted = |flag: &String| crate::shared::permitted_flag(rights, flag);
    let fixed = existing
        .iter()
        .filter(|flag| !permitted(flag))
        .cloned()
        .collect::<Vec<_>>();
    let requested = requested
        .iter()
        .filter(|flag| permitted(flag))
        .cloned()
        .collect::<Vec<_>>();
    let mut flags = apply_operation(existing, mode, &requested);
    flags.retain(|flag| permitted(flag));
    flags.extend(fixed);
    flags.sort();
    flags.dedup();
    flags
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

fn outcome(response: Response) -> Outcome {
    Outcome {
        response,
        flag_updates: Vec::new(),
        condstore_activated: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_changes_only_the_flags_the_rights_allow() {
        let rights = rmail_common::acl::Rights::parse("lrs").unwrap();
        let existing = vec!["\\Flagged".to_string()];
        let requested = vec!["\\Seen".to_string(), "\\Deleted".to_string()];
        assert_eq!(
            apply_permitted(existing.clone(), StoreMode::Replace, &requested, rights),
            vec!["\\Flagged".to_string(), "\\Seen".to_string()]
        );
        assert_eq!(
            apply_permitted(
                existing,
                StoreMode::Remove,
                &["\\Flagged".to_string()],
                rights
            ),
            vec!["\\Flagged".to_string()]
        );
    }

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
            StoreContext::default(),
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
            StoreContext::default(),
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
