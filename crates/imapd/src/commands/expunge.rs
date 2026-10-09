use std::{collections::HashSet, path::Path};

use crate::{
    commands::search::compress_ids,
    mailbox::SelectedMailbox,
    parser::{self, ImapArg},
    response::{Response, Status, StatusLine},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SelectionEffect {
    Keep,
    /// The listed UIDs were expunged and reported to the client.
    Remove(Vec<u64>),
    Clear,
}

pub(crate) struct Outcome {
    pub(crate) response: Response,
    pub(crate) selection_effect: SelectionEffect,
}

pub(crate) async fn expunge(
    tag: &str,
    mail_root: &str,
    selected: &SelectedMailbox,
    qresync_enabled: bool,
) -> Outcome {
    run(
        tag,
        "EXPUNGE",
        mail_root,
        selected,
        None,
        qresync_enabled,
        false,
    )
    .await
}

pub(crate) async fn uid_expunge(
    tag: &str,
    raw_args: &str,
    mail_root: &str,
    selected: &SelectedMailbox,
    saved_uids: &[u64],
    qresync_enabled: bool,
    message_limit: Option<usize>,
) -> Outcome {
    let uid_set = match parse_uid_set(raw_args) {
        Some(uid_set) => uid_set,
        None => return failure(bad(tag, "Invalid UID EXPUNGE arguments")),
    };
    let requested: HashSet<u64> = if uid_set == "$" {
        saved_uids.iter().copied().collect()
    } else {
        parser::uids_from_set(&uid_set, &selected.msgs)
            .into_iter()
            .collect()
    };
    // RFC 9738 §3.1: only \Deleted messages count towards the limit.
    let mut deleted = selected
        .msgs
        .iter()
        .filter(|(uid, _, flags, _)| {
            requested.contains(uid)
                && flags
                    .iter()
                    .any(|flag| flag.eq_ignore_ascii_case("\\Deleted"))
        })
        .map(|(uid, _, _, _)| *uid)
        .collect::<Vec<_>>();
    let limited = crate::commands::limit::truncate(&mut deleted, message_limit);
    let mut outcome = run(
        tag,
        "UID EXPUNGE",
        mail_root,
        selected,
        Some(deleted.into_iter().collect()),
        qresync_enabled,
        false,
    )
    .await;
    if let Some(code) = limited {
        outcome.response = outcome.response.with_message_limit(code);
    }
    outcome
}

pub(crate) async fn close(tag: &str, mail_root: &str, selected: &SelectedMailbox) -> Outcome {
    // RFC 4314 section 4: without the expunge right CLOSE only closes.
    if selected.read_only || !selected.rights.contains(rmail_common::acl::Rights::EXPUNGE) {
        return Outcome {
            response: completed(tag, "CLOSE"),
            selection_effect: SelectionEffect::Clear,
        };
    }
    run(tag, "CLOSE", mail_root, selected, None, false, true).await
}

async fn run(
    tag: &str,
    command: &str,
    mail_root: &str,
    selected: &SelectedMailbox,
    requested: Option<HashSet<u64>>,
    qresync_enabled: bool,
    silent: bool,
) -> Outcome {
    if selected.read_only {
        return failure(Response::new().status(StatusLine::tagged(
            tag,
            Status::No,
            "Mailbox is read-only",
        )));
    }
    if !selected.rights.contains(rmail_common::acl::Rights::EXPUNGE) {
        return failure(
            Response::new().status(
                StatusLine::tagged(tag, Status::No, "Permission denied").with_code("NOPERM"),
            ),
        );
    }
    let mut deleted = selected
        .msgs
        .iter()
        .enumerate()
        .filter_map(|(index, (uid, _, flags, _))| {
            (flags
                .iter()
                .any(|flag| flag.eq_ignore_ascii_case("\\Deleted"))
                && requested
                    .as_ref()
                    .is_none_or(|requested| requested.contains(uid)))
            .then_some((index + 1, *uid))
        })
        .collect::<Vec<_>>();
    deleted.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.0));
    let deleted_uids = deleted.iter().map(|(_, uid)| *uid).collect::<Vec<_>>();
    let root = mail_root.to_string();
    let domain = selected.domain.clone();
    let local = selected.local.clone();
    let mailbox = selected.mailbox.clone();
    let delete_result = tokio::task::spawn_blocking(move || {
        rmail_common::imap_state::delete_messages_by_uid(
            Path::new(&root),
            &domain,
            &local,
            &mailbox,
            &deleted_uids,
        )
    })
    .await;
    match delete_result {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => return failure(unavailable(tag, command, error)),
        Err(error) => return failure(unavailable(tag, command, error)),
    }

    let mut response = Response::new();
    if !silent && qresync_enabled && !deleted.is_empty() {
        let mut uids = deleted.iter().map(|(_, uid)| *uid).collect::<Vec<_>>();
        uids.sort_unstable();
        response = response.data(format!("VANISHED {}", compress_ids(&uids)));
    } else if !silent {
        for (sequence, _) in &deleted {
            response = response.data(format!("{sequence} EXPUNGE"));
        }
    }
    Outcome {
        response: response.status(StatusLine::tagged(
            tag,
            Status::Ok,
            format!("{command} completed"),
        )),
        selection_effect: if silent {
            SelectionEffect::Clear
        } else {
            SelectionEffect::Remove(deleted.iter().map(|(_, uid)| *uid).collect())
        },
    }
}

fn parse_uid_set(raw_args: &str) -> Option<String> {
    let arguments = parser::parse_imap_args(raw_args).ok()?;
    let [ImapArg::Atom(uid_set)] = arguments.as_slice() else {
        return None;
    };
    if uid_set != "$" && parser::SequenceSet::parse(uid_set, 1).is_none() {
        return None;
    }
    Some(uid_set.clone())
}

fn completed(tag: &str, command: &str) -> Response {
    Response::new().status(StatusLine::tagged(
        tag,
        Status::Ok,
        format!("{command} completed"),
    ))
}

fn bad(tag: &str, text: &str) -> Response {
    Response::new().status(StatusLine::tagged(tag, Status::Bad, text))
}

fn unavailable(tag: &str, command: &str, error: impl std::fmt::Display) -> Response {
    Response::new().status(
        StatusLine::tagged(tag, Status::No, format!("{command} failed: {error}"))
            .with_code("UNAVAILABLE"),
    )
}

fn failure(response: Response) -> Outcome {
    Outcome {
        response,
        selection_effect: SelectionEffect::Keep,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_set_parser_is_exact_and_supports_searchres() {
        assert_eq!(parse_uid_set("1:4"), Some("1:4".to_string()));
        assert_eq!(parse_uid_set("$"), Some("$".to_string()));
        assert_eq!(parse_uid_set("1:4 trailing"), None);
        assert_eq!(parse_uid_set("bogus"), None);
    }
}
