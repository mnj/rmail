use std::{collections::HashMap, path::PathBuf};

use anyhow::Result;
use tokio::io::{AsyncWriteExt, BufReader};

use crate::{
    AsyncStream,
    commands::search::compress_ids,
    mailbox::{self, SelectedMailbox},
    parser,
    response::{Response, Status, StatusLine},
};

/// Session state that shapes FETCH responses.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct FetchContext {
    pub(crate) qresync: bool,
    pub(crate) condstore: bool,
    pub(crate) imap4rev2: bool,
    /// RFC 9586: responses are UIDFETCH.
    pub(crate) uidonly: bool,
    /// RFC 9738 MESSAGELIMIT.
    pub(crate) message_limit: Option<usize>,
}

#[derive(Default)]
pub(crate) struct Outcome {
    /// Flags this FETCH changed (implicit \Seen) as (uid, flags, modseq).
    pub(crate) flag_updates: Vec<(u64, Vec<String>, u64)>,
    /// The command used MODSEQ or CHANGEDSINCE, which enables CONDSTORE.
    pub(crate) condstore_activated: bool,
}

struct Target {
    sequence: usize,
    uid: u64,
    path: PathBuf,
    flags: Vec<String>,
    modseq: u64,
    internal_date: (i64, i32),
    save_date: i64,
    email_id: String,
}

pub(crate) async fn handle(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    tag: &str,
    raw_args: &str,
    mail_root: &str,
    selected: &SelectedMailbox,
    saved_uids: &[u64],
    uid_mode: bool,
    context: FetchContext,
) -> Result<Outcome> {
    let command = if uid_mode { "UID FETCH" } else { "FETCH" };
    let request = match parser::parse_fetch_command_request(raw_args) {
        Ok(request) => request,
        Err(_) => {
            write_status(
                reader,
                StatusLine::tagged(tag, Status::Bad, format!("Invalid {command} arguments")),
            )
            .await?;
            return Ok(Outcome::default());
        }
    };
    if request.vanished && !uid_mode {
        write_status(
            reader,
            StatusLine::tagged(tag, Status::Bad, "VANISHED requires UID FETCH"),
        )
        .await?;
        return Ok(Outcome::default());
    }
    // RFC 9394 §3.3: PARTIAL extends UID FETCH only.
    if request.partial.is_some() && !uid_mode {
        write_status(
            reader,
            StatusLine::tagged(tag, Status::Bad, "PARTIAL requires UID FETCH"),
        )
        .await?;
        return Ok(Outcome::default());
    }
    if request.vanished && !context.qresync {
        write_status(
            reader,
            StatusLine::tagged(tag, Status::Bad, "QRESYNC is not enabled"),
        )
        .await?;
        return Ok(Outcome::default());
    }
    // RFC 7162 §3.1: FETCH MODSEQ and CHANGEDSINCE are CONDSTORE-enabling.
    let condstore_activated =
        request.changed_since.is_some() || request.items.iter().any(|item| item == "MODSEQ");
    let condstore = context.condstore || condstore_activated;

    if request.vanished {
        let root = mail_root.to_string();
        let domain = selected.domain.clone();
        let local = selected.local.clone();
        let mailbox_name = selected.mailbox.clone();
        let changed_since = request.changed_since.unwrap_or(0);
        let changes = tokio::task::spawn_blocking(move || {
            rmail_common::imap_state::qresync_changes(
                std::path::Path::new(&root),
                &domain,
                &local,
                &mailbox_name,
                changed_since,
                None,
            )
        })
        .await??;
        let vanished = filter_vanished(
            &request.message_set,
            changes.vanished_uids,
            selected,
            saved_uids,
        );
        if !vanished.is_empty() {
            let response = Response::new()
                .data(format!("VANISHED (EARLIER) {}", compress_ids(&vanished)))
                .encode();
            reader.get_mut().write_all(response.as_bytes()).await?;
        }
    }

    let (mut targets, expunged_requested) =
        collect_targets(&request, selected, saved_uids, uid_mode);
    // RFC 9738: a PARTIAL page larger than the limit is refused; otherwise
    // the newest messages are fetched and the client continues below them.
    if request.partial.is_some()
        && let Some(code) = crate::commands::limit::exceeded(targets.len(), context.message_limit)
    {
        write_status(
            reader,
            StatusLine::tagged(tag, Status::No, "PARTIAL range exceeds the message limit")
                .with_code(code),
        )
        .await?;
        return Ok(Outcome::default());
    }
    let limited =
        crate::commands::limit::truncate_by(&mut targets, context.message_limit, |target| {
            target.uid
        });
    if limited.is_some() {
        targets.sort_unstable_by_key(|target| target.sequence);
    }
    let mark_seen = fetch_marks_seen(&request.items) && !selected.read_only;
    let seen_updates = if mark_seen {
        targets
            .iter_mut()
            .filter_map(|target| {
                if target
                    .flags
                    .iter()
                    .any(|flag| flag.eq_ignore_ascii_case("\\Seen"))
                {
                    return None;
                }
                target.flags.push("\\Seen".to_string());
                target.flags.sort();
                target.flags.dedup();
                Some((target.uid, target.flags.clone()))
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let mut flag_updates = Vec::new();
    if !seen_updates.is_empty() {
        let root = mail_root.to_string();
        let domain = selected.domain.clone();
        let local = selected.local.clone();
        let mailbox_name = selected.mailbox.clone();
        let updates = seen_updates.clone();
        let modseqs = match tokio::task::spawn_blocking(move || {
            rmail_common::imap_state::set_uid_flags_batch(
                std::path::Path::new(&root),
                &domain,
                &local,
                &mailbox_name,
                &updates,
            )
        })
        .await?
        {
            Ok(modseqs) => modseqs.into_iter().collect::<HashMap<_, _>>(),
            Err(error) => {
                write_status(
                    reader,
                    StatusLine::tagged(tag, Status::No, format!("{command} failed: {error}"))
                        .with_code("UNAVAILABLE"),
                )
                .await?;
                return Ok(Outcome {
                    condstore_activated,
                    ..Outcome::default()
                });
            }
        };
        for target in &mut targets {
            if let Some(modseq) = modseqs.get(&target.uid) {
                target.modseq = *modseq;
                flag_updates.push((target.uid, target.flags.clone(), *modseq));
            }
        }
    }
    let outcome = Outcome {
        flag_updates,
        condstore_activated,
    };

    let flags_requested = request.items.iter().any(|item| item == "FLAGS");
    let modseq_requested = request.items.iter().any(|item| item == "MODSEQ");
    for target in targets {
        let mut response_flags = target.flags.clone();
        if !context.imap4rev2 && selected.recent_uids.contains(&target.uid) {
            response_flags.push("\\Recent".to_string());
            response_flags.sort();
            response_flags.dedup();
        }
        // RFC 3501 §6.4.5: flags changed by an implicit \Seen SHOULD be
        // returned; RFC 7162 §3.1: with CONDSTORE every untagged FETCH
        // carries MODSEQ.
        let seen_changed = outcome
            .flag_updates
            .iter()
            .any(|(uid, _, _)| *uid == target.uid);
        let add_flags = seen_changed && !flags_requested;
        let add_modseq = condstore && !modseq_requested;
        let extended_items;
        let items = if add_flags || add_modseq {
            let mut items = request.items.clone();
            if add_flags {
                items.push("FLAGS".to_string());
            }
            if add_modseq {
                items.push("MODSEQ".to_string());
            }
            extended_items = items;
            &extended_items
        } else {
            &request.items
        };
        if let Err(error) = mailbox::write_fetch_response(
            reader,
            target.sequence,
            target.uid,
            &response_flags,
            target.modseq,
            target.internal_date,
            target.save_date,
            &target.email_id,
            target.path,
            items,
            &request.raw_items,
            uid_mode || condstore,
            context.uidonly,
        )
        .await
        {
            write_status(
                reader,
                StatusLine::tagged(tag, Status::No, format!("Error reading message: {error}"))
                    .with_code("UNAVAILABLE"),
            )
            .await?;
            return Ok(outcome);
        }
    }
    let completion = if expunged_requested {
        // RFC 2180 §4.1.2 / RFC 9051 EXPUNGEISSUED: the data of messages
        // expunged by another session is omitted until the expunge can be
        // reported.
        StatusLine::tagged(
            tag,
            Status::No,
            "Some of the requested messages no longer exist",
        )
        .with_code("EXPUNGEISSUED")
    } else {
        StatusLine::tagged(tag, Status::Ok, format!("{command} completed"))
    };
    let mut response = Response::new().status(completion);
    if let Some(code) = limited {
        response = response.with_message_limit(code);
    }
    reader
        .get_mut()
        .write_all(response.encode().as_bytes())
        .await?;
    reader.get_mut().flush().await?;
    Ok(outcome)
}

/// The messages addressed by the request, and whether any addressed message
/// was expunged by another session and is only kept for its sequence number.
fn collect_targets(
    request: &parser::FetchCommandRequest,
    selected: &SelectedMailbox,
    saved_uids: &[u64],
    uid_mode: bool,
) -> (Vec<Target>, bool) {
    let star = if uid_mode {
        selected.uidnext.saturating_sub(1)
    } else {
        selected.msgs.len() as u64
    };
    let set = parser::SequenceSet::parse(&request.message_set, star);
    let mut expunged_requested = false;
    let addressed = selected
        .msgs
        .iter()
        .enumerate()
        .filter(|(index, (uid, _, _, _))| {
            if request.message_set == "$" {
                return saved_uids.binary_search(uid).is_ok();
            }
            set.as_ref()
                .is_some_and(|set| set.contains(if uid_mode { *uid } else { *index as u64 + 1 }))
        })
        .collect::<Vec<_>>();
    // RFC 9394 §3.3/§3.4: PARTIAL picks positions among the addressed
    // messages first; CHANGEDSINCE then filters that page.
    let addressed = match request.partial {
        Some(range) => range.select(&addressed),
        None => &addressed[..],
    };
    let targets = addressed
        .iter()
        .copied()
        .filter(|(_, (uid, _, _, _))| {
            if selected.is_expunged(*uid) {
                expunged_requested = true;
                return false;
            }
            true
        })
        .filter(|(_, (_, _, _, modseq))| {
            request
                .changed_since
                .is_none_or(|threshold| *modseq > threshold)
        })
        .map(|(index, (uid, path, flags, modseq))| Target {
            sequence: index + 1,
            uid: *uid,
            path: path.clone(),
            flags: flags.clone(),
            modseq: *modseq,
            internal_date: selected.internal_dates.get(uid).copied().unwrap_or((0, 0)),
            save_date: selected.save_dates.get(uid).copied().unwrap_or(0),
            email_id: selected.email_ids.get(uid).cloned().unwrap_or_default(),
        })
        .collect();
    (targets, expunged_requested)
}

fn filter_vanished(
    message_set: &str,
    vanished: Vec<u64>,
    selected: &SelectedMailbox,
    saved_uids: &[u64],
) -> Vec<u64> {
    if message_set == "$" {
        return vanished
            .into_iter()
            .filter(|uid| saved_uids.binary_search(uid).is_ok())
            .collect();
    }
    let max_uid = vanished
        .iter()
        .copied()
        .chain(selected.msgs.iter().map(|message| message.0))
        .max()
        .unwrap_or_else(|| selected.uidnext.saturating_sub(1));
    parser::SequenceSet::parse(message_set, max_uid).map_or_else(Vec::new, |set| {
        vanished
            .into_iter()
            .filter(|uid| set.contains(*uid))
            .collect()
    })
}

pub(crate) fn fetch_marks_seen(items: &[String]) -> bool {
    items.iter().any(|item| {
        item == "RFC822"
            || item == "RFC822.TEXT"
            || (item.starts_with("BODY[") && item.contains(']'))
            || (item.starts_with("BINARY[") && item.contains(']'))
    })
}

async fn write_status(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    line: StatusLine,
) -> Result<()> {
    let response = Response::new().status(line).encode();
    reader.get_mut().write_all(response.as_bytes()).await?;
    reader.get_mut().flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peek_and_metadata_fetches_do_not_mark_seen() {
        assert!(!fetch_marks_seen(&["FLAGS".to_string()]));
        assert!(!fetch_marks_seen(&["BODY.PEEK[]".to_string()]));
        assert!(fetch_marks_seen(&["BODY[]".to_string()]));
        assert!(fetch_marks_seen(&["RFC822.TEXT".to_string()]));
    }
}
