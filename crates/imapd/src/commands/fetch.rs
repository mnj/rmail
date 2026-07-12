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

pub(crate) struct Outcome {
    pub(crate) refresh_selected: bool,
}

struct Target {
    sequence: usize,
    uid: u64,
    path: PathBuf,
    flags: Vec<String>,
    modseq: u64,
    internal_date: (i64, i32),
    save_date: i64,
}

pub(crate) async fn handle(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    tag: &str,
    raw_args: &str,
    mail_root: &str,
    selected: &SelectedMailbox,
    saved_uids: &[u64],
    uid_mode: bool,
    qresync_enabled: bool,
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
            return Ok(Outcome {
                refresh_selected: false,
            });
        }
    };
    if request.vanished && !uid_mode {
        write_status(
            reader,
            StatusLine::tagged(tag, Status::Bad, "VANISHED requires UID FETCH"),
        )
        .await?;
        return Ok(Outcome {
            refresh_selected: false,
        });
    }
    if request.vanished && !qresync_enabled {
        write_status(
            reader,
            StatusLine::tagged(tag, Status::Bad, "QRESYNC is not enabled"),
        )
        .await?;
        return Ok(Outcome {
            refresh_selected: false,
        });
    }

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

    let mut targets = collect_targets(&request, selected, saved_uids, uid_mode);
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
                    refresh_selected: false,
                });
            }
        };
        for target in &mut targets {
            if let Some(modseq) = modseqs.get(&target.uid) {
                target.modseq = *modseq;
            }
        }
    }

    for target in targets {
        let mut response_flags = target.flags.clone();
        if selected.recent_uids.contains(&target.uid) {
            response_flags.push("\\Recent".to_string());
            response_flags.sort();
            response_flags.dedup();
        }
        if let Err(error) = mailbox::write_fetch_response(
            reader,
            target.sequence,
            target.uid,
            &response_flags,
            target.modseq,
            target.internal_date,
            target.save_date,
            target.path,
            &request.items,
            &request.raw_items,
            uid_mode,
        )
        .await
        {
            write_status(
                reader,
                StatusLine::tagged(tag, Status::No, format!("Error reading message: {error}"))
                    .with_code("UNAVAILABLE"),
            )
            .await?;
            return Ok(Outcome {
                refresh_selected: !seen_updates.is_empty(),
            });
        }
    }
    write_status(
        reader,
        StatusLine::tagged(tag, Status::Ok, format!("{command} completed")),
    )
    .await?;
    Ok(Outcome {
        refresh_selected: !seen_updates.is_empty(),
    })
}

fn collect_targets(
    request: &parser::FetchCommandRequest,
    selected: &SelectedMailbox,
    saved_uids: &[u64],
    uid_mode: bool,
) -> Vec<Target> {
    selected
        .msgs
        .iter()
        .enumerate()
        .filter(|(index, (uid, _, _, _))| {
            if request.message_set == "$" {
                return saved_uids.binary_search(uid).is_ok();
            }
            let star = if uid_mode {
                selected.uidnext.saturating_sub(1)
            } else {
                selected.msgs.len() as u64
            };
            parser::SequenceSet::parse(&request.message_set, star)
                .is_some_and(|set| set.contains(if uid_mode { *uid } else { *index as u64 + 1 }))
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
        })
        .collect()
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

fn fetch_marks_seen(items: &[String]) -> bool {
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
