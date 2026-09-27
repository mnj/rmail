//! REPLACE and UID REPLACE (RFC 8508).
//!
//! The new message is read like an APPEND (synchronizing, LITERAL+/LITERAL-
//! and `literal8` data, UTF8 and CATENATE) into a staging file; storage then
//! publishes it in the target mailbox and expunges the old message from the
//! selected mailbox in one index transaction, so either both happen or
//! neither does. The session reports the result like MOVE: an untagged
//! `OK [APPENDUID]`, `EXISTS` when the target is the selected mailbox, then
//! `EXPUNGE` (or `VANISHED` with QRESYNC) for the old message.

use std::path::Path;

use anyhow::Result;
use tokio::io::{AsyncReadExt, BufReader};

use super::append::{
    CatenateError, LiteralStreamError, bounded_internal_date, catenate_error_response,
    create_append_stage, split_catenate_args, stream_catenate_parts, stream_literal_to_stage,
    write_response,
};
use crate::{
    AsyncStream, MAX_APPEND_LITERAL_BYTES,
    mailbox::{self, SelectedMailbox},
    parser,
    response::{Response, Status, StatusLine},
};

type Reader = BufReader<Box<dyn AsyncStream + Send + 'static>>;

pub(crate) enum Outcome {
    /// The command failed and its tagged response was sent.
    Failed { close_connection: bool },
    /// The new message is stored; the caller reports the rest.
    Replaced(Replaced),
}

pub(crate) struct Replaced {
    pub(crate) uidvalidity: u64,
    pub(crate) uid: u64,
    /// UID of the replaced message, if it was still there to expunge.
    pub(crate) expunged_uid: Option<u64>,
    /// The target mailbox is the selected mailbox.
    pub(crate) target_is_selected: bool,
}

pub(crate) struct Context<'a> {
    pub(crate) mail_root: &'a str,
    pub(crate) address: &'a str,
    pub(crate) selected: &'a SelectedMailbox,
    pub(crate) uid_mode: bool,
    pub(crate) utf8_accept: bool,
}

/// The new message's arguments: either one literal or CATENATE parts.
enum Payload {
    Literal(parser::AppendRequest),
    Catenate(parser::AppendRequest, String),
}

impl Payload {
    fn request(&self) -> &parser::AppendRequest {
        match self {
            Self::Literal(request) | Self::Catenate(request, _) => request,
        }
    }
}

pub(crate) async fn handle(
    reader: &mut Reader,
    tag: &str,
    name: &str,
    raw_args: &str,
    context: Context<'_>,
) -> Result<Outcome> {
    let raw_args = raw_args.trim();
    let (message_id, append_args) = raw_args
        .split_once(|character: char| character.is_ascii_whitespace())
        .map(|(id, rest)| (id, rest.trim_start()))
        .unwrap_or((raw_args, ""));

    let payload = match split_catenate_args(append_args) {
        Some((prefix, parts)) => match parser::parse_append_args(&format!("{prefix} {{0+}}")) {
            Ok(request) if !request.utf8 => Payload::Catenate(request, parts.to_string()),
            _ => return reject(reader, None, bad(tag, "Invalid CATENATE arguments")).await,
        },
        None => match parser::parse_append_args(append_args) {
            Ok(request) => Payload::Literal(request),
            Err(parser::ParseError::InvalidDateTime) => {
                return reject(
                    reader,
                    None,
                    bad(tag, &format!("Invalid {name} internal date")),
                )
                .await;
            }
            Err(_) => {
                return reject(reader, None, bad(tag, &format!("Invalid {name} arguments"))).await;
            }
        },
    };
    let request = payload.request();
    let literal = match &payload {
        Payload::Literal(request) => Some(request),
        Payload::Catenate(..) => None,
    };

    if let Payload::Literal(request) = &payload
        && request.literal_len > MAX_APPEND_LITERAL_BYTES
    {
        // A synchronizing literal is simply refused. The data of an
        // oversized non-synchronizing literal is already on its way and is
        // not read, so the command stream cannot be trusted afterwards.
        write_response(
            reader,
            Response::new().status(
                StatusLine::tagged(tag, Status::No, format!("{name} literal too large"))
                    .with_code("TOOBIG"),
            ),
        )
        .await?;
        return Ok(Outcome::Failed {
            close_connection: request.non_sync,
        });
    }
    if request.utf8 && !context.utf8_accept {
        return reject(reader, literal, bad(tag, "UTF8=ACCEPT is not enabled")).await;
    }
    let Some(source_uid) = resolve_message(message_id, context.selected, context.uid_mode) else {
        let response = if !valid_message_id(message_id) {
            bad(tag, &format!("Invalid {name} arguments"))
        } else if context.uid_mode {
            Response::new().status(StatusLine::tagged(
                tag,
                Status::No,
                "No such message to replace",
            ))
        } else {
            bad(tag, "Invalid message sequence number")
        };
        return reject(reader, literal, response).await;
    };
    if context.selected.read_only {
        return reject(
            reader,
            literal,
            Response::new().status(
                StatusLine::tagged(tag, Status::No, "Mailbox is read-only").with_code("READ-ONLY"),
            ),
        )
        .await;
    }
    if context.selected.is_expunged(source_uid) {
        return reject(
            reader,
            literal,
            Response::new().status(
                StatusLine::tagged(tag, Status::No, "The message to replace no longer exists")
                    .with_code("EXPUNGEISSUED"),
            ),
        )
        .await;
    }
    let target = match mailbox::decode_wire_mailbox_name(&request.mailbox, context.utf8_accept) {
        Ok(target) => target,
        Err(_) => return reject(reader, literal, bad(tag, "Invalid mailbox name")).await,
    };
    let (local, domain) = match mailbox::address_parts(context.address) {
        Ok(parts) => parts,
        Err(error) => return reject(reader, literal, unavailable(tag, name, error)).await,
    };
    match target_exists(context.mail_root, &domain, &local, &target).await {
        Ok(true) => {}
        Ok(false) => return reject(reader, literal, missing_mailbox(tag)).await,
        Err(error) => return reject(reader, literal, unavailable(tag, name, error)).await,
    }

    // Read the new message into a staging file.
    let staged_path = create_append_stage(context.mail_root, &domain, &local).await?;
    let request = match payload {
        Payload::Literal(request) => {
            if !request.non_sync {
                write_response(
                    reader,
                    Response::new().continuation("Ready for literal data"),
                )
                .await?;
            }
            if let Err(error) =
                stream_literal_to_stage(reader, &staged_path, request.literal_len, request.utf8)
                    .await
            {
                let _ = tokio::fs::remove_file(&staged_path).await;
                let response = match error {
                    LiteralStreamError::InvalidUtf8 => Response::new().status(
                        StatusLine::tagged(tag, Status::No, "Invalid UTF-8 message")
                            .with_code("UTF8"),
                    ),
                    LiteralStreamError::Io(error) => {
                        unavailable(tag, name, format!("Error reading literal: {error}"))
                    }
                };
                write_response(reader, response).await?;
                return Ok(failed());
            }
            if reader
                .buffer()
                .first()
                .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
            {
                // REPLACE takes exactly one message (no MULTIAPPEND).
                let _ = tokio::fs::remove_file(&staged_path).await;
                let _ = crate::read_bounded_line(reader, crate::MAX_AUTHENTICATED_LINE_BYTES).await;
                write_response(reader, bad(tag, &format!("Invalid {name} arguments"))).await?;
                return Ok(failed());
            }
            request
        }
        Payload::Catenate(request, parts) => {
            match stream_catenate_parts(
                reader,
                &parts,
                &staged_path,
                context.mail_root,
                &domain,
                &local,
                Some(context.selected.mailbox.as_str()),
            )
            .await
            {
                Ok(tail) if tail.is_empty() => request,
                Ok(_) => {
                    let _ = tokio::fs::remove_file(&staged_path).await;
                    write_response(reader, bad(tag, &format!("Invalid {name} arguments"))).await?;
                    return Ok(failed());
                }
                Err(error) => {
                    let _ = tokio::fs::remove_file(&staged_path).await;
                    let close_connection = matches!(error, CatenateError::TooBigDesynchronized);
                    write_response(reader, catenate_error_response(tag, error)).await?;
                    return Ok(Outcome::Failed { close_connection });
                }
            }
        }
    };

    let root = context.mail_root.to_string();
    let source = context.selected.mailbox.clone();
    let target_for_task = target.clone();
    let cleanup_path = staged_path.clone();
    let staged = rmail_common::imap_state::StagedAppend {
        path: staged_path,
        flags: request.flags,
        internal_date: bounded_internal_date(request.internal_date),
    };
    let result = tokio::task::spawn_blocking(move || {
        rmail_common::imap_state::replace_message(
            Path::new(&root),
            &domain,
            &local,
            &source,
            source_uid,
            &target_for_task,
            staged,
        )
    })
    .await;
    let _ = tokio::fs::remove_file(&cleanup_path).await;
    let error = match result {
        Ok(Ok(outcome)) => {
            return Ok(Outcome::Replaced(Replaced {
                uidvalidity: outcome.uidvalidity,
                uid: outcome.uid,
                expunged_uid: outcome.expunged.then_some(source_uid),
                target_is_selected: same_mailbox(&target, &context.selected.mailbox),
            }));
        }
        Ok(Err(error)) => error,
        Err(error) => anyhow::Error::from(error),
    };
    let response = if error
        .downcast_ref::<rmail_common::imap_state::StorageQuotaExceeded>()
        .is_some()
    {
        Response::new().status(
            StatusLine::tagged(tag, Status::No, format!("{name} exceeds storage quota"))
                .with_code("OVERQUOTA"),
        )
    } else if error.to_string().contains("does not exist") {
        missing_mailbox(tag)
    } else {
        unavailable(tag, name, error)
    };
    write_response(reader, response).await?;
    Ok(failed())
}

/// The UID of the message a REPLACE names, if it is in the selected view.
fn resolve_message(message_id: &str, selected: &SelectedMailbox, uid_mode: bool) -> Option<u64> {
    if !valid_message_id(message_id) {
        return None;
    }
    if uid_mode {
        let uid = if message_id == "*" {
            selected.msgs.iter().map(|message| message.0).max()?
        } else {
            message_id.parse().ok()?
        };
        selected
            .msgs
            .iter()
            .any(|message| message.0 == uid)
            .then_some(uid)
    } else {
        let sequence = if message_id == "*" {
            selected.msgs.len()
        } else {
            message_id.parse().ok()?
        };
        selected
            .msgs
            .get(sequence.checked_sub(1)?)
            .map(|message| message.0)
    }
}

/// `seq-number` (RFC 3501): a non-zero 32-bit number or `*`.
fn valid_message_id(message_id: &str) -> bool {
    message_id == "*"
        || (message_id.bytes().all(|byte| byte.is_ascii_digit())
            && !message_id.starts_with('0')
            && message_id
                .parse::<u64>()
                .is_ok_and(|value| (1..=u64::from(u32::MAX)).contains(&value)))
}

fn same_mailbox(left: &str, right: &str) -> bool {
    left == right || (left.eq_ignore_ascii_case("INBOX") && right.eq_ignore_ascii_case("INBOX"))
}

async fn target_exists(mail_root: &str, domain: &str, local: &str, target: &str) -> Result<bool> {
    let root = mail_root.to_string();
    let domain = domain.to_string();
    let local = local.to_string();
    let target = target.to_string();
    tokio::task::spawn_blocking(move || {
        rmail_common::imap_state::folder_exists(Path::new(&root), &domain, &local, &target)
    })
    .await?
}

/// Send a failure before the message data was read. A synchronizing literal
/// is never sent by the client without a continuation, but the data of a
/// non-synchronizing one is already on its way and is skipped here.
async fn reject(
    reader: &mut Reader,
    literal: Option<&parser::AppendRequest>,
    response: Response,
) -> Result<Outcome> {
    if let Some(request) = literal.filter(|request| request.non_sync) {
        let mut remaining = (&mut *reader).take(request.literal_len as u64);
        let skipped = tokio::io::copy(&mut remaining, &mut tokio::io::sink()).await?;
        if skipped != request.literal_len as u64 {
            return Ok(Outcome::Failed {
                close_connection: true,
            });
        }
    }
    write_response(reader, response).await?;
    Ok(failed())
}

fn failed() -> Outcome {
    Outcome::Failed {
        close_connection: false,
    }
}

fn bad(tag: &str, text: &str) -> Response {
    Response::new().status(StatusLine::tagged(tag, Status::Bad, text))
}

fn missing_mailbox(tag: &str) -> Response {
    Response::new().status(
        StatusLine::tagged(tag, Status::No, "Mailbox does not exist").with_code("TRYCREATE"),
    )
}

fn unavailable(tag: &str, name: &str, error: impl std::fmt::Display) -> Response {
    Response::new().status(
        StatusLine::tagged(tag, Status::No, format!("{name} failed: {error}"))
            .with_code("UNAVAILABLE"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_ids_follow_seq_number_syntax() {
        for valid in ["1", "42", "*", "4294967295"] {
            assert!(valid_message_id(valid), "{valid}");
        }
        for invalid in ["", "0", "01", "1:2", "1,2", "$", "-1", "4294967296", "x"] {
            assert!(!valid_message_id(invalid), "{invalid}");
        }
    }

    #[test]
    fn same_mailbox_treats_inbox_case_insensitively() {
        assert!(same_mailbox("inbox", "INBOX"));
        assert!(same_mailbox("Drafts", "Drafts"));
        assert!(!same_mailbox("drafts", "Drafts"));
    }
}
