//! Sending and drafts. Messages go out through this server's submission
//! service as the signed-in user (see `crate::submit`); a copy goes to Sent.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine;
use rmail_common::compose::{self, Outgoing, OutgoingAttachment};
use rmail_common::imap_state;
use serde::Deserialize;

use super::{Session, Shared, blocking, internal_error};

/// Largest message webmail sends; the submission service accepts 10 MiB.
pub(crate) const MAX_MESSAGE_BYTES: usize = 10 * 1024 * 1024;
const MAX_RECIPIENTS: usize = 100;

pub(crate) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/send", post(send))
        .route("/api/drafts", post(save_draft))
}

#[derive(Deserialize)]
struct UploadedAttachment {
    filename: String,
    #[serde(default)]
    content_type: String,
    /// Base64.
    data: String,
}

/// An attachment of a stored message, included without uploading it again
/// (forwarding, or a draft's attachments).
#[derive(Deserialize)]
struct StoredAttachment {
    folder: String,
    uid: u64,
    index: usize,
}

/// The message being replied to or forwarded; marked after sending.
#[derive(Deserialize)]
struct Source {
    folder: String,
    uid: u64,
    /// `reply` or `forward`.
    kind: String,
}

#[derive(Deserialize)]
struct ComposeRequest {
    #[serde(default)]
    to: Vec<String>,
    #[serde(default)]
    cc: Vec<String>,
    #[serde(default)]
    bcc: Vec<String>,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    in_reply_to: Option<String>,
    #[serde(default)]
    references: Option<String>,
    #[serde(default)]
    attachments: Vec<UploadedAttachment>,
    #[serde(default)]
    stored_attachments: Vec<StoredAttachment>,
    #[serde(default)]
    source: Option<Source>,
    /// The draft this message replaces (removed once sent or re-saved).
    #[serde(default)]
    draft_uid: Option<u64>,
}

/// The account's folder with special-use `attribute`, else one named
/// `fallback`, created when missing.
fn special_folder(
    root: &std::path::Path,
    domain: &str,
    local: &str,
    attribute: &str,
    fallback: &str,
) -> anyhow::Result<String> {
    let folders = imap_state::list_folders(root, domain, local)?;
    if let Some(folder) = folders
        .iter()
        .find(|f| f.special_use.as_deref() == Some(attribute))
        .or_else(|| {
            folders
                .iter()
                .find(|f| f.name.eq_ignore_ascii_case(fallback))
        })
    {
        return Ok(folder.name.clone());
    }
    imap_state::create_folder_with_special_use(root, domain, local, fallback, Some(attribute))?;
    Ok(fallback.to_string())
}

/// Turn the request into a message from the signed-in user.
fn outgoing(
    state: &Shared,
    session: &Session,
    input: ComposeRequest,
) -> anyhow::Result<(Outgoing, Option<Source>, Option<u64>)> {
    let mut attachments = Vec::new();
    for upload in input.attachments {
        let data = base64::engine::general_purpose::STANDARD
            .decode(upload.data.as_bytes())
            .map_err(|_| anyhow::anyhow!("attachment {} is not valid base64", upload.filename))?;
        attachments.push(OutgoingAttachment {
            filename: upload.filename,
            content_type: upload.content_type,
            data,
        });
    }
    for stored in input.stored_attachments {
        // Forwarded attachments may come from a folder shared with the user.
        let location = super::locate(state, session, &stored.folder)?;
        let (_, messages) = imap_state::load_folder(
            &state.mail_root,
            &location.domain,
            &location.localpart,
            &location.folder,
        )?;
        let message = messages
            .into_iter()
            .find(|message| message.uid == stored.uid)
            .ok_or_else(|| anyhow::anyhow!("the original message is gone"))?;
        let (meta, data) =
            rmail_common::mime::attachment_data(&std::fs::read(&message.path)?, stored.index)
                .ok_or_else(|| anyhow::anyhow!("the original attachment is gone"))?;
        attachments.push(OutgoingAttachment {
            filename: meta.filename,
            content_type: meta.content_type,
            data,
        });
    }
    let message = Outgoing {
        from: session.address.clone(),
        to: input.to,
        cc: input.cc,
        bcc: input.bcc,
        subject: input.subject,
        text: input.text,
        in_reply_to: input.in_reply_to,
        references: input.references,
        attachments,
        calendar: None,
    };
    Ok((message, input.source, input.draft_uid))
}

fn rejected(status: StatusCode, message: impl Into<String>) -> Response {
    (status, message.into()).into_response()
}

async fn send(app: State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<ComposeRequest>(&body) else {
        return rejected(StatusCode::BAD_REQUEST, "invalid json");
    };
    let Some(address) = state.submission else {
        return rejected(
            StatusCode::CONFLICT,
            "sending is not set up on this server (no submission listener)",
        );
    };
    let prepared = {
        let (state, session) = (state.clone(), session.clone());
        blocking(move || {
            let (message, source, draft) = outgoing(&state, &session, input)?;
            let recipients = message.envelope_recipients()?;
            let wire = compose::build(&message, false, None)?;
            let copy = compose::build(&message, true, Some(&wire.message_id))?;
            Ok((recipients, wire, copy, source, draft))
        })
        .await
    };
    let (recipients, wire, copy, source, draft) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => return rejected(StatusCode::UNPROCESSABLE_ENTITY, format!("{error:#}")),
    };
    if recipients.is_empty() {
        return rejected(
            StatusCode::UNPROCESSABLE_ENTITY,
            "add at least one recipient",
        );
    }
    if recipients.len() > MAX_RECIPIENTS {
        return rejected(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("at most {MAX_RECIPIENTS} recipients"),
        );
    }
    if wire.bytes.len() > MAX_MESSAGE_BYTES {
        return rejected(
            StatusCode::PAYLOAD_TOO_LARGE,
            "the message is larger than 10 MB",
        );
    }
    if let Err(error) = crate::submit::submit(
        address,
        &state.mail_root,
        &session.address,
        &recipients,
        &wire.bytes,
    )
    .await
    {
        return match error.downcast_ref::<crate::submit::Refused>() {
            Some(refused) => rejected(StatusCode::UNPROCESSABLE_ENTITY, refused.to_string()),
            None => rejected(StatusCode::BAD_GATEWAY, format!("{error:#}")),
        };
    }
    webmail_log!("info", "message_sent", { "address": session.address, "recipients": recipients.len(), "message_id": wire.message_id });
    // The message is out; keeping a copy and tidying up are best effort.
    let message_id = wire.message_id.clone();
    let kept = blocking(move || {
        let (root, domain, local) = (&state.mail_root, &session.domain, &session.localpart);
        let sent = special_folder(root, domain, local, "\\Sent", "Sent")?;
        imap_state::append_message(
            root,
            domain,
            local,
            &sent,
            &copy.bytes,
            vec!["\\Seen".to_string()],
        )?;
        if let Some(uid) = draft {
            let drafts = special_folder(root, domain, local, "\\Drafts", "Drafts")?;
            let _ = imap_state::delete_message_by_uid(root, domain, local, &drafts, uid);
        }
        // Marking the original needs the write right in a shared folder.
        if let Some(source) = source
            && let Ok(location) = super::locate(&state, &session, &source.folder)
            && location.rights.contains(rmail_common::acl::Rights::WRITE)
        {
            let flag = if source.kind == "forward" {
                "$Forwarded"
            } else {
                "\\Answered"
            };
            let _ = rmail_common::classifier_store::set_keyword(
                root,
                &location.domain,
                &location.localpart,
                &location.folder,
                source.uid,
                flag,
                true,
            );
        }
        Ok(())
    })
    .await;
    if let Err(error) = &kept {
        webmail_log!("warn", "sent_copy_failed", { "error": format!("{error:#}") });
    }
    Json(serde_json::json!({ "message_id": message_id, "saved_copy": kept.is_ok() }))
        .into_response()
}

async fn save_draft(app: State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<ComposeRequest>(&body) else {
        return rejected(StatusCode::BAD_REQUEST, "invalid json");
    };
    let result = blocking(move || {
        let (message, _, previous) = outgoing(&state, &session, input)?;
        let built = compose::build(&message, true, None)?;
        if built.bytes.len() > MAX_MESSAGE_BYTES {
            anyhow::bail!("the draft is larger than 10 MB");
        }
        let (root, domain, local) = (&state.mail_root, &session.domain, &session.localpart);
        let drafts = special_folder(root, domain, local, "\\Drafts", "Drafts")?;
        let (_, uid) = imap_state::append_message(
            root,
            domain,
            local,
            &drafts,
            &built.bytes,
            vec!["\\Draft".to_string(), "\\Seen".to_string()],
        )?;
        if let Some(previous) = previous {
            let _ = imap_state::delete_message_by_uid(root, domain, local, &drafts, previous);
        }
        Ok((drafts, uid))
    })
    .await;
    match result {
        Ok((folder, uid)) => {
            Json(serde_json::json!({ "folder": folder, "uid": uid })).into_response()
        }
        Err(error) if error.to_string().contains("larger than") => {
            rejected(StatusCode::PAYLOAD_TOO_LARGE, error.to_string())
        }
        Err(error) => internal_error(error),
    }
}
