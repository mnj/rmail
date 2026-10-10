//! Composing: sending, drafts, scheduled sending (undo send and send
//! later), identities and signatures, compose preferences, address
//! suggestions and quoting. Messages go out through this server's
//! submission service as the signed-in user (see `crate::submit`); a copy
//! goes to Sent. Scheduled messages wait in `rmail_common::hold` until the
//! outbound worker releases them.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::Engine;
use rmail_common::compose::{self, Outgoing, OutgoingAttachment};
use rmail_common::compose_html::{self, DataImages};
use rmail_common::{compose_store, hold, imap_state};
use serde::{Deserialize, Serialize};

use super::{Session, Shared, blocking, internal_error};
use crate::jmap::identity;

/// Largest message webmail sends; the submission service accepts 10 MiB.
pub(crate) const MAX_MESSAGE_BYTES: usize = 10 * 1024 * 1024;
const MAX_RECIPIENTS: usize = 100;
/// Largest signature kept (it may hold a small inline logo).
const MAX_SIGNATURE_BYTES: usize = 256 * 1024;
/// Address suggestions returned for one query.
const MAX_SUGGESTIONS: usize = 8;
/// Sent messages searched for the copy of a scheduled message on cancel.
const SENT_SEARCH: usize = 500;

pub(crate) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/send", post(send))
        .route("/api/drafts", post(save_draft))
        .route("/api/scheduled", get(scheduled))
        .route("/api/scheduled/{id}/cancel", post(cancel_scheduled))
        .route("/api/identities", get(identities))
        .route("/api/identities/{id}", put(update_identity))
        .route(
            "/api/compose/settings",
            get(compose_settings).put(save_compose_settings),
        )
        .route("/api/contacts", get(contacts))
        .route(
            "/api/folders/{folder}/messages/{uid}/compose",
            get(compose_source),
        )
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
    /// The body as HTML (from the editor); when present it replaces `text`,
    /// which is then generated from it.
    #[serde(default)]
    html: Option<String>,
    /// The identity to send as; the account's own address by default.
    #[serde(default)]
    identity_id: Option<String>,
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
    /// Hold the message this many seconds so it can be undone.
    #[serde(default)]
    delay: Option<u32>,
    /// Send at this time (Unix seconds) instead of now.
    #[serde(default)]
    send_at: Option<i64>,
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

/// The user's identities (creating the default one the first time).
fn load_identities(state: &Shared, session: &Session) -> anyhow::Result<Vec<identity::Identity>> {
    let conn =
        rmail_common::jmap::store::open(&state.mail_root, &session.domain, &session.localpart)?;
    identity::list(&conn, &session.address)
}

/// `Name <address>`, or the bare address without a name.
fn mailbox(name: &str, email: &str) -> String {
    let name: String = name
        .chars()
        .filter(|c| !c.is_control() && !"<>\"".contains(*c))
        .collect();
    if name.trim().is_empty() {
        email.to_string()
    } else {
        format!("{} <{email}>", name.trim())
    }
}

/// The From header and envelope sender: the chosen identity (identities
/// only ever hold the user's own address or aliases that deliver to them),
/// else the account's own address with its identity's name.
fn sender(
    state: &Shared,
    session: &Session,
    identity_id: Option<&str>,
) -> anyhow::Result<(String, String)> {
    let identities = load_identities(state, session)?;
    let chosen = match identity_id {
        Some(id) => Some(
            identities
                .iter()
                .find(|identity| identity.id == id)
                .ok_or_else(|| anyhow::anyhow!("no such identity"))?,
        ),
        None => identities
            .iter()
            .find(|identity| identity.email.eq_ignore_ascii_case(&session.address)),
    };
    Ok(match chosen {
        Some(identity) => (
            mailbox(&identity.name, &identity.email),
            identity.email.clone(),
        ),
        None => (session.address.clone(), session.address.clone()),
    })
}

/// Turn the request into a message from the signed-in user; also returns
/// the envelope sender.
fn outgoing(
    state: &Shared,
    session: &Session,
    input: ComposeRequest,
) -> anyhow::Result<(Outgoing, String, Option<Source>, Option<u64>)> {
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
    let (from, mail_from) = sender(state, session, input.identity_id.as_deref())?;
    let mut message = Outgoing {
        from,
        to: input.to,
        cc: input.cc,
        bcc: input.bcc,
        subject: input.subject,
        text: input.text,
        in_reply_to: input.in_reply_to,
        references: input.references,
        attachments,
        ..Default::default()
    };
    if let Some(html) = input.html.filter(|html| !html.trim().is_empty()) {
        message.set_html(&html);
    }
    Ok((message, mail_from, input.source, input.draft_uid))
}

fn rejected(status: StatusCode, message: impl Into<String>) -> Response {
    (status, message.into()).into_response()
}

/// When a message asked to be held should go: `None` for now.
fn release_time(delay: Option<u32>, send_at: Option<i64>) -> Result<Option<i64>, String> {
    let now = chrono::Utc::now().timestamp();
    let at = match (delay, send_at) {
        (_, Some(at)) => at,
        (Some(delay), None) => now + i64::from(delay.min(compose_store::MAX_UNDO_SECONDS)),
        (None, None) => return Ok(None),
    };
    if at - now > hold::MAX_HOLD_SECONDS {
        return Err("messages can be scheduled at most 30 days ahead".to_string());
    }
    Ok((at > now).then_some(at))
}

#[derive(Serialize)]
struct Scheduled {
    id: String,
    send_at: i64,
    recipients: Vec<String>,
    subject: String,
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
    let release_at = match release_time(input.delay, input.send_at) {
        Ok(at) => at,
        Err(error) => return rejected(StatusCode::UNPROCESSABLE_ENTITY, error),
    };
    let prepared = {
        let (state, session) = (state.clone(), session.clone());
        blocking(move || {
            let (message, mail_from, source, draft) = outgoing(&state, &session, input)?;
            let recipients = message.envelope_recipients()?;
            let wire = compose::build(&message, false, None)?;
            let copy = compose::build(&message, true, Some(&wire.message_id))?;
            let named: Vec<String> = message
                .to
                .iter()
                .chain(&message.cc)
                .chain(&message.bcc)
                .cloned()
                .collect();
            Ok((
                recipients,
                mail_from,
                wire,
                copy,
                source,
                draft,
                named,
                message.subject,
            ))
        })
        .await
    };
    let (recipients, mail_from, wire, copy, source, draft, named, subject) = match prepared {
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
    let mut scheduled = None;
    if let Some(release_at) = release_at {
        let held = {
            let (state, session, recipients) = (state.clone(), session.clone(), recipients.clone());
            let (mail_from, data) = (mail_from.clone(), wire.bytes.clone());
            blocking(move || {
                if hold::count_for(&state.mail_root, &session.address)? >= hold::MAX_HELD_PER_USER {
                    anyhow::bail!("too many scheduled messages");
                }
                hold::hold(
                    &state.mail_root,
                    hold::Held {
                        id: String::new(),
                        user: session.address.clone(),
                        mail_from,
                        recipients,
                        release_at,
                        submission_id: None,
                        last_error: None,
                    },
                    &data,
                )
            })
            .await
        };
        match held {
            Ok(held) => {
                scheduled = Some(Scheduled {
                    id: held.id,
                    send_at: held.release_at,
                    recipients: held.recipients,
                    subject,
                })
            }
            Err(error) => {
                return rejected(StatusCode::UNPROCESSABLE_ENTITY, format!("{error:#}"));
            }
        }
    } else if let Err(error) = crate::submit::submit_as(
        address,
        &state.mail_root,
        &session.address,
        &mail_from,
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
    webmail_log!("info", if scheduled.is_some() { "message_scheduled" } else { "message_sent" }, { "address": session.address, "recipients": recipients.len(), "message_id": wire.message_id });
    // The message is out (or waiting); keeping a copy and tidying up are
    // best effort.
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
        let _ = compose_store::record_recipients(root, domain, local, &named);
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
    Json(serde_json::json!({
        "message_id": message_id,
        "saved_copy": kept.is_ok(),
        "scheduled": scheduled,
    }))
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
        let (message, _, _, previous) = outgoing(&state, &session, input)?;
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

// ---------------------------------------------------------------------------
// Scheduled messages

/// The signed-in user's waiting messages, soonest first.
async fn scheduled(app: State<Shared>, headers: HeaderMap) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let result = blocking(move || {
        let mut out = Vec::new();
        for held in hold::waiting_for(&state.mail_root, &session.address)? {
            let subject = hold::message(&state.mail_root, &held.id)?
                .map(|data| rmail_common::mime::parse_message(&data).subject)
                .unwrap_or_default();
            out.push(Scheduled {
                id: held.id,
                send_at: held.release_at,
                recipients: held.recipients,
                subject,
            });
        }
        Ok(out)
    })
    .await;
    match result {
        Ok(list) => Json(list).into_response(),
        Err(error) => internal_error(error),
    }
}

/// The Message-ID header of a message, if any.
fn message_id_of(data: &[u8]) -> String {
    rmail_common::mime::parse_message(data)
        .message_id
        .trim()
        .to_string()
}

/// Stop a waiting message and turn it back into a draft: its Sent copy
/// (which keeps Bcc) moves to Drafts. Answers with the draft's location.
async fn cancel_scheduled(
    app: State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let result = blocking(move || {
        let root = &state.mail_root;
        let Ok(Some(held)) = hold::get(root, &id) else {
            return Ok(Err(StatusCode::NOT_FOUND));
        };
        if !held.user.eq_ignore_ascii_case(&session.address) {
            return Ok(Err(StatusCode::NOT_FOUND));
        }
        let Some(data) = hold::message(root, &id)? else {
            return Ok(Err(StatusCode::CONFLICT));
        };
        if !hold::cancel(root, &id)? {
            // Released in the meantime.
            return Ok(Err(StatusCode::CONFLICT));
        }
        let (domain, local) = (&session.domain, &session.localpart);
        let message_id = message_id_of(&data);
        let sent = special_folder(root, domain, local, "\\Sent", "Sent")?;
        let (_, messages) = imap_state::load_folder(root, domain, local, &sent)?;
        let copy = messages.iter().rev().take(SENT_SEARCH).find_map(|message| {
            let bytes = std::fs::read(&message.path).ok()?;
            (!message_id.is_empty() && message_id_of(&bytes) == message_id)
                .then_some((message.uid, bytes))
        });
        let drafts = special_folder(root, domain, local, "\\Drafts", "Drafts")?;
        let draft = copy.as_ref().map_or(&data, |(_, bytes)| bytes);
        let (_, uid) = imap_state::append_message(
            root,
            domain,
            local,
            &drafts,
            draft,
            vec!["\\Draft".to_string(), "\\Seen".to_string()],
        )?;
        if let Some((sent_uid, _)) = copy {
            let _ = imap_state::delete_message_by_uid(root, domain, local, &sent, sent_uid);
        }
        Ok(Ok((drafts, uid)))
    })
    .await;
    match result {
        Ok(Ok((folder, uid))) => {
            Json(serde_json::json!({ "folder": folder, "uid": uid })).into_response()
        }
        Ok(Err(StatusCode::CONFLICT)) => {
            rejected(StatusCode::CONFLICT, "the message has already been sent")
        }
        Ok(Err(status)) => status.into_response(),
        Err(error) => internal_error(error),
    }
}

// ---------------------------------------------------------------------------
// Identities, signatures and preferences

#[derive(Serialize)]
struct IdentityView {
    id: String,
    name: String,
    email: String,
    text_signature: String,
    html_signature: String,
}

async fn identities(app: State<Shared>, headers: HeaderMap) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    match blocking(move || load_identities(&state, &session)).await {
        Ok(list) => Json(
            list.into_iter()
                .map(|identity| IdentityView {
                    id: identity.id,
                    name: identity.name,
                    email: identity.email,
                    text_signature: identity.text_signature,
                    html_signature: identity.html_signature,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => internal_error(error),
    }
}

#[derive(Deserialize)]
struct IdentityUpdate {
    #[serde(default)]
    name: String,
    #[serde(default)]
    text_signature: String,
    #[serde(default)]
    html_signature: String,
}

/// Clean a signature: HTML through the compose cleaner (images may stay
/// inline), and the text taken from it when there is HTML.
fn clean_signature(text: &str, html: &str) -> Result<(String, String), &'static str> {
    let html = compose_html::clean(
        html,
        compose_html::Options {
            remote_images: true,
            data_images: DataImages::Keep,
        },
    )
    .html;
    let html = if compose_html::to_text(&html).trim().is_empty() && !html.contains("<img") {
        String::new()
    } else {
        html
    };
    let text = if html.is_empty() {
        text.replace("\r\n", "\n").trim_end().to_string()
    } else {
        compose_html::to_text(&html).trim_end().to_string()
    };
    if html.len() > MAX_SIGNATURE_BYTES || text.len() > MAX_SIGNATURE_BYTES {
        return Err("the signature is too large (images count too)");
    }
    Ok((text, html))
}

async fn update_identity(
    app: State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<IdentityUpdate>(&body) else {
        return rejected(StatusCode::BAD_REQUEST, "invalid json");
    };
    let (text, html) = match clean_signature(&input.text_signature, &input.html_signature) {
        Ok(cleaned) => cleaned,
        Err(error) => return rejected(StatusCode::PAYLOAD_TOO_LARGE, error),
    };
    let name: String = input
        .name
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    let result = blocking(move || {
        let conn =
            rmail_common::jmap::store::open(&state.mail_root, &session.domain, &session.localpart)?;
        identity::list(&conn, &session.address)?;
        identity::update_signature(&conn, &id, name.trim(), &text, &html)
    })
    .await;
    match result {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => internal_error(error),
    }
}

async fn compose_settings(app: State<Shared>, headers: HeaderMap) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    match blocking(move || {
        let prefs = compose_store::prefs(&state.mail_root, &session.domain, &session.localpart)?;
        // Whether writing suggestions can be offered, and where the draft
        // would go; the endpoint's key and full URL stay on the server.
        let config = rmail_common::settings::open(&state.db_path)
            .and_then(|conn| rmail_common::settings::compose_ai(&conn))
            .unwrap_or_default();
        Ok(ComposeSettings {
            ai: AiAvailability {
                available: config.available(),
                provider: config.available().then(|| config.host()).flatten(),
            },
            prefs,
        })
    })
    .await
    {
        Ok(settings) => Json(settings).into_response(),
        Err(error) => internal_error(error),
    }
}

#[derive(Serialize)]
struct AiAvailability {
    available: bool,
    /// Host name of the AI service, told to users when they opt in.
    provider: Option<String>,
}

#[derive(Serialize)]
struct ComposeSettings {
    #[serde(flatten)]
    prefs: compose_store::Prefs,
    ai: AiAvailability,
}

async fn save_compose_settings(app: State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(prefs) = serde_json::from_slice::<compose_store::Prefs>(&body) else {
        return rejected(StatusCode::BAD_REQUEST, "invalid json");
    };
    match blocking(move || {
        compose_store::set_prefs(&state.mail_root, &session.domain, &session.localpart, prefs)
    })
    .await
    {
        Ok(prefs) => Json(prefs).into_response(),
        Err(error) => internal_error(error),
    }
}

#[derive(Deserialize)]
struct ContactQuery {
    #[serde(default)]
    q: String,
}

/// People to suggest while typing an address.
async fn contacts(
    app: State<Shared>,
    headers: HeaderMap,
    Query(query): Query<ContactQuery>,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let needle: String = query.q.chars().take(100).collect();
    match blocking(move || {
        compose_store::suggestions(
            &state.mail_root,
            &session.domain,
            &session.localpart,
            &needle,
            MAX_SUGGESTIONS,
        )
    })
    .await
    {
        Ok(list) => Json(list).into_response(),
        Err(error) => internal_error(error),
    }
}

#[derive(Deserialize)]
struct SourceQuery {
    #[serde(default)]
    remote_content: Option<String>,
}

/// A stored message's HTML body cleaned for the editor (a quote, a
/// forward, or a draft to continue): inline images as data URLs, remote
/// images only when the user chose to load them.
async fn compose_source(
    app: State<Shared>,
    headers: HeaderMap,
    Path((folder, uid)): Path<(String, String)>,
    Query(query): Query<SourceQuery>,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(uid) = uid.parse::<u64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let remote_images = query.remote_content.as_deref() == Some("1");
    let result = blocking(move || {
        let location = super::locate(&state, &session, &folder)?;
        let (_, messages) = imap_state::load_folder(
            &state.mail_root,
            &location.domain,
            &location.localpart,
            &location.folder,
        )?;
        let message = messages
            .into_iter()
            .find(|message| message.uid == uid)
            .ok_or_else(|| anyhow::anyhow!("no such message"))?;
        let parsed = rmail_common::mime::parse_message(&std::fs::read(&message.path)?);
        Ok(parsed.html_body.map(|html| {
            compose_html::clean(
                &html,
                compose_html::Options {
                    remote_images,
                    data_images: DataImages::Keep,
                },
            )
            .html
            .trim()
            .to_string()
        }))
    })
    .await;
    match result {
        Ok(html) => Json(serde_json::json!({ "html": html })).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_times_are_bounded() {
        let now = chrono::Utc::now().timestamp();
        assert_eq!(release_time(None, None), Ok(None));
        let undo = release_time(Some(10), None).unwrap().unwrap();
        assert!((now + 9..=now + 11).contains(&undo));
        let capped = release_time(Some(100_000), None).unwrap().unwrap();
        assert!(capped <= now + 61);
        assert_eq!(release_time(None, Some(now - 100)), Ok(None), "past is now");
        assert!(release_time(None, Some(now + 40 * 86400)).is_err());
    }

    #[test]
    fn signatures_are_cleaned() {
        let (text, html) = clean_signature(
            "ignored",
            "<div><b>Ann</b> | <a href=\"https://example.test\" onclick=\"x()\">example.test</a></div><script>x()</script>",
        )
        .unwrap();
        assert_eq!(
            html,
            "<div><b>Ann</b> | <a href=\"https://example.test\">example.test</a></div>"
        );
        assert_eq!(text, "Ann | example.test <https://example.test>");
        let (text, html) = clean_signature("Ann\r\nExample\r\n", "<div><br></div>").unwrap();
        assert_eq!((text.as_str(), html.as_str()), ("Ann\nExample", ""));
        assert!(clean_signature("x".repeat(MAX_SIGNATURE_BYTES + 1).as_str(), "").is_err());
    }
}
