//! Webmail HTTP API: an axum router over the account's Maildir state.
//! Sessions are signed cookies bound to the mailbox password hash.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use axum::body::Bytes;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use rmail_common::acl::{self, Rights};
use rmail_common::http::Peer;
use rmail_common::throttle::AuthThrottle;
use rmail_common::{auth, db, imap_state, websession};
use serde::{Deserialize, Serialize};

use rmail_common::mime::{
    Attachment, attachment_data, has_remote_content, parse_message, sanitize_email_html, snippet,
};

mod compose;
mod organize;

const SESSION_COOKIE: &str = "rmail_webmail";
const SESSION_TTL_SECS: u64 = 12 * 60 * 60;
/// Room for a 10 MiB message as base64 attachments in JSON.
pub(crate) const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
/// State-changing requests must carry this header; browsers cannot add it to
/// cross-site form posts.
pub(crate) const CSRF_HEADER: &str = "x-rmail-webmail";
/// Policy for the web app itself. Message HTML is rendered in a sandboxed
/// srcdoc iframe that inherits this policy and adds its own, stricter one.
pub(crate) const APP_CSP: &str = "default-src 'self'; img-src * data: blob:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; frame-src 'self' about:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'";

pub(crate) struct AppState {
    pub mail_root: PathBuf,
    pub db_path: PathBuf,
    pub static_dir: PathBuf,
    pub session_secret: Vec<u8>,
    pub secure_cookies: bool,
    pub throttle: AuthThrottle,
    pub revoked: websession::RevocationList,
    /// Loopback address of this server's submission service; `None` when
    /// no usable submission listener is configured (sending is off).
    pub submission: Option<std::net::SocketAddr>,
    /// Bearer token validation for JMAP, when OAuth is configured.
    pub oauth: Option<rmail_common::oauth::OAuthValidator>,
    /// JMAP clients authenticate every request; recent checks are cached.
    pub jmap_logins: crate::jmap::LoginCache,
    /// Becomes true when the server shuts down; long-lived responses (JMAP
    /// push) end then instead of holding up the shutdown.
    pub shutdown: Option<tokio::sync::watch::Receiver<bool>>,
}

type Shared = Arc<AppState>;

pub(crate) fn router(state: Shared) -> Router {
    let app = Router::new()
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/session", get(session_info))
        .route("/api/folders", get(folders).post(create_folder))
        .route(
            "/api/folders/{folder}",
            axum::routing::patch(rename_folder).delete(delete_folder),
        )
        .route(
            "/api/folders/{folder}/sharing",
            get(folder_sharing).put(change_folder_sharing),
        )
        .route("/api/folders/{folder}/messages", get(message_list))
        .route(
            "/api/folders/{folder}/messages/{uid}",
            get(message_detail).patch(patch_message),
        )
        .route(
            "/api/folders/{folder}/messages/{uid}/attachments/{index}",
            get(attachment),
        )
        .route("/api/folders/{folder}/messages/{uid}/raw", get(raw_message))
        .route(
            "/api/folders/{folder}/messages/{uid}/ai",
            post(organize::ai_action),
        )
        .route("/api/folders/{folder}/messages/bulk", post(bulk))
        .merge(organize::routes())
        .merge(compose::routes())
        .merge(crate::jmap::routes())
        .merge(crate::dav::routes())
        .fallback(fallback)
        .layer(middleware::from_fn(reject_cross_site))
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn(log_request))
        .with_state(state);
    rmail_common::http::harden(app, MAX_BODY_BYTES)
}

// ---------------------------------------------------------------------------
// Middleware

async fn log_request(request: Request, next: Next) -> Response {
    let request_id = rmail_common::tracking::new_tracking_id("webmail-http");
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let peer = request
        .extensions()
        .get::<Peer>()
        .and_then(|peer| peer.0)
        .map(|address| address.to_string());
    let response = next.run(request).await;
    webmail_log!("info", "request_completed", { "request_id": request_id, "peer": peer, "method": method.as_str(), "path": path, "status": response.status().as_u16() });
    response
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in [
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::CACHE_CONTROL, "no-store"),
        (header::CONTENT_SECURITY_POLICY, APP_CSP),
    ] {
        headers
            .entry(name)
            .or_insert(HeaderValue::from_static(value));
    }
    response
}

async fn reject_cross_site(request: Request, next: Next) -> Response {
    if request.uri().path().starts_with("/api/")
        && !matches!(*request.method(), Method::GET | Method::HEAD)
        && !request.headers().contains_key(CSRF_HEADER)
    {
        return (StatusCode::FORBIDDEN, "missing CSRF header").into_response();
    }
    next.run(request).await
}

async fn fallback(app: State<Shared>, method: Method, uri: Uri) -> Response {
    let state = app.0;
    if uri.path().starts_with("/api/") {
        StatusCode::NOT_FOUND.into_response()
    } else if method == Method::GET {
        crate::assets::spa(&state.static_dir, uri.path())
    } else {
        StatusCode::METHOD_NOT_ALLOWED.into_response()
    }
}

async fn blocking<T, F>(work: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| anyhow::anyhow!("background task failed: {error}"))?
}

fn internal_error(error: anyhow::Error) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
}

// ---------------------------------------------------------------------------
// Sessions

/// The signed-in mailbox. Extracting it rejects the request with 401 unless
/// the cookie is valid, not logged out, and bound to the current password.
#[derive(Debug, Clone)]
pub(crate) struct Session {
    pub address: String,
    pub domain: String,
    pub localpart: String,
}

impl Session {
    /// The signed-in mailbox for a request, or 401. Handlers call this
    /// rather than taking `Session` as a parameter: the account then comes
    /// from the mailbox database, not from request data, which keeps
    /// CodeQL's taint analysis from treating every storage path as tainted.
    pub(crate) async fn signed_in(
        state: &AppState,
        headers: &HeaderMap,
    ) -> Result<Self, StatusCode> {
        let token = session_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;
        if state.revoked.is_revoked(token) {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let session =
            websession::verify(&state.session_secret, token).ok_or(StatusCode::UNAUTHORIZED)?;
        split_address(&session.subject).ok_or(StatusCode::UNAUTHORIZED)?;
        let db_path = state.db_path.clone();
        let address = session.subject.clone();
        let mailbox = blocking(move || db::get_mailbox(&db_path, &address))
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        let mailbox = mailbox.ok_or(StatusCode::UNAUTHORIZED)?;
        let bound = mailbox.password_hash.as_ref().is_some_and(|hash| {
            websession::credential_binding(&state.session_secret, hash) == session.binding
        });
        if !bound {
            return Err(StatusCode::UNAUTHORIZED);
        }
        // Use the stored account, not the cookie's text, for everything after.
        let (localpart, domain) =
            split_address(&mailbox.address.to_ascii_lowercase()).ok_or(StatusCode::UNAUTHORIZED)?;
        Ok(Session {
            address: format!("{localpart}@{domain}"),
            domain,
            localpart,
        })
    }
}

fn session_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookie| websession::cookie_value(cookie, SESSION_COOKIE))
}

fn split_address(address: &str) -> Option<(String, String)> {
    let (local, domain) = address.split_once('@')?;
    if local.is_empty() || domain.is_empty() || local.contains('/') || domain.contains('/') {
        return None;
    }
    Some((local.to_string(), domain.to_string()))
}

fn with_cookie(response: impl IntoResponse, cookie: String) -> Response {
    let mut response = response.into_response();
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

#[cfg(test)]
pub(crate) fn sign_session(state: &AppState, address: &str) -> String {
    let hash = db::get_mailbox(&state.db_path, address)
        .unwrap()
        .and_then(|mailbox| mailbox.password_hash)
        .unwrap();
    let binding = websession::credential_binding(&state.session_secret, &hash);
    websession::sign(&state.session_secret, address, &binding, SESSION_TTL_SECS)
}

#[derive(Deserialize)]
struct LoginRequest {
    address: String,
    password: String,
}

#[derive(Serialize)]
struct SessionResponse {
    address: String,
    /// Whether this server can send mail from webmail.
    can_send: bool,
}

async fn login(app: State<Shared>, Extension(peer): Extension<Peer>, body: Bytes) -> Response {
    let state = app.0;
    let Ok(input) = serde_json::from_slice::<LoginRequest>(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid json").into_response();
    };
    if let Some(remaining) = peer.ip().and_then(|ip| state.throttle.blocked_for(ip)) {
        let mut response = (
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "too many failed sign-in attempts; try again in {} minutes",
                remaining.as_secs().div_ceil(60)
            ),
        )
            .into_response();
        if let Ok(value) = HeaderValue::from_str(&remaining.as_secs().to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        return response;
    }
    // A name SASLprep rejects is empty here and fails the split below.
    let address = auth::normalize_login_name(input.address.trim()).unwrap_or_default();
    let reject = || {
        if let Some(ip) = peer.ip() {
            state.throttle.record_failure(ip);
        }
        rmail_common::metrics::inc_auth_failures();
        (StatusCode::UNAUTHORIZED, "invalid login").into_response()
    };
    let Some((localpart, domain)) = split_address(&address) else {
        auth::burn_password_verification(input.password).await;
        return reject();
    };
    let db_path = state.db_path.clone();
    let lookup = address.clone();
    let hash = blocking(move || db::get_mailbox(&db_path, &lookup))
        .await
        .ok()
        .flatten()
        .and_then(|mailbox| mailbox.password_hash);
    let Some(hash) = hash else {
        // Same cost as a real check so unknown accounts are not revealed.
        auth::burn_password_verification(input.password).await;
        return reject();
    };
    if !matches!(
        auth::verify_password_async(input.password, hash.clone()).await,
        Ok(true)
    ) {
        return reject();
    }
    if let Some(ip) = peer.ip() {
        state.throttle.reset(ip);
    }
    let mail_root = state.mail_root.clone();
    let _ = blocking(move || imap_state::init_account(&mail_root, &domain, &localpart)).await;
    let binding = websession::credential_binding(&state.session_secret, &hash);
    let token = websession::sign(&state.session_secret, &address, &binding, SESSION_TTL_SECS);
    with_cookie(
        Json(SessionResponse {
            address,
            can_send: state.submission.is_some(),
        }),
        websession::set_cookie(
            SESSION_COOKIE,
            &token,
            SESSION_TTL_SECS,
            state.secure_cookies,
            "Strict",
        ),
    )
}

async fn logout(app: State<Shared>, headers: HeaderMap) -> Response {
    let state = app.0;
    if let Some(token) = session_token(&headers)
        && let Some(session) = websession::verify(&state.session_secret, token)
    {
        state.revoked.revoke(token, session.expires_at);
    }
    with_cookie(
        StatusCode::NO_CONTENT,
        websession::set_cookie(SESSION_COOKIE, "", 0, state.secure_cookies, "Strict"),
    )
}

async fn session_info(app: State<Shared>, headers: HeaderMap) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    Json(SessionResponse {
        address: session.address,
        can_send: state.submission.is_some(),
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// Mailbox API

#[derive(Serialize, Deserialize)]
pub(crate) struct FolderResponse {
    pub name: String,
    pub special_use: Option<String>,
    pub messages: usize,
    pub unread: usize,
    /// The account that shared this folder with the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// The user's RFC 4314 rights in a shared folder, e.g. `lrs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rights: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct MessageListItem {
    pub uid: u64,
    pub flags: Vec<String>,
    pub size: u64,
    pub internal_date: i64,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub snippet: String,
    #[serde(default)]
    pub has_attachments: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<organize::SuggestionView>,
    /// The user's labels whose keyword the message carries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<rmail_common::classifier_store::Label>,
}

/// A page of a folder's messages, newest first.
#[derive(Serialize, Deserialize)]
pub(crate) struct MessagePage {
    /// Messages in the folder, or matching the search.
    pub total: usize,
    pub messages: Vec<MessageListItem>,
}

#[derive(Serialize)]
struct MessageDetail {
    uid: u64,
    flags: Vec<String>,
    size: u64,
    internal_date: i64,
    from: String,
    to: String,
    cc: String,
    bcc: String,
    reply_to: String,
    message_id: String,
    in_reply_to: String,
    references: String,
    subject: String,
    date: String,
    attachments: Vec<Attachment>,
    labels: Vec<rmail_common::classifier_store::Label>,
    text_body: String,
    html_body: Option<String>,
    /// The HTML references remote images or styles, which are blocked unless
    /// the reader asks for them (`?remote_content=1`) to prevent tracking.
    has_remote_content: bool,
}

#[derive(Deserialize)]
struct ListQuery {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
    #[serde(default)]
    q: String,
}

fn default_limit() -> usize {
    50
}

#[derive(Deserialize)]
struct DetailQuery {
    #[serde(default)]
    remote_content: Option<String>,
    #[serde(default)]
    inline: Option<String>,
}

#[derive(Deserialize)]
struct PatchMessage {
    seen: Option<bool>,
    /// Keywords (labels) to add (`true`) or remove (`false`). System flags
    /// and `$` keywords are not accepted.
    #[serde(default)]
    keywords: std::collections::BTreeMap<String, bool>,
}

/// A user keyword: a non-empty IMAP atom that is not a system flag or a
/// reserved `$` keyword.
fn is_user_keyword(keyword: &str) -> bool {
    !keyword.is_empty()
        && keyword.len() <= 100
        && !keyword.starts_with(['\\', '$'])
        && keyword
            .chars()
            .all(|c| c.is_ascii_graphic() && !"(){%*\"\\]".contains(c))
}

#[derive(Deserialize)]
struct BulkRequest {
    action: String,
    uids: Vec<u64>,
    /// Folder for `move`.
    #[serde(default)]
    target: Option<String>,
}

/// Most messages one bulk request may touch.
const MAX_BULK: usize = 1000;

async fn folders(app: State<Shared>, headers: HeaderMap) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let result = blocking(move || {
        let mut folders = imap_state::list_folder_summaries(
            &state.mail_root,
            &session.domain,
            &session.localpart,
        )?
        .into_iter()
        .filter(|summary| {
            !summary
                .folder
                .name
                .starts_with(OTHER_USERS.trim_end_matches('/'))
        })
        .map(|summary| FolderResponse {
            name: summary.folder.name,
            special_use: summary.folder.special_use,
            messages: summary.messages,
            unread: summary.unseen,
            owner: None,
            rights: None,
        })
        .collect::<Vec<_>>();
        for shared in acl::shared_mailboxes(&state.mail_root, &state.db_path, &session.address)? {
            if !shared.rights.contains(Rights::READ) {
                continue;
            }
            let Some(summary) = imap_state::folder_summary(
                &state.mail_root,
                &shared.domain,
                &shared.localpart,
                &shared.folder.name,
            )?
            else {
                continue;
            };
            folders.push(FolderResponse {
                name: format!("{OTHER_USERS}{}/{}", shared.owner, shared.folder.name),
                special_use: None,
                messages: summary.messages,
                unread: summary.unseen,
                owner: Some(shared.owner),
                rights: Some(shared.rights.to_string()),
            });
        }
        Ok(folders)
    })
    .await;
    match result {
        Ok(folders) => Json(folders).into_response(),
        Err(error) => internal_error(error),
    }
}

/// Sharing presets offered by webmail, as RFC 4314 rights.
const SHARING_PRESETS: &[(&str, &str)] = &[("read", "lr"), ("edit", "lrswite")];

#[derive(Serialize)]
struct Grant {
    address: String,
    rights: String,
    /// The preset the rights match, if any.
    access: Option<&'static str>,
}

#[derive(Deserialize)]
struct SharingChange {
    address: String,
    /// `read`, `edit` or `none` (stop sharing).
    access: String,
}

/// Who the user's own folder is shared with.
async fn folder_sharing(
    app: State<Shared>,
    headers: HeaderMap,
    Path(folder): Path<String>,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let result = blocking(move || {
        let Some(id) = own_folder_id(&state, &session, &folder)? else {
            return Ok(None);
        };
        let grants = acl::entries(&state.db_path, &session.address, &id)?
            .into_iter()
            .map(|(address, rights)| {
                let rights = rights.to_string();
                let access = SHARING_PRESETS
                    .iter()
                    .find(|(_, preset)| {
                        Rights::parse(preset).is_ok_and(|preset| preset.to_string() == rights)
                    })
                    .map(|(name, _)| *name);
                Grant {
                    address,
                    rights,
                    access,
                }
            })
            .collect::<Vec<_>>();
        Ok(Some(grants))
    })
    .await;
    match result {
        Ok(Some(grants)) => Json(grants).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => internal_error(error),
    }
}

/// Share the user's own folder with another account, change its access or
/// stop sharing it.
async fn change_folder_sharing(
    app: State<Shared>,
    headers: HeaderMap,
    Path(folder): Path<String>,
    body: Bytes,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<SharingChange>(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid json").into_response();
    };
    let rights = match input.access.as_str() {
        "none" => Rights::NONE,
        access => match SHARING_PRESETS.iter().find(|(name, _)| *name == access) {
            Some((_, rights)) => Rights::parse(rights).expect("presets are valid"),
            None => return (StatusCode::BAD_REQUEST, "unknown access").into_response(),
        },
    };
    let result = blocking(move || {
        let Some(id) = own_folder_id(&state, &session, &folder)? else {
            return Ok(Err(StatusCode::NOT_FOUND.into_response()));
        };
        Ok(
            match acl::set_rights(
                &state.db_path,
                &session.address,
                &id,
                input.address.trim(),
                rights,
            ) {
                Ok(()) => Ok(()),
                Err(error) => {
                    Err((StatusCode::UNPROCESSABLE_ENTITY, format!("{error:#}")).into_response())
                }
            },
        )
    })
    .await;
    match result {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(response)) => response,
        Err(error) => internal_error(error),
    }
}

/// The MAILBOXID of the user's own folder `name`.
fn own_folder_id(state: &AppState, session: &Session, name: &str) -> Result<Option<String>> {
    let Ok(name) = stored_folder(&state.mail_root, &session.domain, &session.localpart, name)
    else {
        return Ok(None);
    };
    Ok(
        imap_state::find_folder(&state.mail_root, &session.domain, &session.localpart, &name)?
            .map(|folder| folder.mailbox_id),
    )
}

/// Whether `parsed` matches a webmail search (`needle` is lowercase): the
/// text the index stores for [`search_index::Field::Decoded`].
fn searchable(parsed: &rmail_common::mime::ParsedMessage, needle: &str) -> bool {
    format!(
        "{} {} {} {} {}",
        parsed.from, parsed.to, parsed.cc, parsed.subject, parsed.text_body
    )
    .to_lowercase()
    .contains(needle)
}

/// Messages indexed per search before the rest are scanned.
const INDEX_BUDGET: usize = 1000;

/// Full-text index answers for `needle` in this folder, or `None` to scan (the
/// needle is too short for the index, or the index failed: it is only a cache).
fn decoded_hits(
    mail_root: &std::path::Path,
    domain: &str,
    localpart: &str,
    info: &imap_state::Folder,
    messages: &[imap_state::Message],
    needle: &str,
) -> Option<rmail_common::search_index::Hits> {
    use rmail_common::search_index::{Field, SearchIndex, usable_needle};
    if !usable_needle(Field::Decoded, needle) {
        return None;
    }
    let result = (|| -> anyhow::Result<_> {
        let index = SearchIndex::open(mail_root, domain, localpart)?;
        let files: Vec<(u64, std::path::PathBuf)> = messages
            .iter()
            .map(|message| (message.uid, message.path.clone()))
            .collect();
        index.sync(&info.name, info.uidvalidity, &files, INDEX_BUDGET)?;
        index.query(&info.name, info.uidvalidity, Field::Decoded, needle)
    })();
    match result {
        Ok(hits) => hits,
        Err(error) => {
            webmail_log!("warn", "search_index_unavailable", { "error": format!("{error:#}") });
            None
        }
    }
}

async fn message_list(
    app: State<Shared>,
    headers: HeaderMap,
    Path(folder): Path<String>,
    Query(query): Query<ListQuery>,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let needle = query.q.trim().to_lowercase();
    let limit = query.limit.clamp(1, 200);
    let result = blocking(move || {
        let location = locate(&state, &session, &folder)?;
        let folder = location.folder.clone();
        let (info, mut messages) = imap_state::load_folder(
            &state.mail_root,
            &location.domain,
            &location.localpart,
            &folder,
        )?;
        let mut suggestions = if info.name == "INBOX" && !location.is_shared() {
            organize::pending_for_inbox(
                &state.mail_root,
                &session.domain,
                &session.localpart,
                info.uidvalidity,
            )
        } else {
            Default::default()
        };
        let labels = organize::labels(&state.mail_root, &session.domain, &session.localpart);
        messages.sort_by(|a, b| b.internaldate.cmp(&a.internaldate).then(b.uid.cmp(&a.uid)));
        let read = |message: &imap_state::Message| {
            std::fs::read(&message.path)
                .ok()
                .map(|raw| parse_message(&raw))
        };
        // Without a search only the requested page is read from disk.
        let (total, page): (
            usize,
            Vec<(imap_state::Message, rmail_common::mime::ParsedMessage)>,
        ) = if needle.is_empty() {
            let total = messages.len();
            let page = messages
                .into_iter()
                .skip(query.offset)
                .take(limit)
                .filter_map(|message| read(&message).map(|parsed| (message, parsed)))
                .collect();
            (total, page)
        } else if let Some(hits) = decoded_hits(
            &state.mail_root,
            &location.domain,
            &location.localpart,
            &info,
            &messages,
            &needle,
        ) {
            // Indexed messages are matched without reading them; the rest are
            // scanned as below. Only the requested page is then read from disk.
            let matching: Vec<_> = messages
                .into_iter()
                .filter(|message| match hits.lookup(message.uid) {
                    Some(matches) => matches,
                    None => read(message).is_some_and(|parsed| searchable(&parsed, &needle)),
                })
                .collect();
            let total = matching.len();
            let page = matching
                .into_iter()
                .skip(query.offset)
                .take(limit)
                .filter_map(|message| read(&message).map(|parsed| (message, parsed)))
                .collect();
            (total, page)
        } else {
            let matching: Vec<_> = messages
                .into_iter()
                .filter_map(|message| read(&message).map(|parsed| (message, parsed)))
                .filter(|(_, parsed)| searchable(parsed, &needle))
                .collect();
            let total = matching.len();
            (
                total,
                matching
                    .into_iter()
                    .skip(query.offset)
                    .take(limit)
                    .collect(),
            )
        };
        let messages = page
            .into_iter()
            .map(|(message, parsed)| {
                let labels = labels_for(&labels, &message.flags);
                MessageListItem {
                    uid: message.uid,
                    flags: message.flags,
                    size: message.size,
                    internal_date: message.internaldate,
                    from: parsed.from,
                    to: parsed.to,
                    subject: parsed.subject,
                    snippet: snippet(&parsed.text_body),
                    has_attachments: parsed.attachments.iter().any(|a| !a.inline),
                    suggestion: suggestions.remove(&message.uid),
                    labels,
                }
            })
            .collect();
        Ok(MessagePage { total, messages })
    })
    .await;
    match result {
        Ok(page) => Json(page).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The account's stored name for the folder a request names, so storage is
/// only ever reached with names from the account's own folder list.
pub(crate) fn stored_folder(
    root: &std::path::Path,
    domain: &str,
    local: &str,
    requested: &str,
) -> Result<String> {
    imap_state::list_folders(root, domain, local)?
        .into_iter()
        .find(|folder| {
            folder.name == requested
                || (folder.name == "INBOX" && requested.eq_ignore_ascii_case("INBOX"))
        })
        .map(|folder| folder.name)
        .ok_or_else(|| anyhow::anyhow!("no such folder"))
}

/// Where a folder named by a request is stored, and the user's rights there.
pub(crate) struct Location {
    pub domain: String,
    pub localpart: String,
    pub folder: String,
    pub rights: Rights,
    /// The folder belongs to another account. A grant may hold every right,
    /// so this cannot be told from `rights`.
    pub shared: bool,
}

impl Location {
    pub(crate) fn is_shared(&self) -> bool {
        self.shared
    }
}

/// The prefix of folders other accounts share with the user, as in IMAP.
pub(crate) const OTHER_USERS: &str = "Other Users/";

/// Locate a folder of the user's own, or one shared with them that they
/// may read, named `Other Users/<owner>/<folder>`. Shared folders come from
/// the owner's grants, never from the request alone.
pub(crate) fn locate(state: &AppState, session: &Session, requested: &str) -> Result<Location> {
    if let Some((owner, name)) = requested
        .strip_prefix(OTHER_USERS)
        .and_then(|rest| rest.split_once('/'))
    {
        let shared = acl::find_shared(
            &state.mail_root,
            &state.db_path,
            &session.address,
            owner,
            name,
        )?
        .filter(|shared| shared.rights.contains(Rights::READ))
        .ok_or_else(|| anyhow::anyhow!("no such folder"))?;
        return Ok(Location {
            domain: shared.domain,
            localpart: shared.localpart,
            folder: shared.folder.name,
            rights: shared.rights,
            shared: true,
        });
    }
    Ok(Location {
        domain: session.domain.clone(),
        localpart: session.localpart.clone(),
        folder: stored_folder(
            &state.mail_root,
            &session.domain,
            &session.localpart,
            requested,
        )?,
        rights: Rights::ALL,
        shared: false,
    })
}

/// Bulk actions in a shared folder: flags as the rights allow, and delete
/// (into the owner's Trash) with the delete and expunge rights. Messages
/// are not moved between accounts here.
fn bulk_shared(
    root: &std::path::Path,
    location: &Location,
    input: &BulkRequest,
) -> Result<Result<(), &'static str>> {
    let needed = match input.action.as_str() {
        "mark_read" | "mark_unread" => Rights::SEEN,
        "flag" | "unflag" => Rights::WRITE,
        "delete" => Rights::DELETE_MESSAGES.union(Rights::EXPUNGE),
        _ => return Ok(Err("not possible in a shared folder")),
    };
    if !location.rights.contains(needed) {
        return Ok(Err("not allowed in this shared folder"));
    }
    let (domain, local, folder) = (&location.domain, &location.localpart, &location.folder);
    for uid in &input.uids {
        match input.action.as_str() {
            "mark_read" => update_flag(root, domain, local, folder, *uid, "\\Seen", true)?,
            "mark_unread" => update_flag(root, domain, local, folder, *uid, "\\Seen", false)?,
            "flag" => update_flag(root, domain, local, folder, *uid, "\\Flagged", true)?,
            "unflag" => update_flag(root, domain, local, folder, *uid, "\\Flagged", false)?,
            _ => imap_state::delete_or_trash_message_by_uid(root, domain, local, folder, *uid)?,
        }
    }
    Ok(Ok(()))
}

/// The labels among `labels` whose keyword is in `flags`.
fn labels_for(
    labels: &[rmail_common::classifier_store::Label],
    flags: &[String],
) -> Vec<rmail_common::classifier_store::Label> {
    labels
        .iter()
        .filter(|label| {
            flags
                .iter()
                .any(|flag| flag.eq_ignore_ascii_case(&label.keyword))
        })
        .cloned()
        .collect()
}

async fn message_detail(
    app: State<Shared>,
    headers: HeaderMap,
    Path((folder, uid)): Path<(String, String)>,
    Query(query): Query<DetailQuery>,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(uid) = uid.parse::<u64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let allow_remote = query.remote_content.as_deref() == Some("1");
    let result = blocking(move || {
        let location = locate(&state, &session, &folder)?;
        let folder = location.folder.clone();
        let (_, messages) = imap_state::load_folder(
            &state.mail_root,
            &location.domain,
            &location.localpart,
            &folder,
        )?;
        let message = messages
            .into_iter()
            .find(|message| message.uid == uid)
            .ok_or_else(|| anyhow::anyhow!("no such message"))?;
        let parsed = parse_message(&std::fs::read(&message.path)?);
        let labels = labels_for(
            &organize::labels(&state.mail_root, &session.domain, &session.localpart),
            &message.flags,
        );
        Ok(MessageDetail {
            uid: message.uid,
            flags: message.flags,
            size: message.size,
            internal_date: message.internaldate,
            from: parsed.from,
            to: parsed.to,
            cc: parsed.cc,
            bcc: parsed.bcc,
            reply_to: parsed.reply_to,
            message_id: parsed.message_id,
            in_reply_to: parsed.in_reply_to,
            references: parsed.references,
            subject: parsed.subject,
            date: parsed.date,
            attachments: parsed.attachments,
            labels,
            text_body: parsed.text_body,
            has_remote_content: parsed.html_body.as_deref().is_some_and(has_remote_content),
            html_body: parsed
                .html_body
                .map(|html| sanitize_email_html(&html, allow_remote)),
        })
    })
    .await;
    match result {
        Ok(detail) => Json(detail).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn patch_message(
    app: State<Shared>,
    headers: HeaderMap,
    Path((folder, uid)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(uid) = uid.parse::<u64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(input) = serde_json::from_slice::<PatchMessage>(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid json").into_response();
    };
    if input.keywords.len() > 50 || !input.keywords.keys().all(|k| is_user_keyword(k)) {
        return (StatusCode::BAD_REQUEST, "invalid keyword").into_response();
    }
    let result = blocking(move || {
        let location = locate(&state, &session, &folder)?;
        let folder = location.folder.clone();
        let (_, messages) = imap_state::load_folder(
            &state.mail_root,
            &location.domain,
            &location.localpart,
            &folder,
        )?;
        if (input.seen.is_some() && !location.rights.contains(Rights::SEEN))
            || (!input.keywords.is_empty() && !location.rights.contains(Rights::WRITE))
        {
            return Ok(Some(StatusCode::FORBIDDEN));
        }
        let Some(message) = messages.into_iter().find(|message| message.uid == uid) else {
            return Ok(Some(StatusCode::NOT_FOUND));
        };
        let mut flags = message.flags;
        if let Some(seen) = input.seen {
            set_flag(&mut flags, "\\Seen", seen);
        }
        for (keyword, present) in &input.keywords {
            set_flag(&mut flags, keyword, *present);
        }
        imap_state::set_uid_flags(
            &state.mail_root,
            &location.domain,
            &location.localpart,
            &folder,
            uid,
            flags,
        )?;
        Ok(None)
    })
    .await;
    match result {
        Ok(None) => StatusCode::NO_CONTENT.into_response(),
        Ok(Some(status)) => status.into_response(),
        Err(error) => internal_error(error),
    }
}

async fn bulk(
    app: State<Shared>,
    headers: HeaderMap,
    Path(folder): Path<String>,
    body: Bytes,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<BulkRequest>(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid json").into_response();
    };
    if !matches!(
        input.action.as_str(),
        "mark_read" | "mark_unread" | "flag" | "unflag" | "archive" | "delete" | "junk" | "move"
    ) {
        return (StatusCode::BAD_REQUEST, "unknown action").into_response();
    }
    if input.uids.len() > MAX_BULK {
        return (StatusCode::BAD_REQUEST, "too many messages").into_response();
    }
    let result = blocking(move || {
        let location = locate(&state, &session, &folder)?;
        let folder = location.folder.clone();
        if location.is_shared() {
            return bulk_shared(&state.mail_root, &location, &input);
        }
        let (root, domain, local) = (&state.mail_root, &session.domain, &session.localpart);
        // Destinations come from the account's folder list, never the request.
        let folders = imap_state::list_folders(root, domain, local)?;
        let special = |attribute: &str, fallback: &str| {
            folders
                .iter()
                .find(|f| f.special_use.as_deref() == Some(attribute))
                .or_else(|| {
                    folders
                        .iter()
                        .find(|f| f.name.eq_ignore_ascii_case(fallback))
                })
                .map(|f| f.name.clone())
        };
        let destination = match input.action.as_str() {
            "archive" => {
                Some(special("\\Archive", "Archive").unwrap_or_else(|| "Archive".to_string()))
            }
            "junk" => Some(special("\\Junk", "Junk").unwrap_or_else(|| "Junk".to_string())),
            "move" => {
                let Some(found) = input
                    .target
                    .as_deref()
                    .and_then(|target| folders.iter().find(|f| f.name == target))
                else {
                    return Ok(Err("no such folder"));
                };
                Some(found.name.clone())
            }
            _ => None,
        };
        if let Some(target) = &destination {
            if !folders.iter().any(|f| &f.name == target) {
                imap_state::create_folder(root, domain, local, target)?;
            }
            if target != &folder {
                imap_state::transfer_messages_by_uid(
                    root,
                    domain,
                    local,
                    &folder,
                    &input.uids,
                    target,
                    true,
                )?;
            }
            return Ok(Ok(()));
        }
        for uid in input.uids {
            match input.action.as_str() {
                "mark_read" => update_flag(root, domain, local, &folder, uid, "\\Seen", true)?,
                "mark_unread" => update_flag(root, domain, local, &folder, uid, "\\Seen", false)?,
                "flag" => update_flag(root, domain, local, &folder, uid, "\\Flagged", true)?,
                "unflag" => update_flag(root, domain, local, &folder, uid, "\\Flagged", false)?,
                _ => imap_state::delete_or_trash_message_by_uid(root, domain, local, &folder, uid)?,
            }
        }
        Ok(Ok(()))
    })
    .await;
    match result {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(message)) => (StatusCode::UNPROCESSABLE_ENTITY, message).into_response(),
        Err(error) => internal_error(error),
    }
}

/// Serve attachment `index`. Only images that browsers render safely are
/// shown inline (`?inline=1`); everything else downloads, under a sandbox
/// policy, so an attachment can never run in this origin.
async fn attachment(
    app: State<Shared>,
    headers: HeaderMap,
    Path((folder, uid, index)): Path<(String, String, String)>,
    Query(query): Query<DetailQuery>,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let (Ok(uid), Ok(index)) = (uid.parse::<u64>(), index.parse::<usize>()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let inline_requested = query.inline.as_deref() == Some("1");
    let result = blocking(move || {
        let location = locate(&state, &session, &folder)?;
        let folder = location.folder.clone();
        let (_, messages) = imap_state::load_folder(
            &state.mail_root,
            &location.domain,
            &location.localpart,
            &folder,
        )?;
        let message = messages
            .into_iter()
            .find(|message| message.uid == uid)
            .ok_or_else(|| anyhow::anyhow!("no such message"))?;
        attachment_data(&std::fs::read(&message.path)?, index)
            .ok_or_else(|| anyhow::anyhow!("no such attachment"))
    })
    .await;
    let Ok((meta, bytes)) = result else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let previewable = matches!(
        meta.content_type.as_str(),
        "image/png" | "image/jpeg" | "image/gif" | "image/webp"
    );
    let inline = inline_requested && previewable;
    let content_type = if previewable {
        meta.content_type.as_str()
    } else {
        "application/octet-stream"
    };
    let disposition = format!(
        "{}; filename=\"{}\"; filename*=UTF-8''{}",
        if inline { "inline" } else { "attachment" },
        meta.filename
            .replace(['"', '\\'], "_")
            .chars()
            .filter(char::is_ascii)
            .collect::<String>(),
        percent_encode(&meta.filename)
    );
    let mut response = bytes.into_response();
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(content_type) {
        headers.insert(header::CONTENT_TYPE, value);
    }
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox; default-src 'none'; img-src 'self'"),
    );
    response
}

/// The message as stored, headers included: as text to show
/// (`text/plain`, sandboxed) or, with `?download=1`, as an `.eml` file.
async fn raw_message(
    app: State<Shared>,
    headers: HeaderMap,
    Path((folder, uid)): Path<(String, String)>,
    Query(query): Query<RawQuery>,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(uid) = uid.parse::<u64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let result = blocking(move || {
        let location = locate(&state, &session, &folder)?;
        let folder = location.folder.clone();
        let (_, messages) = imap_state::load_folder(
            &state.mail_root,
            &location.domain,
            &location.localpart,
            &folder,
        )?;
        let message = messages
            .into_iter()
            .find(|message| message.uid == uid)
            .ok_or_else(|| anyhow::anyhow!("no such message"))?;
        Ok(std::fs::read(&message.path)?)
    })
    .await;
    let Ok(bytes) = result else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let download = query.download.as_deref() == Some("1");
    let mut response = bytes.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(if download {
            "message/rfc822"
        } else {
            "text/plain; charset=utf-8"
        }),
    );
    if download
        && let Ok(value) =
            HeaderValue::from_str(&format!("attachment; filename=\"message-{uid}.eml\""))
    {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox; default-src 'none'"),
    );
    response
}

#[derive(Deserialize)]
struct RawQuery {
    #[serde(default)]
    download: Option<String>,
}

/// RFC 5987 percent-encoding for `filename*`.
fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[derive(Deserialize)]
struct FolderName {
    name: String,
}

/// Folder names users may create or rename to: what IMAP accepts, minus INBOX.
fn valid_new_folder(name: &str) -> Option<String> {
    let name = name.trim();
    let normalized = rmail_common::maildir::normalize_mailbox_name(name).ok()?;
    // Names under "Other Users" are where shared folders appear.
    (!normalized.eq_ignore_ascii_case("INBOX")
        && !normalized.starts_with(OTHER_USERS.trim_end_matches('/'))
        && normalized.chars().count() <= 200)
        .then_some(normalized)
}

async fn create_folder(app: State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<FolderName>(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid json").into_response();
    };
    let Some(name) = valid_new_folder(&input.name) else {
        return (StatusCode::UNPROCESSABLE_ENTITY, "invalid folder name").into_response();
    };
    let result = blocking(move || {
        imap_state::create_folder(&state.mail_root, &session.domain, &session.localpart, &name)
    })
    .await;
    match result {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(error) => (StatusCode::CONFLICT, error.to_string()).into_response(),
    }
}

/// Only the user's own folders can be renamed or deleted, never INBOX or
/// special-use folders such as Sent and Trash.
fn own_folder(
    root: &std::path::Path,
    domain: &str,
    local: &str,
    name: &str,
) -> Result<Option<String>> {
    Ok(imap_state::list_folders(root, domain, local)?
        .into_iter()
        .filter(rmail_common::classifier_store::is_user_folder)
        .find(|folder| folder.name == name)
        .map(|folder| folder.name))
}

async fn rename_folder(
    app: State<Shared>,
    headers: HeaderMap,
    Path(folder): Path<String>,
    body: Bytes,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<FolderName>(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid json").into_response();
    };
    let Some(name) = valid_new_folder(&input.name) else {
        return (StatusCode::UNPROCESSABLE_ENTITY, "invalid folder name").into_response();
    };
    let result = blocking(move || {
        let (root, domain, local) = (&state.mail_root, &session.domain, &session.localpart);
        let Some(current) = own_folder(root, domain, local, &folder)? else {
            return Ok(false);
        };
        imap_state::rename_folder(root, domain, local, &current, &name)?;
        Ok(true)
    })
    .await;
    match result {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => (StatusCode::CONFLICT, error.to_string()).into_response(),
    }
}

async fn delete_folder(
    app: State<Shared>,
    headers: HeaderMap,
    Path(folder): Path<String>,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let result = blocking(move || {
        let (root, domain, local) = (&state.mail_root, &session.domain, &session.localpart);
        let Some(current) = own_folder(root, domain, local, &folder)? else {
            return Ok(false);
        };
        let id = imap_state::find_folder(root, domain, local, &current)?.map(|f| f.mailbox_id);
        imap_state::delete_folder(root, domain, local, &current)?;
        if let Some(id) = id {
            acl::forget_mailbox(&state.db_path, &session.address, &id)?;
        }
        Ok(true)
    })
    .await;
    match result {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => (StatusCode::CONFLICT, error.to_string()).into_response(),
    }
}

fn update_flag(
    mail_root: &std::path::Path,
    domain: &str,
    local: &str,
    folder: &str,
    uid: u64,
    flag: &str,
    present: bool,
) -> Result<()> {
    let (_, messages) = imap_state::load_folder(mail_root, domain, local, folder)?;
    if let Some(message) = messages.into_iter().find(|message| message.uid == uid) {
        let mut flags = message.flags;
        set_flag(&mut flags, flag, present);
        imap_state::set_uid_flags(mail_root, domain, local, folder, uid, flags)?;
    }
    Ok(())
}

fn set_flag(flags: &mut Vec<String>, flag: &str, enabled: bool) {
    if enabled && !flags.iter().any(|f| f.eq_ignore_ascii_case(flag)) {
        flags.push(flag.to_string());
    } else if !enabled {
        flags.retain(|f| !f.eq_ignore_ascii_case(flag));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use rmail_common::maildir;
    use std::fs;
    use tower::ServiceExt;

    fn state(td: &tempfile::TempDir) -> Arc<AppState> {
        let db_path = td.path().join("accounts.sqlite");
        db::init_db(&db_path).unwrap();
        db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:secret"),
            None,
            None,
        )
        .unwrap();
        Arc::new(AppState {
            mail_root: td.path().join("mail"),
            db_path,
            static_dir: td.path().join("static"),
            session_secret: b"test secret".to_vec(),
            secure_cookies: false,
            throttle: AuthThrottle::default(),
            revoked: websession::RevocationList::default(),
            submission: None,
            oauth: None,
            jmap_logins: Default::default(),
            shutdown: None,
        })
    }

    fn req(
        method: &str,
        path: &str,
        body: &[u8],
        cookie: Option<String>,
    ) -> axum::http::Request<Body> {
        let mut builder = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header(CSRF_HEADER, "1");
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        let mut request = builder.body(Body::from(body.to_vec())).unwrap();
        request
            .extensions_mut()
            .insert(Peer(Some("192.0.2.1:40000".parse().unwrap())));
        request
    }

    struct TestResponse {
        status: u16,
        content_type: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl TestResponse {
        fn header(&self, name: &str) -> &str {
            self.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map_or("", |(_, value)| value.as_str())
        }
    }

    /// Run a request through the real router.
    async fn route(request: axum::http::Request<Body>, state: &Arc<AppState>) -> TestResponse {
        let response = router(state.clone()).oneshot(request).await.unwrap();
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                // Title-case names ("set-cookie" -> "Set-Cookie") as on the wire.
                let name = name
                    .as_str()
                    .split('-')
                    .map(|part| {
                        let mut chars = part.chars();
                        chars.next().map_or(String::new(), |first| {
                            first.to_ascii_uppercase().to_string() + chars.as_str()
                        })
                    })
                    .collect::<Vec<_>>()
                    .join("-");
                (name, value.to_str().unwrap_or_default().to_string())
            })
            .collect::<Vec<_>>();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        TestResponse {
            status,
            content_type,
            headers,
            body,
        }
    }

    #[tokio::test]
    async fn login_success_and_failure() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        let bad = route(
            req(
                "POST",
                "/api/login",
                br#"{"address":"user@example.test","password":"bad"}"#,
                None,
            ),
            &state,
        )
        .await;
        assert_eq!(bad.status, 401);
        let ok = route(
            req(
                "POST",
                "/api/login",
                br#"{"address":"user@example.test","password":"secret"}"#,
                None,
            ),
            &state,
        )
        .await;
        assert_eq!(ok.status, 200);
        assert!(ok.headers.iter().any(|(k, _)| k == "Set-Cookie"));
    }

    #[tokio::test]
    async fn folders_require_cookie_and_return_maildir_state() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        let denied = route(req("GET", "/api/folders", b"", None), &state).await;
        assert_eq!(denied.status, 401);
        maildir::deliver(
            &state.mail_root,
            "example.test",
            "user",
            b"From: a@example.test\r\nTo: user@example.test\r\nSubject: hello\r\n\r\nbody",
        )
        .unwrap();
        let token = sign_session(&state, "user@example.test");
        let ok = route(
            req(
                "GET",
                "/api/folders",
                b"",
                Some(format!("{SESSION_COOKIE}={token}")),
            ),
            &state,
        )
        .await;
        assert_eq!(ok.status, 200);
        let folders: Vec<FolderResponse> = serde_json::from_slice(&ok.body).unwrap();
        let inbox = folders.iter().find(|f| f.name == "INBOX").unwrap();
        assert_eq!(inbox.messages, 1);
        assert_eq!(inbox.unread, 1);
    }

    #[tokio::test]
    async fn folders_shared_by_another_account_follow_its_grants() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        db::add_mailbox(
            &state.db_path,
            "friend@example.test",
            Some("plain:secret"),
            None,
            None,
        )
        .unwrap();
        imap_state::create_folder(&state.mail_root, "example.test", "user", "Projects").unwrap();
        imap_state::append_message(
            &state.mail_root,
            "example.test",
            "user",
            "Projects",
            b"From: a@example.test\r\nSubject: plan\r\n\r\nthe plan",
            Vec::new(),
        )
        .unwrap();
        let owner = Some(format!(
            "{SESSION_COOKIE}={}",
            sign_session(&state, "user@example.test")
        ));
        let friend = Some(format!(
            "{SESSION_COOKIE}={}",
            sign_session(&state, "friend@example.test")
        ));
        let call = |method: &'static str, path: &str, body: &str, cookie: &Option<String>| {
            let request = req(method, path, body.as_bytes(), cookie.clone());
            let state = state.clone();
            async move { route(request, &state).await }
        };
        let shared = "/api/folders/Other%20Users%2Fuser%40example.test%2FProjects";
        assert_eq!(
            call("GET", &format!("{shared}/messages"), "", &friend)
                .await
                .status,
            404
        );

        let share = |access: &str, address: &str| {
            format!(r#"{{"address":"{address}","access":"{access}"}}"#)
        };
        assert_eq!(
            call(
                "PUT",
                "/api/folders/Projects/sharing",
                &share("read", "nobody@example.test"),
                &owner
            )
            .await
            .status,
            422
        );
        assert_eq!(
            call(
                "PUT",
                "/api/folders/Projects/sharing",
                &share("read", "friend@example.test"),
                &owner
            )
            .await
            .status,
            204
        );
        let grants = call("GET", "/api/folders/Projects/sharing", "", &owner).await;
        assert_eq!(
            String::from_utf8(grants.body).unwrap(),
            r#"[{"address":"friend@example.test","rights":"lr","access":"read"}]"#
        );
        // The grantee cannot see who else the owner's folders are shared with.
        assert_eq!(
            call("GET", &format!("{shared}/sharing"), "", &friend)
                .await
                .status,
            404
        );

        let folders = call("GET", "/api/folders", "", &friend).await;
        let folders: Vec<FolderResponse> = serde_json::from_slice(&folders.body).unwrap();
        let listed = folders
            .iter()
            .find(|folder| folder.name == "Other Users/user@example.test/Projects")
            .unwrap();
        assert_eq!(listed.owner.as_deref(), Some("user@example.test"));
        assert_eq!(listed.rights.as_deref(), Some("lr"));
        assert_eq!(listed.messages, 1);

        let page = call("GET", &format!("{shared}/messages"), "", &friend).await;
        let page: MessagePage = serde_json::from_slice(&page.body).unwrap();
        let uid = page.messages[0].uid;
        let detail = call("GET", &format!("{shared}/messages/{uid}"), "", &friend).await;
        assert_eq!(detail.status, 200);
        // Read access changes nothing.
        let seen = call(
            "PATCH",
            &format!("{shared}/messages/{uid}"),
            r#"{"seen":true}"#,
            &friend,
        );
        assert_eq!(seen.await.status, 403);
        let bulk = |action: &str| format!(r#"{{"action":"{action}","uids":[{uid}]}}"#);
        let flagged = call(
            "POST",
            &format!("{shared}/messages/bulk"),
            &bulk("flag"),
            &friend,
        );
        assert_eq!(flagged.await.status, 422);

        // Edit access allows marking and deleting, never moving out.
        assert_eq!(
            call(
                "PUT",
                "/api/folders/Projects/sharing",
                &share("edit", "friend@example.test"),
                &owner
            )
            .await
            .status,
            204
        );
        let seen = call(
            "PATCH",
            &format!("{shared}/messages/{uid}"),
            r#"{"seen":true}"#,
            &friend,
        );
        assert_eq!(seen.await.status, 204);
        let moved = call(
            "POST",
            &format!("{shared}/messages/bulk"),
            &bulk("archive"),
            &friend,
        );
        assert_eq!(moved.await.status, 422);
        let (_, messages) =
            imap_state::load_folder(&state.mail_root, "example.test", "user", "Projects").unwrap();
        assert!(messages[0].flags.iter().any(|flag| flag == "\\Seen"));

        assert_eq!(
            call(
                "PUT",
                "/api/folders/Projects/sharing",
                &share("none", "friend@example.test"),
                &owner
            )
            .await
            .status,
            204
        );
        assert_eq!(
            call("GET", &format!("{shared}/messages"), "", &friend)
                .await
                .status,
            404
        );
        // Own folders cannot take names where shared folders appear.
        let created = call(
            "POST",
            "/api/folders",
            r#"{"name":"Other Users/x"}"#,
            &friend,
        );
        assert_eq!(created.await.status, 422);
    }

    #[tokio::test]
    async fn message_endpoints_and_bulk_archive() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        maildir::deliver(
            &state.mail_root,
            "example.test",
            "user",
            b"From: a@example.test\r\nTo: user@example.test\r\nSubject: hello\r\n\r\nbody text",
        )
        .unwrap();
        let token = sign_session(&state, "user@example.test");
        let cookie = Some(format!("{SESSION_COOKIE}={token}"));
        let list = route(
            req(
                "GET",
                "/api/folders/INBOX/messages?q=hello",
                b"",
                cookie.clone(),
            ),
            &state,
        )
        .await;
        assert_eq!(list.status, 200);
        let page: MessagePage = serde_json::from_slice(&list.body).unwrap();
        assert_eq!(page.total, page.messages.len());
        let items = page.messages;
        assert_eq!(items.len(), 1);
        let patch = route(
            req(
                "PATCH",
                &format!("/api/folders/INBOX/messages/{}", items[0].uid),
                br#"{"seen":true}"#,
                cookie.clone(),
            ),
            &state,
        )
        .await;
        assert_eq!(patch.status, 204);
        let bulk = route(
            req(
                "POST",
                "/api/folders/INBOX/messages/bulk",
                format!(r#"{{"action":"archive","uids":[{}]}}"#, items[0].uid).as_bytes(),
                cookie,
            ),
            &state,
        )
        .await;
        assert_eq!(bulk.status, 204);
        assert_eq!(
            imap_state::load_folder(&state.mail_root, "example.test", "user", "INBOX")
                .unwrap()
                .1
                .len(),
            0
        );
        assert_eq!(
            imap_state::load_folder(&state.mail_root, "example.test", "user", "Archive")
                .unwrap()
                .1
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn serves_static_webmail_assets_when_present() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        fs::create_dir_all(&state.static_dir).unwrap();
        fs::write(
            state.static_dir.join("index.html"),
            "<!doctype html><p>built ui</p>",
        )
        .unwrap();
        fs::create_dir_all(state.static_dir.join("assets")).unwrap();
        fs::write(
            state.static_dir.join("assets/app.js"),
            "console.log('built')",
        )
        .unwrap();

        let index = route(req("GET", "/", b"", None), &state).await;
        assert_eq!(index.status, 200);
        assert_eq!(index.content_type, "text/html; charset=utf-8");
        assert!(String::from_utf8(index.body).unwrap().contains("built ui"));

        let asset = route(req("GET", "/assets/app.js", b"", None), &state).await;
        assert_eq!(asset.status, 200);
        assert_eq!(asset.content_type, "application/javascript; charset=utf-8");
        assert_eq!(asset.body, b"console.log('built')");
    }

    #[tokio::test]
    async fn state_changes_require_csrf_header() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        let mut request = req(
            "POST",
            "/api/login",
            br#"{"address":"user@example.test","password":"secret"}"#,
            None,
        );
        request.headers_mut().remove(CSRF_HEADER);
        assert_eq!(route(request, &state).await.status, 403);
    }

    #[tokio::test]
    async fn sessions_end_on_logout_and_password_change() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        let login = route(
            req(
                "POST",
                "/api/login",
                br#"{"address":"user@example.test","password":"secret"}"#,
                None,
            ),
            &state,
        )
        .await;
        let cookie = login
            .headers
            .iter()
            .find(|(k, _)| k == "Set-Cookie")
            .map(|(_, v)| v.split(';').next().unwrap().to_string())
            .unwrap();
        assert!(
            login
                .headers
                .iter()
                .any(|(_, v)| v.contains("SameSite=Strict"))
        );
        let ok = route(
            req("GET", "/api/session", b"", Some(cookie.clone())),
            &state,
        )
        .await;
        assert_eq!(ok.status, 200);

        route(
            req("POST", "/api/logout", b"", Some(cookie.clone())),
            &state,
        )
        .await;
        let after = route(req("GET", "/api/session", b"", Some(cookie)), &state).await;
        assert_eq!(after.status, 401);

        let token = sign_session(&state, "user@example.test");
        db::add_mailbox(
            &state.db_path,
            "user@example.test",
            Some("plain:changed"),
            None,
            None,
        )
        .unwrap();
        let stale = route(
            req(
                "GET",
                "/api/session",
                b"",
                Some(format!("{SESSION_COOKIE}={token}")),
            ),
            &state,
        )
        .await;
        assert_eq!(stale.status, 401);
    }

    #[tokio::test]
    async fn repeated_failed_logins_are_throttled() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        for _ in 0..5 {
            let bad = route(
                req(
                    "POST",
                    "/api/login",
                    br#"{"address":"user@example.test","password":"bad"}"#,
                    None,
                ),
                &state,
            )
            .await;
            assert_eq!(bad.status, 401);
        }
        let locked = route(
            req(
                "POST",
                "/api/login",
                br#"{"address":"user@example.test","password":"secret"}"#,
                None,
            ),
            &state,
        )
        .await;
        assert_eq!(locked.status, 429);
    }

    /// A submission service stand-in: checks webmail's credential against
    /// the real key, refuses one recipient, and records what it receives.
    async fn fake_submission(
        mail_root: std::path::PathBuf,
    ) -> (
        std::net::SocketAddr,
        tokio::sync::mpsc::UnboundedReceiver<(Vec<String>, String)>,
    ) {
        use base64::Engine;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (read, mut write) = stream.into_split();
                let mut lines = tokio::io::BufReader::new(read).lines();
                write.write_all(b"220 test ESMTP\r\n").await.unwrap();
                let mut envelope = Vec::new();
                let mut data = String::new();
                let mut in_data = false;
                while let Ok(Some(line)) = lines.next_line().await {
                    if in_data {
                        if line == "." {
                            in_data = false;
                            write.write_all(b"250 2.0.0 queued\r\n").await.unwrap();
                        } else {
                            data.push_str(&line);
                            data.push('\n');
                        }
                        continue;
                    }
                    let reply: &[u8] = if line.starts_with("EHLO") {
                        b"250-test\r\n250 8BITMIME\r\n"
                    } else if let Some(token) = line.strip_prefix("AUTH X-RMAIL-WEBMAIL ") {
                        let decoded = String::from_utf8(
                            base64::engine::general_purpose::STANDARD
                                .decode(token)
                                .unwrap(),
                        )
                        .unwrap();
                        let key =
                            rmail_common::runtime::webmail_submission_key(&mail_root).unwrap();
                        if decoded == format!("user@example.test\0{key}") {
                            b"235 ok\r\n"
                        } else {
                            b"535 no\r\n"
                        }
                    } else if line.starts_with("MAIL FROM:") || line.starts_with("RCPT TO:") {
                        envelope.push(line.clone());
                        if line.contains("blocked@") {
                            b"550 5.1.1 Recipient rejected\r\n"
                        } else {
                            b"250 ok\r\n"
                        }
                    } else if line == "DATA" {
                        in_data = true;
                        b"354 go\r\n"
                    } else if line == "QUIT" {
                        write.write_all(b"221 bye\r\n").await.unwrap();
                        break;
                    } else {
                        b"250 ok\r\n"
                    };
                    write.write_all(reply).await.unwrap();
                }
                if !data.is_empty() {
                    tx.send((envelope, data)).unwrap();
                }
            }
        });
        (address, rx)
    }

    #[tokio::test]
    async fn sending_goes_through_submission_and_keeps_a_copy() {
        use base64::Engine;
        let td = tempfile::tempdir().unwrap();
        let base = state(&td);
        let (root, d, l) = (base.mail_root.clone(), "example.test", "user");
        imap_state::init_account(&root, d, l).unwrap();
        let (address, mut received) = fake_submission(root.clone()).await;
        let state = Arc::new(AppState {
            mail_root: base.mail_root.clone(),
            db_path: base.db_path.clone(),
            static_dir: base.static_dir.clone(),
            session_secret: base.session_secret.clone(),
            secure_cookies: false,
            throttle: AuthThrottle::default(),
            revoked: websession::RevocationList::default(),
            submission: Some(address),
            oauth: None,
            jmap_logins: Default::default(),
            shutdown: None,
        });
        let cookie = Some(format!(
            "{SESSION_COOKIE}={}",
            sign_session(&state, "user@example.test")
        ));
        let call = |method: &'static str, path: &'static str, body: Vec<u8>| {
            let (state, cookie) = (state.clone(), cookie.clone());
            async move { route(req(method, path, &body, cookie), &state).await }
        };
        let session: serde_json::Value =
            serde_json::from_slice(&call("GET", "/api/session", vec![]).await.body).unwrap();
        assert_eq!(session["can_send"], true);

        let (_, original) = imap_state::deliver_message(
            &root,
            d,
            l,
            b"From: a@b.test\r\nMessage-ID: <o1@b.test>\r\nSubject: Hi\r\n\r\nhello",
        )
        .unwrap();
        let draft: serde_json::Value = serde_json::from_slice(
            &call(
                "POST",
                "/api/drafts",
                br#"{"to":["a@b.test"],"subject":"Re: Hi","text":"draft"}"#.to_vec(),
            )
            .await
            .body,
        )
        .unwrap();
        assert_eq!(draft["folder"], "Drafts");
        let draft_uid = draft["uid"].as_u64().unwrap();
        let drafts = imap_state::load_folder(&root, d, l, "Drafts").unwrap().1;
        assert!(drafts[0].flags.iter().any(|f| f == "\\Draft"));

        let file = base64::engine::general_purpose::STANDARD.encode(b"report");
        let body = serde_json::json!({
            "to": ["Ann <a@b.test>"], "bcc": ["hidden@c.test"], "subject": "Re: Hi", "text": ".leading dot\nthanks",
            "in_reply_to": "<o1@b.test>", "references": "<o1@b.test>",
            "attachments": [{"filename": "r.txt", "content_type": "text/plain", "data": file}],
            "source": {"folder": "INBOX", "uid": original, "kind": "reply"},
            "draft_uid": draft_uid,
        });
        let sent = call("POST", "/api/send", body.to_string().into_bytes()).await;
        assert_eq!(sent.status, 200, "{}", String::from_utf8_lossy(&sent.body));
        let (envelope, data) = received.recv().await.unwrap();
        assert_eq!(
            envelope,
            vec![
                "MAIL FROM:<user@example.test>",
                "RCPT TO:<a@b.test>",
                "RCPT TO:<hidden@c.test>"
            ]
        );
        assert!(!data.contains("hidden@c.test"), "Bcc stays off the wire");
        assert!(data.contains("..leading dot"), "dot-stuffed");
        assert!(data.contains("In-Reply-To: <o1@b.test>"));

        let sent_folder = imap_state::load_folder(&root, d, l, "Sent").unwrap().1;
        assert_eq!(sent_folder.len(), 1);
        let copy = std::fs::read_to_string(&sent_folder[0].path).unwrap();
        assert!(
            copy.contains("Bcc: hidden@c.test"),
            "the Sent copy keeps Bcc"
        );
        assert!(
            imap_state::load_folder(&root, d, l, "Drafts")
                .unwrap()
                .1
                .is_empty(),
            "draft removed"
        );
        let inbox = imap_state::load_folder(&root, d, l, "INBOX").unwrap().1;
        assert!(inbox[0].flags.iter().any(|f| f == "\\Answered"));

        let refused = call(
            "POST",
            "/api/send",
            br#"{"to":["blocked@b.test"],"subject":"x","text":"y"}"#.to_vec(),
        )
        .await;
        assert_eq!(refused.status, 422);
        assert!(String::from_utf8_lossy(&refused.body).contains("550 5.1.1 Recipient rejected"));
        let empty = call(
            "POST",
            "/api/send",
            br#"{"to":[],"subject":"x","text":"y"}"#.to_vec(),
        )
        .await;
        assert_eq!(empty.status, 422);
        let injected = call(
            "POST",
            "/api/send",
            b"{\"to\":[\"a@b.test\\r\\nRCPT TO:<x@y.test>\"],\"text\":\"y\"}".to_vec(),
        )
        .await;
        assert_eq!(injected.status, 422);
    }

    #[tokio::test]
    async fn reading_organizing_and_ai_endpoints() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        let (root, d, l) = (&state.mail_root, "example.test", "user");
        imap_state::init_account(root, d, l).unwrap();
        let cookie = Some(format!(
            "{SESSION_COOKIE}={}",
            sign_session(&state, "user@example.test")
        ));
        let call = |method: &'static str, path: String, body: Vec<u8>| {
            let (state, cookie) = (state.clone(), cookie.clone());
            async move { route(req(method, &path, &body, cookie), &state).await }
        };
        let json = |body: &[u8]| serde_json::from_slice::<serde_json::Value>(body).unwrap();

        for n in 0..5 {
            let raw = format!("From: a@b.test\r\nSubject: Note {n}\r\n\r\nbody {n}");
            imap_state::deliver_message(root, d, l, raw.as_bytes()).unwrap();
        }
        let with_files = b"From: s@b.test\r\nSubject: Files\r\nContent-Type: multipart/mixed; boundary=\"x\"\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--x\r\nContent-Type: image/png\r\nContent-Disposition: attachment; filename=\"pic.png\"\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0K\r\n--x\r\nContent-Type: text/html\r\nContent-Disposition: attachment; filename=\"evil.html\"\r\n\r\n<script>alert(1)</script>\r\n--x--\r\n";
        let (_, files_uid) = imap_state::deliver_message(root, d, l, with_files).unwrap();

        // Paging reports the folder total; search narrows it.
        let page = json(
            &call(
                "GET",
                "/api/folders/INBOX/messages?limit=2&offset=1".into(),
                vec![],
            )
            .await
            .body,
        );
        assert_eq!(page["total"], 6);
        assert_eq!(page["messages"].as_array().unwrap().len(), 2);
        let found = json(
            &call(
                "GET",
                "/api/folders/INBOX/messages?q=note%203".into(),
                vec![],
            )
            .await
            .body,
        );
        assert_eq!(found["total"], 1);

        // Attachments: listed, downloaded under a sandbox, previewed only when safe.
        let detail = json(
            &call(
                "GET",
                format!("/api/folders/INBOX/messages/{files_uid}"),
                vec![],
            )
            .await
            .body,
        );
        assert_eq!(detail["text_body"], "see attached");
        let attachments = detail["attachments"].as_array().unwrap();
        assert_eq!(attachments.len(), 2);
        let png = attachments[0]["index"].as_u64().unwrap();
        let html = attachments[1]["index"].as_u64().unwrap();
        let shown = call(
            "GET",
            format!("/api/folders/INBOX/messages/{files_uid}/attachments/{png}?inline=1"),
            vec![],
        )
        .await;
        assert_eq!(shown.status, 200);
        assert_eq!(shown.header("content-type"), "image/png");
        assert!(shown.header("content-disposition").starts_with("inline"));
        assert!(
            shown
                .header("content-security-policy")
                .starts_with("sandbox")
        );
        let script = call(
            "GET",
            format!("/api/folders/INBOX/messages/{files_uid}/attachments/{html}?inline=1"),
            vec![],
        )
        .await;
        assert_eq!(script.header("content-type"), "application/octet-stream");
        assert!(
            script
                .header("content-disposition")
                .starts_with("attachment; filename=\"evil.html\"")
        );
        let missing = call(
            "GET",
            format!("/api/folders/INBOX/messages/{files_uid}/attachments/9"),
            vec![],
        )
        .await;
        assert_eq!(missing.status, 404);

        // Raw source, as text or as an .eml download.
        let raw = call(
            "GET",
            format!("/api/folders/INBOX/messages/{files_uid}/raw"),
            vec![],
        )
        .await;
        assert!(raw.header("content-type").starts_with("text/plain"));
        assert!(String::from_utf8_lossy(&raw.body).starts_with("From: s@b.test\r\nSubject: Files"));
        let eml = call(
            "GET",
            format!("/api/folders/INBOX/messages/{files_uid}/raw?download=1"),
            vec![],
        )
        .await;
        assert_eq!(eml.header("content-type"), "message/rfc822");

        // Bulk: star, move to an existing folder only, junk.
        let uids: Vec<u64> = page["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["uid"].as_u64().unwrap())
            .collect();
        let bulk = |body: String| {
            call(
                "POST",
                "/api/folders/INBOX/messages/bulk".into(),
                body.into_bytes(),
            )
        };
        assert_eq!(
            bulk(format!(r#"{{"action":"flag","uids":[{}]}}"#, uids[0]))
                .await
                .status,
            204
        );
        let (_, inbox) = imap_state::load_folder(root, d, l, "INBOX").unwrap();
        assert!(
            inbox
                .iter()
                .find(|m| m.uid == uids[0])
                .unwrap()
                .flags
                .iter()
                .any(|f| f == "\\Flagged")
        );
        assert_eq!(
            bulk(format!(
                r#"{{"action":"move","uids":[{}],"target":"Nope"}}"#,
                uids[0]
            ))
            .await
            .status,
            422
        );
        assert_eq!(
            call(
                "POST",
                "/api/folders".into(),
                br#"{"name":"Projects"}"#.to_vec()
            )
            .await
            .status,
            201
        );
        assert_eq!(
            bulk(format!(
                r#"{{"action":"move","uids":[{}],"target":"Projects"}}"#,
                uids[0]
            ))
            .await
            .status,
            204
        );
        assert_eq!(
            imap_state::load_folder(root, d, l, "Projects")
                .unwrap()
                .1
                .len(),
            1
        );
        assert_eq!(
            bulk(format!(r#"{{"action":"junk","uids":[{}]}}"#, uids[1]))
                .await
                .status,
            204
        );
        assert_eq!(
            imap_state::load_folder(root, d, l, "Junk").unwrap().1.len(),
            1
        );

        // Folders: create, rename and delete the user's own; never INBOX or system folders.
        assert_eq!(
            call(
                "POST",
                "/api/folders".into(),
                br#"{"name":"../x"}"#.to_vec()
            )
            .await
            .status,
            422
        );
        assert_eq!(
            call(
                "POST",
                "/api/folders".into(),
                br#"{"name":"inbox"}"#.to_vec()
            )
            .await
            .status,
            422
        );
        assert_eq!(
            call(
                "PATCH",
                "/api/folders/Projects".into(),
                br#"{"name":"Work"}"#.to_vec()
            )
            .await
            .status,
            204
        );
        assert_eq!(
            call(
                "PATCH",
                "/api/folders/Junk".into(),
                br#"{"name":"Spam"}"#.to_vec()
            )
            .await
            .status,
            404
        );
        assert_eq!(
            call("DELETE", "/api/folders/INBOX".into(), vec![])
                .await
                .status,
            404
        );
        assert_eq!(
            call("DELETE", "/api/folders/Work".into(), vec![])
                .await
                .status,
            204
        );

        // AI actions: unavailable without a model, then gated on consent.
        let ai = |action: &'static str| {
            call(
                "POST",
                format!("/api/folders/INBOX/messages/{files_uid}/ai"),
                format!(r#"{{"action":"{action}"}}"#).into_bytes(),
            )
        };
        assert_eq!(ai("labels").await.status, 409);
        let mut conn = rmail_common::settings::open(&state.db_path).unwrap();
        rmail_common::settings::write_raw(
            &mut conn,
            &[
                (
                    "classifier.enabled".to_string(),
                    Some(serde_json::Value::from(true)),
                ),
                (
                    "classifier.chat_provider".to_string(),
                    Some(serde_json::Value::from("jev")),
                ),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap();
        assert_eq!(ai("summary").await.status, 409, "Jev cannot summarize");
        let refused = ai("labels").await;
        assert_eq!(refused.status, 403);
        assert_eq!(String::from_utf8_lossy(&refused.body), "consent:typesafe");
        let overview = json(&call("GET", "/api/organize".into(), vec![]).await.body);
        assert_eq!(
            (
                overview["ai_labels"].as_bool(),
                overview["ai_summary"].as_bool()
            ),
            (Some(true), Some(false))
        );
        call(
            "PUT",
            "/api/organize".into(),
            br#"{"enabled":false,"cloud_consent":true}"#.to_vec(),
        )
        .await;
        // Consented, but no classifier daemon is running in the test.
        assert_eq!(ai("labels").await.status, 502);
    }

    #[tokio::test]
    async fn labels_are_their_own_setting_and_suggest_folders() {
        use rmail_common::classifier_store as store;
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        let (root, d, l) = (&state.mail_root, "example.test", "user");
        imap_state::init_account(root, d, l).unwrap();
        let cookie = Some(format!(
            "{SESSION_COOKIE}={}",
            sign_session(&state, "user@example.test")
        ));
        let call = |method: &'static str, path: String, body: Vec<u8>| {
            let (state, cookie) = (state.clone(), cookie.clone());
            async move { route(req(method, &path, &body, cookie), &state).await }
        };
        let json = |body: &[u8]| serde_json::from_slice::<serde_json::Value>(body).unwrap();

        let saved = call(
            "PUT",
            "/api/organize".into(),
            br#"{"enabled":false,"labels_enabled":true,"labels":[{"name":"To do","description":"Needs a reply"},{"name":"Invoices"}]}"#.to_vec(),
        )
        .await;
        assert_eq!(saved.status, 204);
        let conn = store::open_existing(root, d, l).unwrap().unwrap();
        let prefs = store::prefs(&conn).unwrap();
        assert!(
            prefs.labels_enabled && !prefs.enabled,
            "labels do not need folder suggestions"
        );

        let overview = json(&call("GET", "/api/organize".into(), vec![]).await.body);
        assert_eq!(overview["labels_enabled"], true);
        assert_eq!(overview["labels"][0]["keyword"], "To_do");
        assert_eq!(
            overview["labels_available"], false,
            "no fallback model is configured"
        );
        assert_eq!(overview["labels"][0]["origin"], "user");
        let starter = overview["labels"]
            .as_array()
            .unwrap()
            .iter()
            .find(|l| l["name"] == "Receipts")
            .expect("starter labels are seeded when labels are turned on");
        assert_eq!(starter["origin"], "starter");

        let duplicate = call(
            "PUT",
            "/api/organize".into(),
            br#"{"enabled":false,"labels":[{"name":"A"},{"name":"a"}]}"#.to_vec(),
        )
        .await;
        assert_eq!(duplicate.status, 422);
        // Saving folder preferences alone keeps labels on.
        call(
            "PUT",
            "/api/organize".into(),
            br#"{"enabled":false}"#.to_vec(),
        )
        .await;
        assert!(store::prefs(&conn).unwrap().labels_enabled);

        // A label on a message can be removed from webmail; system flags cannot be touched.
        let (_, uid) = imap_state::deliver_message(root, d, l, b"Subject: x\r\n\r\ny").unwrap();
        store::set_keyword(root, d, l, "INBOX", uid, "To_do", true).unwrap();
        // The message list names the labels a message carries.
        let listed = json(
            &call("GET", "/api/folders/INBOX/messages".into(), vec![])
                .await
                .body,
        );
        assert_eq!(listed["messages"][0]["labels"][0]["name"], "To do");
        assert_eq!(listed["messages"][0]["labels"][0]["keyword"], "To_do");
        let path = format!("/api/folders/INBOX/messages/{uid}");
        let removed = call(
            "PATCH",
            path.clone(),
            br#"{"keywords":{"To_do":false}}"#.to_vec(),
        )
        .await;
        assert_eq!(removed.status, 204);
        let (_, messages) = imap_state::load_folder(root, d, l, "INBOX").unwrap();
        assert!(!messages[0].flags.iter().any(|f| f == "To_do"));
        let system = call(
            "PATCH",
            path,
            br#"{"keywords":{"\\Deleted":true}}"#.to_vec(),
        )
        .await;
        assert_eq!(system.status, 400);

        // A label used often, with no folder of that name, is offered as a folder.
        for uid in 0..10 {
            store::record_labels(&conn, 1, 100 + uid, &[("Invoices".into(), 0.9)]).unwrap();
        }
        let overview = json(&call("GET", "/api/organize".into(), vec![]).await.body);
        assert_eq!(overview["folder_ideas"][0]["label"], "Invoices");
        assert_eq!(overview["folder_ideas"][0]["count"], 10);
        // Folders are only created from a stored label, inside an existing folder.
        let unknown = call(
            "POST",
            "/api/organize/folders".into(),
            br#"{"label":"../etc"}"#.to_vec(),
        )
        .await;
        assert_eq!(unknown.status, 422);
        let no_parent = call(
            "POST",
            "/api/organize/folders".into(),
            br#"{"label":"Invoices","parent":"Nope"}"#.to_vec(),
        )
        .await;
        assert_eq!(no_parent.status, 422);
        imap_state::create_folder(root, d, l, "Money").unwrap();
        let created = call(
            "POST",
            "/api/organize/folders".into(),
            br#"{"label":"Invoices","parent":"Money"}"#.to_vec(),
        )
        .await;
        assert_eq!(created.status, 200);
        assert_eq!(json(&created.body)["folder"], "Money/Invoices");
        let overview = json(&call("GET", "/api/organize".into(), vec![]).await.body);
        assert_eq!(overview["folder_ideas"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn organize_asks_for_cloud_consent_per_provider() {
        use rmail_common::classifier_store as store;
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        let (root, d, l) = (&state.mail_root, "example.test", "user");
        imap_state::init_account(root, d, l).unwrap();
        let cookie = Some(format!(
            "{SESSION_COOKIE}={}",
            sign_session(&state, "user@example.test")
        ));
        let get = |state: Arc<AppState>, cookie: Option<String>| async move {
            let response = route(req("GET", "/api/organize", b"", cookie), &state).await;
            serde_json::from_slice::<serde_json::Value>(&response.body).unwrap()
        };

        // Everything local: nothing to consent to.
        let local = get(state.clone(), cookie.clone()).await;
        assert_eq!(local["cloud_providers"], serde_json::json!([]));
        assert_eq!(local["cloud_consent"], false);

        let mut conn = rmail_common::settings::open(&state.db_path).unwrap();
        rmail_common::settings::write_raw(
            &mut conn,
            &[(
                "classifier.embed_provider".to_string(),
                Some(serde_json::Value::from("openrouter")),
            )]
            .into_iter()
            .collect(),
        )
        .unwrap();
        let cloud = get(state.clone(), cookie.clone()).await;
        assert_eq!(cloud["cloud_providers"], serde_json::json!(["openrouter"]));
        assert_eq!(cloud["cloud_consent"], false);
        assert_eq!(cloud["cloud_required"], true);

        let put = |body: &'static [u8]| {
            let (state, cookie) = (state.clone(), cookie.clone());
            async move {
                route(req("PUT", "/api/organize", body, cookie), &state)
                    .await
                    .status
            }
        };
        assert_eq!(put(br#"{"enabled":true,"cloud_consent":true}"#).await, 204);
        assert_eq!(
            get(state.clone(), cookie.clone()).await["cloud_consent"],
            true
        );
        let prefs = || store::prefs(&store::open_existing(root, d, l).unwrap().unwrap()).unwrap();
        assert_eq!(prefs().cloud_consent, vec!["openrouter".to_string()]);

        // Saving folders without the field keeps the decision.
        assert_eq!(put(br#"{"enabled":true}"#).await, 204);
        assert_eq!(prefs().cloud_consent, vec!["openrouter".to_string()]);

        assert_eq!(put(br#"{"enabled":true,"cloud_consent":false}"#).await, 204);
        assert!(prefs().cloud_consent.is_empty());
    }

    #[tokio::test]
    async fn organize_opt_in_suggestions_accept_and_dismiss() {
        use rmail_common::classifier_store as store;
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        let (root, d, l) = (&state.mail_root, "example.test", "user");
        imap_state::init_account(root, d, l).unwrap();
        imap_state::create_folder(root, d, l, "Receipts").unwrap();
        let cookie = Some(format!(
            "{SESSION_COOKIE}={}",
            sign_session(&state, "user@example.test")
        ));

        let before = route(req("GET", "/api/organize", b"", cookie.clone()), &state).await;
        assert_eq!(before.status, 200);
        let body = String::from_utf8(before.body).unwrap();
        assert!(body.contains("\"enabled\":false"), "{body}");
        assert!(body.contains("\"name\":\"Receipts\""), "{body}");
        assert!(
            !body.contains("\"name\":\"Sent\""),
            "special-use folders are not offered: {body}"
        );
        assert!(
            store::open_existing(root, d, l).unwrap().is_none(),
            "reading does not opt in"
        );

        let saved = route(
            req(
                "PUT",
                "/api/organize",
                br#"{"enabled":true,"excluded_folders":["Nope"],"autofile_folders":["Receipts"]}"#,
                cookie.clone(),
            ),
            &state,
        )
        .await;
        assert_eq!(saved.status, 204);
        let conn = store::open_existing(root, d, l).unwrap().unwrap();
        let prefs = store::prefs(&conn).unwrap();
        assert!(prefs.enabled);
        assert!(
            prefs.excluded_folders.is_empty(),
            "unknown folders are dropped"
        );
        assert_eq!(prefs.autofile_folders, vec!["Receipts".to_string()]);

        // Simulate the daemon's work: two INBOX messages with suggestions.
        let mut uids = Vec::new();
        for subject in ["Receipt one", "Receipt two"] {
            let data = format!("From: shop@example.net\r\nSubject: {subject}\r\n\r\nthanks");
            let (uidvalidity, uid) =
                imap_state::deliver_message(root, d, l, data.as_bytes()).unwrap();
            store::record_suggestion(
                &conn,
                &store::Suggestion {
                    uidvalidity,
                    uid,
                    folder: "Receipts".into(),
                    score: 0.9,
                    method: "knn".into(),
                    state: "pending".into(),
                    sender: "shop@example.net".into(),
                    created_at: store::now(),
                },
            )
            .unwrap();
            store::set_keyword(root, d, l, "INBOX", uid, store::SUGGESTED_KEYWORD, true).unwrap();
            uids.push(uid);
        }

        let list = route(
            req("GET", "/api/folders/INBOX/messages", b"", cookie.clone()),
            &state,
        )
        .await;
        let body = String::from_utf8(list.body).unwrap();
        assert_eq!(
            body.matches("\"suggestion\":{\"folder\":\"Receipts\"")
                .count(),
            2,
            "{body}"
        );

        let accepted = route(
            req(
                "POST",
                &format!("/api/suggestions/{}/accept", uids[0]),
                b"",
                cookie.clone(),
            ),
            &state,
        )
        .await;
        assert_eq!(accepted.status, 200);
        let (_, receipts) = imap_state::load_folder(root, d, l, "Receipts").unwrap();
        assert_eq!(receipts.len(), 1);

        let dismissed = route(
            req(
                "POST",
                &format!("/api/suggestions/{}/dismiss", uids[1]),
                b"",
                cookie.clone(),
            ),
            &state,
        )
        .await;
        assert_eq!(dismissed.status, 204);
        let again = route(
            req(
                "POST",
                &format!("/api/suggestions/{}/accept", uids[1]),
                b"",
                cookie.clone(),
            ),
            &state,
        )
        .await;
        assert_eq!(
            again.status, 409,
            "dismissed suggestions cannot be accepted"
        );
        let (_, inbox) = imap_state::load_folder(root, d, l, "INBOX").unwrap();
        assert_eq!(inbox.len(), 1);
        assert!(!inbox[0].flags.iter().any(|f| f == store::SUGGESTED_KEYWORD));
        assert_eq!(
            store::dismissals(&conn).unwrap()["shop@example.net"],
            vec!["Receipts".to_string()]
        );

        let other = route(
            req("POST", "/api/suggestions/abc/accept", b"", cookie.clone()),
            &state,
        )
        .await;
        assert_eq!(other.status, 404);
        let anonymous = route(req("GET", "/api/organize", b"", None), &state).await;
        assert_eq!(anonymous.status, 401);
    }

    #[tokio::test]
    async fn indexed_search_pages_decodes_and_follows_new_mail() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        let deliver = |raw: &str| {
            maildir::deliver(&state.mail_root, "example.test", "user", raw.as_bytes()).unwrap();
        };
        for n in 0..5 {
            deliver(&format!(
                "From: a@b.test\r\nSubject: Invoice {n}\r\n\r\ntotals {n}"
            ));
        }
        deliver(
            "From: c@d.test\r\nSubject: Lunch\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nCaf=C3=A9 receipt attached",
        );
        deliver("From: e@f.test\r\nSubject: Other\r\n\r\nnothing relevant");
        let token = sign_session(&state, "user@example.test");
        let cookie = Some(format!("{SESSION_COOKIE}={token}"));
        let search = |query: &str| {
            let state = state.clone();
            let cookie = cookie.clone();
            let path = format!("/api/folders/INBOX/messages?{query}");
            async move {
                let response = route(req("GET", &path, b"", cookie), &state).await;
                assert_eq!(response.status, 200);
                let page: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
                (
                    page["total"].as_u64().unwrap(),
                    page["messages"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|m| m["subject"].as_str().unwrap().to_string())
                        .collect::<Vec<_>>(),
                )
            }
        };

        // Newest first; the total counts all matches while the page is a window.
        let (total, all) = search("q=INVOICE&limit=10").await;
        assert_eq!(total, 5);
        assert_eq!(all.len(), 5);
        let (total, window) = search("q=invoice&limit=2&offset=3").await;
        assert_eq!(total, 5);
        assert_eq!(window, all[3..5]);
        // Text is searched decoded: the quoted-printable body matches "café".
        assert_eq!(search("q=caf%C3%A9").await, (1, vec!["Lunch".to_string()]));
        assert_eq!(
            search("q=totals%203").await,
            (1, vec!["Invoice 3".to_string()])
        );
        // Repeating a search (now served from the index) gives the same answer.
        assert_eq!(search("q=invoice&limit=10").await, (total, all.clone()));
        assert!(
            rmail_common::search_index::index_path(&state.mail_root, "example.test", "user")
                .exists()
        );
        // New mail is found; needles too short for the index still work.
        deliver("From: g@h.test\r\nSubject: Invoice F\r\n\r\nlate");
        assert_eq!(search("q=invoice&limit=10").await.0, 6);
        assert_eq!(search("q=zz").await.0, 0);
        assert_eq!(search("q=g@").await.0, 1);
    }
}
