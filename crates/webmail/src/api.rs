//! Webmail HTTP API: an axum router over the account's Maildir state.
//! Sessions are signed cookies bound to the mailbox password hash.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use axum::body::Bytes;
use axum::extract::{FromRequestParts, Path, Query, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use rmail_common::http::Peer;
use rmail_common::throttle::AuthThrottle;
use rmail_common::{auth, db, imap_state, websession};
use serde::{Deserialize, Serialize};

use rmail_common::mime::{has_remote_content, parse_message, sanitize_email_html, snippet};

mod organize;

const SESSION_COOKIE: &str = "rmail_webmail";
const SESSION_TTL_SECS: u64 = 12 * 60 * 60;
const MAX_BODY_BYTES: usize = 1024 * 1024;
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
}

type Shared = Arc<AppState>;

pub(crate) fn router(state: Shared) -> Router {
    let app = Router::new()
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/session", get(session_info))
        .route("/api/folders", get(folders))
        .route("/api/folders/{folder}/messages", get(message_list))
        .route(
            "/api/folders/{folder}/messages/{uid}",
            get(message_detail).patch(patch_message),
        )
        .route("/api/folders/{folder}/messages/bulk", post(bulk))
        .merge(organize::routes())
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

async fn fallback(State(state): State<Shared>, method: Method, uri: Uri) -> Response {
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

impl FromRequestParts<Shared> for Session {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &Shared) -> Result<Self, StatusCode> {
        let token = session_token(&parts.headers).ok_or(StatusCode::UNAUTHORIZED)?;
        if state.revoked.is_revoked(token) {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let session =
            websession::verify(&state.session_secret, token).ok_or(StatusCode::UNAUTHORIZED)?;
        let (localpart, domain) =
            split_address(&session.subject).ok_or(StatusCode::UNAUTHORIZED)?;
        let db_path = state.db_path.clone();
        let address = session.subject.clone();
        let mailbox = blocking(move || db::get_mailbox(&db_path, &address))
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        let bound = mailbox
            .and_then(|mailbox| mailbox.password_hash)
            .is_some_and(|hash| {
                websession::credential_binding(&state.session_secret, &hash) == session.binding
            });
        if !bound {
            return Err(StatusCode::UNAUTHORIZED);
        }
        Ok(Session {
            address: session.subject,
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
}

async fn login(
    State(state): State<Shared>,
    Extension(peer): Extension<Peer>,
    body: Bytes,
) -> Response {
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
        Json(SessionResponse { address }),
        websession::set_cookie(
            SESSION_COOKIE,
            &token,
            SESSION_TTL_SECS,
            state.secure_cookies,
            "Strict",
        ),
    )
}

async fn logout(State(state): State<Shared>, headers: HeaderMap) -> Response {
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

async fn session_info(session: Session) -> Json<SessionResponse> {
    Json(SessionResponse {
        address: session.address,
    })
}

// ---------------------------------------------------------------------------
// Mailbox API

#[derive(Serialize, Deserialize)]
pub(crate) struct FolderResponse {
    pub name: String,
    pub special_use: Option<String>,
    pub messages: usize,
    pub unread: usize,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<organize::SuggestionView>,
}

#[derive(Serialize)]
struct MessageDetail {
    uid: u64,
    flags: Vec<String>,
    size: u64,
    internal_date: i64,
    from: String,
    to: String,
    subject: String,
    date: String,
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
}

async fn folders(State(state): State<Shared>, session: Session) -> Response {
    let result = blocking(move || {
        imap_state::list_folder_summaries(&state.mail_root, &session.domain, &session.localpart)
    })
    .await;
    match result {
        Ok(summaries) => Json(
            summaries
                .into_iter()
                .map(|summary| FolderResponse {
                    name: summary.folder.name,
                    special_use: summary.folder.special_use,
                    messages: summary.messages,
                    unread: summary.unseen,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => internal_error(error),
    }
}

async fn message_list(
    State(state): State<Shared>,
    session: Session,
    Path(folder): Path<String>,
    Query(query): Query<ListQuery>,
) -> Response {
    let needle = query.q.to_ascii_lowercase();
    let result = blocking(move || {
        let (info, mut messages) = imap_state::load_folder(
            &state.mail_root,
            &session.domain,
            &session.localpart,
            &folder,
        )?;
        let mut suggestions = if info.name == "INBOX" {
            organize::pending_for_inbox(
                &state.mail_root,
                &session.domain,
                &session.localpart,
                info.uidvalidity,
            )
        } else {
            Default::default()
        };
        messages.sort_by(|a, b| b.internaldate.cmp(&a.internaldate).then(b.uid.cmp(&a.uid)));
        Ok(messages
            .into_iter()
            .filter_map(|message| {
                let parsed = parse_message(&std::fs::read(&message.path).ok()?);
                let haystack = format!(
                    "{} {} {} {}",
                    parsed.from, parsed.to, parsed.subject, parsed.text_body
                )
                .to_ascii_lowercase();
                if !needle.is_empty() && !haystack.contains(&needle) {
                    return None;
                }
                Some(MessageListItem {
                    uid: message.uid,
                    flags: message.flags,
                    size: message.size,
                    internal_date: message.internaldate,
                    from: parsed.from,
                    to: parsed.to,
                    subject: parsed.subject,
                    snippet: snippet(&parsed.text_body),
                    suggestion: suggestions.remove(&message.uid),
                })
            })
            .skip(query.offset)
            .take(query.limit)
            .collect::<Vec<_>>())
    })
    .await;
    match result {
        Ok(items) => Json(items).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn message_detail(
    State(state): State<Shared>,
    session: Session,
    Path((folder, uid)): Path<(String, String)>,
    Query(query): Query<DetailQuery>,
) -> Response {
    let Ok(uid) = uid.parse::<u64>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let allow_remote = query.remote_content.as_deref() == Some("1");
    let result = blocking(move || {
        let (_, messages) = imap_state::load_folder(
            &state.mail_root,
            &session.domain,
            &session.localpart,
            &folder,
        )?;
        let message = messages
            .into_iter()
            .find(|message| message.uid == uid)
            .ok_or_else(|| anyhow::anyhow!("no such message"))?;
        let parsed = parse_message(&std::fs::read(&message.path)?);
        Ok(MessageDetail {
            uid: message.uid,
            flags: message.flags,
            size: message.size,
            internal_date: message.internaldate,
            from: parsed.from,
            to: parsed.to,
            subject: parsed.subject,
            date: parsed.date,
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
    State(state): State<Shared>,
    session: Session,
    Path((folder, uid)): Path<(String, String)>,
    body: Bytes,
) -> Response {
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
        let (_, messages) = imap_state::load_folder(
            &state.mail_root,
            &session.domain,
            &session.localpart,
            &folder,
        )?;
        let Some(message) = messages.into_iter().find(|message| message.uid == uid) else {
            return Ok(false);
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
            &session.domain,
            &session.localpart,
            &folder,
            uid,
            flags,
        )?;
        Ok(true)
    })
    .await;
    match result {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => internal_error(error),
    }
}

async fn bulk(
    State(state): State<Shared>,
    session: Session,
    Path(folder): Path<String>,
    body: Bytes,
) -> Response {
    let Ok(input) = serde_json::from_slice::<BulkRequest>(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid json").into_response();
    };
    if !matches!(
        input.action.as_str(),
        "mark_read" | "mark_unread" | "archive" | "delete"
    ) {
        return (StatusCode::BAD_REQUEST, "unknown action").into_response();
    }
    let result = blocking(move || {
        let (root, domain, local) = (&state.mail_root, &session.domain, &session.localpart);
        for uid in input.uids {
            match input.action.as_str() {
                "mark_read" => update_seen(root, domain, local, &folder, uid, true)?,
                "mark_unread" => update_seen(root, domain, local, &folder, uid, false)?,
                "archive" => {
                    imap_state::move_message_by_uid(root, domain, local, &folder, uid, "Archive")?;
                }
                _ => imap_state::delete_or_trash_message_by_uid(root, domain, local, &folder, uid)?,
            }
        }
        Ok(())
    })
    .await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => internal_error(error),
    }
}

fn update_seen(
    mail_root: &std::path::Path,
    domain: &str,
    local: &str,
    folder: &str,
    uid: u64,
    seen: bool,
) -> Result<()> {
    let (_, messages) = imap_state::load_folder(mail_root, domain, local, folder)?;
    if let Some(message) = messages.into_iter().find(|message| message.uid == uid) {
        let mut flags = message.flags;
        set_flag(&mut flags, "\\Seen", seen);
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
        let items: Vec<MessageListItem> = serde_json::from_slice(&list.body).unwrap();
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
        let listed = json(&call("GET", "/api/labels".into(), vec![]).await.body);
        assert_eq!(listed[1]["name"], "Invoices");

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
        let created = call(
            "POST",
            "/api/organize/folders".into(),
            br#"{"name":"Invoices"}"#.to_vec(),
        )
        .await;
        assert_eq!(created.status, 200);
        let overview = json(&call("GET", "/api/organize".into(), vec![]).await.body);
        assert_eq!(overview["folder_ideas"], serde_json::json!([]));
        let inbox = call(
            "POST",
            "/api/organize/folders".into(),
            br#"{"name":"inbox"}"#.to_vec(),
        )
        .await;
        assert_eq!(inbox.status, 422);
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
}
