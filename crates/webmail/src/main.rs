use anyhow::{Context, Result};
use base64::Engine;
use percent_encoding::percent_decode_str;
use rmail_common::{
    auth, config::Config, db, http::HttpLimits, imap_state, net::bind_tcp_listener_with_config,
    runtime::GracefulShutdown, throttle::AuthThrottle, tracking::new_tracking_id, websession,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, fs, net::IpAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    task::JoinSet,
};

const SESSION_COOKIE: &str = "rmail_webmail";
const SESSION_TTL_SECS: u64 = 12 * 60 * 60;
/// State-changing requests must carry this header; browsers cannot add it to
/// cross-site form posts.
const CSRF_HEADER: &str = "x-rmail-webmail";
/// Policy for the web app itself. Message HTML is rendered in a sandboxed
/// srcdoc iframe that inherits this policy and adds its own, stricter one.
const APP_CSP: &str = "default-src 'self'; img-src * data: blob:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; frame-src 'self' about:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'";

macro_rules! webmail_log {
    ($level:expr, $event:expr, $fields:tt) => {
        rmail_common::structured_log!($level, "webmail", $event, $fields)
    };
}

struct AppState {
    mail_root: PathBuf,
    db_path: PathBuf,
    static_dir: PathBuf,
    session_secret: Vec<u8>,
    secure_cookies: bool,
    throttle: AuthThrottle,
    revoked: websession::RevocationList,
}

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    peer: Option<IpAddr>,
}

#[derive(Debug)]
struct Response {
    status: u16,
    content_type: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Session {
    address: String,
    domain: String,
    localpart: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    address: String,
    password: String,
}

#[derive(Deserialize)]
struct PatchMessage {
    seen: Option<bool>,
}

#[derive(Deserialize)]
struct BulkRequest {
    action: String,
    uids: Vec<u64>,
}

#[derive(Serialize)]
struct SessionResponse {
    address: String,
}

#[derive(Serialize, Deserialize)]
struct FolderResponse {
    name: String,
    special_use: Option<String>,
    messages: usize,
    unread: usize,
}

#[derive(Serialize, Deserialize)]
struct MessageListItem {
    uid: u64,
    flags: Vec<String>,
    size: u64,
    internal_date: i64,
    from: String,
    to: String,
    subject: String,
    snippet: String,
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

#[tokio::main]
async fn main() -> Result<()> {
    let cfg_path = env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let cfg = Config::load(&cfg_path).with_context(|| format!("loading {cfg_path}"))?;
    let mail_root = PathBuf::from(&cfg.global.mail_root);
    rmail_common::runtime::redirect_stdio_to_log(&mail_root, "webmail")
        .context("redirecting logs")?;
    let db_path = cfg
        .global
        .db_path
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(|| mail_root.join("rmail.sqlite"));
    if let Err(error) = rmail_common::settings::record_service_start(&cfg, "webmail") {
        webmail_log!("warn", "service_state_failed", { "error": format!("{error:#}") });
    }
    let session_secret = match (&cfg.global.webmail_session_secret, &cfg.global.db_path) {
        (Some(secret), _) => secret.clone(),
        // Persist a generated key so sessions survive restarts.
        (None, Some(db_path)) => {
            let mut conn = rmail_common::settings::open(db_path)?;
            rmail_common::settings::internal_secret(&mut conn, "webmail_session_key")?
        }
        (None, None) => {
            webmail_log!("warn", "ephemeral_session_secret", { "reason": "no database or webmail_session_secret; sessions end on restart" });
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            base64::engine::general_purpose::STANDARD.encode(bytes)
        }
    }
    .into_bytes();
    let static_dir = env::var("RMAIL_WEBMAIL_STATIC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/usr/share/rmail/webmail"));
    let bind_addrs = cfg.global.webmail_listeners();
    let tls = rmail_common::tls::web_tls_channel(&cfg.global)?;
    let secure_cookies = tls.1.borrow().is_some() || cfg.global.tls.web_http_only;
    let state = Arc::new(AppState {
        mail_root,
        db_path,
        static_dir,
        session_secret,
        secure_cookies,
        throttle: AuthThrottle::default(),
        revoked: websession::RevocationList::default(),
    });
    rmail_common::tls::spawn_web_tls_reloader(
        tls.0.clone(),
        cfg.global.tls_cert.clone(),
        cfg.global.tls_key.clone(),
        cfg.global.tls.clone(),
        "webmail",
    );
    let listener_config = cfg.global.tcp_listener.clone();
    let shutdown = GracefulShutdown::new();
    let mut listeners = JoinSet::new();
    for addr in bind_addrs {
        let listener = bind_tcp_listener_with_config(&addr, &listener_config)?;
        webmail_log!("info", "listener_started", { "address": addr, "tls_configured": tls.1.borrow().is_some() });
        let state = state.clone();
        let listener_shutdown = shutdown.clone();
        let tls = tls.1.clone();
        listeners.spawn(async move {
            let mut shutdown_signal = listener_shutdown.subscribe();
            loop {
                if *shutdown_signal.borrow() {
                    break;
                }
                let accepted = tokio::select! {
                    _ = shutdown_signal.changed() => break,
                    accepted = listener.accept() => accepted,
                };
                match accepted {
                    Ok((stream, peer)) => {
                        let state = state.clone();
                        let tls_context = tls.borrow().clone();
                        let session = listener_shutdown.start_session();
                        tokio::spawn(async move {
                            let _session = session;
                            let result = if let Some(context) = tls_context {
                                match tokio::time::timeout(Duration::from_secs(15), context.acceptor.accept(stream)).await {
                                    Ok(Ok(stream)) => handle_connection(stream, state, Some(peer.to_string())).await,
                                    Ok(Err(error)) => Err(error.into()),
                                    Err(_) => Err(anyhow::anyhow!("TLS handshake timed out")),
                                }
                            } else {
                                handle_connection(stream, state, Some(peer.to_string())).await
                            };
                            if let Err(err) = result {
                                webmail_log!("error", "connection_failed", { "peer": peer.to_string(), "error": format!("{err:#}") });
                            }
                        });
                    }
                    Err(err) => {
                        webmail_log!("error", "listener_accept_failed", { "address": addr, "error": err.to_string() });
                        break;
                    }
                }
            }
        });
    }
    rmail_common::runtime::wait_for_shutdown_signal().await?;
    webmail_log!("info", "shutdown_requested", { "active_requests": shutdown.active_sessions() });
    shutdown.request();
    while let Some(result) = listeners.join_next().await {
        if let Err(error) = result {
            webmail_log!("error", "shutdown_listener_join_failed", { "error": error.to_string() });
        }
    }
    if !shutdown.wait_for_sessions(Duration::from_secs(30)).await {
        webmail_log!("warn", "shutdown_drain_timed_out", { "active_requests": shutdown.active_sessions() });
    }
    Ok(())
}

async fn handle_connection<S>(
    mut stream: S,
    state: Arc<AppState>,
    peer: Option<String>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request_id = new_tracking_id("webmail-http");
    let response = match rmail_common::http::read_request(&mut stream, HttpLimits::default()).await
    {
        Ok(raw) => {
            let (path, query) = split_target(&raw.target);
            let request = Request {
                method: raw.method,
                path,
                query,
                headers: raw.headers,
                body: raw.body,
                peer: peer.as_deref().and_then(peer_ip),
            };
            let method = request.method.clone();
            let path = request.path.clone();
            let response = route(request, &state).await;
            webmail_log!("info", "request_completed", { "request_id": request_id, "peer": peer, "method": method, "path": path, "status": response.status, "response_bytes": response.body.len() });
            response
        }
        Err(error) => match error.status() {
            Some(status) => Response::empty(status),
            None => return Ok(()),
        },
    };
    write_response(&mut stream, response).await?;
    let _ = stream.shutdown().await;
    Ok(())
}

fn peer_ip(peer: &str) -> Option<IpAddr> {
    peer.parse::<std::net::SocketAddr>()
        .map(|address| address.ip())
        .ok()
}

async fn write_response<S: AsyncWrite + Unpin>(stream: &mut S, response: Response) -> Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\
         X-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\n",
        response.status,
        rmail_common::http::reason_phrase(response.status),
        response.body.len(),
        response.content_type
    );
    if !response
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("cache-control"))
    {
        head.push_str("Cache-Control: no-store\r\n");
    }
    if !response
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-security-policy"))
    {
        head.push_str(&format!("Content-Security-Policy: {APP_CSP}\r\n"));
    }
    for (k, v) in response.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&response.body).await?;
    Ok(())
}

async fn route(request: Request, state: &AppState) -> Response {
    if request.path.starts_with("/api/")
        && !matches!(request.method.as_str(), "GET" | "HEAD")
        && !request.headers.contains_key(CSRF_HEADER)
    {
        return Response::text(403, "missing CSRF header");
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/api/login") => login(request, state).await,
        ("POST", "/api/logout") => {
            if let Some(token) = session_token(&request)
                && let Some(session) = websession::verify(&state.session_secret, token)
            {
                state.revoked.revoke(token, session.expires_at);
            }
            Response::empty(204).with_header(
                "Set-Cookie",
                websession::set_cookie(SESSION_COOKIE, "", 0, state.secure_cookies, "Strict"),
            )
        }
        ("GET", "/api/session") => match require_session(&request, state) {
            Ok(session) => json(
                200,
                &SessionResponse {
                    address: session.address,
                },
            ),
            Err(response) => response,
        },
        ("GET", "/api/folders") => match require_session(&request, state) {
            Ok(session) => folders(state, &session),
            Err(response) => response,
        },
        _ if request.path.starts_with("/api/folders/") => mailbox_api(request, state),
        _ if request.method == "GET" => static_spa(&request.path, state),
        _ => Response::empty(405),
    }
}

async fn login(request: Request, state: &AppState) -> Response {
    let Ok(input) = serde_json::from_slice::<LoginRequest>(&request.body) else {
        return Response::text(400, "invalid json");
    };
    if let Some(remaining) = request.peer.and_then(|ip| state.throttle.blocked_for(ip)) {
        return Response::text(
            429,
            &format!(
                "too many failed sign-in attempts; try again in {} minutes",
                remaining.as_secs().div_ceil(60)
            ),
        )
        .with_header("Retry-After", remaining.as_secs().to_string());
    }
    let address = auth::saslprep(input.address.trim()).to_ascii_lowercase();
    let reject = |state: &AppState| {
        if let Some(ip) = request.peer {
            state.throttle.record_failure(ip);
        }
        rmail_common::metrics::inc_auth_failures();
        Response::text(401, "invalid login")
    };
    let Some((localpart, domain)) = split_address(&address) else {
        auth::burn_password_verification(input.password).await;
        return reject(state);
    };
    let db_path = state.db_path.clone();
    let lookup = address.clone();
    let mailbox = tokio::task::spawn_blocking(move || db::get_mailbox(&db_path, &lookup)).await;
    let Ok(Ok(Some(mailbox))) = mailbox else {
        auth::burn_password_verification(input.password).await;
        return reject(state);
    };
    let Some(hash) = mailbox.password_hash else {
        auth::burn_password_verification(input.password).await;
        return reject(state);
    };
    match auth::verify_password_async(input.password, hash.clone()).await {
        Ok(true) => {
            if let Some(ip) = request.peer {
                state.throttle.reset(ip);
            }
            let mail_root = state.mail_root.clone();
            let _ = tokio::task::spawn_blocking(move || {
                imap_state::init_account(&mail_root, &domain, &localpart)
            })
            .await;
            let binding = websession::credential_binding(&state.session_secret, &hash);
            let token =
                websession::sign(&state.session_secret, &address, &binding, SESSION_TTL_SECS);
            json(200, &SessionResponse { address }).with_header(
                "Set-Cookie",
                websession::set_cookie(
                    SESSION_COOKIE,
                    &token,
                    SESSION_TTL_SECS,
                    state.secure_cookies,
                    "Strict",
                ),
            )
        }
        _ => reject(state),
    }
}

fn mailbox_api(request: Request, state: &AppState) -> Response {
    let session = match require_session(&request, state) {
        Ok(session) => session,
        Err(response) => return response,
    };
    let rest = request.path.trim_start_matches("/api/folders/");
    let parts = rest.split('/').collect::<Vec<_>>();
    if parts.len() < 2 || parts[1] != "messages" {
        return Response::empty(404);
    }
    let folder = decode_path(parts[0]);
    match (request.method.as_str(), parts.as_slice()) {
        ("GET", [_, "messages"]) => message_list(state, &session, &folder, &request.query),
        ("GET", [_, "messages", uid]) => uid
            .parse::<u64>()
            .ok()
            .map(|uid| {
                let remote = request
                    .query
                    .get("remote_content")
                    .is_some_and(|v| v == "1");
                message_detail(state, &session, &folder, uid, remote)
            })
            .unwrap_or_else(|| Response::empty(404)),
        ("PATCH", [_, "messages", uid]) => uid
            .parse::<u64>()
            .ok()
            .map(|uid| patch_message(state, &session, &folder, uid, &request.body))
            .unwrap_or_else(|| Response::empty(404)),
        ("POST", [_, "messages", "bulk"]) => bulk(state, &session, &folder, &request.body),
        _ => Response::empty(404),
    }
}

fn folders(state: &AppState, session: &Session) -> Response {
    match imap_state::list_folder_summaries(&state.mail_root, &session.domain, &session.localpart) {
        Ok(summaries) => json(
            200,
            &summaries
                .into_iter()
                .map(|s| FolderResponse {
                    name: s.folder.name,
                    special_use: s.folder.special_use,
                    messages: s.messages,
                    unread: s.unseen,
                })
                .collect::<Vec<_>>(),
        ),
        Err(err) => Response::text(500, &err.to_string()),
    }
}

fn message_list(
    state: &AppState,
    session: &Session,
    folder: &str,
    query: &HashMap<String, String>,
) -> Response {
    let limit = query
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    let offset = query
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let q = query
        .get("q")
        .map(|v| v.to_ascii_lowercase())
        .unwrap_or_default();
    let Ok((_folder, mut messages)) = imap_state::load_folder(
        &state.mail_root,
        &session.domain,
        &session.localpart,
        folder,
    ) else {
        return Response::empty(404);
    };
    messages.sort_by(|a, b| b.internaldate.cmp(&a.internaldate).then(b.uid.cmp(&a.uid)));
    let items = messages
        .into_iter()
        .filter_map(|message| {
            let parsed = parse_message(&fs::read(&message.path).ok()?);
            let haystack = format!(
                "{} {} {} {}",
                parsed.from, parsed.to, parsed.subject, parsed.text_body
            )
            .to_ascii_lowercase();
            if !q.is_empty() && !haystack.contains(&q) {
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
            })
        })
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
    json(200, &items)
}

fn message_detail(
    state: &AppState,
    session: &Session,
    folder: &str,
    uid: u64,
    allow_remote_content: bool,
) -> Response {
    let Ok((_folder, messages)) = imap_state::load_folder(
        &state.mail_root,
        &session.domain,
        &session.localpart,
        folder,
    ) else {
        return Response::empty(404);
    };
    let Some(message) = messages.into_iter().find(|m| m.uid == uid) else {
        return Response::empty(404);
    };
    let Ok(bytes) = fs::read(&message.path) else {
        return Response::empty(404);
    };
    let parsed = parse_message(&bytes);
    json(
        200,
        &MessageDetail {
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
                .map(|html| sanitize_email_html(&html, allow_remote_content)),
        },
    )
}

fn patch_message(
    state: &AppState,
    session: &Session,
    folder: &str,
    uid: u64,
    body: &[u8],
) -> Response {
    let Ok(input) = serde_json::from_slice::<PatchMessage>(body) else {
        return Response::text(400, "invalid json");
    };
    let Ok((_folder, messages)) = imap_state::load_folder(
        &state.mail_root,
        &session.domain,
        &session.localpart,
        folder,
    ) else {
        return Response::empty(404);
    };
    let Some(message) = messages.into_iter().find(|m| m.uid == uid) else {
        return Response::empty(404);
    };
    let mut flags = message.flags;
    if let Some(seen) = input.seen {
        set_flag(&mut flags, "\\Seen", seen);
    }
    match imap_state::set_uid_flags(
        &state.mail_root,
        &session.domain,
        &session.localpart,
        folder,
        uid,
        flags,
    ) {
        Ok(_) => Response::empty(204),
        Err(err) => Response::text(500, &err.to_string()),
    }
}

fn bulk(state: &AppState, session: &Session, folder: &str, body: &[u8]) -> Response {
    let Ok(input) = serde_json::from_slice::<BulkRequest>(body) else {
        return Response::text(400, "invalid json");
    };
    for uid in input.uids {
        let result = match input.action.as_str() {
            "mark_read" => update_seen(state, session, folder, uid, true),
            "mark_unread" => update_seen(state, session, folder, uid, false),
            "archive" => imap_state::move_message_by_uid(
                &state.mail_root,
                &session.domain,
                &session.localpart,
                folder,
                uid,
                "Archive",
            )
            .map(|_| ()),
            "delete" => imap_state::delete_or_trash_message_by_uid(
                &state.mail_root,
                &session.domain,
                &session.localpart,
                folder,
                uid,
            ),
            _ => return Response::text(400, "unknown action"),
        };
        if let Err(err) = result {
            return Response::text(500, &err.to_string());
        }
    }
    Response::empty(204)
}

fn update_seen(
    state: &AppState,
    session: &Session,
    folder: &str,
    uid: u64,
    seen: bool,
) -> Result<()> {
    let (_, messages) = imap_state::load_folder(
        &state.mail_root,
        &session.domain,
        &session.localpart,
        folder,
    )?;
    if let Some(message) = messages.into_iter().find(|m| m.uid == uid) {
        let mut flags = message.flags;
        set_flag(&mut flags, "\\Seen", seen);
        imap_state::set_uid_flags(
            &state.mail_root,
            &session.domain,
            &session.localpart,
            folder,
            uid,
            flags,
        )?;
    }
    Ok(())
}

fn session_token(request: &Request) -> Option<&str> {
    request
        .headers
        .get("cookie")
        .and_then(|cookie| websession::cookie_value(cookie, SESSION_COOKIE))
}

fn require_session(request: &Request, state: &AppState) -> std::result::Result<Session, Response> {
    let Some(token) = session_token(request) else {
        return Err(Response::empty(401));
    };
    if state.revoked.is_revoked(token) {
        return Err(Response::empty(401));
    }
    let Some(session) = websession::verify(&state.session_secret, token) else {
        return Err(Response::empty(401));
    };
    let address = session.subject;
    let Some((localpart, domain)) = split_address(&address) else {
        return Err(Response::empty(401));
    };
    // The session is bound to the password hash at login time, so a password
    // change or account removal ends it.
    match db::get_mailbox(&state.db_path, &address) {
        Ok(Some(mailbox))
            if mailbox.password_hash.as_deref().is_some_and(|hash| {
                websession::credential_binding(&state.session_secret, hash) == session.binding
            }) =>
        {
            Ok(Session {
                address,
                domain,
                localpart,
            })
        }
        _ => Err(Response::empty(401)),
    }
}

#[cfg(test)]
fn sign_session(state: &AppState, address: &str) -> String {
    let hash = db::get_mailbox(&state.db_path, address)
        .unwrap()
        .and_then(|mailbox| mailbox.password_hash)
        .unwrap();
    let binding = websession::credential_binding(&state.session_secret, &hash);
    websession::sign(&state.session_secret, address, &binding, SESSION_TTL_SECS)
}

#[derive(Default)]
struct ParsedMessage {
    from: String,
    to: String,
    subject: String,
    date: String,
    text_body: String,
    html_body: Option<String>,
    inline_images: HashMap<String, String>,
}

#[derive(Default)]
struct MultipartParsed {
    text_body: Option<String>,
    html_body: Option<String>,
    inline_images: HashMap<String, String>,
}

fn parse_message(bytes: &[u8]) -> ParsedMessage {
    let text = String::from_utf8_lossy(bytes).replace("\r\n", "\n");
    let (headers, body) = text.split_once("\n\n").unwrap_or(("", &text));
    parse_message_parts(headers, body)
}

fn parse_message_parts(headers: &str, body: &str) -> ParsedMessage {
    let mut parsed = ParsedMessage::default();
    let header_map = parse_headers(headers);
    parsed.from = header_map.get("from").cloned().unwrap_or_default();
    parsed.to = header_map.get("to").cloned().unwrap_or_default();
    parsed.subject = header_map.get("subject").cloned().unwrap_or_default();
    parsed.date = header_map.get("date").cloned().unwrap_or_default();

    let content_type_raw = header_map
        .get("content-type")
        .cloned()
        .unwrap_or_else(|| "text/plain".to_string());
    let content_type = content_type_raw.to_ascii_lowercase();
    let transfer_encoding = header_map
        .get("content-transfer-encoding")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    let (text_body, html_body, inline_images) = if content_type.starts_with("multipart/") {
        if let Some(boundary) = header_param(&content_type_raw, "boundary") {
            let multipart = parse_multipart_body(body, &boundary);
            (
                multipart.text_body.unwrap_or_else(|| {
                    multipart
                        .html_body
                        .as_deref()
                        .map(strip_html)
                        .unwrap_or_default()
                }),
                multipart.html_body,
                multipart.inline_images,
            )
        } else {
            (
                decode_transfer_text(body, &transfer_encoding),
                None,
                HashMap::new(),
            )
        }
    } else {
        let decoded = decode_transfer_text(body, &transfer_encoding);
        if content_type.contains("text/html") {
            (strip_html(decoded.trim()), Some(decoded), HashMap::new())
        } else {
            (decoded, None, HashMap::new())
        }
    };

    parsed.text_body = text_body.trim().to_string();
    parsed.inline_images = inline_images;
    parsed.html_body =
        html_body.map(|html| apply_inline_images(html.trim(), &parsed.inline_images));
    parsed
}

fn parse_headers(headers: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut current_name: Option<String> = None;
    let mut current_value = String::new();
    for line in headers.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if !current_value.is_empty() {
                current_value.push(' ');
            }
            current_value.push_str(line.trim());
            continue;
        }
        if let Some(name) = current_name.take() {
            out.insert(name, decode_rfc2047_words(current_value.trim()));
            current_value.clear();
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        current_name = Some(name.trim().to_ascii_lowercase());
        current_value.push_str(value.trim());
    }
    if let Some(name) = current_name {
        out.insert(name, decode_rfc2047_words(current_value.trim()));
    }
    out
}

fn header_param(content_type: &str, name: &str) -> Option<String> {
    for part in content_type.split(';').skip(1) {
        let (k, v) = part.trim().split_once('=')?;
        if k.trim().eq_ignore_ascii_case(name) {
            return Some(v.trim().trim_matches('"').to_string());
        }
    }
    None
}

fn parse_multipart_body(body: &str, boundary: &str) -> MultipartParsed {
    let marker = format!("--{boundary}");
    let mut parsed = MultipartParsed::default();
    for raw_part in body.split(&marker).skip(1) {
        let part = raw_part.trim_start_matches('\n').trim_end();
        if part.starts_with("--") {
            break;
        }
        let Some((part_headers, part_body)) = part.split_once("\n\n") else {
            continue;
        };
        let headers = parse_headers(part_headers);
        let content_type_raw = headers
            .get("content-type")
            .cloned()
            .unwrap_or_else(|| "text/plain".to_string());
        let content_type = content_type_raw.to_ascii_lowercase();
        let transfer_encoding = headers
            .get("content-transfer-encoding")
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        if content_type.starts_with("multipart/") {
            if let Some(boundary) = header_param(&content_type_raw, "boundary") {
                let nested = parse_multipart_body(part_body, &boundary);
                if parsed.text_body.is_none() {
                    parsed.text_body = nested.text_body;
                }
                if parsed.html_body.is_none() {
                    parsed.html_body = nested.html_body;
                }
                parsed.inline_images.extend(nested.inline_images);
            }
            continue;
        }

        let decoded = decode_transfer_text(part_body, &transfer_encoding);
        if content_type.starts_with("image/") {
            if let Some(cid) = headers
                .get("content-id")
                .map(|v| v.trim().trim_matches('<').trim_matches('>').to_string())
            {
                let bytes = decode_transfer_bytes(part_body, &transfer_encoding);
                parsed.inline_images.insert(
                    cid,
                    format!(
                        "data:{};base64,{}",
                        content_type_raw
                            .split(';')
                            .next()
                            .unwrap_or("application/octet-stream"),
                        base64::engine::general_purpose::STANDARD.encode(bytes)
                    ),
                );
            }
        } else if content_type.contains("text/plain") && parsed.text_body.is_none() {
            parsed.text_body = Some(decoded);
        } else if content_type.contains("text/html") && parsed.html_body.is_none() {
            parsed.html_body = Some(decoded);
        }
    }
    parsed
}

fn decode_transfer_text(input: &str, encoding: &str) -> String {
    String::from_utf8_lossy(&decode_transfer_bytes(input, encoding)).to_string()
}

fn decode_transfer_bytes(input: &str, encoding: &str) -> Vec<u8> {
    if encoding.contains("quoted-printable") {
        decode_quoted_printable(input.as_bytes())
    } else if encoding.contains("base64") {
        let compact = input.split_whitespace().collect::<String>();
        base64::engine::general_purpose::STANDARD
            .decode(compact)
            .unwrap_or_else(|_| input.as_bytes().to_vec())
    } else {
        input.as_bytes().to_vec()
    }
}

fn apply_inline_images(html: &str, inline_images: &HashMap<String, String>) -> String {
    let mut out = html.to_string();
    for (cid, data_url) in inline_images {
        out = out.replace(&format!("cid:{cid}"), data_url);
        out = out.replace(&format!("cid:<{cid}>"), data_url);
    }
    out
}

fn decode_quoted_printable(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'=' {
            if input.get(i + 1) == Some(&b'\r') && input.get(i + 2) == Some(&b'\n') {
                i += 3;
                continue;
            }
            if input.get(i + 1) == Some(&b'\n') {
                i += 2;
                continue;
            }
            if i + 2 < input.len()
                && let (Some(hi), Some(lo)) = (hex_val(input[i + 1]), hex_val(input[i + 2]))
            {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_rfc2047_words(input: &str) -> String {
    let mut out = String::new();
    let mut rest = input;
    while let Some(start) = rest.find("=?") {
        out.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let Some(charset_end) = after_start.find('?') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let charset = &after_start[..charset_end];
        let after_charset = &after_start[charset_end + 1..];
        let Some(enc_end) = after_charset.find('?') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let encoding = &after_charset[..enc_end];
        let after_encoding = &after_charset[enc_end + 1..];
        let Some(data_end) = after_encoding.find("?=") else {
            out.push_str(&rest[start..]);
            return out;
        };
        let data = &after_encoding[..data_end];
        if charset.eq_ignore_ascii_case("utf-8") || charset.eq_ignore_ascii_case("us-ascii") {
            if encoding.eq_ignore_ascii_case("q") {
                let qp = data.replace('_', " ");
                out.push_str(&String::from_utf8_lossy(&decode_quoted_printable(
                    qp.as_bytes(),
                )));
            } else if encoding.eq_ignore_ascii_case("b") {
                match base64::engine::general_purpose::STANDARD.decode(data) {
                    Ok(bytes) => out.push_str(&String::from_utf8_lossy(&bytes)),
                    Err(_) => out.push_str(data),
                }
            } else {
                out.push_str(data);
            }
        } else {
            out.push_str(data);
        }
        rest = &after_encoding[data_end + 2..];
    }
    out.push_str(rest);
    out
}

fn strip_html(input: &str) -> String {
    let input = remove_html_block(input, "head");
    let input = remove_html_block(&input, "style");
    let input = remove_html_block(&input, "script");
    let input = remove_html_block(&input, "noscript");
    let input = remove_html_comments(&input);
    let mut out = String::new();
    let mut in_tag = false;
    let mut last_was_space = false;
    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                if !last_was_space {
                    out.push(' ');
                    last_was_space = true;
                }
            }
            _ if !in_tag => {
                if ch.is_whitespace() {
                    if !last_was_space {
                        out.push(' ');
                        last_was_space = true;
                    }
                } else {
                    out.push(ch);
                    last_was_space = false;
                }
            }
            _ => {}
        }
    }
    html_unescape(&out).trim().to_string()
}

fn remove_html_block(input: &str, tag: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    loop {
        let lower = rest.to_ascii_lowercase();
        let Some(start) = lower.find(&open) else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..start]);
        let after_open = &rest[start..];
        let lower_after = &lower[start..];
        if let Some(end) = lower_after.find(&close) {
            rest = &after_open[end + close.len()..];
        } else {
            break;
        }
    }
    out
}

fn remove_html_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    loop {
        let Some(start) = rest.find("<!--") else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..start]);
        let after = &rest[start + 4..];
        if let Some(end) = after.find("-->") {
            rest = &after[end + 3..];
        } else {
            break;
        }
    }
    out
}

fn has_remote_content(html: &str) -> bool {
    let lower = html.to_ascii_lowercase();
    [
        "src=\"http",
        "src='http",
        "src=http",
        "src=\"//",
        "src='//",
        "url(http",
        "url('http",
        "url(\"http",
        "url(//",
        "background=\"http",
        "srcset=\"http",
        "@import",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// Content policy for a rendered message. Remote images, fonts and styles are
/// blocked by default so opening a message cannot be tracked.
fn message_csp(allow_remote_content: bool) -> &'static str {
    if allow_remote_content {
        "default-src 'none'; img-src data: cid: https: http:; style-src 'unsafe-inline' https: http:; font-src data: https: http:"
    } else {
        "default-src 'none'; img-src data: cid:; style-src 'unsafe-inline'; font-src data:"
    }
}

fn sanitize_email_html(input: &str, allow_remote_content: bool) -> String {
    let input = remove_html_block(input, "script");
    let input = remove_html_block(&input, "iframe");
    let input = remove_html_block(&input, "object");
    let input = remove_html_block(&input, "embed");
    let input = remove_html_comments(&input);
    let mut out = String::with_capacity(input.len() + 128);
    let mut rest = input.as_str();
    while let Some(start) = rest.find('<') {
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        let Some(end) = after.find('>') else {
            break;
        };
        let tag = &after[..=end];
        out.push_str(&sanitize_html_tag(tag));
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    format!(
        r#"<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="{}"><base target="_blank"><style>html,body{{margin:0;padding:0;background:#fff;color:#222831;font:14px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;overflow-wrap:anywhere}}img{{max-width:100%;height:auto}}table{{max-width:100%;border-collapse:collapse}}a{{color:#276ef1}}</style></head><body>{}</body></html>"#,
        message_csp(allow_remote_content),
        out
    )
}

fn sanitize_html_tag(tag: &str) -> String {
    let lower = tag.to_ascii_lowercase();
    if lower.starts_with("<script")
        || lower.starts_with("</script")
        || lower.starts_with("<iframe")
        || lower.starts_with("</iframe")
        || lower.starts_with("<object")
        || lower.starts_with("</object")
        || lower.starts_with("<embed")
        || lower.starts_with("</embed")
        || lower.starts_with("<meta")
        || lower.starts_with("<link")
    {
        return String::new();
    }

    let mut cleaned = String::with_capacity(tag.len());
    let bytes = tag.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            let attr_start = i;
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            let name_start = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'-' || bytes[i] == b':')
            {
                i += 1;
            }
            let name = tag[name_start..i].to_ascii_lowercase();
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'=' {
                i += 1;
                while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                    let quote = bytes[i];
                    i += 1;
                    while i < bytes.len() && bytes[i] != quote {
                        i += 1;
                    }
                    if i < bytes.len() {
                        i += 1;
                    }
                } else {
                    while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
                        i += 1;
                    }
                }
            }
            if name.starts_with("on") || name == "srcdoc" {
                continue;
            }
            cleaned.push_str(&tag[attr_start..i]);
        } else {
            cleaned.push(bytes[i] as char);
            i += 1;
        }
    }
    cleaned
}

fn snippet(input: &str) -> String {
    let compact = input.split_whitespace().collect::<Vec<_>>().join(" ");
    compact.chars().take(160).collect()
}

fn set_flag(flags: &mut Vec<String>, flag: &str, enabled: bool) {
    if enabled && !flags.iter().any(|f| f.eq_ignore_ascii_case(flag)) {
        flags.push(flag.to_string());
    } else if !enabled {
        flags.retain(|f| !f.eq_ignore_ascii_case(flag));
    }
}

fn split_address(address: &str) -> Option<(String, String)> {
    let (local, domain) = address.split_once('@')?;
    if local.is_empty() || domain.is_empty() || local.contains('/') || domain.contains('/') {
        return None;
    }
    Some((local.to_string(), domain.to_string()))
}

fn split_target(target: &str) -> (String, HashMap<String, String>) {
    let (path, raw_query) = target.split_once('?').unwrap_or((target, ""));
    let query = raw_query
        .split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((decode_path(k), decode_path(v)))
        })
        .collect();
    (decode_path(path), query)
}

fn decode_path(value: &str) -> String {
    percent_decode_str(value).decode_utf8_lossy().to_string()
}

fn html_unescape(input: &str) -> String {
    input
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&amp;", "&")
}

fn static_spa(path: &str, state: &AppState) -> Response {
    if state.static_dir.is_dir() {
        let relative = if path == "/" {
            "index.html"
        } else {
            path.trim_start_matches('/')
        };
        if !relative
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        {
            let file_path = state.static_dir.join(relative);
            if file_path.is_file()
                && let Ok(body) = fs::read(&file_path)
            {
                return Response {
                    status: 200,
                    content_type: static_content_type(&file_path),
                    headers: vec![("Cache-Control".to_string(), "no-cache".to_string())],
                    body,
                };
            }
        }
        let index = state.static_dir.join("index.html");
        if index.is_file()
            && let Ok(body) = fs::read(index)
        {
            return Response {
                status: 200,
                content_type: "text/html; charset=utf-8",
                headers: vec![("Cache-Control".to_string(), "no-cache".to_string())],
                body,
            };
        }
    }
    embedded_spa()
}

fn static_content_type(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()).unwrap_or("") {
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "ico" => "image/x-icon",
        "html" => "text/html; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn embedded_spa() -> Response {
    Response {
        status: 200,
        content_type: "text/html; charset=utf-8",
        headers: vec![
            ("Cache-Control".to_string(), "no-cache".to_string()),
            // The built-in fallback page carries its script inline.
            (
                "Content-Security-Policy".to_string(),
                APP_CSP.replacen(
                    "default-src 'self'",
                    "default-src 'self'; script-src 'self' 'unsafe-inline'",
                    1,
                ),
            ),
        ],
        body: EMBEDDED_SPA.as_bytes().to_vec(),
    }
}

const EMBEDDED_SPA: &str = r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>rMail Webmail</title>
    <style>
      html,body,#root{height:100%}body{margin:0;overflow:hidden;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f5f7f8;color:#222831}
      button,input{font:inherit}button{cursor:pointer}.login{min-height:100vh;display:grid;place-items:center;background:#edf3f2}
      form{width:min(360px,calc(100vw - 32px));display:grid;gap:12px;padding:24px;background:#fff;border:1px solid #d8dee2;border-radius:8px}
      input{border:1px solid #cfd7dc;border-radius:6px;padding:10px 12px}form button,.bar button{border:0;border-radius:6px;padding:10px 14px;background:#276ef1;color:#fff}
      .app{height:100vh;min-height:0;display:grid;grid-template-columns:220px minmax(340px,.95fr) minmax(380px,1.15fr);overflow:hidden}.folders{background:#24313a;color:#eef5f6;padding:14px 10px;overflow:auto}
      .folders button{width:100%;display:flex;justify-content:space-between;border:0;background:transparent;color:inherit;border-radius:6px;padding:9px 10px}.folders .active,.folders button:hover{background:#38505c}
      .list{display:grid;grid-template-rows:58px minmax(0,1fr);border-right:1px solid #d8dee2;min-width:0;min-height:0;background:#fff}.bar{display:flex;gap:8px;align-items:center;padding:8px 12px;border-bottom:1px solid #d8dee2}.bar input{flex:1;min-width:0;background:#f3f6f7}
      .list>div{min-height:0;overflow:auto}.msg{display:grid;grid-template-columns:140px 1fr;gap:4px 12px;width:100%;border:0;border-bottom:1px solid #e3e8eb;background:#fff;text-align:left;padding:12px}.msg.unread{font-weight:700}.msg small{grid-column:2;color:#667780;font-weight:400;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
      .reader{min-height:0;background:#fff;padding:24px;overflow:hidden;display:flex;flex-direction:column}.reader-actions{display:flex;gap:8px;margin-bottom:18px}.reader pre{flex:1 1 auto;min-height:0;overflow:auto;white-space:pre-wrap;font-family:inherit;line-height:1.5}.html-message{flex:1 1 auto;min-height:0;width:100%;height:100%;border:0;background:#fff}.muted{color:#667780}
      @media(max-width:820px){.app{display:block}.folders,.list,.reader{height:auto;min-height:33vh}.msg{grid-template-columns:1fr}.msg small{grid-column:1}}
    </style>
  </head>
  <body><div id="root" class="login"></div><script>
    const root=document.getElementById('root');let folder='INBOX',q='';
    async function api(url,options={}){const r=await fetch(url,{credentials:'same-origin',headers:{'Content-Type':'application/json','X-Rmail-Webmail':'1'},...options});if(!r.ok)throw new Error(await r.text()||r.statusText);return r.status===204?null:r.json()}
    function esc(s){return (s||'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
    async function load(){try{const s=await api('/api/session'),folders=await api('/api/folders'),msgs=await api('/api/folders/'+encodeURIComponent(folder)+'/messages?limit=100&q='+encodeURIComponent(q));root.className='app';root.innerHTML='<aside class="folders"><p class="muted">'+esc(s.address)+'</p>'+folders.map(f=>'<button class="'+(f.name===folder?'active':'')+'" data-folder="'+esc(f.name)+'"><span>'+esc(f.name)+'</span><small>'+(f.unread||f.messages)+'</small></button>').join('')+'</aside><main class="list"><div class="bar"><input id="q" placeholder="Search mail" value="'+esc(q)+'"><button id="refresh">Refresh</button></div><div>'+msgs.map(m=>'<button class="msg '+(m.flags.some(f=>f.toLowerCase()==='\\\\seen')?'':'unread')+'" data-uid="'+m.uid+'"><span>'+esc(m.from||'(unknown)')+'</span><span>'+esc(m.subject||'(no subject)')+'</span><small>'+esc(m.snippet)+'</small></button>').join('')+'</div></main><article class="reader" id="reader">Select a message</article>';document.querySelector('.folders').onclick=e=>{const b=e.target.closest('button[data-folder]');if(b){folder=b.dataset.folder;load()}};document.getElementById('refresh').onclick=()=>{q=document.getElementById('q').value;load()};document.getElementById('q').onkeydown=e=>{if(e.key==='Enter'){q=e.target.value;load()}};document.querySelector('.list').onclick=async e=>{const b=e.target.closest('button[data-uid]');if(!b)return;const m=await api('/api/folders/'+encodeURIComponent(folder)+'/messages/'+b.dataset.uid);const body=m.html_body?'<iframe class="html-message" sandbox="allow-popups allow-popups-to-escape-sandbox"></iframe>':'<pre>'+esc(m.text_body)+'</pre>';document.getElementById('reader').innerHTML='<div class="reader-actions"><button id="archive">Archive</button><button id="delete">Delete</button></div><h2>'+esc(m.subject||'(no subject)')+'</h2><p class="muted">From '+esc(m.from||'(unknown)')+' to '+esc(m.to||s.address)+'</p>'+body;if(m.html_body){document.querySelector('.html-message').srcdoc=m.html_body}window.currentUid=Number(b.dataset.uid);document.getElementById('archive').onclick=()=>bulk('archive');document.getElementById('delete').onclick=()=>bulk('delete')}}catch{login()}}
    async function bulk(action){if(!window.currentUid)return;await api('/api/folders/'+encodeURIComponent(folder)+'/messages/bulk',{method:'POST',body:JSON.stringify({action,uids:[window.currentUid]})});window.currentUid=null;load()}
    function login(){root.className='login';root.innerHTML='<form id="login"><h1>rMail</h1><input name="address" placeholder="Mailbox" autocomplete="username"><input name="password" placeholder="Password" type="password" autocomplete="current-password"><button>Sign in</button><p id="err"></p></form>';document.getElementById('login').onsubmit=async e=>{e.preventDefault();const fd=new FormData(e.target);try{await api('/api/login',{method:'POST',body:JSON.stringify({address:fd.get('address'),password:fd.get('password')})});load()}catch{document.getElementById('err').textContent='Invalid mailbox or password'}}}
    load();
  </script></body>
</html>"#;

fn json<T: Serialize>(status: u16, value: &T) -> Response {
    Response {
        status,
        content_type: "application/json",
        headers: Vec::new(),
        body: serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec()),
    }
}

impl Response {
    fn empty(status: u16) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn text(status: u16, text: &str) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            headers: Vec::new(),
            body: text.as_bytes().to_vec(),
        }
    }

    fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((key.into(), value.into()));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmail_common::maildir;

    fn state(td: &tempfile::TempDir) -> AppState {
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
        AppState {
            mail_root: td.path().join("mail"),
            db_path,
            static_dir: td.path().join("static"),
            session_secret: b"test secret".to_vec(),
            secure_cookies: false,
            throttle: AuthThrottle::default(),
            revoked: websession::RevocationList::default(),
        }
    }

    fn req(method: &str, path: &str, body: &[u8], cookie: Option<String>) -> Request {
        let mut headers = HashMap::new();
        if let Some(cookie) = cookie {
            headers.insert("cookie".to_string(), cookie);
        }
        headers.insert(CSRF_HEADER.to_string(), "1".to_string());
        let (path, query) = split_target(path);
        Request {
            method: method.to_string(),
            path,
            query,
            headers,
            body: body.to_vec(),
            peer: Some("192.0.2.1".parse().unwrap()),
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

    #[test]
    fn parse_message_decodes_quoted_printable_html() {
        let parsed = parse_message(
            b"From: =?UTF-8?Q?Glassdoor_Jobs?= <noreply@example.test>\r\nSubject: =?UTF-8?Q?Apply_Now_=E2=80=93_Aarhus?=\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n<p>Vestas Wind Systems =E2=80=93 apply now.</p>",
        );

        assert_eq!(parsed.from, "Glassdoor Jobs <noreply@example.test>");
        assert_eq!(parsed.subject, "Apply Now – Aarhus");
        assert_eq!(parsed.text_body, "Vestas Wind Systems – apply now.");
    }

    #[test]
    fn parse_message_drops_html_styles_from_visible_text() {
        let parsed = parse_message(
            b"From: jobs@example.test\r\nSubject: styled\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n<html><head><style>@font-face { font-family: 'Glassdoor Sans'; src: url(font.woff2); } body { color: red; }</style></head><body><h1>Apply Now</h1><p>Vestas Wind Systems =E2=80=93 Aarhus</p></body></html>",
        );

        assert_eq!(parsed.text_body, "Apply Now Vestas Wind Systems – Aarhus");
        assert!(!parsed.text_body.contains("@font-face"));
        assert!(!parsed.text_body.contains("font-family"));
    }

    #[test]
    fn parse_message_prefers_plain_part_from_multipart() {
        let parsed = parse_message(
            b"From: a@example.test\r\nSubject: multipart\r\nContent-Type: multipart/alternative; boundary=\"b1\"\r\n\r\n--b1\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nPlain =E2=80=93 text\r\n--b1\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n<p>HTML =E2=80=93 text</p>\r\n--b1--\r\n",
        );

        assert_eq!(parsed.text_body, "Plain – text");
        assert_eq!(parsed.html_body.as_deref(), Some("<p>HTML – text</p>"));
    }

    #[test]
    fn parse_message_rewrites_inline_cid_images() {
        let parsed = parse_message(
            b"From: a@example.test\r\nSubject: image\r\nContent-Type: multipart/related; boundary=\"rel\"\r\n\r\n--rel\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<p>Logo <img src=\"cid:logo@example.test\"></p>\r\n--rel\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\nContent-ID: <logo@example.test>\r\n\r\naGVsbG8=\r\n--rel--\r\n",
        );

        let html = parsed.html_body.unwrap();
        assert!(html.contains("Logo"));
        assert!(html.contains("src=\"data:image/png;base64,aGVsbG8=\""));
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
        request.headers.remove(CSRF_HEADER);
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

    #[test]
    fn remote_content_is_blocked_unless_requested() {
        let html = r#"<p>Hi</p><img src="https://tracker.example/pixel.gif">"#;
        assert!(has_remote_content(html));
        assert!(!has_remote_content(
            "<p>plain</p><img src=\"data:image/png;base64,AA\">"
        ));
        let blocked = sanitize_email_html(html, false);
        assert!(blocked.contains("img-src data: cid:;"), "{blocked}");
        let allowed = sanitize_email_html(html, true);
        assert!(
            allowed.contains("img-src data: cid: https: http:"),
            "{allowed}"
        );
    }
}
