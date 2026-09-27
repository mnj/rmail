//! HTTP layer of the admin console: request reading, authentication, CSRF
//! protection and routing. Data access helpers live in `main.rs`.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use rmail_common::http::{HttpLimits, HttpRequest, read_request, reason_phrase};
use rmail_common::throttle::AuthThrottle;
use rmail_common::websession;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::*;

pub(crate) const SESSION_COOKIE: &str = "rmail_admin";
const SESSION_TTL_SECS: u64 = 12 * 60 * 60;
/// Mutating requests must carry this header. Browsers cannot add custom
/// headers to cross-site form posts, so this blocks CSRF for both cookie and
/// Basic authentication.
pub(crate) const CSRF_HEADER: &str = "x-rmail-admin";
const BASIC_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const MIN_ADMIN_PASSWORD_CHARS: usize = 10;

pub(crate) struct AdminState {
    pub mail_root: PathBuf,
    pub db_path: Option<String>,
    /// Credentials from the configuration file; used when the settings
    /// database holds none (file-only deployments).
    pub file_admin: Option<(String, String)>,
    pub acme_dir: Option<String>,
    pub readiness: ReadinessConfig,
    /// Re-read readiness settings from here so edits show up without restart.
    pub config_path: Option<String>,
    pub secure_cookies: bool,
    pub session_key: Vec<u8>,
    pub throttle: AuthThrottle,
    pub revoked: websession::RevocationList,
    basic_cache: Mutex<HashMap<[u8; 32], Instant>>,
}

impl AdminState {
    pub fn new(
        mail_root: PathBuf,
        db_path: Option<String>,
        file_admin: Option<(String, String)>,
        acme_dir: Option<String>,
        readiness: ReadinessConfig,
    ) -> Self {
        let mut session_key = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut session_key);
        Self {
            mail_root,
            db_path,
            file_admin,
            acme_dir,
            readiness,
            config_path: None,
            secure_cookies: false,
            session_key,
            throttle: AuthThrottle::default(),
            revoked: websession::RevocationList::default(),
            basic_cache: Mutex::new(HashMap::new()),
        }
    }
}

pub(crate) struct Response {
    status: u16,
    content_type: &'static str,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

impl Response {
    fn new(status: u16, content_type: &'static str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    fn json(status: u16, value: &impl serde::Serialize) -> Self {
        match serde_json::to_vec(value) {
            Ok(body) => Self::new(status, "application/json", body),
            Err(error) => Self::error(500, &error.to_string()),
        }
    }

    fn ok() -> Self {
        Self::json(200, &json!({"result": "ok"}))
    }

    fn text(status: u16, body: impl Into<String>) -> Self {
        Self::new(status, "text/plain; charset=utf-8", body.into())
    }

    /// JSON error body the frontend can show verbatim.
    fn error(status: u16, message: &str) -> Self {
        Self::json(status, &json!({"error": message}))
    }

    fn with_header(mut self, name: &'static str, value: String) -> Self {
        self.headers.push((name, value));
        self
    }
}

fn method_not_allowed() -> Response {
    Response::error(405, "method not allowed")
}

/// 401 response. API clients (curl, Prometheus) get a Basic challenge; the
/// console's own requests do not, so browsers never show their native dialog.
fn unauthorized(request: &HttpRequest) -> Response {
    let response = Response::error(401, "authentication required");
    if request.header(CSRF_HEADER).is_some() {
        response
    } else {
        response.with_header("WWW-Authenticate", "Basic realm=\"rMail\"".to_string())
    }
}

pub(crate) async fn serve<S>(mut stream: S, peer: String, state: Arc<AdminState>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request_id = rmail_common::tracking::new_tracking_id("admin-http");
    let limits = HttpLimits {
        max_body_bytes: 1024 * 1024,
        ..HttpLimits::default()
    };
    let (response, method, target) = match read_request(&mut stream, limits).await {
        Ok(request) => {
            let method = request.method.clone();
            let target = request.path.clone();
            (route(request, &peer, &state).await, method, target)
        }
        Err(error) => match error.status() {
            Some(status) => (
                Response::error(status, reason_phrase(status)),
                String::new(),
                String::new(),
            ),
            None => return,
        },
    };
    let status = response.status;
    let bytes = response.body.len();
    let _ = write_response(&mut stream, response).await;
    let _ = stream.shutdown().await;
    web_log!("info", "request_completed", { "request_id": request_id, "peer": peer, "method": method, "path": target, "status": status, "response_bytes": bytes });
}

async fn write_response<S: AsyncWrite + Unpin>(stream: &mut S, response: Response) -> Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\
         X-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\n\
         Cache-Control: no-store\r\n\
         Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'\r\n",
        response.status,
        reason_phrase(response.status),
        response.body.len(),
        response.content_type,
    );
    for (name, value) in &response.headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&response.body).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Authentication

#[derive(Debug, Clone, PartialEq, Eq)]
enum Principal {
    /// No admin credentials exist yet. Only possible on loopback listeners.
    Setup,
    Admin(String),
}

fn peer_ip(peer: &str) -> Option<IpAddr> {
    peer.parse::<std::net::SocketAddr>()
        .map(|address| address.ip())
        .ok()
}

/// Current admin credentials: the settings database wins over the file.
async fn admin_credentials(state: &AdminState) -> Result<Option<(String, String)>> {
    if let Some(db_path) = state.db_path.clone() {
        let stored = tokio::task::spawn_blocking(move || -> Result<Option<(String, String)>> {
            let conn = rmail_common::settings::open(&db_path)?;
            let user = rmail_common::settings::get_string(&conn, "global.web_admin_user")?;
            let hash = rmail_common::settings::get_string(&conn, "global.web_admin_password_hash")?;
            Ok(user.zip(hash))
        })
        .await
        .map_err(|error| anyhow!("credential lookup failed: {error}"))??;
        if stored.is_some() {
            return Ok(stored);
        }
    }
    Ok(state.file_admin.clone())
}

async fn authenticate(
    request: &HttpRequest,
    peer: &str,
    state: &AdminState,
) -> std::result::Result<Principal, Response> {
    let credentials = admin_credentials(state)
        .await
        .map_err(|error| Response::error(503, &error.to_string()))?;
    let Some((user, hash)) = credentials else {
        return Ok(Principal::Setup);
    };
    if let Some(token) = request
        .header("cookie")
        .and_then(|cookie| websession::cookie_value(cookie, SESSION_COOKIE))
        && !state.revoked.is_revoked(token)
        && let Some(session) = websession::verify(&state.session_key, token)
        && session.subject == user
        && session.binding == websession::credential_binding(&state.session_key, &hash)
    {
        return Ok(Principal::Admin(user));
    }
    let Some((basic_user, basic_password)) = request.header("authorization").and_then(parse_basic)
    else {
        return Err(unauthorized(request));
    };
    if let Some(ip) = peer_ip(peer)
        && let Some(remaining) = state.throttle.blocked_for(ip)
    {
        return Err(too_many_attempts(remaining));
    }
    if check_password(state, &user, &hash, &basic_user, &basic_password).await {
        Ok(Principal::Admin(user))
    } else {
        if let Some(ip) = peer_ip(peer) {
            state.throttle.record_failure(ip);
        }
        Err(unauthorized(request))
    }
}

fn too_many_attempts(remaining: Duration) -> Response {
    Response::error(
        429,
        &format!(
            "too many failed sign-in attempts; try again in {} minutes",
            remaining.as_secs().div_ceil(60)
        ),
    )
    .with_header("Retry-After", remaining.as_secs().to_string())
}

fn parse_basic(header: &str) -> Option<(String, String)> {
    let (scheme, encoded) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, password) = decoded.split_once(':')?;
    Some((user.to_string(), password.to_string()))
}

/// Verify admin credentials. Successful Basic logins are cached briefly so
/// API clients do not pay for Argon2 on every request.
async fn check_password(
    state: &AdminState,
    user: &str,
    hash: &str,
    given_user: &str,
    given_password: &str,
) -> bool {
    let cache_key: [u8; 32] = Sha256::new()
        .chain_update(given_user.as_bytes())
        .chain_update([0])
        .chain_update(given_password.as_bytes())
        .chain_update([0])
        .chain_update(hash.as_bytes())
        .finalize()
        .into();
    {
        let mut cache = state
            .basic_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        cache.retain(|_, expiry| *expiry > now);
        if cache.contains_key(&cache_key) {
            return true;
        }
    }
    let user_matches = rmail_common::http::constant_time_eq(user.as_bytes(), given_user.as_bytes());
    let valid =
        rmail_common::auth::verify_password_async(given_password.to_string(), hash.to_string())
            .await
            .unwrap_or(false)
            && user_matches;
    if valid {
        state
            .basic_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(cache_key, Instant::now() + BASIC_CACHE_TTL);
    }
    valid
}

fn session_cookie(state: &AdminState, user: &str, hash: &str) -> String {
    let binding = websession::credential_binding(&state.session_key, hash);
    let token = websession::sign(&state.session_key, user, &binding, SESSION_TTL_SECS);
    websession::set_cookie(
        SESSION_COOKIE,
        &token,
        SESSION_TTL_SECS,
        state.secure_cookies,
        "Strict",
    )
}

fn clear_cookie(state: &AdminState) -> String {
    websession::set_cookie(SESSION_COOKIE, "", 0, state.secure_cookies, "Strict")
}

/// Reject cross-site state changes: require the custom header and, when the
/// browser sends an Origin, require it to match the Host.
fn check_csrf(request: &HttpRequest) -> Option<Response> {
    if matches!(request.method.as_str(), "GET" | "HEAD") {
        return None;
    }
    if request.header(CSRF_HEADER).is_none() {
        return Some(Response::error(
            403,
            &format!("missing {CSRF_HEADER} header"),
        ));
    }
    if let (Some(origin), Some(host)) = (request.header("origin"), request.header("host")) {
        let origin_host = origin
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(origin);
        if !origin_host.eq_ignore_ascii_case(host) {
            return Some(Response::error(403, "cross-origin request rejected"));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Routing

fn is_acme_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 256
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

async fn blocking<T, F>(work: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| anyhow!("background task failed: {error}"))?
}

fn json_body<T: for<'de> Deserialize<'de>>(
    request: &HttpRequest,
) -> std::result::Result<T, Response> {
    serde_json::from_slice(&request.body)
        .map_err(|error| Response::error(400, &format!("invalid JSON: {error}")))
}

fn result_response<T: serde::Serialize>(result: Result<T>, error_status: u16) -> Response {
    match result {
        Ok(value) => Response::json(200, &value),
        Err(error) => Response::error(error_status, &format!("{error:#}")),
    }
}

fn require_db(state: &AdminState) -> std::result::Result<String, Response> {
    state
        .db_path
        .clone()
        .ok_or_else(|| Response::error(400, "no database is configured (global.db_path)"))
}

pub(crate) async fn route(request: HttpRequest, peer: &str, state: &Arc<AdminState>) -> Response {
    let method = request.method.as_str();
    let path = request.path.as_str();

    // Public endpoints.
    if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
        if method != "GET" {
            return method_not_allowed();
        }
        let (Some(dir), true) = (state.acme_dir.as_ref(), is_acme_token(token)) else {
            return Response::text(404, "Not Found");
        };
        return match tokio::fs::read(PathBuf::from(dir).join(token)).await {
            Ok(body) => Response::new(200, "text/plain", body),
            Err(_) => Response::text(404, "Not Found"),
        };
    }
    match path {
        "/health" | "/healthz" => {
            return if method == "GET" {
                Response::text(200, "ok")
            } else {
                method_not_allowed()
            };
        }
        "/ready" | "/readyz" => {
            if method != "GET" {
                return method_not_allowed();
            }
            let report = readiness_report(
                state.mail_root.clone(),
                state.db_path.clone(),
                current_readiness(state).await,
            )
            .await;
            return Response::json(if report.ready { 200 } else { 503 }, &report);
        }
        _ => {}
    }
    if !path.starts_with("/api/") && !matches!(path, "/stats" | "/metrics" | "/dmarc" | "/logs") {
        return if method == "GET" {
            static_asset(path)
        } else {
            Response::error(404, "not found")
        };
    }
    if let Some(response) = check_csrf(&request) {
        return response;
    }

    match (method, path) {
        ("GET", "/api/session") => return session_info(&request, state).await,
        ("POST", "/api/login") => return login(&request, peer, state).await,
        ("POST", "/api/logout") => {
            if let Some(token) = request
                .header("cookie")
                .and_then(|cookie| websession::cookie_value(cookie, SESSION_COOKIE))
                && let Some(session) = websession::verify(&state.session_key, token)
            {
                state.revoked.revoke(token, session.expires_at);
            }
            return Response::ok().with_header("Set-Cookie", clear_cookie(state));
        }
        _ => {}
    }

    let principal = match authenticate(&request, peer, state).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };

    let mail_root = state.mail_root.clone();
    let db_path = state.db_path.clone();
    match (method, path) {
        ("GET", "/stats") => {
            let root = mail_root.clone();
            match blocking(move || scan_maildirs_sync(&root)).await {
                Ok(mut stats) => {
                    stats.delivered_count = tokio::fs::read_to_string(
                        rmail_common::runtime::delivered_count_path(&mail_root),
                    )
                    .await
                    .ok()
                    .and_then(|text| text.trim().parse().ok())
                    .unwrap_or(0);
                    Response::json(200, &stats)
                }
                Err(error) => Response::error(500, &error.to_string()),
            }
        }
        ("GET", "/metrics") => Response::new(
            200,
            "text/plain; version=0.0.4",
            metrics_text(&mail_root).await,
        ),
        ("GET", "/dmarc") => match require_db(state) {
            Ok(db) => result_response(blocking(move || dmarc_summary_sync(&db)).await, 500),
            Err(response) => response,
        },
        ("GET", "/logs") => {
            let params = request.query_params();
            let component = params
                .get("component")
                .map(String::as_str)
                .unwrap_or("smtpd");
            let lines = params
                .get("lines")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(200)
                .min(2000);
            if !matches!(
                component,
                "smtpd" | "imapd" | "web" | "outbound" | "webmail"
            ) {
                return Response::error(400, "invalid component");
            }
            let path = rmail_common::runtime::log_path(&mail_root, component);
            match tokio::fs::read(&path).await {
                Ok(bytes) => {
                    Response::text(200, tail_lines(&String::from_utf8_lossy(&bytes), lines))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Response::text(200, "")
                }
                Err(error) => Response::error(500, &format!("reading {}: {error}", path.display())),
            }
        }
        ("GET", "/api/overview") => result_response(
            blocking(move || overview_summary_sync(&mail_root, db_path.as_deref())).await,
            500,
        ),
        ("GET", "/api/queue/summary") => {
            result_response(blocking(move || queue_summary_sync(&mail_root)).await, 500)
        }
        ("GET", "/api/queue") => {
            let spool = request
                .query_params()
                .get("spool")
                .cloned()
                .unwrap_or_else(|| "queue".to_string());
            result_response(
                blocking(move || queue_listing_sync(&mail_root, &spool)).await,
                400,
            )
        }
        ("POST", "/api/queue/action") => queue_action(&request, None, state).await,
        ("POST", "/api/queue/requeue") => queue_action(&request, Some("requeue"), state).await,
        ("POST", "/api/queue/promote") => queue_action(&request, Some("promote"), state).await,
        ("POST", "/api/queue/delete") => queue_action(&request, Some("delete"), state).await,
        (
            _,
            "/api/queue/action" | "/api/queue/requeue" | "/api/queue/promote" | "/api/queue/delete",
        ) => method_not_allowed(),
        ("GET", "/api/accounts") => result_response(
            blocking(move || account_summaries_sync(&mail_root, db_path.as_deref())).await,
            500,
        ),
        ("POST" | "PATCH", "/api/accounts") => {
            let db = match require_db(state) {
                Ok(db) => db,
                Err(response) => return response,
            };
            let mut input: AccountRequest = match json_body(&request) {
                Ok(input) => input,
                Err(response) => return response,
            };
            input.must_exist = method == "PATCH";
            result_response(
                blocking(move || {
                    upsert_account_sync(&mail_root, &db, input).map(|_| json!({"result": "ok"}))
                })
                .await,
                400,
            )
        }
        ("DELETE", "/api/accounts") => {
            let db = match require_db(state) {
                Ok(db) => db,
                Err(response) => return response,
            };
            let input: AccountDeleteRequest = match json_body(&request) {
                Ok(input) => input,
                Err(response) => return response,
            };
            result_response(
                blocking(move || delete_account_sync(&db, input).map(|_| json!({"result": "ok"})))
                    .await,
                400,
            )
        }
        ("GET", "/api/routing") => result_response(
            blocking(move || routing_summary_sync(db_path.as_deref())).await,
            500,
        ),
        ("POST" | "DELETE", "/api/routing/alias") => {
            let db = match require_db(state) {
                Ok(db) => db,
                Err(response) => return response,
            };
            let mut input: AliasRequest = match json_body(&request) {
                Ok(input) => input,
                Err(response) => return response,
            };
            if method == "DELETE" {
                input.targets = None;
            }
            result_response(
                blocking(move || upsert_alias_sync(&db, input).map(|_| json!({"result": "ok"})))
                    .await,
                400,
            )
        }
        ("POST" | "DELETE", "/api/routing/catchall") => {
            let db = match require_db(state) {
                Ok(db) => db,
                Err(response) => return response,
            };
            let mut input: CatchallRequest = match json_body(&request) {
                Ok(input) => input,
                Err(response) => return response,
            };
            if method == "DELETE" {
                input.target = None;
            }
            result_response(
                blocking(move || upsert_catchall_sync(&db, input).map(|_| json!({"result": "ok"})))
                    .await,
                400,
            )
        }
        ("GET", "/api/settings") => match require_db(state) {
            Ok(db) => result_response(blocking(move || settings_view_sync(&db)).await, 500),
            Err(_) => Response::json(200, &json!({"managed": false})),
        },
        ("PUT", "/api/settings") => {
            let db = match require_db(state) {
                Ok(db) => db,
                Err(response) => return response,
            };
            #[derive(Deserialize)]
            struct Changes {
                changes: BTreeMap<String, Value>,
            }
            let input: Changes = match json_body(&request) {
                Ok(input) => input,
                Err(response) => return response,
            };
            let result = blocking(move || {
                let mut conn = rmail_common::settings::open(&db)?;
                rmail_common::settings::update(&mut conn, &input.changes)?;
                settings_view_sync(&db)
            })
            .await;
            if let Ok(view) = &result {
                web_log!("info", "settings_updated", { "peer": peer, "revision": view["revision"] });
            }
            result_response(result, 422)
        }
        ("POST", "/api/admin/credentials") => {
            change_admin_credentials(&request, &principal, state).await
        }
        (_, path) if path.starts_with("/api/") => Response::error(404, "not found"),
        _ => method_not_allowed(),
    }
}

async fn current_readiness(state: &AdminState) -> ReadinessConfig {
    let Some(path) = state.config_path.clone() else {
        return state.readiness.clone();
    };
    let fallback = state.readiness.clone();
    blocking(move || rmail_common::config::Config::load(&path))
        .await
        .map(|config| readiness_from_config(&config))
        .unwrap_or(fallback)
}

async fn session_info(request: &HttpRequest, state: &AdminState) -> Response {
    let credentials = match admin_credentials(state).await {
        Ok(credentials) => credentials,
        Err(error) => return Response::error(503, &error.to_string()),
    };
    let setup_required = credentials.is_none();
    // Only look at the cookie here; Basic credentials are checked on use.
    let user = credentials.and_then(|(user, hash)| {
        let token = request
            .header("cookie")
            .and_then(|cookie| websession::cookie_value(cookie, SESSION_COOKIE))?;
        if state.revoked.is_revoked(token) {
            return None;
        }
        let session = websession::verify(&state.session_key, token)?;
        (session.subject == user
            && session.binding == websession::credential_binding(&state.session_key, &hash))
        .then_some(user)
    });
    Response::json(
        200,
        &json!({
            "authenticated": setup_required || user.is_some(),
            "user": user,
            "setup_required": setup_required,
            "settings_managed": state.db_path.is_some(),
        }),
    )
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login(request: &HttpRequest, peer: &str, state: &AdminState) -> Response {
    let input: LoginRequest = match json_body(request) {
        Ok(input) => input,
        Err(response) => return response,
    };
    let ip = peer_ip(peer);
    if let Some(remaining) = ip.and_then(|ip| state.throttle.blocked_for(ip)) {
        return too_many_attempts(remaining);
    }
    let credentials = match admin_credentials(state).await {
        Ok(credentials) => credentials,
        Err(error) => return Response::error(503, &error.to_string()),
    };
    let Some((user, hash)) = credentials else {
        return Response::error(409, "no admin account exists yet; set a password first");
    };
    if check_password(state, &user, &hash, input.username.trim(), &input.password).await {
        if let Some(ip) = ip {
            state.throttle.reset(ip);
        }
        web_log!("info", "admin_login", { "peer": peer, "user": user });
        Response::json(200, &json!({"user": user}))
            .with_header("Set-Cookie", session_cookie(state, &user, &hash))
    } else {
        if let Some(ip) = ip {
            state.throttle.record_failure(ip);
        }
        web_log!("warn", "admin_login_failed", { "peer": peer });
        Response::error(401, "invalid username or password")
    }
}

#[derive(Deserialize)]
struct CredentialsRequest {
    username: String,
    #[serde(default)]
    current_password: Option<String>,
    new_password: String,
}

async fn change_admin_credentials(
    request: &HttpRequest,
    principal: &Principal,
    state: &AdminState,
) -> Response {
    let db = match require_db(state) {
        Ok(db) => db,
        Err(_) => {
            return Response::error(
                400,
                "admin credentials are set in the configuration file when no database is configured",
            );
        }
    };
    let input: CredentialsRequest = match json_body(request) {
        Ok(input) => input,
        Err(response) => return response,
    };
    let username = input.username.trim().to_string();
    if username.is_empty() || username.contains(':') {
        return Response::error(422, "username must be non-empty and must not contain ':'");
    }
    if input.new_password.chars().count() < MIN_ADMIN_PASSWORD_CHARS {
        return Response::error(
            422,
            &format!("password must be at least {MIN_ADMIN_PASSWORD_CHARS} characters"),
        );
    }
    if let Principal::Admin(_) = principal {
        let (user, hash) = match admin_credentials(state).await {
            Ok(Some(credentials)) => credentials,
            Ok(None) => return Response::error(409, "admin credentials disappeared"),
            Err(error) => return Response::error(503, &error.to_string()),
        };
        let current = input.current_password.unwrap_or_default();
        if !check_password(state, &user, &hash, &user, &current).await {
            return Response::error(403, "current password is incorrect");
        }
    }
    let new_password = input.new_password;
    let hash = match blocking(move || {
        use argon2::password_hash::{PasswordHasher, SaltString};
        let salt = SaltString::generate(&mut rand::rngs::OsRng);
        argon2::Argon2::default()
            .hash_password(new_password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|error| anyhow!(error.to_string()))
    })
    .await
    {
        Ok(hash) => hash,
        Err(error) => return Response::error(500, &error.to_string()),
    };
    let stored_hash = hash.clone();
    let stored_user = username.clone();
    let result = blocking(move || {
        let mut conn = rmail_common::settings::open(&db)?;
        rmail_common::settings::write_raw(
            &mut conn,
            &BTreeMap::from([
                (
                    "global.web_admin_user".to_string(),
                    Some(Value::from(stored_user)),
                ),
                (
                    "global.web_admin_password_hash".to_string(),
                    Some(Value::from(stored_hash)),
                ),
            ]),
        )
    })
    .await;
    match result {
        Ok(_) => {
            web_log!("info", "admin_credentials_changed", { "user": username });
            // Changing the hash invalidates every other session; keep this one.
            Response::json(200, &json!({"user": username}))
                .with_header("Set-Cookie", session_cookie(state, &username, &hash))
        }
        Err(error) => Response::error(500, &error.to_string()),
    }
}

async fn queue_action(request: &HttpRequest, fixed: Option<&str>, state: &AdminState) -> Response {
    let input: Value = match json_body(request) {
        Ok(input) => input,
        Err(response) => return response,
    };
    let action = fixed
        .map(str::to_string)
        .or_else(|| {
            input
                .get("action")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();
    if !matches!(action.as_str(), "requeue" | "promote" | "delete") {
        return Response::error(400, "unknown action");
    }
    let name = input
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_string);
    let pattern = input
        .get("pattern")
        .and_then(Value::as_str)
        .map(str::to_string);
    let priority = input.get("priority").and_then(Value::as_i64).unwrap_or(0) as i32;
    let root = state.mail_root.clone();
    let result = blocking(move || -> Result<usize> {
        let targets = match (name, pattern) {
            (Some(name), _) => {
                let (spool, eml, control) = find_message_sync(&root, &name)?
                    .ok_or_else(|| anyhow!("message {name} not found"))?;
                vec![(spool, eml, control)]
            }
            (None, Some(pattern)) if !pattern.trim().is_empty() => {
                find_messages_matching_sync(&root, &pattern)?
                    .into_iter()
                    .map(|(spool, eml, control, _)| (spool, eml, control))
                    .collect()
            }
            _ => anyhow::bail!("missing name or pattern"),
        };
        for (spool, eml, control) in &targets {
            match action.as_str() {
                "requeue" => requeue_single_sync(spool, eml, control, &root)?,
                "promote" => promote_single_sync(spool, eml, control, &root, priority)?,
                _ => delete_single_sync(spool, eml, control, &root)?,
            }
        }
        Ok(targets.len())
    })
    .await;
    match result {
        Ok(count) => Response::json(200, &json!({"result": "ok", "affected": count})),
        Err(error) if error.to_string().contains("not found") => {
            Response::error(404, &error.to_string())
        }
        Err(error) => Response::error(400, &format!("{error:#}")),
    }
}

fn static_asset(path: &str) -> Response {
    match read_admin_static(path) {
        Some((content_type, body)) => Response::new(200, content_type, body),
        None if path == "/" || !path.contains('.') => {
            Response::new(200, "text/html; charset=utf-8", admin_app_html())
        }
        None => Response::text(404, "Not Found"),
    }
}
