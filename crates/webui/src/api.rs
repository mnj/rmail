//! HTTP API of the admin console: an axum router with authentication, CSRF
//! and security-header middleware. Data access helpers live in `main.rs`.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use axum::body::Bytes;
use axum::extract::{Path as UrlPath, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use rmail_common::http::Peer;
use rmail_common::throttle::AuthThrottle;
use rmail_common::websession;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[cfg(test)]
use tokio::io::{AsyncRead, AsyncWrite};

use crate::*;

pub(crate) mod certificates;
mod discovery;
mod organization;

pub(crate) const SESSION_COOKIE: &str = "rmail_admin";
const SESSION_TTL_SECS: u64 = 12 * 60 * 60;
/// Mutating requests must carry this header. Browsers cannot add custom
/// headers to cross-site form posts, so this blocks CSRF for both cookie and
/// Basic authentication.
pub(crate) const CSRF_HEADER: &str = "x-rmail-admin";
const BASIC_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_BODY_BYTES: usize = 1024 * 1024;
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

pub(crate) struct AdminState {
    pub mail_root: PathBuf,
    pub db_path: Option<String>,
    /// Credentials loaded at startup; the settings database is checked first
    /// on every login, so later changes take effect without a restart.
    pub file_admin: Option<(String, String)>,
    /// Where the plain-HTTP listener redirects to; `None` keeps the host.
    pub http_redirect_url: Option<String>,
    pub readiness: ReadinessConfig,
    /// Re-read readiness settings from here so edits show up without restart.
    pub config_path: Option<String>,
    pub secure_cookies: bool,
    pub session_key: Vec<u8>,
    pub throttle: AuthThrottle,
    pub revoked: websession::RevocationList,
    basic_cache: Mutex<HashMap<[u8; 32], Instant>>,
    downloads: organization::Downloads,
}

impl AdminState {
    pub fn new(
        mail_root: PathBuf,
        db_path: Option<String>,
        file_admin: Option<(String, String)>,
        readiness: ReadinessConfig,
    ) -> Self {
        let mut session_key = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut session_key);
        Self {
            mail_root,
            db_path,
            file_admin,
            http_redirect_url: None,
            readiness,
            config_path: None,
            secure_cookies: false,
            session_key,
            throttle: AuthThrottle::default(),
            revoked: websession::RevocationList::default(),
            basic_cache: Mutex::new(HashMap::new()),
            downloads: organization::Downloads::default(),
        }
    }
}

type Shared = Arc<AdminState>;

pub(crate) fn router(state: Shared) -> Router {
    let protected = Router::new()
        .route("/stats", get(stats))
        .route("/metrics", get(metrics))
        .route("/dmarc", get(dmarc))
        .route("/logs", get(logs))
        .route("/api/overview", get(overview))
        .route("/api/queue", get(queue_listing))
        .route("/api/queue/summary", get(queue_summary))
        .route("/api/queue/action", post(queue_action))
        .route("/api/queue/{action}", post(queue_action_path))
        .route(
            "/api/accounts",
            get(accounts)
                .post(save_account)
                .patch(update_account)
                .delete(delete_account),
        )
        .route("/api/sharing", get(sharing).delete(delete_sharing))
        .route("/api/routing", get(routing))
        .route("/api/routing/alias", post(save_alias).delete(delete_alias))
        .route(
            "/api/routing/catchall",
            post(save_catchall).delete(delete_catchall),
        )
        .route(
            "/api/routing/transport",
            post(save_transport).delete(delete_transport),
        )
        .route("/api/settings", get(settings).put(update_settings))
        .route("/api/services/restart", post(restart_services))
        .route("/api/admin/credentials", post(change_credentials))
        .merge(organization::routes())
        .merge(discovery::protected_routes())
        .merge(certificates::routes())
        .route_layer(middleware::from_fn_with_state(state.clone(), require_admin));
    let app = Router::new()
        .route(
            "/.well-known/acme-challenge/{*token}",
            get(certificates::challenge),
        )
        .route("/health", get(health))
        .route("/healthz", get(health))
        .route("/ready", get(ready))
        .route("/readyz", get(ready))
        .route("/api/session", get(session_info))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .merge(protected)
        .fallback(fallback)
        .layer(middleware::from_fn(reject_cross_site))
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn(log_request))
        .with_state(state.clone());
    // Public discovery endpoints sit outside the CSRF layer (see
    // `discovery::public_routes`), so they are merged after it.
    let app = app.merge(discovery::public_routes().with_state(state));
    rmail_common::http::harden(app, MAX_BODY_BYTES)
}

/// Serve one connection (used by the tests with in-memory streams).
#[cfg(test)]
pub(crate) async fn serve<S>(stream: S, peer: String, state: Shared)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let _ =
        rmail_common::http::serve_connection(stream, peer.parse().ok(), router(state), None).await;
}

// ---------------------------------------------------------------------------
// Responses

/// JSON error body the frontend can show verbatim.
fn error(status: StatusCode, message: impl AsRef<str>) -> Response {
    (status, Json(json!({"error": message.as_ref()}))).into_response()
}

fn ok() -> Response {
    Json(json!({"result": "ok"})).into_response()
}

fn outcome<T: serde::Serialize>(result: Result<T>, failure: StatusCode) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(err) => error(failure, format!("{err:#}")),
    }
}

/// An error answered as `{"error": message}` with the given status.
struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        error(self.0, self.1)
    }
}

/// Parse a JSON body regardless of Content-Type (scripts often omit it).
fn parse<T: DeserializeOwned>(body: &Bytes) -> std::result::Result<T, ApiError> {
    serde_json::from_slice(body)
        .map_err(|err| ApiError(StatusCode::BAD_REQUEST, format!("invalid JSON: {err}")))
}

fn require_db(state: &AdminState) -> std::result::Result<String, ApiError> {
    state.db_path.clone().ok_or_else(|| {
        ApiError(
            StatusCode::BAD_REQUEST,
            "no database is configured (global.db_path)".to_string(),
        )
    })
}

async fn blocking<T, F>(work: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|err| anyhow!("background task failed: {err}"))?
}

fn with_cookie(response: impl IntoResponse, cookie: String) -> Response {
    let mut response = response.into_response();
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

// ---------------------------------------------------------------------------
// Middleware

async fn log_request(request: Request, next: Next) -> Response {
    let request_id = rmail_common::tracking::new_tracking_id("admin-http");
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let peer = request
        .extensions()
        .get::<Peer>()
        .and_then(|peer| peer.0)
        .map(|address| address.to_string());
    let response = next.run(request).await;
    web_log!("info", "request_completed", { "request_id": request_id, "peer": peer, "method": method.as_str(), "path": path, "status": response.status().as_u16() });
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
        (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
    ] {
        headers
            .entry(name)
            .or_insert(HeaderValue::from_static(value));
    }
    response
}

/// Reject cross-site state changes: require the custom header and, when the
/// browser sends an Origin, require it to match the Host.
async fn reject_cross_site(request: Request, next: Next) -> Response {
    if matches!(*request.method(), Method::GET | Method::HEAD) {
        return next.run(request).await;
    }
    let headers = request.headers();
    if !headers.contains_key(CSRF_HEADER) {
        return error(
            StatusCode::FORBIDDEN,
            format!("missing {CSRF_HEADER} header"),
        );
    }
    if let (Some(origin), Some(host)) = (
        headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()),
        headers.get(header::HOST).and_then(|v| v.to_str().ok()),
    ) {
        let origin_host = origin
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(origin);
        if !origin_host.eq_ignore_ascii_case(host) {
            return error(StatusCode::FORBIDDEN, "cross-origin request rejected");
        }
    }
    next.run(request).await
}

/// Authenticate the request and attach the [`Principal`].
async fn require_admin(State(state): State<Shared>, mut request: Request, next: Next) -> Response {
    let peer = request
        .extensions()
        .get::<Peer>()
        .copied()
        .unwrap_or(Peer(None));
    match authenticate(request.headers(), peer, &state).await {
        Ok(principal) => {
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        Err(response) => *response,
    }
}

// ---------------------------------------------------------------------------
// Authentication

#[derive(Debug, Clone, PartialEq, Eq)]
enum Principal {
    /// No admin credentials exist yet. Only possible on loopback listeners.
    Setup,
    Admin(String),
}

/// 401 response. API clients (curl, Prometheus) get a Basic challenge; the
/// console's own requests do not, so browsers never show their native dialog.
fn unauthorized(headers: &HeaderMap) -> Response {
    let mut response = error(StatusCode::UNAUTHORIZED, "authentication required");
    if !headers.contains_key(CSRF_HEADER) {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"rMail\""),
        );
    }
    response
}

fn too_many_attempts(remaining: Duration) -> Response {
    let mut response = error(
        StatusCode::TOO_MANY_REQUESTS,
        format!(
            "too many failed sign-in attempts; try again in {} minutes",
            remaining.as_secs().div_ceil(60)
        ),
    );
    if let Ok(value) = HeaderValue::from_str(&remaining.as_secs().to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// Current admin credentials: the settings database wins over the file.
async fn admin_credentials(state: &AdminState) -> Result<Option<(String, String)>> {
    if let Some(db_path) = state.db_path.clone() {
        let stored = blocking(move || {
            let conn = rmail_common::settings::open(&db_path)?;
            let user = rmail_common::settings::get_string(&conn, "global.web_admin_user")?;
            let hash = rmail_common::settings::get_string(&conn, "global.web_admin_password_hash")?;
            Ok(user.zip(hash))
        })
        .await?;
        if stored.is_some() {
            return Ok(stored);
        }
    }
    Ok(state.file_admin.clone())
}

fn session_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookie| websession::cookie_value(cookie, SESSION_COOKIE))
}

/// The admin named by a valid session cookie, if any.
fn cookie_user(headers: &HeaderMap, state: &AdminState, user: &str, hash: &str) -> bool {
    session_token(headers).is_some_and(|token| {
        !state.revoked.is_revoked(token)
            && websession::verify(&state.session_key, token).is_some_and(|session| {
                session.subject == user
                    && session.binding == websession::credential_binding(&state.session_key, hash)
            })
    })
}

// The error is an HTTP response returned straight to axum.
#[allow(clippy::result_large_err)]
async fn authenticate(
    headers: &HeaderMap,
    peer: Peer,
    state: &AdminState,
) -> std::result::Result<Principal, Box<Response>> {
    let credentials = admin_credentials(state)
        .await
        .map_err(|err| error(StatusCode::SERVICE_UNAVAILABLE, err.to_string()))?;
    let Some((user, hash)) = credentials else {
        return Ok(Principal::Setup);
    };
    if cookie_user(headers, state, &user, &hash) {
        return Ok(Principal::Admin(user));
    }
    let Some((basic_user, basic_password)) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_basic)
    else {
        return Err(Box::new(unauthorized(headers)));
    };
    if let Some(remaining) = peer.ip().and_then(|ip| state.throttle.blocked_for(ip)) {
        return Err(Box::new(too_many_attempts(remaining)));
    }
    if check_password(state, &user, &hash, &basic_user, &basic_password).await {
        Ok(Principal::Admin(user))
    } else {
        if let Some(ip) = peer.ip() {
            state.throttle.record_failure(ip);
        }
        Err(Box::new(unauthorized(headers)))
    }
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

// ---------------------------------------------------------------------------
// Public endpoints

async fn health() -> &'static str {
    "ok"
}

async fn ready(State(state): State<Shared>) -> Response {
    let report = readiness_report(
        state.mail_root.clone(),
        state.db_path.clone(),
        current_readiness(&state).await,
    )
    .await;
    let status = if report.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(report)).into_response()
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

async fn fallback(method: Method, uri: axum::http::Uri) -> Response {
    let path = uri.path();
    if method != Method::GET || path.starts_with("/api/") {
        return error(StatusCode::NOT_FOUND, "not found");
    }
    match read_admin_static(path) {
        Some((content_type, body)) => {
            ([(header::CONTENT_TYPE, content_type)], body).into_response()
        }
        None if path == "/" || !path.contains('.') => (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            admin_app_html(),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

async fn session_info(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let credentials = match admin_credentials(&state).await {
        Ok(credentials) => credentials,
        Err(err) => return error(StatusCode::SERVICE_UNAVAILABLE, err.to_string()),
    };
    let setup_required = credentials.is_none();
    // Only the cookie counts here; Basic credentials are checked on use.
    let user = credentials
        .filter(|(user, hash)| cookie_user(&headers, &state, user, hash))
        .map(|(user, _)| user);
    // The policy is public so the setup screen can check a password before
    // submitting it; it describes rules, not credentials.
    let policy = match password_policy(&state).await {
        Ok(policy) => policy,
        Err(err) => return error(StatusCode::SERVICE_UNAVAILABLE, err.to_string()),
    };
    Json(json!({
        "authenticated": setup_required || user.is_some(),
        "user": user,
        "setup_required": setup_required,
        "password_policy": policy,
    }))
    .into_response()
}

/// The admin password policy in effect: from the settings database when
/// there is one, otherwise the built-in defaults.
async fn password_policy(state: &AdminState) -> Result<rmail_common::config::AdminPasswordPolicy> {
    let Some(db) = state.db_path.clone() else {
        return Ok(Default::default());
    };
    blocking(move || {
        rmail_common::settings::admin_password_policy(&rmail_common::settings::open(&db)?)
    })
    .await
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login(
    State(state): State<Shared>,
    Extension(peer): Extension<Peer>,
    body: Bytes,
) -> Response {
    let input: LoginRequest = match parse(&body) {
        Ok(input) => input,
        Err(err) => return err.into_response(),
    };
    if let Some(remaining) = peer.ip().and_then(|ip| state.throttle.blocked_for(ip)) {
        return too_many_attempts(remaining);
    }
    let credentials = match admin_credentials(&state).await {
        Ok(credentials) => credentials,
        Err(err) => return error(StatusCode::SERVICE_UNAVAILABLE, err.to_string()),
    };
    let Some((user, hash)) = credentials else {
        return error(
            StatusCode::CONFLICT,
            "no admin account exists yet; set a password first",
        );
    };
    if check_password(&state, &user, &hash, input.username.trim(), &input.password).await {
        if let Some(ip) = peer.ip() {
            state.throttle.reset(ip);
        }
        web_log!("info", "admin_login", { "peer": peer.0.map(|a| a.to_string()), "user": user });
        with_cookie(
            Json(json!({"user": user})),
            session_cookie(&state, &user, &hash),
        )
    } else {
        if let Some(ip) = peer.ip() {
            state.throttle.record_failure(ip);
        }
        web_log!("warn", "admin_login_failed", { "peer": peer.0.map(|a| a.to_string()) });
        error(StatusCode::UNAUTHORIZED, "invalid username or password")
    }
}

async fn logout(State(state): State<Shared>, headers: HeaderMap) -> Response {
    if let Some(token) = session_token(&headers)
        && let Some(session) = websession::verify(&state.session_key, token)
    {
        state.revoked.revoke(token, session.expires_at);
    }
    with_cookie(ok(), clear_cookie(&state))
}

// ---------------------------------------------------------------------------
// Protected endpoints

async fn stats(State(state): State<Shared>) -> Response {
    let root = state.mail_root.clone();
    match blocking(move || scan_maildirs_sync(&root)).await {
        Ok(mut stats) => {
            stats.delivered_count = tokio::fs::read_to_string(
                rmail_common::runtime::delivered_count_path(&state.mail_root),
            )
            .await
            .ok()
            .and_then(|text| text.trim().parse().ok())
            .unwrap_or(0);
            Json(stats).into_response()
        }
        Err(err) => error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

async fn metrics(State(state): State<Shared>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        metrics_text(&state.mail_root).await,
    )
        .into_response()
}

async fn dmarc(State(state): State<Shared>) -> Response {
    match require_db(&state) {
        Ok(db) => outcome(
            blocking(move || dmarc_summary_sync(&db)).await,
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        Err(err) => err.into_response(),
    }
}

async fn logs(
    State(state): State<Shared>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
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
        "smtpd" | "imapd" | "web" | "outbound" | "webmail" | "classifier"
    ) {
        return error(StatusCode::BAD_REQUEST, "invalid component");
    }
    let path = rmail_common::runtime::log_path(&state.mail_root, component);
    match tokio::fs::read(&path).await {
        Ok(bytes) => tail_lines(&String::from_utf8_lossy(&bytes), lines).into_response(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new().into_response(),
        Err(err) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("reading {}: {err}", path.display()),
        ),
    }
}

async fn overview(State(state): State<Shared>) -> Response {
    let (root, db) = (state.mail_root.clone(), state.db_path.clone());
    outcome(
        blocking(move || overview_summary_sync(&root, db.as_deref())).await,
        StatusCode::INTERNAL_SERVER_ERROR,
    )
}

async fn queue_summary(State(state): State<Shared>) -> Response {
    let root = state.mail_root.clone();
    outcome(
        blocking(move || queue_summary_sync(&root)).await,
        StatusCode::INTERNAL_SERVER_ERROR,
    )
}

async fn queue_listing(
    State(state): State<Shared>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let root = state.mail_root.clone();
    let spool = params
        .get("spool")
        .cloned()
        .unwrap_or_else(|| "queue".to_string());
    outcome(
        blocking(move || queue_listing_sync(&root, &spool)).await,
        StatusCode::BAD_REQUEST,
    )
}

async fn queue_action(State(state): State<Shared>, body: Bytes) -> Response {
    run_queue_action(&state, None, &body).await
}

/// Legacy `/api/queue/{requeue,promote,delete}` endpoints.
async fn queue_action_path(
    State(state): State<Shared>,
    UrlPath(action): UrlPath<String>,
    body: Bytes,
) -> Response {
    if !matches!(action.as_str(), "requeue" | "promote" | "delete") {
        return error(StatusCode::NOT_FOUND, "not found");
    }
    run_queue_action(&state, Some(&action), &body).await
}

async fn run_queue_action(state: &AdminState, fixed: Option<&str>, body: &Bytes) -> Response {
    let input: Value = match parse(body) {
        Ok(input) => input,
        Err(err) => return err.into_response(),
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
        return error(StatusCode::BAD_REQUEST, "unknown action");
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
    let result = blocking(move || {
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
        Ok(count) => Json(json!({"result": "ok", "affected": count})).into_response(),
        Err(err) if err.to_string().contains("not found") => {
            error(StatusCode::NOT_FOUND, err.to_string())
        }
        Err(err) => error(StatusCode::BAD_REQUEST, format!("{err:#}")),
    }
}

async fn accounts(State(state): State<Shared>) -> Response {
    let (root, db) = (state.mail_root.clone(), state.db_path.clone());
    outcome(
        blocking(move || account_summaries_sync(&root, db.as_deref())).await,
        StatusCode::INTERNAL_SERVER_ERROR,
    )
}

async fn save_account(State(state): State<Shared>, body: Bytes) -> Response {
    write_account(&state, &body, false).await
}

async fn update_account(State(state): State<Shared>, body: Bytes) -> Response {
    write_account(&state, &body, true).await
}

async fn write_account(state: &AdminState, body: &Bytes, must_exist: bool) -> Response {
    let db = match require_db(state) {
        Ok(db) => db,
        Err(err) => return err.into_response(),
    };
    let mut input: AccountRequest = match parse(body) {
        Ok(input) => input,
        Err(err) => return err.into_response(),
    };
    input.must_exist = must_exist;
    let root = state.mail_root.clone();
    outcome(
        blocking(move || upsert_account_sync(&root, &db, input).map(|_| json!({"result": "ok"})))
            .await,
        StatusCode::BAD_REQUEST,
    )
}

async fn delete_account(State(state): State<Shared>, body: Bytes) -> Response {
    let db = match require_db(&state) {
        Ok(db) => db,
        Err(err) => return err.into_response(),
    };
    let input: AccountDeleteRequest = match parse(&body) {
        Ok(input) => input,
        Err(err) => return err.into_response(),
    };
    outcome(
        blocking(move || delete_account_sync(&db, input).map(|_| json!({"result": "ok"}))).await,
        StatusCode::BAD_REQUEST,
    )
}

async fn routing(State(state): State<Shared>) -> Response {
    let db = state.db_path.clone();
    outcome(
        blocking(move || routing_summary_sync(db.as_deref())).await,
        StatusCode::INTERNAL_SERVER_ERROR,
    )
}

async fn save_alias(State(state): State<Shared>, body: Bytes) -> Response {
    write_alias(&state, &body, false).await
}

async fn delete_alias(State(state): State<Shared>, body: Bytes) -> Response {
    write_alias(&state, &body, true).await
}

async fn write_alias(state: &AdminState, body: &Bytes, delete: bool) -> Response {
    let db = match require_db(state) {
        Ok(db) => db,
        Err(err) => return err.into_response(),
    };
    let mut input: AliasRequest = match parse(body) {
        Ok(input) => input,
        Err(err) => return err.into_response(),
    };
    if delete {
        input.targets = None;
    }
    outcome(
        blocking(move || upsert_alias_sync(&db, input).map(|_| json!({"result": "ok"}))).await,
        StatusCode::BAD_REQUEST,
    )
}

#[derive(serde::Deserialize)]
struct TransportRequest {
    domain: String,
    #[serde(flatten)]
    action: Option<rmail_common::transport::RouteAction>,
}

/// Store a delivery route; a relay saved without a password keeps the
/// stored one.
async fn save_transport(State(state): State<Shared>, body: Bytes) -> Response {
    let db = match require_db(&state) {
        Ok(db) => db,
        Err(err) => return err.into_response(),
    };
    let input: TransportRequest = match parse(&body) {
        Ok(input) => input,
        Err(err) => return err.into_response(),
    };
    let Some(action) = input.action else {
        return error(StatusCode::BAD_REQUEST, "action must be relay or reject");
    };
    outcome(
        blocking(move || {
            rmail_common::transport::set_route(std::path::Path::new(&db), &input.domain, action)
        })
        .await,
        StatusCode::BAD_REQUEST,
    )
}

async fn delete_transport(State(state): State<Shared>, body: Bytes) -> Response {
    let db = match require_db(&state) {
        Ok(db) => db,
        Err(err) => return err.into_response(),
    };
    let input: TransportRequest = match parse(&body) {
        Ok(input) => input,
        Err(err) => return err.into_response(),
    };
    outcome(
        blocking(move || {
            if !rmail_common::transport::delete_route(std::path::Path::new(&db), &input.domain)? {
                anyhow::bail!("no route for {}", input.domain);
            }
            Ok(json!({"result": "ok"}))
        })
        .await,
        StatusCode::BAD_REQUEST,
    )
}

/// Every folder an account shares with another (IMAP ACL grants).
async fn sharing(State(state): State<Shared>) -> Response {
    let db = match require_db(&state) {
        Ok(db) => db,
        Err(err) => return err.into_response(),
    };
    let root = state.mail_root.clone();
    outcome(
        blocking(move || {
            let db = std::path::Path::new(&db);
            let mut folders = std::collections::HashMap::new();
            let mut shares = Vec::new();
            for (owner, mailbox_id, grantee, rights) in rmail_common::acl::all_grants(db)? {
                let names = match folders.entry(owner.clone()) {
                    std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        let names = match owner.split_once('@') {
                            Some((local, domain)) => {
                                rmail_common::imap_state::list_folders(&root, domain, local)
                                    .unwrap_or_default()
                            }
                            None => Vec::new(),
                        };
                        entry.insert(names)
                    }
                };
                // Grants on folders deleted since are not shown.
                let Some(folder) = names.iter().find(|f| f.mailbox_id == mailbox_id) else {
                    continue;
                };
                shares.push(json!({
                    "owner": owner,
                    "folder": folder.name,
                    "mailbox_id": mailbox_id,
                    "grantee": grantee,
                    "rights": rights.to_string(),
                }));
            }
            Ok(shares)
        })
        .await,
        StatusCode::INTERNAL_SERVER_ERROR,
    )
}

#[derive(Deserialize)]
struct SharingDelete {
    owner: String,
    mailbox_id: String,
    grantee: String,
}

/// Stop sharing a folder with one account.
async fn delete_sharing(State(state): State<Shared>, body: Bytes) -> Response {
    let db = match require_db(&state) {
        Ok(db) => db,
        Err(err) => return err.into_response(),
    };
    let input: SharingDelete = match parse(&body) {
        Ok(input) => input,
        Err(err) => return err.into_response(),
    };
    outcome(
        blocking(move || {
            if !rmail_common::acl::delete_rights(
                std::path::Path::new(&db),
                &input.owner,
                &input.mailbox_id,
                &input.grantee,
            )? {
                anyhow::bail!(
                    "{} does not share that folder with {}",
                    input.owner,
                    input.grantee
                );
            }
            Ok(json!({"result": "ok"}))
        })
        .await,
        StatusCode::BAD_REQUEST,
    )
}

async fn save_catchall(State(state): State<Shared>, body: Bytes) -> Response {
    write_catchall(&state, &body, false).await
}

async fn delete_catchall(State(state): State<Shared>, body: Bytes) -> Response {
    write_catchall(&state, &body, true).await
}

async fn write_catchall(state: &AdminState, body: &Bytes, delete: bool) -> Response {
    let db = match require_db(state) {
        Ok(db) => db,
        Err(err) => return err.into_response(),
    };
    let mut input: CatchallRequest = match parse(body) {
        Ok(input) => input,
        Err(err) => return err.into_response(),
    };
    if delete {
        input.target = None;
    }
    outcome(
        blocking(move || upsert_catchall_sync(&db, input).map(|_| json!({"result": "ok"}))).await,
        StatusCode::BAD_REQUEST,
    )
}

async fn settings(State(state): State<Shared>) -> Response {
    match require_db(&state) {
        Ok(db) => outcome(
            blocking(move || settings_view_sync(&db)).await,
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        Err(err) => err.into_response(),
    }
}

async fn update_settings(
    State(state): State<Shared>,
    Extension(peer): Extension<Peer>,
    body: Bytes,
) -> Response {
    #[derive(Deserialize)]
    struct Changes {
        changes: BTreeMap<String, Value>,
    }
    let db = match require_db(&state) {
        Ok(db) => db,
        Err(err) => return err.into_response(),
    };
    let input: Changes = match parse(&body) {
        Ok(input) => input,
        Err(err) => return err.into_response(),
    };
    let result = blocking(move || {
        let mut conn = rmail_common::settings::open(&db)?;
        rmail_common::settings::update(&mut conn, &input.changes)?;
        settings_view_sync(&db)
    })
    .await;
    if let Ok(view) = &result {
        web_log!("info", "settings_updated", { "peer": peer.0.map(|a| a.to_string()), "revision": view["revision"] });
    }
    outcome(result, StatusCode::UNPROCESSABLE_ENTITY)
}

/// Queue a restart of the services whose saved settings are not yet applied.
/// A root-owned systemd path unit performs it (see `rmail_common::restart`).
async fn restart_services(
    State(state): State<Shared>,
    Extension(peer): Extension<Peer>,
) -> Response {
    let db = match require_db(&state) {
        Ok(db) => db,
        Err(err) => return err.into_response(),
    };
    if !rmail_common::restart::helper_installed() {
        return error(
            StatusCode::NOT_IMPLEMENTED,
            "the rmail_restart.path unit is not installed; restart services with rmail_ctl",
        );
    }
    let mail_root = state.mail_root.clone();
    let result = blocking(move || {
        let pending = rmail_common::restart::queue_pending(&db, &mail_root)?;
        Ok(json!({"restarting": pending}))
    })
    .await;
    if let Ok(body) = &result {
        web_log!("info", "services_restart_requested", { "peer": peer.0.map(|a| a.to_string()), "services": body["restarting"] });
    }
    outcome(result, StatusCode::BAD_REQUEST)
}

#[derive(Deserialize)]
struct CredentialsRequest {
    username: String,
    #[serde(default)]
    current_password: Option<String>,
    new_password: String,
}

async fn change_credentials(
    State(state): State<Shared>,
    Extension(principal): Extension<Principal>,
    body: Bytes,
) -> Response {
    let Some(db) = state.db_path.clone() else {
        return error(
            StatusCode::BAD_REQUEST,
            "admin credentials are set in the configuration file when no database is configured",
        );
    };
    let input: CredentialsRequest = match parse(&body) {
        Ok(input) => input,
        Err(err) => return err.into_response(),
    };
    let username = input.username.trim().to_string();
    if username.is_empty() || username.contains(':') {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "username must be non-empty and must not contain ':'",
        );
    }
    let policy = match password_policy(&state).await {
        Ok(policy) => policy,
        Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };
    if let Err(message) = policy.check(&username, &input.new_password) {
        return error(StatusCode::UNPROCESSABLE_ENTITY, message);
    }
    // Setup mode (no credentials yet) needs no current password.
    if let Principal::Admin(_) = principal {
        let (user, hash) = match admin_credentials(&state).await {
            Ok(Some(credentials)) => credentials,
            Ok(None) => return error(StatusCode::CONFLICT, "admin credentials disappeared"),
            Err(err) => return error(StatusCode::SERVICE_UNAVAILABLE, err.to_string()),
        };
        let current = input.current_password.unwrap_or_default();
        if !check_password(&state, &user, &hash, &user, &current).await {
            return error(StatusCode::FORBIDDEN, "current password is incorrect");
        }
    }
    let new_password = input.new_password;
    let hash = match blocking(move || {
        use argon2::password_hash::{PasswordHasher, SaltString};
        let salt = SaltString::generate(&mut rand::rngs::OsRng);
        argon2::Argon2::default()
            .hash_password(new_password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|err| anyhow!(err.to_string()))
    })
    .await
    {
        Ok(hash) => hash,
        Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };
    let (stored_user, stored_hash) = (username.clone(), hash.clone());
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
            // The new hash invalidates every other session; keep this one.
            with_cookie(
                Json(json!({"user": username})),
                session_cookie(&state, &username, &hash),
            )
        }
        Err(err) => error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

#[cfg(test)]
mod transport_request_tests {
    use super::TransportRequest;
    use rmail_common::transport::RouteAction;

    #[test]
    fn save_and_delete_bodies_parse() {
        let save: TransportRequest = serde_json::from_str(
            r#"{"domain":"*","action":"relay","host":"smtp.example.net","port":587,"username":"u","password":"p"}"#,
        )
        .unwrap();
        assert!(matches!(
            save.action,
            Some(RouteAction::Relay { port: 587, .. })
        ));
        let delete: TransportRequest = serde_json::from_str(r#"{"domain":"old.example"}"#).unwrap();
        assert!(delete.action.is_none());
    }
}
