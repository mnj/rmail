//! JMAP (RFC 8620 core, RFC 8621 mail and submission) over the accounts'
//! Maildir storage, served by webmail next to its own API.
//!
//! - Clients authenticate every request with HTTP Basic (address and
//!   password) or, when OAuth introspection is configured, a Bearer token.
//!   The webmail cookie is not accepted, so cross-site requests cannot use
//!   it.
//! - Each user has their own account plus one account per owner who shared
//!   mailboxes with them (RFC 4314 grants); a shared account shows only the
//!   shared mailboxes and their emails, within the user's rights.
//! - State strings are the account's change-log sequence number
//!   (`rmail_common::jmap::store`); a shared account's state also carries a
//!   digest of the user's grants, so a changed grant makes the client
//!   resynchronize.
//! - A request runs on one blocking thread: storage is synchronous, and the
//!   one network step (submitting mail) waits there for its future.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Extension;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use rmail_common::acl::{self, Rights};
use rmail_common::http::Peer;
use rmail_common::{auth, db, imap_state};
use serde_json::{Map, Value, json};

use crate::api::AppState;

mod blob;
mod email;
mod identity;
mod mailbox;
mod push;
mod query;
mod snippet;
mod submission;
mod thread;
mod vacation;

#[cfg(test)]
pub(crate) mod tests;

pub(crate) const CORE: &str = "urn:ietf:params:jmap:core";
pub(crate) const MAIL: &str = "urn:ietf:params:jmap:mail";
pub(crate) const SUBMISSION: &str = "urn:ietf:params:jmap:submission";
pub(crate) const VACATION: &str = "urn:ietf:params:jmap:vacationresponse";

const MAX_CALLS_IN_REQUEST: usize = 64;
pub(crate) const MAX_OBJECTS_IN_GET: usize = 1000;
pub(crate) const MAX_OBJECTS_IN_SET: usize = 1000;
const MAX_SIZE_REQUEST: usize = 10 * 1024 * 1024;
/// Uploads share webmail's request body limit.
pub(crate) const MAX_SIZE_UPLOAD: usize = crate::api::MAX_BODY_BYTES;
/// How long a verified password is trusted without running the password
/// hash again. Every request still checks the stored hash is unchanged.
const LOGIN_CACHE_TTL: Duration = Duration::from_secs(15 * 60);

type Shared = Arc<AppState>;

pub(crate) fn routes() -> Router<Shared> {
    Router::new()
        .route("/.well-known/jmap", get(session_resource))
        .route("/jmap/session", get(session_resource))
        .route("/jmap/api", post(api))
        .route("/jmap/api/", post(api))
        .route("/jmap/upload/{account}", post(blob::upload))
        .route("/jmap/upload/{account}/", post(blob::upload))
        .route(
            "/jmap/download/{account}/{blob}/{name}",
            get(blob::download),
        )
        .route("/jmap/eventsource", get(push::event_source))
        .route("/jmap/eventsource/", get(push::event_source))
}

// ---------------------------------------------------------------------------
// Authentication

/// The authenticated user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct User {
    pub address: String,
    pub domain: String,
    pub localpart: String,
}

/// Recently verified passwords: address -> (keyed digest of the password,
/// the stored hash it was checked against, when).
#[derive(Default)]
pub(crate) struct LoginCache(Mutex<HashMap<String, CachedLogin>>);

/// A keyed digest of the password, the stored hash it matched, and when.
type CachedLogin = (Vec<u8>, String, Instant);

fn password_digest(secret: &[u8], address: &str, password: &str) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    let mut mac =
        Hmac::<sha2::Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(address.as_bytes());
    mac.update(b"\0");
    mac.update(password.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn unauthorized() -> Response {
    let mut response = (StatusCode::UNAUTHORIZED, "authentication required").into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"rMail\", charset=\"UTF-8\""),
    );
    response
}

fn user_for(address: &str) -> Option<User> {
    let (localpart, domain) = address.split_once('@')?;
    if localpart.is_empty() || domain.is_empty() || address.contains('/') {
        return None;
    }
    Some(User {
        address: address.to_string(),
        domain: domain.to_string(),
        localpart: localpart.to_string(),
    })
}

async fn blocking<T, F>(work: F) -> anyhow::Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> anyhow::Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| anyhow::anyhow!("background task failed: {error}"))?
}

/// Authenticate a request, or the response refusing it.
pub(crate) async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    peer: &Peer,
) -> Result<User, Box<Response>> {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return Err(Box::new(unauthorized()));
    };
    if let Some(remaining) = peer.ip().and_then(|ip| state.throttle.blocked_for(ip)) {
        let mut response = (
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed sign-in attempts",
        )
            .into_response();
        if let Ok(value) = HeaderValue::from_str(&remaining.as_secs().to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        return Err(Box::new(response));
    }
    let reject = || {
        if let Some(ip) = peer.ip() {
            state.throttle.record_failure(ip);
        }
        rmail_common::metrics::inc_auth_failures();
        unauthorized()
    };
    let (scheme, credentials) = value.split_once(' ').unwrap_or((value, ""));
    let address = if scheme.eq_ignore_ascii_case("Bearer") {
        let Some(validator) = &state.oauth else {
            return Err(Box::new(reject()));
        };
        match validator.validate(credentials.trim(), None).await {
            rmail_common::oauth::OAuthValidation::Active { identity } => {
                auth::normalize_login_name(&identity).unwrap_or_default()
            }
            rmail_common::oauth::OAuthValidation::Rejected => return Err(Box::new(reject())),
            rmail_common::oauth::OAuthValidation::Unavailable(_) => {
                return Err(Box::new(
                    (StatusCode::SERVICE_UNAVAILABLE, "token check unavailable").into_response(),
                ));
            }
        }
    } else if scheme.eq_ignore_ascii_case("Basic") {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(credentials.trim())
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok());
        let Some((name, password)) = decoded.as_deref().and_then(|text| text.split_once(':'))
        else {
            return Err(Box::new(reject()));
        };
        let address = auth::normalize_login_name(name.trim()).unwrap_or_default();
        if !verify_password(state, &address, password).await {
            return Err(Box::new(reject()));
        }
        address
    } else {
        return Err(Box::new(reject()));
    };
    // The stored account decides the address's spelling from here on.
    let db_path = state.db_path.clone();
    let lookup = address.clone();
    let mailbox = blocking(move || db::get_mailbox(&db_path, &lookup))
        .await
        .ok()
        .flatten();
    let Some(user) = mailbox.and_then(|mailbox| user_for(&mailbox.address.to_ascii_lowercase()))
    else {
        return Err(Box::new(reject()));
    };
    if let Some(ip) = peer.ip() {
        state.throttle.reset(ip);
    }
    Ok(user)
}

async fn verify_password(state: &AppState, address: &str, password: &str) -> bool {
    if address.is_empty() {
        auth::burn_password_verification(password.to_string()).await;
        return false;
    }
    let db_path = state.db_path.clone();
    let lookup = address.to_string();
    let hash = blocking(move || db::get_mailbox(&db_path, &lookup))
        .await
        .ok()
        .flatten()
        .and_then(|mailbox| mailbox.password_hash);
    let Some(hash) = hash else {
        auth::burn_password_verification(password.to_string()).await;
        return false;
    };
    let digest = password_digest(&state.session_secret, address, password);
    {
        let cache = state.jmap_logins.0.lock().unwrap();
        if let Some((cached, cached_hash, at)) = cache.get(address)
            && *cached == digest
            && *cached_hash == hash
            && at.elapsed() < LOGIN_CACHE_TTL
        {
            return true;
        }
    }
    let verified = matches!(
        auth::verify_password_async(password.to_string(), hash.clone()).await,
        Ok(true)
    );
    if verified {
        let mut cache = state.jmap_logins.0.lock().unwrap();
        cache.retain(|_, (_, _, at)| at.elapsed() < LOGIN_CACHE_TTL);
        cache.insert(address.to_string(), (digest, hash, Instant::now()));
    }
    verified
}

// ---------------------------------------------------------------------------
// Accounts

/// The JMAP id of the account holding `address`'s mail.
pub(crate) fn account_id(address: &str) -> String {
    let hex = address
        .bytes()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("a{hex}")
}

/// A JMAP account the user can use.
#[derive(Debug, Clone)]
pub(crate) struct Account {
    pub id: String,
    /// The address whose mail this is.
    pub owner: String,
    pub domain: String,
    pub localpart: String,
    /// For a shared account, the user's rights per MAILBOXID; `None` for
    /// the user's own account.
    pub shared: Option<HashMap<String, Rights>>,
}

impl Account {
    pub fn is_personal(&self) -> bool {
        self.shared.is_none()
    }

    pub fn rights(&self, mailbox_id: &str) -> Rights {
        match &self.shared {
            None => Rights::ALL,
            Some(rights) => rights.get(mailbox_id).copied().unwrap_or(Rights::NONE),
        }
    }

    /// The mailbox may be listed (`l`).
    pub fn lists(&self, mailbox_id: &str) -> bool {
        self.rights(mailbox_id).contains(Rights::LOOKUP)
    }

    /// The mailbox's emails may be read (`r`).
    pub fn reads(&self, mailbox_id: &str) -> bool {
        self.rights(mailbox_id).contains(Rights::READ)
    }

    /// The account accepts no changes at all.
    pub fn is_read_only(&self) -> bool {
        match &self.shared {
            None => false,
            Some(rights) => rights.values().all(|rights| {
                !rights.intersects(
                    Rights::ALL
                        .without(Rights::LOOKUP)
                        .without(Rights::READ)
                        .without(Rights::ADMIN),
                )
            }),
        }
    }

    /// A digest of the grants, part of a shared account's state.
    fn grants_digest(&self) -> String {
        let Some(rights) = &self.shared else {
            return String::new();
        };
        let mut pairs = rights
            .iter()
            .map(|(id, rights)| format!("{id}={rights}"))
            .collect::<Vec<_>>();
        pairs.sort();
        format!("{:016x}", fnv1a(pairs.join(",").as_bytes()))
    }

    /// The state string for change-log sequence `seq`.
    pub fn state(&self, seq: u64) -> String {
        match &self.shared {
            None => seq.to_string(),
            Some(_) => format!("{seq}-{}", self.grants_digest()),
        }
    }

    /// The sequence a state string names, if it is one of this account's
    /// with the current grants.
    pub fn parse_state(&self, state: &str) -> Option<u64> {
        match &self.shared {
            None => state.parse().ok(),
            Some(_) => {
                let (seq, digest) = state.split_once('-')?;
                (digest == self.grants_digest())
                    .then(|| seq.parse().ok())
                    .flatten()
            }
        }
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// The user's own account and one per owner who shares mailboxes with them.
pub(crate) fn accounts(state: &AppState, user: &User) -> anyhow::Result<Vec<Account>> {
    let mut accounts = vec![Account {
        id: account_id(&user.address),
        owner: user.address.clone(),
        domain: user.domain.clone(),
        localpart: user.localpart.clone(),
        shared: None,
    }];
    for shared in acl::shared_mailboxes(&state.mail_root, &state.db_path, &user.address)? {
        if !shared.rights.contains(Rights::LOOKUP) {
            continue;
        }
        let id = account_id(&shared.owner);
        let account = match accounts.iter_mut().find(|account| account.id == id) {
            Some(account) => account,
            None => {
                accounts.push(Account {
                    id,
                    owner: shared.owner.clone(),
                    domain: shared.domain.clone(),
                    localpart: shared.localpart.clone(),
                    shared: Some(HashMap::new()),
                });
                accounts.last_mut().unwrap()
            }
        };
        if let Some(rights) = &mut account.shared {
            rights.insert(shared.folder.mailbox_id.clone(), shared.rights);
        }
    }
    Ok(accounts)
}

// ---------------------------------------------------------------------------
// Session resource (RFC 8620 section 2)

fn base_url(state: &AppState, headers: &HeaderMap) -> String {
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .filter(|host| {
            !host.is_empty()
                && host
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-:[]".contains(&byte))
        })
        .unwrap_or("localhost");
    let forwarded_https = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|proto| proto.eq_ignore_ascii_case("https"));
    let scheme = if state.secure_cookies || forwarded_https {
        "https"
    } else {
        "http"
    };
    format!("{scheme}://{host}")
}

pub(crate) fn mail_account_capabilities(account: &Account) -> Value {
    json!({
        "maxMailboxesPerEmail": null,
        "maxMailboxDepth": null,
        "maxSizeMailboxName": 255,
        "maxSizeAttachmentsPerEmail": MAX_SIZE_UPLOAD,
        "emailQuerySortOptions": query::EMAIL_SORT_OPTIONS,
        "mayCreateTopLevelMailbox": account.is_personal(),
    })
}

fn session_state(accounts: &[Account], can_send: bool) -> String {
    let mut text = accounts
        .iter()
        .map(|account| format!("{}:{}", account.id, account.grants_digest()))
        .collect::<Vec<_>>();
    text.sort();
    text.push(can_send.to_string());
    format!("{:016x}", fnv1a(text.join(",").as_bytes()))
}

fn session_object(state: &AppState, user: &User, accounts: &[Account], base: &str) -> Value {
    let can_send = state.submission.is_some();
    let mut account_map = Map::new();
    for account in accounts {
        let mut capabilities = Map::new();
        capabilities.insert(MAIL.to_string(), mail_account_capabilities(account));
        if account.is_personal() {
            capabilities.insert(VACATION.to_string(), json!({}));
        }
        if account.is_personal() && can_send {
            capabilities.insert(
                SUBMISSION.to_string(),
                json!({
                    "maxDelayedSend": rmail_common::hold::MAX_HOLD_SECONDS,
                    "submissionExtensions": {
                        "FUTURERELEASE": [
                            rmail_common::hold::MAX_HOLD_SECONDS.to_string(),
                            utc_date(
                                chrono::Utc::now().timestamp()
                                    + rmail_common::hold::MAX_HOLD_SECONDS,
                            ),
                        ],
                    },
                }),
            );
        }
        account_map.insert(
            account.id.clone(),
            json!({
                "name": account.owner,
                "isPersonal": account.is_personal(),
                "isReadOnly": account.is_read_only(),
                "accountCapabilities": capabilities,
            }),
        );
    }
    let own = account_id(&user.address);
    let mut primary = Map::new();
    primary.insert(MAIL.to_string(), json!(own));
    let mut capabilities = Map::new();
    capabilities.insert(
        CORE.to_string(),
        json!({
            "maxSizeUpload": MAX_SIZE_UPLOAD,
            "maxConcurrentUpload": 4,
            "maxSizeRequest": MAX_SIZE_REQUEST,
            "maxConcurrentRequests": 8,
            "maxCallsInRequest": MAX_CALLS_IN_REQUEST,
            "maxObjectsInGet": MAX_OBJECTS_IN_GET,
            "maxObjectsInSet": MAX_OBJECTS_IN_SET,
            "collationAlgorithms": ["i;ascii-casemap", "i;unicode-casemap"],
        }),
    );
    capabilities.insert(MAIL.to_string(), json!({}));
    capabilities.insert(VACATION.to_string(), json!({}));
    primary.insert(VACATION.to_string(), json!(own));
    if can_send {
        capabilities.insert(SUBMISSION.to_string(), json!({}));
        primary.insert(SUBMISSION.to_string(), json!(own));
    }
    json!({
        "capabilities": capabilities,
        "accounts": account_map,
        "primaryAccounts": primary,
        "username": user.address,
        "apiUrl": format!("{base}/jmap/api/"),
        "downloadUrl": format!("{base}/jmap/download/{{accountId}}/{{blobId}}/{{name}}?accept={{type}}"),
        "uploadUrl": format!("{base}/jmap/upload/{{accountId}}/"),
        "eventSourceUrl": format!("{base}/jmap/eventsource/?types={{types}}&closeafter={{closeafter}}&ping={{ping}}"),
        "state": session_state(accounts, can_send),
    })
}

async fn session_resource(
    app: State<Shared>,
    Extension(peer): Extension<Peer>,
    headers: HeaderMap,
) -> Response {
    let state = app.0;
    let user = match authenticate(&state, &headers, &peer).await {
        Ok(user) => user,
        Err(response) => return *response,
    };
    let base = base_url(&state, &headers);
    let task_state = state.clone();
    let task_user = user.clone();
    match blocking(move || {
        imap_state::init_account(
            &task_state.mail_root,
            &task_user.domain,
            &task_user.localpart,
        )?;
        accounts(&task_state, &task_user)
    })
    .await
    {
        Ok(accounts) => json_response(&session_object(&state, &user, &accounts, &base)),
        Err(error) => internal_response(format!("{error:#}")),
    }
}

pub(crate) fn json_response(value: &Value) -> Response {
    let mut response = (StatusCode::OK, value.to_string()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

/// A request-level error (RFC 8620 section 3.6.1) as RFC 7807 problem JSON.
fn problem(kind: &str, detail: &str) -> Response {
    let mut response = (
        StatusCode::BAD_REQUEST,
        json!({"type": kind, "status": 400, "detail": detail}).to_string(),
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response
}

// ---------------------------------------------------------------------------
// API requests (RFC 8620 section 3)

/// A method-level error (RFC 8620 section 3.6.2).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MethodError {
    pub kind: &'static str,
    pub description: Option<String>,
}

impl MethodError {
    pub fn new(kind: &'static str) -> Self {
        Self {
            kind,
            description: None,
        }
    }

    pub fn with(kind: &'static str, description: impl Into<String>) -> Self {
        Self {
            kind,
            description: Some(description.into()),
        }
    }

    pub fn invalid(description: impl Into<String>) -> Self {
        Self::with("invalidArguments", description)
    }

    fn to_json(&self) -> Value {
        let mut object = json!({"type": self.kind});
        if let Some(description) = &self.description {
            object["description"] = json!(description);
        }
        object
    }
}

impl From<anyhow::Error> for MethodError {
    fn from(error: anyhow::Error) -> Self {
        log_internal(format!("{error:#}"));
        Self::with("serverFail", INTERNAL_ERROR)
    }
}

impl From<rusqlite::Error> for MethodError {
    fn from(error: rusqlite::Error) -> Self {
        log_internal(&error);
        Self::with("serverFail", INTERNAL_ERROR)
    }
}

/// What clients are told about an internal failure; the detail (paths,
/// database errors) goes to the log only.
pub(crate) const INTERNAL_ERROR: &str = "internal server error";

pub(crate) fn log_internal(detail: impl std::fmt::Display) {
    webmail_log!("error", "jmap_internal_error", { "error": detail.to_string() });
}

/// A 500 response for an internal failure, logged.
pub(crate) fn internal_response(detail: impl std::fmt::Display) -> Response {
    log_internal(detail);
    (StatusCode::INTERNAL_SERVER_ERROR, INTERNAL_ERROR).into_response()
}

/// A `serverFail` SetError for an internal failure, logged.
pub(crate) fn server_fail(detail: impl std::fmt::Display) -> Value {
    log_internal(detail);
    set_error("serverFail", INTERNAL_ERROR)
}

pub(crate) type MethodResult = Result<Vec<(String, Value)>, MethodError>;

/// A per-object error in a `/set` or similar response (RFC 8620 section
/// 5.3).
pub(crate) fn set_error(kind: &str, description: impl Into<String>) -> Value {
    json!({"type": kind, "description": description.into()})
}

pub(crate) fn set_error_properties(kind: &str, description: &str, properties: &[&str]) -> Value {
    json!({"type": kind, "description": description, "properties": properties})
}

/// Everything a method call can reach.
pub(crate) struct Ctx {
    pub app: Shared,
    pub user: User,
    pub accounts: Vec<Account>,
    /// Creation ids from this request and the client's `createdIds`.
    pub created_ids: HashMap<String, String>,
    pub using: HashSet<String>,
    synced: HashSet<String>,
}

impl Ctx {
    pub(crate) fn new(app: Shared, user: User, accounts: Vec<Account>) -> Self {
        Self {
            app,
            user,
            accounts,
            created_ids: HashMap::new(),
            using: HashSet::new(),
            synced: HashSet::new(),
        }
    }

    /// The account `args.accountId` names (synchronized with its Maildir
    /// once per request).
    pub fn account(&mut self, args: &Map<String, Value>) -> Result<Account, MethodError> {
        let id = match args.get("accountId") {
            Some(Value::String(id)) => id.clone(),
            Some(_) => return Err(MethodError::invalid("accountId must be a string")),
            None => account_id(&self.user.address),
        };
        self.account_by_id(&id)
    }

    pub fn account_by_id(&mut self, id: &str) -> Result<Account, MethodError> {
        let account = self
            .accounts
            .iter()
            .find(|account| account.id == id)
            .cloned()
            .ok_or_else(|| MethodError::new("accountNotFound"))?;
        if self.synced.insert(account.id.clone()) {
            rmail_common::jmap::store::sync_account(
                &self.app.mail_root,
                &account.domain,
                &account.localpart,
            )?;
        }
        Ok(account)
    }

    pub fn open(
        &self,
        account: &Account,
    ) -> Result<rmail_common::sqlite_pool::SqliteConnection, MethodError> {
        Ok(rmail_common::jmap::store::open(
            &self.app.mail_root,
            &account.domain,
            &account.localpart,
        )?)
    }

    /// Mark an account as changed, so later calls index what was written.
    pub fn touched(&mut self, account: &Account) {
        self.synced.remove(&account.id);
    }

    /// Resolve `#creationId` references to ids created in this request.
    pub fn resolve_id(&self, id: &str) -> Option<String> {
        match id.strip_prefix('#') {
            Some(creation_id) => self.created_ids.get(creation_id).cloned(),
            None => Some(id.to_string()),
        }
    }

    pub fn mail_root(&self) -> PathBuf {
        self.app.mail_root.clone()
    }
}

/// The capability a method needs in `using`.
fn method_capability(name: &str) -> &'static str {
    match name.split('/').next().unwrap_or_default() {
        "Core" => CORE,
        "Identity" | "EmailSubmission" => SUBMISSION,
        "VacationResponse" => VACATION,
        _ => MAIL,
    }
}

fn call_method(ctx: &mut Ctx, name: &str, args: Map<String, Value>) -> MethodResult {
    if !ctx.using.contains(method_capability(name)) {
        return Err(MethodError::new("unknownMethod"));
    }
    match name {
        "Core/echo" => Ok(vec![(name.to_string(), Value::Object(args))]),
        "Mailbox/get" => mailbox::get(ctx, args),
        "Mailbox/changes" => mailbox::changes(ctx, args),
        "Mailbox/query" => mailbox::query(ctx, args),
        "Mailbox/queryChanges" => query::cannot_calculate(ctx, args),
        "Mailbox/set" => mailbox::set(ctx, args),
        "Email/get" => email::get(ctx, args),
        "Email/changes" => email::changes(ctx, args),
        "Email/query" => query::email_query(ctx, args),
        "Email/queryChanges" => query::cannot_calculate(ctx, args),
        "Email/set" => email::set(ctx, args),
        "Email/import" => email::import(ctx, args),
        "Email/copy" => email::copy(ctx, args),
        "Email/parse" => email::parse(ctx, args),
        "Thread/get" => thread::get(ctx, args),
        "Thread/changes" => thread::changes(ctx, args),
        "SearchSnippet/get" => snippet::get(ctx, args),
        "Identity/get" => identity::get(ctx, args),
        "Identity/changes" => identity::changes(ctx, args),
        "Identity/set" => identity::set(ctx, args),
        "EmailSubmission/get" => submission::get(ctx, args),
        "EmailSubmission/changes" => submission::changes(ctx, args),
        "EmailSubmission/query" => submission::query(ctx, args),
        "EmailSubmission/queryChanges" => query::cannot_calculate(ctx, args),
        "EmailSubmission/set" => submission::set(ctx, args),
        "VacationResponse/get" => vacation::get(ctx, args),
        "VacationResponse/set" => vacation::set(ctx, args),
        _ => Err(MethodError::new("unknownMethod")),
    }
}

/// Evaluate a JSON pointer with the `*` array wildcard of RFC 8620 section
/// 3.7.
pub(crate) fn evaluate_pointer(value: &Value, path: &str) -> Option<Value> {
    if path.is_empty() {
        return Some(value.clone());
    }
    let path = path.strip_prefix('/')?;
    let (token, rest) = match path.find('/') {
        Some(index) => (&path[..index], &path[index..]),
        None => (path, ""),
    };
    let token = token.replace("~1", "/").replace("~0", "~");
    match value {
        Value::Array(items) if token == "*" => {
            let mut out = Vec::new();
            for item in items {
                match evaluate_pointer(item, rest)? {
                    Value::Array(inner) => out.extend(inner),
                    other => out.push(other),
                }
            }
            Some(Value::Array(out))
        }
        Value::Array(items) => evaluate_pointer(items.get(token.parse::<usize>().ok()?)?, rest),
        Value::Object(map) => evaluate_pointer(map.get(&token)?, rest),
        _ => None,
    }
}

/// Replace `#name` arguments by the values their result references point
/// to (RFC 8620 section 3.7).
fn resolve_references(
    args: Map<String, Value>,
    responses: &[(String, Value, String)],
) -> Result<Map<String, Value>, MethodError> {
    let mut out = Map::new();
    for (key, value) in &args {
        let Some(name) = key.strip_prefix('#') else {
            continue;
        };
        if args.contains_key(name) {
            return Err(MethodError::invalid(format!(
                "both {name} and #{name} are given"
            )));
        }
        let reference = value.as_object().ok_or_else(|| {
            MethodError::with(
                "invalidResultReference",
                "a result reference must be an object",
            )
        })?;
        let field = |field: &str| {
            reference.get(field).and_then(Value::as_str).ok_or_else(|| {
                MethodError::with(
                    "invalidResultReference",
                    format!("result reference without {field}"),
                )
            })
        };
        let (result_of, method, path) = (field("resultOf")?, field("name")?, field("path")?);
        let response = responses
            .iter()
            .find(|(_, _, call_id)| call_id == result_of)
            .filter(|(name, _, _)| name == method)
            .ok_or_else(|| {
                MethodError::with(
                    "invalidResultReference",
                    format!("no {method} response for call {result_of}"),
                )
            })?;
        let resolved = evaluate_pointer(&response.1, path).ok_or_else(|| {
            MethodError::with("invalidResultReference", format!("{path} does not resolve"))
        })?;
        out.insert(name.to_string(), resolved);
    }
    for (key, value) in args {
        if !key.starts_with('#') {
            out.insert(key, value);
        }
    }
    Ok(out)
}

/// Process a whole API request; returns the Response object.
pub(crate) fn process(ctx: &mut Ctx, request: &Value) -> Result<Value, (&'static str, String)> {
    const NOT_REQUEST: &str = "urn:ietf:params:jmap:error:notRequest";
    let request = request
        .as_object()
        .ok_or((NOT_REQUEST, "the request is not an object".to_string()))?;
    let using = request
        .get("using")
        .and_then(Value::as_array)
        .ok_or((NOT_REQUEST, "using is missing".to_string()))?;
    for capability in using {
        let capability = capability
            .as_str()
            .ok_or((NOT_REQUEST, "using holds a non-string".to_string()))?;
        let known = [CORE, MAIL, VACATION].contains(&capability)
            || (capability == SUBMISSION && ctx.app.submission.is_some());
        if !known {
            return Err((
                "urn:ietf:params:jmap:error:unknownCapability",
                format!("unknown capability {capability}"),
            ));
        }
        ctx.using.insert(capability.to_string());
    }
    let calls = request
        .get("methodCalls")
        .and_then(Value::as_array)
        .ok_or((NOT_REQUEST, "methodCalls is missing".to_string()))?;
    if calls.len() > MAX_CALLS_IN_REQUEST {
        return Err((
            "urn:ietf:params:jmap:error:limit",
            format!("at most {MAX_CALLS_IN_REQUEST} method calls per request"),
        ));
    }
    let echo_created = request.get("createdIds").and_then(Value::as_object);
    if let Some(created) = echo_created {
        for (creation_id, id) in created {
            if let Some(id) = id.as_str() {
                ctx.created_ids.insert(creation_id.clone(), id.to_string());
            }
        }
    }
    let mut responses: Vec<(String, Value, String)> = Vec::new();
    for call in calls {
        let Some(
            [
                Value::String(name),
                Value::Object(args),
                Value::String(call_id),
            ],
        ) = call.as_array().map(Vec::as_slice)
        else {
            return Err((
                NOT_REQUEST,
                "a method call is not [name, args, id]".to_string(),
            ));
        };
        let outcome = resolve_references(args.clone(), &responses)
            .and_then(|args| call_method(ctx, name, args));
        match outcome {
            Ok(results) => {
                for (name, result) in results {
                    responses.push((name, result, call_id.clone()));
                }
            }
            Err(error) => responses.push(("error".to_string(), error.to_json(), call_id.clone())),
        }
    }
    let session = session_state(&ctx.accounts, ctx.app.submission.is_some());
    let mut response = json!({
        "methodResponses": responses
            .into_iter()
            .map(|(name, result, call_id)| json!([name, result, call_id]))
            .collect::<Vec<_>>(),
        "sessionState": session,
    });
    if echo_created.is_some() {
        response["createdIds"] = json!(ctx.created_ids);
    }
    Ok(response)
}

/// Whether a browser sent the request on behalf of another site. A browser
/// attaches cached Basic credentials even to a cross-site form post, so
/// such requests are refused before authentication (native clients send
/// neither header).
pub(crate) fn from_another_site(headers: &HeaderMap) -> bool {
    let text = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    if let Some(site) = text("sec-fetch-site")
        && !matches!(site, "same-origin" | "none")
    {
        return true;
    }
    if let Some(origin) = text("origin") {
        let origin_host = origin.split_once("://").map(|(_, host)| host);
        if origin_host.is_none() || origin_host != text("host") {
            return true;
        }
    }
    false
}

pub(crate) fn cross_site_refusal() -> Response {
    (
        StatusCode::FORBIDDEN,
        "cross-site requests are not accepted",
    )
        .into_response()
}

async fn api(
    app: State<Shared>,
    Extension(peer): Extension<Peer>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let state = app.0;
    if from_another_site(&headers) {
        return cross_site_refusal();
    }
    // HTML forms cannot send this type, so a form can never pose as a
    // JMAP request (RFC 8620 section 3.3 requires it anyway).
    let json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
    if !json {
        return problem(
            "urn:ietf:params:jmap:error:notJSON",
            "the request must be application/json",
        );
    }
    let user = match authenticate(&state, &headers, &peer).await {
        Ok(user) => user,
        Err(response) => return *response,
    };
    if body.len() > MAX_SIZE_REQUEST {
        return problem(
            "urn:ietf:params:jmap:error:limit",
            "the request is larger than maxSizeRequest",
        );
    }
    let Ok(request) = serde_json::from_slice::<Value>(&body) else {
        return problem(
            "urn:ietf:params:jmap:error:notJSON",
            "the request is not JSON",
        );
    };
    let outcome = blocking(move || {
        let accounts = accounts(&state, &user)?;
        let mut ctx = Ctx::new(state, user, accounts);
        Ok(process(&mut ctx, &request))
    })
    .await;
    match outcome {
        Ok(Ok(response)) => json_response(&response),
        Ok(Err((kind, detail))) => problem(kind, &detail),
        Err(error) => internal_response(format!("{error:#}")),
    }
}

// ---------------------------------------------------------------------------
// Helpers shared by the object types

/// `ids` from the arguments: `None` for null (all objects).
pub(crate) fn ids_arg(
    ctx: &Ctx,
    args: &Map<String, Value>,
    name: &str,
) -> Result<Option<Vec<String>>, MethodError> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => {
            if items.len() > MAX_OBJECTS_IN_GET {
                return Err(MethodError::new("requestTooLarge"));
            }
            items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(|id| ctx.resolve_id(id).unwrap_or_else(|| id.to_string()))
                        .ok_or_else(|| MethodError::invalid(format!("{name} must hold strings")))
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Some)
        }
        Some(_) => Err(MethodError::invalid(format!("{name} must be a list"))),
    }
}

/// `properties` from the arguments, checked against `known`.
pub(crate) fn properties_arg(
    args: &Map<String, Value>,
    name: &str,
    known: &[&str],
    defaults: &[&str],
    accept: impl Fn(&str) -> bool,
) -> Result<Vec<String>, MethodError> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(defaults.iter().map(|p| p.to_string()).collect()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item.as_str() {
                Some(property) if known.contains(&property) || accept(property) => {
                    Ok(property.to_string())
                }
                _ => Err(MethodError::invalid(format!("unknown property {item}"))),
            })
            .collect(),
        Some(_) => Err(MethodError::invalid(format!("{name} must be a list"))),
    }
}

pub(crate) fn uint_arg(args: &Map<String, Value>, name: &str) -> Result<Option<u64>, MethodError> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| MethodError::invalid(format!("{name} must be an unsigned integer"))),
    }
}

pub(crate) fn bool_arg(args: &Map<String, Value>, name: &str) -> Result<bool, MethodError> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(MethodError::invalid(format!("{name} must be a boolean"))),
    }
}

pub(crate) fn str_arg<'a>(
    args: &'a Map<String, Value>,
    name: &str,
) -> Result<Option<&'a str>, MethodError> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(MethodError::invalid(format!("{name} must be a string"))),
    }
}

/// Keep only `properties` of an object (`id` always stays).
pub(crate) fn project(mut object: Map<String, Value>, properties: &[String]) -> Value {
    object.retain(|key, _| key == "id" || properties.iter().any(|property| property == key));
    Value::Object(object)
}

/// A `/changes` response for one object kind.
pub(crate) fn changes_response(
    ctx: &mut Ctx,
    args: &Map<String, Value>,
    kind: &str,
    filter: impl Fn(
        &Account,
        &rusqlite::Connection,
        &std::path::Path,
        &mut rmail_common::jmap::store::Changes,
    ) -> Result<(), MethodError>,
) -> Result<(Account, Value, bool), MethodError> {
    let account = ctx.account(args)?;
    let since = str_arg(args, "sinceState")?
        .ok_or_else(|| MethodError::invalid("sinceState is required"))?;
    let max = uint_arg(args, "maxChanges")?;
    if max == Some(0) {
        return Err(MethodError::invalid("maxChanges must be positive"));
    }
    let since = account
        .parse_state(since)
        .ok_or_else(|| MethodError::new("cannotCalculateChanges"))?;
    let conn = ctx.open(&account)?;
    let mut changes = match rmail_common::jmap::store::changes(
        &conn,
        kind,
        since,
        max.map(|max| max as usize),
    )? {
        Ok(changes) => changes,
        Err(_) => return Err(MethodError::new("cannotCalculateChanges")),
    };
    filter(&account, &conn, &ctx.app.mail_root, &mut changes)?;
    let counts_only = changes.counts_only;
    Ok((
        account.clone(),
        json!({
            "accountId": account.id,
            "oldState": account.state(since),
            "newState": account.state(changes.new_state),
            "hasMoreChanges": changes.has_more,
            "created": changes.created,
            "updated": changes.updated,
            "destroyed": changes.destroyed,
        }),
        counts_only,
    ))
}

/// The account's current state string.
pub(crate) fn current_state(ctx: &Ctx, account: &Account) -> Result<String, MethodError> {
    let conn = ctx.open(account)?;
    Ok(account.state(rmail_common::jmap::store::state(&conn)?))
}

/// `ifInState` check for `/set` methods.
pub(crate) fn check_if_in_state(
    ctx: &Ctx,
    account: &Account,
    args: &Map<String, Value>,
) -> Result<String, MethodError> {
    let state = current_state(ctx, account)?;
    if let Some(expected) = str_arg(args, "ifInState")?
        && expected != state
    {
        return Err(MethodError::new("stateMismatch"));
    }
    Ok(state)
}

/// UTCDate for a Unix timestamp.
pub(crate) fn utc_date(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

pub(crate) fn parse_utc_date(text: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|date| date.timestamp())
}

/// The IMAP flag for a JMAP keyword and back (RFC 8621 section 4.1.1).
pub(crate) fn keyword_to_flag(keyword: &str) -> String {
    match keyword.to_ascii_lowercase().as_str() {
        "$seen" => "\\Seen".to_string(),
        "$flagged" => "\\Flagged".to_string(),
        "$answered" => "\\Answered".to_string(),
        "$draft" => "\\Draft".to_string(),
        "$forwarded" => "$Forwarded".to_string(),
        _ => keyword.to_string(),
    }
}

/// `None` for flags with no keyword (\Recent, \Deleted).
pub(crate) fn flag_to_keyword(flag: &str) -> Option<String> {
    match flag.to_ascii_lowercase().as_str() {
        "\\seen" => Some("$seen".to_string()),
        "\\flagged" => Some("$flagged".to_string()),
        "\\answered" => Some("$answered".to_string()),
        "\\draft" => Some("$draft".to_string()),
        "\\recent" | "\\deleted" => None,
        other if other.starts_with('\\') => None,
        other => Some(other.to_string()),
    }
}

/// A keyword is an atom of 1 to 255 printable ASCII characters without
/// `( ) { ] % * " \` (RFC 8621 section 4.1.1).
pub(crate) fn valid_keyword(keyword: &str) -> bool {
    !keyword.is_empty()
        && keyword.len() <= 255
        && keyword
            .bytes()
            .all(|byte| (0x21..0x7f).contains(&byte) && !b"(){]%*\"\\".contains(&byte))
}

/// Generate an object id with a prefix.
pub(crate) fn new_id(prefix: &str) -> String {
    format!("{prefix}{:024x}", rand::random::<u128>() >> 32)
}
