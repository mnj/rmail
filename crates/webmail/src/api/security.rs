//! Two-factor sign-in and app passwords, managed by the user in webmail
//! (see `rmail_common::two_factor`).
//!
//! Every change asks for the account's password again, so a stolen session
//! cookie alone cannot turn 2FA off or mint an app password. Turning 2FA on
//! or off changes what sessions are bound to, which signs out every other
//! session; the response carries a fresh cookie for this one.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use rmail_common::{auth, db, two_factor, websession};
use serde::Deserialize;
use serde_json::json;

use super::{SESSION_TTL_SECS, Session, Shared, blocking, internal_error, session_cookie};

pub(crate) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/security", get(overview))
        .route("/api/security/totp/start", post(start))
        .route("/api/security/totp/confirm", post(confirm))
        .route("/api/security/totp/disable", post(disable))
        .route("/api/security/recovery-codes", post(recovery_codes))
        .route("/api/security/app-passwords", post(create_app_password))
        .route(
            "/api/security/app-passwords/{id}",
            delete(revoke_app_password),
        )
}

fn refused(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

async fn overview(app: State<Shared>, headers: HeaderMap) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let result = blocking(move || {
        let status = two_factor::status(&state.db_path, &session.address)?;
        let passwords = two_factor::app_passwords(&state.db_path, &session.address)?;
        Ok(json!({
            "two_factor": {
                "enabled": status.enabled,
                "since": status.since,
                "recovery_left": status.recovery_left,
            },
            "app_passwords": passwords,
        }))
    })
    .await;
    match result {
        Ok(body) => Json(body).into_response(),
        Err(error) => internal_error(error),
    }
}

/// Whether `password` is the account's main password. Wrong guesses are
/// counted per account and lock these checks for a while
/// (`two_factor::Check::Password`), so a stolen session cookie cannot be
/// used to guess the password.
async fn password_ok(state: &Shared, address: &str, password: &str) -> Result<(), Response> {
    let (db_path, lookup) = (state.db_path.clone(), address.to_string());
    let locked =
        blocking(move || two_factor::locked_for(&db_path, &lookup, two_factor::Check::Password))
            .await
            .unwrap_or(Some(two_factor::LOCKOUT_SECONDS));
    if let Some(seconds) = locked {
        return Err(refused(
            StatusCode::TOO_MANY_REQUESTS,
            &format!(
                "Too many wrong passwords. Try again in {} minutes.",
                (seconds + 59) / 60
            ),
        ));
    }
    let (db_path, lookup) = (state.db_path.clone(), address.to_string());
    let hash = blocking(move || db::get_mailbox(&db_path, &lookup))
        .await
        .ok()
        .flatten()
        .and_then(|mailbox| mailbox.password_hash);
    let ok = match hash {
        Some(hash) => matches!(
            auth::verify_password_async(password.to_string(), hash).await,
            Ok(true)
        ),
        None => false,
    };
    let (db_path, account) = (state.db_path.clone(), address.to_string());
    let _ = blocking(move || {
        if ok {
            two_factor::record_success(&db_path, &account, two_factor::Check::Password)
        } else {
            two_factor::record_failure(&db_path, &account, two_factor::Check::Password)
        }
    })
    .await;
    if ok {
        Ok(())
    } else {
        Err(refused(StatusCode::FORBIDDEN, "That is not your password."))
    }
}

/// A new session cookie for `address`, bound to its current credentials.
fn renewed(state: &Shared, address: &str, body: serde_json::Value) -> Response {
    let credential = db::get_mailbox(&state.db_path, address)
        .ok()
        .flatten()
        .and_then(|mailbox| mailbox.session_credential());
    let mut response = Json(body).into_response();
    if let Some(credential) = credential {
        let binding = websession::credential_binding(&state.session_secret, &credential);
        let token = websession::sign(&state.session_secret, address, &binding, SESSION_TTL_SECS);
        if let Ok(value) = HeaderValue::from_str(&session_cookie(state, &token)) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

#[derive(Deserialize)]
struct PasswordOnly {
    password: String,
}

/// Begin turning 2FA on: a new secret, as text and as a QR code.
async fn start(app: State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<PasswordOnly>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "invalid json");
    };
    if let Err(response) = password_ok(&state, &session.address, &input.password).await {
        return response;
    }
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|host| host.split(':').next())
        .filter(|host| {
            host.len() <= 100
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        })
        .unwrap_or("mail")
        .to_string();
    let result = blocking(move || {
        let secret = two_factor::begin(&state.db_path, &session.address)?;
        let uri = two_factor::provisioning_uri(&session.address, &secret, &format!("rMail {host}"));
        let svg = qrcode::QrCode::new(uri.as_bytes())?
            .render::<qrcode::render::svg::Color<'_>>()
            .min_dimensions(200, 200)
            .quiet_zone(true)
            .build();
        Ok(json!({ "secret": secret, "uri": uri, "qr_svg": svg }))
    })
    .await;
    match result {
        Ok(body) => Json(body).into_response(),
        Err(error) if error.to_string().contains("already on") => {
            refused(StatusCode::CONFLICT, "Two-factor sign-in is already on.")
        }
        Err(error) => internal_error(error),
    }
}

#[derive(Deserialize)]
struct CodeOnly {
    code: String,
}

/// Turn 2FA on with a code from the app; the recovery codes, once.
async fn confirm(app: State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<CodeOnly>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "invalid json");
    };
    let (db_path, address) = (state.db_path.clone(), session.address.clone());
    match blocking(move || two_factor::confirm(&db_path, &address, &input.code)).await {
        Ok(Some(codes)) => renewed(&state, &session.address, json!({ "recovery_codes": codes })),
        Ok(None) => refused(
            StatusCode::BAD_REQUEST,
            "That code is not right. Check the time on your phone and try the newest code.",
        ),
        Err(error) => internal_error(error),
    }
}

#[derive(Deserialize)]
struct PasswordAndCode {
    password: String,
    code: String,
}

/// Turn 2FA off: the password and a current code (or a recovery code).
async fn disable(app: State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<PasswordAndCode>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "invalid json");
    };
    if let Err(response) = password_ok(&state, &session.address, &input.password).await {
        return response;
    }
    let (db_path, address) = (state.db_path.clone(), session.address.clone());
    let result = blocking(move || {
        if !two_factor::verify(&db_path, &address, &input.code)? {
            return Ok(false);
        }
        two_factor::disable(&db_path, &address)
    })
    .await;
    match result {
        Ok(true) => renewed(&state, &session.address, json!({ "enabled": false })),
        Ok(false) => refused(StatusCode::BAD_REQUEST, "That code is not right."),
        Err(error) => internal_error(error),
    }
}

/// New recovery codes (the old ones stop working).
async fn recovery_codes(app: State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<PasswordAndCode>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "invalid json");
    };
    if let Err(response) = password_ok(&state, &session.address, &input.password).await {
        return response;
    }
    let (db_path, address) = (state.db_path.clone(), session.address.clone());
    let result = blocking(move || {
        if !two_factor::verify(&db_path, &address, &input.code)? {
            return Ok(None);
        }
        two_factor::regenerate_recovery_codes(&db_path, &address).map(Some)
    })
    .await;
    match result {
        Ok(Some(codes)) => Json(json!({ "recovery_codes": codes })).into_response(),
        Ok(None) => refused(StatusCode::BAD_REQUEST, "That code is not right."),
        Err(error) => internal_error(error),
    }
}

#[derive(Deserialize)]
struct NewAppPassword {
    name: String,
    password: String,
}

/// A new app password; the password itself is shown once.
async fn create_app_password(app: State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<NewAppPassword>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "invalid json");
    };
    if let Err(response) = password_ok(&state, &session.address, &input.password).await {
        return response;
    }
    let (db_path, address) = (state.db_path.clone(), session.address.clone());
    match blocking(move || two_factor::create_app_password(&db_path, &address, &input.name)).await {
        Ok((made, password)) => {
            Json(json!({ "app_password": made, "password": password })).into_response()
        }
        Err(error) => refused(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    }
}

async fn revoke_app_password(
    app: State<Shared>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    match blocking(move || two_factor::revoke_app_password(&state.db_path, &session.address, id))
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => internal_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{req, route, state};
    use super::super::{SESSION_COOKIE, sign_session};
    use base64::Engine;
    use serde_json::{Value, json};

    const ME: &str = "user@example.test";

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn code(secret: &str, step_offset: i64) -> String {
        let key = rmail_common::two_factor::base32_decode(secret).unwrap();
        format!(
            "{:06}",
            rmail_common::two_factor::code_at(&key, now() / 30 + step_offset)
        )
    }

    #[tokio::test]
    async fn two_factor_sign_in_and_app_passwords() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        let cookie = Some(format!("{SESSION_COOKIE}={}", sign_session(&state, ME)));
        let call =
            |method: &'static str, path: &'static str, body: Value, cookie: Option<String>| {
                let state = state.clone();
                async move {
                    let body = if body.is_null() {
                        Vec::new()
                    } else {
                        body.to_string().into_bytes()
                    };
                    let response = route(req(method, path, &body, cookie), &state).await;
                    let set_cookie = response.header("Set-Cookie").to_string();
                    let json = serde_json::from_slice::<Value>(&response.body).unwrap_or_default();
                    (response.status, json, set_cookie)
                }
            };
        let basic = |password: &str| {
            let state = state.clone();
            let header = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{ME}:{password}"))
            );
            async move {
                let mut request = req("GET", "/jmap/session", b"", None);
                request
                    .headers_mut()
                    .insert(axum::http::header::AUTHORIZATION, header.parse().unwrap());
                route(request, &state).await.status
            }
        };

        let (status, overview, _) = call("GET", "/api/security", Value::Null, cookie.clone()).await;
        assert_eq!(status, 200);
        assert_eq!(overview["two_factor"]["enabled"], false);

        // An app password, for a phone; the main password is asked for again.
        let (status, _, _) = call(
            "POST",
            "/api/security/app-passwords",
            json!({"name": "Phone", "password": "wrong"}),
            cookie.clone(),
        )
        .await;
        assert_eq!(status, 403);
        let (status, made, _) = call(
            "POST",
            "/api/security/app-passwords",
            json!({"name": "Phone", "password": "secret"}),
            cookie.clone(),
        )
        .await;
        assert_eq!(status, 200, "{made}");
        let app = made["password"].as_str().unwrap().to_string();
        assert_eq!(basic(&app).await, 200);
        assert_eq!(
            basic("secret").await,
            200,
            "the main password still works without 2FA"
        );

        // Turning 2FA on.
        let (status, started, _) = call(
            "POST",
            "/api/security/totp/start",
            json!({"password": "secret"}),
            cookie.clone(),
        )
        .await;
        assert_eq!(status, 200, "{started}");
        let secret = started["secret"].as_str().unwrap().to_string();
        let first = code(&secret, 0);
        assert!(
            started["qr_svg"].as_str().unwrap().starts_with("<?xml")
                || started["qr_svg"].as_str().unwrap().contains("<svg")
        );
        assert!(
            started["uri"]
                .as_str()
                .unwrap()
                .starts_with("otpauth://totp/")
        );
        let (status, _, _) = call(
            "POST",
            "/api/security/totp/confirm",
            json!({"code": "000000"}),
            cookie.clone(),
        )
        .await;
        assert_eq!(status, 400);
        let (status, confirmed, renewed) = call(
            "POST",
            "/api/security/totp/confirm",
            json!({"code": first.clone()}),
            cookie.clone(),
        )
        .await;
        assert_eq!(status, 200, "{confirmed}");
        let recovery: Vec<String> =
            serde_json::from_value(confirmed["recovery_codes"].clone()).unwrap();
        assert_eq!(recovery.len(), 10);
        assert!(
            renewed.starts_with(SESSION_COOKIE),
            "a fresh cookie for this session"
        );
        let (status, _, _) = call("GET", "/api/security", Value::Null, cookie.clone()).await;
        assert_eq!(status, 401, "other sessions are signed out");
        let fresh = Some(renewed.split(';').next().unwrap().to_string());
        let (status, overview, _) = call("GET", "/api/security", Value::Null, fresh.clone()).await;
        assert_eq!(status, 200);
        assert_eq!(overview["two_factor"]["enabled"], true);

        // Mail apps: app passwords only.
        assert_eq!(basic("secret").await, 401);
        assert_eq!(basic(&app).await, 200);

        // Webmail sign-in asks for a code.
        let login = |code: Option<String>| {
            let mut body = json!({"address": ME, "password": "secret"});
            if let Some(code) = code {
                body["code"] = json!(code);
            }
            call("POST", "/api/login", body, None)
        };
        let (status, asked, _) = login(None).await;
        assert_eq!((status, asked["two_factor"].clone()), (401, json!(true)));
        let (status, _, _) = login(Some("123456".into())).await;
        assert_eq!(status, 401);
        let (status, _, _) = login(Some(first.clone())).await;
        assert_eq!(
            status, 401,
            "the code used to turn 2FA on cannot be used again"
        );
        let (status, _, signed_in) = login(Some(code(&secret, 1))).await;
        assert_eq!(status, 200);
        assert!(signed_in.starts_with(SESSION_COOKIE));
        let (status, _, _) = login(Some(recovery[0].clone())).await;
        assert_eq!(status, 200, "a recovery code");
        let (status, _, _) = login(Some(recovery[0].clone())).await;
        assert_eq!(status, 401, "only once");

        // Turning it off needs the password and a code.
        let (status, _, _) = call(
            "POST",
            "/api/security/totp/disable",
            json!({"password": "secret", "code": "000000"}),
            fresh.clone(),
        )
        .await;
        assert_eq!(status, 400);
        let (status, _, _) = call(
            "POST",
            "/api/security/totp/disable",
            json!({"password": "secret", "code": recovery[1]}),
            fresh.clone(),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(basic("secret").await, 200);
        let id = made["app_password"]["id"].as_i64().unwrap();
        let path: &'static str =
            Box::leak(format!("/api/security/app-passwords/{id}").into_boxed_str());
        let (status, _, _) = call("DELETE", path, Value::Null, fresh.clone()).await;
        assert_eq!(
            status, 401,
            "the session after turning 2FA off is a new one"
        );
    }
}

#[cfg(test)]
mod lockout_tests {
    use super::super::tests::{req, route, state};
    use super::super::{SESSION_COOKIE, sign_session};
    use serde_json::json;

    #[tokio::test]
    async fn password_guesses_with_a_session_are_limited_per_account() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        let cookie = Some(format!(
            "{SESSION_COOKIE}={}",
            sign_session(&state, "user@example.test")
        ));
        let attempt = |password: &'static str| {
            let (state, cookie) = (state.clone(), cookie.clone());
            async move {
                let body = json!({"name": "Phone", "password": password}).to_string();
                route(
                    req(
                        "POST",
                        "/api/security/app-passwords",
                        body.as_bytes(),
                        cookie,
                    ),
                    &state,
                )
                .await
                .status
            }
        };
        for _ in 0..rmail_common::two_factor::MAX_FAILURES {
            assert_eq!(attempt("guess").await, 403);
        }
        assert_eq!(
            attempt("secret").await,
            429,
            "locked, even with the right password"
        );
    }
}

#[cfg(test)]
mod policy_tests {
    use super::super::tests::{req, route, state};
    use super::super::{SESSION_COOKIE, sign_session};
    use serde_json::{Value, json};

    #[tokio::test]
    async fn a_domain_policy_asks_for_setup_before_anything_else() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        rmail_common::imap_state::init_account(&state.mail_root, "example.test", "user").unwrap();
        let cookie = Some(format!(
            "{SESSION_COOKIE}={}",
            sign_session(&state, "user@example.test")
        ));
        let call =
            |method: &'static str, path: &'static str, body: Value, cookie: Option<String>| {
                let state = state.clone();
                async move {
                    let body = if body.is_null() {
                        Vec::new()
                    } else {
                        body.to_string().into_bytes()
                    };
                    let response = route(req(method, path, &body, cookie), &state).await;
                    let set_cookie = response.header("Set-Cookie").to_string();
                    (
                        response.status,
                        serde_json::from_slice::<Value>(&response.body).unwrap_or_default(),
                        set_cookie,
                    )
                }
            };
        assert_eq!(
            call("GET", "/api/folders", Value::Null, cookie.clone())
                .await
                .0,
            200
        );
        rmail_common::two_factor::set_required(&state.db_path, "example.test", true).unwrap();
        let (status, refused, _) = call("GET", "/api/folders", Value::Null, cookie.clone()).await;
        assert_eq!(
            (status, refused["two_factor_setup"].clone()),
            (403, json!(true))
        );
        let (_, session, _) = call("GET", "/api/session", Value::Null, cookie.clone()).await;
        assert_eq!(session["two_factor_setup"], true);
        assert_eq!(
            call("GET", "/api/security", Value::Null, cookie.clone())
                .await
                .0,
            200
        );

        let (_, started, _) = call(
            "POST",
            "/api/security/totp/start",
            json!({"password": "secret"}),
            cookie.clone(),
        )
        .await;
        let key =
            rmail_common::two_factor::base32_decode(started["secret"].as_str().unwrap()).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let code = format!("{:06}", rmail_common::two_factor::code_at(&key, now / 30));
        let (status, _, renewed) = call(
            "POST",
            "/api/security/totp/confirm",
            json!({"code": code}),
            cookie,
        )
        .await;
        assert_eq!(status, 200);
        let fresh = Some(renewed.split(';').next().unwrap().to_string());
        assert_eq!(
            call("GET", "/api/folders", Value::Null, fresh.clone())
                .await
                .0,
            200
        );
        let (_, session, _) = call("GET", "/api/session", Value::Null, fresh).await;
        assert_eq!(session["two_factor_setup"], false);
    }
}
