//! Webmail sign-in through an OpenID Connect provider (see
//! `rmail_common::oidc`). The provider's email must be an existing mailbox;
//! signing in this way stands in for the password and two-factor code,
//! which the provider is trusted to have asked for.
//!
//! The state, nonce and PKCE verifier of a sign-in in progress live in a
//! short-lived signed cookie (SameSite=Lax, so it comes back with the
//! provider's redirect).

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use hmac::{Hmac, Mac};
use rmail_common::http::Peer;
use rmail_common::{db, imap_state, oidc, websession};
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;

use super::{AppState, SESSION_COOKIE, SESSION_TTL_SECS, Shared, blocking, with_cookie};

const FLOW_COOKIE: &str = "rmail_oidc";
/// How long a sign-in at the provider may take.
const FLOW_TTL_SECS: u64 = 600;

pub(crate) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/oidc", get(offered))
        .route("/api/oidc/start", get(start))
        .route("/api/oidc/callback", get(callback))
}

fn settings(state: &AppState) -> rmail_common::config::OidcConfig {
    rmail_common::settings::open(&state.db_path)
        .ok()
        .and_then(|conn| rmail_common::settings::oidc(&conn).ok())
        .unwrap_or_default()
}

/// A key for flow cookies only, so they can never pass as sessions.
fn flow_key(state: &AppState) -> Vec<u8> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&state.session_secret).expect("HMAC accepts any key length");
    mac.update(b"oidc-flow");
    mac.finalize().into_bytes().to_vec()
}

fn redirect_uri(state: &AppState, headers: &HeaderMap) -> String {
    format!(
        "{}/api/oidc/callback",
        crate::jmap::base_url(state, headers)
    )
}

fn redirect(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
}

/// Back to the sign-in page with a reason.
fn failed(state: &AppState, reason: &str) -> Response {
    with_cookie(
        redirect(&format!("/?sso_error={reason}")),
        websession::set_cookie(FLOW_COOKIE, "", 0, state.secure_cookies, "Lax"),
    )
}

/// Whether the sign-in page offers single sign-on, and its button.
async fn offered(State(state): State<Shared>) -> Response {
    let config = blocking(move || Ok(settings(&state)))
        .await
        .unwrap_or_default();
    Json(json!({
        "enabled": oidc::configured(&config),
        "label": config.button_label,
    }))
    .into_response()
}

async fn start(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let config = {
        let state = state.clone();
        blocking(move || Ok(settings(&state)))
            .await
            .unwrap_or_default()
    };
    if !oidc::configured(&config) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let provider = match oidc::discover(&config.issuer).await {
        Ok(provider) => provider,
        Err(error) => {
            webmail_log!("warn", "oidc_discovery_failed", { "error": format!("{error:#}") });
            return failed(&state, "provider");
        }
    };
    let (flow_state, nonce, verifier) = (
        oidc::random_token(),
        oidc::random_token(),
        oidc::random_token(),
    );
    let Ok(location) = oidc::authorize_url(
        &provider,
        &config,
        &redirect_uri(&state, &headers),
        &flow_state,
        &nonce,
        &verifier,
    ) else {
        return failed(&state, "provider");
    };
    let flow = websession::sign(
        &flow_key(&state),
        &format!("{flow_state} {nonce} {verifier}"),
        "oidc",
        FLOW_TTL_SECS,
    );
    with_cookie(
        redirect(&location),
        websession::set_cookie(
            FLOW_COOKIE,
            &flow,
            FLOW_TTL_SECS,
            state.secure_cookies,
            "Lax",
        ),
    )
}

#[derive(Deserialize)]
struct Callback {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

async fn callback(
    State(state): State<Shared>,
    Extension(peer): Extension<Peer>,
    headers: HeaderMap,
    Query(query): Query<Callback>,
) -> Response {
    if query.error.is_some() {
        return failed(&state, "cancelled");
    }
    let flow = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| websession::cookie_value(cookies, FLOW_COOKIE))
        .and_then(|token| websession::verify(&flow_key(&state), token))
        .filter(|flow| flow.binding == "oidc");
    let Some(flow) = flow else {
        return failed(&state, "expired");
    };
    let mut parts = flow.subject.split(' ');
    let (Some(flow_state), Some(nonce), Some(verifier)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return failed(&state, "expired");
    };
    let (Some(code), Some(returned)) = (query.code, query.state) else {
        return failed(&state, "expired");
    };
    if returned != flow_state {
        return failed(&state, "expired");
    }
    let config = {
        let state = state.clone();
        blocking(move || Ok(settings(&state)))
            .await
            .unwrap_or_default()
    };
    if !oidc::configured(&config) {
        return failed(&state, "provider");
    }
    let identity = match oidc::discover(&config.issuer).await {
        Ok(provider) => {
            oidc::exchange(
                &provider,
                &config,
                &redirect_uri(&state, &headers),
                &code,
                verifier,
                nonce,
            )
            .await
        }
        Err(error) => Err(error),
    };
    let identity = match identity {
        Ok(identity) => identity,
        Err(error) => {
            webmail_log!("warn", "oidc_sign_in_failed", { "error": format!("{error:#}") });
            return failed(&state, "provider");
        }
    };
    if config.require_verified_email && !identity.email_verified {
        return failed(&state, "unverified");
    }
    let (db_path, address) = (state.db_path.clone(), identity.email.clone());
    let mailbox = blocking(move || db::get_mailbox(&db_path, &address))
        .await
        .ok()
        .flatten();
    let Some((mailbox, credential)) =
        mailbox.and_then(|m| Some((m.clone(), m.session_credential()?)))
    else {
        webmail_log!("info", "oidc_no_mailbox", { "email": identity.email, "ip": peer.ip().map(|ip| ip.to_string()) });
        return failed(&state, "no_mailbox");
    };
    let address = mailbox.address.to_ascii_lowercase();
    if let Some((localpart, domain)) = address.split_once('@') {
        let (root, domain, localpart) = (
            state.mail_root.clone(),
            domain.to_string(),
            localpart.to_string(),
        );
        let _ = blocking(move || imap_state::init_account(&root, &domain, &localpart)).await;
    }
    webmail_log!("info", "oidc_sign_in", { "address": address, "ip": peer.ip().map(|ip| ip.to_string()) });
    let binding = websession::credential_binding(&state.session_secret, &credential);
    let token = websession::sign(&state.session_secret, &address, &binding, SESSION_TTL_SECS);
    let response = with_cookie(
        redirect("/"),
        websession::set_cookie(
            SESSION_COOKIE,
            &token,
            SESSION_TTL_SECS,
            state.secure_cookies,
            "Strict",
        ),
    );
    with_cookie(
        response,
        websession::set_cookie(FLOW_COOKIE, "", 0, state.secure_cookies, "Lax"),
    )
}

#[cfg(test)]
mod tests {
    use axum::routing::post;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::Value;

    use crate::api::tests::{TestResponse, req, route, state};

    /// A provider whose token endpoint takes the nonce as the code and
    /// vouches for `email`.
    async fn provider(email: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let discovery = serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/auth"),
            "token_endpoint": format!("{issuer}/token"),
        });
        let iss = issuer.clone();
        let app = axum::Router::new()
            .route(
                "/.well-known/openid-configuration",
                axum::routing::get(move || async move { axum::Json(discovery) }),
            )
            .route(
                "/token",
                post(move |body: String| async move {
                    let form: std::collections::HashMap<String, String> = url_form(&body);
                    assert_eq!(form["client_secret"], "shh");
                    assert!(!form["code_verifier"].is_empty());
                    let claims = serde_json::json!({
                        "iss": iss, "aud": "rmail", "exp": chrono::Utc::now().timestamp() + 300,
                        "nonce": form["code"], "email": email, "email_verified": true,
                    });
                    let token = format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(claims.to_string()));
                    axum::Json(serde_json::json!({ "id_token": token, "access_token": "a" }))
                }),
            );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        issuer
    }

    fn url_form(body: &str) -> std::collections::HashMap<String, String> {
        body.split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(k, v)| {
                let decode = |text: &str| {
                    let text = text.replace('+', " ");
                    let mut out = Vec::new();
                    let bytes = text.as_bytes();
                    let mut i = 0;
                    while i < bytes.len() {
                        if bytes[i] == b'%' && i + 2 < bytes.len() {
                            out.push(u8::from_str_radix(&text[i + 1..i + 3], 16).unwrap());
                            i += 3;
                        } else {
                            out.push(bytes[i]);
                            i += 1;
                        }
                    }
                    String::from_utf8(out).unwrap()
                };
                (decode(k), decode(v))
            })
            .collect()
    }

    fn cookie(response: &TestResponse, name: &str) -> Option<String> {
        response
            .headers
            .iter()
            .filter(|(key, _)| key == "Set-Cookie")
            .find_map(|(_, value)| {
                let pair = value.split(';').next()?;
                let (key, value) = pair.split_once('=')?;
                (key == name && !value.is_empty()).then(|| pair.to_string())
            })
    }

    fn query(location: &str, key: &str) -> String {
        url_form(location.split_once('?').unwrap().1)[key].clone()
    }

    async fn configure(state: &std::sync::Arc<crate::api::AppState>, issuer: &str) {
        let mut settings = rmail_common::settings::open(&state.db_path).unwrap();
        rmail_common::settings::write_raw(
            &mut settings,
            &[
                ("oidc.enabled", serde_json::json!(true)),
                ("oidc.issuer", serde_json::json!(issuer)),
                ("oidc.client_id", serde_json::json!("rmail")),
                ("oidc.client_secret", serde_json::json!("shh")),
                (
                    "oidc.button_label",
                    serde_json::json!("Sign in with Example"),
                ),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), Some(v)))
            .collect(),
        )
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_provider_signs_users_in_to_their_mailbox() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        let offered = route(req("GET", "/api/oidc", b"", None), &state).await;
        let offered: Value = serde_json::from_slice(&offered.body).unwrap();
        assert_eq!(offered["enabled"], false, "off until set up");

        configure(&state, &provider("user@example.test").await).await;
        let offered = route(req("GET", "/api/oidc", b"", None), &state).await;
        let offered: Value = serde_json::from_slice(&offered.body).unwrap();
        assert_eq!(
            (offered["enabled"].as_bool(), offered["label"].as_str()),
            (Some(true), Some("Sign in with Example"))
        );

        let start = route(req("GET", "/api/oidc/start", b"", None), &state).await;
        assert_eq!(start.status, 303);
        let location = start.header("Location").to_string();
        assert!(
            location.contains("/auth?response_type=code&client_id=rmail"),
            "{location}"
        );
        let flow = cookie(&start, "rmail_oidc").expect("flow cookie");
        let (flow_state, nonce) = (query(&location, "state"), query(&location, "nonce"));

        // A state that is not this sign-in's is refused.
        let forged = route(
            req(
                "GET",
                &format!("/api/oidc/callback?code={nonce}&state=other"),
                b"",
                Some(flow.clone()),
            ),
            &state,
        )
        .await;
        assert_eq!(forged.header("Location"), "/?sso_error=expired");
        assert!(cookie(&forged, "rmail_webmail").is_none());

        let back = route(
            req(
                "GET",
                &format!("/api/oidc/callback?code={nonce}&state={flow_state}"),
                b"",
                Some(flow.clone()),
            ),
            &state,
        )
        .await;
        assert_eq!((back.status, back.header("Location")), (303, "/"));
        let session = cookie(&back, "rmail_webmail").expect("signed in");
        let me = route(req("GET", "/api/session", b"", Some(session)), &state).await;
        assert_eq!(me.status, 200);
        let me: Value = serde_json::from_slice(&me.body).unwrap();
        assert_eq!(me["address"], "user@example.test");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn only_existing_mailboxes_sign_in() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        configure(&state, &provider("stranger@example.test").await).await;
        let start = route(req("GET", "/api/oidc/start", b"", None), &state).await;
        let location = start.header("Location").to_string();
        let flow = cookie(&start, "rmail_oidc").unwrap();
        let back = route(
            req(
                "GET",
                &format!(
                    "/api/oidc/callback?code={}&state={}",
                    query(&location, "nonce"),
                    query(&location, "state")
                ),
                b"",
                Some(flow),
            ),
            &state,
        )
        .await;
        assert_eq!(back.header("Location"), "/?sso_error=no_mailbox");
        assert!(cookie(&back, "rmail_webmail").is_none());
    }
}
