//! Automatic certificates: status and "issue now" for the admin console,
//! the background renewal task, http-01 challenge responses and the
//! plain-HTTP listener that redirects everything else to HTTPS.

use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path as UrlPath, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rmail_common::acme::{self, AcmeStatus, CertificateInfo, RenewalCheck, RunOptions};
use rmail_common::config::{AcmeChallenge, Config};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{ApiError, Shared, blocking, error, parse};

/// How often the renewal task looks at the installed certificate.
const RENEWAL_INTERVAL: Duration = Duration::from_secs(3600);
/// Give the other services time to start before the first check.
const RENEWAL_FIRST_CHECK: Duration = Duration::from_secs(60);

pub(crate) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/certificates", get(overview))
        .route("/api/certificates/issue", post(issue))
}

async fn current_config(state: &Shared) -> Result<Config, ApiError> {
    let Some(path) = state.config_path.clone() else {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "the configuration file path is unknown".into(),
        ));
    };
    blocking(move || rmail_common::config::Config::load(&path))
        .await
        .map_err(|err| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{err:#}")))
}

#[derive(Serialize)]
struct Overview {
    managed: bool,
    enabled: bool,
    names: Vec<String>,
    names_error: Option<String>,
    challenge: AcmeChallenge,
    directory: Option<String>,
    cert_path: String,
    key_path: String,
    certificate: Option<CertificateInfo>,
    certificate_error: Option<String>,
    renewal: Option<RenewalCheck>,
    running: bool,
    status: AcmeStatus,
    http_listeners: Vec<String>,
    warnings: Vec<String>,
}

fn build_overview(config: &Config) -> anyhow::Result<Overview> {
    let db_path = config.global.db_path.clone();
    let status = match &db_path {
        Some(db) => acme::load_status(db)?,
        None => AcmeStatus::default(),
    };
    let (cert_path, key_path, unset) = acme::certificate_paths(config);
    let tls_configured = !unset;
    let (certificate, certificate_error) = if tls_configured || cert_path.exists() {
        match acme::cert::inspect_file(&cert_path) {
            Ok(info) => (Some(info), None),
            Err(err) => (None, Some(format!("{err:#}"))),
        }
    } else {
        (None, None)
    };
    let (names, names_error) = match acme::certificate_names(config) {
        Ok(names) => (names, None),
        Err(err) => (Vec::new(), Some(format!("{err:#}"))),
    };
    let enabled = config.acme.enabled;
    let http_listeners = config.global.http_listeners();
    let mut warnings = Vec::new();
    if enabled && config.acme.challenge == AcmeChallenge::Http01 && http_listeners.is_empty() {
        warnings.push(
            "The http-01 challenge needs port 80. Add a Plain HTTP listener (Settings → Listeners, for example [::]:80), or have the web server on port 80 forward /.well-known/acme-challenge/ to the admin listener.".to_string(),
        );
    }
    if enabled && unset {
        warnings.push(format!(
            "No TLS certificate is configured yet. The first certificate is written to {} and the services need one restart to enable TLS; renewals after that are picked up automatically.",
            cert_path.parent().map(|p| p.display().to_string()).unwrap_or_default()
        ));
    }
    if enabled && config.acme.domains.is_empty() && config.global.hostname.is_none() {
        warnings.push(format!(
            "No certificate names are set, so the system hostname {} is used.",
            config.global.server_hostname()
        ));
    }
    Ok(Overview {
        managed: db_path.is_some(),
        enabled,
        names,
        names_error,
        challenge: config.acme.challenge,
        directory: acme::directory_url(&config.acme).ok(),
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        certificate,
        certificate_error,
        renewal: enabled.then(|| acme::renewal_check(config, &status)),
        running: acme::run_in_progress(config),
        status,
        http_listeners,
        warnings,
    })
}

async fn overview(State(state): State<Shared>) -> Response {
    let config = match current_config(&state).await {
        Ok(config) => config,
        Err(err) => return err.into_response(),
    };
    match blocking(move || build_overview(&config)).await {
        Ok(view) => Json(view).into_response(),
        Err(err) => error(StatusCode::INTERNAL_SERVER_ERROR, format!("{err:#}")),
    }
}

#[derive(Deserialize, Default)]
struct IssueRequest {
    #[serde(default)]
    dry_run: bool,
}

async fn issue(State(state): State<Shared>, body: Bytes) -> Response {
    let input: IssueRequest = if body.is_empty() {
        IssueRequest::default()
    } else {
        match parse(&body) {
            Ok(input) => input,
            Err(err) => return err.into_response(),
        }
    };
    let config = match current_config(&state).await {
        Ok(config) => config,
        Err(err) => return err.into_response(),
    };
    if config.global.db_path.is_none() {
        return error(
            StatusCode::BAD_REQUEST,
            "automatic certificates need the settings database (global.db_path)",
        );
    }
    if !input.dry_run && !config.acme.enabled {
        return error(
            StatusCode::CONFLICT,
            "turn on automatic certificates first, or run a test",
        );
    }
    if acme::run_in_progress(&config) {
        return error(
            StatusCode::CONFLICT,
            "a certificate request is already running",
        );
    }
    web_log!("info", "acme_run_requested", { "dry_run": input.dry_run });
    tokio::spawn(async move {
        let _ = acme::run(
            &config,
            RunOptions {
                trigger: "manual".into(),
                dry_run: input.dry_run,
                echo: false,
            },
        )
        .await;
    });
    (StatusCode::ACCEPTED, Json(json!({"started": true}))).into_response()
}

/// Renew the certificate whenever it becomes due. Settings are re-read on
/// every pass, so enabling ACME or changing names needs no restart.
pub(crate) fn spawn_renewal_task(config_path: String) {
    tokio::spawn(async move {
        tokio::time::sleep(RENEWAL_FIRST_CHECK).await;
        loop {
            let path = config_path.clone();
            match tokio::task::spawn_blocking(move || Config::load(&path)).await {
                Ok(Ok(config)) => {
                    if let Err(err) = acme::renew_if_due(&config, "renewal").await {
                        web_log!("warn", "acme_renewal_failed", { "error": format!("{err:#}") });
                    }
                }
                Ok(Err(err)) => {
                    web_log!("warn", "acme_renewal_config_failed", { "error": format!("{err:#}") })
                }
                Err(err) => {
                    web_log!("warn", "acme_renewal_config_failed", { "error": err.to_string() })
                }
            }
            tokio::time::sleep(RENEWAL_INTERVAL).await;
        }
    });
}

// ---------------------------------------------------------------------------
// http-01 challenge responses

fn is_acme_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 256
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// ACME http-01 challenges for runs started by any rMail process. Tokens are
/// a single URL-safe segment and only answered while a run waits for them.
pub(crate) async fn challenge(
    State(state): State<Shared>,
    UrlPath(token): UrlPath<String>,
) -> Response {
    let not_found = || (StatusCode::NOT_FOUND, "Not Found").into_response();
    let (Some(db), true) = (state.db_path.clone(), is_acme_token(&token)) else {
        return not_found();
    };
    match blocking(move || acme::challenge_response(&db, &token)).await {
        Ok(Some(body)) => ([(header::CONTENT_TYPE, "text/plain")], body).into_response(),
        Ok(None) => not_found(),
        Err(err) => {
            web_log!("warn", "acme_challenge_lookup_failed", { "error": format!("{err:#}") });
            not_found()
        }
    }
}

// ---------------------------------------------------------------------------
// Plain-HTTP listener

/// Router for `global.listeners.http`: ACME challenges, and a permanent
/// redirect to HTTPS for everything else.
pub(crate) fn http_router(state: Shared) -> Router {
    let app = Router::new()
        .route("/.well-known/acme-challenge/{*token}", get(challenge))
        .fallback(redirect_to_https)
        .with_state(state);
    rmail_common::http::harden(app, 16 * 1024)
}

/// The request's host without port, when it is a plausible host name or
/// bracketed IPv6 literal (never anything that could alter the URL).
fn request_host(value: &str) -> Option<&str> {
    let host = if value.starts_with('[') {
        &value[..=value.find(']')?]
    } else {
        value.rsplit_once(':').map_or(value, |(host, _)| host)
    };
    let valid = !host.is_empty()
        && host.len() <= 255
        && host.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'[' | b']' | b':')
        });
    valid.then_some(host)
}

async fn redirect_to_https(State(state): State<Shared>, request: Request) -> Response {
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let target = match state.http_redirect_url.as_deref() {
        Some(base) => format!("{}{path}", base.trim_end_matches('/')),
        None => {
            let Some(host) = request
                .headers()
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .and_then(request_host)
            else {
                return (StatusCode::BAD_REQUEST, "Bad Request").into_response();
            };
            format!("https://{host}{path}")
        }
    };
    let Ok(location) = HeaderValue::from_str(&target) else {
        return (StatusCode::BAD_REQUEST, "Bad Request").into_response();
    };
    let status = if matches!(*request.method(), Method::GET | Method::HEAD) {
        StatusCode::MOVED_PERMANENTLY
    } else {
        StatusCode::PERMANENT_REDIRECT
    };
    (status, [(header::LOCATION, location)]).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_are_sanitized_before_redirecting() {
        assert_eq!(request_host("mail.example.com"), Some("mail.example.com"));
        assert_eq!(
            request_host("mail.example.com:80"),
            Some("mail.example.com")
        );
        assert_eq!(request_host("[2001:db8::1]:80"), Some("[2001:db8::1]"));
        assert_eq!(request_host("evil.com/@x"), None);
        assert_eq!(request_host(""), None);
    }
}
