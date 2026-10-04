//! Public client auto-configuration and MTA-STS policy endpoints, plus the
//! admin view of the DNS records to publish for each hosted domain.
//!
//! The public routes answer only for domains that have mailboxes or a
//! catchall here, and expose nothing beyond what DNS and the listeners
//! already reveal.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use rmail_common::config::Config;
use rmail_common::discovery::{self, ServiceEndpoints};
use serde_json::json;

use super::{Shared, blocking, error, require_db};

const MAX_AUTODISCOVER_BODY: usize = 8 * 1024;

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "Not Found").into_response()
}

/// Autoconfig routes, safe to serve over plain HTTP as well.
pub(crate) fn autoconfig_routes() -> Router<Shared> {
    Router::new()
        .route("/mail/config-v1.1.xml", get(thunderbird))
        .route(
            "/.well-known/autoconfig/mail/config-v1.1.xml",
            get(thunderbird),
        )
        .route("/autodiscover/autodiscover.xml", get(outlook).post(outlook))
        .route("/Autodiscover/Autodiscover.xml", get(outlook).post(outlook))
}

/// All public discovery routes; MTA-STS is HTTPS-only by specification, so
/// this is for the TLS listeners.
pub(crate) fn public_routes() -> Router<Shared> {
    autoconfig_routes().route("/.well-known/mta-sts.txt", get(mta_sts))
}

pub(crate) fn protected_routes() -> Router<Shared> {
    Router::new().route("/api/discovery", get(records))
}

fn host_header(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::HOST)?.to_str().ok()
}

fn is_domain_name(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.contains('.')
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// Load the configuration and confirm `domain` is hosted here.
async fn hosted(state: &Shared, domain: &str) -> Option<Config> {
    if !is_domain_name(domain) {
        return None;
    }
    let (path, db) = (state.config_path.clone()?, state.db_path.clone()?);
    let domain = domain.to_ascii_lowercase();
    blocking(move || {
        let config = Config::load(&path)?;
        Ok(rmail_common::db::is_local_domain(&db, &domain)?.then_some(config))
    })
    .await
    .ok()
    .flatten()
}

async fn mta_sts(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let Some(domain) =
        host_header(&headers).and_then(|host| discovery::domain_from_host(host, "mta-sts"))
    else {
        return not_found();
    };
    let Some(config) = hosted(&state, &domain).await else {
        return not_found();
    };
    match discovery::mta_sts_policy(
        config.security.mta_sts_mode,
        &config.global.server_hostname(),
        config.security.mta_sts_max_age_secs,
    ) {
        Some(policy) => (
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            policy,
        )
            .into_response(),
        None => not_found(),
    }
}

async fn thunderbird(
    State(state): State<Shared>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let domain = query
        .get("emailaddress")
        .and_then(|email| email.rsplit_once('@').map(|(_, domain)| domain.to_string()))
        .or_else(|| {
            host_header(&headers).and_then(|host| discovery::domain_from_host(host, "autoconfig"))
        });
    let Some(domain) = domain.map(|domain| domain.to_ascii_lowercase()) else {
        return not_found();
    };
    let Some(config) = hosted(&state, &domain).await else {
        return not_found();
    };
    let xml =
        discovery::thunderbird_config(&domain, &ServiceEndpoints::from_global(&config.global));
    (
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        xml,
    )
        .into_response()
}

async fn outlook(State(state): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    if body.len() > MAX_AUTODISCOVER_BODY {
        return (StatusCode::PAYLOAD_TOO_LARGE, "Payload Too Large").into_response();
    }
    let email = discovery::autodiscover_request_email(&String::from_utf8_lossy(&body));
    let domain = email
        .as_deref()
        .and_then(|email| email.rsplit_once('@').map(|(_, domain)| domain.to_string()))
        .or_else(|| {
            host_header(&headers).and_then(|host| discovery::domain_from_host(host, "autodiscover"))
        });
    let Some(domain) = domain.map(|domain| domain.to_ascii_lowercase()) else {
        return not_found();
    };
    let Some(config) = hosted(&state, &domain).await else {
        return not_found();
    };
    let email = email.unwrap_or_else(|| format!("user@{domain}"));
    let xml =
        discovery::outlook_autodiscover(&email, &ServiceEndpoints::from_global(&config.global));
    ([(header::CONTENT_TYPE, "text/xml; charset=utf-8")], xml).into_response()
}

/// DNS records to publish, per hosted domain.
async fn records(State(state): State<Shared>) -> Response {
    let db = match require_db(&state) {
        Ok(db) => db,
        Err(err) => return err.into_response(),
    };
    let Some(path) = state.config_path.clone() else {
        return error(StatusCode::BAD_REQUEST, "no configuration file is loaded");
    };
    let result = blocking(move || {
        let config = Config::load(&path)?;
        let endpoints = ServiceEndpoints::from_global(&config.global);
        let domains = rmail_common::db::local_domains(&db)?;
        let per_domain = domains
            .into_iter()
            .map(|domain| {
                let records = discovery::dns_records(
                    &domain,
                    &endpoints,
                    config.security.mta_sts_mode,
                    config.security.mta_sts_max_age_secs,
                    &format!("postmaster@{domain}"),
                );
                json!({ "domain": domain, "records": records })
            })
            .collect::<Vec<_>>();
        Ok(json!({ "hostname": endpoints.hostname, "domains": per_domain }))
    })
    .await;
    match result {
        Ok(value) => Json(value).into_response(),
        Err(err) => error(StatusCode::INTERNAL_SERVER_ERROR, format!("{err:#}")),
    }
}
