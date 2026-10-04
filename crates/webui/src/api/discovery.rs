//! Public client auto-configuration and MTA-STS policy endpoints, plus the
//! admin view of the DNS records to publish for each hosted domain.
//!
//! The public routes answer only for domains that have mailboxes or a
//! catchall here, and expose nothing beyond what DNS and the listeners
//! already reveal.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware;
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

fn autoconfig_inner() -> Router<Shared> {
    Router::new()
        .route("/mail/config-v1.1.xml", get(thunderbird))
        .route(
            "/.well-known/autoconfig/mail/config-v1.1.xml",
            get(thunderbird),
        )
        .route("/autodiscover/autodiscover.xml", get(outlook).post(outlook))
        .route("/Autodiscover/Autodiscover.xml", get(outlook).post(outlook))
}

/// Responses vary by domain and requested address, so they must not be
/// cached; requests are logged like the rest of the admin API. The CSRF layer
/// is deliberately absent: Outlook's POST carries no custom header and
/// nothing here changes state.
fn public_layers(router: Router<Shared>) -> Router<Shared> {
    router
        .layer(middleware::from_fn(super::security_headers))
        .layer(middleware::from_fn(super::log_request))
}

/// Autoconfig routes, safe to serve over plain HTTP as well.
pub(crate) fn autoconfig_routes() -> Router<Shared> {
    public_layers(autoconfig_inner())
}

/// All public discovery routes; MTA-STS is HTTPS-only by specification, so
/// this is for the TLS listeners.
pub(crate) fn public_routes() -> Router<Shared> {
    public_layers(autoconfig_inner().route("/.well-known/mta-sts.txt", get(mta_sts)))
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

/// How long a loaded configuration is reused by the public endpoints, so
/// anonymous requests cannot force a file read and parse each time.
const CONFIG_TTL: Duration = Duration::from_secs(10);

/// Most distinct configuration paths cached at once (normally one).
const CONFIG_CACHE_ENTRIES: usize = 8;

type ConfigCache = HashMap<String, (Instant, Arc<Config>)>;

fn cached_config(path: &str) -> anyhow::Result<Arc<Config>> {
    static CACHE: Mutex<Option<ConfigCache>> = Mutex::new(None);
    // Held across the load on purpose: concurrent misses share one read.
    let mut guard = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let cache = guard.get_or_insert_with(HashMap::new);
    if let Some((loaded, config)) = cache.get(path)
        && loaded.elapsed() < CONFIG_TTL
    {
        return Ok(config.clone());
    }
    let config = Arc::new(Config::load(path)?);
    cache.retain(|_, (loaded, _)| loaded.elapsed() < CONFIG_TTL);
    if cache.len() >= CONFIG_CACHE_ENTRIES {
        cache.clear();
    }
    cache.insert(path.to_string(), (Instant::now(), config.clone()));
    Ok(config)
}

/// Confirm `domain` is hosted here, then load the configuration. Unknown
/// names are rejected before any configuration is read.
async fn hosted(state: &Shared, domain: &str) -> Option<Arc<Config>> {
    if !is_domain_name(domain) {
        return None;
    }
    let (path, db) = (state.config_path.clone()?, state.db_path.clone()?);
    let domain = domain.to_ascii_lowercase();
    blocking(move || {
        if !rmail_common::db::is_local_domain(&db, &domain)? {
            return Ok(None);
        }
        Ok(Some(cached_config(&path)?))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn config_file(dir: &std::path::Path, name: &str, hostname: &str) -> String {
        let path = dir.join(name);
        std::fs::write(
            &path,
            format!(
                "[global]\nmail_root = \"{}\"\nhostname = \"{hostname}\"\n",
                dir.display()
            ),
        )
        .unwrap();
        path.display().to_string()
    }

    #[test]
    fn config_is_cached_briefly_and_per_path() {
        let td = tempfile::tempdir().unwrap();
        let a = config_file(td.path(), "a.toml", "a.example.com");
        let first = cached_config(&a).unwrap();
        // Rewriting the file is not seen until the cache expires: no re-read.
        config_file(td.path(), "a.toml", "changed.example.com");
        let second = cached_config(&a).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(second.global.server_hostname(), "a.example.com");
        // A different path is loaded on its own.
        let b = config_file(td.path(), "b.toml", "b.example.com");
        assert_eq!(
            cached_config(&b).unwrap().global.server_hostname(),
            "b.example.com"
        );
        // Errors are reported, not cached.
        assert!(cached_config(&td.path().join("missing.toml").display().to_string()).is_err());
    }
}
