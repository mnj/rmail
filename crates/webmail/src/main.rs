//! rmail_webmail: browser webmail for rMail accounts.
//!
//! - `api` is the HTTP API (axum) with signed-cookie sessions.
//! - `assets` serves the single-page app.

use std::{env, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use base64::Engine;
use rmail_common::{
    config::Config, http::serve_connection, net::bind_tcp_listener_with_config,
    runtime::GracefulShutdown, throttle::AuthThrottle, websession,
};
use tokio::task::JoinSet;

macro_rules! webmail_log {
    ($level:expr, $event:expr, $fields:tt) => {
        rmail_common::structured_log!($level, "webmail", $event, $fields)
    };
}

mod api;
mod assets;

#[tokio::main]
async fn main() -> Result<()> {
    let cfg_path = env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let cfg = Config::load(&cfg_path).with_context(|| format!("loading {cfg_path}"))?;
    rmail_common::runtime::set_log_level(cfg.global.log_level.as_deref());
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
    let state = Arc::new(api::AppState {
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
    let app = api::router(state);
    let listener_config = cfg.global.tcp_listener.clone();
    let shutdown = GracefulShutdown::new();
    let mut listeners = JoinSet::new();
    for addr in bind_addrs {
        let listener = bind_tcp_listener_with_config(&addr, &listener_config)?;
        webmail_log!("info", "listener_started", { "address": addr, "tls_configured": tls.1.borrow().is_some() });
        let app = app.clone();
        let listener_shutdown = shutdown.clone();
        let tls = tls.1.clone();
        listeners.spawn(async move {
            let mut shutdown_signal = listener_shutdown.subscribe();
            loop {
                if *shutdown_signal.borrow() {
                    break;
                }
                let (stream, peer) = tokio::select! {
                    _ = shutdown_signal.changed() => break,
                    accepted = listener.accept() => match accepted {
                        Ok(accepted) => accepted,
                        Err(err) => {
                            webmail_log!("error", "listener_accept_failed", { "address": addr, "error": err.to_string() });
                            break;
                        }
                    },
                };
                let app = app.clone();
                let tls_context = tls.borrow().clone();
                let session = listener_shutdown.start_session();
                let stop = listener_shutdown.subscribe();
                tokio::spawn(async move {
                    let _session = session;
                    let served = match tls_context {
                        Some(context) => {
                            match tokio::time::timeout(Duration::from_secs(15), context.acceptor.accept(stream)).await {
                                Ok(Ok(stream)) => serve_connection(stream, Some(peer), app, Some(stop)).await,
                                Ok(Err(error)) => {
                                    webmail_log!("error", "tls_handshake_failed", { "peer": peer.to_string(), "error": error.to_string() });
                                    return;
                                }
                                Err(_) => {
                                    webmail_log!("warn", "tls_handshake_timeout", { "peer": peer.to_string() });
                                    return;
                                }
                            }
                        }
                        None => serve_connection(stream, Some(peer), app, Some(stop)).await,
                    };
                    if let Err(error) = served {
                        webmail_log!("debug", "connection_error", { "peer": peer.to_string(), "error": error.to_string() });
                    }
                });
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
