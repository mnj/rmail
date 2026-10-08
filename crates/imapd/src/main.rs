//! rmail_imapd: IMAP4rev1/IMAP4rev2 server over Maildir storage.
//!
//! - `listener` accepts connections (IMAP with STARTTLS, and IMAPS).
//! - `session` runs one connection: reads commands and dispatches them.
//! - `commands` implements individual IMAP commands; `parser`, `response`,
//!   `mailbox`, `sort`, `thread` and `transport` support them.

#![allow(clippy::too_many_arguments, clippy::type_complexity)]

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use rmail_common::config::Config;
use rmail_common::net::{TcpListenerConfig, bind_tcp_listener_with_config};
use rmail_common::runtime::GracefulShutdown;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

macro_rules! imap_log {
    ($level:expr, $event:expr, $fields:tt) => {
        rmail_common::structured_log!($level, "imapd", $event, $fields)
    };
}

mod auth;
mod commands;
mod input;
mod listener;
mod mailbox;
mod managesieve;
mod parser;
mod pop3;
mod response;
mod session;
mod sort;
mod state;
#[cfg(test)]
mod tests;
mod thread;
mod tls;
mod transport;

use listener::{ListenerContext, run_listener};

// Shared with the command modules.
pub(crate) use input::{BoundedLine, read_bounded_line};
pub(crate) use session::sync_selected_mailbox;
pub(crate) use transport::{AsyncStream, RawStream};

// Internals exercised directly by the tests.
#[cfg(test)]
use {
    base64::engine::general_purpose::STANDARD as BASE64_ENGINE,
    listener::{CONNECTION_ATTEMPTS, accept_connection_from},
    mailbox::selected_mailbox_for_log,
    session::{
        logged_command_args, process_stream, process_stream_inner, process_stream_with_policy,
    },
};
#[cfg(test)]
fn parse_scram_attr<'a>(message: &'a str, key: &str) -> Option<&'a str> {
    auth::parse_scram_attr(message, key)
}

pub(crate) const MAX_APPEND_LITERAL_BYTES: usize = 100 * 1024 * 1024;
pub(crate) const MAX_PREAUTH_LINE_BYTES: usize = 8 * 1024;
pub(crate) const MAX_AUTHENTICATED_LINE_BYTES: usize = 64 * 1024;
pub(crate) const MAX_SASL_RESPONSE_BYTES: usize = 64 * 1024;

#[tokio::main]
async fn main() -> Result<()> {
    let cfg_path =
        std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let cfg = Config::load(&cfg_path).context(format!("loading {}", cfg_path))?;
    rmail_common::runtime::set_log_level(cfg.global.log_level.as_deref());
    rmail_common::proxy::set_trusted_networks(&cfg.security.proxy_protocol_trusted_networks)
        .context("security.proxy_protocol_trusted_networks")?;
    if let Err(error) = rmail_common::settings::record_service_start(&cfg, "imapd") {
        rmail_common::structured_log!("warn", "imapd", "service_state_failed", { "error": format!("{error:#}") });
    }
    let auth_policy = Arc::new(
        auth::AuthPolicy::from_security(&cfg.security)
            .context("validating security.imap_sasl_mechanisms")?,
    );
    let mail_root = cfg.global.mail_root.clone();
    rmail_common::runtime::redirect_stdio_to_log(std::path::Path::new(&mail_root), "imapd")
        .context("redirecting logs")?;
    let _metrics_task = rmail_common::metrics::spawn_prometheus_snapshot_task(
        std::path::Path::new(&mail_root),
        "imapd",
    )?;

    // SQLite DB is the authoritative source for mailboxes/catchalls
    let db_path = cfg.global.db_path.clone();
    let shutdown = GracefulShutdown::new();
    let session_limit = Arc::new(Semaphore::new(
        cfg.security.imap_max_concurrent_sessions.max(1),
    ));
    let connection_rate_limit = cfg.security.imap_max_connections_per_minute.max(1);
    let mut listeners = JoinSet::new();
    if db_path.is_none() {
        imap_log!("error", "configuration_invalid", { "field": "global.db_path" });
        std::process::exit(1);
    }

    // TLS context if certs present
    let tls_context = match (&cfg.global.tls_cert, &cfg.global.tls_key) {
        (Some(cert), Some(key)) => Some(
            tls::load_tls_context_with_policy(cert, key, &cfg.global.tls)
                .context("loading IMAP TLS certificate and policy")?,
        ),
        (None, None) => None,
        _ => anyhow::bail!("global.tls_cert and global.tls_key must be configured together"),
    };
    let (tls_sender, tls_receiver) = tokio::sync::watch::channel(tls_context.clone());
    #[cfg(unix)]
    let _tls_reload_task = if let (Some(cert), Some(key)) =
        (cfg.global.tls_cert.clone(), cfg.global.tls_key.clone())
    {
        Some(listener::spawn_tls_reloader(
            tls_sender,
            cert,
            key,
            cfg.global.tls.clone(),
        )?)
    } else {
        None
    };

    let pop3_context = db_path.clone().map(|db_path| pop3::Pop3Context {
        mail_root: mail_root.clone(),
        db_path,
        tls: tls_receiver.clone(),
        session_limit: session_limit.clone(),
        connection_rate_limit,
        implicit_tls: false,
        shutdown: shutdown.clone(),
    });
    let managesieve_context = db_path
        .clone()
        .map(|db_path| managesieve::ManageSieveContext {
            db_path,
            tls: tls_receiver.clone(),
            session_limit: session_limit.clone(),
            connection_rate_limit,
            shutdown: shutdown.clone(),
        });
    let template = ListenerContext {
        mail_root,
        tls: tls_receiver,
        db_path,
        auth_policy,
        session_limit,
        connection_rate_limit,
        implicit_tls: false,
        shutdown: shutdown.clone(),
    };
    let tcp = cfg.global.tcp_listener.clone();
    // Plain IMAP (STARTTLS when a certificate is configured).
    let mut listener_count = spawn_listeners(
        &mut listeners,
        cfg.global.imap_listeners(),
        &tcp,
        template.clone(),
    )?;
    // IMAPS (implicit TLS).
    let imaps = cfg.global.imaps_listeners();
    if tls_context.is_some() {
        listener_count += spawn_listeners(
            &mut listeners,
            imaps,
            &tcp,
            ListenerContext {
                implicit_tls: true,
                ..template
            },
        )?;
    } else if !imaps.is_empty() {
        imap_log!("warn", "implicit_tls_listener_disabled", { "reason": "TLS certificate or key unavailable" });
    }

    // POP3 (STLS) and POP3S (implicit TLS).
    if let Some(context) = pop3_context {
        for (addrs, implicit_tls) in [
            (cfg.global.pop3_listeners(), false),
            (cfg.global.pop3s_listeners(), true),
        ] {
            if implicit_tls && tls_context.is_none() && !addrs.is_empty() {
                imap_log!("warn", "implicit_tls_listener_disabled", { "reason": "TLS certificate or key unavailable" });
                continue;
            }
            for addr in addrs {
                let listener = bind_tcp_listener_with_config(&addr, &tcp)
                    .with_context(|| format!("starting POP3 listener on {addr}"))?;
                let context = pop3::Pop3Context {
                    implicit_tls,
                    ..context.clone()
                };
                listeners.spawn(async move {
                    if let Err(error) = pop3::run_listener(addr, listener, context).await {
                        imap_log!("error", "pop3_listener_failed", { "error": error.to_string() });
                    }
                });
                listener_count += 1;
            }
        }
    }

    // ManageSieve (STARTTLS); plain-text login is only offered once TLS is active.
    if let Some(context) = managesieve_context {
        for addr in cfg.global.managesieve_listeners() {
            let listener = bind_tcp_listener_with_config(&addr, &tcp)
                .with_context(|| format!("starting ManageSieve listener on {addr}"))?;
            let context = context.clone();
            listeners.spawn(async move {
                if let Err(error) = managesieve::run_listener(addr, listener, context).await {
                    imap_log!("error", "managesieve_listener_failed", { "error": error.to_string() });
                }
            });
            listener_count += 1;
        }
    }

    if listener_count == 0 {
        return Err(anyhow!("no IMAP listeners were started"));
    }

    rmail_common::runtime::wait_for_shutdown_signal().await?;
    imap_log!("info", "shutdown_requested", { "active_sessions": shutdown.active_sessions() });
    shutdown.request();
    while let Some(result) = listeners.join_next().await {
        if let Err(error) = result {
            imap_log!("error", "shutdown_listener_join_failed", { "error": error.to_string() });
        }
    }
    if !shutdown.wait_for_sessions(Duration::from_secs(30)).await {
        imap_log!("warn", "shutdown_drain_timed_out", { "active_sessions": shutdown.active_sessions() });
    }
    Ok(())
}

fn spawn_listeners(
    listeners: &mut JoinSet<()>,
    addrs: Vec<String>,
    tcp: &TcpListenerConfig,
    ctx: ListenerContext,
) -> Result<usize> {
    let label = if ctx.implicit_tls { "IMAPS" } else { "IMAP" };
    let count = addrs.len();
    for addr in addrs {
        let listener = bind_tcp_listener_with_config(&addr, tcp)
            .with_context(|| format!("starting {label} listener on {addr}"))?;
        let ctx = ctx.clone();
        listeners.spawn(async move {
            let tls = ctx.implicit_tls;
            if let Err(error) = run_listener(addr, listener, ctx).await {
                imap_log!("error", "listener_failed", { "tls": tls, "error": error.to_string() });
            }
        });
    }
    Ok(count)
}
