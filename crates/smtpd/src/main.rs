//! rmail_smtpd: inbound SMTP (MX), message submission, SMTPS and LMTP.
//!
//! - `listener` accepts connections and applies connection limits.
//! - `session` runs one SMTP conversation: command dispatch, recipient
//!   resolution, message intake and delivery.
//! - `data`, `dsn`, `limits` and `trace` hold the supporting pieces.

#![allow(clippy::too_many_arguments)]

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rmail_common::config::Config;
use rmail_common::net::{TcpListenerConfig, bind_tcp_listener_with_config};
use rmail_common::runtime::GracefulShutdown;
use rmail_common::tracking::TrackingHub;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

macro_rules! smtp_log {
    ($level:expr, $event:expr, $fields:tt) => {
        rmail_common::structured_log!($level, "smtpd", $event, $fields)
    };
}

mod authenticate;
mod data;
mod dsn;
mod limits;
mod listener;
mod protocol;
mod session;
#[cfg(test)]
mod tests;
mod tls;
mod trace;

use listener::{ListenerContext, run_listener};
use trace::TRACKING_HUB;

// Re-exported for the authentication handlers and the tests.
pub(crate) use limits::{record_auth_failure, reset_auth_failures};
#[cfg(test)]
use {
    data::received_header,
    limits::{accept_connection_from, record_submission_message, submission_quota_available},
    session::{is_forwarded_recipient, parse_mail_from_arg, process_stream},
    trace::{ConnectionTrace, ReplyTraceState, ReplyTrackingStream, TRACKING_TEST_EVENTS},
};

/// Combined read/write stream that can be boxed (plain TCP or TLS).
pub(crate) trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized> AsyncStream for T {}

pub(crate) const MAX_MESSAGE_BYTES: usize = 10 * 1024 * 1024;
pub(crate) const MAX_DATA_LINE_BYTES: usize = 1000;
pub(crate) const COMMAND_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub(crate) const AUTH_CONTINUATION_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const DATA_READ_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub(crate) const STARTTLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// This server's SMTP identity (`global.hostname` or the system hostname).
static SERVER_HOSTNAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Domain announced in greetings, EHLO/HELO replies and Received headers.
pub(crate) fn server_hostname() -> &'static str {
    SERVER_HOSTNAME.get_or_init(rmail_common::config::system_hostname)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SmtpService {
    Mta,
    Submission,
    Lmtp,
}

impl SmtpService {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Mta => "smtp",
            Self::Submission => "submission",
            Self::Lmtp => "lmtp",
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg_path =
        std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let cfg = Config::load(&cfg_path).context(format!("loading {}", cfg_path))?;
    rmail_common::runtime::set_log_level(cfg.global.log_level.as_deref());
    rmail_common::proxy::set_trusted_networks(&cfg.security.proxy_protocol_trusted_networks)
        .context("security.proxy_protocol_trusted_networks")?;
    let _ = SERVER_HOSTNAME.set(cfg.global.server_hostname());
    rmail_common::dkim::use_database(&cfg.global.db_path);
    if let Err(error) = rmail_common::settings::record_service_start(&cfg, "smtpd") {
        smtp_log!("warn", "service_state_failed", { "error": format!("{error:#}") });
    }

    let mail_root = cfg.global.mail_root.clone();
    rmail_common::runtime::redirect_stdio_to_log(std::path::Path::new(&mail_root), "smtpd")
        .context("redirecting logs")?;
    let tracking = Arc::new(
        TrackingHub::start_with_config(
            std::path::Path::new(&mail_root),
            "smtpd",
            cfg.global.tracking,
        )
        .context("starting SMTP tracking hub")?,
    );
    TRACKING_HUB
        .set(tracking)
        .map_err(|_| anyhow::anyhow!("SMTP tracking hub was already initialized"))?;
    let _metrics_task = rmail_common::metrics::spawn_prometheus_snapshot_task(
        std::path::Path::new(&mail_root),
        "smtpd",
    )?;
    // SQLite DB is the authoritative source for mailboxes and catchalls
    let db_path = cfg.global.db_path.clone();
    if let Err(e) = rmail_common::db::init_db(&db_path) {
        smtp_log!("error", "database_initialization_failed", { "path": db_path, "error": e.to_string() });
        std::process::exit(1);
    }

    // TLS context (acceptor and channel-binding data), reloaded on SIGHUP.
    let tls_context = match (&cfg.global.tls_cert, &cfg.global.tls_key) {
        (Some(cert), Some(key)) => Some(
            tls::load_tls_context_with_policy(cert, key, &cfg.global.tls)
                .context("loading SMTP TLS certificate and policy")?,
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

    let security = Arc::new(cfg.security.clone());
    let greylist_task = if security.greylist_enabled {
        Some(rmail_common::greylist::spawn_persistence(
            std::path::PathBuf::from(&db_path),
            Duration::from_secs(security.greylist_persist_interval_secs.max(1)),
        )?)
    } else {
        None
    };
    protocol::validate_sasl_mechanisms(&security.smtp_sasl_mechanisms, security.oauth.is_some())
        .context("validating security.smtp_sasl_mechanisms")?;
    let shutdown = GracefulShutdown::new();
    let template = ListenerContext {
        mail_root,
        tls: tls_receiver,
        db_path: Some(db_path.clone()),
        enforce_dmarc: cfg.global.enforce_dmarc.unwrap_or(false),
        security: security.clone(),
        session_limit: Arc::new(Semaphore::new(security.smtp_max_concurrent_sessions.max(1))),
        service: SmtpService::Mta,
        implicit_tls: false,
        shutdown: shutdown.clone(),
    };
    let tcp = cfg.global.tcp_listener.clone();
    let mut listeners = JoinSet::new();
    // Port 25: MTA policy, DMARC enforcement as configured.
    spawn_listeners(
        &mut listeners,
        cfg.global.smtp_listeners(),
        "smtp",
        &tcp,
        ListenerContext { ..template.clone() },
    )?;
    // RFC 2033 LMTP: local delivery only; never authenticates or relays.
    spawn_listeners(
        &mut listeners,
        cfg.global.lmtp_listeners(),
        "lmtp",
        &tcp,
        ListenerContext {
            service: SmtpService::Lmtp,
            enforce_dmarc: false,
            ..template.clone()
        },
    )?;
    // RFC 8314 implicit-TLS submission.
    let smtps = cfg.global.smtps_listeners();
    if tls_context.is_some() {
        spawn_listeners(
            &mut listeners,
            smtps,
            "smtps",
            &tcp,
            ListenerContext {
                service: SmtpService::Submission,
                implicit_tls: true,
                ..template.clone()
            },
        )?;
    } else if !smtps.is_empty() {
        smtp_log!("warn", "implicit_tls_listener_disabled", { "reason": "TLS certificate or key unavailable" });
    }
    // RFC 6409 submission: STARTTLS and authentication are required before MAIL.
    spawn_listeners(
        &mut listeners,
        cfg.global.submission_listeners(),
        "submission",
        &tcp,
        ListenerContext {
            service: SmtpService::Submission,
            enforce_dmarc: false,
            ..template
        },
    )?;

    rmail_common::runtime::wait_for_shutdown_signal().await?;
    smtp_log!("info", "shutdown_requested", { "active_sessions": shutdown.active_sessions() });
    shutdown.request();
    while let Some(result) = listeners.join_next().await {
        if let Err(error) = result {
            smtp_log!("error", "shutdown_listener_join_failed", { "error": error.to_string() });
        }
    }
    if !shutdown.wait_for_sessions(Duration::from_secs(30)).await {
        smtp_log!("warn", "shutdown_drain_timed_out", { "active_sessions": shutdown.active_sessions() });
    }
    if let Some(task) = greylist_task {
        task.abort();
        if let Err(error) = rmail_common::greylist::flush(std::path::Path::new(&db_path)) {
            smtp_log!("error", "greylist_flush_failed", { "error": error.to_string() });
        }
    }
    Ok(())
}

fn spawn_listeners(
    listeners: &mut JoinSet<()>,
    addrs: Vec<String>,
    label: &'static str,
    tcp: &TcpListenerConfig,
    ctx: ListenerContext,
) -> Result<()> {
    for addr in addrs {
        let listener = bind_tcp_listener_with_config(&addr, tcp)
            .with_context(|| format!("starting {label} listener on {addr}"))?;
        let ctx = ctx.clone();
        listeners.spawn(async move {
            if let Err(error) = run_listener(addr.clone(), listener, ctx).await {
                smtp_log!("error", "listener_failed", { "address": addr, "service": label, "error": error.to_string() });
            }
        });
    }
    Ok(())
}
