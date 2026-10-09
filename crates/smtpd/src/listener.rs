//! Accept loops for the SMTP, submission, SMTPS and LMTP listeners.

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use rmail_common::config::SecurityConfig;
use rmail_common::metrics;
use rmail_common::runtime::GracefulShutdown;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::time::timeout;

use crate::limits::accept_connection_from;
use crate::session::process_stream_with_bindings;
use crate::trace::{ConnectionTrace, emit_tracking};
use crate::{STARTTLS_HANDSHAKE_TIMEOUT, SmtpService, tls};

pub(crate) type TlsReceiver = watch::Receiver<Option<Arc<tls::TlsContext>>>;

/// Everything a listener needs to start sessions.
#[derive(Clone)]
pub(crate) struct ListenerContext {
    pub mail_root: String,
    pub tls: TlsReceiver,
    pub db_path: Option<String>,
    pub enforce_dmarc: bool,
    pub security: Arc<SecurityConfig>,
    pub session_limit: Arc<Semaphore>,
    pub service: SmtpService,
    /// SMTPS: TLS starts before the greeting instead of via STARTTLS.
    pub implicit_tls: bool,
    pub shutdown: GracefulShutdown,
}

pub(crate) async fn run_listener(
    addr: String,
    listener: TcpListener,
    ctx: ListenerContext,
) -> Result<()> {
    let service = ctx.service;
    smtp_log!("info", "listener_started", { "address": addr, "service": service.as_str(), "tls": ctx.implicit_tls });
    let mut clients = rmail_common::proxy::ClientAcceptor::new(listener, "smtpd", addr.clone());
    let mut shutdown_signal = ctx.shutdown.subscribe();
    loop {
        if *shutdown_signal.borrow() {
            return Ok(());
        }
        let (mut stream, peer) = tokio::select! {
            changed = shutdown_signal.changed() => {
                changed.context("waiting for SMTP shutdown signal")?;
                return Ok(());
            }
            accepted = clients.accept() => accepted,
        };
        let trace = ConnectionTrace::new(stream.local_addr().ok());
        smtp_log!("info", "connection_accepted", { "connection_id": trace.id, "listener": addr, "peer": peer.to_string(), "service": service.as_str(), "tls": ctx.implicit_tls, "starttls_available": !ctx.implicit_tls && ctx.tls.borrow().is_some() });
        let mut connected = trace.event(Some(peer), None, "connection", "connected");
        if ctx.implicit_tls {
            connected.detail = Some("implicit TLS listener".to_string());
        }
        emit_tracking(connected);

        let tls_context = ctx.tls.borrow().clone();
        if ctx.implicit_tls && tls_context.is_none() {
            smtp_log!("warn", "connection_rejected", { "connection_id": trace.id, "peer": peer.to_string(), "reason": "TLS context unavailable" });
            continue;
        }
        if !accept_connection_from(peer.ip(), ctx.security.smtp_max_connections_per_minute) {
            let _ = stream
                .write_all(b"421 4.7.0 Connection rate limit exceeded\r\n")
                .await;
            continue;
        }
        let Ok(permit) = ctx.session_limit.clone().try_acquire_owned() else {
            let _ = stream
                .write_all(b"421 4.3.2 Too many concurrent sessions\r\n")
                .await;
            continue;
        };
        let session = ctx.shutdown.start_session();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _session = session;
            let _permit = permit;
            let connection_id = trace.id.clone();
            let (stream, channel_bindings): (Box<dyn crate::AsyncStream + Send>, _) =
                match tls_context.clone() {
                    Some(tls) if ctx.implicit_tls => {
                        let started = Instant::now();
                        let handshake =
                            timeout(STARTTLS_HANDSHAKE_TIMEOUT, tls.acceptor.accept(stream)).await;
                        metrics::observe_tls_handshake_duration(started.elapsed());
                        match handshake {
                            Ok(Ok(tls_stream)) => {
                                smtp_log!("info", "tls_handshake_succeeded", { "connection_id": connection_id, "peer": peer.to_string(), "implicit": true });
                                let bindings = tls.channel_bindings(tls_stream.get_ref().1);
                                (Box::new(tls_stream), Some(bindings))
                            }
                            Ok(Err(error)) => {
                                smtp_log!("error", "tls_handshake_failed", { "connection_id": connection_id, "peer": peer.to_string(), "implicit": true, "error": error.to_string() });
                                return;
                            }
                            Err(_) => {
                                smtp_log!("error", "tls_handshake_failed", { "connection_id": connection_id, "peer": peer.to_string(), "implicit": true, "error": "handshake timed out" });
                                return;
                            }
                        }
                    }
                    _ => (Box::new(stream), None),
                };
            if let Err(error) = process_stream_with_bindings(
                stream,
                ctx.mail_root,
                tls_context,
                ctx.db_path,
                Some(peer),
                ctx.implicit_tls,
                ctx.enforce_dmarc,
                true,
                ctx.security,
                ctx.service,
                Some(trace),
                channel_bindings,
            )
            .await
            {
                smtp_log!("error", "session_failed", { "connection_id": connection_id, "peer": peer.to_string(), "tls": ctx.implicit_tls, "error": error.to_string() });
            }
        });
    }
}

#[cfg(unix)]
pub(crate) fn spawn_tls_reloader(
    sender: watch::Sender<Option<Arc<tls::TlsContext>>>,
    cert_path: String,
    key_path: String,
    policy: rmail_common::config::TlsPolicy,
) -> Result<tokio::task::JoinHandle<()>> {
    let mut trigger = rmail_common::tls::ReloadTrigger::new(&cert_path, &key_path, &policy)
        .context("installing SMTP TLS reload handler")?;
    Ok(tokio::spawn(async move {
        loop {
            let reason = trigger.next().await;
            match tls::reload_tls_context(&sender, &cert_path, &key_path, &policy) {
                Ok(()) => smtp_log!("info", "tls_reloaded", { "reason": reason }),
                Err(error) => {
                    smtp_log!("error", "tls_reload_failed", { "reason": reason, "error": error.to_string() })
                }
            }
        }
    }))
}
