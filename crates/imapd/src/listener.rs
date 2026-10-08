//! Accept loops for the IMAP (STARTTLS) and IMAPS listeners.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use rmail_common::runtime::GracefulShutdown;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::time::timeout;

use crate::session::{process_stream_with_policy, process_tls_stream};
use crate::{auth, tls};

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) static CONNECTION_ATTEMPTS: Lazy<Mutex<HashMap<IpAddr, VecDeque<Instant>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Everything a listener needs to start sessions.
#[derive(Clone)]
pub(crate) struct ListenerContext {
    pub mail_root: String,
    pub tls: watch::Receiver<Option<Arc<tls::TlsContext>>>,
    pub db_path: Option<String>,
    pub auth_policy: Arc<auth::AuthPolicy>,
    pub session_limit: Arc<Semaphore>,
    pub connection_rate_limit: usize,
    /// IMAPS: TLS starts before the greeting instead of via STARTTLS.
    pub implicit_tls: bool,
    pub shutdown: GracefulShutdown,
}

pub(crate) async fn run_listener(
    addr: String,
    listener: TcpListener,
    ctx: ListenerContext,
) -> Result<()> {
    imap_log!("info", "listener_started", { "address": addr, "tls": ctx.implicit_tls });
    let mut clients = rmail_common::proxy::ClientAcceptor::new(listener, "imapd", addr.clone());
    let mut shutdown_signal = ctx.shutdown.subscribe();
    loop {
        if *shutdown_signal.borrow() {
            return Ok(());
        }
        let (mut stream, peer) = tokio::select! {
            changed = shutdown_signal.changed() => {
                changed.context("waiting for IMAP shutdown signal")?;
                return Ok(());
            }
            accepted = clients.accept() => accepted,
        };
        imap_log!("info", "connection_accepted", { "listener": addr, "peer": peer.to_string(), "tls": ctx.implicit_tls, "starttls_available": !ctx.implicit_tls && ctx.tls.borrow().is_some() });
        // Rejections are only announced in plaintext; an IMAPS client
        // expects a TLS handshake first, so the socket is simply closed.
        if !accept_connection_from(peer.ip(), ctx.connection_rate_limit) {
            if !ctx.implicit_tls {
                let _ = stream
                    .write_all(b"* BYE Connection rate limit exceeded\r\n")
                    .await;
            }
            continue;
        }
        let tls_context = ctx.tls.borrow().clone();
        if ctx.implicit_tls && tls_context.is_none() {
            imap_log!("warn", "connection_rejected", { "peer": peer.to_string(), "reason": "TLS context unavailable" });
            continue;
        }
        let Ok(permit) = ctx.session_limit.clone().try_acquire_owned() else {
            if !ctx.implicit_tls {
                let _ = stream
                    .write_all(b"* BYE Too many concurrent sessions\r\n")
                    .await;
            }
            continue;
        };
        let session = ctx.shutdown.start_session();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _session = session;
            let _permit = permit;
            let (stream, bindings): (Box<dyn crate::RawStream + Send>, _) = match tls_context
                .clone()
            {
                Some(tls) if ctx.implicit_tls => {
                    let started = Instant::now();
                    let handshake =
                        timeout(TLS_HANDSHAKE_TIMEOUT, tls.acceptor.accept(stream)).await;
                    rmail_common::metrics::observe_tls_handshake_duration(started.elapsed());
                    match handshake {
                        Ok(Ok(tls_stream)) => {
                            let bindings = tls.channel_bindings(tls_stream.get_ref().1);
                            (Box::new(tls_stream), Some(bindings))
                        }
                        Ok(Err(error)) => {
                            imap_log!("error", "tls_handshake_failed", { "peer": peer.to_string(), "error": error.to_string() });
                            return;
                        }
                        Err(_) => {
                            imap_log!("error", "tls_handshake_failed", { "peer": peer.to_string(), "error": "handshake timed out" });
                            return;
                        }
                    }
                }
                _ => (Box::new(stream), None),
            };
            let result = match bindings {
                Some(bindings) => {
                    process_tls_stream(
                        stream,
                        ctx.mail_root,
                        tls_context,
                        ctx.db_path,
                        Some(peer),
                        bindings,
                        ctx.auth_policy,
                    )
                    .await
                }
                None => {
                    process_stream_with_policy(
                        stream,
                        ctx.mail_root,
                        tls_context,
                        ctx.db_path,
                        Some(peer),
                        ctx.implicit_tls,
                        ctx.auth_policy,
                    )
                    .await
                }
            };
            if let Err(error) = result {
                imap_log!("error", "session_failed", { "peer": peer.to_string(), "tls": ctx.implicit_tls, "error": error.to_string() });
            }
        });
    }
}

/// Sliding one-minute connection rate limit per client address.
pub(crate) fn accept_connection_from(ip: IpAddr, limit: usize) -> bool {
    const MAX_TRACKED_SOURCE_IPS: usize = 10_000;
    let now = Instant::now();
    let mut all = CONNECTION_ATTEMPTS.lock().unwrap();
    all.retain(|_, attempts| {
        while attempts
            .front()
            .is_some_and(|seen| now.duration_since(*seen) >= Duration::from_secs(60))
        {
            attempts.pop_front();
        }
        !attempts.is_empty()
    });
    if !all.contains_key(&ip)
        && all.len() >= MAX_TRACKED_SOURCE_IPS
        && let Some(oldest) = all
            .iter()
            .min_by_key(|(_, attempts)| attempts.back().copied())
            .map(|(address, _)| *address)
    {
        all.remove(&oldest);
    }
    let attempts = all.entry(ip).or_default();
    if attempts.len() >= limit.max(1) {
        return false;
    }
    attempts.push_back(now);
    true
}

#[cfg(unix)]
pub(crate) fn spawn_tls_reloader(
    sender: watch::Sender<Option<Arc<tls::TlsContext>>>,
    cert_path: String,
    key_path: String,
    policy: rmail_common::config::TlsPolicy,
) -> Result<tokio::task::JoinHandle<()>> {
    let mut trigger = rmail_common::tls::ReloadTrigger::new(&cert_path, &key_path, &policy)
        .context("installing IMAP TLS reload handler")?;
    Ok(tokio::spawn(async move {
        loop {
            let reason = trigger.next().await;
            match tls::reload_tls_context(&sender, &cert_path, &key_path, &policy) {
                Ok(()) => imap_log!("info", "tls_reloaded", { "reason": reason }),
                Err(error) => {
                    imap_log!("error", "tls_reload_failed", { "reason": reason, "error": error.to_string() })
                }
            }
        }
    }))
}
