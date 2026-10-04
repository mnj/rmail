use anyhow::{Context, Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Notify, watch};

/// Most verbose level that is written: 0 error, 1 warn, 2 info, 3 debug.
static LOG_THRESHOLD: AtomicU8 = AtomicU8::new(2);

fn level_rank(level: &str) -> u8 {
    match level {
        "error" => 0,
        "warn" => 1,
        "debug" | "trace" => 3,
        _ => 2,
    }
}

/// Apply `global.log_level` (error, warn, info or debug; default info).
pub fn set_log_level(level: Option<&str>) {
    LOG_THRESHOLD.store(level.map_or(2, level_rank), Ordering::Relaxed);
}

pub fn log_enabled(level: &str) -> bool {
    level_rank(level) <= LOG_THRESHOLD.load(Ordering::Relaxed)
}

pub fn structured_log(level: &str, component: &str, event: &str, fields: serde_json::Value) {
    if !log_enabled(level) {
        return;
    }
    let encoded = structured_log_value(level, component, event, fields).to_string();
    if matches!(level, "error" | "warn") {
        eprintln!("{encoded}");
    } else {
        println!("{encoded}");
    }
}

fn structured_log_value(
    level: &str,
    component: &str,
    event: &str,
    fields: serde_json::Value,
) -> serde_json::Value {
    let timestamp_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    serde_json::json!({
        "timestamp_unix_ms": timestamp_unix_ms,
        "level": level,
        "component": component,
        "event": event,
        "fields": fields,
    })
}

#[macro_export]
macro_rules! structured_log {
    ($level:expr, $component:expr, $event:expr, $fields:tt) => {
        $crate::runtime::structured_log(
            $level,
            $component,
            $event,
            $crate::serde_json::json!($fields),
        )
    };
}

#[derive(Clone)]
pub struct GracefulShutdown {
    signal: watch::Sender<bool>,
    sessions: Arc<SessionState>,
}

struct SessionState {
    active: AtomicUsize,
    idle: Notify,
}

pub struct SessionGuard {
    sessions: Arc<SessionState>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if self.sessions.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.sessions.idle.notify_waiters();
        }
    }
}

impl Default for GracefulShutdown {
    fn default() -> Self {
        Self::new()
    }
}

impl GracefulShutdown {
    pub fn new() -> Self {
        let (signal, _) = watch::channel(false);
        Self {
            signal,
            sessions: Arc::new(SessionState {
                active: AtomicUsize::new(0),
                idle: Notify::new(),
            }),
        }
    }

    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.signal.subscribe()
    }

    pub fn request(&self) {
        self.signal.send_replace(true);
    }

    pub fn start_session(&self) -> SessionGuard {
        self.sessions.active.fetch_add(1, Ordering::AcqRel);
        SessionGuard {
            sessions: self.sessions.clone(),
        }
    }

    pub fn active_sessions(&self) -> usize {
        self.sessions.active.load(Ordering::Acquire)
    }

    pub async fn wait_for_sessions(&self, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, async {
            loop {
                let notified = self.sessions.idle.notified();
                if self.active_sessions() == 0 {
                    return;
                }
                notified.await;
            }
        })
        .await
        .is_ok()
    }
}

pub async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("installing SIGTERM handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("waiting for Ctrl-C")?,
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl-C")?;
    Ok(())
}
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

pub fn delivered_count_path(mail_root: &Path) -> PathBuf {
    mail_root.join("_metrics").join("delivered.count")
}

pub fn prometheus_snapshot_path(mail_root: &Path, component: &str) -> PathBuf {
    mail_root
        .join("_metrics")
        .join(format!("{}.prom", component))
}

/// The secret webmail presents to the local submission service to send as
/// its signed-in user (SASL `X-RMAIL-WEBMAIL`, loopback only).
pub fn webmail_submission_key_path(mail_root: &Path) -> PathBuf {
    mail_root.join("run").join("webmail-submission.key")
}

/// The webmail submission secret, created (owner-only, 0600) when missing.
pub fn webmail_submission_key(mail_root: &Path) -> Result<String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = webmail_submission_key_path(mail_root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(mut file) => {
            let key: String = (0..32)
                .map(|_| format!("{:02x}", rand::random::<u8>()))
                .collect();
            file.write_all(key.as_bytes())?;
            file.sync_all()?;
            Ok(key)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let key = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let key = key.trim().to_string();
            if key.len() < 32 {
                anyhow::bail!("{} is too short", path.display());
            }
            Ok(key)
        }
        Err(error) => Err(error).with_context(|| format!("creating {}", path.display())),
    }
}

/// Byte-wise comparison whose time does not depend on where inputs differ.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn log_path(mail_root: &Path, component: &str) -> PathBuf {
    mail_root.join("logs").join(format!("{}.log", component))
}

pub fn redirect_stdio_to_log(mail_root: &Path, component: &str) -> Result<()> {
    let path = log_path(mail_root, component);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating log dir {}", parent.display()))?;
    }

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening log file {}", path.display()))?;
    let fd = file.as_raw_fd();

    unsafe {
        if libc::dup2(fd, libc::STDOUT_FILENO) == -1 {
            return Err(std::io::Error::last_os_error()).context("redirecting stdout");
        }
        if libc::dup2(fd, libc::STDERR_FILENO) == -1 {
            return Err(std::io::Error::last_os_error()).context("redirecting stderr");
        }
    }

    std::mem::forget(file);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{GracefulShutdown, structured_log_value};
    use std::time::Duration;

    #[tokio::test]
    async fn shutdown_signal_and_session_drain_are_coordinated() {
        let shutdown = GracefulShutdown::new();
        let mut signal = shutdown.subscribe();
        let first = shutdown.start_session();
        let second = shutdown.start_session();
        assert_eq!(shutdown.active_sessions(), 2);

        shutdown.request();
        signal.changed().await.unwrap();
        assert!(*signal.borrow());
        drop(first);
        assert!(!shutdown.wait_for_sessions(Duration::from_millis(5)).await);
        drop(second);
        assert!(shutdown.wait_for_sessions(Duration::from_millis(50)).await);
    }

    #[test]
    fn structured_events_have_stable_machine_readable_context() {
        let event = structured_log_value(
            "warn",
            "outbound",
            "delivery_failed",
            serde_json::json!({"connection_id": "c-1", "message_id": "m-1"}),
        );
        assert_eq!(event["level"], "warn");
        assert_eq!(event["component"], "outbound");
        assert_eq!(event["event"], "delivery_failed");
        assert_eq!(event["fields"]["connection_id"], "c-1");
        assert_eq!(event["fields"]["message_id"], "m-1");
        assert!(event["timestamp_unix_ms"].as_u64().is_some());
    }
}
