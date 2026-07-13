use anyhow::{Context, Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{Notify, watch};

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
    use super::GracefulShutdown;
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
}
