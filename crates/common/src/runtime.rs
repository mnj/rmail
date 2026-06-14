use anyhow::{Context, Result};
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
