//! Service restart requests.
//!
//! The admin console runs unprivileged and cannot restart systemd units. It
//! writes the short names of the services to restart (one per line) to
//! `<mail_root>/restart-request`; the root-owned `rmail_restart.path` unit
//! notices the file and runs `rmail_ctl service apply-request`, which only
//! ever acts on names from [`crate::settings::SERVICES`].

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

pub const REQUEST_FILE: &str = "restart-request";

/// Units that watch for requests; present when the package installed them.
const HELPER_UNITS: &[&str] = &[
    "/usr/lib/systemd/system/rmail_restart.path",
    "/lib/systemd/system/rmail_restart.path",
    "/etc/systemd/system/rmail_restart.path",
];

pub fn request_path(mail_root: &Path) -> PathBuf {
    mail_root.join(REQUEST_FILE)
}

/// True when the systemd unit that applies requests is installed.
pub fn helper_installed() -> bool {
    HELPER_UNITS.iter().any(|unit| Path::new(unit).exists())
}

/// Validate `services` and queue them for restart, replacing a pending request.
pub fn write_request(mail_root: &Path, services: &[String]) -> Result<()> {
    let services = validate(services.iter().map(String::as_str))?;
    let path = request_path(mail_root);
    let staged = path.with_extension("tmp");
    let mut file = fs::File::create(&staged).with_context(|| format!("creating {staged:?}"))?;
    file.write_all(services.join("\n").as_bytes())?;
    file.sync_all()?;
    fs::rename(&staged, &path).with_context(|| format!("queueing {path:?}"))
}

/// Read a queued request, rejecting anything but a small regular file of known service names.
pub fn read_request(path: &Path) -> Result<Vec<String>> {
    let meta = fs::symlink_metadata(path).with_context(|| format!("reading {path:?}"))?;
    if !meta.is_file() || meta.len() > 1024 {
        bail!("{path:?} is not a restart request");
    }
    let text = fs::read_to_string(path)?;
    validate(text.lines())
}

fn validate<'a>(names: impl Iterator<Item = &'a str>) -> Result<Vec<String>> {
    let mut services = Vec::new();
    for name in names.map(str::trim).filter(|name| !name.is_empty()) {
        if !crate::settings::SERVICES.contains(&name) {
            bail!("unknown service {name:?}");
        }
        if !services.iter().any(|known| known == name) {
            services.push(name.to_string());
        }
    }
    if services.is_empty() {
        bail!("no services to restart");
    }
    Ok(services)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_and_rejects_unknown_services() {
        let dir = tempfile::tempdir().unwrap();
        let names = ["smtpd".to_string(), "web".to_string(), "smtpd".to_string()];
        write_request(dir.path(), &names).unwrap();
        assert_eq!(
            read_request(&request_path(dir.path())).unwrap(),
            ["smtpd", "web"]
        );
        assert!(write_request(dir.path(), &["sshd".to_string()]).is_err());
        assert!(write_request(dir.path(), &[]).is_err());
    }
}
