use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct Global {
    pub mail_root: String,
    /// Plain SMTP bind addresses, e.g. ["0.0.0.0:25", "[::]:25"]
    pub listen_addrs: Option<Vec<String>>,
    /// Implicit TLS SMTP bind addresses; if unset, smtps_port binds wildcard v4+v6
    pub smtps_listen_addrs: Option<Vec<String>>,
    pub smtps_port: Option<u16>,
    pub submission_port: Option<u16>,
    /// IMAPS bind addresses; if unset, imaps_port binds wildcard v4 only for compatibility
    pub imaps_listen_addrs: Option<Vec<String>>,
    pub imaps_port: Option<u16>,
    /// Plain IMAP bind addresses; if unset, imap_port binds wildcard v4 only for compatibility
    pub imap_listen_addrs: Option<Vec<String>>,
    pub imap_port: Option<u16>,
    /// Web UI bind addresses; if unset, web_port binds 127.0.0.1 only
    pub web_listen_addrs: Option<Vec<String>>,
    pub web_port: Option<u16>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub log_level: Option<String>,
    /// Optional SQLite database path for mailboxes/catchalls
    pub db_path: Option<String>,
    /// Optional web admin username for the lightweight web UI
    pub web_admin_user: Option<String>,
    /// Argon2 password hash for administrative web UI access (optional)
    pub web_admin_password_hash: Option<String>,
    /// Directory to serve ACME http-01 challenges from (for production TLS automation)
    pub acme_challenge_dir: Option<String>,
    /// If true, enforce DMARC policies (reject/quarantine) at SMTP time for inbound mail
    pub enforce_dmarc: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub global: Global,
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Config> {
        let s = fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&s)?;
        Ok(cfg)
    }
}
