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
    /// Explicit message-submission bind addresses; defaults to wildcard v4+v6 for submission_port.
    pub submission_listen_addrs: Option<Vec<String>>,
    /// IMAPS bind addresses; if unset, imaps_port binds wildcard v4 only for compatibility
    pub imaps_listen_addrs: Option<Vec<String>>,
    pub imaps_port: Option<u16>,
    /// Plain IMAP bind addresses; if unset, imap_port binds wildcard v4 only for compatibility
    pub imap_listen_addrs: Option<Vec<String>>,
    pub imap_port: Option<u16>,
    /// Web UI bind addresses; if unset, web_port binds 127.0.0.1 only
    pub web_listen_addrs: Option<Vec<String>>,
    pub web_port: Option<u16>,
    /// User webmail bind addresses; if unset, webmail_port binds 127.0.0.1 only
    pub webmail_listen_addrs: Option<Vec<String>>,
    pub webmail_port: Option<u16>,
    /// Secret used to sign webmail session cookies.
    pub webmail_session_secret: Option<String>,
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
    #[serde(default)]
    pub security: SecurityConfig,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScannerFailureAction {
    Tempfail,
    Accept,
    Reject,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    #[serde(default = "default_smtp_max_concurrent_sessions")]
    pub smtp_max_concurrent_sessions: usize,
    #[serde(default = "default_smtp_max_connections_per_minute")]
    pub smtp_max_connections_per_minute: usize,
    #[serde(default = "default_smtp_max_commands_per_minute")]
    pub smtp_max_commands_per_minute: usize,
    #[serde(default = "default_smtp_max_recipients")]
    pub smtp_max_recipients: usize,
    #[serde(default = "default_submission_max_recipients")]
    pub submission_max_recipients: usize,
    #[serde(default = "default_submission_max_messages_per_minute")]
    pub submission_max_messages_per_minute: usize,
    #[serde(default = "default_imap_sasl_mechanisms")]
    pub imap_sasl_mechanisms: Vec<String>,
    #[serde(default = "default_smtp_sasl_mechanisms")]
    pub smtp_sasl_mechanisms: Vec<String>,
    #[serde(default = "default_scanner_failure_action")]
    pub scanner_failure_action: ScannerFailureAction,
    #[serde(default = "default_scanner_timeout_ms")]
    pub scanner_timeout_ms: u64,
    #[serde(default = "default_scanner_max_message_bytes")]
    pub scanner_max_message_bytes: usize,
    #[serde(default)]
    pub clamav_enabled: bool,
    #[serde(default = "default_clamav_endpoint")]
    pub clamav_endpoint: String,
    #[serde(default)]
    pub rspamd_enabled: bool,
    #[serde(default = "default_rspamd_url")]
    pub rspamd_url: String,
    #[serde(default = "default_rspamd_quarantine_actions")]
    pub rspamd_quarantine_actions: Vec<String>,
    #[serde(default)]
    pub rspamd_reject_actions: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            smtp_max_concurrent_sessions: default_smtp_max_concurrent_sessions(),
            smtp_max_connections_per_minute: default_smtp_max_connections_per_minute(),
            smtp_max_commands_per_minute: default_smtp_max_commands_per_minute(),
            smtp_max_recipients: default_smtp_max_recipients(),
            submission_max_recipients: default_submission_max_recipients(),
            submission_max_messages_per_minute: default_submission_max_messages_per_minute(),
            imap_sasl_mechanisms: default_imap_sasl_mechanisms(),
            smtp_sasl_mechanisms: default_smtp_sasl_mechanisms(),
            scanner_failure_action: default_scanner_failure_action(),
            scanner_timeout_ms: default_scanner_timeout_ms(),
            scanner_max_message_bytes: default_scanner_max_message_bytes(),
            clamav_enabled: false,
            clamav_endpoint: default_clamav_endpoint(),
            rspamd_enabled: false,
            rspamd_url: default_rspamd_url(),
            rspamd_quarantine_actions: default_rspamd_quarantine_actions(),
            rspamd_reject_actions: Vec::new(),
        }
    }
}

fn default_smtp_max_concurrent_sessions() -> usize {
    1_000
}

fn default_smtp_max_connections_per_minute() -> usize {
    60
}

fn default_smtp_max_commands_per_minute() -> usize {
    120
}

fn default_smtp_max_recipients() -> usize {
    100
}

fn default_submission_max_recipients() -> usize {
    50
}

fn default_submission_max_messages_per_minute() -> usize {
    30
}

fn default_imap_sasl_mechanisms() -> Vec<String> {
    vec![
        "PLAIN".to_string(),
        "LOGIN".to_string(),
        "SCRAM-SHA-256".to_string(),
        "SCRAM-SHA-256-PLUS".to_string(),
    ]
}

fn default_smtp_sasl_mechanisms() -> Vec<String> {
    vec![
        "PLAIN".to_string(),
        "LOGIN".to_string(),
        "SCRAM-SHA-256".to_string(),
    ]
}

impl SecurityConfig {
    pub fn scanners_enabled(&self) -> bool {
        self.clamav_enabled || self.rspamd_enabled
    }
}

fn default_scanner_failure_action() -> ScannerFailureAction {
    ScannerFailureAction::Tempfail
}

fn default_scanner_timeout_ms() -> u64 {
    5000
}

fn default_scanner_max_message_bytes() -> usize {
    10 * 1024 * 1024
}

fn default_clamav_endpoint() -> String {
    "unix:/run/clamav/clamd.ctl".to_string()
}

fn default_rspamd_url() -> String {
    "http://127.0.0.1:11333/checkv2".to_string()
}

fn default_rspamd_quarantine_actions() -> Vec<String> {
    vec![
        "add header".to_string(),
        "rewrite subject".to_string(),
        "reject".to_string(),
    ]
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Config> {
        let s = fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&s)?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, ScannerFailureAction};

    #[test]
    fn security_defaults_when_absent() {
        let cfg: Config = toml::from_str("[global]\nmail_root = \"mail\"\n").expect("config");
        assert_eq!(
            cfg.security.scanner_failure_action,
            ScannerFailureAction::Tempfail
        );
        assert_eq!(cfg.security.scanner_timeout_ms, 5000);
        assert_eq!(cfg.security.scanner_max_message_bytes, 10 * 1024 * 1024);
        assert_eq!(cfg.security.smtp_max_concurrent_sessions, 1_000);
        assert_eq!(cfg.security.smtp_max_connections_per_minute, 60);
        assert_eq!(cfg.security.smtp_max_commands_per_minute, 120);
        assert_eq!(cfg.security.smtp_max_recipients, 100);
        assert_eq!(cfg.security.submission_max_recipients, 50);
        assert_eq!(cfg.security.submission_max_messages_per_minute, 30);
        assert!(!cfg.security.clamav_enabled);
        assert_eq!(
            cfg.security.imap_sasl_mechanisms,
            ["PLAIN", "LOGIN", "SCRAM-SHA-256", "SCRAM-SHA-256-PLUS"]
        );
        assert_eq!(
            cfg.security.smtp_sasl_mechanisms,
            ["PLAIN", "LOGIN", "SCRAM-SHA-256"]
        );
        assert!(!cfg.security.rspamd_enabled);
        assert!(!cfg.security.scanners_enabled());
    }

    #[test]
    fn security_parses_enums_and_values() {
        let cfg: Config = toml::from_str(
            r#"
[global]
mail_root = "mail"

[security]
imap_sasl_mechanisms = ["SCRAM-SHA-256"]
smtp_sasl_mechanisms = ["SCRAM-SHA-256"]
scanner_failure_action = "reject"
scanner_timeout_ms = 42
scanner_max_message_bytes = 99
clamav_enabled = true
clamav_endpoint = "tcp:127.0.0.1:3310"
rspamd_enabled = true
rspamd_url = "http://localhost:11333/checkv2"
rspamd_quarantine_actions = ["add header"]
rspamd_reject_actions = ["reject"]
"#,
        )
        .expect("config");
        assert_eq!(
            cfg.security.scanner_failure_action,
            ScannerFailureAction::Reject
        );
        assert_eq!(cfg.security.scanner_timeout_ms, 42);
        assert_eq!(cfg.security.imap_sasl_mechanisms, ["SCRAM-SHA-256"]);
        assert_eq!(cfg.security.smtp_sasl_mechanisms, ["SCRAM-SHA-256"]);
        assert_eq!(cfg.security.scanner_max_message_bytes, 99);
        assert!(cfg.security.scanners_enabled());
    }
}
