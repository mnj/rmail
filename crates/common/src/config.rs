use crate::net::TcpListenerConfig;
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct Global {
    pub mail_root: String,
    /// Durable SMTP tracking retention and pruning limits.
    #[serde(default)]
    pub tracking: TrackingConfig,
    /// Process-wide TCP listener behavior. Explicit listen address arrays still
    /// choose IPv4-only, IPv6-only, or combined listeners per service.
    #[serde(default)]
    pub tcp_listener: TcpListenerConfig,
    /// Preferred listener configuration. Each service is a list of complete
    /// socket addresses, such as `["[::]:25"]` or
    /// `["0.0.0.0:25", "[::]:25"]`.
    #[serde(default)]
    pub listeners: ListenerEndpoints,
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
    #[serde(default)]
    pub tls: TlsPolicy,
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

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct TlsPolicy {
    #[serde(default)]
    pub minimum_version: TlsMinimumVersion,
    /// Rustls cipher-suite names. Empty uses the safe Rustls defaults.
    #[serde(default)]
    pub cipher_suites: Vec<String>,
    /// DER-encoded OCSP response to staple with the configured certificate.
    pub ocsp_response: Option<String>,
    /// Keep admin web and webmail on HTTP when a reverse proxy terminates TLS.
    #[serde(default)]
    pub web_http_only: bool,
}

impl Default for TlsPolicy {
    fn default() -> Self {
        Self {
            minimum_version: TlsMinimumVersion::Tls12,
            cipher_suites: Vec::new(),
            ocsp_response: None,
            web_http_only: false,
        }
    }
}

#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum TlsMinimumVersion {
    #[default]
    #[serde(rename = "1.2")]
    Tls12,
    #[serde(rename = "1.3")]
    Tls13,
}

#[derive(Debug, Deserialize, Clone, Copy)]
pub struct TrackingConfig {
    /// Remove events older than this many days; zero disables age pruning.
    #[serde(default = "default_tracking_retention_days")]
    pub retention_days: u32,
    /// Retain at most this many events; zero disables count pruning.
    #[serde(default = "default_tracking_max_events")]
    pub max_events: u64,
    #[serde(default = "default_tracking_prune_interval_seconds")]
    pub prune_interval_seconds: u64,
    #[serde(default = "default_tracking_prune_batch_size")]
    pub prune_batch_size: u32,
}

impl Default for TrackingConfig {
    fn default() -> Self {
        Self {
            retention_days: default_tracking_retention_days(),
            max_events: default_tracking_max_events(),
            prune_interval_seconds: default_tracking_prune_interval_seconds(),
            prune_batch_size: default_tracking_prune_batch_size(),
        }
    }
}

fn default_tracking_retention_days() -> u32 {
    30
}
fn default_tracking_max_events() -> u64 {
    2_000_000
}
fn default_tracking_prune_interval_seconds() -> u64 {
    3_600
}
fn default_tracking_prune_batch_size() -> u32 {
    10_000
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct ListenerEndpoints {
    pub smtp: Option<Vec<String>>,
    /// Local Mail Transfer Protocol endpoints. Empty by default.
    pub lmtp: Option<Vec<String>>,
    pub submission: Option<Vec<String>>,
    pub smtps: Option<Vec<String>>,
    pub imap: Option<Vec<String>>,
    pub imaps: Option<Vec<String>>,
    pub admin: Option<Vec<String>>,
    pub webmail: Option<Vec<String>>,
}

impl Global {
    pub fn smtp_listeners(&self) -> Vec<String> {
        self.listeners
            .smtp
            .clone()
            .or_else(|| self.listen_addrs.clone())
            .unwrap_or_else(|| vec!["127.0.0.1:2525".to_string(), "[::1]:2525".to_string()])
    }

    pub fn lmtp_listeners(&self) -> Vec<String> {
        self.listeners.lmtp.clone().unwrap_or_default()
    }

    pub fn submission_listeners(&self) -> Vec<String> {
        if let Some(addresses) = self.listeners.submission.clone() {
            return addresses;
        }
        self.submission_port.map_or_else(Vec::new, |port| {
            self.submission_listen_addrs
                .clone()
                .unwrap_or_else(|| vec![format!("0.0.0.0:{port}"), format!("[::]:{port}")])
        })
    }

    pub fn smtps_listeners(&self) -> Vec<String> {
        if let Some(addresses) = self.listeners.smtps.clone() {
            return addresses;
        }
        self.smtps_port.map_or_else(Vec::new, |port| {
            self.smtps_listen_addrs
                .clone()
                .unwrap_or_else(|| vec![format!("0.0.0.0:{port}"), format!("[::]:{port}")])
        })
    }

    pub fn imap_listeners(&self) -> Vec<String> {
        self.listeners
            .imap
            .clone()
            .or_else(|| self.imap_listen_addrs.clone())
            .unwrap_or_else(|| vec![format!("0.0.0.0:{}", self.imap_port.unwrap_or(143))])
    }

    pub fn imaps_listeners(&self) -> Vec<String> {
        if let Some(addresses) = self.listeners.imaps.clone() {
            return addresses;
        }
        self.imaps_port.map_or_else(Vec::new, |port| {
            self.imaps_listen_addrs
                .clone()
                .unwrap_or_else(|| vec![format!("0.0.0.0:{port}")])
        })
    }

    pub fn admin_listeners(&self) -> Vec<String> {
        self.listeners
            .admin
            .clone()
            .or_else(|| self.web_listen_addrs.clone())
            .unwrap_or_else(|| vec![format!("127.0.0.1:{}", self.web_port.unwrap_or(8080))])
    }

    pub fn webmail_listeners(&self) -> Vec<String> {
        self.listeners
            .webmail
            .clone()
            .or_else(|| self.webmail_listen_addrs.clone())
            .unwrap_or_else(|| vec![format!("127.0.0.1:{}", self.webmail_port.unwrap_or(8081))])
    }
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
    #[serde(default = "default_imap_max_concurrent_sessions")]
    pub imap_max_concurrent_sessions: usize,
    #[serde(default = "default_imap_max_connections_per_minute")]
    pub imap_max_connections_per_minute: usize,
    #[serde(default = "default_imap_max_commands_per_minute")]
    pub imap_max_commands_per_minute: usize,
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
    /// Require every RFC 5322 From mailbox on authenticated submission to match the login.
    #[serde(default)]
    pub submission_require_from_alignment: bool,
    #[serde(default = "default_imap_sasl_mechanisms")]
    pub imap_sasl_mechanisms: Vec<String>,
    #[serde(default = "default_smtp_sasl_mechanisms")]
    pub smtp_sasl_mechanisms: Vec<String>,
    /// OAuth 2.0 token introspection authority. Required before an OAuth SASL
    /// mechanism can be enabled.
    #[serde(default)]
    pub oauth: Option<OAuthConfig>,
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
            imap_max_concurrent_sessions: default_imap_max_concurrent_sessions(),
            imap_max_connections_per_minute: default_imap_max_connections_per_minute(),
            imap_max_commands_per_minute: default_imap_max_commands_per_minute(),
            smtp_max_concurrent_sessions: default_smtp_max_concurrent_sessions(),
            smtp_max_connections_per_minute: default_smtp_max_connections_per_minute(),
            smtp_max_commands_per_minute: default_smtp_max_commands_per_minute(),
            smtp_max_recipients: default_smtp_max_recipients(),
            submission_max_recipients: default_submission_max_recipients(),
            submission_max_messages_per_minute: default_submission_max_messages_per_minute(),
            submission_require_from_alignment: false,
            imap_sasl_mechanisms: default_imap_sasl_mechanisms(),
            smtp_sasl_mechanisms: default_smtp_sasl_mechanisms(),
            oauth: None,
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

#[derive(Deserialize, Clone)]
pub struct OAuthConfig {
    pub introspection_url: String,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub required_scopes: Vec<String>,
    #[serde(default = "default_oauth_identity_claim")]
    pub identity_claim: String,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default = "default_oauth_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub allow_insecure_http: bool,
}

impl std::fmt::Debug for OAuthConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthConfig")
            .field("introspection_url", &self.introspection_url)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("required_scopes", &self.required_scopes)
            .field("identity_claim", &self.identity_claim)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("timeout_ms", &self.timeout_ms)
            .field("allow_insecure_http", &self.allow_insecure_http)
            .finish()
    }
}

fn default_oauth_identity_claim() -> String {
    "username".to_string()
}

fn default_oauth_timeout_ms() -> u64 {
    5_000
}

fn default_smtp_max_concurrent_sessions() -> usize {
    1_000
}

fn default_imap_max_concurrent_sessions() -> usize {
    1_000
}

fn default_imap_max_connections_per_minute() -> usize {
    60
}

fn default_imap_max_commands_per_minute() -> usize {
    300
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
    use super::{Config, ScannerFailureAction, TlsMinimumVersion};

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
        assert_eq!(cfg.security.imap_max_concurrent_sessions, 1_000);
        assert_eq!(cfg.security.imap_max_connections_per_minute, 60);
        assert_eq!(cfg.security.imap_max_commands_per_minute, 300);
        assert_eq!(cfg.security.smtp_max_connections_per_minute, 60);
        assert_eq!(cfg.security.smtp_max_commands_per_minute, 120);
        assert_eq!(cfg.security.smtp_max_recipients, 100);
        assert_eq!(cfg.security.submission_max_recipients, 50);
        assert_eq!(cfg.security.submission_max_messages_per_minute, 30);
        assert!(!cfg.security.submission_require_from_alignment);
        assert!(!cfg.security.clamav_enabled);
        assert_eq!(
            cfg.security.imap_sasl_mechanisms,
            ["PLAIN", "LOGIN", "SCRAM-SHA-256", "SCRAM-SHA-256-PLUS"]
        );
        assert_eq!(
            cfg.security.smtp_sasl_mechanisms,
            ["PLAIN", "LOGIN", "SCRAM-SHA-256"]
        );
        assert!(cfg.security.oauth.is_none());
        assert!(!cfg.security.rspamd_enabled);
        assert!(!cfg.security.scanners_enabled());
        assert_eq!(cfg.global.tls.minimum_version, TlsMinimumVersion::Tls12);
        assert!(cfg.global.tls.cipher_suites.is_empty());
        assert!(cfg.global.tls.ocsp_response.is_none());
    }

    #[test]
    fn oauth_introspection_configuration_parses_without_exposing_secret() {
        let cfg: Config = toml::from_str(
            r#"[global]
mail_root = "mail"
[security.oauth]
introspection_url = "https://identity.example.test/oauth/introspect"
client_id = "rmail"
client_secret = "top-secret"
required_scopes = ["mail"]
identity_claim = "email"
issuer = "https://identity.example.test/"
audience = "rmail"
timeout_ms = 2500
"#,
        )
        .expect("OAuth configuration");
        let oauth = cfg.security.oauth.expect("OAuth settings");
        assert_eq!(oauth.identity_claim, "email");
        assert_eq!(oauth.required_scopes, ["mail"]);
        assert_eq!(oauth.timeout_ms, 2500);
        assert!(!format!("{oauth:?}").contains("top-secret"));
    }

    #[test]
    fn tls_policy_parses_ocsp_response_path() {
        let cfg: Config = toml::from_str(
            "[global]\nmail_root = \"mail\"\n[global.tls]\nocsp_response = \"/run/rmail/ocsp.der\"\n",
        )
        .expect("config");
        assert_eq!(
            cfg.global.tls.ocsp_response.as_deref(),
            Some("/run/rmail/ocsp.der")
        );
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
submission_require_from_alignment = true
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
        assert!(cfg.security.submission_require_from_alignment);
        assert!(cfg.security.scanners_enabled());
    }

    #[test]
    fn unified_listener_table_supports_concise_dual_stack_configuration() {
        let cfg: Config = toml::from_str(
            r#"
[global]
mail_root = "mail"

[global.tcp_listener]
ipv6_only = false
reuse_port = true
backlog = 256

[global.listeners]
smtp = ["[::]:25"]
lmtp = ["127.0.0.1:24"]
submission = ["127.0.0.1:587"]
imap = ["[::1]:143"]
imaps = []
"#,
        )
        .expect("config");

        assert_eq!(cfg.global.smtp_listeners(), ["[::]:25"]);
        assert_eq!(cfg.global.lmtp_listeners(), ["127.0.0.1:24"]);
        assert_eq!(cfg.global.submission_listeners(), ["127.0.0.1:587"]);
        assert_eq!(cfg.global.imap_listeners(), ["[::1]:143"]);
        assert!(cfg.global.imaps_listeners().is_empty());
        assert!(!cfg.global.tcp_listener.ipv6_only);
        assert!(cfg.global.tcp_listener.reuse_port);
        assert_eq!(cfg.global.tcp_listener.backlog, 256);
    }

    #[test]
    fn legacy_listener_fields_remain_compatible() {
        let cfg: Config = toml::from_str(
            r#"
[global]
mail_root = "mail"
listen_addrs = ["127.0.0.1:2525"]
submission_port = 2587
imap_port = 1143
"#,
        )
        .expect("config");

        assert_eq!(cfg.global.smtp_listeners(), ["127.0.0.1:2525"]);
        assert_eq!(
            cfg.global.submission_listeners(),
            ["0.0.0.0:2587", "[::]:2587"]
        );
        assert_eq!(cfg.global.imap_listeners(), ["0.0.0.0:1143"]);
    }

    #[test]
    fn distributed_example_configs_parse() {
        let example: Config =
            toml::from_str(include_str!("../../../config/example.toml")).expect("example config");
        let test: Config =
            toml::from_str(include_str!("../../../config/test.toml")).expect("test config");

        assert_eq!(example.global.smtp_listeners(), ["[::]:25"]);
        assert_eq!(example.global.tls.minimum_version, TlsMinimumVersion::Tls12);
        assert_eq!(example.global.imap_listeners(), ["[::]:143"]);
        assert_eq!(test.global.smtp_listeners().len(), 2);
        assert_eq!(test.global.tcp_listener.backlog, 128);
    }
}
