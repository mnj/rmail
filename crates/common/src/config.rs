use crate::net::TcpListenerConfig;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Global {
    pub mail_root: String,
    /// Fully qualified domain name this server announces in SMTP/LMTP
    /// greetings, EHLO/HELO and Received headers. Defaults to the system
    /// hostname; see [`Global::server_hostname`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
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
    /// error, warn, info (default) or debug.
    #[serde(default = "default_log_level")]
    pub log_level: Option<String>,
    /// Optional SQLite database path for mailboxes/catchalls
    pub db_path: Option<String>,
    /// Optional web admin username for the lightweight web UI
    pub web_admin_user: Option<String>,
    /// Argon2 password hash for administrative web UI access (optional)
    pub web_admin_password_hash: Option<String>,
    /// Base URL that plain-HTTP requests on `listeners.http` are redirected
    /// to. Empty redirects to `https://` on the requested host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_redirect_url: Option<String>,
    /// If true, enforce DMARC policies (reject/quarantine) at SMTP time for inbound mail
    pub enforce_dmarc: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
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

#[derive(Debug, Default, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
pub enum TlsMinimumVersion {
    #[default]
    #[serde(rename = "1.2")]
    Tls12,
    #[serde(rename = "1.3")]
    Tls13,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
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

fn default_log_level() -> Option<String> {
    Some("info".to_string())
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

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
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
    /// Plain-HTTP listeners (usually port 80) served by the admin daemon:
    /// ACME http-01 challenges, and a redirect to HTTPS for everything else.
    pub http: Option<Vec<String>>,
}

/// The kernel's hostname, canonicalized as a DNS name, or `localhost` when
/// it cannot be read or is not a valid domain name.
pub fn system_hostname() -> String {
    ["/proc/sys/kernel/hostname", "/etc/hostname"]
        .iter()
        .filter_map(|source| fs::read_to_string(source).ok())
        .find_map(|text| crate::domain::canonicalize_domain(text.trim()).ok())
        .unwrap_or_else(|| "localhost".to_string())
}

impl Global {
    /// Name used for the server's SMTP identity (RFC 5321 sections 4.1.1.1,
    /// 4.2 and 4.4): the configured `hostname`, or the system hostname.
    pub fn server_hostname(&self) -> String {
        self.hostname
            .as_deref()
            .and_then(|name| crate::domain::canonicalize_domain(name.trim()).ok())
            .unwrap_or_else(system_hostname)
    }

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

    pub fn http_listeners(&self) -> Vec<String> {
        self.listeners.http.clone().unwrap_or_default()
    }

    pub fn webmail_listeners(&self) -> Vec<String> {
        self.listeners
            .webmail
            .clone()
            .or_else(|| self.webmail_listen_addrs.clone())
            .unwrap_or_else(|| vec![format!("127.0.0.1:{}", self.webmail_port.unwrap_or(8081))])
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    pub global: Global,
    #[serde(default)]
    pub security: SecurityConfig,
    /// Local-model mail organization (the `rmail_classifier` daemon).
    #[serde(default)]
    pub classifier: ClassifierConfig,
    /// Automatic certificates from an ACME CA such as Let's Encrypt.
    #[serde(default)]
    pub acme: AcmeConfig,
    /// Revision of the database-managed settings this config was built from.
    /// Zero when the config came from a file only.
    #[serde(skip)]
    pub settings_revision: u64,
}

/// A configuration value that must never appear in logs or `Debug` output.
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(transparent)]
pub struct SecretString(pub String);

impl SecretString {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
pub enum AcmeCa {
    #[default]
    #[serde(rename = "letsencrypt")]
    LetsEncrypt,
    #[serde(rename = "letsencrypt-staging")]
    LetsEncryptStaging,
    #[serde(rename = "zerossl")]
    ZeroSsl,
    #[serde(rename = "custom")]
    Custom,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
pub enum AcmeChallenge {
    #[default]
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsProviderKind {
    Cloudflare,
    DigitalOcean,
    Desec,
    Gandi,
    Route53,
    Rfc2136,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
pub enum TsigAlgorithm {
    #[default]
    #[serde(rename = "hmac-sha256")]
    HmacSha256,
    #[serde(rename = "hmac-sha512")]
    HmacSha512,
}

/// Automatic certificate management (RFC 8555). Certificates are written to
/// `global.tls_cert` / `global.tls_key`, which every TLS service reloads when
/// the files change.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct AcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Names on the certificate. Empty uses the server hostname.
    #[serde(default)]
    pub domains: Vec<String>,
    /// Contact address registered with the CA for account notices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default)]
    pub ca: AcmeCa,
    /// ACME directory URL when `ca` is `custom`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_url: Option<String>,
    /// External account binding (required by ZeroSSL and some private CAs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eab_kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eab_hmac_key: Option<SecretString>,
    #[serde(default)]
    pub challenge: AcmeChallenge,
    #[serde(default)]
    pub dns: AcmeDnsConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AcmeDnsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<DnsProviderKind>,
    /// API token for Cloudflare, DigitalOcean, deSEC and Gandi.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_token: Option<SecretString>,
    /// Zone holding the challenge records. Empty discovers it from DNS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws_access_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws_secret_access_key: Option<SecretString>,
    /// Primary name server accepting RFC 2136 updates, as `host` or `host:port`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rfc2136_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsig_key_name: Option<String>,
    /// Base64 TSIG secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsig_secret: Option<SecretString>,
    #[serde(default)]
    pub tsig_algorithm: TsigAlgorithm,
    /// How long to wait for the TXT record to appear on every authoritative
    /// name server before asking the CA to validate.
    #[serde(default = "default_dns_propagation_timeout_seconds")]
    pub propagation_timeout_seconds: u64,
}

impl Default for AcmeDnsConfig {
    fn default() -> Self {
        Self {
            provider: None,
            api_token: None,
            zone: None,
            aws_access_key_id: None,
            aws_secret_access_key: None,
            rfc2136_server: None,
            tsig_key_name: None,
            tsig_secret: None,
            tsig_algorithm: TsigAlgorithm::default(),
            propagation_timeout_seconds: default_dns_propagation_timeout_seconds(),
        }
    }
}

fn default_dns_propagation_timeout_seconds() -> u64 {
    180
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScannerFailureAction {
    Tempfail,
    Accept,
    Reject,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
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

#[derive(Deserialize, Serialize, Clone)]
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
        "SCRAM-SHA-256-PLUS".to_string(),
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

/// Settings for the `rmail_classifier` daemon, which suggests folders for new
/// INBOX mail using local GGUF models stored under `<mail_root>/models`.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct ClassifierConfig {
    #[serde(default)]
    pub enabled: bool,
    /// File name of the embedding model in the models directory; empty disables
    /// classification.
    #[serde(default)]
    pub embed_model: String,
    /// File name of the optional chat model used when the embedding vote is
    /// not confident; empty disables the fallback.
    #[serde(default)]
    pub chat_model: String,
    /// Inference threads; zero picks the number of CPUs.
    #[serde(default)]
    pub threads: u32,
    #[serde(default = "default_classifier_poll_interval_seconds")]
    pub poll_interval_seconds: u64,
    /// Most recent messages per folder learned when an account opts in.
    #[serde(default = "default_classifier_backfill_per_folder")]
    pub backfill_per_folder: u32,
    /// Bytes of message text given to the models.
    #[serde(default = "default_classifier_max_input_bytes")]
    pub max_input_bytes: usize,
    /// Minimum embedding vote (percent) before a folder is suggested without
    /// asking the chat model.
    #[serde(default = "default_classifier_knn_confidence")]
    pub knn_confidence: u32,
    /// Minimum confidence (percent) before a message is moved automatically
    /// into a folder the user enabled auto-move for.
    #[serde(default = "default_classifier_autofile_confidence")]
    pub autofile_confidence: u32,
    /// Folders with fewer learned messages than this defer to the chat model.
    #[serde(default = "default_classifier_min_examples")]
    pub min_examples: u32,
}

impl Default for ClassifierConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            embed_model: String::new(),
            chat_model: String::new(),
            threads: 0,
            poll_interval_seconds: default_classifier_poll_interval_seconds(),
            backfill_per_folder: default_classifier_backfill_per_folder(),
            max_input_bytes: default_classifier_max_input_bytes(),
            knn_confidence: default_classifier_knn_confidence(),
            autofile_confidence: default_classifier_autofile_confidence(),
            min_examples: default_classifier_min_examples(),
        }
    }
}

fn default_classifier_poll_interval_seconds() -> u64 {
    15
}
fn default_classifier_backfill_per_folder() -> u32 {
    300
}
fn default_classifier_max_input_bytes() -> usize {
    2048
}
fn default_classifier_knn_confidence() -> u32 {
    60
}
fn default_classifier_autofile_confidence() -> u32 {
    85
}
fn default_classifier_min_examples() -> u32 {
    5
}

impl Config {
    /// Directory holding downloaded classifier models.
    pub fn models_dir(&self) -> std::path::PathBuf {
        crate::classifier_models::models_dir(Path::new(&self.global.mail_root))
    }

    /// Unix socket the classifier daemon accepts control commands on.
    pub fn classifier_socket(&self) -> std::path::PathBuf {
        crate::classifier_control::socket_path(Path::new(&self.global.mail_root))
    }

    /// Parse a TOML file as-is, without consulting the settings database.
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Config> {
        let s = fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&s)?;
        Ok(cfg)
    }

    /// Load the effective configuration for a daemon.
    ///
    /// When the file names a `db_path`, the file only bootstraps `mail_root`
    /// and `db_path`; every other setting lives in the database (see
    /// [`crate::settings`]). File values are imported into an empty database
    /// once. Without a `db_path` the file is used as-is.
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Config> {
        let path = path.as_ref();
        let text = fs::read_to_string(path)
            .map_err(|error| anyhow::anyhow!("reading {}: {error}", path.display()))?;
        let root: toml::Value = toml::from_str(&text)
            .map_err(|error| anyhow::anyhow!("parsing {}: {error}", path.display()))?;
        let file = serde_json::to_value(root)?;
        crate::settings::resolve_config(file, &path.display().to_string())
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
            ["PLAIN", "LOGIN", "SCRAM-SHA-256", "SCRAM-SHA-256-PLUS"]
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
    fn example_config_imports_into_settings_database() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("rmail.db");
        let text = include_str!("../../../config/example.toml").replace(
            "db_path = \"config/rmail.db\"",
            &format!("db_path = {:?}", db.display().to_string()),
        );
        let path = dir.path().join("rmail.toml");
        std::fs::write(&path, text).unwrap();
        let first = Config::load(&path).expect("first load imports the file");
        assert_eq!(first.global.smtp_listeners(), ["[::]:25"]);
        assert_eq!(first.settings_revision, 1);
        // A file trimmed to the bootstrap keys yields the same configuration.
        std::fs::write(
            &path,
            format!(
                "[global]\nmail_root = \"mail\"\ndb_path = {:?}\n",
                db.display().to_string()
            ),
        )
        .unwrap();
        let second = Config::load(&path).expect("bootstrap-only load");
        assert_eq!(second.global.smtp_listeners(), ["[::]:25"]);
        assert_eq!(
            second.security.smtp_max_recipients,
            first.security.smtp_max_recipients
        );
        assert_eq!(second.global.tls_cert, first.global.tls_cert);
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
