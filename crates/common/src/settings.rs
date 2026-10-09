//! Database-managed runtime settings.
//!
//! The configuration file only bootstraps `global.mail_root` and
//! `global.db_path`. Every other setting is stored as a flattened
//! `section.key` → JSON row in the `settings` table, which is the single
//! source of truth that the admin web UI and `rmail_ctl settings` edit. Other
//! values in the file are ignored (a warning names them).
//!
//! Daemons read settings at startup and record the revision they loaded in
//! `service_state`, so the admin UI can show which services need a restart.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
pub use rusqlite::Connection;
use rusqlite::{OptionalExtension, params};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::config::Config;

/// Keys that must stay in the configuration file.
pub const BOOTSTRAP_KEYS: &[&str] = &["global.mail_root", "global.db_path"];

/// Keys managed through dedicated flows rather than the generic settings
/// editor. Their values are never returned by [`describe`].
pub const RESERVED_KEYS: &[&str] = &[
    "global.web_admin_user",
    "global.web_admin_password_hash",
    "global.webmail_session_secret",
];

/// Internal values (session signing keys and similar) live under this prefix
/// and are never part of the [`Config`] tree.
pub const INTERNAL_PREFIX: &str = "internal.";

pub const SERVICES: &[&str] = &["smtpd", "imapd", "outbound", "web", "webmail", "classifier"];

const SMTP: &[&str] = &["smtpd"];
const IMAP: &[&str] = &["imapd"];
const MAIL: &[&str] = &["smtpd", "imapd"];
const ALL_TLS: &[&str] = &["smtpd", "imapd", "web", "webmail"];
const ALL_LISTENERS: &[&str] = &["smtpd", "imapd", "web", "webmail"];
const TRACKING: &[&str] = &["smtpd", "outbound"];
const SMTP_IDENTITY: &[&str] = &["smtpd", "outbound"];
const WEB: &[&str] = &["web"];
const WEBMAIL: &[&str] = &["webmail"];
const CLASSIFIER: &[&str] = &["classifier"];
const OUTBOUND: &[&str] = &["outbound"];
const ALL: &[&str] = &["smtpd", "imapd", "outbound", "web", "webmail", "classifier"];
/// Read on every use; no restart needed.
const LIVE: &[&str] = &[];

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SettingKind {
    Bool,
    Integer {
        min: i64,
        max: i64,
    },
    Text,
    /// Write-only value; reads only report whether it is set.
    Secret,
    List,
    /// List of `ip:port` socket addresses.
    AddressList,
    Choice {
        options: &'static [&'static str],
    },
    MultiChoice {
        options: &'static [&'static str],
    },
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct SettingSpec {
    pub key: &'static str,
    pub group: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    pub kind: SettingKind,
    /// Daemons that read this setting at startup.
    pub services: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct SettingGroup {
    pub id: &'static str,
    pub label: &'static str,
    pub description: &'static str,
}

pub const GROUPS: &[SettingGroup] = &[
    SettingGroup {
        id: "identity",
        label: "Server identity",
        description: "How this server names itself to other mail systems.",
    },
    SettingGroup {
        id: "network",
        label: "Listeners",
        description: "Socket addresses each service binds. Use [::]:port for dual-stack wildcards.",
    },
    SettingGroup {
        id: "tls",
        label: "TLS",
        description: "Certificates and protocol policy shared by every TLS listener.",
    },
    SettingGroup {
        id: "acme",
        label: "Certificates (ACME)",
        description: "Automatic certificates from Let's Encrypt or another ACME CA. Managed on the Certificates page; changes apply without a restart.",
    },
    SettingGroup {
        id: "auth",
        label: "Authentication",
        description: "SASL mechanisms offered to IMAP and SMTP clients and submission policy.",
    },
    SettingGroup {
        id: "limits",
        label: "Rate limits",
        description: "Resource-exhaustion controls for IMAP and SMTP listeners.",
    },
    SettingGroup {
        id: "filtering",
        label: "Content filtering",
        description: "Virus and spam scanning for inbound mail.",
    },
    SettingGroup {
        id: "policy",
        label: "Mail policy",
        description: "Inbound authentication policy enforcement.",
    },
    SettingGroup {
        id: "oauth",
        label: "OAuth",
        description: "RFC 7662 token introspection used by OAUTHBEARER and XOAUTH2. Leave the URL empty to disable.",
    },
    SettingGroup {
        id: "classifier",
        label: "Mail organization",
        description: "Folder suggestions from local or cloud models. Pick models and providers on the Organization page; changes apply without a restart.",
    },
    SettingGroup {
        id: "logging",
        label: "Logging",
        description: "Structured JSON logs written by every daemon, shown on the Logs page.",
    },
    SettingGroup {
        id: "tracking",
        label: "Message tracking",
        description: "Retention of the durable protocol and delivery history.",
    },
];

const IMAP_SASL: &[&str] = &[
    "PLAIN",
    "LOGIN",
    "SCRAM-SHA-256",
    "SCRAM-SHA-256-PLUS",
    "OAUTHBEARER",
    "XOAUTH2",
];
const SMTP_SASL: &[&str] = &[
    "PLAIN",
    "LOGIN",
    "SCRAM-SHA-256",
    "SCRAM-SHA-256-PLUS",
    "OAUTHBEARER",
    "XOAUTH2",
];
const OAUTH_MECHANISMS: &[&str] = &["OAUTHBEARER", "XOAUTH2"];

const fn int(min: i64, max: i64) -> SettingKind {
    SettingKind::Integer { min, max }
}

const fn spec(
    key: &'static str,
    group: &'static str,
    label: &'static str,
    help: &'static str,
    kind: SettingKind,
    services: &'static [&'static str],
) -> SettingSpec {
    SettingSpec {
        key,
        group,
        label,
        help,
        kind,
        services,
    }
}

pub const SETTINGS: &[SettingSpec] = &[
    spec(
        "global.hostname",
        "identity",
        "Hostname",
        "Fully qualified domain name used in the SMTP/LMTP greeting, EHLO/HELO and Received headers. Empty uses the system hostname.",
        SettingKind::Text,
        SMTP_IDENTITY,
    ),
    spec(
        "global.listeners.smtp",
        "network",
        "SMTP",
        "Inbound MX listeners (port 25).",
        SettingKind::AddressList,
        SMTP,
    ),
    spec(
        "global.listeners.submission",
        "network",
        "Submission",
        "Authenticated submission with STARTTLS (port 587).",
        SettingKind::AddressList,
        SMTP,
    ),
    spec(
        "global.listeners.smtps",
        "network",
        "SMTPS",
        "Implicit-TLS submission (port 465).",
        SettingKind::AddressList,
        SMTP,
    ),
    spec(
        "global.listeners.lmtp",
        "network",
        "LMTP",
        "Local delivery endpoints. Bind loopback or a private address only.",
        SettingKind::AddressList,
        SMTP,
    ),
    spec(
        "global.listeners.imap",
        "network",
        "IMAP",
        "IMAP with STARTTLS (port 143).",
        SettingKind::AddressList,
        IMAP,
    ),
    spec(
        "global.listeners.imaps",
        "network",
        "IMAPS",
        "Implicit-TLS IMAP (port 993).",
        SettingKind::AddressList,
        IMAP,
    ),
    spec(
        "global.listeners.pop3",
        "network",
        "POP3",
        "POP3 with STLS (port 110) for legacy clients. Reads the INBOX; needs a TLS certificate for password login off loopback.",
        SettingKind::AddressList,
        IMAP,
    ),
    spec(
        "global.listeners.pop3s",
        "network",
        "POP3S",
        "Implicit-TLS POP3 (port 995).",
        SettingKind::AddressList,
        IMAP,
    ),
    spec(
        "global.listeners.managesieve",
        "network",
        "ManageSieve",
        "Mail filter script management (RFC 5804), STARTTLS (port 4190). Needs a TLS certificate.",
        SettingKind::AddressList,
        IMAP,
    ),
    spec(
        "global.listeners.admin",
        "network",
        "Admin console",
        "This admin console. Non-loopback addresses require an admin password.",
        SettingKind::AddressList,
        WEB,
    ),
    spec(
        "global.listeners.webmail",
        "network",
        "Webmail",
        "User webmail.",
        SettingKind::AddressList,
        WEBMAIL,
    ),
    spec(
        "global.listeners.http",
        "network",
        "Plain HTTP",
        "Usually [::]:80. Answers ACME http-01 challenges and redirects every other request to HTTPS.",
        SettingKind::AddressList,
        WEB,
    ),
    spec(
        "global.http_redirect_url",
        "network",
        "HTTP redirect target",
        "Base URL plain-HTTP requests are redirected to, e.g. https://mail.example.com. Empty keeps the requested host and switches to https://.",
        SettingKind::Text,
        WEB,
    ),
    spec(
        "global.tcp_listener.ipv6_only",
        "network",
        "IPv6-only wildcards",
        "When off, a single [::]:port socket also accepts IPv4.",
        SettingKind::Bool,
        ALL_LISTENERS,
    ),
    spec(
        "global.tcp_listener.reuse_port",
        "network",
        "SO_REUSEPORT",
        "Allow several processes to bind the same sockets.",
        SettingKind::Bool,
        ALL_LISTENERS,
    ),
    spec(
        "global.tcp_listener.backlog",
        "network",
        "Listen backlog",
        "Pending-connection queue length per socket.",
        int(1, 65_535),
        ALL_LISTENERS,
    ),
    spec(
        "global.tls_cert",
        "tls",
        "Certificate chain",
        "PEM certificate chain path. Reloaded on SIGHUP.",
        SettingKind::Text,
        ALL_TLS,
    ),
    spec(
        "global.tls_key",
        "tls",
        "Private key",
        "PEM private key path. Reloaded on SIGHUP.",
        SettingKind::Text,
        ALL_TLS,
    ),
    spec(
        "global.tls.minimum_version",
        "tls",
        "Minimum TLS version",
        "Oldest protocol version accepted.",
        SettingKind::Choice {
            options: &["1.2", "1.3"],
        },
        ALL_TLS,
    ),
    spec(
        "global.tls.cipher_suites",
        "tls",
        "Cipher suites",
        "Rustls suite names. Empty uses the safe Rustls defaults.",
        SettingKind::List,
        ALL_TLS,
    ),
    spec(
        "global.tls.ocsp_response",
        "tls",
        "OCSP response",
        "Path to a DER OCSP response to staple.",
        SettingKind::Text,
        ALL_TLS,
    ),
    spec(
        "global.tls.web_http_only",
        "tls",
        "Web behind TLS proxy",
        "Serve admin and webmail over plain HTTP because a reverse proxy terminates HTTPS.",
        SettingKind::Bool,
        &["web", "webmail"],
    ),
    spec(
        "acme.enabled",
        "acme",
        "Automatic certificates",
        "Request the TLS certificate from the CA below and renew it automatically. It is written to the certificate and key paths (or <mail_root>/tls/ when unset) and every service reloads it when it changes.",
        SettingKind::Bool,
        LIVE,
    ),
    spec(
        "acme.domains",
        "acme",
        "Certificate names",
        "One name per line; the first becomes the subject. Empty uses the server hostname. Wildcards (*.example.com) need the DNS challenge.",
        SettingKind::List,
        LIVE,
    ),
    spec(
        "acme.email",
        "acme",
        "Contact email",
        "Registered with the CA for account and policy notices. Optional.",
        SettingKind::Text,
        LIVE,
    ),
    spec(
        "acme.ca",
        "acme",
        "Certificate authority",
        "Let's Encrypt staging issues untrusted test certificates.",
        SettingKind::Choice {
            options: &["letsencrypt", "letsencrypt-staging", "zerossl", "custom"],
        },
        LIVE,
    ),
    spec(
        "acme.directory_url",
        "acme",
        "Directory URL",
        "ACME directory of a custom CA, e.g. https://ca.internal/acme/acme/directory.",
        SettingKind::Text,
        LIVE,
    ),
    spec(
        "acme.eab_kid",
        "acme",
        "EAB key ID",
        "External account binding key ID. Required by ZeroSSL.",
        SettingKind::Text,
        LIVE,
    ),
    spec(
        "acme.eab_hmac_key",
        "acme",
        "EAB HMAC key",
        "External account binding HMAC key (base64url), used once when the account is registered.",
        SettingKind::Secret,
        LIVE,
    ),
    spec(
        "acme.challenge",
        "acme",
        "Challenge",
        "http-01 needs port 80 reachable from the internet; dns-01 publishes a TXT record through the DNS provider.",
        SettingKind::Choice {
            options: &["http-01", "dns-01"],
        },
        LIVE,
    ),
    spec(
        "acme.dns.provider",
        "acme",
        "DNS provider",
        "Where the _acme-challenge TXT records are published.",
        SettingKind::Choice {
            options: &[
                "cloudflare",
                "digitalocean",
                "desec",
                "gandi",
                "route53",
                "rfc2136",
            ],
        },
        LIVE,
    ),
    spec(
        "acme.dns.api_token",
        "acme",
        "API token",
        "Cloudflare (Zone:Read and DNS:Edit), DigitalOcean, deSEC or Gandi personal access token.",
        SettingKind::Secret,
        LIVE,
    ),
    spec(
        "acme.dns.zone",
        "acme",
        "DNS zone",
        "Zone that holds the challenge records. Empty finds it from DNS.",
        SettingKind::Text,
        LIVE,
    ),
    spec(
        "acme.dns.aws_access_key_id",
        "acme",
        "AWS access key ID",
        "Route 53 credentials; the key needs route53:ListHostedZonesByName and route53:ChangeResourceRecordSets.",
        SettingKind::Text,
        LIVE,
    ),
    spec(
        "acme.dns.aws_secret_access_key",
        "acme",
        "AWS secret access key",
        "",
        SettingKind::Secret,
        LIVE,
    ),
    spec(
        "acme.dns.rfc2136_server",
        "acme",
        "Update server",
        "Primary name server accepting RFC 2136 updates, as host or host:port.",
        SettingKind::Text,
        LIVE,
    ),
    spec(
        "acme.dns.tsig_key_name",
        "acme",
        "TSIG key name",
        "",
        SettingKind::Text,
        LIVE,
    ),
    spec(
        "acme.dns.tsig_secret",
        "acme",
        "TSIG secret",
        "Base64 secret, as in the BIND key file.",
        SettingKind::Secret,
        LIVE,
    ),
    spec(
        "acme.dns.tsig_algorithm",
        "acme",
        "TSIG algorithm",
        "",
        SettingKind::Choice {
            options: &["hmac-sha256", "hmac-sha512"],
        },
        LIVE,
    ),
    spec(
        "acme.dns.propagation_timeout_seconds",
        "acme",
        "Propagation timeout (s)",
        "How long to wait for the TXT record on every authoritative name server.",
        int(10, 3_600),
        LIVE,
    ),
    spec(
        "security.imap_sasl_mechanisms",
        "auth",
        "IMAP mechanisms",
        "PLAIN and LOGIN are only offered over TLS.",
        SettingKind::MultiChoice { options: IMAP_SASL },
        IMAP,
    ),
    spec(
        "security.smtp_sasl_mechanisms",
        "auth",
        "SMTP mechanisms",
        "PLAIN and LOGIN are only offered over TLS.",
        SettingKind::MultiChoice { options: SMTP_SASL },
        SMTP,
    ),
    spec(
        "security.submission_require_from_alignment",
        "auth",
        "Require From alignment",
        "Every From address on submitted mail must match the authenticated mailbox.",
        SettingKind::Bool,
        SMTP,
    ),
    spec(
        "security.admin_password_policy.min_length",
        "auth",
        "Admin password: minimum length",
        "Applies when the admin password is set or changed.",
        int(1, 1_024),
        LIVE,
    ),
    spec(
        "security.admin_password_policy.max_length",
        "auth",
        "Admin password: maximum length",
        "Upper bound in characters.",
        int(1, 1_024),
        LIVE,
    ),
    spec(
        "security.admin_password_policy.require_lowercase",
        "auth",
        "Admin password: require lowercase",
        "",
        SettingKind::Bool,
        LIVE,
    ),
    spec(
        "security.admin_password_policy.require_uppercase",
        "auth",
        "Admin password: require uppercase",
        "",
        SettingKind::Bool,
        LIVE,
    ),
    spec(
        "security.admin_password_policy.require_digit",
        "auth",
        "Admin password: require digit",
        "",
        SettingKind::Bool,
        LIVE,
    ),
    spec(
        "security.admin_password_policy.require_symbol",
        "auth",
        "Admin password: require symbol",
        "",
        SettingKind::Bool,
        LIVE,
    ),
    spec(
        "security.admin_password_policy.forbid_username",
        "auth",
        "Admin password: forbid username",
        "Reject passwords that contain the admin username.",
        SettingKind::Bool,
        LIVE,
    ),
    spec(
        "security.imap_max_concurrent_sessions",
        "limits",
        "IMAP concurrent sessions",
        "",
        int(1, 1_000_000),
        IMAP,
    ),
    spec(
        "security.imap_max_connections_per_minute",
        "limits",
        "IMAP connections / minute / IP",
        "",
        int(1, 1_000_000),
        IMAP,
    ),
    spec(
        "security.imap_max_commands_per_minute",
        "limits",
        "IMAP commands / minute / session",
        "",
        int(1, 1_000_000),
        IMAP,
    ),
    spec(
        "security.smtp_max_concurrent_sessions",
        "limits",
        "SMTP concurrent sessions",
        "",
        int(1, 1_000_000),
        SMTP,
    ),
    spec(
        "security.smtp_max_connections_per_minute",
        "limits",
        "SMTP connections / minute / IP",
        "",
        int(1, 1_000_000),
        SMTP,
    ),
    spec(
        "security.smtp_max_commands_per_minute",
        "limits",
        "SMTP commands / minute / session",
        "",
        int(1, 1_000_000),
        SMTP,
    ),
    spec(
        "security.smtp_max_recipients",
        "limits",
        "SMTP recipients / message",
        "",
        int(1, 100_000),
        SMTP,
    ),
    spec(
        "security.submission_max_recipients",
        "limits",
        "Submission recipients / message",
        "",
        int(1, 100_000),
        SMTP,
    ),
    spec(
        "security.submission_max_messages_per_minute",
        "limits",
        "Submitted messages / minute / user",
        "",
        int(1, 1_000_000),
        SMTP,
    ),
    spec(
        "security.submission_max_messages_per_user_per_day",
        "limits",
        "Messages per account per day",
        "Caps steady sending from one account, e.g. a compromised one. 0 means unlimited.",
        int(0, 10_000_000),
        SMTP,
    ),
    spec(
        "security.submission_max_messages_per_domain_per_hour",
        "limits",
        "Messages per domain per hour",
        "Caps all accounts of one sending domain together. 0 means unlimited.",
        int(0, 10_000_000),
        SMTP,
    ),
    spec(
        "security.clamav_enabled",
        "filtering",
        "ClamAV",
        "Scan inbound mail with clamd.",
        SettingKind::Bool,
        SMTP,
    ),
    spec(
        "security.clamav_endpoint",
        "filtering",
        "ClamAV endpoint",
        "unix:/path/to/socket or tcp:host:port.",
        SettingKind::Text,
        SMTP,
    ),
    spec(
        "security.rspamd_enabled",
        "filtering",
        "Rspamd",
        "Score inbound mail with rspamd.",
        SettingKind::Bool,
        SMTP,
    ),
    spec(
        "security.rspamd_url",
        "filtering",
        "Rspamd URL",
        "rspamd /checkv2 endpoint.",
        SettingKind::Text,
        SMTP,
    ),
    spec(
        "security.rspamd_quarantine_actions",
        "filtering",
        "Quarantine actions",
        "Rspamd actions that deliver to Junk.",
        SettingKind::List,
        SMTP,
    ),
    spec(
        "security.rspamd_reject_actions",
        "filtering",
        "Reject actions",
        "Rspamd actions that reject at SMTP time.",
        SettingKind::List,
        SMTP,
    ),
    spec(
        "security.mta_sts_mode",
        "tls",
        "MTA-STS policy",
        "Publish an MTA-STS policy for hosted domains. Needs an mta-sts.<domain> DNS name and a trusted certificate. Start with testing.",
        SettingKind::Choice {
            options: &["none", "testing", "enforce"],
        },
        LIVE,
    ),
    spec(
        "security.mta_sts_max_age_secs",
        "tls",
        "MTA-STS max age (s)",
        "How long senders cache the policy.",
        int(60, 31_557_600),
        LIVE,
    ),
    spec(
        "security.tls_rpt_enabled",
        "tls",
        "SMTP TLS reports",
        "Send daily TLS reports (RFC 8460) to domains that publish a _smtp._tls record, covering sessions checked against their MTA-STS policy.",
        SettingKind::Bool,
        OUTBOUND,
    ),
    spec(
        "security.dane_enabled",
        "tls",
        "Outbound DANE",
        "Authenticate recipient MX hosts with DNSSEC-signed TLSA records (RFC 7672). Requires a resolver that passes DNSSEC records; signed domains are deferred if it strips them.",
        SettingKind::Bool,
        OUTBOUND,
    ),
    spec(
        "security.greylist_enabled",
        "filtering",
        "Greylisting",
        "Defer the first delivery from unknown sender/recipient/network triples on inbound SMTP.",
        SettingKind::Bool,
        SMTP,
    ),
    spec(
        "security.greylist_delay_secs",
        "filtering",
        "Greylist delay (s)",
        "Minimum wait before a deferred triple is accepted.",
        int(1, 86_400),
        SMTP,
    ),
    spec(
        "security.greylist_persist_interval_secs",
        "filtering",
        "Greylist save interval (s)",
        "How often changed greylist state is written to disk. Changes are batched; nothing is written while idle.",
        int(10, 86_400),
        SMTP,
    ),
    spec(
        "security.srs_domain",
        "filtering",
        "SRS domain",
        "Rewrite the envelope sender of mail forwarded by aliases, catchalls and Sieve redirects into this domain (Sender Rewriting Scheme), so SPF passes at the next hop, and return bounces to the original sender. The domain's MX and SPF must point at this server. Empty disables SRS.",
        SettingKind::Text,
        SMTP,
    ),
    spec(
        "security.imap_message_limit",
        "limits",
        "IMAP message limit",
        "Most messages one IMAP command may touch (RFC 9738 MESSAGELIMIT, at least 1000). Larger FETCH, STORE, SEARCH and MOVE commands handle the newest messages and tell the client where to continue; larger COPY and APPEND are refused. Clients that do not know the extension see partial results, so 0 (no limit) is the default.",
        int(0, 100_000_000),
        IMAP,
    ),
    spec(
        "security.proxy_protocol_trusted_networks",
        "limits",
        "PROXY protocol networks",
        "Load balancer addresses or networks (e.g. 10.0.0.0/8), one per line. Their SMTP, IMAP, POP3 and ManageSieve connections must start with a HAProxy PROXY header (v1 or v2) carrying the client address. Empty disables it.",
        SettingKind::List,
        MAIL,
    ),
    spec(
        "security.dnsbl_zones",
        "filtering",
        "DNS blocklists",
        "Blocklist zones (e.g. zen.spamhaus.org). Listed clients are rejected at MAIL FROM; lookup failures never block mail.",
        SettingKind::List,
        SMTP,
    ),
    spec(
        "security.dnsbl_timeout_ms",
        "filtering",
        "DNSBL timeout (ms)",
        "",
        int(100, 30_000),
        SMTP,
    ),
    spec(
        "security.scanner_failure_action",
        "filtering",
        "When a scanner fails",
        "tempfail asks the sender to retry later.",
        SettingKind::Choice {
            options: &["tempfail", "accept", "reject"],
        },
        SMTP,
    ),
    spec(
        "security.scanner_timeout_ms",
        "filtering",
        "Scanner timeout (ms)",
        "",
        int(1, 600_000),
        SMTP,
    ),
    spec(
        "security.scanner_max_message_bytes",
        "filtering",
        "Max scanned size (bytes)",
        "Larger messages skip scanning.",
        int(1, i64::MAX),
        SMTP,
    ),
    spec(
        "global.enforce_dmarc",
        "policy",
        "Enforce DMARC",
        "Apply sender DMARC reject/quarantine policies at SMTP time.",
        SettingKind::Bool,
        SMTP,
    ),
    spec(
        "security.oauth.introspection_url",
        "oauth",
        "Introspection URL",
        "HTTPS RFC 7662 endpoint.",
        SettingKind::Text,
        MAIL,
    ),
    spec(
        "security.oauth.client_id",
        "oauth",
        "Client ID",
        "",
        SettingKind::Text,
        MAIL,
    ),
    spec(
        "security.oauth.client_secret",
        "oauth",
        "Client secret",
        "",
        SettingKind::Secret,
        MAIL,
    ),
    spec(
        "security.oauth.required_scopes",
        "oauth",
        "Required scopes",
        "",
        SettingKind::List,
        MAIL,
    ),
    spec(
        "security.oauth.identity_claim",
        "oauth",
        "Identity claim",
        "Token claim that names the mailbox.",
        SettingKind::Choice {
            options: &["username", "sub", "email"],
        },
        MAIL,
    ),
    spec(
        "security.oauth.issuer",
        "oauth",
        "Issuer",
        "Expected iss claim.",
        SettingKind::Text,
        MAIL,
    ),
    spec(
        "security.oauth.audience",
        "oauth",
        "Audience",
        "Expected aud claim.",
        SettingKind::Text,
        MAIL,
    ),
    spec(
        "security.oauth.timeout_ms",
        "oauth",
        "Timeout (ms)",
        "",
        int(1, 600_000),
        MAIL,
    ),
    spec(
        "security.oauth.allow_insecure_http",
        "oauth",
        "Allow plain HTTP",
        "Only for a loopback identity provider.",
        SettingKind::Bool,
        MAIL,
    ),
    spec(
        "classifier.enabled",
        "classifier",
        "Enabled",
        "Run the classifier for accounts that opt in from webmail.",
        SettingKind::Bool,
        CLASSIFIER,
    ),
    spec(
        "classifier.label_confidence",
        "classifier",
        "Label confidence (%)",
        "Minimum probability before a label is applied. Labels use the fallback model.",
        int(1, 100),
        CLASSIFIER,
    ),
    spec(
        "classifier.label_discovery",
        "classifier",
        "AI-created labels",
        "Let the local or OpenRouter chat model create a new label when none fits (Jev only picks existing labels). Labels users remove are not created again.",
        SettingKind::Bool,
        CLASSIFIER,
    ),
    spec(
        "classifier.embed_provider",
        "classifier",
        "Embedding provider",
        "local runs a model on this server. openrouter sends the text of every message learned or classified to OpenRouter, only for users who agreed to it in webmail.",
        SettingKind::Choice {
            options: &["local", "openrouter"],
        },
        CLASSIFIER,
    ),
    spec(
        "classifier.embed_model",
        "classifier",
        "Embedding model",
        "File name in the models directory (local provider).",
        SettingKind::Text,
        CLASSIFIER,
    ),
    spec(
        "classifier.chat_provider",
        "classifier",
        "Fallback provider",
        "Where uncertain messages are decided. jev is TypeSafe's decision model, which picks one folder with a confidence instead of generating text. Cloud providers only see mail of users who agreed to them in webmail.",
        SettingKind::Choice {
            options: &["local", "openrouter", "jev"],
        },
        CLASSIFIER,
    ),
    spec(
        "classifier.chat_model",
        "classifier",
        "Chat model",
        "File name in the models directory (local provider). Empty disables the fallback.",
        SettingKind::Text,
        CLASSIFIER,
    ),
    spec(
        "classifier.openrouter_api_key",
        "classifier",
        "OpenRouter API key",
        "From openrouter.ai/settings/keys.",
        SettingKind::Secret,
        CLASSIFIER,
    ),
    spec(
        "classifier.openrouter_base_url",
        "classifier",
        "OpenRouter API base",
        "Any OpenAI-compatible endpoint works, such as a self-hosted vLLM or Ollama.",
        SettingKind::Text,
        CLASSIFIER,
    ),
    spec(
        "classifier.openrouter_embed_model",
        "classifier",
        "OpenRouter embedding model",
        "Model id, e.g. openai/text-embedding-3-small. Changing it relearns every opted-in mailbox.",
        SettingKind::Text,
        CLASSIFIER,
    ),
    spec(
        "classifier.openrouter_chat_model",
        "classifier",
        "OpenRouter chat model",
        "Model id for the fallback, e.g. openai/gpt-4.1-mini. Empty disables it.",
        SettingKind::Text,
        CLASSIFIER,
    ),
    spec(
        "classifier.typesafe_api_key",
        "classifier",
        "TypeSafe API key",
        "For the jev fallback provider.",
        SettingKind::Secret,
        CLASSIFIER,
    ),
    spec(
        "classifier.jev_model",
        "classifier",
        "Jev model",
        "jev-latest follows TypeSafe's current release.",
        SettingKind::Text,
        CLASSIFIER,
    ),
    spec(
        "classifier.threads",
        "classifier",
        "Inference threads",
        "Zero uses every CPU.",
        int(0, 256),
        CLASSIFIER,
    ),
    spec(
        "classifier.poll_interval_seconds",
        "classifier",
        "Poll interval (s)",
        "How often mailboxes are checked for new mail.",
        int(1, 3_600),
        CLASSIFIER,
    ),
    spec(
        "classifier.backfill_per_folder",
        "classifier",
        "Backfill per folder",
        "Recent messages learned from each folder when an account opts in.",
        int(0, 100_000),
        CLASSIFIER,
    ),
    spec(
        "classifier.max_input_bytes",
        "classifier",
        "Max input (bytes)",
        "Message text given to the models.",
        int(256, 65_536),
        CLASSIFIER,
    ),
    spec(
        "classifier.knn_confidence",
        "classifier",
        "Suggestion confidence (%)",
        "Below this the chat model is asked, when one is configured.",
        int(1, 100),
        CLASSIFIER,
    ),
    spec(
        "classifier.autofile_confidence",
        "classifier",
        "Auto-move confidence (%)",
        "Minimum confidence to move mail into folders users enabled auto-move for.",
        int(1, 100),
        CLASSIFIER,
    ),
    spec(
        "classifier.min_examples",
        "classifier",
        "Minimum examples",
        "Folders with fewer learned messages defer to the chat model.",
        int(1, 1_000),
        CLASSIFIER,
    ),
    spec(
        "global.log_level",
        "logging",
        "Log level",
        "debug adds per-transaction detail such as MAIL FROM and DATA start.",
        SettingKind::Choice {
            options: &["error", "warn", "info", "debug"],
        },
        ALL,
    ),
    spec(
        "global.tracking.retention_days",
        "tracking",
        "Retention (days)",
        "Zero disables age pruning.",
        int(0, 36_500),
        TRACKING,
    ),
    spec(
        "global.tracking.max_events",
        "tracking",
        "Maximum events",
        "Zero disables count pruning.",
        int(0, i64::MAX),
        TRACKING,
    ),
    spec(
        "global.tracking.prune_interval_seconds",
        "tracking",
        "Prune interval (s)",
        "",
        int(1, 86_400 * 7),
        TRACKING,
    ),
    spec(
        "global.tracking.prune_batch_size",
        "tracking",
        "Prune batch size",
        "",
        int(1, 10_000_000),
        TRACKING,
    ),
];

pub fn spec_for(key: &str) -> Option<&'static SettingSpec> {
    SETTINGS.iter().find(|spec| spec.key == key)
}

// ---------------------------------------------------------------------------
// Storage

pub fn open(db_path: impl AsRef<Path>) -> Result<Connection> {
    let db_path = db_path.as_ref();
    let conn = Connection::open(db_path)
        .with_context(|| format!("opening settings database {}", db_path.display()))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    ensure_schema(&conn)?;
    Ok(conn)
}

pub fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS settings (
             key TEXT PRIMARY KEY,
             value TEXT NOT NULL,
             updated_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS settings_meta (
             id INTEGER PRIMARY KEY CHECK (id = 1),
             revision INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS settings_changes (
             revision INTEGER NOT NULL,
             key TEXT NOT NULL,
             PRIMARY KEY (revision, key)
         );
         CREATE TABLE IF NOT EXISTS service_state (
             service TEXT PRIMARY KEY,
             pid INTEGER NOT NULL,
             host TEXT,
             started_at INTEGER NOT NULL,
             settings_revision INTEGER NOT NULL
         );",
    )?;
    Ok(())
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

pub fn revision(conn: &Connection) -> Result<u64> {
    let revision: Option<i64> = conn
        .query_row(
            "SELECT revision FROM settings_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(revision.unwrap_or(0) as u64)
}

pub fn load_all(conn: &Connection) -> Result<BTreeMap<String, Value>> {
    let mut stmt = conn.prepare("SELECT key, value FROM settings ORDER BY key")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut out = BTreeMap::new();
    for row in rows {
        let (key, raw) = row?;
        let value = serde_json::from_str(&raw)
            .with_context(|| format!("setting {key} holds invalid JSON"))?;
        out.insert(key, value);
    }
    Ok(out)
}

pub fn get(conn: &Connection, key: &str) -> Result<Option<Value>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    raw.map(|raw| serde_json::from_str(&raw).map_err(Into::into))
        .transpose()
}

/// The admin password policy stored in the settings database.
/// Where the classifier's models run under the stored settings, for
/// webmail's consent prompt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClassifierModels {
    /// The cloud provider computing embeddings, if any.
    pub embed_cloud: Option<&'static str>,
    /// The cloud provider behind the fallback model (folders and labels).
    pub chat_cloud: Option<&'static str>,
    /// Whether a fallback model is configured at all; labels need one.
    pub chat_configured: bool,
    /// Whether that model writes text (local or OpenRouter chat), which
    /// summaries need; Jev only picks from options.
    pub chat_writes_text: bool,
}

impl ClassifierModels {
    /// Every provider that may receive message text, sorted.
    pub fn cloud_providers(&self) -> Vec<&'static str> {
        let mut providers: Vec<&'static str> = [self.embed_cloud, self.chat_cloud]
            .into_iter()
            .flatten()
            .collect();
        providers.sort_unstable();
        providers.dedup();
        providers
    }
}

pub fn classifier_models(conn: &Connection) -> Result<ClassifierModels> {
    use crate::config::ChatProvider;
    let value = |key: &str| get(conn, key).map(|value| value.unwrap_or(Value::Null));
    let text = |key: &str| -> Result<String> {
        Ok(value(key)?.as_str().unwrap_or_default().trim().to_string())
    };
    let embed: crate::config::EmbedProvider =
        serde_json::from_value(value("classifier.embed_provider")?).unwrap_or_default();
    let chat: ChatProvider =
        serde_json::from_value(value("classifier.chat_provider")?).unwrap_or_default();
    let chat_configured = match chat {
        ChatProvider::Local => !text("classifier.chat_model")?.is_empty(),
        ChatProvider::OpenRouter => !text("classifier.openrouter_chat_model")?.is_empty(),
        ChatProvider::Jev => true,
    };
    Ok(ClassifierModels {
        embed_cloud: embed.cloud(),
        chat_cloud: chat.cloud().filter(|_| chat_configured),
        chat_configured,
        chat_writes_text: chat_configured && chat != ChatProvider::Jev,
    })
}

pub fn admin_password_policy(conn: &Connection) -> Result<crate::config::AdminPasswordPolicy> {
    let stored = load_all(conn)?;
    let prefix = "security.admin_password_policy.";
    let tree = unflatten(stored.iter().filter(|(key, _)| key.starts_with(prefix)));
    let policy = tree
        .pointer("/security/admin_password_policy")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    serde_json::from_value(policy).context("invalid admin password policy")
}

pub fn get_string(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(get(conn, key)?.and_then(|value| value.as_str().map(str::to_string)))
}

/// Write values without registry validation and bump the revision.
/// `None` deletes a key. Used for reserved and internal keys.
pub fn write_raw(conn: &mut Connection, changes: &BTreeMap<String, Option<Value>>) -> Result<u64> {
    let tx = conn.transaction()?;
    let now = now();
    tx.execute(
        "INSERT INTO settings_meta(id, revision) VALUES (1, 1)
         ON CONFLICT(id) DO UPDATE SET revision = revision + 1",
        [],
    )?;
    let revision = tx.query_row(
        "SELECT revision FROM settings_meta WHERE id = 1",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    for (key, value) in changes {
        match value {
            Some(value) => {
                tx.execute(
                    "INSERT INTO settings(key, value, updated_at) VALUES (?1, ?2, ?3)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                    params![key, value.to_string(), now],
                )?;
            }
            None => {
                tx.execute("DELETE FROM settings WHERE key = ?1", params![key])?;
            }
        }
        tx.execute(
            "INSERT OR IGNORE INTO settings_changes(revision, key) VALUES (?1, ?2)",
            params![revision, key],
        )?;
    }
    tx.commit()?;
    Ok(revision as u64)
}

/// Return an internal value, generating and storing it on first use.
pub fn internal_secret(conn: &mut Connection, name: &str) -> Result<String> {
    let key = format!("{INTERNAL_PREFIX}{name}");
    if let Some(existing) = get_string(conn, &key)? {
        return Ok(existing);
    }
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    let secret = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    // Another process may have raced us; the INSERT OR IGNORE keeps the first.
    conn.execute(
        "INSERT OR IGNORE INTO settings(key, value, updated_at) VALUES (?1, ?2, ?3)",
        params![key, Value::String(secret).to_string(), now()],
    )?;
    get_string(conn, &key)?.ok_or_else(|| anyhow!("internal secret {name} was not stored"))
}

// ---------------------------------------------------------------------------
// Resolution

fn flatten_into(prefix: &str, value: &Value, out: &mut BTreeMap<String, Value>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten_into(&path, child, out);
            }
        }
        Value::Null => {}
        leaf => {
            out.insert(prefix.to_string(), leaf.clone());
        }
    }
}

pub fn flatten(value: &Value) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    flatten_into("", value, &mut out);
    out
}

pub fn unflatten<'a>(entries: impl IntoIterator<Item = (&'a String, &'a Value)>) -> Value {
    let mut root = Map::new();
    for (key, value) in entries {
        let mut parts = key.split('.').peekable();
        let mut cursor = &mut root;
        while let Some(part) = parts.next() {
            if parts.peek().is_none() {
                cursor.insert(part.to_string(), value.clone());
            } else {
                let child = cursor
                    .entry(part.to_string())
                    .or_insert_with(|| Value::Object(Map::new()));
                if !child.is_object() {
                    *child = Value::Object(Map::new());
                }
                cursor = child.as_object_mut().expect("object inserted above");
            }
        }
    }
    Value::Object(root)
}

/// Stand-in bootstrap values for building a config that only checks or
/// describes the stored settings.
fn placeholder_bootstrap() -> BTreeMap<String, Value> {
    BTreeMap::from([
        ("global.mail_root".to_string(), Value::from("mail")),
        ("global.db_path".to_string(), Value::from("rmail.db")),
    ])
}

fn is_bootstrap(key: &str) -> bool {
    BOOTSTRAP_KEYS.contains(&key)
}

fn is_internal(key: &str) -> bool {
    key.starts_with(INTERNAL_PREFIX)
}

/// Build a [`Config`] from bootstrap values plus stored settings.
pub fn build_config(
    bootstrap: &BTreeMap<String, Value>,
    stored: &BTreeMap<String, Value>,
) -> Result<Config> {
    let tree = unflatten(
        stored
            .iter()
            .filter(|(key, _)| !is_internal(key) && !is_bootstrap(key))
            .chain(bootstrap.iter().filter(|(key, _)| is_bootstrap(key))),
    );
    let config: Config = serde_json::from_value(tree).context("invalid settings")?;
    validate_semantics(&config)?;
    Ok(config)
}

/// Checks that span several keys and would otherwise only fail at daemon
/// startup.
pub fn validate_semantics(config: &Config) -> Result<()> {
    if let Some(hostname) = config.global.hostname.as_deref() {
        crate::domain::canonicalize_domain(hostname.trim()).map_err(|error| {
            anyhow!("global.hostname: {hostname:?} is not a valid domain name ({error})")
        })?;
    }
    if !config.security.srs_domain.is_empty() {
        crate::domain::canonicalize_domain(config.security.srs_domain.trim())
            .map_err(|error| anyhow!("security.srs_domain: {error:#}"))?;
    }
    let limit = config.security.imap_message_limit;
    if limit > 0 && limit < 1000 {
        bail!("security.imap_message_limit: use 0 (no limit) or at least 1000 (RFC 9738)");
    }
    for network in &config.security.proxy_protocol_trusted_networks {
        crate::proxy::Network::parse(network)
            .map_err(|error| anyhow!("security.proxy_protocol_trusted_networks: {error:#}"))?;
    }
    let policy = &config.security.admin_password_policy;
    if policy.min_length > policy.max_length {
        bail!(
            "security.admin_password_policy: min_length ({}) exceeds max_length ({})",
            policy.min_length,
            policy.max_length
        );
    }
    let oauth = config.security.oauth.is_some();
    for (key, mechanisms) in [
        (
            "security.imap_sasl_mechanisms",
            &config.security.imap_sasl_mechanisms,
        ),
        (
            "security.smtp_sasl_mechanisms",
            &config.security.smtp_sasl_mechanisms,
        ),
    ] {
        if mechanisms.is_empty() {
            bail!("{key} must not be empty");
        }
        if !oauth
            && mechanisms.iter().any(|name| {
                OAUTH_MECHANISMS
                    .iter()
                    .any(|oauth| oauth.eq_ignore_ascii_case(name))
            })
        {
            bail!("{key}: OAuth mechanisms require an OAuth introspection URL");
        }
    }
    if let Some(oauth) = &config.security.oauth {
        crate::oauth::validate_config(oauth).context("OAuth settings")?;
    }
    if let Some(url) = config.global.http_redirect_url.as_deref()
        && !(url.starts_with("https://") || url.starts_with("http://"))
    {
        bail!("global.http_redirect_url must start with https://");
    }
    crate::acme::validate_config(config)?;
    Ok(())
}

/// Resolve the effective configuration: `mail_root` and `db_path` from the
/// file, everything else from the settings database.
pub fn resolve_config(file: Value, source: &str) -> Result<Config> {
    let db_path = file
        .pointer("/global/db_path")
        .and_then(Value::as_str)
        .map(str::to_string)
        .with_context(|| format!("{source} must set global.db_path"))?;
    let file_flat = flatten(&file);
    let conn = open(&db_path)?;
    let ignored = file_flat
        .keys()
        .filter(|key| !is_bootstrap(key))
        .map(String::as_str)
        .collect::<Vec<_>>();
    if !ignored.is_empty() {
        crate::structured_log!("warn", "settings", "file_settings_ignored", {
            "config_file": source,
            "keys": ignored,
            "hint": "only mail_root and db_path are read from the file; manage settings in the admin console or with `rmail_ctl settings`",
        });
    }
    let stored = load_all(&conn)?;
    let mut config = build_config(&file_flat, &stored)
        .with_context(|| format!("settings stored in {db_path}"))?;
    config.settings_revision = revision(&conn)?;
    Ok(config)
}

// ---------------------------------------------------------------------------
// Editing

/// Validate and normalize a value for a registry setting. `Ok(None)` means
/// the value clears the setting (falls back to the built-in default).
pub fn normalize(spec: &SettingSpec, value: &Value) -> Result<Option<Value>> {
    if value.is_null() {
        return Ok(None);
    }
    let key = spec.key;
    let string_list = |value: &Value| -> Result<Vec<String>> {
        let items = match value {
            Value::Array(items) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(|text| text.trim().to_string())
                        .ok_or_else(|| anyhow!("{key}: list items must be strings"))
                })
                .collect::<Result<Vec<_>>>()?,
            Value::String(text) => text
                .split([',', '\n'])
                .map(|item| item.trim().to_string())
                .collect(),
            _ => bail!("{key}: expected a list"),
        };
        Ok(items.into_iter().filter(|item| !item.is_empty()).collect())
    };
    let normalized = match spec.kind {
        SettingKind::Bool => Value::Bool(
            value
                .as_bool()
                .ok_or_else(|| anyhow!("{key}: expected true or false"))?,
        ),
        SettingKind::Integer { min, max } => {
            let number = match value {
                Value::Number(number) => number.as_i64(),
                Value::String(text) => text.trim().parse::<i64>().ok(),
                _ => None,
            }
            .ok_or_else(|| anyhow!("{key}: expected a whole number"))?;
            if number < min || number > max {
                bail!("{key}: must be between {min} and {max}");
            }
            Value::from(number)
        }
        SettingKind::Text | SettingKind::Secret => {
            let text = value
                .as_str()
                .ok_or_else(|| anyhow!("{key}: expected text"))?
                .trim();
            if text.is_empty() {
                return Ok(None);
            }
            Value::String(text.to_string())
        }
        SettingKind::List => Value::from(string_list(value)?),
        SettingKind::AddressList => {
            let items = string_list(value)?;
            for item in &items {
                item.parse::<std::net::SocketAddr>().map_err(|_| {
                    anyhow!("{key}: {item:?} is not an ip:port socket address (IPv6 as [::1]:port)")
                })?;
            }
            Value::from(items)
        }
        SettingKind::Choice { options } => {
            let text = value
                .as_str()
                .ok_or_else(|| anyhow!("{key}: expected text"))?;
            let option = options
                .iter()
                .find(|option| option.eq_ignore_ascii_case(text.trim()))
                .ok_or_else(|| anyhow!("{key}: must be one of {}", options.join(", ")))?;
            Value::from(*option)
        }
        SettingKind::MultiChoice { options } => {
            let mut selected = Vec::new();
            for item in string_list(value)? {
                let option = options
                    .iter()
                    .find(|option| option.eq_ignore_ascii_case(&item))
                    .ok_or_else(|| anyhow!("{key}: unsupported value {item:?}"))?;
                if !selected.contains(option) {
                    selected.push(*option);
                }
            }
            if selected.is_empty() {
                bail!("{key}: select at least one value");
            }
            Value::from(selected)
        }
    };
    Ok(Some(normalized))
}

/// Apply user edits: validate every value, check the resulting configuration
/// as a whole, then store it atomically. Returns the new revision.
pub fn update(conn: &mut Connection, changes: &BTreeMap<String, Value>) -> Result<u64> {
    if changes.is_empty() {
        return revision(conn);
    }
    let mut stored = load_all(conn)?;
    let mut writes = BTreeMap::new();
    for (key, value) in changes {
        if is_bootstrap(key) {
            bail!("{key} can only be changed in the configuration file");
        }
        if is_internal(key) || RESERVED_KEYS.contains(&key.as_str()) {
            bail!("{key} cannot be changed here");
        }
        let normalized = match spec_for(key) {
            Some(spec) => normalize(spec, value)?,
            None => bail!("unknown setting {key}"),
        };
        match &normalized {
            Some(value) => {
                stored.insert(key.clone(), value.clone());
            }
            None => {
                stored.remove(key);
            }
        }
        writes.insert(key.clone(), normalized);
    }
    // Clearing the introspection URL disables OAuth entirely.
    if !stored.contains_key("security.oauth.introspection_url") {
        let oauth_keys = stored
            .keys()
            .filter(|key| key.starts_with("security.oauth."))
            .cloned()
            .collect::<Vec<_>>();
        for key in oauth_keys {
            stored.remove(&key);
            writes.insert(key, None);
        }
    }
    let bootstrap = placeholder_bootstrap();
    build_config(&bootstrap, &stored)?;
    write_raw(conn, &writes)
}

#[derive(Debug, Serialize)]
pub struct SettingView {
    #[serde(flatten)]
    pub spec: SettingSpec,
    /// Stored value, or `null` when the built-in default applies. Secrets are
    /// never returned.
    pub value: Option<Value>,
    pub default: Option<Value>,
    pub is_set: bool,
}

#[derive(Debug, Serialize)]
pub struct ServiceState {
    pub service: String,
    pub pid: i64,
    pub host: Option<String>,
    pub started_at: i64,
    pub settings_revision: u64,
    pub restart_required: bool,
    /// Settings this service reads that changed after it started.
    pub pending_changes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SettingsView {
    pub revision: u64,
    pub groups: &'static [SettingGroup],
    pub settings: Vec<SettingView>,
    pub services: Vec<ServiceState>,
}

fn default_values() -> BTreeMap<String, Value> {
    let bootstrap = placeholder_bootstrap();
    build_config(&bootstrap, &BTreeMap::new())
        .ok()
        .and_then(|config| serde_json::to_value(config).ok())
        .map(|tree| flatten(&tree))
        .unwrap_or_default()
}

pub fn describe(conn: &Connection) -> Result<SettingsView> {
    let stored = load_all(conn)?;
    let defaults = default_values();
    let settings = SETTINGS
        .iter()
        .map(|spec| {
            let stored_value = stored.get(spec.key).cloned();
            let secret = matches!(spec.kind, SettingKind::Secret);
            SettingView {
                spec: *spec,
                is_set: stored_value.is_some(),
                value: if secret { None } else { stored_value },
                default: if secret {
                    None
                } else {
                    defaults.get(spec.key).cloned()
                },
            }
        })
        .collect();
    Ok(SettingsView {
        revision: revision(conn)?,
        groups: GROUPS,
        settings,
        services: service_states(conn)?,
    })
}

// ---------------------------------------------------------------------------
// Service state

/// Record that `service` started with the settings revision in `config`.
pub fn record_service_start(config: &Config, service: &str) -> Result<()> {
    let db_path = config.global.db_path.as_str();
    let conn = open(db_path)?;
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|host| host.trim().to_string());
    conn.execute(
        "INSERT INTO service_state(service, pid, host, started_at, settings_revision)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(service) DO UPDATE SET pid = excluded.pid, host = excluded.host,
             started_at = excluded.started_at, settings_revision = excluded.settings_revision",
        params![
            service,
            std::process::id() as i64,
            host,
            now(),
            config.settings_revision as i64
        ],
    )?;
    Ok(())
}

pub fn service_states(conn: &Connection) -> Result<Vec<ServiceState>> {
    let mut stmt = conn.prepare(
        "SELECT service, pid, host, started_at, settings_revision FROM service_state ORDER BY service",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)? as u64,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut changes =
        conn.prepare("SELECT DISTINCT key FROM settings_changes WHERE revision > ?1 ORDER BY key")?;
    let mut out = Vec::with_capacity(rows.len());
    for (service, pid, host, started_at, settings_revision) in rows {
        let changed = changes
            .query_map(params![settings_revision as i64], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let pending_changes = changed
            .into_iter()
            .filter(|key| affects_service(key, &service))
            .collect::<Vec<_>>();
        out.push(ServiceState {
            restart_required: !pending_changes.is_empty(),
            pending_changes,
            service,
            pid,
            host,
            started_at,
            settings_revision,
        });
    }
    Ok(out)
}

fn affects_service(key: &str, service: &str) -> bool {
    match spec_for(key) {
        Some(spec) => spec.services.contains(&service),
        // Admin credentials are read per request; the webmail secret at start.
        None if key == "global.webmail_session_secret" => service == "webmail",
        None if RESERVED_KEYS.contains(&key) || is_internal(key) => false,
        // Unknown legacy keys: assume every daemon may read them.
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn file(db: &Path, extra: &str) -> Value {
        let text = format!(
            "[global]\nmail_root = \"mail\"\ndb_path = \"{}\"\n{extra}",
            db.display()
        );
        serde_json::to_value(toml::from_str::<toml::Value>(&text).unwrap()).unwrap()
    }

    #[test]
    fn update_validates_values_and_whole_config() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("rmail.db");
        resolve_config(file(&db, ""), "test").unwrap();
        let mut conn = open(&db).unwrap();
        let change = |key: &str, value: Value| BTreeMap::from([(key.to_string(), value)]);

        assert!(update(&mut conn, &change("security.smtp_max_recipients", json!(0))).is_err());
        assert!(update(&mut conn, &change("global.listeners.smtp", json!(["nope"]))).is_err());
        assert!(update(&mut conn, &change("global.mail_root", json!("x"))).is_err());
        assert!(
            update(
                &mut conn,
                &change("global.web_admin_password_hash", json!("x"))
            )
            .is_err()
        );
        assert!(update(&mut conn, &change("made.up", json!(1))).is_err());
        let error = update(
            &mut conn,
            &change("security.smtp_sasl_mechanisms", json!(["PLAIN", "XOAUTH2"])),
        )
        .unwrap_err();
        assert!(error.to_string().contains("OAuth"), "{error:#}");

        update(
            &mut conn,
            &change(
                "security.smtp_sasl_mechanisms",
                json!("plain, scram-sha-256"),
            ),
        )
        .unwrap();
        let stored = get(&conn, "security.smtp_sasl_mechanisms")
            .unwrap()
            .unwrap();
        assert_eq!(stored, json!(["PLAIN", "SCRAM-SHA-256"]));

        // null resets to the default.
        update(
            &mut conn,
            &change("security.smtp_sasl_mechanisms", Value::Null),
        )
        .unwrap();
        assert!(
            get(&conn, "security.smtp_sasl_mechanisms")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn clearing_oauth_url_removes_the_whole_section() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("rmail.db");
        resolve_config(file(&db, ""), "test").unwrap();
        let mut conn = open(&db).unwrap();
        update(
            &mut conn,
            &BTreeMap::from([
                (
                    "security.oauth.introspection_url".to_string(),
                    json!("https://idp.example/introspect"),
                ),
                ("security.oauth.identity_claim".to_string(), json!("email")),
            ]),
        )
        .unwrap();
        update(
            &mut conn,
            &BTreeMap::from([("security.oauth.introspection_url".to_string(), json!(""))]),
        )
        .unwrap();
        assert!(
            get(&conn, "security.oauth.identity_claim")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn describe_hides_secrets_and_reports_restart_needs() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("rmail.db");
        let mut conn = open(&db).unwrap();
        update(
            &mut conn,
            &BTreeMap::from([
                (
                    "security.oauth.introspection_url".to_string(),
                    json!("https://idp.example/i"),
                ),
                ("security.oauth.client_id".to_string(), json!("c")),
                ("security.oauth.client_secret".to_string(), json!("s3cret")),
            ]),
        )
        .unwrap();
        let config = resolve_config(file(&db, ""), "test").unwrap();
        record_service_start(&config, "smtpd").unwrap();
        update(
            &mut conn,
            &BTreeMap::from([("security.smtp_max_recipients".to_string(), json!(5))]),
        )
        .unwrap();
        let view = describe(&conn).unwrap();
        let rendered = serde_json::to_string(&view).unwrap();
        assert!(!rendered.contains("s3cret"));
        let secret = view
            .settings
            .iter()
            .find(|setting| setting.spec.key == "security.oauth.client_secret")
            .unwrap();
        assert!(secret.is_set && secret.value.is_none());
        let recipients = view
            .settings
            .iter()
            .find(|setting| setting.spec.key == "security.smtp_max_recipients")
            .unwrap();
        assert_eq!(recipients.default, Some(json!(100)));
        assert!(view.services[0].restart_required);
        assert_eq!(
            view.services[0].pending_changes,
            ["security.smtp_max_recipients"]
        );

        // A change that smtpd does not read does not require restarting it.
        let config = resolve_config(file(&db, ""), "test").unwrap();
        record_service_start(&config, "smtpd").unwrap();
        update(
            &mut conn,
            &BTreeMap::from([(
                "security.imap_max_commands_per_minute".to_string(),
                json!(50),
            )]),
        )
        .unwrap();
        assert!(!describe(&conn).unwrap().services[0].restart_required);
    }

    #[test]
    fn hostname_setting_is_validated_and_defaults_to_the_system_name() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("rmail.db");
        let config = resolve_config(file(&db, ""), "test").unwrap();
        assert_eq!(config.global.hostname, None);
        assert_eq!(
            config.global.server_hostname(),
            crate::config::system_hostname()
        );
        let mut conn = open(&db).unwrap();
        let change = |value: Value| BTreeMap::from([("global.hostname".to_string(), value)]);
        assert!(update(&mut conn, &change(json!("not a host"))).is_err());
        assert!(update(&mut conn, &change(json!("-bad.example"))).is_err());
        update(&mut conn, &change(json!("MX1.Example.TEST"))).unwrap();
        let config = resolve_config(file(&db, ""), "test").unwrap();
        assert_eq!(config.global.server_hostname(), "mx1.example.test");
        assert!(
            describe(&conn)
                .unwrap()
                .settings
                .iter()
                .any(|setting| setting.spec.key == "global.hostname" && setting.is_set)
        );
    }

    #[test]
    fn internal_secrets_are_generated_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = open(dir.path().join("rmail.db")).unwrap();
        let first = internal_secret(&mut conn, "session").unwrap();
        let second = internal_secret(&mut conn, "session").unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn every_registry_key_round_trips_through_config() {
        let defaults = default_values();
        for spec in SETTINGS {
            if spec.key.starts_with("security.oauth.")
                || matches!(
                    spec.key,
                    "global.tls_cert"
                        | "global.hostname"
                        | "global.tls_key"
                        | "global.tls.ocsp_response"
                        | "global.http_redirect_url"
                        | "global.enforce_dmarc"
                        | "acme.email"
                        | "acme.directory_url"
                        | "acme.eab_kid"
                        | "acme.eab_hmac_key"
                        | "acme.dns.provider"
                        | "acme.dns.api_token"
                        | "acme.dns.zone"
                        | "acme.dns.aws_access_key_id"
                        | "acme.dns.aws_secret_access_key"
                        | "acme.dns.rfc2136_server"
                        | "acme.dns.tsig_key_name"
                        | "acme.dns.tsig_secret"
                        | "classifier.openrouter_api_key"
                        | "classifier.typesafe_api_key"
                )
                || spec.key.starts_with("global.listeners.")
            {
                continue;
            }
            assert!(
                defaults.contains_key(spec.key),
                "{} has no default",
                spec.key
            );
        }
    }
}
