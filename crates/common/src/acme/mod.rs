//! Automatic TLS certificates from an ACME CA (RFC 8555) such as Let's
//! Encrypt, without an external client.
//!
//! * Account keys, pending http-01 responses and run status live in the
//!   settings database, so the admin daemon's HTTP listeners can answer
//!   challenges for runs started by any process (`rmail_ctl acme issue`).
//! * dns-01 records are published through a provider API or RFC 2136 and
//!   checked on every authoritative name server before validation.
//! * Certificates are written atomically to `global.tls_cert` /
//!   `global.tls_key` (or `<mail_root>/tls/` when unset); every TLS service
//!   notices the changed files and reloads them (see [`crate::tls`]).
//! * Renewal follows the CA's ACME Renewal Information (RFC 9773) when
//!   offered, otherwise it starts after two thirds of the lifetime.

pub mod cert;
mod dns;
mod rfc2136;

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, CertificateIdentifier, ChallengeType,
    ExternalAccountKey, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy,
    ZeroSsl,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

pub use cert::CertificateInfo;

use crate::config::{AcmeCa, AcmeChallenge, AcmeConfig, Config};

macro_rules! acme_log {
    ($level:expr, $event:expr, $fields:tt) => {
        $crate::structured_log!($level, "acme", $event, $fields)
    };
}

const MAX_LOG_LINES: usize = 200;
const CHALLENGE_TTL_SECS: i64 = 3600;
/// Retry a failed run after this long, doubling per consecutive failure.
const FAILURE_BACKOFF_SECS: i64 = 3600;
const MAX_FAILURE_BACKOFF_SECS: i64 = 24 * 3600;
/// Ask the CA for renewal information at most this often.
const ARI_REFRESH_SECS: i64 = 6 * 3600;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Configuration

/// Names to put on the certificate: `acme.domains`, or the server hostname.
pub fn certificate_names(config: &Config) -> Result<Vec<String>> {
    let wanted = if config.acme.domains.is_empty() {
        vec![config.global.server_hostname()]
    } else {
        config.acme.domains.clone()
    };
    let mut names = Vec::new();
    for name in wanted {
        let name = name.trim();
        let (wildcard, base) = match name.strip_prefix("*.") {
            Some(base) => (true, base),
            None => (false, name),
        };
        let base = crate::domain::canonicalize_domain(base)
            .map_err(|error| anyhow!("acme.domains: {name:?} is not a valid domain ({error})"))?;
        if !base.contains('.') {
            bail!(
                "acme.domains: {name:?} is not a public domain name; set acme.domains or global.hostname"
            );
        }
        let name = if wildcard { format!("*.{base}") } else { base };
        if !names.contains(&name) {
            names.push(name);
        }
    }
    Ok(names)
}

pub fn directory_url(acme: &AcmeConfig) -> Result<String> {
    Ok(match acme.ca {
        AcmeCa::LetsEncrypt => LetsEncrypt::Production.url().to_string(),
        AcmeCa::LetsEncryptStaging => LetsEncrypt::Staging.url().to_string(),
        AcmeCa::ZeroSsl => ZeroSsl::Production.url().to_string(),
        AcmeCa::Custom => acme
            .directory_url
            .clone()
            .filter(|url| !url.trim().is_empty())
            .ok_or_else(|| anyhow!("acme.directory_url is required for a custom CA"))?,
    })
}

/// Directory used for a test run: Let's Encrypt staging when the configured
/// CA is Let's Encrypt, otherwise the configured CA itself.
fn test_directory_url(acme: &AcmeConfig) -> Result<String> {
    match acme.ca {
        AcmeCa::LetsEncrypt => Ok(LetsEncrypt::Staging.url().to_string()),
        _ => directory_url(acme),
    }
}

/// Checks run whenever settings are saved. Incomplete settings are allowed
/// while ACME is disabled.
pub fn validate_config(config: &Config) -> Result<()> {
    let acme = &config.acme;
    if !acme.enabled {
        return Ok(());
    }
    let names = certificate_names(config)?;
    if acme.challenge != AcmeChallenge::Dns01 && names.iter().any(|name| name.starts_with("*.")) {
        bail!("acme.domains: wildcard names need the dns-01 challenge");
    }
    if let Some(email) = acme.email.as_deref()
        && !email.trim().is_empty()
        && crate::domain::canonicalize_mailbox_address(email.trim()).is_err()
    {
        bail!("acme.email: {email:?} is not an email address");
    }
    let url = directory_url(acme)?;
    if !url.starts_with("https://") {
        bail!("acme.directory_url must be an https:// URL");
    }
    let has_kid = acme
        .eab_kid
        .as_deref()
        .is_some_and(|kid| !kid.trim().is_empty());
    if has_kid != acme.eab_hmac_key.is_some() {
        bail!("acme.eab_kid and acme.eab_hmac_key must be set together");
    }
    if acme.ca == AcmeCa::ZeroSsl && !has_kid {
        bail!("ZeroSSL needs external account binding: set acme.eab_kid and acme.eab_hmac_key");
    }
    // Validation only checks secrets are well formed; it never keeps them.
    if acme
        .eab_hmac_key
        .as_ref()
        .is_some_and(|key| decode_eab_key(key.expose()).is_err())
    {
        bail!("acme.eab_hmac_key must be base64url, as issued by the CA");
    }
    if acme.challenge == AcmeChallenge::Dns01 {
        dns::check_config(&acme.dns)?;
    }
    if config.global.tls.ocsp_response.is_some() {
        bail!(
            "global.tls.ocsp_response cannot be combined with ACME: a stapled response would not match renewed certificates"
        );
    }
    Ok(())
}

fn decode_eab_key(key: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let key = key.trim().trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(key)
        .map_err(|_| anyhow!("acme.eab_hmac_key must be base64url, as issued by the CA"))
}

/// Where certificates are installed: the configured TLS paths, or
/// `<mail_root>/tls/` when they are unset. The flag reports whether the
/// settings need to point at the managed location.
pub fn certificate_paths(config: &Config) -> (PathBuf, PathBuf, bool) {
    match (&config.global.tls_cert, &config.global.tls_key) {
        (Some(cert), Some(key)) => (PathBuf::from(cert), PathBuf::from(key), false),
        _ => {
            let dir = Path::new(&config.global.mail_root).join("tls");
            (dir.join("fullchain.pem"), dir.join("privkey.pem"), true)
        }
    }
}

fn lock_path(config: &Config) -> PathBuf {
    Path::new(&config.global.mail_root)
        .join("tls")
        .join(".acme.lock")
}

// ---------------------------------------------------------------------------
// Storage

pub fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS acme_accounts (
             directory TEXT PRIMARY KEY,
             credentials TEXT NOT NULL,
             contact TEXT,
             created_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS acme_challenges (
             token TEXT PRIMARY KEY,
             key_authorization TEXT NOT NULL,
             expires_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS acme_state (
             id INTEGER PRIMARY KEY CHECK (id = 1),
             value TEXT NOT NULL
         );",
    )?;
    Ok(())
}

fn open(db_path: &str) -> Result<Connection> {
    let conn = crate::settings::open(db_path)?;
    ensure_schema(&conn)?;
    Ok(conn)
}

/// Key authorization for an http-01 `token`, if a run is waiting for it.
pub fn challenge_response(db_path: &str, token: &str) -> Result<Option<String>> {
    let conn = open(db_path)?;
    Ok(conn
        .query_row(
            "SELECT key_authorization FROM acme_challenges WHERE token = ?1 AND expires_at > ?2",
            params![token, now()],
            |row| row.get(0),
        )
        .optional()?)
}

pub fn put_challenge(db_path: &str, token: &str, key_authorization: &str) -> Result<()> {
    let conn = open(db_path)?;
    conn.execute(
        "DELETE FROM acme_challenges WHERE expires_at <= ?1",
        params![now()],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO acme_challenges(token, key_authorization, expires_at) VALUES (?1, ?2, ?3)",
        params![token, key_authorization, now() + CHALLENGE_TTL_SECS],
    )?;
    Ok(())
}

fn delete_challenge(db_path: &str, token: &str) -> Result<()> {
    open(db_path)?.execute(
        "DELETE FROM acme_challenges WHERE token = ?1",
        params![token],
    )?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLine {
    pub at: i64,
    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunRecord {
    /// `manual`, `renewal` or `cli`.
    pub trigger: String,
    /// Test runs issue from staging and install nothing.
    pub dry_run: bool,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub ok: Option<bool>,
    pub error: Option<String>,
    pub names: Vec<String>,
    pub log: Vec<LogLine>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AcmeStatus {
    pub last_run: Option<RunRecord>,
    pub last_success_at: Option<i64>,
    /// Directory URL of the CA that issued the installed certificate.
    pub issued_by: Option<String>,
    pub consecutive_failures: u32,
    /// Earliest time the renewal task retries after a failure.
    pub retry_after: Option<i64>,
    /// Renewal window suggested by the CA (RFC 9773), as Unix timestamps.
    pub renewal_window: Option<(i64, i64)>,
    pub renewal_window_checked_at: Option<i64>,
}

pub fn load_status(db_path: &str) -> Result<AcmeStatus> {
    let conn = open(db_path)?;
    let raw: Option<String> = conn
        .query_row("SELECT value FROM acme_state WHERE id = 1", [], |row| {
            row.get(0)
        })
        .optional()?;
    Ok(raw
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default())
}

fn save_status(db_path: &str, status: &AcmeStatus) -> Result<()> {
    open(db_path)?.execute(
        "INSERT INTO acme_state(id, value) VALUES (1, ?1)
         ON CONFLICT(id) DO UPDATE SET value = excluded.value",
        params![serde_json::to_string(status)?],
    )?;
    Ok(())
}

fn update_status(db_path: &str, change: impl FnOnce(&mut AcmeStatus)) -> Result<AcmeStatus> {
    let mut status = load_status(db_path)?;
    change(&mut status);
    save_status(db_path, &status)?;
    Ok(status)
}

// ---------------------------------------------------------------------------
// Run lock

/// Exclusive lock held for the duration of a run, shared across processes.
struct RunLock {
    _file: fs::File,
}

impl RunLock {
    fn acquire(path: &Path) -> Result<Option<Self>> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: flock on a descriptor we own; released when it closes.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Ok(None);
            }
        }
        Ok(Some(Self { _file: file }))
    }
}

/// Whether a run (in any process) currently holds the lock.
pub fn run_in_progress(config: &Config) -> bool {
    let path = lock_path(config);
    if !path.exists() {
        return false;
    }
    matches!(RunLock::acquire(&path), Ok(None))
}

// ---------------------------------------------------------------------------
// Progress reporting

struct Progress {
    db_path: String,
    record: RunRecord,
    echo: bool,
}

impl Progress {
    fn step(&mut self, message: impl Into<String>) {
        let message = message.into();
        acme_log!("info", "acme_progress", { "message": message });
        if self.echo {
            println!("{message}");
        }
        self.record.log.push(LogLine { at: now(), message });
        if self.record.log.len() > MAX_LOG_LINES {
            self.record.log.remove(0);
        }
        self.flush();
    }

    fn warn(&mut self, message: impl Into<String>) {
        self.step(format!("Warning: {}", message.into()));
    }

    fn flush(&self) {
        let record = self.record.clone();
        if let Err(error) = update_status(&self.db_path, |status| status.last_run = Some(record)) {
            acme_log!("warn", "acme_status_write_failed", { "error": format!("{error:#}") });
        }
    }
}

// ---------------------------------------------------------------------------
// Runs

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub trigger: String,
    pub dry_run: bool,
    /// Print progress to standard output (for the CLI).
    pub echo: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunOutcome {
    pub names: Vec<String>,
    pub not_after: i64,
    pub installed: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    /// The TLS settings were pointed at the managed certificate location;
    /// services need one restart to start using TLS.
    pub settings_updated: bool,
}

/// Request a certificate now and install it (unless `dry_run`). Only one
/// run can be active at a time across all processes.
pub async fn run(config: &Config, options: RunOptions) -> Result<RunOutcome> {
    let db_path = config
        .global
        .db_path
        .clone()
        .ok_or_else(|| anyhow!("ACME needs the settings database (global.db_path)"))?;
    let Some(_lock) = RunLock::acquire(&lock_path(config))? else {
        bail!("another certificate request is already running");
    };
    let names = certificate_names(config).unwrap_or_default();
    let mut progress = Progress {
        db_path: db_path.clone(),
        record: RunRecord {
            trigger: options.trigger.clone(),
            dry_run: options.dry_run,
            started_at: now(),
            names: names.clone(),
            ..RunRecord::default()
        },
        echo: options.echo,
    };
    progress.step(if options.dry_run {
        format!(
            "Test run for {} (nothing will be installed)",
            names.join(", ")
        )
    } else {
        format!("Requesting a certificate for {}", names.join(", "))
    });
    let result = issue(config, &db_path, &options, &mut progress).await;
    progress.record.finished_at = Some(now());
    progress.record.ok = Some(result.is_ok());
    match &result {
        Ok(outcome) => {
            progress.step(if outcome.installed {
                format!(
                    "Done. Certificate valid until {}",
                    format_time(outcome.not_after)
                )
            } else {
                "Test run succeeded; the CA issued a certificate for every name".to_string()
            });
        }
        Err(error) => {
            progress.record.error = Some(format!("{error:#}"));
            progress.step(format!("Failed: {error:#}"));
        }
    }
    let record = progress.record.clone();
    let directory = directory_url(&config.acme).ok();
    update_status(&db_path, |status| {
        status.last_run = Some(record);
        if options.dry_run {
            return;
        }
        match &result {
            Ok(_) => {
                status.last_success_at = Some(now());
                status.issued_by = directory;
                status.consecutive_failures = 0;
                status.retry_after = None;
                status.renewal_window = None;
                status.renewal_window_checked_at = None;
            }
            Err(_) => {
                status.consecutive_failures += 1;
                let backoff = (FAILURE_BACKOFF_SECS
                    << status.consecutive_failures.saturating_sub(1).min(5))
                .min(MAX_FAILURE_BACKOFF_SECS);
                status.retry_after = Some(now() + backoff);
            }
        }
    })?;
    match &result {
        Ok(outcome) => {
            acme_log!("info", "acme_run_succeeded", { "names": outcome.names, "installed": outcome.installed, "not_after": outcome.not_after })
        }
        Err(error) => {
            acme_log!("error", "acme_run_failed", { "error": format!("{error:#}") })
        }
    }
    result
}

pub fn format_time(timestamp: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(timestamp)
        .map(|at| {
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02} UTC",
                at.year(),
                u8::from(at.month()),
                at.day(),
                at.hour(),
                at.minute()
            )
        })
        .unwrap_or_else(|_| timestamp.to_string())
}

async fn load_account(
    db_path: &str,
    directory: &str,
    acme: &AcmeConfig,
    progress: &mut Progress,
) -> Result<Account> {
    let contact = acme
        .email
        .as_deref()
        .map(str::trim)
        .filter(|email| !email.is_empty())
        .map(|email| format!("mailto:{email}"));
    let stored: Option<(String, Option<String>)> = open(db_path)?
        .query_row(
            "SELECT credentials, contact FROM acme_accounts WHERE directory = ?1",
            params![directory],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((credentials, stored_contact)) = stored {
        let credentials: AccountCredentials =
            serde_json::from_str(&credentials).context("stored ACME account is unreadable")?;
        let account = Account::builder()?
            .from_credentials(credentials)
            .await
            .context("loading the ACME account")?;
        if stored_contact != contact {
            let contacts = contact.iter().map(String::as_str).collect::<Vec<_>>();
            match account.update_contacts(&contacts).await {
                Ok(()) => {
                    open(db_path)?.execute(
                        "UPDATE acme_accounts SET contact = ?1 WHERE directory = ?2",
                        params![contact, directory],
                    )?;
                    progress.step("Updated the account contact address");
                }
                Err(error) => {
                    progress.warn(format!("could not update the account contact: {error}"))
                }
            }
        }
        return Ok(account);
    }
    progress.step(format!("Registering a new account with {directory}"));
    let contacts = contact.iter().map(String::as_str).collect::<Vec<_>>();
    let eab = match (&acme.eab_kid, &acme.eab_hmac_key) {
        (Some(kid), Some(key)) if !kid.trim().is_empty() => Some(ExternalAccountKey::new(
            kid.trim().to_string(),
            &decode_eab_key(key.expose())?,
        )),
        _ => None,
    };
    let (account, credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: &contacts,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory.to_string(),
            eab.as_ref(),
        )
        .await
        .context("registering the ACME account")?;
    open(db_path)?.execute(
        "INSERT OR REPLACE INTO acme_accounts(directory, credentials, contact, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![directory, serde_json::to_string(&credentials)?, contact, now()],
    )?;
    Ok(account)
}

/// Pending challenge material, removed once the order is done.
enum Pending {
    Http { token: String },
    Dns { fqdn: String, value: String },
}

async fn issue(
    config: &Config,
    db_path: &str,
    options: &RunOptions,
    progress: &mut Progress,
) -> Result<RunOutcome> {
    let acme = &config.acme;
    let names = certificate_names(config)?;
    if acme.challenge != AcmeChallenge::Dns01 && names.iter().any(|name| name.starts_with("*.")) {
        bail!("wildcard names need the dns-01 challenge");
    }
    if config.global.tls.ocsp_response.is_some() && !options.dry_run {
        bail!("global.tls.ocsp_response cannot be combined with ACME certificates");
    }
    let directory = if options.dry_run {
        test_directory_url(acme)?
    } else {
        directory_url(acme)?
    };
    let provider = match acme.challenge {
        AcmeChallenge::Dns01 => Some(dns::Provider::from_config(&acme.dns)?),
        AcmeChallenge::Http01 => None,
    };
    let account = load_account(db_path, &directory, acme, progress).await?;

    let identifiers = names
        .iter()
        .map(|name| Identifier::Dns(name.clone()))
        .collect::<Vec<_>>();
    let (cert_path, key_path, _) = certificate_paths(config);
    // Mark the order as replacing the current certificate (RFC 9773) when it
    // came from the same CA; the CA may exempt it from rate limits.
    let status = load_status(db_path).unwrap_or_default();
    let replaces = (!options.dry_run && status.issued_by.as_deref() == Some(directory.as_str()))
        .then(|| current_certificate_id(&cert_path))
        .flatten();
    let mut order = match &replaces {
        Some(id) => match account
            .new_order(&NewOrder::new(&identifiers).replaces(id.clone()))
            .await
        {
            Ok(order) => order,
            Err(error) => {
                progress.warn(format!(
                    "the CA did not accept a replacement order ({error}); requesting a new one"
                ));
                account.new_order(&NewOrder::new(&identifiers)).await?
            }
        },
        None => account.new_order(&NewOrder::new(&identifiers)).await?,
    };
    progress.step(if order.state().replaces.is_some() {
        "Order created (replacing the installed certificate)"
    } else {
        "Order created"
    });

    let challenge_type = match acme.challenge {
        AcmeChallenge::Http01 => ChallengeType::Http01,
        AcmeChallenge::Dns01 => ChallengeType::Dns01,
    };
    let mut pending = Vec::new();
    let mut prepared = async {
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization = authorization?;
            let identifier = authorization.identifier().to_string();
            match authorization.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => {
                    progress.step(format!("{identifier} is already authorized"));
                    continue;
                }
                other => bail!("authorization for {identifier} is {other:?}"),
            }
            let challenge = authorization
                .challenge(challenge_type.clone())
                .ok_or_else(|| {
                    anyhow!("the CA offers no {challenge_type:?} challenge for {identifier}")
                })?;
            let key_authorization = challenge.key_authorization();
            match acme.challenge {
                AcmeChallenge::Http01 => {
                    put_challenge(db_path, &challenge.token, key_authorization.as_str())?;
                    pending.push((
                        identifier,
                        Pending::Http {
                            token: challenge.token.clone(),
                        },
                    ));
                }
                AcmeChallenge::Dns01 => {
                    let base = identifier.trim_start_matches("*.");
                    pending.push((
                        identifier.clone(),
                        Pending::Dns {
                            fqdn: format!("_acme-challenge.{base}"),
                            value: key_authorization.dns_value(),
                        },
                    ));
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;

    // Publish DNS records grouped per name: a name and its wildcard share one.
    let mut records: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (_, item) in &pending {
        if let Pending::Dns { fqdn, value } = item {
            records.entry(fqdn.clone()).or_default().push(value.clone());
        }
    }
    let mut published = Vec::new();
    if prepared.is_ok()
        && let Some(provider) = &provider
    {
        for (fqdn, values) in &records {
            let zone = match acme.dns.zone.as_deref().map(str::trim) {
                Some(zone) if !zone.is_empty() => zone.trim_end_matches('.').to_string(),
                _ => match dns::find_zone(fqdn).await {
                    Ok(zone) => zone,
                    Err(error) => {
                        prepared = Err(error);
                        break;
                    }
                },
            };
            progress.step(format!(
                "Publishing TXT {fqdn} in zone {zone} via {}",
                provider.name()
            ));
            match provider.present(&zone, fqdn, values).await {
                Ok(handle) => published.push((zone, fqdn.clone(), values.clone(), handle)),
                Err(error) => {
                    prepared = Err(error.context(format!("publishing {fqdn}")));
                    break;
                }
            }
        }
    }

    let result = match prepared {
        Ok(()) => {
            complete_order(
                &mut order,
                &challenge_type,
                &pending,
                &published,
                acme,
                progress,
            )
            .await
        }
        Err(error) => Err(error),
    };

    // Clean up challenge material whatever happened.
    for (_, item) in &pending {
        if let Pending::Http { token } = item
            && let Err(error) = delete_challenge(db_path, token)
        {
            progress.warn(format!("could not remove challenge {token}: {error:#}"));
        }
    }
    if let Some(provider) = &provider {
        for (zone, fqdn, values, handle) in &published {
            match provider.cleanup(zone, fqdn, values, handle).await {
                Ok(()) => progress.step(format!("Removed TXT {fqdn}")),
                Err(error) => progress.warn(format!("could not remove TXT {fqdn}: {error:#}")),
            }
        }
    }
    let (private_key_pem, chain_pem) = result?;

    let info = cert::inspect_pem(chain_pem.as_bytes())?;
    if options.dry_run {
        return Ok(RunOutcome {
            names: info.names,
            not_after: info.not_after,
            installed: false,
            cert_path: None,
            key_path: None,
            settings_updated: false,
        });
    }
    install(&cert_path, &key_path, &chain_pem, &private_key_pem, config)?;
    progress.step(format!(
        "Installed {} and {}",
        cert_path.display(),
        key_path.display()
    ));
    let settings_updated = point_settings_at(config, &cert_path, &key_path, progress)?;
    Ok(RunOutcome {
        names: info.names,
        not_after: info.not_after,
        installed: true,
        cert_path: Some(cert_path.display().to_string()),
        key_path: Some(key_path.display().to_string()),
        settings_updated,
    })
}

async fn complete_order(
    order: &mut instant_acme::Order,
    challenge_type: &ChallengeType,
    pending: &[(String, Pending)],
    published: &[(String, String, Vec<String>, dns::Published)],
    acme: &AcmeConfig,
    progress: &mut Progress,
) -> Result<(String, String)> {
    if pending.is_empty() {
        progress.step("Every name is already authorized");
    }
    // Check the challenges are visible before asking the CA to look.
    for (identifier, item) in pending {
        if let Pending::Http { token } = item {
            match self_check_http(identifier, token).await {
                Ok(()) => progress.step(format!("{identifier}: challenge reachable over HTTP")),
                Err(error) => progress.warn(format!(
                    "{identifier}: could not fetch the challenge from here ({error:#}). \
                     The CA needs to reach http://{identifier}/.well-known/acme-challenge/ on port 80 \
                     (a plain HTTP listener in rmail_web, or a proxy forwarding that path to it)"
                )),
            }
        }
    }
    let mut by_zone: BTreeMap<&str, Vec<(String, Vec<String>)>> = BTreeMap::new();
    for (zone, fqdn, values, _) in published {
        by_zone
            .entry(zone.as_str())
            .or_default()
            .push((fqdn.clone(), values.clone()));
    }
    for (zone, records) in by_zone {
        progress.step(format!(
            "Waiting for the TXT records to reach every name server of {zone}"
        ));
        match dns::wait_for_propagation(
            zone,
            &records,
            Duration::from_secs(acme.dns.propagation_timeout_seconds.max(10)),
        )
        .await
        {
            Ok(()) => progress.step("TXT records visible on every name server"),
            Err(missing) => progress.warn(format!(
                "records not visible everywhere yet ({missing}); asking the CA anyway"
            )),
        }
    }

    let mut authorizations = order.authorizations();
    while let Some(authorization) = authorizations.next().await {
        let mut authorization = authorization?;
        if authorization.status != AuthorizationStatus::Pending {
            continue;
        }
        let identifier = authorization.identifier().to_string();
        let mut challenge = authorization
            .challenge(challenge_type.clone())
            .ok_or_else(|| anyhow!("challenge for {identifier} disappeared"))?;
        challenge.set_ready().await?;
    }
    progress.step("Waiting for the CA to validate");
    let status = order
        .poll_ready(
            &RetryPolicy::new()
                .initial_delay(Duration::from_secs(2))
                .backoff(1.5)
                .timeout(Duration::from_secs(180)),
        )
        .await?;
    if status != OrderStatus::Ready {
        let mut reasons = Vec::new();
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let Ok(mut authorization) = authorization else {
                continue;
            };
            let identifier = authorization.identifier().to_string();
            if let Ok(state) = authorization.refresh().await {
                for challenge in &state.challenges {
                    if let Some(error) = &challenge.error {
                        reasons.push(format!("{identifier}: {error}"));
                    }
                }
            }
        }
        if reasons.is_empty() {
            bail!("the CA marked the order {status:?}");
        }
        bail!("validation failed: {}", reasons.join("; "));
    }
    progress.step("Validated; finalizing the order");
    let private_key_pem = order.finalize().await?;
    let chain_pem = order
        .poll_certificate(
            &RetryPolicy::new()
                .initial_delay(Duration::from_secs(1))
                .backoff(1.5)
                .timeout(Duration::from_secs(120)),
        )
        .await?;
    Ok((private_key_pem, chain_pem))
}

async fn self_check_http(identifier: &str, token: &str) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;
    let response = client
        .get(format!(
            "http://{identifier}/.well-known/acme-challenge/{token}"
        ))
        .send()
        .await
        .map_err(|error| anyhow!("{}", error.without_url()))?;
    if !response.status().is_success() {
        bail!("HTTP {}", response.status());
    }
    let body = response.text().await?;
    if !body.starts_with(token) {
        bail!("a different server answered");
    }
    Ok(())
}

fn current_certificate_id(cert_path: &Path) -> Option<CertificateIdentifier<'static>> {
    let pem = fs::read(cert_path).ok()?;
    let der = cert::leaf_der(&pem).ok()?;
    let der = rustls_pki_types::CertificateDer::from(der);
    CertificateIdentifier::try_from(&der)
        .ok()
        .map(CertificateIdentifier::into_owned)
}

// ---------------------------------------------------------------------------
// Installation

/// Write `contents` next to `path`, fsync, and return the temporary path.
fn write_temporary(path: &Path, contents: &[u8], private: bool) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("{} has no file name", path.display()))?;
    let temporary = parent.join(format!(".{name}.acme.{}", rand::random::<u64>()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options.open(&temporary).with_context(|| {
        format!(
            "writing {} (is the directory writable?)",
            temporary.display()
        )
    })?;
    file.write_all(contents)?;
    file.sync_all()?;
    chown_like_parent(&temporary, parent);
    Ok(temporary)
}

/// When run as root (the CLI), hand the files to the owner of the directory
/// so the unprivileged daemons can read them.
fn chown_like_parent(path: &Path, parent: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        if let Ok(meta) = fs::metadata(parent) {
            let _ = std::os::unix::fs::chown(path, Some(meta.uid()), Some(meta.gid()));
        }
    }
}

fn install(
    cert_path: &Path,
    key_path: &Path,
    chain_pem: &str,
    key_pem: &str,
    config: &Config,
) -> Result<()> {
    let cert_tmp = write_temporary(cert_path, chain_pem.as_bytes(), false)?;
    let key_tmp = match write_temporary(key_path, key_pem.as_bytes(), true) {
        Ok(path) => path,
        Err(error) => {
            let _ = fs::remove_file(&cert_tmp);
            return Err(error);
        }
    };
    let result = (|| -> Result<()> {
        // Refuse to install anything the TLS services would reject.
        let material = crate::tls::load_server_tls_material(
            &cert_tmp.to_string_lossy(),
            &key_tmp.to_string_lossy(),
            None,
        )?;
        crate::tls::build_server_config(material, &config.global.tls)
            .context("the issued certificate does not satisfy the TLS policy")?;
        fs::rename(&key_tmp, key_path)
            .with_context(|| format!("installing {}", key_path.display()))?;
        fs::rename(&cert_tmp, cert_path)
            .with_context(|| format!("installing {}", cert_path.display()))?;
        for dir in [cert_path.parent(), key_path.parent()]
            .into_iter()
            .flatten()
        {
            if let Ok(dir) = fs::File::open(dir) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    })();
    let _ = fs::remove_file(&cert_tmp);
    let _ = fs::remove_file(&key_tmp);
    result
}

/// Point `global.tls_cert`/`tls_key` at the installed files when they were
/// unset. Returns whether the settings changed.
fn point_settings_at(
    config: &Config,
    cert_path: &Path,
    key_path: &Path,
    progress: &mut Progress,
) -> Result<bool> {
    if config.global.tls_cert.is_some() && config.global.tls_key.is_some() {
        return Ok(false);
    }
    let Some(db_path) = config.global.db_path.as_deref() else {
        return Ok(false);
    };
    let mut conn = crate::settings::open(db_path)?;
    let changes = BTreeMap::from([
        (
            "global.tls_cert".to_string(),
            serde_json::Value::from(cert_path.display().to_string()),
        ),
        (
            "global.tls_key".to_string(),
            serde_json::Value::from(key_path.display().to_string()),
        ),
    ]);
    crate::settings::update(&mut conn, &changes)?;
    progress.step(
        "Set global.tls_cert and global.tls_key to the new files. Restart the rMail services once to enable TLS; later renewals are picked up automatically",
    );
    Ok(true)
}

// ---------------------------------------------------------------------------
// Renewal

#[derive(Debug, Clone, Serialize)]
pub struct RenewalCheck {
    pub due: bool,
    pub reason: String,
    /// When the certificate becomes due, if it is not yet.
    pub due_at: Option<i64>,
}

/// Decide from local state alone whether the installed certificate needs
/// replacing.
pub fn renewal_check(config: &Config, status: &AcmeStatus) -> RenewalCheck {
    let due = |reason: String| RenewalCheck {
        due: true,
        reason,
        due_at: None,
    };
    let names = match certificate_names(config) {
        Ok(names) => names,
        Err(error) => return due(format!("{error:#}")),
    };
    let (cert_path, _, _) = certificate_paths(config);
    let info = match cert::inspect_file(&cert_path) {
        Ok(info) => info,
        Err(_) => return due(format!("no certificate at {}", cert_path.display())),
    };
    if !info.covers(&names) {
        return due("the certificate does not cover every configured name".into());
    }
    if let Ok(directory) = directory_url(&config.acme)
        && status.issued_by.as_deref() != Some(directory.as_str())
    {
        return due("the certificate was not issued by the configured CA".into());
    }
    let now = now();
    if info.not_after <= now {
        return due("the certificate has expired".into());
    }
    let (due_at, source) = match status.renewal_window {
        Some((start, _)) => (start, "the CA's renewal window"),
        None => (
            info.not_before + info.lifetime_secs() * 2 / 3,
            "two thirds of its lifetime",
        ),
    };
    if now >= due_at {
        return due(format!(
            "{source} has been reached (expires {})",
            format_time(info.not_after)
        ));
    }
    RenewalCheck {
        due: false,
        reason: format!(
            "valid until {}; renewal from {} ({source})",
            format_time(info.not_after),
            format_time(due_at)
        ),
        due_at: Some(due_at),
    }
}

/// Refresh the CA's suggested renewal window (RFC 9773) for the installed
/// certificate. Failures are ignored: the lifetime rule still applies.
async fn refresh_renewal_window(config: &Config, db_path: &str) {
    let Ok(directory) = directory_url(&config.acme) else {
        return;
    };
    let (cert_path, _, _) = certificate_paths(config);
    let Some(id) = current_certificate_id(&cert_path) else {
        return;
    };
    let stored: Option<String> = open(db_path).ok().and_then(|conn| {
        conn.query_row(
            "SELECT credentials FROM acme_accounts WHERE directory = ?1",
            params![directory],
            |row| row.get(0),
        )
        .optional()
        .ok()
        .flatten()
    });
    let Some(credentials) = stored.and_then(|raw| serde_json::from_str(&raw).ok()) else {
        return;
    };
    let window = async {
        let account = Account::builder()?.from_credentials(credentials).await?;
        let (info, _) = account.renewal_info(&id).await?;
        Ok::<_, instant_acme::Error>((
            info.suggested_window.start.unix_timestamp(),
            info.suggested_window.end.unix_timestamp(),
        ))
    }
    .await;
    let _ = update_status(db_path, |status| {
        status.renewal_window_checked_at = Some(now());
        if let Ok(window) = window {
            status.renewal_window = Some(window);
        }
    });
}

/// One pass of the renewal scheduler: renew when due, honoring the failure
/// backoff. Returns the outcome when a run happened.
pub async fn renew_if_due(config: &Config, trigger: &str) -> Result<Option<RunOutcome>> {
    if !config.acme.enabled {
        return Ok(None);
    }
    let db_path = config
        .global
        .db_path
        .clone()
        .ok_or_else(|| anyhow!("ACME needs the settings database (global.db_path)"))?;
    let status = load_status(&db_path)?;
    if status.retry_after.is_some_and(|at| at > now()) {
        return Ok(None);
    }
    if status
        .renewal_window_checked_at
        .is_none_or(|at| now() - at >= ARI_REFRESH_SECS)
    {
        refresh_renewal_window(config, &db_path).await;
    }
    let status = load_status(&db_path)?;
    let check = renewal_check(config, &status);
    if !check.due {
        return Ok(None);
    }
    acme_log!("info", "acme_renewal_due", { "reason": check.reason });
    run(
        config,
        RunOptions {
            trigger: trigger.to_string(),
            dry_run: false,
            echo: false,
        },
    )
    .await
    .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(extra: &str) -> Config {
        toml::from_str(&format!(
            "[global]\nmail_root = \"mail\"\nhostname = \"mail.example.com\"\n{extra}"
        ))
        .unwrap()
    }

    #[test]
    fn names_default_to_the_hostname_and_are_canonicalized() {
        let cfg = config("");
        assert_eq!(certificate_names(&cfg).unwrap(), ["mail.example.com"]);
        let cfg = config(
            "[acme]\ndomains = [\"Mail.Example.com\", \"*.example.com\", \"mail.example.com\"]\n",
        );
        assert_eq!(
            certificate_names(&cfg).unwrap(),
            ["mail.example.com", "*.example.com"]
        );
        let cfg = config("[acme]\ndomains = [\"localhost\"]\n");
        assert!(certificate_names(&cfg).is_err());
    }

    #[test]
    fn validation_is_skipped_while_disabled_and_strict_when_enabled() {
        assert!(validate_config(&config("[acme]\nchallenge = \"dns-01\"\n")).is_ok());
        let err = validate_config(&config("[acme]\nenabled = true\nchallenge = \"dns-01\"\n"))
            .unwrap_err();
        assert!(err.to_string().contains("acme.dns.provider"), "{err}");
        let err = validate_config(&config(
            "[acme]\nenabled = true\ndomains = [\"*.example.com\"]\n",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("wildcard"), "{err}");
        let err =
            validate_config(&config("[acme]\nenabled = true\nca = \"zerossl\"\n")).unwrap_err();
        assert!(
            err.to_string().contains("external account binding"),
            "{err}"
        );
        assert!(
            validate_config(&config(
                "[acme]\nenabled = true\nchallenge = \"dns-01\"\n[acme.dns]\nprovider = \"cloudflare\"\napi_token = \"t\"\n"
            ))
            .is_ok()
        );
        let err = validate_config(&config(
            "[acme]\nenabled = true\nchallenge = \"dns-01\"\n[acme.dns]\nprovider = \"rfc2136\"\nrfc2136_server = \"192.0.2.1\"\ntsig_key_name = \"k\"\ntsig_secret = \"not base64!\"\n",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("base64"), "{err}");
        let err = validate_config(&config(
            "[global.tls]\nocsp_response = \"/x\"\n[acme]\nenabled = true\n",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("ocsp"), "{err}");
    }

    #[test]
    fn managed_paths_are_used_when_tls_paths_are_unset() {
        let (cert, key, update) = certificate_paths(&config(""));
        assert_eq!(cert, Path::new("mail/tls/fullchain.pem"));
        assert_eq!(key, Path::new("mail/tls/privkey.pem"));
        assert!(update);
        let (cert, _, update) =
            certificate_paths(&config("tls_cert = \"/c.pem\"\ntls_key = \"/k.pem\"\n"));
        assert_eq!(cert, Path::new("/c.pem"));
        assert!(!update);
    }

    #[test]
    fn challenges_expire_and_status_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("rmail.db").display().to_string();
        put_challenge(&db, "tok", "tok.thumb").unwrap();
        assert_eq!(
            challenge_response(&db, "tok").unwrap().as_deref(),
            Some("tok.thumb")
        );
        assert_eq!(challenge_response(&db, "other").unwrap(), None);
        delete_challenge(&db, "tok").unwrap();
        assert_eq!(challenge_response(&db, "tok").unwrap(), None);

        update_status(&db, |status| status.consecutive_failures = 3).unwrap();
        assert_eq!(load_status(&db).unwrap().consecutive_failures, 3);
    }

    #[test]
    fn renewal_is_due_for_missing_foreign_or_mismatched_certificates() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config("[acme]\nenabled = true\n");
        cfg.global.mail_root = dir.path().display().to_string();
        let status = AcmeStatus::default();
        let check = renewal_check(&cfg, &status);
        assert!(
            check.due && check.reason.contains("no certificate"),
            "{check:?}"
        );

        let (cert_path, key_path) = crate::test_support::localhost_cert();
        cfg.global.tls_cert = Some(cert_path.to_string());
        cfg.global.tls_key = Some(key_path.to_string());
        let check = renewal_check(&cfg, &status);
        assert!(check.due && check.reason.contains("cover"), "{check:?}");

        cfg.acme.domains = vec!["localhost.example".into()];
        cfg.global.hostname = None;
        let check = renewal_check(&cfg, &status);
        assert!(check.due, "{check:?}");
    }

    #[test]
    fn install_rejects_mismatched_material_and_keeps_old_files() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("fullchain.pem");
        let key_path = dir.path().join("privkey.pem");
        fs::write(&cert_path, "old").unwrap();
        let cfg = config("");
        assert!(install(&cert_path, &key_path, "not a cert", "not a key", &cfg).is_err());
        assert_eq!(fs::read_to_string(&cert_path).unwrap(), "old");
        assert!(!key_path.exists());
        let leftovers = fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(leftovers, 1, "temporary files must be removed");

        let (source_cert, source_key) = crate::test_support::localhost_cert();
        install(
            &cert_path,
            &key_path,
            &fs::read_to_string(source_cert).unwrap(),
            &fs::read_to_string(source_key).unwrap(),
            &cfg,
        )
        .unwrap();
        assert!(
            fs::read_to_string(&cert_path)
                .unwrap()
                .contains("BEGIN CERTIFICATE")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
