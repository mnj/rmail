// rmail_web: admin console and JSON API (minimal tokio HTTP server; see api.rs)

#![allow(clippy::ptr_arg, clippy::too_many_arguments, clippy::type_complexity)]

use anyhow::{Context, Result};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use rand::rngs::OsRng;
use rmail_common::config::Config;
use rmail_common::http::serve_connection;
use rmail_common::net::bind_tcp_listener_with_config;
use rmail_common::outbound::QueueControl;
use rmail_common::runtime::GracefulShutdown;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
#[cfg(test)]
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};
use tokio::task::JoinSet;
use tokio::time::timeout;

macro_rules! web_log {
    ($level:expr, $event:expr, $fields:tt) => {
        rmail_common::structured_log!($level, "web", $event, $fields)
    };
}

mod api;

#[derive(Serialize)]
struct Stats {
    mailboxes: usize,
    total_messages: usize,
    delivered_count: u64,
    outbound_pending: usize,
}

#[derive(Serialize)]
struct AccountSummary {
    address: String,
    auth: String,
    folders: usize,
    messages: usize,
    unseen: usize,
    used_bytes: u64,
    quota_bytes: Option<u64>,
}

#[derive(Serialize)]
struct RoutingSummary {
    aliases: Vec<AliasSummary>,
    catchalls: Vec<CatchallSummary>,
}

#[derive(Serialize)]
struct AliasSummary {
    address: String,
    targets: Vec<String>,
}

#[derive(Serialize)]
struct CatchallSummary {
    domain: String,
    target: String,
}

#[derive(Serialize)]
struct QueueSummary {
    queued: usize,
    inflight: usize,
    sent: usize,
    failed: usize,
}

#[derive(Serialize)]
struct OverviewSummary {
    accounts: usize,
    folders: usize,
    total_messages: usize,
    unseen_messages: usize,
    aliases: usize,
    catchalls: usize,
    domains: Vec<DomainSummary>,
    top_mailboxes: Vec<MailboxLoadSummary>,
    queue: QueueSummary,
    used_bytes: u64,
    near_quota: Vec<QuotaPressure>,
}

#[derive(Clone, Default)]
struct ReadinessConfig {
    tls_cert: Option<String>,
    tls_key: Option<String>,
    tls_policy: rmail_common::config::TlsPolicy,
    security: rmail_common::config::SecurityConfig,
    check_dns: bool,
}

#[derive(Serialize)]
struct ReadinessReport {
    ready: bool,
    checks: BTreeMap<String, ProbeResult>,
}

#[derive(Serialize)]
struct ProbeResult {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl ProbeResult {
    fn ok() -> Self {
        Self {
            status: "ok",
            error: None,
        }
    }

    fn skipped() -> Self {
        Self {
            status: "skipped",
            error: None,
        }
    }

    fn from_result(result: Result<()>) -> Self {
        match result {
            Ok(()) => Self::ok(),
            Err(error) => Self {
                status: "error",
                error: Some(error.to_string()),
            },
        }
    }
}

async fn readiness_report(
    mail_root: PathBuf,
    db_path: Option<String>,
    config: ReadinessConfig,
) -> ReadinessReport {
    let queue = tokio::task::spawn_blocking(move || probe_queue(&mail_root))
        .await
        .unwrap_or_else(|error| Err(anyhow::anyhow!("queue probe task failed: {error}")));
    let database = if let Some(db_path) = db_path {
        tokio::task::spawn_blocking(move || probe_database(Path::new(&db_path)))
            .await
            .unwrap_or_else(|error| Err(anyhow::anyhow!("database probe task failed: {error}")))
            .into()
    } else {
        None
    };
    let certificates = probe_certificates(
        config.tls_cert.as_deref(),
        config.tls_key.as_deref(),
        &config.tls_policy,
    );
    let dns = if config.check_dns {
        Some(
            timeout(
                Duration::from_secs(2),
                rmail_common::mail_auth::dns_health_check(),
            )
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("DNS probe timed out"))),
        )
    } else {
        None
    };
    let clamav = if config.security.clamav_enabled {
        Some(probe_clamav(&config.security.clamav_endpoint).await)
    } else {
        None
    };
    let rspamd = if config.security.rspamd_enabled {
        Some(probe_rspamd(&config.security.rspamd_url).await)
    } else {
        None
    };

    let mut checks = BTreeMap::new();
    checks.insert("queue".to_string(), ProbeResult::from_result(queue));
    checks.insert(
        "database".to_string(),
        database.map_or_else(ProbeResult::skipped, ProbeResult::from_result),
    );
    checks.insert(
        "certificates".to_string(),
        ProbeResult::from_result(certificates),
    );
    checks.insert(
        "dns".to_string(),
        dns.map_or_else(ProbeResult::skipped, ProbeResult::from_result),
    );
    checks.insert(
        "clamav".to_string(),
        clamav.map_or_else(ProbeResult::skipped, ProbeResult::from_result),
    );
    checks.insert(
        "rspamd".to_string(),
        rspamd.map_or_else(ProbeResult::skipped, ProbeResult::from_result),
    );
    ReadinessReport {
        ready: checks.values().all(|probe| probe.status != "error"),
        checks,
    }
}

fn probe_queue(mail_root: &Path) -> Result<()> {
    let directory = mail_root.join("outbound").join("maildrop").join("tmp");
    std::fs::create_dir_all(&directory).context("creating outbound queue directories")?;
    let path = directory.join(format!(
        ".readiness-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .context("creating queue readiness probe")?;
        file.write_all(b"ready")?;
        Ok(())
    })();
    let _ = std::fs::remove_file(&path);
    result
}

fn probe_database(path: &Path) -> Result<()> {
    let connection = rmail_common::sqlite_pool::connection(path)?;
    connection.query_row("SELECT 1", [], |_| Ok(()))?;
    Ok(())
}

fn probe_certificates(
    cert: Option<&str>,
    key: Option<&str>,
    policy: &rmail_common::config::TlsPolicy,
) -> Result<()> {
    match (cert, key) {
        (None, None) => Ok(()),
        (Some(_), None) | (None, Some(_)) => {
            anyhow::bail!("TLS certificate and key must both be configured")
        }
        (Some(cert), Some(key)) => {
            let material = rmail_common::tls::load_server_tls_material(
                cert,
                key,
                policy.ocsp_response.as_deref(),
            )?;
            rmail_common::tls::build_server_config(material, policy)?;
            Ok(())
        }
    }
}

async fn probe_clamav(endpoint: &str) -> Result<()> {
    timeout(Duration::from_secs(2), async {
        if let Some(path) = endpoint.strip_prefix("unix:") {
            UnixStream::connect(path).await?;
        } else if let Some(address) = endpoint.strip_prefix("tcp:") {
            TcpStream::connect(address).await?;
        } else {
            anyhow::bail!("unsupported ClamAV endpoint");
        }
        Ok(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("ClamAV probe timed out"))?
}

async fn probe_rspamd(url: &str) -> Result<()> {
    timeout(
        Duration::from_secs(2),
        reqwest::Client::new().get(url).send(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Rspamd probe timed out"))??;
    Ok(())
}

#[derive(Serialize)]
struct DomainSummary {
    domain: String,
    accounts: usize,
    messages: usize,
    unseen: usize,
}

#[derive(Serialize)]
struct MailboxLoadSummary {
    address: String,
    messages: usize,
    unseen: usize,
    folders: usize,
}

#[derive(Serialize)]
struct QuotaPressure {
    address: String,
    used_bytes: u64,
    quota_bytes: u64,
}

/// Share of its quota at which a mailbox is reported on the overview.
const QUOTA_WARNING_PERCENT: u64 = 90;

#[derive(Deserialize)]
struct AccountRequest {
    address: String,
    password: Option<String>,
    password_hash: Option<String>,
    /// Storage quota in MiB. Zero removes the limit; absent keeps it.
    quota_mib: Option<u64>,
    /// Set for updates: fail instead of creating a new mailbox.
    #[serde(skip)]
    must_exist: bool,
}

#[derive(Deserialize)]
struct AccountDeleteRequest {
    address: String,
}

#[derive(Deserialize)]
struct AliasRequest {
    address: String,
    targets: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct CatchallRequest {
    domain: String,
    target: Option<String>,
}

fn tail_lines(s: &str, n: usize) -> String {
    let mut out: Vec<&str> = s.lines().rev().take(n).collect();
    out.reverse();
    out.join("\n")
}

fn admin_app_html() -> &'static str {
    r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>rMail Admin</title>
  <style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;color:#1d252c}code{background:#eef2f3;padding:.1rem .3rem;border-radius:4px}</style>
</head>
<body>
  <div id="root">
    <h1>rMail Admin</h1>
    <p>The admin console frontend is not installed. Build it with
    <code>cd crates/webui/frontend &amp;&amp; bun install &amp;&amp; bun run build</code>
    or set <code>RMAIL_WEB_STATIC_DIR</code> to the built <code>dist</code> directory.</p>
    <p>The JSON API under <code>/api/</code> and <code>/metrics</code> remain available.</p>
  </div>
</body>
</html>"##
}

fn admin_static_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(dir) = std::env::var("RMAIL_WEB_STATIC_DIR") {
        dirs.push(PathBuf::from(dir));
    }
    dirs.push(PathBuf::from("/usr/share/rmail/admin"));
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd.join("crates/webui/frontend/dist"));
    }
    dirs
}

fn static_content_type(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()).unwrap_or("") {
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "ico" => "image/x-icon",
        "html" => "text/html; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn read_admin_static(path: &str) -> Option<(&'static str, Vec<u8>)> {
    let relative = if path == "/" {
        "index.html"
    } else {
        path.trim_start_matches('/')
    };
    if relative
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return None;
    }
    for dir in admin_static_dirs() {
        if !dir.is_dir() {
            continue;
        }
        let requested = dir.join(relative);
        let file_path = if requested.is_file() {
            requested
        } else if path == "/" || !path.starts_with("/api/") {
            dir.join("index.html")
        } else {
            continue;
        };
        if file_path.is_file()
            && let Ok(body) = std::fs::read(&file_path)
        {
            return Some((static_content_type(&file_path), body));
        }
    }
    None
}

fn scan_maildirs_sync(mail_root: &std::path::Path) -> Result<Stats> {
    let mut mailbox_count = 0usize;
    let mut total_messages = 0usize;
    if !mail_root.exists() || !mail_root.is_dir() {
        return Ok(Stats {
            mailboxes: 0,
            total_messages: 0,
            delivered_count: 0,
            outbound_pending: 0,
        });
    }
    for domain_entry in std::fs::read_dir(mail_root)? {
        let domain_entry = domain_entry?;
        if !domain_entry.file_type()?.is_dir() {
            continue;
        }
        let domain_path = domain_entry.path();
        for local_entry in std::fs::read_dir(domain_path)? {
            let local_entry = local_entry?;
            if !local_entry.file_type()?.is_dir() {
                continue;
            }
            let maildir_path = local_entry.path().join("Maildir");
            if !maildir_path.exists() {
                continue;
            }
            mailbox_count += 1;
            for dname in ["new", "cur"] {
                let dirpath = maildir_path.join(dname);
                if dirpath.exists() && dirpath.is_dir() {
                    for entry in std::fs::read_dir(&dirpath)? {
                        let e = entry?;
                        if e.file_type()?.is_file() {
                            total_messages += 1;
                        }
                    }
                }
            }
        }
    }
    Ok(Stats {
        mailboxes: mailbox_count,
        total_messages,
        delivered_count: 0,
        outbound_pending: count_queue_entries_sync(mail_root)?,
    })
}

fn split_address(address: &str) -> Option<(&str, &str)> {
    let (local, domain) = address.split_once('@')?;
    if local.is_empty() || domain.is_empty() {
        None
    } else {
        Some((local, domain))
    }
}

fn normalize_address(address: &str) -> Result<String> {
    let address = address.trim().to_ascii_lowercase();
    let Some((local, domain)) = split_address(&address) else {
        anyhow::bail!("invalid mailbox address");
    };
    if local.contains('/') || domain.contains('/') || local.contains('\\') || domain.contains('\\')
    {
        anyhow::bail!("invalid mailbox address");
    }
    Ok(address)
}

fn password_material(
    password: Option<&str>,
    password_hash: Option<&str>,
) -> Result<(Option<String>, Option<String>)> {
    if let Some(hash) = password_hash {
        return Ok((Some(hash.to_string()), None));
    }
    let Some(password) = password else {
        return Ok((None, None));
    };
    let mut rng = OsRng;
    let salt = SaltString::generate(&mut rng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?
        .to_string();
    // SASLprep rejects some passwords (e.g. control characters); those can
    // still log in with PLAIN/LOGIN but get no SCRAM verifier.
    let scram = rmail_common::auth::create_scram_verifier(password, 4096).ok();
    Ok((Some(hash), scram))
}

fn account_summaries_sync(
    mail_root: &std::path::Path,
    db_path: Option<&str>,
) -> Result<Vec<AccountSummary>> {
    let mut accounts = Vec::new();
    if let Some(db_path) = db_path {
        for mailbox in rmail_common::db::list_mailboxes(db_path)? {
            let mut folders = 0usize;
            let mut messages = 0usize;
            let mut unseen = 0usize;
            let mut used_bytes = 0u64;
            if let Some((local, domain)) = split_address(&mailbox.address)
                && let Ok(summaries) =
                    rmail_common::imap_state::list_folder_summaries(mail_root, domain, local)
            {
                folders = summaries.len();
                messages = summaries.iter().map(|summary| summary.messages).sum();
                unseen = summaries.iter().map(|summary| summary.unseen).sum();
                used_bytes = summaries.iter().map(|summary| summary.size).sum();
            }
            accounts.push(AccountSummary {
                address: mailbox.address,
                auth: if mailbox.scram.is_some() {
                    "SCRAM".to_string()
                } else if mailbox.password_hash.is_some() {
                    "Password".to_string()
                } else {
                    "Unset".to_string()
                },
                folders,
                messages,
                unseen,
                used_bytes,
                quota_bytes: mailbox.quota_bytes,
            });
        }
    }
    accounts.sort_by(|a, b| a.address.cmp(&b.address));
    Ok(accounts)
}

fn routing_summary_sync(db_path: Option<&str>) -> Result<RoutingSummary> {
    let Some(db_path) = db_path else {
        return Ok(RoutingSummary {
            aliases: Vec::new(),
            catchalls: Vec::new(),
        });
    };
    Ok(RoutingSummary {
        aliases: rmail_common::db::list_aliases(db_path)?
            .into_iter()
            .map(|(address, targets)| AliasSummary { address, targets })
            .collect(),
        catchalls: rmail_common::db::list_catchalls(db_path)?
            .into_iter()
            .map(|(domain, target)| CatchallSummary { domain, target })
            .collect(),
    })
}

fn upsert_account_sync(
    mail_root: &std::path::Path,
    db_path: &str,
    req: AccountRequest,
) -> Result<()> {
    let address = normalize_address(&req.address)?;
    let (local, domain) = split_address(&address).expect("validated address");
    let existing = rmail_common::db::get_mailbox(db_path, &address)?;
    if req.must_exist && existing.is_none() {
        anyhow::bail!("mailbox {address} does not exist");
    }
    let password = req
        .password
        .as_deref()
        .filter(|password| !password.is_empty());
    let (password_hash, scram) = match (
        password_material(password, req.password_hash.as_deref())?,
        &existing,
    ) {
        // No new password: keep the current credentials instead of clearing them.
        ((None, None), Some(existing)) => (existing.password_hash.clone(), existing.scram.clone()),
        (material, _) => material,
    };
    let maildir_path = mail_root.join(domain).join(local).join("Maildir");
    rmail_common::maildir::ensure_maildir(&maildir_path)?;
    rmail_common::db::add_mailbox(
        db_path,
        &address,
        password_hash.as_deref(),
        Some(&maildir_path.to_string_lossy()),
        scram.as_deref(),
    )?;
    if let Some(quota_mib) = req.quota_mib {
        let quota_bytes = if quota_mib == 0 {
            None
        } else {
            Some(
                quota_mib
                    .checked_mul(1024 * 1024)
                    .ok_or_else(|| anyhow::anyhow!("quota is too large"))?,
            )
        };
        rmail_common::db::set_mailbox_quota(db_path, &address, quota_bytes)?;
        rmail_common::imap_state::set_storage_quota(mail_root, domain, local, quota_bytes)?;
    }
    Ok(())
}

fn delete_account_sync(db_path: &str, req: AccountDeleteRequest) -> Result<()> {
    let address = normalize_address(&req.address)?;
    rmail_common::db::remove_mailbox(db_path, &address)
}

fn upsert_alias_sync(db_path: &str, req: AliasRequest) -> Result<()> {
    let address = normalize_address(&req.address)?;
    let targets = req.targets.unwrap_or_default();
    if targets.is_empty() {
        rmail_common::db::remove_alias(db_path, &address)
    } else {
        let refs = targets.iter().map(String::as_str).collect::<Vec<_>>();
        rmail_common::db::add_alias(db_path, &address, &refs)
    }
}

fn upsert_catchall_sync(db_path: &str, req: CatchallRequest) -> Result<()> {
    let domain = req.domain.trim().to_ascii_lowercase();
    if domain.is_empty() || domain.contains('/') || domain.contains('\\') {
        anyhow::bail!("invalid domain");
    }
    if let Some(target) = req.target {
        let target = normalize_address(&target)?;
        rmail_common::db::set_catchall(db_path, &domain, &target)
    } else {
        rmail_common::db::remove_catchall(db_path, &domain)
    }
}

// --- on-disk queue helper functions (synchronous) ---
fn spool_dirs(base: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let base = base.join("outbound");
    (
        base.join("maildrop").join("queue"),
        base.join("maildrop").join("inflight"),
        base.join("sent"),
        base.join("failed"),
    )
}

fn count_queue_entries_sync(root: &std::path::Path) -> Result<usize> {
    let queue_dir = root.join("outbound").join("maildrop").join("queue");
    if !queue_dir.exists() {
        return Ok(0);
    }
    let mut count = 0usize;
    for entry in std::fs::read_dir(queue_dir)? {
        let ent = entry?;
        if ent.file_type()?.is_file()
            && ent.path().extension().and_then(|s| s.to_str()) == Some("eml")
        {
            count += 1;
        }
    }
    Ok(count)
}

fn count_eml_files(dir: &std::path::Path) -> Result<usize> {
    if !dir.exists() {
        return Ok(0);
    }
    let mut count = 0usize;
    for entry in std::fs::read_dir(dir)? {
        let ent = entry?;
        if ent.file_type()?.is_file()
            && ent.path().extension().and_then(|s| s.to_str()) == Some("eml")
        {
            count += 1;
        }
    }
    Ok(count)
}

fn queue_summary_sync(root: &PathBuf) -> Result<QueueSummary> {
    let (queue, inflight, sent, failed) = spool_dirs(root);
    Ok(QueueSummary {
        queued: count_eml_files(&queue)?,
        inflight: count_eml_files(&inflight)?,
        sent: count_eml_files(&sent)?,
        failed: count_eml_files(&failed)?,
    })
}

fn overview_summary_sync(
    mail_root: &std::path::Path,
    db_path: Option<&str>,
) -> Result<OverviewSummary> {
    let accounts = account_summaries_sync(mail_root, db_path)?;
    let routing = routing_summary_sync(db_path)?;
    let queue = queue_summary_sync(&mail_root.to_path_buf())?;

    let mut domains = HashMap::<String, DomainSummary>::new();
    for account in &accounts {
        if let Some((_, domain)) = split_address(&account.address) {
            let entry = domains.entry(domain.to_string()).or_insert(DomainSummary {
                domain: domain.to_string(),
                accounts: 0,
                messages: 0,
                unseen: 0,
            });
            entry.accounts += 1;
            entry.messages += account.messages;
            entry.unseen += account.unseen;
        }
    }

    let mut domains = domains.into_values().collect::<Vec<_>>();
    domains.sort_by(|a, b| {
        b.messages
            .cmp(&a.messages)
            .then_with(|| b.accounts.cmp(&a.accounts))
            .then_with(|| a.domain.cmp(&b.domain))
    });

    let mut top_mailboxes = accounts
        .iter()
        .map(|account| MailboxLoadSummary {
            address: account.address.clone(),
            messages: account.messages,
            unseen: account.unseen,
            folders: account.folders,
        })
        .collect::<Vec<_>>();
    top_mailboxes.sort_by(|a, b| {
        b.messages
            .cmp(&a.messages)
            .then_with(|| b.unseen.cmp(&a.unseen))
            .then_with(|| a.address.cmp(&b.address))
    });
    top_mailboxes.truncate(8);

    let mut near_quota = accounts
        .iter()
        .filter_map(|account| {
            let quota = account.quota_bytes.filter(|quota| *quota > 0)?;
            (account.used_bytes.saturating_mul(100) >= quota.saturating_mul(QUOTA_WARNING_PERCENT))
                .then(|| QuotaPressure {
                    address: account.address.clone(),
                    used_bytes: account.used_bytes,
                    quota_bytes: quota,
                })
        })
        .collect::<Vec<_>>();
    near_quota.sort_by(|a, b| {
        (b.used_bytes as f64 / b.quota_bytes as f64)
            .total_cmp(&(a.used_bytes as f64 / a.quota_bytes as f64))
            .then_with(|| a.address.cmp(&b.address))
    });

    Ok(OverviewSummary {
        used_bytes: accounts.iter().map(|account| account.used_bytes).sum(),
        near_quota,
        accounts: accounts.len(),
        folders: accounts.iter().map(|account| account.folders).sum(),
        total_messages: accounts.iter().map(|account| account.messages).sum(),
        unseen_messages: accounts.iter().map(|account| account.unseen).sum(),
        aliases: routing.aliases.len(),
        catchalls: routing.catchalls.len(),
        domains,
        top_mailboxes,
        queue,
    })
}

fn read_queue_entries(dir: &PathBuf) -> Result<Vec<serde_json::Value>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for e in std::fs::read_dir(dir)? {
        let ent = e?;
        if !ent.file_type()?.is_file() {
            continue;
        }
        let fname = ent.file_name().into_string().unwrap_or_default();
        if !fname.ends_with(".eml") {
            continue;
        }
        let jsonp = rmail_common::outbound::control_path_for_eml(&dir.join(&fname));
        let control = if jsonp.exists() {
            match std::fs::read_to_string(&jsonp) {
                Ok(s) => serde_json::from_str::<QueueControl>(&s)
                    .ok()
                    .map(|c| serde_json::to_value(c).unwrap_or(serde_json::json!(null))),
                Err(_) => Some(serde_json::json!(null)),
            }
        } else {
            None
        };
        let mut obj = serde_json::json!({"name": fname});
        if let Some(c) = control {
            obj["control"] = c;
        }
        out.push(obj);
    }
    out.sort_by(|a, b| {
        a["name"]
            .as_str()
            .unwrap_or("")
            .cmp(b["name"].as_str().unwrap_or(""))
    });
    Ok(out)
}

fn ensure_ext(name: &str) -> String {
    if name.ends_with(".eml") {
        name.to_string()
    } else {
        format!("{}.eml", name)
    }
}

fn find_message_sync(
    root: &PathBuf,
    name: &str,
) -> Result<Option<(String, PathBuf, Option<PathBuf>)>> {
    if name.is_empty() || name.contains(['/', '\\', '\0']) || name.starts_with('.') {
        anyhow::bail!("invalid message name");
    }
    let fname = ensure_ext(name);
    let (queue, inflight, sent, failed) = spool_dirs(root);
    let candidates = vec![
        ("queue", queue),
        ("inflight", inflight),
        ("sent", sent),
        ("failed", failed),
    ];
    for (spool, dir) in candidates {
        let eml = dir.join(&fname);
        if eml.exists() && eml.is_file() {
            let jsonp = rmail_common::outbound::control_path_for_eml(&eml);
            let j = if jsonp.exists() { Some(jsonp) } else { None };
            return Ok(Some((spool.to_string(), eml, j)));
        }
    }
    Ok(None)
}

fn read_control_opt_sync(jsonp: &Option<PathBuf>) -> Option<QueueControl> {
    if let Some(p) = jsonp {
        match std::fs::read_to_string(p) {
            Ok(s) => serde_json::from_str::<QueueControl>(&s).ok(),
            Err(_) => None,
        }
    } else {
        None
    }
}

fn write_control_sync(path: &PathBuf, ctrl: &QueueControl) -> Result<()> {
    let j = serde_json::to_string_pretty(ctrl)?;
    std::fs::write(path, j)?;
    Ok(())
}

fn move_with_json_sync(
    src_eml: &PathBuf,
    dst_dir: &PathBuf,
    json_opt: &Option<PathBuf>,
) -> Result<(PathBuf, Option<PathBuf>)> {
    std::fs::create_dir_all(dst_dir)?;
    let fname = src_eml
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid filename"))?
        .to_string();
    let dst_eml = dst_dir.join(&fname);
    std::fs::rename(src_eml, &dst_eml)?;
    let dst_json = if let Some(jp) = json_opt {
        let dstj = dst_dir.join(jp.file_name().and_then(|n| n.to_str()).unwrap_or(""));
        std::fs::rename(jp, &dstj).ok();
        Some(dstj)
    } else {
        None
    };
    Ok((dst_eml, dst_json))
}

fn matches_pattern(name: &str, pattern: &str) -> bool {
    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        let mut rem = name;
        for (i, p) in parts.iter().enumerate() {
            if p.is_empty() {
                continue;
            }
            if let Some(pos) = rem.find(p) {
                if i == 0 && !pattern.starts_with('*') && pos != 0 {
                    return false;
                }
                rem = &rem[pos + p.len()..];
            } else {
                return false;
            }
        }
        if !pattern.ends_with('*')
            && let Some(last) = parts.iter().rev().find(|s| !s.is_empty())
            && !name.ends_with(last)
        {
            return false;
        }
        true
    } else {
        name == pattern || name == format!("{}.eml", pattern) || name.contains(pattern)
    }
}

fn find_messages_matching_sync(
    root: &PathBuf,
    pattern: &str,
) -> Result<Vec<(String, PathBuf, Option<PathBuf>, String)>> {
    let (queue, inflight, sent, failed) = spool_dirs(root);
    let mut out = Vec::new();
    let dirs = vec![
        ("queue", queue),
        ("inflight", inflight),
        ("sent", sent),
        ("failed", failed),
    ];
    for (spool, dir) in dirs {
        if !dir.exists() {
            continue;
        }
        for e in std::fs::read_dir(&dir)? {
            let ent = e?;
            if !ent.file_type()?.is_file() {
                continue;
            }
            let fname = ent.file_name().into_string().unwrap_or_default();
            if !fname.ends_with(".eml") {
                continue;
            }
            if matches_pattern(&fname, pattern)
                || matches_pattern(&fname, &format!("{}.eml", pattern))
                || matches_pattern(&fname, pattern.trim_matches('*'))
            {
                let eml = dir.join(&fname);
                let jsonp = rmail_common::outbound::control_path_for_eml(&eml);
                let j = if jsonp.exists() { Some(jsonp) } else { None };
                out.push((spool.to_string(), eml, j, fname));
            }
        }
    }
    Ok(out)
}

fn requeue_single_sync(
    spool: &str,
    eml: &PathBuf,
    jsonp: &Option<PathBuf>,
    root: &PathBuf,
) -> Result<()> {
    let (queue, _inflight, _sent, _failed) = spool_dirs(root);
    if spool == "queue" {
        if let Some(j) = jsonp
            && let Some(mut ctrl) = read_control_opt_sync(&Some(j.clone()))
        {
            ctrl.attempts = 0;
            ctrl.next_try = None;
            write_control_sync(j, &ctrl)?;
        }
        return Ok(());
    }
    let (_dst_eml, dst_json) = move_with_json_sync(eml, &queue, jsonp)?;
    if let Some(jp) = dst_json {
        let mut ctrl = read_control_opt_sync(&Some(jp.clone()))
            .unwrap_or_else(|| QueueControl::default_with_timestamp(0));
        ctrl.attempts = 0;
        ctrl.next_try = None;
        write_control_sync(&jp, &ctrl)?;
    }
    Ok(())
}

fn promote_single_sync(
    spool: &str,
    eml: &PathBuf,
    jsonp: &Option<PathBuf>,
    root: &PathBuf,
    priority: i32,
) -> Result<()> {
    let (queue, _inflight, _sent, _failed) = spool_dirs(root);
    let dst_json = if spool == "queue" {
        jsonp.clone()
    } else {
        let (_dst_eml, dst_json) = move_with_json_sync(eml, &queue, jsonp)?;
        dst_json
    };
    if let Some(jp) = dst_json {
        let mut ctrl = read_control_opt_sync(&Some(jp.clone()))
            .unwrap_or_else(|| QueueControl::default_with_timestamp(0));
        ctrl.priority = priority;
        write_control_sync(&jp, &ctrl)?;
    }
    Ok(())
}

fn delete_single_sync(
    _spool: &str,
    eml: &PathBuf,
    jsonp: &Option<PathBuf>,
    root: &PathBuf,
) -> Result<()> {
    let (_queue, _inflight, _sent, failed) = spool_dirs(root);
    let (_dst_eml, dst_json) = move_with_json_sync(eml, &failed, jsonp)?;
    if let Some(jp) = dst_json {
        let mut ctrl = read_control_opt_sync(&Some(jp.clone()))
            .unwrap_or_else(|| QueueControl::default_with_timestamp(0));
        ctrl.attempts = ctrl.max_attempts;
        ctrl.last_error = Some("deleted by admin".to_string());
        write_control_sync(&jp, &ctrl)?;
    }
    Ok(())
}

/// Serve one admin connection. Kept as a free function for tests.
#[cfg(test)]
async fn handle_connection<S>(
    stream: S,
    peer: String,
    mail_root: PathBuf,
    admin_user: Option<String>,
    admin_hash: Option<String>,
    db_path: Option<String>,
    readiness: ReadinessConfig,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let state = api::AdminState::new(mail_root, db_path, admin_user.zip(admin_hash), readiness);
    api::serve(stream, peer, Arc::new(state)).await;
}

fn readiness_from_config(cfg: &Config) -> ReadinessConfig {
    ReadinessConfig {
        tls_cert: cfg.global.tls_cert.clone(),
        tls_key: cfg.global.tls_key.clone(),
        tls_policy: cfg.global.tls.clone(),
        security: cfg.security.clone(),
        check_dns: true,
    }
}

async fn metrics_text(mail_root: &Path) -> String {
    // Aggregate process-local snapshots with one bounded component label.
    let mut metrics_text = String::new();
    let mut have_metadata = false;
    for component in ["smtpd", "outbound", "imapd", "web"] {
        let Ok(snapshot) = tokio::fs::read_to_string(
            rmail_common::runtime::prometheus_snapshot_path(mail_root, component),
        )
        .await
        else {
            continue;
        };
        let labeled = rmail_common::metrics::add_component_label(&snapshot, component);
        for line in labeled.lines() {
            if !line.starts_with('#') || !have_metadata {
                metrics_text.push_str(line);
                metrics_text.push('\n');
            }
        }
        have_metadata = true;
    }
    if metrics_text.is_empty() {
        metrics_text = rmail_common::metrics::add_component_label(
            &rmail_common::metrics::gather_prometheus(),
            "web",
        );
    }
    let root = mail_root.to_path_buf();
    match tokio::task::spawn_blocking(move || count_queue_entries_sync(&root)).await {
        Ok(Ok(pending)) => {
            metrics_text
                .push_str("# HELP rmail_outbound_pending Number of pending outbound messages\n");
            metrics_text.push_str("# TYPE rmail_outbound_pending gauge\n");
            metrics_text.push_str(&format!("rmail_outbound_pending {pending}\n"));
        }
        Ok(Err(error)) => {
            web_log!("error", "queue_metrics_failed", { "error": error.to_string() });
        }
        Err(error) => {
            web_log!("error", "queue_metrics_failed", { "error": error.to_string() });
        }
    }
    metrics_text
}

fn dmarc_summary_sync(db_path: &str) -> Result<Vec<serde_json::Value>> {
    let mut out = Vec::new();
    for domain in rmail_common::db::get_unreported_dmarc_domains(db_path)? {
        let events = rmail_common::db::fetch_unreported_dmarc_events_for_domain(db_path, &domain)?;
        out.push(json!({"domain": domain, "events": events.len()}));
    }
    Ok(out)
}

fn queue_listing_sync(mail_root: &PathBuf, spool: &str) -> Result<serde_json::Value> {
    let (queue, inflight, sent, failed) = spool_dirs(mail_root);
    let dir = match spool {
        "queue" => queue,
        "inflight" => inflight,
        "sent" => sent,
        "failed" => failed,
        _ => anyhow::bail!("unknown spool {spool:?}"),
    };
    let entries = read_queue_entries(&dir)?;
    // "queued" is kept for older clients of this endpoint.
    Ok(json!({"spool": spool, "entries": entries, "queued": entries}))
}

fn settings_view_sync(db_path: &str) -> Result<serde_json::Value> {
    let conn = rmail_common::settings::open(db_path)?;
    let mut view = serde_json::to_value(rmail_common::settings::describe(&conn)?)?;
    view["managed"] = json!(true);
    view["restart_available"] = json!(rmail_common::restart::helper_installed());
    Ok(view)
}

/// Accept connections on `listener` until shutdown, terminating TLS when a
/// context is available.
fn spawn_listener(
    listeners: &mut JoinSet<()>,
    addr: String,
    listener: tokio::net::TcpListener,
    app: axum::Router,
    tls: rmail_common::tls::ServerTlsReceiver,
    listener_shutdown: GracefulShutdown,
) {
    listeners.spawn(async move {
        let mut shutdown_signal = listener_shutdown.subscribe();
        loop {
            if *shutdown_signal.borrow() {
                break;
            }
            let (stream, peer) = tokio::select! {
                _ = shutdown_signal.changed() => break,
                accepted = listener.accept() => match accepted {
                    Ok(value) => value,
                    Err(e) => {
                        web_log!("error", "listener_accept_failed", { "address": addr, "error": e.to_string() });
                        break;
                    }
                },
            };
            let session = listener_shutdown.start_session();
            let tls_context = tls.borrow().clone();
            let app = app.clone();
            let stop = listener_shutdown.subscribe();
            tokio::spawn(async move {
                let _session = session;
                let served = match tls_context {
                    Some(context) => {
                        match timeout(Duration::from_secs(15), context.acceptor.accept(stream)).await {
                            Ok(Ok(stream)) => serve_connection(stream, Some(peer), app, Some(stop)).await,
                            Ok(Err(error)) => {
                                web_log!("error", "tls_handshake_failed", { "peer": peer.to_string(), "error": error.to_string() });
                                return;
                            }
                            Err(_) => {
                                web_log!("warn", "tls_handshake_timeout", { "peer": peer.to_string() });
                                return;
                            }
                        }
                    }
                    None => serve_connection(stream, Some(peer), app, Some(stop)).await,
                };
                if let Err(error) = served {
                    web_log!("debug", "connection_error", { "peer": peer.to_string(), "error": error.to_string() });
                }
            });
        }
    });
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg_path =
        std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let cfg = Config::load(&cfg_path).with_context(|| format!("loading {cfg_path}"))?;
    rmail_common::runtime::set_log_level(cfg.global.log_level.as_deref());
    let mail_root = PathBuf::from(&cfg.global.mail_root);
    rmail_common::runtime::redirect_stdio_to_log(&mail_root, "web").context("redirecting logs")?;
    if let Err(error) = rmail_common::settings::record_service_start(&cfg, "web") {
        web_log!("warn", "service_state_failed", { "error": format!("{error:#}") });
    }
    let _metrics_task = rmail_common::metrics::spawn_prometheus_snapshot_task(&mail_root, "web")?;
    let bind_addrs = cfg.global.admin_listeners();
    let tls = rmail_common::tls::web_tls_channel(&cfg.global)?;
    let tls_active = tls.1.borrow().is_some();

    let mut state = api::AdminState::new(
        mail_root.clone(),
        cfg.global.db_path.clone(),
        cfg.global
            .web_admin_user
            .clone()
            .zip(cfg.global.web_admin_password_hash.clone()),
        readiness_from_config(&cfg),
    );
    state.config_path = Some(cfg_path.clone());
    state.http_redirect_url = cfg
        .global
        .http_redirect_url
        .clone()
        .filter(|url| !url.trim().is_empty());
    state.secure_cookies = tls_active || cfg.global.tls.web_http_only;
    if let Some(db_path) = cfg.global.db_path.as_deref() {
        // A persistent key keeps admins signed in across restarts.
        let mut conn = rmail_common::settings::open(db_path)?;
        state.session_key =
            rmail_common::settings::internal_secret(&mut conn, "admin_session_key")?.into_bytes();
    }
    // Without credentials the console runs in first-run setup mode, where the
    // first visitor chooses the admin password. Never allow that remotely.
    let has_credentials =
        cfg.global.web_admin_user.is_some() && cfg.global.web_admin_password_hash.is_some();
    if !has_credentials {
        let exposed = bind_addrs
            .iter()
            .filter(|address| !rmail_common::http::is_loopback_bind(address))
            .cloned()
            .collect::<Vec<_>>();
        if !exposed.is_empty() {
            anyhow::bail!(
                "refusing to serve the admin console on {} without admin credentials; \
                 run `rmail_ctl admin-password` or bind it to 127.0.0.1 and complete setup in the browser",
                exposed.join(", ")
            );
        }
        web_log!("warn", "admin_setup_mode", { "reason": "no admin credentials configured; the first visitor on a loopback listener sets them" });
    }
    let state = Arc::new(state);
    let app = api::router(state.clone());
    let http_app = api::certificates::http_router(state);
    if cfg.global.db_path.is_some() {
        api::certificates::spawn_renewal_task(cfg_path.clone());
    }

    rmail_common::tls::spawn_web_tls_reloader(
        tls.0.clone(),
        cfg.global.tls_cert.clone(),
        cfg.global.tls_key.clone(),
        cfg.global.tls.clone(),
        "web admin",
    );
    let listener_config = cfg.global.tcp_listener.clone();
    let shutdown = GracefulShutdown::new();
    let mut listeners = JoinSet::new();
    for addr in bind_addrs {
        let listener = bind_tcp_listener_with_config(&addr, &listener_config)?;
        web_log!("info", "listener_started", { "address": addr, "tls_configured": tls_active });
        spawn_listener(
            &mut listeners,
            addr,
            listener,
            app.clone(),
            tls.1.clone(),
            shutdown.clone(),
        );
    }
    // Plain HTTP (port 80): ACME challenges and a redirect to HTTPS.
    let (_, no_tls) = tokio::sync::watch::channel(None);
    for addr in cfg.global.http_listeners() {
        let listener = bind_tcp_listener_with_config(&addr, &listener_config)
            .with_context(|| format!("binding the plain HTTP listener {addr}"))?;
        web_log!("info", "http_listener_started", { "address": addr });
        spawn_listener(
            &mut listeners,
            addr,
            listener,
            http_app.clone(),
            no_tls.clone(),
            shutdown.clone(),
        );
    }
    rmail_common::runtime::wait_for_shutdown_signal().await?;
    web_log!("info", "shutdown_requested", { "active_requests": shutdown.active_sessions() });
    shutdown.request();
    while let Some(result) = listeners.join_next().await {
        if let Err(error) = result {
            web_log!("error", "shutdown_listener_join_failed", { "error": error.to_string() });
        }
    }
    if !shutdown.wait_for_sessions(Duration::from_secs(30)).await {
        web_log!("warn", "shutdown_drain_timed_out", { "active_requests": shutdown.active_sessions() });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmail_common::outbound::{QueueControl, control_path_for_eml};
    use std::fs;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn send_request(mail_root: PathBuf, request: String) -> String {
        send_request_with_db(mail_root, request, None).await
    }

    async fn send_request_with_db(
        mail_root: PathBuf,
        request: String,
        db_path: Option<String>,
    ) -> String {
        send_request_with_readiness(mail_root, request, db_path, ReadinessConfig::default()).await
    }

    async fn send_request_with_readiness(
        mail_root: PathBuf,
        request: String,
        db_path: Option<String>,
        readiness: ReadinessConfig,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            handle_connection(
                stream,
                "test-client".to_string(),
                mail_root,
                None,
                None,
                db_path,
                readiness,
            )
            .await;
        });

        let mut client = TcpStream::connect(addr).await.expect("connect");
        client
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        client.shutdown().await.expect("shutdown");

        let mut response = String::new();
        client
            .read_to_string(&mut response)
            .await
            .expect("read response");
        server.await.expect("server");
        response
    }

    #[tokio::test]
    async fn liveness_and_readiness_have_distinct_semantics() {
        let td = tempdir().expect("tempdir");
        let health = send_request(
            td.path().to_path_buf(),
            "GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n".to_string(),
        )
        .await;
        assert!(health.starts_with("HTTP/1.1 200 OK"), "{health}");

        let db_path = td.path().join("rmail.sqlite");
        rmail_common::db::init_db(&db_path).unwrap();
        let ready = send_request_with_db(
            td.path().to_path_buf(),
            "GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n".to_string(),
            Some(db_path.to_string_lossy().into_owned()),
        )
        .await;
        assert!(ready.starts_with("HTTP/1.1 200 OK"), "{ready}");
        assert!(ready.contains("\"ready\":true"), "{ready}");
        assert!(
            ready.contains("\"database\":{\"status\":\"ok\"}"),
            "{ready}"
        );
        assert!(ready.contains("\"queue\":{\"status\":\"ok\"}"), "{ready}");
        assert!(ready.contains("\"checks\":"), "{ready}");
        assert!(!ready.contains("\"components\":"), "{ready}");
    }

    #[tokio::test]
    async fn readiness_reports_dependency_failures_with_service_unavailable() {
        let td = tempdir().expect("tempdir");
        let readiness = ReadinessConfig {
            tls_cert: Some(td.path().join("missing.pem").to_string_lossy().into_owned()),
            tls_key: None,
            ..ReadinessConfig::default()
        };
        let response = send_request_with_readiness(
            td.path().to_path_buf(),
            "GET /ready HTTP/1.1\r\nHost: localhost\r\n\r\n".to_string(),
            None,
            readiness,
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 503 Service Unavailable"),
            "{response}"
        );
        assert!(response.contains("\"ready\":false"), "{response}");
        assert!(
            response.contains("\"certificates\":{\"status\":\"error\""),
            "{response}"
        );
    }

    #[tokio::test]
    async fn scanner_readiness_probes_enabled_services() {
        let clamav = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let clamav_address = clamav.local_addr().unwrap();
        let clamav_task = tokio::spawn(async move {
            let _ = clamav.accept().await.unwrap();
        });
        assert!(probe_clamav(&format!("tcp:{clamav_address}")).await.is_ok());
        clamav_task.await.unwrap();

        let rspamd = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rspamd_address = rspamd.local_addr().unwrap();
        let rspamd_task = tokio::spawn(async move {
            let (mut stream, _) = rspamd.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        assert!(
            probe_rspamd(&format!("http://{rspamd_address}/checkv2"))
                .await
                .is_ok()
        );
        rspamd_task.await.unwrap();
    }

    #[tokio::test]
    async fn root_serves_modern_admin_console() {
        let td = tempdir().expect("tempdir");
        let request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_string();

        let response = send_request(td.path().to_path_buf(), request).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("rMail Admin"), "{response}");
        assert!(
            response.contains("id=\"root\"") || response.contains("Account Management"),
            "{response}"
        );
    }

    #[tokio::test]
    async fn account_api_reports_db_mailboxes_and_maildir_state() {
        let td = tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Subject: hello\r\n\r\nbody\r\n",
        )
        .expect("deliver");

        let request = "GET /api/accounts HTTP/1.1\r\nHost: localhost\r\n\r\n".to_string();
        let response = send_request_with_db(
            mail_root,
            request,
            Some(db_path.to_string_lossy().to_string()),
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(
            response.contains("\"address\":\"user@example.test\""),
            "{response}"
        );
        assert!(response.contains("\"messages\":1"), "{response}");
        assert!(response.contains("\"unseen\":1"), "{response}");
    }

    #[tokio::test]
    async fn account_api_creates_and_deletes_mailboxes() {
        let td = tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");

        let body = r#"{"address":"New@Example.Test","password":"secret","quota_mib":256}"#;
        let request = format!(
            "POST /api/accounts HTTP/1.1\r\nHost: localhost\r\nX-Rmail-Admin: 1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let response = send_request_with_db(
            mail_root.clone(),
            request,
            Some(db_path.to_string_lossy().to_string()),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        let mailbox = rmail_common::db::get_mailbox(&db_path, "new@example.test")
            .unwrap()
            .expect("mailbox");
        assert_eq!(mailbox.quota_bytes, Some(256 * 1024 * 1024));
        assert_eq!(
            rmail_common::imap_state::storage_quota(mail_root.as_path(), "example.test", "new")
                .unwrap(),
            (0, Some(256 * 1024 * 1024))
        );
        assert!(mail_root.join("example.test/new/Maildir").is_dir());

        let body = r#"{"address":"new@example.test"}"#;
        let request = format!(
            "DELETE /api/accounts HTTP/1.1\r\nHost: localhost\r\nX-Rmail-Admin: 1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let response = send_request_with_db(
            mail_root,
            request,
            Some(db_path.to_string_lossy().to_string()),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(
            rmail_common::db::get_mailbox(&db_path, "new@example.test")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn routing_api_manages_aliases_and_catchalls() {
        let td = tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");

        let alias =
            r#"{"address":"team@example.test","targets":["a@example.test","b@example.test"]}"#;
        let request = format!(
            "POST /api/routing/alias HTTP/1.1\r\nHost: localhost\r\nX-Rmail-Admin: 1\r\nContent-Length: {}\r\n\r\n{}",
            alias.len(),
            alias
        );
        let response = send_request_with_db(
            mail_root.clone(),
            request,
            Some(db_path.to_string_lossy().to_string()),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

        let catchall = r#"{"domain":"example.test","target":"postmaster@example.test"}"#;
        let request = format!(
            "POST /api/routing/catchall HTTP/1.1\r\nHost: localhost\r\nX-Rmail-Admin: 1\r\nContent-Length: {}\r\n\r\n{}",
            catchall.len(),
            catchall
        );
        let response = send_request_with_db(
            mail_root.clone(),
            request,
            Some(db_path.to_string_lossy().to_string()),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

        let request = "GET /api/routing HTTP/1.1\r\nHost: localhost\r\n\r\n".to_string();
        let response = send_request_with_db(
            mail_root,
            request,
            Some(db_path.to_string_lossy().to_string()),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(
            response.contains("\"address\":\"team@example.test\""),
            "{response}"
        );
        assert!(
            response.contains("\"domain\":\"example.test\""),
            "{response}"
        );
        assert!(
            response.contains("\"target\":\"postmaster@example.test\""),
            "{response}"
        );
    }

    #[tokio::test]
    async fn overview_api_reports_domain_mailbox_and_queue_load() {
        let td = tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "alice@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add alice");
        rmail_common::db::add_mailbox(
            &db_path,
            "bob@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add bob");
        rmail_common::db::add_alias(
            &db_path,
            "team@example.test",
            &["alice@example.test", "bob@example.test"],
        )
        .expect("add alias");
        rmail_common::db::set_catchall(&db_path, "example.test", "alice@example.test")
            .expect("set catchall");
        // A quota smaller than one message puts alice over the warning line.
        rmail_common::db::set_mailbox_quota(&db_path, "alice@example.test", Some(16))
            .expect("set quota");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "alice",
            b"Subject: hello\r\n\r\nbody\r\n",
        )
        .expect("deliver alice");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "bob",
            b"Subject: hello\r\n\r\nbody\r\n",
        )
        .expect("deliver bob");
        let queue = mail_root.join("outbound/maildrop/queue");
        fs::create_dir_all(&queue).expect("queue dir");
        fs::write(queue.join("msg.eml"), b"body").expect("queue message");

        let request = "GET /api/overview HTTP/1.1\r\nHost: localhost\r\n\r\n".to_string();
        let response = send_request_with_db(
            mail_root,
            request,
            Some(db_path.to_string_lossy().to_string()),
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("\"accounts\":2"), "{response}");
        assert!(response.contains("\"total_messages\":2"), "{response}");
        assert!(response.contains("\"unseen_messages\":2"), "{response}");
        assert!(response.contains("\"aliases\":1"), "{response}");
        assert!(response.contains("\"catchalls\":1"), "{response}");
        let body: serde_json::Value =
            serde_json::from_str(response.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert!(body["used_bytes"].as_u64().unwrap() > 0, "{response}");
        let near_quota = body["near_quota"].as_array().unwrap();
        assert_eq!(near_quota.len(), 1, "{response}");
        assert_eq!(near_quota[0]["address"], "alice@example.test");
        assert_eq!(near_quota[0]["quota_bytes"], 16);
        assert!(
            response.contains("\"domain\":\"example.test\""),
            "{response}"
        );
        assert!(
            response.contains("\"address\":\"alice@example.test\"")
                || response.contains("\"address\":\"bob@example.test\""),
            "{response}"
        );
        assert!(response.contains("\"queued\":1"), "{response}");
    }

    #[tokio::test]
    async fn queue_summary_counts_all_spools() {
        let td = tempdir().expect("tempdir");
        let mail_root = td.path().to_path_buf();
        for spool in [
            "outbound/maildrop/queue",
            "outbound/maildrop/inflight",
            "outbound/sent",
            "outbound/failed",
        ] {
            let dir = mail_root.join(spool);
            fs::create_dir_all(&dir).expect("spool dir");
            fs::write(dir.join("msg.eml"), b"body").expect("message");
        }

        let request = "GET /api/queue/summary HTTP/1.1\r\nHost: localhost\r\n\r\n".to_string();
        let response = send_request(mail_root, request).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("\"queued\":1"), "{response}");
        assert!(response.contains("\"inflight\":1"), "{response}");
        assert!(response.contains("\"sent\":1"), "{response}");
        assert!(response.contains("\"failed\":1"), "{response}");
    }

    #[tokio::test]
    async fn queue_action_post_requeues_failed_message_with_sidecar() {
        let td = tempdir().expect("tempdir");
        let mail_root = td.path().to_path_buf();
        let failed = mail_root.join("outbound").join("failed");
        fs::create_dir_all(&failed).expect("failed dir");

        let eml = failed.join("msg.eml");
        fs::write(&eml, b"X-RMail-Envelope-To: user@example.com\r\n\r\nbody").expect("write eml");
        let mut control = QueueControl::new(5, 0);
        control.attempts = 3;
        control.next_try = Some(123);
        let sidecar = control_path_for_eml(&eml);
        fs::write(
            &sidecar,
            serde_json::to_string(&control).expect("control json"),
        )
        .expect("write sidecar");

        let body = r#"{"action":"requeue","name":"msg.eml"}"#;
        let request = format!(
            "POST /api/queue/action HTTP/1.1\r\nHost: localhost\r\nX-Rmail-Admin: 1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        let response = send_request(mail_root.clone(), request).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

        let queued = mail_root
            .join("outbound")
            .join("maildrop")
            .join("queue")
            .join("msg.eml");
        let queued_sidecar = control_path_for_eml(&queued);
        assert!(queued.exists());
        assert!(queued_sidecar.exists());
        assert!(!eml.exists());
        assert!(!sidecar.exists());

        let updated: QueueControl =
            serde_json::from_str(&fs::read_to_string(queued_sidecar).expect("read sidecar"))
                .expect("parse sidecar");
        assert_eq!(updated.attempts, 0);
        assert_eq!(updated.next_try, None);
    }

    #[tokio::test]
    async fn queue_action_get_is_method_not_allowed() {
        let td = tempdir().expect("tempdir");
        let request = "GET /api/queue/action HTTP/1.1\r\nHost: localhost\r\n\r\n".to_string();

        let response = send_request(td.path().to_path_buf(), request).await;
        assert!(
            response.starts_with("HTTP/1.1 405 Method Not Allowed"),
            "{response}"
        );
    }

    async fn send_to_state(state: Arc<api::AdminState>, peer: &str, request: String) -> String {
        let (mut client, server) = tokio::io::duplex(1 << 20);
        let peer = peer.to_string();
        let task = tokio::spawn(async move { api::serve(server, peer, state).await });
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        task.await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    fn hash(password: &str) -> String {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string()
    }

    fn post(path: &str, body: &str, extra: &str) -> String {
        format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nX-Rmail-Admin: 1\r\n{extra}Content-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    fn cookie_from(response: &str) -> String {
        response
            .lines()
            .find_map(|line| line.strip_prefix("Set-Cookie: "))
            .and_then(|cookie| cookie.split(';').next())
            .expect("session cookie")
            .to_string()
    }

    #[tokio::test]
    async fn acme_challenge_rejects_path_traversal() {
        let td = tempdir().unwrap();
        let db = td.path().join("rmail.db").display().to_string();
        rmail_common::acme::put_challenge(&db, "good-token_1", "good-token_1.thumb").unwrap();
        fs::write(td.path().join("secret.txt"), "TOPSECRET").unwrap();
        let state = Arc::new(api::AdminState::new(
            td.path().to_path_buf(),
            Some(db),
            Some(("admin".into(), hash("correct horse battery"))),
            ReadinessConfig::default(),
        ));
        let ok = send_to_state(
            state.clone(),
            "t",
            "GET /.well-known/acme-challenge/good-token_1 HTTP/1.1\r\n\r\n".into(),
        )
        .await;
        assert!(
            ok.starts_with("HTTP/1.1 200 OK") && ok.ends_with("good-token_1.thumb"),
            "{ok}"
        );
        let unknown = send_to_state(
            state.clone(),
            "t",
            "GET /.well-known/acme-challenge/other HTTP/1.1\r\n\r\n".into(),
        )
        .await;
        assert!(unknown.starts_with("HTTP/1.1 404"), "{unknown}");
        for target in [
            "/.well-known/acme-challenge/../secret.txt".to_string(),
            format!(
                "/.well-known/acme-challenge/{}/secret.txt",
                td.path().display()
            ),
            "/.well-known/acme-challenge/%2e%2e%2fsecret.txt".to_string(),
        ] {
            let response =
                send_to_state(state.clone(), "t", format!("GET {target} HTTP/1.1\r\n\r\n")).await;
            assert!(response.starts_with("HTTP/1.1 404"), "{target}: {response}");
            assert!(!response.contains("TOPSECRET"), "{target}: {response}");
        }
    }

    async fn send_http(state: Arc<api::AdminState>, request: &str) -> String {
        let (mut client, server) = tokio::io::duplex(1 << 16);
        let app = api::certificates::http_router(state);
        let task = tokio::spawn(async move {
            let _ = rmail_common::http::serve_connection(server, None, app, None).await;
        });
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        task.await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    #[tokio::test]
    async fn plain_http_listener_answers_challenges_and_redirects_to_https() {
        let td = tempdir().unwrap();
        let db = td.path().join("rmail.db").display().to_string();
        rmail_common::acme::put_challenge(&db, "tok", "tok.thumb").unwrap();
        let state = |redirect: Option<&str>| {
            let mut state = api::AdminState::new(
                td.path().to_path_buf(),
                Some(db.clone()),
                None,
                ReadinessConfig::default(),
            );
            state.http_redirect_url = redirect.map(str::to_string);
            Arc::new(state)
        };
        let challenge = send_http(
            state(None),
            "GET /.well-known/acme-challenge/tok HTTP/1.1\r\nHost: mail.example.com\r\n\r\n",
        )
        .await;
        assert!(
            challenge.starts_with("HTTP/1.1 200") && challenge.ends_with("tok.thumb"),
            "{challenge}"
        );

        let redirect = send_http(
            state(None),
            "GET /mail/inbox?x=1 HTTP/1.1\r\nHost: mail.example.com:80\r\n\r\n",
        )
        .await;
        assert!(redirect.starts_with("HTTP/1.1 301"), "{redirect}");
        assert!(
            redirect
                .to_ascii_lowercase()
                .contains("location: https://mail.example.com/mail/inbox?x=1"),
            "{redirect}"
        );
        // The admin API is not reachable over plain HTTP.
        let api = send_http(
            state(None),
            "GET /api/settings HTTP/1.1\r\nHost: mail.example.com\r\n\r\n",
        )
        .await;
        assert!(api.starts_with("HTTP/1.1 301"), "{api}");

        let fixed = send_http(
            state(Some("https://webmail.example.com/")),
            "POST /x HTTP/1.1\r\nHost: evil.example\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert!(fixed.starts_with("HTTP/1.1 308"), "{fixed}");
        assert!(
            fixed
                .to_ascii_lowercase()
                .contains("location: https://webmail.example.com/x"),
            "{fixed}"
        );
    }

    #[tokio::test]
    async fn certificates_api_reports_configuration_and_guards_runs() {
        let td = tempdir().unwrap();
        let db = td.path().join("rmail.db");
        let config_path = td.path().join("config.toml");
        fs::write(
            &config_path,
            format!(
                "[global]\nmail_root = {:?}\ndb_path = {:?}\nhostname = \"mail.example.com\"\n",
                td.path().display().to_string(),
                db.display().to_string()
            ),
        )
        .unwrap();
        let mut state = api::AdminState::new(
            td.path().to_path_buf(),
            Some(db.display().to_string()),
            None,
            ReadinessConfig::default(),
        );
        state.config_path = Some(config_path.display().to_string());
        let state = Arc::new(state);

        let overview = send_to_state(
            state.clone(),
            "127.0.0.1:1",
            "GET /api/certificates HTTP/1.1\r\nHost: localhost\r\n\r\n".into(),
        )
        .await;
        assert!(overview.starts_with("HTTP/1.1 200"), "{overview}");
        let body: serde_json::Value =
            serde_json::from_str(overview.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body["enabled"], false);
        assert_eq!(body["names"], json!(["mail.example.com"]));
        assert_eq!(body["challenge"], "http-01");
        assert_eq!(body["running"], false);

        // A real run requires ACME to be enabled first.
        let refused = send_to_state(
            state.clone(),
            "127.0.0.1:1",
            post("/api/certificates/issue", "{}", ""),
        )
        .await;
        assert!(refused.starts_with("HTTP/1.1 409"), "{refused}");

        // Enabling http-01 without a port-80 listener warns about it.
        let mut conn = rmail_common::settings::open(&db).unwrap();
        rmail_common::settings::update(
            &mut conn,
            &BTreeMap::from([("acme.enabled".to_string(), json!(true))]),
        )
        .unwrap();
        let overview = send_to_state(
            state.clone(),
            "127.0.0.1:1",
            "GET /api/certificates HTTP/1.1\r\nHost: localhost\r\n\r\n".into(),
        )
        .await;
        let body: serde_json::Value =
            serde_json::from_str(overview.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body["enabled"], true);
        assert_eq!(body["renewal"]["due"], true);
        let warnings = body["warnings"].to_string();
        assert!(warnings.contains("port 80"), "{warnings}");
        assert!(warnings.contains("restart"), "{warnings}");
    }

    #[tokio::test]
    async fn restart_endpoint_needs_a_database_and_the_helper_unit() {
        let td = tempdir().unwrap();
        let no_db = Arc::new(api::AdminState::new(
            td.path().to_path_buf(),
            None,
            None,
            ReadinessConfig::default(),
        ));
        let response = send_to_state(no_db, "t", post("/api/services/restart", "", "")).await;
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");

        let db = td.path().join("rmail.db");
        rmail_common::settings::open(db.to_str().unwrap()).unwrap();
        let state = Arc::new(api::AdminState::new(
            td.path().to_path_buf(),
            Some(db.display().to_string()),
            None,
            ReadinessConfig::default(),
        ));
        let response = send_to_state(state, "t", post("/api/services/restart", "", "")).await;
        let expected = if rmail_common::restart::helper_installed() {
            "HTTP/1.1 400" // nothing is waiting for a restart
        } else {
            "HTTP/1.1 501"
        };
        assert!(response.starts_with(expected), "{response}");
        assert!(!rmail_common::restart::request_path(td.path()).exists());
    }

    #[tokio::test]
    async fn oversized_bodies_are_rejected_before_allocation() {
        let td = tempdir().unwrap();
        let state = Arc::new(api::AdminState::new(
            td.path().to_path_buf(),
            None,
            None,
            ReadinessConfig::default(),
        ));
        let response = send_to_state(
            state,
            "t",
            "POST /api/accounts HTTP/1.1\r\nContent-Length: 99999999999\r\n\r\n".into(),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 413"), "{response}");
    }

    #[tokio::test]
    async fn api_requires_credentials_and_csrf_header() {
        let td = tempdir().unwrap();
        let state = Arc::new(api::AdminState::new(
            td.path().to_path_buf(),
            None,
            Some(("admin".into(), hash("correct horse battery"))),
            ReadinessConfig::default(),
        ));
        let anonymous = send_to_state(
            state.clone(),
            "t",
            "GET /api/queue/summary HTTP/1.1\r\n\r\n".into(),
        )
        .await;
        assert!(anonymous.starts_with("HTTP/1.1 401"), "{anonymous}");

        let basic = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "admin:correct horse battery",
        );
        let authorized = send_to_state(
            state.clone(),
            "t",
            format!("GET /api/queue/summary HTTP/1.1\r\nAuthorization: Basic {basic}\r\n\r\n"),
        )
        .await;
        assert!(authorized.starts_with("HTTP/1.1 200"), "{authorized}");

        let no_csrf = send_to_state(
            state.clone(),
            "t",
            format!(
                "POST /api/queue/action HTTP/1.1\r\nAuthorization: Basic {basic}\r\nContent-Length: 2\r\n\r\n{{}}"
            ),
        )
        .await;
        assert!(no_csrf.starts_with("HTTP/1.1 403"), "{no_csrf}");

        let cross_origin = send_to_state(
            state,
            "t",
            post(
                "/api/queue/action",
                "{}",
                &format!("Authorization: Basic {basic}\r\nOrigin: https://evil.example\r\n"),
            ),
        )
        .await;
        assert!(cross_origin.starts_with("HTTP/1.1 403"), "{cross_origin}");
    }

    #[tokio::test]
    async fn login_issues_session_and_throttles_guessing() {
        let td = tempdir().unwrap();
        let state = Arc::new(api::AdminState::new(
            td.path().to_path_buf(),
            None,
            Some(("admin".into(), hash("correct horse battery"))),
            ReadinessConfig::default(),
        ));
        let peer = "192.0.2.10:5555";
        let login = send_to_state(
            state.clone(),
            peer,
            post(
                "/api/login",
                r#"{"username":"admin","password":"correct horse battery"}"#,
                "",
            ),
        )
        .await;
        assert!(login.starts_with("HTTP/1.1 200"), "{login}");
        assert!(login.contains("HttpOnly; SameSite=Strict"), "{login}");
        let cookie = cookie_from(&login);

        let session = send_to_state(
            state.clone(),
            peer,
            format!("GET /api/session HTTP/1.1\r\nCookie: {cookie}\r\n\r\n"),
        )
        .await;
        assert!(session.contains("\"authenticated\":true"), "{session}");
        let summary = send_to_state(
            state.clone(),
            peer,
            format!("GET /api/queue/summary HTTP/1.1\r\nCookie: {cookie}\r\n\r\n"),
        )
        .await;
        assert!(summary.starts_with("HTTP/1.1 200"), "{summary}");

        let logout = send_to_state(
            state.clone(),
            peer,
            post("/api/logout", "", &format!("Cookie: {cookie}\r\n")),
        )
        .await;
        assert!(logout.starts_with("HTTP/1.1 200"), "{logout}");
        let after_logout = send_to_state(
            state.clone(),
            peer,
            format!("GET /api/queue/summary HTTP/1.1\r\nCookie: {cookie}\r\n\r\n"),
        )
        .await;
        assert!(after_logout.starts_with("HTTP/1.1 401"), "{after_logout}");

        let attacker = "198.51.100.7:4444";
        for _ in 0..5 {
            let response = send_to_state(
                state.clone(),
                attacker,
                post(
                    "/api/login",
                    r#"{"username":"admin","password":"wrong"}"#,
                    "",
                ),
            )
            .await;
            assert!(response.starts_with("HTTP/1.1 401"), "{response}");
        }
        let locked = send_to_state(
            state,
            attacker,
            post(
                "/api/login",
                r#"{"username":"admin","password":"correct horse battery"}"#,
                "",
            ),
        )
        .await;
        assert!(locked.starts_with("HTTP/1.1 429"), "{locked}");
    }

    #[tokio::test]
    async fn setup_mode_sets_credentials_and_settings_are_editable() {
        let td = tempdir().unwrap();
        let db_path = td.path().join("rmail.db");
        rmail_common::db::init_db(&db_path).unwrap();
        let db = db_path.to_string_lossy().into_owned();
        let state = Arc::new(api::AdminState::new(
            td.path().to_path_buf(),
            Some(db.clone()),
            None,
            ReadinessConfig::default(),
        ));
        let session = send_to_state(
            state.clone(),
            "t",
            "GET /api/session HTTP/1.1\r\n\r\n".into(),
        )
        .await;
        assert!(session.contains("\"setup_required\":true"), "{session}");
        // The setup screen checks passwords against the policy before submitting.
        let policy: serde_json::Value =
            serde_json::from_str(session.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(policy["password_policy"]["min_length"], 10, "{session}");
        assert_eq!(
            policy["password_policy"]["forbid_username"], true,
            "{session}"
        );

        let short = send_to_state(
            state.clone(),
            "t",
            post(
                "/api/admin/credentials",
                r#"{"username":"root","new_password":"short"}"#,
                "",
            ),
        )
        .await;
        assert!(short.starts_with("HTTP/1.1 422"), "{short}");
        let created = send_to_state(
            state.clone(),
            "t",
            post(
                "/api/admin/credentials",
                r#"{"username":"root","new_password":"a much longer password"}"#,
                "",
            ),
        )
        .await;
        assert!(created.starts_with("HTTP/1.1 200"), "{created}");
        let cookie = cookie_from(&created);

        // Setup mode is over: anonymous requests are now rejected.
        let anonymous = send_to_state(
            state.clone(),
            "t",
            "GET /api/settings HTTP/1.1\r\n\r\n".into(),
        )
        .await;
        assert!(anonymous.starts_with("HTTP/1.1 401"), "{anonymous}");

        let settings = send_to_state(
            state.clone(),
            "t",
            format!("GET /api/settings HTTP/1.1\r\nCookie: {cookie}\r\n\r\n"),
        )
        .await;
        assert!(settings.starts_with("HTTP/1.1 200"), "{settings}");
        assert!(
            settings.contains("security.smtp_max_recipients"),
            "{settings}"
        );
        assert!(
            !settings.contains("argon2"),
            "admin hash leaked: {settings}"
        );

        let body = r#"{"changes":{"security.smtp_max_recipients":0}}"#;
        let invalid = send_to_state(
            state.clone(),
            "t",
            format!(
                "PUT /api/settings HTTP/1.1\r\nX-Rmail-Admin: 1\r\nCookie: {cookie}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert!(invalid.starts_with("HTTP/1.1 422"), "{invalid}");
        let body = r#"{"changes":{"security.smtp_max_recipients":42}}"#;
        let saved = send_to_state(
            state,
            "t",
            format!(
                "PUT /api/settings HTTP/1.1\r\nX-Rmail-Admin: 1\r\nCookie: {cookie}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert!(saved.starts_with("HTTP/1.1 200"), "{saved}");
        let conn = rmail_common::settings::open(&db).unwrap();
        assert_eq!(
            rmail_common::settings::get(&conn, "security.smtp_max_recipients").unwrap(),
            Some(json!(42))
        );
    }

    #[tokio::test]
    async fn updating_quota_keeps_existing_password() {
        let td = tempdir().unwrap();
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).unwrap();
        let db = Some(db_path.to_string_lossy().into_owned());
        for body in [
            r#"{"address":"keep@example.test","password":"secret-password"}"#,
            r#"{"address":"keep@example.test","quota_mib":10}"#,
        ] {
            let response = send_request_with_db(
                mail_root.clone(),
                post("/api/accounts", body, ""),
                db.clone(),
            )
            .await;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        }
        let mailbox = rmail_common::db::get_mailbox(&db_path, "keep@example.test")
            .unwrap()
            .unwrap();
        assert!(mailbox.password_hash.is_some() && mailbox.scram.is_some());
        assert_eq!(mailbox.quota_bytes, Some(10 * 1024 * 1024));

        let body = r#"{"address":"missing@example.test","quota_mib":1}"#;
        let patch = format!(
            "PATCH /api/accounts HTTP/1.1\r\nX-Rmail-Admin: 1\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = send_request_with_db(mail_root, patch, db).await;
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    }

    #[tokio::test]
    async fn queue_actions_reject_path_like_names() {
        let td = tempdir().unwrap();
        let response = send_request(
            td.path().to_path_buf(),
            post(
                "/api/queue/action",
                r#"{"action":"delete","name":"../../x"}"#,
                "",
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    }

    fn organization_db(td: &std::path::Path) -> String {
        let db_path = td.join("rmail.sqlite");
        rmail_common::db::init_db(&db_path).expect("init db");
        db_path.to_string_lossy().into_owned()
    }

    #[tokio::test]
    async fn organization_overview_lists_catalog_and_reports_missing_daemon() {
        let td = tempdir().unwrap();
        let db = organization_db(td.path());
        let response = send_request_with_db(
            td.path().to_path_buf(),
            "GET /api/organization HTTP/1.1\r\nHost: localhost\r\n\r\n".into(),
            Some(db),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(
            response.contains("bge-small-en-v1.5-q8_0.gguf"),
            "{response}"
        );
        assert!(response.contains("\"running\":false"), "{response}");
    }

    #[tokio::test]
    async fn organization_overview_never_returns_api_keys() {
        let td = tempdir().unwrap();
        let db = organization_db(td.path());
        let mut conn = rmail_common::settings::open(&db).unwrap();
        rmail_common::settings::write_raw(
            &mut conn,
            &BTreeMap::from([
                (
                    "classifier.openrouter_api_key".to_string(),
                    Some(serde_json::Value::from("sk-or-secret-123")),
                ),
                (
                    "classifier.chat_provider".to_string(),
                    Some(serde_json::Value::from("jev")),
                ),
            ]),
        )
        .unwrap();
        let response = send_request_with_db(
            td.path().to_path_buf(),
            "GET /api/organization HTTP/1.1\r\nHost: localhost\r\n\r\n".into(),
            Some(db),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(
            !response.contains("sk-or-secret-123"),
            "API key leaked: {response}"
        );
        assert!(
            response.contains("\"openrouter_api_key\":true"),
            "{response}"
        );
        assert!(response.contains("\"chat_provider\":\"jev\""), "{response}");
    }

    #[tokio::test]
    async fn organization_activate_requires_installed_models_of_the_right_kind() {
        let td = tempdir().unwrap();
        let db = organization_db(td.path());
        let models = rmail_common::classifier_models::models_dir(td.path());
        fs::create_dir_all(&models).unwrap();
        fs::write(models.join("embed.gguf"), b"gguf").unwrap();

        let missing = send_request_with_db(
            td.path().to_path_buf(),
            post(
                "/api/organization/activate",
                r#"{"embed_model":"absent.gguf"}"#,
                "",
            ),
            Some(db.clone()),
        )
        .await;
        assert!(missing.starts_with("HTTP/1.1 422"), "{missing}");

        let traversal = send_request_with_db(
            td.path().to_path_buf(),
            post(
                "/api/organization/activate",
                r#"{"embed_model":"../rmail.sqlite"}"#,
                "",
            ),
            Some(db.clone()),
        )
        .await;
        assert!(traversal.starts_with("HTTP/1.1 422"), "{traversal}");

        let ok = send_request_with_db(
            td.path().to_path_buf(),
            post(
                "/api/organization/activate",
                r#"{"enabled":true,"embed_model":"embed.gguf"}"#,
                "",
            ),
            Some(db.clone()),
        )
        .await;
        assert!(ok.starts_with("HTTP/1.1 200 OK"), "{ok}");
        assert!(ok.contains("\"reloaded\":false"), "{ok}");
        let conn = rmail_common::settings::open(&db).unwrap();
        assert_eq!(
            rmail_common::settings::get_string(&conn, "classifier.embed_model")
                .unwrap()
                .as_deref(),
            Some("embed.gguf")
        );

        let refused = send_request_with_db(
            td.path().to_path_buf(),
            post("/api/organization/delete", r#"{"file":"embed.gguf"}"#, ""),
            Some(db.clone()),
        )
        .await;
        assert!(refused.starts_with("HTTP/1.1 400"), "{refused}");
        assert!(models.join("embed.gguf").exists());
    }

    #[tokio::test]
    async fn organization_rejects_unsafe_downloads() {
        let td = tempdir().unwrap();
        let db = organization_db(td.path());
        for body in [
            r#"{"file":"m.gguf","url":"http://example.test/m.gguf","kind":"embedding"}"#,
            r#"{"file":"../m.gguf","url":"https://example.test/m.gguf","kind":"embedding"}"#,
            r#"{"catalog_id":"nope"}"#,
        ] {
            let response = send_request_with_db(
                td.path().to_path_buf(),
                post("/api/organization/download", body, ""),
                Some(db.clone()),
            )
            .await;
            assert!(response.starts_with("HTTP/1.1 400"), "{body}: {response}");
        }
    }

    #[tokio::test]
    async fn organization_tests_are_proxied_to_the_daemon_socket() {
        let td = tempdir().unwrap();
        let db = organization_db(td.path());
        let socket = rmail_common::classifier_control::socket_path(td.path());
        fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let daemon = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut line = String::new();
            tokio::io::AsyncBufReadExt::read_line(&mut tokio::io::BufReader::new(read), &mut line)
                .await
                .unwrap();
            let request: rmail_common::classifier_control::Request =
                serde_json::from_str(line.trim()).unwrap();
            assert_eq!(
                request,
                rmail_common::classifier_control::Request::TestChat {
                    text: "Your flight".into(),
                    folders: vec!["Travel".into(), "Receipts".into()],
                }
            );
            write
                .write_all(b"{\"ok\":true,\"data\":{\"folder\":\"Travel\",\"confidence\":0.9}}\n")
                .await
                .unwrap();
        });
        let response = send_request_with_db(
            td.path().to_path_buf(),
            post(
                "/api/organization/test",
                r#"{"kind":"chat","text":"Your flight","folders":["Travel"," ","Receipts"]}"#,
                "",
            ),
            Some(db),
        )
        .await;
        daemon.await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("\"folder\":\"Travel\""), "{response}");
    }

    fn discovery_state(td: &tempfile::TempDir, mode: &str) -> Arc<api::AdminState> {
        let db = td.path().join("rmail.db");
        rmail_common::db::init_db(&db).unwrap();
        rmail_common::db::add_mailbox(&db, "alice@example.com", None, None, None).unwrap();
        let config = td.path().join("rmail.toml");
        fs::write(
            &config,
            format!(
                "[global]\nmail_root = \"{root}\"\ndb_path = \"{db}\"\nhostname = \"mail.example.com\"\n[global.listeners]\nimaps = [\"[::]:993\"]\nsubmission = [\"[::]:587\"]\n[security]\nmta_sts_mode = \"{mode}\"\n",
                root = td.path().display(),
                db = db.display(),
            ),
        )
        .unwrap();
        let mut state = api::AdminState::new(
            td.path().to_path_buf(),
            Some(db.display().to_string()),
            None,
            ReadinessConfig::default(),
        );
        state.config_path = Some(config.display().to_string());
        Arc::new(state)
    }

    #[tokio::test]
    async fn discovery_endpoints_answer_for_hosted_domains_only() {
        let td = tempdir().unwrap();
        let state = discovery_state(&td, "testing");

        let policy = send_to_state(
            state.clone(),
            "t",
            "GET /.well-known/mta-sts.txt HTTP/1.1\r\nHost: mta-sts.example.com\r\n\r\n".into(),
        )
        .await;
        assert!(policy.starts_with("HTTP/1.1 200"), "{policy}");
        let lower = policy.to_ascii_lowercase();
        assert!(lower.contains("cache-control: no-store"), "{policy}");
        assert!(
            lower.contains("x-content-type-options: nosniff"),
            "{policy}"
        );
        assert!(
            policy.ends_with(
                "version: STSv1\r\nmode: testing\r\nmx: mail.example.com\r\nmax_age: 604800\r\n"
            ),
            "{policy}"
        );
        for request in [
            "GET /.well-known/mta-sts.txt HTTP/1.1\r\nHost: mta-sts.other.test\r\n\r\n",
            "GET /.well-known/mta-sts.txt HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ] {
            let response = send_to_state(state.clone(), "t", request.into()).await;
            assert!(response.starts_with("HTTP/1.1 404"), "{response}");
        }

        let tb = send_to_state(
            state.clone(),
            "t",
            "GET /mail/config-v1.1.xml?emailaddress=alice@example.com HTTP/1.1\r\nHost: autoconfig.example.com\r\n\r\n".into(),
        )
        .await;
        assert!(tb.starts_with("HTTP/1.1 200"), "{tb}");
        assert!(tb.contains("<hostname>mail.example.com</hostname>"), "{tb}");
        assert!(
            tb.contains("<port>993</port>") && tb.contains("<port>587</port>"),
            "{tb}"
        );
        let unknown = send_to_state(
            state.clone(),
            "t",
            "GET /mail/config-v1.1.xml?emailaddress=x@unknown.test HTTP/1.1\r\n\r\n".into(),
        )
        .await;
        assert!(unknown.starts_with("HTTP/1.1 404"), "{unknown}");

        // Outlook posts without the admin CSRF header.
        let body = "<Autodiscover><Request><EMailAddress>alice@example.com</EMailAddress></Request></Autodiscover>";
        let pox = send_to_state(
            state.clone(),
            "t",
            format!(
                "POST /autodiscover/autodiscover.xml HTTP/1.1\r\nHost: autodiscover.example.com\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert!(pox.starts_with("HTTP/1.1 200"), "{pox}");
        assert!(
            pox.contains("<LoginName>alice@example.com</LoginName>"),
            "{pox}"
        );

        // Unicode domains match the ASCII form stored for a hosted IDN.
        rmail_common::db::add_mailbox(
            td.path().join("rmail.db"),
            "bob@bücher.example",
            None,
            None,
            None,
        )
        .unwrap();
        let tb = send_to_state(
            state.clone(),
            "t",
            "GET /mail/config-v1.1.xml?emailaddress=bob%40B%C3%BCcher.example HTTP/1.1\r\n\r\n"
                .into(),
        )
        .await;
        assert!(tb.starts_with("HTTP/1.1 200"), "{tb}");
        let body = "<Autodiscover><Request><EMailAddress>bob@bücher.example</EMailAddress></Request></Autodiscover>";
        let pox = send_to_state(
            state.clone(),
            "t",
            format!(
                "POST /autodiscover/autodiscover.xml HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert!(pox.starts_with("HTTP/1.1 200"), "{pox}");

        // Autoconfig is also served over plain HTTP; MTA-STS is not.
        let http = send_http(
            state.clone(),
            "GET /mail/config-v1.1.xml?emailaddress=alice@example.com HTTP/1.1\r\nHost: autoconfig.example.com\r\n\r\n",
        )
        .await;
        assert!(http.starts_with("HTTP/1.1 200"), "{http}");
        assert!(
            http.to_ascii_lowercase()
                .contains("cache-control: no-store"),
            "{http}"
        );
        let http_sts = send_http(
            state,
            "GET /.well-known/mta-sts.txt HTTP/1.1\r\nHost: mta-sts.example.com\r\n\r\n",
        )
        .await;
        assert!(http_sts.starts_with("HTTP/1.1 301"), "{http_sts}");
    }

    #[tokio::test]
    async fn mta_sts_is_not_published_when_mode_is_none() {
        let td = tempdir().unwrap();
        let response = send_to_state(
            discovery_state(&td, "none"),
            "t",
            "GET /.well-known/mta-sts.txt HTTP/1.1\r\nHost: mta-sts.example.com\r\n\r\n".into(),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    }
}
