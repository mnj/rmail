// rmail_web: minimal tokio-based HTTP UI for stats and logs (no hyper/axum)

#![allow(clippy::ptr_arg, clippy::type_complexity)]

use anyhow::{Context, Result};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use base64::Engine;
use rand::rngs::OsRng;
use rmail_common::auth;
use rmail_common::config::Config;
use rmail_common::net::bind_tcp_listener_with_config;
use rmail_common::outbound::QueueControl;
use rmail_common::runtime::GracefulShutdown;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};
use tokio::task::JoinSet;
use tokio::time::timeout;

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
}

#[derive(Clone, Default)]
struct ReadinessConfig {
    tls_cert: Option<String>,
    tls_key: Option<String>,
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
    let certificates = probe_certificates(config.tls_cert.as_deref(), config.tls_key.as_deref());
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

fn probe_certificates(cert: Option<&str>, key: Option<&str>) -> Result<()> {
    match (cert, key) {
        (None, None) => Ok(()),
        (Some(_), None) | (None, Some(_)) => {
            anyhow::bail!("TLS certificate and key must both be configured")
        }
        (Some(cert), Some(key)) => {
            let certificate_bytes = std::fs::read(cert).context("reading TLS certificate")?;
            let certificates = rustls_pemfile::certs(&mut certificate_bytes.as_slice())
                .context("parsing TLS certificate PEM")?;
            if certificates.is_empty() {
                anyhow::bail!("TLS certificate PEM contains no certificates");
            }
            let key_bytes = std::fs::read(key).context("reading TLS private key")?;
            let mut reader = key_bytes.as_slice();
            let has_private_key = loop {
                match rustls_pemfile::read_one(&mut reader)
                    .context("parsing TLS private key PEM")?
                {
                    Some(
                        rustls_pemfile::Item::RSAKey(_)
                        | rustls_pemfile::Item::PKCS8Key(_)
                        | rustls_pemfile::Item::ECKey(_),
                    ) => break true,
                    Some(_) => {}
                    None => break false,
                }
            };
            if !has_private_key {
                anyhow::bail!("TLS private key PEM contains no supported private key");
            }
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

#[derive(Deserialize)]
struct AccountRequest {
    address: String,
    password: Option<String>,
    password_hash: Option<String>,
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
  <style>
    :root {
      color: #1d252c;
      background: #eef2f3;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 15px;
    }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; background: #eef2f3; }
    button, input, select { font: inherit; }
    .shell { min-height: 100vh; display: grid; grid-template-columns: 260px minmax(0, 1fr); }
    .side { background: #1f2d34; color: #edf5f6; padding: 24px 18px; display: flex; flex-direction: column; gap: 24px; }
    .brand { display: flex; gap: 12px; align-items: center; }
    .mark { width: 38px; height: 38px; display: grid; place-items: center; border-radius: 8px; background: #69d2c2; color: #152126; font-weight: 800; }
    .brand strong { display: block; font-size: 20px; }
    .brand span { display: block; color: #9eb4ba; font-size: 13px; margin-top: 2px; }
    nav { display: grid; gap: 6px; }
    nav a { color: #d8e6e8; text-decoration: none; padding: 10px 12px; border-radius: 7px; display: flex; justify-content: space-between; }
    nav a:hover, nav a.active { background: #31464f; color: #fff; }
    .side-foot { margin-top: auto; color: #9eb4ba; font-size: 13px; line-height: 1.5; }
    .main { min-width: 0; padding: 22px 28px 36px; display: grid; gap: 18px; }
    .top { display: flex; align-items: center; justify-content: space-between; gap: 18px; }
    h1 { margin: 0; font-size: 28px; line-height: 1.15; letter-spacing: 0; }
    .subtitle { color: #64747b; margin-top: 5px; }
    .actions { display: flex; gap: 8px; flex-wrap: wrap; }
    .btn { border: 1px solid #c9d4d8; background: #fff; color: #213038; border-radius: 7px; padding: 9px 12px; cursor: pointer; }
    .btn.primary { background: #1f6feb; border-color: #1f6feb; color: #fff; }
    .btn.danger { color: #9b1c2b; }
    .grid { display: grid; gap: 14px; }
    .kpis { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    .panel-grid { grid-template-columns: minmax(0, 1.35fr) minmax(360px, .65fr); align-items: start; }
    .panel, .kpi { background: #fff; border: 1px solid #d8e0e3; border-radius: 8px; box-shadow: 0 10px 28px rgba(31, 45, 52, .06); }
    .kpi { padding: 16px; min-height: 116px; display: grid; align-content: space-between; }
    .kpi span { color: #65777f; font-size: 13px; }
    .kpi strong { font-size: 30px; line-height: 1; }
    .kpi small { color: #71838a; }
    .panel { min-width: 0; overflow: hidden; }
    .panel-head { padding: 15px 16px; border-bottom: 1px solid #e3eaed; display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .panel-head h2 { margin: 0; font-size: 16px; }
    .panel-body { padding: 14px 16px 16px; }
    .tabs { display: flex; gap: 6px; flex-wrap: wrap; }
    .tab { border: 1px solid #cbd7db; background: #f7fafb; border-radius: 999px; padding: 7px 10px; cursor: pointer; color: #3b4d55; }
    .tab.active { background: #253842; border-color: #253842; color: #fff; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 11px 8px; border-bottom: 1px solid #e8eef0; text-align: left; vertical-align: middle; }
    th { color: #64747b; font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
    td strong { display: block; }
    .muted { color: #6d7f87; }
    .pill { display: inline-flex; align-items: center; min-height: 24px; padding: 3px 8px; border-radius: 999px; background: #edf5f3; color: #27645b; font-size: 12px; }
    .queue-actions { display: grid; grid-template-columns: minmax(0, 1fr) auto auto auto; gap: 8px; margin-bottom: 12px; }
    input, select { border: 1px solid #cbd7db; border-radius: 7px; padding: 9px 10px; min-width: 0; background: #fff; }
    pre { margin: 0; white-space: pre-wrap; word-break: break-word; max-height: 420px; overflow: auto; background: #172228; color: #d8f3ef; border-radius: 8px; padding: 14px; line-height: 1.45; }
    .metric-list { display: grid; gap: 8px; }
    .metric { display: flex; justify-content: space-between; gap: 12px; padding: 10px 0; border-bottom: 1px solid #e8eef0; }
    .metric:last-child { border-bottom: 0; }
    .empty { color: #77888f; padding: 18px 0; }
    .status { color: #64747b; font-size: 13px; }
    .error { color: #9b1c2b; }
    @media (max-width: 980px) {
      .shell { grid-template-columns: 1fr; }
      .side { position: static; }
      .kpis, .panel-grid { grid-template-columns: 1fr; }
      .top { align-items: flex-start; flex-direction: column; }
      .queue-actions { grid-template-columns: 1fr 1fr; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <aside class="side">
      <div class="brand"><div class="mark">rM</div><div><strong>rMail</strong><span>Admin console</span></div></div>
      <nav>
        <a class="active" href="#overview">Overview <span>01</span></a>
        <a href="#accounts">Accounts <span>02</span></a>
        <a href="#queue">Queue <span>03</span></a>
        <a href="#metrics">Metrics <span>04</span></a>
        <a href="#logs">Logs <span>05</span></a>
      </nav>
      <div class="side-foot">Live operational view backed by rMail stats, queue, metrics, and log endpoints.</div>
    </aside>
    <main class="main">
      <header class="top">
        <div><h1>Mail Operations</h1><div class="subtitle">Accounts, delivery health, queue pressure, and daemon diagnostics in one place.</div></div>
        <div class="actions"><button class="btn" id="refresh">Refresh</button><a class="btn" href="/metrics">Prometheus</a><a class="btn" href="/health">Health</a></div>
      </header>
      <section class="grid kpis" id="overview">
        <div class="kpi"><span>Mailboxes</span><strong id="k-mailboxes">-</strong><small id="k-accounts">configured accounts</small></div>
        <div class="kpi"><span>Stored messages</span><strong id="k-messages">-</strong><small>new and current maildir files</small></div>
        <div class="kpi"><span>Delivered</span><strong id="k-delivered">-</strong><small>runtime delivery counter</small></div>
        <div class="kpi"><span>Outbound pending</span><strong id="k-pending">-</strong><small id="k-queue-detail">queued workload</small></div>
      </section>
      <section class="grid panel-grid">
        <section class="panel" id="accounts">
          <div class="panel-head"><h2>Account Management</h2><span class="status" id="account-status">Loading</span></div>
          <div class="panel-body"><table><thead><tr><th>Mailbox</th><th>Auth</th><th>Folders</th><th>Messages</th><th>Unseen</th></tr></thead><tbody id="accounts-body"></tbody></table></div>
        </section>
        <section class="panel" id="metrics">
          <div class="panel-head"><h2>Metrics Snapshot</h2><span class="status" id="metrics-status">Loading</span></div>
          <div class="panel-body"><div class="metric-list" id="metrics-list"></div></div>
        </section>
      </section>
      <section class="grid panel-grid">
        <section class="panel" id="queue">
          <div class="panel-head"><h2>Outbound Queue</h2><span class="status" id="queue-status">Loading</span></div>
          <div class="panel-body">
            <div class="queue-actions">
              <input id="queue-target" placeholder="Message name or pattern">
              <button class="btn" data-action="requeue">Requeue</button>
              <button class="btn primary" data-action="promote">Promote</button>
              <button class="btn danger" data-action="delete">Delete</button>
            </div>
            <table><thead><tr><th>Message</th><th>Attempts</th><th>Priority</th><th>Next try</th><th>Error</th></tr></thead><tbody id="queue-body"></tbody></table>
          </div>
        </section>
        <section class="panel">
          <div class="panel-head"><h2>DMARC</h2><span class="status" id="dmarc-status">Loading</span></div>
          <div class="panel-body"><div class="metric-list" id="dmarc-list"></div></div>
        </section>
      </section>
      <section class="panel" id="logs">
        <div class="panel-head"><h2>Daemon Logs</h2><div class="tabs" id="log-tabs"><button class="tab active" data-log="smtpd">SMTP</button><button class="tab" data-log="imapd">IMAP</button><button class="tab" data-log="outbound">Outbound</button><button class="tab" data-log="web">Web</button></div></div>
        <div class="panel-body"><pre id="log-output">Loading logs...</pre></div>
      </section>
    </main>
  </div>
  <script>
    const $ = (id) => document.getElementById(id);
    const fmt = (n) => Number(n || 0).toLocaleString();
    async function json(url, options) {
      const res = await fetch(url, options);
      if (!res.ok) throw new Error(await res.text() || res.statusText);
      return res.json();
    }
    async function text(url) {
      const res = await fetch(url);
      if (!res.ok) throw new Error(await res.text() || res.statusText);
      return res.text();
    }
    function metricRow(label, value) {
      return `<div class="metric"><span>${label}</span><strong>${value}</strong></div>`;
    }
    async function loadStats() {
      const [stats, queue] = await Promise.all([json('/stats'), json('/api/queue/summary')]);
      $('k-mailboxes').textContent = fmt(stats.mailboxes);
      $('k-messages').textContent = fmt(stats.total_messages);
      $('k-delivered').textContent = fmt(stats.delivered_count);
      $('k-pending').textContent = fmt(stats.outbound_pending);
      $('k-queue-detail').textContent = `${fmt(queue.inflight)} inflight, ${fmt(queue.failed)} failed`;
    }
    async function loadAccounts() {
      const accounts = await json('/api/accounts');
      $('k-accounts').textContent = `${fmt(accounts.length)} configured accounts`;
      $('account-status').textContent = `${fmt(accounts.length)} accounts`;
      $('accounts-body').innerHTML = accounts.length ? accounts.map(a => `<tr><td><strong>${a.address}</strong><span class="muted">${a.unseen ? 'Needs attention' : 'No unread mail'}</span></td><td><span class="pill">${a.auth}</span></td><td>${fmt(a.folders)}</td><td>${fmt(a.messages)}</td><td>${fmt(a.unseen)}</td></tr>`).join('') : `<tr><td colspan="5" class="empty">No DB-backed accounts found.</td></tr>`;
    }
    async function loadQueue() {
      const data = await json('/api/queue');
      const queued = data.queued || [];
      $('queue-status').textContent = `${fmt(queued.length)} queued`;
      $('queue-body').innerHTML = queued.length ? queued.slice(0, 12).map(item => {
        const c = item.control || {};
        return `<tr><td><strong>${item.name}</strong></td><td>${fmt(c.attempts)}</td><td>${fmt(c.priority)}</td><td>${c.next_try ?? '-'}</td><td class="muted">${c.last_error || '-'}</td></tr>`;
      }).join('') : `<tr><td colspan="5" class="empty">No queued outbound messages.</td></tr>`;
    }
    async function loadMetrics() {
      const raw = await text('/metrics');
      const lines = raw.split('\n').filter(line => line && !line.startsWith('#')).slice(0, 8);
      $('metrics-status').textContent = `${fmt(lines.length)} displayed`;
      $('metrics-list').innerHTML = lines.length ? lines.map(line => {
        const parts = line.trim().split(/\s+/);
        return metricRow(parts[0], parts.slice(1).join(' '));
      }).join('') : '<div class="empty">No metrics emitted yet.</div>';
    }
    async function loadDmarc() {
      try {
        const rows = await json('/dmarc');
        $('dmarc-status').textContent = `${fmt(rows.length)} domains`;
        $('dmarc-list').innerHTML = rows.length ? rows.map(r => metricRow(r.domain, `${fmt(r.events)} events`)).join('') : '<div class="empty">No unreported DMARC events.</div>';
      } catch (err) {
        $('dmarc-status').textContent = 'Unavailable';
        $('dmarc-list').innerHTML = `<div class="empty">${err.message}</div>`;
      }
    }
    async function loadLogs(component = document.querySelector('.tab.active')?.dataset.log || 'smtpd') {
      $('log-output').textContent = await text(`/logs?component=${component}&lines=160`);
    }
    async function refreshAll() {
      const jobs = [loadStats(), loadAccounts(), loadQueue(), loadMetrics(), loadDmarc(), loadLogs()];
      const results = await Promise.allSettled(jobs);
      const failed = results.filter(r => r.status === 'rejected');
      if (failed.length) console.error(failed);
    }
    document.getElementById('refresh').onclick = refreshAll;
    document.getElementById('log-tabs').onclick = (event) => {
      const btn = event.target.closest('button[data-log]');
      if (!btn) return;
      document.querySelectorAll('.tab').forEach(tab => tab.classList.toggle('active', tab === btn));
      loadLogs(btn.dataset.log).catch(err => $('log-output').textContent = err.message);
    };
    document.querySelectorAll('[data-action]').forEach(btn => btn.addEventListener('click', async () => {
      const value = $('queue-target').value.trim();
      if (!value) return;
      const body = value.includes('*') ? { pattern: value } : { name: value };
      body.action = btn.dataset.action;
      if (body.action === 'promote') body.priority = 10;
      await json('/api/queue/action', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      $('queue-target').value = '';
      await Promise.all([loadStats(), loadQueue()]);
    }));
    refreshAll();
    setInterval(refreshAll, 30000);
  </script>
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

fn read_admin_static(path: &str) -> Option<(&'static str, String)> {
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
            && let Ok(body) = std::fs::read_to_string(&file_path)
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
    let scram = rmail_common::auth::create_scram_verifier(password, 4096)?;
    Ok((Some(hash), Some(scram)))
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
            if let Some((local, domain)) = split_address(&mailbox.address)
                && let Ok(summaries) =
                    rmail_common::imap_state::list_folder_summaries(mail_root, domain, local)
            {
                folders = summaries.len();
                messages = summaries.iter().map(|summary| summary.messages).sum();
                unseen = summaries.iter().map(|summary| summary.unseen).sum();
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
    let maildir_path = mail_root.join(domain).join(local).join("Maildir");
    rmail_common::maildir::ensure_maildir(&maildir_path)?;
    let (password_hash, scram) =
        password_material(req.password.as_deref(), req.password_hash.as_deref())?;
    rmail_common::db::add_mailbox(
        db_path,
        &address,
        password_hash.as_deref(),
        Some(&maildir_path.to_string_lossy()),
        scram.as_deref(),
    )
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

    Ok(OverviewSummary {
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

async fn handle_connection(
    stream: tokio::net::TcpStream,
    mail_root: PathBuf,
    admin_user: Option<String>,
    admin_hash: Option<String>,
    db_path: Option<String>,
    acme_challenge_dir: Option<String>,
    readiness: ReadinessConfig,
) {
    let peer = match stream.peer_addr() {
        Ok(p) => p.to_string(),
        Err(_) => "unknown".to_string(),
    };
    let mut reader = BufReader::new(stream);
    let mut first_line = String::new();
    // read request line
    match reader.read_line(&mut first_line).await {
        Ok(0) => return,
        Ok(_) => {}
        Err(_) => return,
    }
    let req_line = first_line
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string();
    // read headers until empty line, store them in a map
    let mut headers: HashMap<String, String> = HashMap::new();
    loop {
        let mut h = String::new();
        match reader.read_line(&mut h).await {
            Ok(0) => break,
            Ok(_) => {
                if h == "\r\n" || h == "\n" {
                    break;
                }
                if let Some(colon) = h.find(':') {
                    let name = h[..colon].trim().to_ascii_lowercase();
                    let val = h[colon + 1..].trim().to_string();
                    headers.insert(name, val);
                }
            }
            Err(_) => break,
        }
    }

    // parse request line: METHOD PATH HTTP/X
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path_q = parts.next().unwrap_or("/");

    // simple basic auth checker closure: returns true if no admin_user configured or credentials match
    let is_authorized = |headers: &HashMap<String, String>| -> bool {
        if admin_user.is_none() {
            return true;
        }
        let expected_user = admin_user.as_ref().unwrap();
        let expected_hash = match &admin_hash {
            Some(h) => h,
            None => return false,
        };
        if let Some(authz) = headers.get("authorization")
            && authz.len() > 6
            && authz[..6].eq_ignore_ascii_case("Basic ")
        {
            let b64 = authz[6..].trim();
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64)
                && let Ok(creds) = String::from_utf8(bytes)
                && let Some(colon) = creds.find(':')
            {
                let u = &creds[..colon];
                let p = &creds[colon + 1..];
                if u == expected_user
                    && let Ok(valid) = auth::verify_password(p, expected_hash)
                {
                    return valid;
                }
            }
        }
        false
    };
    let mut extra_headers = String::new();

    // prepare response
    let mut status = 200;
    let mut content_type = "text/plain".to_string();
    let body: String;

    // read body for POST requests
    let mut body_bytes: Vec<u8> = Vec::new();
    if (method == "POST" || method == "DELETE")
        && let Some(cl) = headers.get("content-length")
        && let Ok(n) = cl.parse::<usize>()
    {
        body_bytes.resize(n, 0);
        let _ = reader.read_exact(&mut body_bytes).await;
    }

    let (path, query) = if let Some(pos) = path_q.find('?') {
        (&path_q[..pos], &path_q[pos + 1..])
    } else {
        (path_q, "")
    };
    // Serve ACME http-01 challenge files from configured directory
    if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
        if method != "GET" {
            status = 405;
            body = "Method Not Allowed".to_string();
        } else {
            if let Some(acme_dir) = acme_challenge_dir.as_ref() {
                let fpath = std::path::Path::new(acme_dir).join(token);
                match tokio::fs::read_to_string(fpath).await {
                    Ok(s) => {
                        content_type = "text/plain".to_string();
                        body = s;
                    }
                    Err(_) => {
                        status = 404;
                        body = "Not Found".to_string();
                    }
                }
            } else {
                status = 404;
                body = "Not Found".to_string();
            }
        }
    } else {
        match path {
            "/" => {
                if method != "GET" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else {
                    if let Some((ctype, static_body)) = read_admin_static(path) {
                        content_type = ctype.to_string();
                        body = static_body;
                    } else {
                        content_type = "text/html".to_string();
                        body = admin_app_html().to_string();
                    }
                }
            }
            "/health" | "/healthz" => {
                if method != "GET" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else {
                    content_type = "text/plain".to_string();
                    body = "ok".to_string();
                }
            }
            "/ready" | "/readyz" => {
                if method != "GET" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else {
                    let report =
                        readiness_report(mail_root.clone(), db_path.clone(), readiness.clone())
                            .await;
                    if !report.ready {
                        status = 503;
                    }
                    content_type = "application/json".to_string();
                    body = serde_json::to_string(&report).unwrap_or_else(|error| {
                        status = 500;
                        format!("{{\"ready\":false,\"error\":\"{error}\"}}")
                    });
                }
            }
            "/stats" => {
                if method != "GET" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else if !is_authorized(&headers) {
                    status = 401;
                    body = "Unauthorized".to_string();
                    extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                } else {
                    // run blocking scan in threadpool
                    let mr_clone = mail_root.clone();
                    match tokio::task::spawn_blocking(move || scan_maildirs_sync(&mr_clone)).await {
                        Ok(Ok(mut stats)) => {
                            // attempt to read delivered count from metrics file (fallback)
                            let delivered = tokio::fs::read_to_string(
                                rmail_common::runtime::delivered_count_path(&mail_root),
                            )
                            .await
                            .ok()
                            .and_then(|s| s.trim().parse::<u64>().ok())
                            .unwrap_or(0);
                            stats.delivered_count = delivered;
                            content_type = "application/json".to_string();
                            body = match serde_json::to_string(&stats) {
                                Ok(s) => s,
                                Err(e) => {
                                    status = 500;
                                    format!("{{\"error\":\"{}\"}}", e)
                                }
                            };
                        }
                        Ok(Err(e)) => {
                            status = 500;
                            body = format!("scan error: {}", e);
                        }
                        Err(e) => {
                            status = 500;
                            body = format!("task join error: {}", e);
                        }
                    }
                }
            }
            "/metrics" => {
                if method != "GET" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else if !is_authorized(&headers) {
                    status = 401;
                    body = "Unauthorized".to_string();
                    extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                } else {
                    // Aggregate process-local snapshots with one bounded component label.
                    let mut metrics_text = String::new();
                    let mut have_metadata = false;
                    for component in ["smtpd", "outbound", "imapd", "web"] {
                        let Ok(snapshot) = tokio::fs::read_to_string(
                            rmail_common::runtime::prometheus_snapshot_path(&mail_root, component),
                        )
                        .await
                        else {
                            continue;
                        };
                        let labeled =
                            rmail_common::metrics::add_component_label(&snapshot, component);
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
                    match count_queue_entries_sync(&mail_root) {
                        Ok(n) => {
                            metrics_text.push_str("# HELP rmail_outbound_pending Number of pending outbound messages\n");
                            metrics_text.push_str("# TYPE rmail_outbound_pending gauge\n");
                            metrics_text.push_str(&format!("rmail_outbound_pending {}\n", n));
                        }
                        Err(e) => {
                            eprintln!("failed to read outbound queue size: {}", e);
                        }
                    }
                    content_type = "text/plain".to_string();
                    body = metrics_text;
                }
            }
            "/dmarc" => {
                // DMARC reporting overview: domains with unreported events and counts
                if method != "GET" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else if !is_authorized(&headers) {
                    status = 401;
                    body = "Unauthorized".to_string();
                    extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                } else if let Some(dbp) = db_path.as_ref() {
                    // fetch unreported domains and counts in blocking thread
                    match tokio::task::spawn_blocking({
                        let dbp = dbp.clone();
                        move || rmail_common::db::get_unreported_dmarc_domains(&dbp)
                    })
                    .await
                    {
                        Ok(Ok(domains)) => {
                            let mut out: Vec<serde_json::Value> = Vec::new();
                            for d in domains {
                                match rmail_common::db::fetch_unreported_dmarc_events_for_domain(
                                    dbp.as_str(),
                                    &d,
                                ) {
                                    Ok(evts) => {
                                        out.push(
                                            serde_json::json!({"domain": d, "events": evts.len()}),
                                        );
                                    }
                                    Err(e) => {
                                        eprintln!("failed to fetch events for {}: {}", d, e);
                                    }
                                }
                            }
                            content_type = "application/json".to_string();
                            body = serde_json::to_string(&out).unwrap_or_else(|e| {
                                status = 500;
                                format!("{{\"error\":\"{}\"}}", e)
                            });
                        }
                        Ok(Err(e)) => {
                            status = 500;
                            body = format!("db error: {}", e);
                        }
                        Err(e) => {
                            status = 500;
                            body = format!("task join error: {}", e);
                        }
                    }
                } else {
                    status = 400;
                    body = "DB not configured".to_string();
                }
            }
            "/logs" => {
                if method != "GET" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else if !is_authorized(&headers) {
                    status = 401;
                    body = "Unauthorized".to_string();
                    extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                } else {
                    // parse query params for component and lines (simple parser, no percent-decoding)
                    let params: HashMap<_, _> = query
                        .split('&')
                        .filter_map(|kv| {
                            if kv.is_empty() {
                                return None;
                            }
                            let mut s = kv.splitn(2, '=');
                            let k = s.next().unwrap_or("").to_string();
                            let v = s.next().unwrap_or("").to_string();
                            if k.is_empty() { None } else { Some((k, v)) }
                        })
                        .collect();
                    let component = params
                        .get("component")
                        .map(|s| s.as_str())
                        .unwrap_or("smtpd");
                    let mut lines: usize = params
                        .get("lines")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(200);
                    lines = std::cmp::min(lines, 2000);
                    match component {
                        "smtpd" | "imapd" | "web" | "outbound" => {
                            let path = rmail_common::runtime::log_path(&mail_root, component);
                            match tokio::fs::read_to_string(&path).await {
                                Ok(s) => {
                                    content_type = "text/plain".to_string();
                                    body = tail_lines(&s, lines);
                                }
                                Err(e) => {
                                    status = 500;
                                    body = format!("read error from {}: {}", path.display(), e);
                                }
                            }
                        }
                        _ => {
                            status = 400;
                            body = "invalid component".to_string();
                        }
                    }
                }
            }
            "/api/queue/requeue" => {
                if method != "POST" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else {
                    if !is_authorized(&headers) {
                        status = 401;
                        body = "Unauthorized".to_string();
                        extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                    } else {
                        let b = String::from_utf8_lossy(&body_bytes).to_string();
                        match serde_json::from_str::<serde_json::Value>(&b) {
                            Ok(val) => {
                                let mr_clone = mail_root.clone();
                                let res = tokio::task::spawn_blocking(move || {
                                    if let Some(name) = val.get("name").and_then(|v| v.as_str()) {
                                        if let Ok(Some((spool, eml, jsonp))) =
                                            find_message_sync(&mr_clone, &ensure_ext(name))
                                        {
                                            return requeue_single_sync(
                                                &spool, &eml, &jsonp, &mr_clone,
                                            );
                                        }
                                        Err(anyhow::anyhow!("not found"))
                                    } else if let Some(pattern) =
                                        val.get("pattern").and_then(|v| v.as_str())
                                    {
                                        let matches =
                                            find_messages_matching_sync(&mr_clone, pattern)?;
                                        for (spool, eml, jsonp, _fname) in matches {
                                            requeue_single_sync(&spool, &eml, &jsonp, &mr_clone)?;
                                        }
                                        Ok(())
                                    } else {
                                        Err(anyhow::anyhow!("missing name or pattern"))
                                    }
                                })
                                .await;
                                match res {
                                    Ok(Ok(_)) => {
                                        content_type = "application/json".to_string();
                                        body = json!({"result":"ok"}).to_string();
                                    }
                                    Ok(Err(e)) => {
                                        status = 500;
                                        body = format!("error: {}", e);
                                    }
                                    Err(e) => {
                                        status = 500;
                                        body = format!("task join error: {}", e);
                                    }
                                }
                            }
                            Err(_) => {
                                status = 400;
                                body = "invalid JSON".to_string();
                            }
                        }
                    }
                }
            }
            "/api/queue/promote" => {
                if method != "POST" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else {
                    if !is_authorized(&headers) {
                        status = 401;
                        body = "Unauthorized".to_string();
                        extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                    } else {
                        let b = String::from_utf8_lossy(&body_bytes).to_string();
                        match serde_json::from_str::<serde_json::Value>(&b) {
                            Ok(val) => {
                                let priority =
                                    val.get("priority").and_then(|v| v.as_i64()).unwrap_or(0)
                                        as i32;
                                let mr_clone = mail_root.clone();
                                let res = tokio::task::spawn_blocking(move || {
                                    if let Some(name) = val.get("name").and_then(|v| v.as_str()) {
                                        if let Ok(Some((spool, eml, jsonp))) =
                                            find_message_sync(&mr_clone, &ensure_ext(name))
                                        {
                                            return promote_single_sync(
                                                &spool, &eml, &jsonp, &mr_clone, priority,
                                            );
                                        }
                                        Err(anyhow::anyhow!("not found"))
                                    } else if let Some(pattern) =
                                        val.get("pattern").and_then(|v| v.as_str())
                                    {
                                        let matches =
                                            find_messages_matching_sync(&mr_clone, pattern)?;
                                        for (spool, eml, jsonp, _fname) in matches {
                                            promote_single_sync(
                                                &spool, &eml, &jsonp, &mr_clone, priority,
                                            )?;
                                        }
                                        Ok(())
                                    } else {
                                        Err(anyhow::anyhow!("missing name or pattern"))
                                    }
                                })
                                .await;
                                match res {
                                    Ok(Ok(_)) => {
                                        content_type = "application/json".to_string();
                                        body = json!({"result":"ok"}).to_string();
                                    }
                                    Ok(Err(e)) => {
                                        status = 500;
                                        body = format!("error: {}", e);
                                    }
                                    Err(e) => {
                                        status = 500;
                                        body = format!("task join error: {}", e);
                                    }
                                }
                            }
                            Err(_) => {
                                status = 400;
                                body = "invalid JSON".to_string();
                            }
                        }
                    }
                }
            }
            "/api/queue/delete" => {
                if method != "POST" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else {
                    if !is_authorized(&headers) {
                        status = 401;
                        body = "Unauthorized".to_string();
                        extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                    } else {
                        let b = String::from_utf8_lossy(&body_bytes).to_string();
                        match serde_json::from_str::<serde_json::Value>(&b) {
                            Ok(val) => {
                                let mr_clone = mail_root.clone();
                                let res = tokio::task::spawn_blocking(move || {
                                    if let Some(name) = val.get("name").and_then(|v| v.as_str()) {
                                        if let Ok(Some((spool, eml, jsonp))) =
                                            find_message_sync(&mr_clone, &ensure_ext(name))
                                        {
                                            return delete_single_sync(
                                                &spool, &eml, &jsonp, &mr_clone,
                                            );
                                        }
                                        Err(anyhow::anyhow!("not found"))
                                    } else if let Some(pattern) =
                                        val.get("pattern").and_then(|v| v.as_str())
                                    {
                                        let matches =
                                            find_messages_matching_sync(&mr_clone, pattern)?;
                                        for (spool, eml, jsonp, _fname) in matches {
                                            delete_single_sync(&spool, &eml, &jsonp, &mr_clone)?;
                                        }
                                        Ok(())
                                    } else {
                                        Err(anyhow::anyhow!("missing name or pattern"))
                                    }
                                })
                                .await;
                                match res {
                                    Ok(Ok(_)) => {
                                        content_type = "application/json".to_string();
                                        body = json!({"result":"ok"}).to_string();
                                    }
                                    Ok(Err(e)) => {
                                        status = 500;
                                        body = format!("error: {}", e);
                                    }
                                    Err(e) => {
                                        status = 500;
                                        body = format!("task join error: {}", e);
                                    }
                                }
                            }
                            Err(_) => {
                                status = 400;
                                body = "invalid JSON".to_string();
                            }
                        }
                    }
                }
            }
            "/api/queue" => {
                if !is_authorized(&headers) {
                    status = 401;
                    body = "Unauthorized".to_string();
                    extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                } else {
                    let mr_clone = mail_root.clone();
                    match tokio::task::spawn_blocking(move || {
                        let (queue, _i, _s, _f) = spool_dirs(&mr_clone);
                        match read_queue_entries(&queue) {
                            Ok(list) => serde_json::to_string(&serde_json::json!({"queued": list}))
                                .map_err(|e| anyhow::anyhow!(e)),
                            Err(e) => Err(anyhow::anyhow!(format!("read error: {}", e))),
                        }
                    })
                    .await
                    {
                        Ok(Ok(s)) => {
                            content_type = "application/json".to_string();
                            body = s;
                        }
                        Ok(Err(e)) => {
                            status = 500;
                            body = format!("error: {}", e);
                        }
                        Err(e) => {
                            status = 500;
                            body = format!("task join error: {}", e);
                        }
                    }
                }
            }
            "/api/queue/summary" => {
                if method != "GET" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else if !is_authorized(&headers) {
                    status = 401;
                    body = "Unauthorized".to_string();
                    extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                } else {
                    let mr_clone = mail_root.clone();
                    match tokio::task::spawn_blocking(move || queue_summary_sync(&mr_clone)).await {
                        Ok(Ok(summary)) => {
                            content_type = "application/json".to_string();
                            body = serde_json::to_string(&summary).unwrap_or_else(|e| {
                                status = 500;
                                format!("{{\"error\":\"{}\"}}", e)
                            });
                        }
                        Ok(Err(e)) => {
                            status = 500;
                            body = format!("error: {}", e);
                        }
                        Err(e) => {
                            status = 500;
                            body = format!("task join error: {}", e);
                        }
                    }
                }
            }
            "/api/overview" => {
                if method != "GET" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else if !is_authorized(&headers) {
                    status = 401;
                    body = "Unauthorized".to_string();
                    extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                } else {
                    let mr_clone = mail_root.clone();
                    let dbp = db_path.clone();
                    match tokio::task::spawn_blocking(move || {
                        overview_summary_sync(&mr_clone, dbp.as_deref())
                    })
                    .await
                    {
                        Ok(Ok(summary)) => {
                            content_type = "application/json".to_string();
                            body = serde_json::to_string(&summary).unwrap_or_else(|e| {
                                status = 500;
                                format!("{{\"error\":\"{}\"}}", e)
                            });
                        }
                        Ok(Err(e)) => {
                            status = 500;
                            body = format!("error: {}", e);
                        }
                        Err(e) => {
                            status = 500;
                            body = format!("task join error: {}", e);
                        }
                    }
                }
            }
            "/api/accounts" => {
                if !is_authorized(&headers) {
                    status = 401;
                    body = "Unauthorized".to_string();
                    extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                } else if method == "GET" {
                    let mr_clone = mail_root.clone();
                    let dbp = db_path.clone();
                    match tokio::task::spawn_blocking(move || {
                        account_summaries_sync(&mr_clone, dbp.as_deref())
                    })
                    .await
                    {
                        Ok(Ok(accounts)) => {
                            content_type = "application/json".to_string();
                            body = serde_json::to_string(&accounts).unwrap_or_else(|e| {
                                status = 500;
                                format!("{{\"error\":\"{}\"}}", e)
                            });
                        }
                        Ok(Err(e)) => {
                            status = 500;
                            body = format!("error: {}", e);
                        }
                        Err(e) => {
                            status = 500;
                            body = format!("task join error: {}", e);
                        }
                    }
                } else if method == "POST" {
                    if let Some(dbp) = db_path.clone() {
                        match serde_json::from_slice::<AccountRequest>(&body_bytes) {
                            Ok(req) => {
                                let mr_clone = mail_root.clone();
                                match tokio::task::spawn_blocking(move || {
                                    upsert_account_sync(&mr_clone, &dbp, req)
                                })
                                .await
                                {
                                    Ok(Ok(())) => {
                                        content_type = "application/json".to_string();
                                        body = json!({"result":"ok"}).to_string();
                                    }
                                    Ok(Err(e)) => {
                                        status = 400;
                                        body = format!("error: {}", e);
                                    }
                                    Err(e) => {
                                        status = 500;
                                        body = format!("task join error: {}", e);
                                    }
                                }
                            }
                            Err(_) => {
                                status = 400;
                                body = "invalid JSON".to_string();
                            }
                        }
                    } else {
                        status = 400;
                        body = "DB not configured".to_string();
                    }
                } else if method == "DELETE" {
                    if let Some(dbp) = db_path.clone() {
                        match serde_json::from_slice::<AccountDeleteRequest>(&body_bytes) {
                            Ok(req) => {
                                match tokio::task::spawn_blocking(move || {
                                    delete_account_sync(&dbp, req)
                                })
                                .await
                                {
                                    Ok(Ok(())) => {
                                        content_type = "application/json".to_string();
                                        body = json!({"result":"ok"}).to_string();
                                    }
                                    Ok(Err(e)) => {
                                        status = 400;
                                        body = format!("error: {}", e);
                                    }
                                    Err(e) => {
                                        status = 500;
                                        body = format!("task join error: {}", e);
                                    }
                                }
                            }
                            Err(_) => {
                                status = 400;
                                body = "invalid JSON".to_string();
                            }
                        }
                    } else {
                        status = 400;
                        body = "DB not configured".to_string();
                    }
                } else {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                }
            }
            "/api/routing" => {
                if !is_authorized(&headers) {
                    status = 401;
                    body = "Unauthorized".to_string();
                    extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                } else if method == "GET" {
                    let dbp = db_path.clone();
                    match tokio::task::spawn_blocking(move || routing_summary_sync(dbp.as_deref()))
                        .await
                    {
                        Ok(Ok(summary)) => {
                            content_type = "application/json".to_string();
                            body = serde_json::to_string(&summary).unwrap_or_else(|e| {
                                status = 500;
                                format!("{{\"error\":\"{}\"}}", e)
                            });
                        }
                        Ok(Err(e)) => {
                            status = 500;
                            body = format!("error: {}", e);
                        }
                        Err(e) => {
                            status = 500;
                            body = format!("task join error: {}", e);
                        }
                    }
                } else {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                }
            }
            "/api/routing/alias" => {
                if method != "POST" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else if !is_authorized(&headers) {
                    status = 401;
                    body = "Unauthorized".to_string();
                    extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                } else if let Some(dbp) = db_path.clone() {
                    match serde_json::from_slice::<AliasRequest>(&body_bytes) {
                        Ok(req) => {
                            match tokio::task::spawn_blocking(move || upsert_alias_sync(&dbp, req))
                                .await
                            {
                                Ok(Ok(())) => {
                                    content_type = "application/json".to_string();
                                    body = json!({"result":"ok"}).to_string();
                                }
                                Ok(Err(e)) => {
                                    status = 400;
                                    body = format!("error: {}", e);
                                }
                                Err(e) => {
                                    status = 500;
                                    body = format!("task join error: {}", e);
                                }
                            }
                        }
                        Err(_) => {
                            status = 400;
                            body = "invalid JSON".to_string();
                        }
                    }
                } else {
                    status = 400;
                    body = "DB not configured".to_string();
                }
            }
            "/api/routing/catchall" => {
                if method != "POST" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else if !is_authorized(&headers) {
                    status = 401;
                    body = "Unauthorized".to_string();
                    extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                } else if let Some(dbp) = db_path.clone() {
                    match serde_json::from_slice::<CatchallRequest>(&body_bytes) {
                        Ok(req) => {
                            match tokio::task::spawn_blocking(move || {
                                upsert_catchall_sync(&dbp, req)
                            })
                            .await
                            {
                                Ok(Ok(())) => {
                                    content_type = "application/json".to_string();
                                    body = json!({"result":"ok"}).to_string();
                                }
                                Ok(Err(e)) => {
                                    status = 400;
                                    body = format!("error: {}", e);
                                }
                                Err(e) => {
                                    status = 500;
                                    body = format!("task join error: {}", e);
                                }
                            }
                        }
                        Err(_) => {
                            status = 400;
                            body = "invalid JSON".to_string();
                        }
                    }
                } else {
                    status = 400;
                    body = "DB not configured".to_string();
                }
            }
            "/api/queue/action" => {
                if method != "POST" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else {
                    if !is_authorized(&headers) {
                        status = 401;
                        body = "Unauthorized".to_string();
                        extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                    } else {
                        let b = String::from_utf8_lossy(&body_bytes).to_string();
                        match serde_json::from_str::<serde_json::Value>(&b) {
                            Ok(val) => {
                                let action =
                                    val.get("action").and_then(|v| v.as_str()).unwrap_or("");
                                let mr_clone = mail_root.clone();
                                match action {
                                    "requeue" => {
                                        let res = tokio::task::spawn_blocking(move || {
                                            if let Some(name) =
                                                val.get("name").and_then(|v| v.as_str())
                                            {
                                                if let Ok(Some((spool, eml, jsonp))) =
                                                    find_message_sync(&mr_clone, &ensure_ext(name))
                                                {
                                                    return requeue_single_sync(
                                                        &spool, &eml, &jsonp, &mr_clone,
                                                    );
                                                }
                                                Err(anyhow::anyhow!("not found"))
                                            } else if let Some(pattern) =
                                                val.get("pattern").and_then(|v| v.as_str())
                                            {
                                                let matches = find_messages_matching_sync(
                                                    &mr_clone, pattern,
                                                )?;
                                                for (spool, eml, jsonp, _fname) in matches {
                                                    requeue_single_sync(
                                                        &spool, &eml, &jsonp, &mr_clone,
                                                    )?;
                                                }
                                                Ok(())
                                            } else {
                                                Err(anyhow::anyhow!("missing name or pattern"))
                                            }
                                        })
                                        .await;
                                        match res {
                                            Ok(Ok(_)) => {
                                                content_type = "application/json".to_string();
                                                body = json!({"result":"ok"}).to_string();
                                            }
                                            Ok(Err(e)) => {
                                                status = 500;
                                                body = format!("error: {}", e);
                                            }
                                            Err(e) => {
                                                status = 500;
                                                body = format!("task join error: {}", e);
                                            }
                                        }
                                    }
                                    "promote" => {
                                        let priority = val
                                            .get("priority")
                                            .and_then(|v| v.as_i64())
                                            .unwrap_or(0)
                                            as i32;
                                        let res = tokio::task::spawn_blocking(move || {
                                            if let Some(name) =
                                                val.get("name").and_then(|v| v.as_str())
                                            {
                                                if let Ok(Some((spool, eml, jsonp))) =
                                                    find_message_sync(&mr_clone, &ensure_ext(name))
                                                {
                                                    return promote_single_sync(
                                                        &spool, &eml, &jsonp, &mr_clone, priority,
                                                    );
                                                }
                                                Err(anyhow::anyhow!("not found"))
                                            } else if let Some(pattern) =
                                                val.get("pattern").and_then(|v| v.as_str())
                                            {
                                                let matches = find_messages_matching_sync(
                                                    &mr_clone, pattern,
                                                )?;
                                                for (spool, eml, jsonp, _fname) in matches {
                                                    promote_single_sync(
                                                        &spool, &eml, &jsonp, &mr_clone, priority,
                                                    )?;
                                                }
                                                Ok(())
                                            } else {
                                                Err(anyhow::anyhow!("missing name or pattern"))
                                            }
                                        })
                                        .await;
                                        match res {
                                            Ok(Ok(_)) => {
                                                content_type = "application/json".to_string();
                                                body = json!({"result":"ok"}).to_string();
                                            }
                                            Ok(Err(e)) => {
                                                status = 500;
                                                body = format!("error: {}", e);
                                            }
                                            Err(e) => {
                                                status = 500;
                                                body = format!("task join error: {}", e);
                                            }
                                        }
                                    }
                                    "delete" => {
                                        let res = tokio::task::spawn_blocking(move || {
                                            if let Some(name) =
                                                val.get("name").and_then(|v| v.as_str())
                                            {
                                                if let Ok(Some((spool, eml, jsonp))) =
                                                    find_message_sync(&mr_clone, &ensure_ext(name))
                                                {
                                                    return delete_single_sync(
                                                        &spool, &eml, &jsonp, &mr_clone,
                                                    );
                                                }
                                                Err(anyhow::anyhow!("not found"))
                                            } else if let Some(pattern) =
                                                val.get("pattern").and_then(|v| v.as_str())
                                            {
                                                let matches = find_messages_matching_sync(
                                                    &mr_clone, pattern,
                                                )?;
                                                for (spool, eml, jsonp, _fname) in matches {
                                                    delete_single_sync(
                                                        &spool, &eml, &jsonp, &mr_clone,
                                                    )?;
                                                }
                                                Ok(())
                                            } else {
                                                Err(anyhow::anyhow!("missing name or pattern"))
                                            }
                                        })
                                        .await;
                                        match res {
                                            Ok(Ok(_)) => {
                                                content_type = "application/json".to_string();
                                                body = json!({"result":"ok"}).to_string();
                                            }
                                            Ok(Err(e)) => {
                                                status = 500;
                                                body = format!("error: {}", e);
                                            }
                                            Err(e) => {
                                                status = 500;
                                                body = format!("task join error: {}", e);
                                            }
                                        }
                                    }
                                    _ => {
                                        status = 400;
                                        body = "unknown action".to_string();
                                    }
                                }
                            }
                            Err(_) => {
                                status = 400;
                                body = "invalid JSON".to_string();
                            }
                        }
                    }
                }
            }
            _ => {
                if method == "GET" && !path.starts_with("/api/") {
                    if let Some((ctype, static_body)) = read_admin_static(path) {
                        content_type = ctype.to_string();
                        body = static_body;
                    } else {
                        status = 404;
                        body = "Not Found".to_string();
                    }
                } else {
                    status = 404;
                    body = "Not Found".to_string();
                }
            }
        }
    }

    // write response (HTTP/1.1)
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n{}\r\n{}",
        status,
        if status == 200 { "OK" } else { "ERR" },
        body.len(),
        content_type,
        extra_headers,
        body
    );
    // take ownership of underlying stream and write once
    let mut stream = reader.into_inner();
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
    println!("Served {} {} -> {}", peer, path_q, status);
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg_path =
        std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let cfg = Config::from_file(&cfg_path).unwrap_or_else(|_| {
        // fallback default settings
        Config {
            global: rmail_common::config::Global {
                tracking: rmail_common::config::TrackingConfig::default(),
                mail_root: "mail".into(),
                tcp_listener: rmail_common::net::TcpListenerConfig::default(),
                listeners: rmail_common::config::ListenerEndpoints::default(),
                listen_addrs: None,
                smtps_listen_addrs: None,
                smtps_port: None,
                submission_port: None,
                submission_listen_addrs: None,
                imaps_listen_addrs: None,
                imaps_port: None,
                imap_listen_addrs: None,
                imap_port: None,
                web_listen_addrs: None,
                web_port: None,
                webmail_listen_addrs: None,
                webmail_port: None,
                webmail_session_secret: None,
                tls_cert: None,
                tls_key: None,
                log_level: None,
                web_admin_user: None,
                web_admin_password_hash: None,
                acme_challenge_dir: None,
                db_path: None,
                enforce_dmarc: None,
            },
            security: rmail_common::config::SecurityConfig::default(),
        }
    });
    let mail_root = PathBuf::from(&cfg.global.mail_root);
    rmail_common::runtime::redirect_stdio_to_log(&mail_root, "web").context("redirecting logs")?;
    let _metrics_task = rmail_common::metrics::spawn_prometheus_snapshot_task(&mail_root, "web")?;
    let admin_user = cfg.global.web_admin_user.clone();
    let admin_hash = cfg.global.web_admin_password_hash.clone();
    let db_path = cfg.global.db_path.clone();
    let acme_dir = cfg.global.acme_challenge_dir.clone();
    let readiness = ReadinessConfig {
        tls_cert: cfg.global.tls_cert.clone(),
        tls_key: cfg.global.tls_key.clone(),
        security: cfg.security.clone(),
        check_dns: true,
    };
    let bind_addrs = cfg.global.admin_listeners();
    let listener_config = cfg.global.tcp_listener.clone();
    let shutdown = GracefulShutdown::new();
    let mut listeners = JoinSet::new();
    for addr in bind_addrs {
        let listener = bind_tcp_listener_with_config(&addr, &listener_config)?;
        println!("rMail web UI listening on {}", addr);
        let mr = mail_root.clone();
        let admin_user = admin_user.clone();
        let admin_hash = admin_hash.clone();
        let db_path = db_path.clone();
        let acme_dir = acme_dir.clone();
        let readiness = readiness.clone();
        let listener_shutdown = shutdown.clone();
        listeners.spawn(async move {
            let mut shutdown_signal = listener_shutdown.subscribe();
            loop {
                if *shutdown_signal.borrow() {
                    break;
                }
                let (stream, _) = tokio::select! {
                    _ = shutdown_signal.changed() => break,
                    accepted = listener.accept() => match accepted {
                        Ok(value) => value,
                        Err(e) => {
                        eprintln!("web listener {} accept error: {}", addr, e);
                        break;
                        }
                    },
                };
                let mr = mr.clone();
                let admin_user = admin_user.clone();
                let admin_hash = admin_hash.clone();
                let db_path = db_path.clone();
                let acme_dir = acme_dir.clone();
                let readiness = readiness.clone();
                let session = listener_shutdown.start_session();
                tokio::spawn(async move {
                    let _session = session;
                    handle_connection(
                        stream, mr, admin_user, admin_hash, db_path, acme_dir, readiness,
                    )
                    .await;
                });
            }
        });
    }
    rmail_common::runtime::wait_for_shutdown_signal().await?;
    println!("Web admin shutdown requested; draining active requests");
    shutdown.request();
    while let Some(result) = listeners.join_next().await {
        if let Err(error) = result {
            eprintln!("web listener task failed during shutdown: {error}");
        }
    }
    if !shutdown.wait_for_sessions(Duration::from_secs(30)).await {
        eprintln!(
            "web shutdown drain timed out with {} active requests",
            shutdown.active_sessions()
        );
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
            handle_connection(stream, mail_root, None, None, db_path, None, readiness).await;
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
        assert!(response.starts_with("HTTP/1.1 503 ERR"), "{response}");
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
        assert!(response.contains("Account Management"), "{response}");
        assert!(response.contains("Outbound Queue"), "{response}");
        assert!(response.contains("/api/accounts"), "{response}");
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

        let body = r#"{"address":"New@Example.Test","password":"secret"}"#;
        let request = format!(
            "POST /api/accounts HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
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
        assert!(
            rmail_common::db::get_mailbox(&db_path, "new@example.test")
                .unwrap()
                .is_some()
        );
        assert!(mail_root.join("example.test/new/Maildir").is_dir());

        let body = r#"{"address":"new@example.test"}"#;
        let request = format!(
            "DELETE /api/accounts HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
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
            "POST /api/routing/alias HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
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
            "POST /api/routing/catchall HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
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
            "POST /api/queue/action HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
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
        assert!(response.starts_with("HTTP/1.1 405 ERR"), "{response}");
    }
}
