use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use std::{collections::HashMap, path::PathBuf, sync::Arc};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use rmail_common::{
    auth,
    config::{Config, ScannerFailureAction, SecurityConfig},
    maildir, metrics,
    net::bind_tcp_listener,
    scanner::{ScanAction, ScanEnvelope},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::timeout;

mod protocol;
mod tls;
use protocol::{Command as SmtpCommand, parse_command, parse_mail_from_args, parse_rcpt_to_args};
use rand::RngCore;
use tls::load_tls_context;

// Trait object helper: combine AsyncRead + AsyncWrite into a single object-safe trait and require Unpin
// so that boxed trait objects can be used with tokio::io::BufReader.
trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized> AsyncStream for T {}

// Simple in-memory rate-limiter for authentication failures keyed by remote IP. This is a
// best-effort defensive measure against brute-force attacks. It is intentionally lightweight
// and uses an in-process Mutex-protected HashMap. For multi-process deployments a shared
// store (Redis, etc.) should be used instead.
#[derive(Clone)]
struct AuthFailInfo {
    count: u32,
    first: Instant,
    locked_until: Option<Instant>,
}

static AUTH_FAILS: Lazy<Mutex<HashMap<IpAddr, AuthFailInfo>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

const MAX_LINE_LEN: usize = 1000;
const MAX_MESSAGE_BYTES: usize = 10 * 1024 * 1024;
const COMMAND_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const AUTH_CONTINUATION_TIMEOUT: Duration = Duration::from_secs(60);
const DATA_READ_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const STARTTLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
const INVALID_CREDENTIALS: &[u8] = b"535 5.7.8 Authentication credentials invalid\r\n";

/// Increment an on-disk counter for delivered messages. Uses an atomic write via a temporary file
/// so that concurrent processes won't corrupt the counter file. This is intentionally simple and
/// avoids pulling in heavier metrics crates — it's a lightweight local metric for the Web UI.
async fn increment_delivery_counter(mail_root: &std::path::Path) -> Result<()> {
    let path = rmail_common::runtime::delivered_count_path(mail_root);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut count: u64 = 0;
    if let Ok(s) = tokio::fs::read_to_string(&path).await {
        count = s.trim().parse::<u64>().unwrap_or(0);
    }
    count = count.saturating_add(1);
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, count.to_string()).await?;
    tokio::fs::rename(&tmp, &path).await?;
    Ok(())
}

/// Check whether the remote IP is currently blocked from authenticating. Returns remaining block Duration if blocked.
fn auth_block_remaining(ip: IpAddr) -> Option<Duration> {
    let m = AUTH_FAILS.lock().unwrap();
    if let Some(info) = m.get(&ip) {
        if let Some(until) = info.locked_until {
            let now = Instant::now();
            if until > now {
                return Some(until - now);
            }
        }
    }
    None
}

/// Record a failed auth attempt for the IP and apply a temporary lockout if threshold exceeded.
fn record_auth_failure(ip: IpAddr) {
    let mut m = AUTH_FAILS.lock().unwrap();
    let now = Instant::now();
    let entry = m.entry(ip).or_insert(AuthFailInfo {
        count: 0,
        first: now,
        locked_until: None,
    });
    entry.count = entry.count.saturating_add(1);
    // Increment global metric for monitoring
    rmail_common::metrics::inc_auth_failures();
    // if 5 failures within short window, lock for 30 minutes
    if entry.count >= 5 {
        entry.locked_until = Some(now + Duration::from_secs(30 * 60));
        entry.count = 0;
        entry.first = now;
    }
}

/// Reset any recorded failures for this IP (on successful authentication)
fn reset_auth_failures(ip: IpAddr) {
    let mut m = AUTH_FAILS.lock().unwrap();
    m.remove(&ip);
}

#[tokio::main]
async fn main() -> Result<()> {
    // load config (example path)
    let cfg_path =
        std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let cfg = Config::from_file(&cfg_path).context(format!("loading {}", cfg_path))?;

    let mail_root = cfg.global.mail_root.clone();
    rmail_common::runtime::redirect_stdio_to_log(std::path::Path::new(&mail_root), "smtpd")
        .context("redirecting logs")?;
    rmail_common::metrics::persist_prometheus_snapshot(std::path::Path::new(&mail_root), "smtpd")
        .context("initializing metrics snapshot")?;
    // SQLite DB is the authoritative source for mailboxes and catchalls
    let db_path = cfg.global.db_path.clone();
    if db_path.is_none() {
        eprintln!("No db_path configured in global; SQLite DB is required");
        std::process::exit(1);
    }
    // initialize DB schema if missing
    if let Some(ref dbp) = db_path {
        if let Err(e) = rmail_common::db::init_db(dbp) {
            eprintln!("Failed to initialize database {}: {}", dbp, e);
            std::process::exit(1);
        }
    }

    // build TLS context if certificate paths present (includes acceptor and channel-binding info)
    let tls_context = if let (Some(cert), Some(key)) = (&cfg.global.tls_cert, &cfg.global.tls_key) {
        match load_tls_context(cert, key) {
            Ok(ctx) => Some(ctx),
            Err(e) => {
                eprintln!("Failed to load TLS config: {}", e);
                None
            }
        }
    } else {
        None
    };

    let listen_addrs = if let Some(addrs) = &cfg.global.listen_addrs {
        addrs.clone()
    } else {
        vec!["127.0.0.1:2525".to_string(), "[::1]:2525".to_string()]
    };

    // DMARC enforcement flag
    let enforce_dmarc = cfg.global.enforce_dmarc.unwrap_or(false);
    let security = Arc::new(cfg.security.clone());

    // spawn plain SMTP listeners
    for addr in listen_addrs.iter() {
        let addr = addr.clone();
        let mail_root_clone = mail_root.clone();
        let acceptor_clone = tls_context.clone();
        let db_clone = db_path.clone();
        let enforce = enforce_dmarc;
        let security = security.clone();
        tokio::spawn(async move {
            if let Err(e) = run_plain_listener(
                &addr,
                mail_root_clone,
                acceptor_clone,
                db_clone,
                enforce,
                security,
            )
            .await
            {
                eprintln!("Listener {} failed: {}", addr, e);
            }
        });
    }

    // spawn SMTPS listener (implicit TLS) if configured
    if let Some(s_ctx) = tls_context.clone() {
        if let Some(port) = cfg.global.smtps_port {
            let smtps_addrs = cfg
                .global
                .smtps_listen_addrs
                .clone()
                .unwrap_or_else(|| vec![format!("0.0.0.0:{}", port), format!("[::]:{}", port)]);

            for addr in smtps_addrs {
                let mail_root_clone = mail_root.clone();
                let ctx_clone = s_ctx.clone();
                let db_clone = db_path.clone();
                let enforce = enforce_dmarc;
                let security = security.clone();
                tokio::spawn(async move {
                    if let Err(e) = run_smtps_listener(
                        &addr,
                        ctx_clone,
                        mail_root_clone,
                        db_clone,
                        enforce,
                        security,
                    )
                    .await
                    {
                        eprintln!("SMTPS {} failed: {}", addr, e);
                    }
                });
            }
        }
    } else {
        println!("TLS not configured; SMTPS disabled (implicit TLS)");
    }

    // keep running
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

async fn run_plain_listener(
    addr: &str,
    mail_root: String,
    tls_ctx: Option<Arc<tls::TlsContext>>,
    db_path: Option<String>,
    enforce_dmarc: bool,
    security: Arc<SecurityConfig>,
) -> Result<()> {
    let listener = bind_tcp_listener(addr)?;
    println!("rMail SMTPD listening on {}", addr);
    loop {
        let (stream, peer) = listener.accept().await?;
        println!(
            "Accepted SMTP plaintext connection on {} from {} (starttls_available={})",
            addr,
            peer,
            tls_ctx.is_some()
        );
        let mail_root = mail_root.clone();
        let acceptor = tls_ctx.clone();
        let db_clone = db_path.clone();
        let enforce = enforce_dmarc;
        let security = security.clone();
        tokio::spawn(async move {
            if let Err(e) = process_stream(
                Box::new(stream),
                mail_root,
                acceptor,
                db_clone,
                Some(peer),
                false,
                enforce,
                true,
                security,
            )
            .await
            {
                eprintln!("client error: {}", e);
            }
        });
    }
}

async fn run_smtps_listener(
    addr: &str,
    ctx: Arc<tls::TlsContext>,
    mail_root: String,
    db_path: Option<String>,
    enforce_dmarc: bool,
    security: Arc<SecurityConfig>,
) -> Result<()> {
    let listener = bind_tcp_listener(addr)?;
    println!("rMail SMTPS listening on {}", addr);
    loop {
        let (stream, peer) = listener.accept().await?;
        println!("Accepted SMTPS TCP connection on {} from {}", addr, peer);
        let ctx = ctx.clone();
        let mail_root = mail_root.clone();
        let db_clone = db_path.clone();
        let enforce = enforce_dmarc;
        let security = security.clone();
        tokio::spawn(async move {
            match ctx.acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    println!("SMTPS TLS handshake success peer={}", peer);
                    if let Err(e) = process_stream(
                        Box::new(tls_stream),
                        mail_root,
                        Some(ctx.clone()),
                        db_clone,
                        Some(peer),
                        true,
                        enforce,
                        true,
                        security,
                    )
                    .await
                    {
                        eprintln!("tls client error: {}", e);
                    }
                }
                Err(e) => eprintln!("SMTPS TLS accept error from {}: {}", peer, e),
            }
        });
    }
}

#[cfg(test)]
fn parse_mail_from_arg(cmd: &str) -> Option<Option<String>> {
    parse_mail_from_args(cmd.strip_prefix("MAIL")?.trim_start()).map(|parsed| parsed.sender)
}

async fn timed_read_line<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    line: &mut String,
    duration: Duration,
) -> Result<Option<usize>> {
    match timeout(duration, reader.read_line(line)).await {
        Ok(Ok(n)) => Ok(Some(n)),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Ok(None),
    }
}

async fn timed_read_until<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    byte: u8,
    buf: &mut Vec<u8>,
    duration: Duration,
) -> Result<Option<usize>> {
    match timeout(duration, reader.read_until(byte, buf)).await {
        Ok(Ok(n)) => Ok(Some(n)),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Ok(None),
    }
}

enum DataReadResult {
    Complete(Vec<u8>),
    TooLarge,
    LineTooLong,
    Timeout,
    Eof,
}

async fn read_smtp_data<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<DataReadResult> {
    let mut data: Vec<u8> = Vec::new();
    let mut failure: Option<DataReadResult> = None;
    loop {
        let mut dline: Vec<u8> = Vec::new();
        let Some(n) = timed_read_until(reader, b'\n', &mut dline, DATA_READ_TIMEOUT).await? else {
            return Ok(DataReadResult::Timeout);
        };
        if n == 0 {
            return Ok(DataReadResult::Eof);
        }

        if dline.len() > MAX_LINE_LEN && failure.is_none() {
            failure = Some(DataReadResult::LineTooLong);
        }

        while matches!(dline.last(), Some(b'\n' | b'\r')) {
            dline.pop();
        }

        if dline == b"." {
            return Ok(failure.unwrap_or(DataReadResult::Complete(data)));
        }

        if failure.is_none() {
            if dline.starts_with(b"..") {
                dline.remove(0);
            }
            data.extend_from_slice(&dline);
            data.extend_from_slice(b"\r\n");
            if data.len() > MAX_MESSAGE_BYTES {
                failure = Some(DataReadResult::TooLarge);
            }
        }
    }
}

fn received_header(peer: Option<SocketAddr>, helo_name: Option<&str>, encrypted: bool) -> Vec<u8> {
    let peer_name = peer
        .map(|p| p.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let helo = helo_name.unwrap_or("unknown");
    let tls = if encrypted {
        "with ESMTPS"
    } else {
        "with ESMTP"
    };
    let timestamp = chrono_like_utc_timestamp();
    format!(
        "Received: from {} ([{}]) by rMail SMTPD {} id {}; {}\r\n",
        helo, peer_name, tls, "local", timestamp
    )
    .into_bytes()
}

fn chrono_like_utc_timestamp() -> String {
    chrono::Utc::now().to_rfc2822()
}

// session_encrypted indicates whether the current TCP stream is protected by TLS (true for SMTPS and after a successful STARTTLS upgrade).
// This allows the server to enforce that authentication mechanisms which transmit secrets
// (such as AUTH PLAIN or LOGIN) are only accepted on encrypted sessions.
async fn process_stream(
    stream: Box<dyn AsyncStream + Send + 'static>,
    mail_root: String,
    tls_ctx: Option<Arc<tls::TlsContext>>,
    db_path: Option<String>,
    peer: Option<SocketAddr>,
    session_encrypted: bool,
    enforce_dmarc: bool,
    send_greeting: bool,
    security: Arc<SecurityConfig>,
) -> Result<()> {
    let mut reader = BufReader::new(stream);
    println!(
        "Starting SMTP session peer={:?} encrypted={} tls_configured={} enforce_dmarc={}",
        peer,
        session_encrypted,
        tls_ctx.is_some(),
        enforce_dmarc
    );
    let mut line = String::new();
    if send_greeting {
        let w = reader.get_mut();
        w.write_all(b"220 rMail SMTPD ready\r\n").await?;
        w.flush().await?;
    }

    // SMTP transaction state
    const MAX_RCPT: usize = 100; // limit recipients per transaction to mitigate abuse
    let mut rcpts: Vec<String> = Vec::new();
    let mut mail_from: Option<String> = None;
    let mut mail_from_seen = false;
    // track authenticated identity when AUTH is used (local mailbox address)
    let mut authenticated_user: Option<String> = None;
    let mut helo_name: Option<String> = None;
    let mut extended_smtp = false;

    loop {
        line.clear();
        let Some(n) = timed_read_line(&mut reader, &mut line, COMMAND_IDLE_TIMEOUT).await? else {
            let w = reader.get_mut();
            let _ = w.write_all(b"421 4.4.2 Timeout\r\n").await;
            let _ = w.flush().await;
            break;
        };
        if n == 0 {
            break;
        }

        // Protect against overly long lines
        if line.len() > MAX_LINE_LEN {
            let w = reader.get_mut();
            w.write_all(b"500 Line too long\r\n").await?;
            w.flush().await?;
            // Skip this command and continue reading
            continue;
        }

        // Trim CRLF safely
        let cmd = line.trim_end_matches('\n').trim_end_matches('\r');
        if cmd.is_empty() {
            continue;
        }
        let parsed_command = parse_command(cmd);
        let logged_cmd = match parsed_command {
            SmtpCommand::Auth(args) => {
                let mech = args.split_whitespace().next().unwrap_or("");
                format!("AUTH {}", mech)
            }
            _ => cmd.to_string(),
        };
        println!(
            "SMTP peer={:?} encrypted={} cmd={:?} authed={:?} mail_from={:?} rcpt_count={}",
            peer,
            session_encrypted,
            logged_cmd,
            authenticated_user,
            mail_from,
            rcpts.len()
        );

        if let Some(reply) = protocol::preflight(
            &parsed_command,
            protocol::SessionContext {
                greeted: helo_name.is_some(),
                extended_smtp,
                encrypted: session_encrypted,
                authenticated: authenticated_user.is_some(),
                transaction_active: mail_from_seen,
                recipients: rcpts.len(),
            },
        ) {
            let writer = reader.get_mut();
            writer.write_all(reply).await?;
            writer.flush().await?;
            continue;
        }

        match parsed_command {
            SmtpCommand::Helo(name) | SmtpCommand::Ehlo(name) => {
                let is_ehlo = matches!(parsed_command, SmtpCommand::Ehlo(_));
                println!(
                    "SMTP greeting peer={:?} verb={}",
                    peer,
                    if is_ehlo { "EHLO" } else { "HELO" }
                );
                helo_name = Some(name.to_string());
                extended_smtp = is_ehlo;
                let mut resp = if is_ehlo {
                    String::from("250-Hello\r\n")
                } else {
                    String::from("250 Hello\r\n")
                };
                if is_ehlo {
                    if !session_encrypted && tls_ctx.is_some() {
                        resp.push_str("250-STARTTLS\r\n");
                    }
                    if session_encrypted && db_path.is_some() {
                        resp.push_str("250-AUTH PLAIN LOGIN SCRAM-SHA-256\r\n");
                    }
                    resp.push_str(&format!("250-SIZE {}\r\n", MAX_MESSAGE_BYTES));
                    resp.push_str("250-8BITMIME\r\n");
                    resp.push_str("250 OK\r\n");
                }
                let w = reader.get_mut();
                w.write_all(resp.as_bytes()).await?;
                w.flush().await?;
                // reset transaction state
                mail_from = None;
                mail_from_seen = false;
                rcpts.clear();
            }
            SmtpCommand::Auth(auth_args) => {
                // Simple AUTH implementation supporting PLAIN and LOGIN (only allowed over TLS in production)
                let auth_cmd = format!("AUTH {}", auth_args);
                let parts: Vec<&str> = auth_cmd.trim().splitn(3, ' ').collect();
                let mech = parts
                    .get(1)
                    .map(|s| s.to_ascii_uppercase())
                    .unwrap_or_default();
                let initial = parts.get(2).map(|s| *s);
                println!(
                    "SMTP AUTH attempt peer={:?} encrypted={} mechanism={}",
                    peer, session_encrypted, mech
                );
                // Rate-limiting: block repeated failures per remote IP
                if let Some(peer_addr) = peer {
                    if let Some(rem) = auth_block_remaining(peer_addr.ip()) {
                        let w = reader.get_mut();
                        w.write_all(
                            format!(
                                "454 4.7.1 Too many failed auth attempts; try again in {}s\r\n",
                                rem.as_secs()
                            )
                            .as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    }
                }
                // Require encryption (implicit SMTPS or STARTTLS) for authentication in production
                if !session_encrypted {
                    let w = reader.get_mut();
                    w.write_all(b"538 Encryption required for authentication\r\n")
                        .await?;
                    w.flush().await?;
                    continue;
                }
                if mech == "PLAIN" {
                    if let Some(b64) = initial {
                        match BASE64_ENGINE.decode(b64) {
                            Ok(bytes) => {
                                // PLAIN: [authz] NUL authcid NUL password
                                let splits: Vec<&[u8]> = bytes.split(|b| *b == 0).collect();
                                let (authcid, password) = if splits.len() >= 3 {
                                    (
                                        String::from_utf8_lossy(splits[1]).to_string(),
                                        String::from_utf8_lossy(splits[2]).to_string(),
                                    )
                                } else if splits.len() == 2 {
                                    (
                                        String::from_utf8_lossy(splits[0]).to_string(),
                                        String::from_utf8_lossy(splits[1]).to_string(),
                                    )
                                } else {
                                    ("".to_string(), "".to_string())
                                };
                                if let Some(dbp) = db_path.as_ref() {
                                    let dbp2 = dbp.clone();
                                    let user_lower = authcid.to_ascii_lowercase();
                                    let user_for_log = user_lower.clone();
                                    match tokio::task::spawn_blocking(move || {
                                        rmail_common::db::get_mailbox(&dbp2, &user_lower)
                                    })
                                    .await
                                    {
                                        Ok(Ok(Some(mb))) => {
                                            if let Some(pw_hash) = mb.password_hash {
                                                match rmail_common::auth::verify_password(
                                                    &password, &pw_hash,
                                                ) {
                                                    Ok(true) => {
                                                        authenticated_user =
                                                            Some(mb.address.to_ascii_lowercase());
                                                        println!(
                                                            "SMTP AUTH success peer={:?} user={}",
                                                            peer, mb.address
                                                        );
                                                        let w = reader.get_mut();
                                                        w.write_all(
                                                            b"235 Authentication succeeded\r\n",
                                                        )
                                                        .await?;
                                                        w.flush().await?;
                                                        if let Some(peer_addr) = peer {
                                                            reset_auth_failures(peer_addr.ip());
                                                        }
                                                    }
                                                    Ok(false) => {
                                                        println!(
                                                            "SMTP AUTH bad password peer={:?} user={}",
                                                            peer, mb.address
                                                        );
                                                        if let Some(peer_addr) = peer {
                                                            record_auth_failure(peer_addr.ip());
                                                        }
                                                        let w = reader.get_mut();
                                                        w.write_all(INVALID_CREDENTIALS).await?;
                                                        w.flush().await?;
                                                    }
                                                    Err(e) => {
                                                        eprintln!("auth verify error: {}", e);
                                                        if let Some(peer_addr) = peer {
                                                            record_auth_failure(peer_addr.ip());
                                                        }
                                                        let w = reader.get_mut();
                                                        w.write_all(b"451 Temporary error\r\n")
                                                            .await?;
                                                        w.flush().await?;
                                                    }
                                                }
                                            } else {
                                                if let Some(peer_addr) = peer {
                                                    record_auth_failure(peer_addr.ip());
                                                }
                                                let w = reader.get_mut();
                                                w.write_all(INVALID_CREDENTIALS).await?;
                                                w.flush().await?;
                                            }
                                        }
                                        Ok(Ok(None)) => {
                                            println!(
                                                "SMTP AUTH unknown user peer={:?} authcid={}",
                                                peer, user_for_log
                                            );
                                            if let Some(peer_addr) = peer {
                                                record_auth_failure(peer_addr.ip());
                                            }
                                            let w = reader.get_mut();
                                            w.write_all(INVALID_CREDENTIALS).await?;
                                            w.flush().await?;
                                        }
                                        Ok(Err(e)) => {
                                            eprintln!("db error: {}", e);
                                            let w = reader.get_mut();
                                            w.write_all(b"451 Temporary error\r\n").await?;
                                            w.flush().await?;
                                        }
                                        Err(e) => {
                                            eprintln!("db task join error: {}", e);
                                            let w = reader.get_mut();
                                            w.write_all(b"451 Temporary error\r\n").await?;
                                            w.flush().await?;
                                        }
                                    }
                                } else {
                                    let w = reader.get_mut();
                                    w.write_all(b"454 TLS not available\r\n").await?;
                                    w.flush().await?;
                                }
                            }
                            Err(_) => {
                                let w = reader.get_mut();
                                w.write_all(b"501 Invalid base64\r\n").await?;
                                w.flush().await?;
                            }
                        }
                    } else {
                        // challenge-response not fully implemented: ask for credentials
                        let w = reader.get_mut();
                        w.write_all(b"334 \r\n").await?;
                        w.flush().await?;
                        let mut resp_line = String::new();
                        let Some(_) =
                            timed_read_line(&mut reader, &mut resp_line, AUTH_CONTINUATION_TIMEOUT)
                                .await?
                        else {
                            let w = reader.get_mut();
                            let _ = w.write_all(b"421 4.4.2 Timeout\r\n").await;
                            let _ = w.flush().await;
                            break;
                        };
                        let b64 = resp_line.trim();
                        match base64::engine::general_purpose::STANDARD.decode(b64) {
                            Ok(bytes) => {
                                let splits: Vec<&[u8]> = bytes.split(|b| *b == 0).collect();
                                let (authcid, password) = if splits.len() >= 3 {
                                    (
                                        String::from_utf8_lossy(splits[1]).to_string(),
                                        String::from_utf8_lossy(splits[2]).to_string(),
                                    )
                                } else if splits.len() == 2 {
                                    (
                                        String::from_utf8_lossy(splits[0]).to_string(),
                                        String::from_utf8_lossy(splits[1]).to_string(),
                                    )
                                } else {
                                    ("".to_string(), "".to_string())
                                };
                                if let Some(dbp) = db_path.as_ref() {
                                    let dbp2 = dbp.clone();
                                    let user_lower = authcid.to_ascii_lowercase();
                                    let user_for_log = user_lower.clone();
                                    match tokio::task::spawn_blocking(move || {
                                        rmail_common::db::get_mailbox(&dbp2, &user_lower)
                                    })
                                    .await
                                    {
                                        Ok(Ok(Some(mb))) => {
                                            if let Some(pw_hash) = mb.password_hash {
                                                match rmail_common::auth::verify_password(
                                                    &password, &pw_hash,
                                                ) {
                                                    Ok(true) => {
                                                        authenticated_user =
                                                            Some(mb.address.to_ascii_lowercase());
                                                        println!(
                                                            "SMTP AUTH success peer={:?} user={}",
                                                            peer, mb.address
                                                        );
                                                        let w = reader.get_mut();
                                                        w.write_all(
                                                            b"235 Authentication succeeded\r\n",
                                                        )
                                                        .await?;
                                                        w.flush().await?;
                                                        if let Some(peer_addr) = peer {
                                                            reset_auth_failures(peer_addr.ip());
                                                        }
                                                    }
                                                    Ok(false) => {
                                                        println!(
                                                            "SMTP AUTH bad password peer={:?} user={}",
                                                            peer, mb.address
                                                        );
                                                        if let Some(peer_addr) = peer {
                                                            record_auth_failure(peer_addr.ip());
                                                        }
                                                        let w = reader.get_mut();
                                                        w.write_all(INVALID_CREDENTIALS).await?;
                                                        w.flush().await?;
                                                    }
                                                    Err(e) => {
                                                        eprintln!("auth verify error: {}", e);
                                                        if let Some(peer_addr) = peer {
                                                            record_auth_failure(peer_addr.ip());
                                                        }
                                                        let w = reader.get_mut();
                                                        w.write_all(b"451 Temporary error\r\n")
                                                            .await?;
                                                        w.flush().await?;
                                                    }
                                                }
                                            } else {
                                                if let Some(peer_addr) = peer {
                                                    record_auth_failure(peer_addr.ip());
                                                }
                                                let w = reader.get_mut();
                                                w.write_all(INVALID_CREDENTIALS).await?;
                                                w.flush().await?;
                                            }
                                        }
                                        Ok(Ok(None)) => {
                                            println!(
                                                "SMTP AUTH unknown user peer={:?} authcid={}",
                                                peer, user_for_log
                                            );
                                            if let Some(peer_addr) = peer {
                                                record_auth_failure(peer_addr.ip());
                                            }
                                            let w = reader.get_mut();
                                            w.write_all(INVALID_CREDENTIALS).await?;
                                            w.flush().await?;
                                        }
                                        Ok(Err(e)) => {
                                            eprintln!("db error: {}", e);
                                            let w = reader.get_mut();
                                            w.write_all(b"451 Temporary error\r\n").await?;
                                            w.flush().await?;
                                        }
                                        Err(e) => {
                                            eprintln!("db task join error: {}", e);
                                            let w = reader.get_mut();
                                            w.write_all(b"451 Temporary error\r\n").await?;
                                            w.flush().await?;
                                        }
                                    }
                                } else {
                                    let w = reader.get_mut();
                                    w.write_all(b"454 TLS not available\r\n").await?;
                                    w.flush().await?;
                                }
                            }
                            Err(_) => {
                                let w = reader.get_mut();
                                w.write_all(b"501 Invalid base64\r\n").await?;
                                w.flush().await?;
                            }
                        }
                    }
                } else if mech == "SCRAM-SHA-256" {
                    // SCRAM-SHA-256 server-side (RFC 5802 minimal implementation)
                    // Workflow: client-first-message [base64] -> server-first-message (r=nonce,s=salt,i=iter) -> client-final-message (with proof)
                    let client_first_msg = if let Some(b64) = initial {
                        match base64::engine::general_purpose::STANDARD.decode(b64) {
                            Ok(b) => String::from_utf8_lossy(&b).to_string(),
                            Err(_) => {
                                let w = reader.get_mut();
                                w.write_all(b"501 Invalid base64\r\n").await?;
                                w.flush().await?;
                                continue;
                            }
                        }
                    } else {
                        let w = reader.get_mut();
                        w.write_all(b"334 \r\n").await?;
                        w.flush().await?;
                        let mut resp_line = String::new();
                        let Some(_) =
                            timed_read_line(&mut reader, &mut resp_line, AUTH_CONTINUATION_TIMEOUT)
                                .await?
                        else {
                            let w = reader.get_mut();
                            let _ = w.write_all(b"421 4.4.2 Timeout\r\n").await;
                            let _ = w.flush().await;
                            break;
                        };
                        let b64 = resp_line.trim();
                        match base64::engine::general_purpose::STANDARD.decode(b64) {
                            Ok(b) => String::from_utf8_lossy(&b).to_string(),
                            Err(_) => {
                                let w = reader.get_mut();
                                w.write_all(b"501 Invalid base64\r\n").await?;
                                w.flush().await?;
                                continue;
                            }
                        }
                    };

                    // Extract GS2 header (the part before ",,") and client-first-bare. GS2 header
                    // indicates whether the client requests channel-binding. We support either the
                    // common "n,," (no channel binding) or "p=tls-server-end-point,," (server-end-point
                    // channel binding) when TLS is in use. Other GS2 variants are rejected.
                    let (gs2_header_owned, client_first_bare) =
                        if let Some(idx) = client_first_msg.find(",,") {
                            let gs2_header = client_first_msg[..idx + 2].to_string();
                            // accept 'n,,' or 'p=tls-server-end-point,,'
                            if !(gs2_header == "n,,"
                                || gs2_header.starts_with("p=tls-server-end-point"))
                            {
                                let w = reader.get_mut();
                                w.write_all(b"538 Channel-binding requested but not supported\r\n")
                                    .await?;
                                w.flush().await?;
                                continue;
                            }
                            (gs2_header, client_first_msg[idx + 2..].to_string())
                        } else {
                            (String::new(), client_first_msg.clone())
                        };

                    // parse username (n=) and client nonce (r=) from client-first-bare
                    let mut username = String::new();
                    let mut client_nonce = String::new();
                    for part in client_first_bare.split(',') {
                        if part.starts_with("n=") {
                            username = part[2..].to_string();
                        } else if part.starts_with("r=") {
                            client_nonce = part[2..].to_string();
                        }
                    }
                    if username.is_empty() || client_nonce.is_empty() {
                        let w = reader.get_mut();
                        w.write_all(b"501 Invalid SCRAM client-first message\r\n")
                            .await?;
                        w.flush().await?;
                        continue;
                    }

                    if let Some(dbp) = db_path.as_ref() {
                        let dbp2 = dbp.clone();
                        // Apply SASLprep-like normalization to the provided username before lookup.
                        // This helps with Unicode equivalence and common client encodings.
                        let user_prep = auth::saslprep(&username);
                        let user_lower = user_prep.to_ascii_lowercase();
                        match tokio::task::spawn_blocking(move || {
                            rmail_common::db::get_mailbox(&dbp2, &user_lower)
                        })
                        .await
                        {
                            Ok(Ok(Some(mb))) => {
                                if let Some(scram_json) = mb.scram {
                                    match rmail_common::auth::parse_scram_verifier(&scram_json) {
                                        Ok((salt_b64, iter)) => {
                                            // generate server nonce and compose server-first-message
                                            let mut rn = [0u8; 18];
                                            let mut rng = rand::rngs::OsRng;
                                            rng.fill_bytes(&mut rn);
                                            let server_nonce =
                                                base64::engine::general_purpose::STANDARD
                                                    .encode(&rn);
                                            let combined_nonce =
                                                format!("{}{}", client_nonce, server_nonce);
                                            let server_first_msg = format!(
                                                "r={},s={},i={}",
                                                combined_nonce, salt_b64, iter
                                            );

                                            // send server-first-message (base64)
                                            let sf_b64 = base64::engine::general_purpose::STANDARD
                                                .encode(server_first_msg.as_bytes());
                                            let w = reader.get_mut();
                                            w.write_all(format!("334 {}\r\n", sf_b64).as_bytes())
                                                .await?;
                                            w.flush().await?;

                                            // read client-final-message (base64)
                                            let mut resp_line = String::new();
                                            let Some(_) = timed_read_line(
                                                &mut reader,
                                                &mut resp_line,
                                                AUTH_CONTINUATION_TIMEOUT,
                                            )
                                            .await?
                                            else {
                                                let w = reader.get_mut();
                                                let _ = w.write_all(b"421 4.4.2 Timeout\r\n").await;
                                                let _ = w.flush().await;
                                                break;
                                            };
                                            let b64_cf = resp_line.trim();
                                            let cf_bytes =
                                                match base64::engine::general_purpose::STANDARD
                                                    .decode(b64_cf)
                                                {
                                                    Ok(b) => b,
                                                    Err(_) => {
                                                        let w = reader.get_mut();
                                                        w.write_all(b"501 Invalid base64\r\n")
                                                            .await?;
                                                        w.flush().await?;
                                                        continue;
                                                    }
                                                };
                                            let client_final_msg =
                                                String::from_utf8_lossy(&cf_bytes).to_string();

                                            // split out the proof (p=) and client-final-without-proof
                                            if let Some(pos) = client_final_msg.find(",p=") {
                                                let client_final_wo_proof =
                                                    client_final_msg[..pos].to_string();
                                                let client_proof_b64 = &client_final_msg[pos + 3..];

                                                // If channel-binding was requested (gs2 header != "n,,"), verify it now.
                                                if !gs2_header_owned.is_empty()
                                                    && !gs2_header_owned.eq("n,,")
                                                {
                                                    // Only support tls-server-end-point; ensure TLS is active and we have server endpoint info
                                                    if !session_encrypted || tls_ctx.is_none() {
                                                        if let Some(peer_addr) = peer {
                                                            record_auth_failure(peer_addr.ip());
                                                        }
                                                        let w = reader.get_mut();
                                                        w.write_all(b"538 Channel-binding required but TLS not active\r\n").await?;
                                                        w.flush().await?;
                                                        continue;
                                                    }
                                                    // Extract c= value from client_final_wo_proof
                                                    let c_b64_opt = client_final_wo_proof
                                                        .split(',')
                                                        .find_map(|kv| kv.strip_prefix("c="));
                                                    if c_b64_opt.is_none() {
                                                        if let Some(peer_addr) = peer {
                                                            record_auth_failure(peer_addr.ip());
                                                        }
                                                        let w = reader.get_mut();
                                                        w.write_all(b"501 Missing c= channel-binding in client-final\r\n").await?;
                                                        w.flush().await?;
                                                        continue;
                                                    }
                                                    let c_b64 = c_b64_opt.unwrap();
                                                    // Validate binding: gs2_header + server_end_point should match decoded c=
                                                    let tctx = tls_ctx.as_ref().unwrap();
                                                    match rmail_common::auth::verify_tls_server_end_point_binding(&gs2_header_owned, &tctx.server_end_point, c_b64) {
                                                    Ok(()) => {
                                                        // ok
                                                    }
                                                    Err(_) => {
                                                        if let Some(peer_addr) = peer { record_auth_failure(peer_addr.ip()); }
                                                        let w = reader.get_mut();
                                                        w.write_all(INVALID_CREDENTIALS).await?;
                                                        w.flush().await?;
                                                        continue;
                                                    }
                                                }
                                                }

                                                let auth_message = format!(
                                                    "{},{},{}",
                                                    client_first_bare,
                                                    server_first_msg,
                                                    client_final_wo_proof
                                                );

                                                match rmail_common::auth::verify_scram_proof(
                                                    &scram_json,
                                                    &auth_message,
                                                    client_proof_b64,
                                                ) {
                                                    Ok(server_sig) => {
                                                        // send server-final-message (v=base64) in a 235 success response
                                                        let server_final = format!(
                                                        "v={}",
                                                        base64::engine::general_purpose::STANDARD
                                                            .encode(&server_sig)
                                                    );
                                                        let sf_b64 =
                                                        base64::engine::general_purpose::STANDARD
                                                            .encode(server_final.as_bytes());
                                                        let w = reader.get_mut();
                                                        w.write_all(
                                                            format!("235 {}\r\n", sf_b64)
                                                                .as_bytes(),
                                                        )
                                                        .await?;
                                                        w.flush().await?;
                                                        authenticated_user =
                                                            Some(mb.address.to_ascii_lowercase());
                                                        if let Some(peer_addr) = peer {
                                                            reset_auth_failures(peer_addr.ip());
                                                        }
                                                    }
                                                    Err(_) => {
                                                        if let Some(peer_addr) = peer {
                                                            record_auth_failure(peer_addr.ip());
                                                        }
                                                        let w = reader.get_mut();
                                                        w.write_all(INVALID_CREDENTIALS).await?;
                                                        w.flush().await?;
                                                    }
                                                }
                                            } else {
                                                let w = reader.get_mut();
                                                w.write_all(
                                                    b"501 Invalid SCRAM client-final message\r\n",
                                                )
                                                .await?;
                                                w.flush().await?;
                                            }
                                        }
                                        Err(_) => {
                                            if let Some(peer_addr) = peer {
                                                record_auth_failure(peer_addr.ip());
                                            }
                                            let w = reader.get_mut();
                                            w.write_all(b"451 Temporary error\r\n").await?;
                                            w.flush().await?;
                                        }
                                    }
                                } else {
                                    if let Some(peer_addr) = peer {
                                        record_auth_failure(peer_addr.ip());
                                    }
                                    let w = reader.get_mut();
                                    w.write_all(INVALID_CREDENTIALS).await?;
                                    w.flush().await?;
                                }
                            }
                            Ok(Ok(None)) => {
                                if let Some(peer_addr) = peer {
                                    record_auth_failure(peer_addr.ip());
                                }
                                let w = reader.get_mut();
                                w.write_all(INVALID_CREDENTIALS).await?;
                                w.flush().await?;
                            }
                            Ok(Err(e)) => {
                                eprintln!("db error: {}", e);
                                let w = reader.get_mut();
                                w.write_all(b"451 Temporary error\r\n").await?;
                                w.flush().await?;
                            }
                            Err(e) => {
                                eprintln!("db task join error: {}", e);
                                let w = reader.get_mut();
                                w.write_all(b"451 Temporary error\r\n").await?;
                                w.flush().await?;
                            }
                        }
                    } else {
                        let w = reader.get_mut();
                        w.write_all(b"454 TLS not available\r\n").await?;
                        w.flush().await?;
                    }
                } else if mech == "LOGIN" {
                    // LOGIN: two step username/password base64 prompts
                    if let Some(b64u) = initial {
                        match base64::engine::general_purpose::STANDARD.decode(b64u) {
                            Ok(u_bytes) => {
                                let username = String::from_utf8_lossy(&u_bytes).to_string();
                                let w = reader.get_mut();
                                w.write_all(b"334 UGFzc3dvcmQ6\r\n").await?; // "Password:" in base64
                                w.flush().await?;
                                let mut pass_line = String::new();
                                let Some(_) = timed_read_line(
                                    &mut reader,
                                    &mut pass_line,
                                    AUTH_CONTINUATION_TIMEOUT,
                                )
                                .await?
                                else {
                                    let w = reader.get_mut();
                                    let _ = w.write_all(b"421 4.4.2 Timeout\r\n").await;
                                    let _ = w.flush().await;
                                    break;
                                };
                                let b64p = pass_line.trim();
                                match base64::engine::general_purpose::STANDARD.decode(b64p) {
                                    Ok(p_bytes) => {
                                        let password =
                                            String::from_utf8_lossy(&p_bytes).to_string();
                                        if let Some(dbp) = db_path.as_ref() {
                                            let dbp2 = dbp.clone();
                                            let user_lower = username.to_ascii_lowercase();
                                            match tokio::task::spawn_blocking(move || {
                                                rmail_common::db::get_mailbox(&dbp2, &user_lower)
                                            })
                                            .await
                                            {
                                                Ok(Ok(Some(mb))) => {
                                                    if let Some(pw_hash) = mb.password_hash {
                                                        match rmail_common::auth::verify_password(
                                                            &password, &pw_hash,
                                                        ) {
                                                            Ok(true) => {
                                                                authenticated_user = Some(
                                                                    mb.address.to_ascii_lowercase(),
                                                                );
                                                                let w = reader.get_mut();
                                                                w.write_all(
                                                                b"235 Authentication succeeded\r\n",
                                                            )
                                                            .await?;
                                                                w.flush().await?;
                                                                if let Some(peer_addr) = peer {
                                                                    reset_auth_failures(
                                                                        peer_addr.ip(),
                                                                    );
                                                                }
                                                            }
                                                            Ok(false) => {
                                                                if let Some(peer_addr) = peer {
                                                                    record_auth_failure(
                                                                        peer_addr.ip(),
                                                                    );
                                                                }
                                                                let w = reader.get_mut();
                                                                w.write_all(INVALID_CREDENTIALS)
                                                                    .await?;
                                                                w.flush().await?;
                                                            }
                                                            Err(e) => {
                                                                eprintln!(
                                                                    "auth verify error: {}",
                                                                    e
                                                                );
                                                                if let Some(peer_addr) = peer {
                                                                    record_auth_failure(
                                                                        peer_addr.ip(),
                                                                    );
                                                                }
                                                                let w = reader.get_mut();
                                                                w.write_all(
                                                                    b"451 Temporary error\r\n",
                                                                )
                                                                .await?;
                                                                w.flush().await?;
                                                            }
                                                        }
                                                    } else {
                                                        if let Some(peer_addr) = peer {
                                                            record_auth_failure(peer_addr.ip());
                                                        }
                                                        let w = reader.get_mut();
                                                        w.write_all(INVALID_CREDENTIALS).await?;
                                                        w.flush().await?;
                                                    }
                                                }
                                                Ok(Ok(None)) => {
                                                    if let Some(peer_addr) = peer {
                                                        record_auth_failure(peer_addr.ip());
                                                    }
                                                    let w = reader.get_mut();
                                                    w.write_all(INVALID_CREDENTIALS).await?;
                                                    w.flush().await?;
                                                }
                                                Ok(Err(e)) => {
                                                    eprintln!("db error: {}", e);
                                                    let w = reader.get_mut();
                                                    w.write_all(b"451 Temporary error\r\n").await?;
                                                    w.flush().await?;
                                                }
                                                Err(e) => {
                                                    eprintln!("db task join error: {}", e);
                                                    let w = reader.get_mut();
                                                    w.write_all(b"451 Temporary error\r\n").await?;
                                                    w.flush().await?;
                                                }
                                            }
                                        } else {
                                            let w = reader.get_mut();
                                            w.write_all(b"454 TLS not available\r\n").await?;
                                            w.flush().await?;
                                        }
                                    }
                                    Err(_) => {
                                        let w = reader.get_mut();
                                        w.write_all(b"501 Invalid base64\r\n").await?;
                                        w.flush().await?;
                                    }
                                }
                            }
                            Err(_) => {
                                let w = reader.get_mut();
                                w.write_all(b"501 Invalid base64\r\n").await?;
                                w.flush().await?;
                            }
                        }
                    } else {
                        let w = reader.get_mut();
                        w.write_all(b"334 VXNlcm5hbWU6\r\n").await?; // "Username:" in base64
                        w.flush().await?;
                        let mut uline = String::new();
                        let Some(_) =
                            timed_read_line(&mut reader, &mut uline, AUTH_CONTINUATION_TIMEOUT)
                                .await?
                        else {
                            let w = reader.get_mut();
                            let _ = w.write_all(b"421 4.4.2 Timeout\r\n").await;
                            let _ = w.flush().await;
                            break;
                        };
                        let b64u = uline.trim();
                        match base64::engine::general_purpose::STANDARD.decode(b64u) {
                            Ok(u_bytes) => {
                                let username = String::from_utf8_lossy(&u_bytes).to_string();
                                let w = reader.get_mut();
                                w.write_all(b"334 UGFzc3dvcmQ6\r\n").await?; // "Password:" in base64
                                w.flush().await?;
                                let mut pass_line = String::new();
                                let Some(_) = timed_read_line(
                                    &mut reader,
                                    &mut pass_line,
                                    AUTH_CONTINUATION_TIMEOUT,
                                )
                                .await?
                                else {
                                    let w = reader.get_mut();
                                    let _ = w.write_all(b"421 4.4.2 Timeout\r\n").await;
                                    let _ = w.flush().await;
                                    break;
                                };
                                let b64p = pass_line.trim();
                                match base64::engine::general_purpose::STANDARD.decode(b64p) {
                                    Ok(p_bytes) => {
                                        let password =
                                            String::from_utf8_lossy(&p_bytes).to_string();
                                        if let Some(dbp) = db_path.as_ref() {
                                            let dbp2 = dbp.clone();
                                            let user_lower = username.to_ascii_lowercase();
                                            match tokio::task::spawn_blocking(move || {
                                                rmail_common::db::get_mailbox(&dbp2, &user_lower)
                                            })
                                            .await
                                            {
                                                Ok(Ok(Some(mb))) => {
                                                    if let Some(pw_hash) = mb.password_hash {
                                                        match rmail_common::auth::verify_password(
                                                            &password, &pw_hash,
                                                        ) {
                                                            Ok(true) => {
                                                                authenticated_user = Some(
                                                                    mb.address.to_ascii_lowercase(),
                                                                );
                                                                let w = reader.get_mut();
                                                                w.write_all(
                                                                b"235 Authentication succeeded\r\n",
                                                            )
                                                            .await?;
                                                                w.flush().await?;
                                                                if let Some(peer_addr) = peer {
                                                                    reset_auth_failures(
                                                                        peer_addr.ip(),
                                                                    );
                                                                }
                                                            }
                                                            Ok(false) => {
                                                                if let Some(peer_addr) = peer {
                                                                    record_auth_failure(
                                                                        peer_addr.ip(),
                                                                    );
                                                                }
                                                                let w = reader.get_mut();
                                                                w.write_all(INVALID_CREDENTIALS)
                                                                    .await?;
                                                                w.flush().await?;
                                                            }
                                                            Err(e) => {
                                                                eprintln!(
                                                                    "auth verify error: {}",
                                                                    e
                                                                );
                                                                if let Some(peer_addr) = peer {
                                                                    record_auth_failure(
                                                                        peer_addr.ip(),
                                                                    );
                                                                }
                                                                let w = reader.get_mut();
                                                                w.write_all(
                                                                    b"451 Temporary error\r\n",
                                                                )
                                                                .await?;
                                                                w.flush().await?;
                                                            }
                                                        }
                                                    } else {
                                                        if let Some(peer_addr) = peer {
                                                            record_auth_failure(peer_addr.ip());
                                                        }
                                                        let w = reader.get_mut();
                                                        w.write_all(INVALID_CREDENTIALS).await?;
                                                        w.flush().await?;
                                                    }
                                                }
                                                Ok(Ok(None)) => {
                                                    if let Some(peer_addr) = peer {
                                                        record_auth_failure(peer_addr.ip());
                                                    }
                                                    let w = reader.get_mut();
                                                    w.write_all(INVALID_CREDENTIALS).await?;
                                                    w.flush().await?;
                                                }
                                                Ok(Err(e)) => {
                                                    eprintln!("db error: {}", e);
                                                    let w = reader.get_mut();
                                                    w.write_all(b"451 Temporary error\r\n").await?;
                                                    w.flush().await?;
                                                }
                                                Err(e) => {
                                                    eprintln!("db task join error: {}", e);
                                                    let w = reader.get_mut();
                                                    w.write_all(b"451 Temporary error\r\n").await?;
                                                    w.flush().await?;
                                                }
                                            }
                                        } else {
                                            let w = reader.get_mut();
                                            w.write_all(b"454 TLS not available\r\n").await?;
                                            w.flush().await?;
                                        }
                                    }
                                    Err(_) => {
                                        let w = reader.get_mut();
                                        w.write_all(b"501 Invalid base64\r\n").await?;
                                        w.flush().await?;
                                    }
                                }
                            }
                            Err(_) => {
                                let w = reader.get_mut();
                                w.write_all(b"501 Invalid base64\r\n").await?;
                                w.flush().await?;
                            }
                        }
                    }
                } else {
                    let w = reader.get_mut();
                    w.write_all(b"504 Unrecognized authentication mechanism\r\n")
                        .await?;
                    w.flush().await?;
                }
            }
            SmtpCommand::Mail(mail_args) => {
                // Parse MAIL FROM and set sender; on syntax error return 501
                match parse_mail_from_args(mail_args) {
                    Some(parsed) => {
                        if parsed
                            .declared_size
                            .is_some_and(|size| size > MAX_MESSAGE_BYTES)
                        {
                            let w = reader.get_mut();
                            w.write_all(b"552 5.3.4 Message size exceeds fixed maximum\r\n")
                                .await?;
                            w.flush().await?;
                            continue;
                        }
                        mail_from = parsed.sender;
                        mail_from_seen = true;
                        println!("SMTP MAIL FROM peer={:?} parsed={:?}", peer, mail_from);
                    }
                    None => {
                        mail_from = None;
                        mail_from_seen = false;
                        println!("SMTP MAIL FROM peer={:?} parse failed", peer);
                    }
                }
                if !mail_from_seen {
                    let w = reader.get_mut();
                    w.write_all(b"501 Syntax: MAIL FROM:<address>\r\n").await?;
                    w.flush().await?;
                    continue;
                }
                rcpts.clear();
                let w = reader.get_mut();
                w.write_all(b"250 OK\r\n").await?;
                w.flush().await?;
            }
            SmtpCommand::Rcpt(rcpt_args) => {
                // Require MAIL FROM before RCPT TO
                if !mail_from_seen {
                    let w = reader.get_mut();
                    w.write_all(b"503 Bad sequence of commands: MAIL required before RCPT\r\n")
                        .await?;
                    w.flush().await?;
                    continue;
                }
                if let Some(addr) = parse_rcpt_to_args(rcpt_args) {
                    println!("SMTP RCPT TO peer={:?} parsed={}", peer, addr);
                    // DB is authoritative — must be configured at startup
                    if let Some(dbp) = db_path.as_ref() {
                        let dbp2 = dbp.clone();
                        let addr2 = addr.clone();
                        match tokio::task::spawn_blocking(move || {
                            rmail_common::db::mailbox_exists(dbp2, &addr2)
                        })
                        .await
                        {
                            Ok(Ok(true)) => {
                                if rcpts.len() >= MAX_RCPT {
                                    let w = reader.get_mut();
                                    w.write_all(b"452 Too many recipients\r\n").await?;
                                    w.flush().await?;
                                } else {
                                    rcpts.push(addr.clone());
                                    println!(
                                        "SMTP RCPT accepted peer={:?} rcpt_count={} current_rcpts={:?}",
                                        peer,
                                        rcpts.len(),
                                        rcpts
                                    );
                                    let w = reader.get_mut();
                                    w.write_all(b"250 OK\r\n").await?;
                                    w.flush().await?;
                                }
                            }
                            Ok(Ok(false)) => {
                                if let Some(at) = addr.find('@') {
                                    let domain = addr[at + 1..].to_string();
                                    // First, check for alias mappings for this exact address
                                    let dbp_alias = dbp.clone();
                                    let addr_for_alias = addr.clone();
                                    match tokio::task::spawn_blocking(move || {
                                        rmail_common::db::get_alias_targets(
                                            &dbp_alias,
                                            &addr_for_alias,
                                        )
                                    })
                                    .await
                                    {
                                        Ok(Ok(Some(targets))) => {
                                            println!(
                                                "SMTP RCPT alias match peer={:?} rcpt={} targets={:?}",
                                                peer, addr, targets
                                            );
                                            // Expand alias targets (allow forwarding even when unauthenticated)
                                            for t in targets {
                                                if rcpts.len() >= MAX_RCPT {
                                                    let w = reader.get_mut();
                                                    w.write_all(b"452 Too many recipients\r\n")
                                                        .await?;
                                                    w.flush().await?;
                                                    break;
                                                } else {
                                                    rcpts.push(t.clone());
                                                    let w = reader.get_mut();
                                                    w.write_all(b"250 OK\r\n").await?;
                                                    w.flush().await?;
                                                }
                                            }
                                        }
                                        Ok(Ok(None)) => {
                                            // No alias; fallback to catchall logic
                                            let dbp3 = dbp.clone();
                                            match tokio::task::spawn_blocking(move || {
                                                rmail_common::db::get_catchall(dbp3, &domain)
                                            })
                                            .await
                                            {
                                                Ok(Ok(Some(target))) => {
                                                    println!(
                                                        "SMTP RCPT catchall match peer={:?} rcpt={} target={}",
                                                        peer, addr, target
                                                    );
                                                    if rcpts.len() >= MAX_RCPT {
                                                        let w = reader.get_mut();
                                                        w.write_all(b"452 Too many recipients\r\n")
                                                            .await?;
                                                        w.flush().await?;
                                                    } else {
                                                        rcpts.push(target.clone());
                                                        let w = reader.get_mut();
                                                        w.write_all(b"250 OK\r\n").await?;
                                                        w.flush().await?;
                                                    }
                                                }
                                                Ok(Ok(None)) => {
                                                    // Not a local recipient and no catchall configured for domain.
                                                    // Allow relay to remote recipients only if the client has authenticated.
                                                    if authenticated_user.is_some() {
                                                        if rcpts.len() >= MAX_RCPT {
                                                            let w = reader.get_mut();
                                                            w.write_all(
                                                                b"452 Too many recipients\r\n",
                                                            )
                                                            .await?;
                                                            w.flush().await?;
                                                        } else {
                                                            rcpts.push(addr.clone());
                                                            let w = reader.get_mut();
                                                            w.write_all(b"250 OK\r\n").await?;
                                                            w.flush().await?;
                                                        }
                                                    } else {
                                                        let w = reader.get_mut();
                                                        w.write_all(b"550 No such user\r\n")
                                                            .await?;
                                                        w.flush().await?;
                                                    }
                                                }
                                                Ok(Err(e)) => {
                                                    eprintln!("db get_catchall error: {}", e);
                                                    let w = reader.get_mut();
                                                    w.write_all(b"451 Temporary error\r\n").await?;
                                                    w.flush().await?;
                                                }
                                                Err(e) => {
                                                    eprintln!("db task join error: {}", e);
                                                    let w = reader.get_mut();
                                                    w.write_all(b"451 Temporary error\r\n").await?;
                                                    w.flush().await?;
                                                }
                                            }
                                        }
                                        Ok(Err(e)) => {
                                            eprintln!("db get_alias_targets error: {}", e);
                                            let w = reader.get_mut();
                                            w.write_all(b"451 Temporary error\r\n").await?;
                                            w.flush().await?;
                                        }
                                        Err(e) => {
                                            eprintln!("db task join error: {}", e);
                                            let w = reader.get_mut();
                                            w.write_all(b"451 Temporary error\r\n").await?;
                                            w.flush().await?;
                                        }
                                    }
                                } else {
                                    let w = reader.get_mut();
                                    w.write_all(b"550 Bad address\r\n").await?;
                                    w.flush().await?;
                                }
                            }
                            Ok(Err(e)) => {
                                eprintln!("db mailbox_exists error: {}", e);
                                let w = reader.get_mut();
                                w.write_all(b"451 Temporary error\r\n").await?;
                                w.flush().await?;
                            }
                            Err(e) => {
                                eprintln!("db task join error: {}", e);
                                let w = reader.get_mut();
                                w.write_all(b"451 Temporary error\r\n").await?;
                                w.flush().await?;
                            }
                        }
                    } else {
                        let w = reader.get_mut();
                        w.write_all(b"451 No DB configured\r\n").await?;
                        w.flush().await?;
                    }
                } else {
                    let w = reader.get_mut();
                    w.write_all(b"501 Syntax: RCPT TO:<address>\r\n").await?;
                    w.flush().await?;
                }
            }
            SmtpCommand::Data => {
                // DATA requires recipients
                if rcpts.is_empty() {
                    let w = reader.get_mut();
                    w.write_all(b"554 No recipients\r\n").await?;
                    w.flush().await?;
                    continue;
                }
                println!(
                    "SMTP DATA begin peer={:?} mail_from={:?} rcpts={:?}",
                    peer, mail_from, rcpts
                );
                let w = reader.get_mut();
                w.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    .await?;
                w.flush().await?;

                let mut data = match read_smtp_data(&mut reader).await? {
                    DataReadResult::Complete(mut data) => {
                        let mut traced =
                            received_header(peer, helo_name.as_deref(), session_encrypted);
                        traced.append(&mut data);
                        traced
                    }
                    DataReadResult::TooLarge => {
                        let w = reader.get_mut();
                        w.write_all(b"552 5.3.4 Message size exceeds fixed maximum\r\n")
                            .await?;
                        w.flush().await?;
                        rcpts.clear();
                        mail_from = None;
                        mail_from_seen = false;
                        continue;
                    }
                    DataReadResult::LineTooLong => {
                        let w = reader.get_mut();
                        w.write_all(b"500 5.5.2 Line too long in data\r\n").await?;
                        w.flush().await?;
                        rcpts.clear();
                        mail_from = None;
                        mail_from_seen = false;
                        continue;
                    }
                    DataReadResult::Timeout => {
                        let w = reader.get_mut();
                        let _ = w.write_all(b"421 4.4.2 Timeout\r\n").await;
                        let _ = w.flush().await;
                        break;
                    }
                    DataReadResult::Eof => break,
                };

                let mut scanner_quarantine = false;
                if security.scanners_enabled() {
                    let envelope = ScanEnvelope {
                        mail_from: mail_from.clone(),
                        rcpts: rcpts.clone(),
                        peer_ip: peer.map(|p| p.ip()),
                        helo: helo_name.clone(),
                        hostname: helo_name.clone(),
                        user: authenticated_user.clone(),
                    };
                    match rmail_common::scanner::scan_message(&security, &data, &envelope).await {
                        Ok(verdict) => match verdict.action {
                            ScanAction::Clean => {
                                if !verdict.headers.is_empty() {
                                    data = rmail_common::scanner::prepend_scan_headers(
                                        &data,
                                        &verdict.headers,
                                    );
                                }
                            }
                            ScanAction::Quarantine => {
                                scanner_quarantine = true;
                                data = rmail_common::scanner::prepend_scan_headers(
                                    &data,
                                    &verdict.headers,
                                );
                            }
                            ScanAction::Reject => {
                                println!(
                                    "SMTP scanner rejected peer={:?} reason={:?}",
                                    peer, verdict.reason
                                );
                                let w = reader.get_mut();
                                w.write_all(b"554 5.7.1 Message rejected: malware detected\r\n")
                                    .await?;
                                w.flush().await?;
                                rcpts.clear();
                                mail_from = None;
                                mail_from_seen = false;
                                continue;
                            }
                        },
                        Err(e) => {
                            eprintln!("SMTP scanner error peer={:?}: {}", peer, e);
                            let w = reader.get_mut();
                            match security.scanner_failure_action {
                                ScannerFailureAction::Accept => {}
                                ScannerFailureAction::Reject => {
                                    w.write_all(
                                        b"554 5.7.1 Message rejected: scanner unavailable\r\n",
                                    )
                                    .await?;
                                    w.flush().await?;
                                    rcpts.clear();
                                    mail_from = None;
                                    mail_from_seen = false;
                                    continue;
                                }
                                ScannerFailureAction::Tempfail => {
                                    w.write_all(b"451 4.7.1 Message scanner unavailable\r\n")
                                        .await?;
                                    w.flush().await?;
                                    rcpts.clear();
                                    mail_from = None;
                                    mail_from_seen = false;
                                    continue;
                                }
                            }
                        }
                    }
                }

                // Attempt delivery to each recipient; errors are logged and yield temporary failure response
                {
                    // account bytes received
                    metrics::add_bytes_received(data.len() as u64);
                    println!(
                        "SMTP DATA received peer={:?} bytes={} rcpts={:?}",
                        peer,
                        data.len(),
                        rcpts
                    );
                    let mut any_accepted = false;
                    let mut any_rejected = false;
                    for rcpt in &rcpts {
                        if let Some(at) = rcpt.find('@') {
                            let local = rcpt[..at].to_string();
                            let domain = rcpt[at + 1..].to_string();
                            let mr = PathBuf::from(&mail_root);

                            // determine if this recipient is local (exists in the SQLite DB)
                            let is_local = if let Some(dbp) = db_path.as_ref() {
                                let dbp2 = dbp.clone();
                                let rcpt_clone = rcpt.clone();
                                match tokio::task::spawn_blocking(move || {
                                    rmail_common::db::mailbox_exists(&dbp2, &rcpt_clone)
                                })
                                .await
                                {
                                    Ok(Ok(b)) => b,
                                    _ => false,
                                }
                            } else {
                                false
                            };

                            if is_local {
                                // perform message auth analysis (DKIM/SPF/DMARC) in blocking thread
                                let data_for_analysis = data.clone();
                                let peer_ip_for_analysis = peer.map(|p| p.ip());
                                let mail_from_clone_analysis = mail_from.clone();
                                let (dkim_res, spf_res, dmarc_res, _header_from_res) =
                                    match tokio::task::spawn_blocking(move || {
                                        rmail_common::mail_auth::analyze_message(
                                            &data_for_analysis,
                                            peer_ip_for_analysis,
                                            mail_from_clone_analysis.as_deref(),
                                        )
                                    })
                                    .await
                                    {
                                        Ok(Ok((dkim, spf, dmarc, header_from))) => {
                                            (dkim, spf, dmarc, header_from)
                                        }
                                        Ok(Err(e)) => {
                                            eprintln!("mail auth analyze error: {}", e);
                                            (None, None, None, None)
                                        }
                                        Err(e) => {
                                            eprintln!("mail auth join error: {}", e);
                                            (None, None, None, None)
                                        }
                                    };

                                // Record mail auth metrics
                                if let Some(dk) = dkim_res.as_deref() {
                                    if dk.starts_with("pass") {
                                        rmail_common::metrics::inc_dkim_pass();
                                    } else {
                                        rmail_common::metrics::inc_dkim_fail();
                                    }
                                }
                                if let Some(sf) = spf_res.as_deref() {
                                    if sf == "pass" {
                                        rmail_common::metrics::inc_spf_pass();
                                    } else {
                                        rmail_common::metrics::inc_spf_fail();
                                    }
                                }
                                if let Some(dm) = dmarc_res.as_deref() {
                                    match dm {
                                        "pass" => rmail_common::metrics::inc_dmarc_pass(),
                                        "quarantine" => {
                                            rmail_common::metrics::inc_dmarc_quarantine()
                                        }
                                        "reject" => rmail_common::metrics::inc_dmarc_reject(),
                                        _ => {}
                                    }
                                }

                                // Enforce DMARC if configured: reject when DMARC policy indicates 'reject'
                                if enforce_dmarc && dmarc_res.as_deref() == Some("reject") {
                                    let w = reader.get_mut();
                                    let msg = format!(
                                        "554 5.7.1 Message rejected by DMARC policy for {}\r\n",
                                        rcpt
                                    );
                                    w.write_all(msg.as_bytes()).await?;
                                    w.flush().await?;
                                    any_rejected = true;
                                    continue;
                                }

                                // measure per-recipient delivery latency
                                let start = std::time::Instant::now();
                                // If DMARC recommends quarantine, deliver to quarantine Maildir
                                if scanner_quarantine || dmarc_res.as_deref() == Some("quarantine")
                                {
                                    match maildir::deliver_quarantine(&mr, &domain, &local, &data) {
                                        Ok(path) => {
                                            any_accepted = true;
                                            let elapsed_us = start.elapsed().as_micros() as u64;
                                            // update metrics
                                            rmail_common::metrics::inc_deliveries();
                                            rmail_common::metrics::add_delivered_bytes(
                                                data.len() as u64
                                            );
                                            rmail_common::metrics::observe_delivery_latency_us(
                                                elapsed_us,
                                            );

                                            println!(
                                                "SMTP local quarantine peer={:?} rcpt={} path={:?} bytes={} dmarc={:?}",
                                                peer,
                                                rcpt,
                                                path,
                                                data.len(),
                                                dmarc_res
                                            );
                                            // update simple on-disk metric; failures are non-fatal
                                            if let Err(e) = increment_delivery_counter(&mr).await {
                                                eprintln!("metrics update failed: {}", e);
                                            }
                                        }
                                        Err(e) => {
                                            any_rejected = true;
                                            rmail_common::metrics::inc_failed_deliveries();
                                            eprintln!(
                                                "quarantine deliver error for {}: {}",
                                                rcpt, e
                                            );
                                            let w = reader.get_mut();
                                            w.write_all(b"451 Requested action aborted: local error in processing\r\n").await?;
                                            w.flush().await?;
                                        }
                                    }
                                } else {
                                    match maildir::deliver(&mr, &domain, &local, &data) {
                                        Ok(path) => {
                                            any_accepted = true;
                                            let elapsed_us = start.elapsed().as_micros() as u64;
                                            // update metrics
                                            rmail_common::metrics::inc_deliveries();
                                            rmail_common::metrics::add_delivered_bytes(
                                                data.len() as u64
                                            );
                                            rmail_common::metrics::observe_delivery_latency_us(
                                                elapsed_us,
                                            );

                                            println!(
                                                "SMTP local delivery peer={:?} rcpt={} path={:?} bytes={} dmarc={:?}",
                                                peer,
                                                rcpt,
                                                path,
                                                data.len(),
                                                dmarc_res
                                            );
                                            // update simple on-disk metric; failures are non-fatal
                                            if let Err(e) = increment_delivery_counter(&mr).await {
                                                eprintln!("metrics update failed: {}", e);
                                            }
                                        }
                                        Err(e) => {
                                            any_rejected = true;
                                            rmail_common::metrics::inc_failed_deliveries();
                                            eprintln!("deliver error for {}: {}", rcpt, e);
                                            let w = reader.get_mut();
                                            w.write_all(b"451 Requested action aborted: local error in processing\r\n").await?;
                                            w.flush().await?;
                                        }
                                    }
                                }
                            } else {
                                // queue outbound for remote recipients (requires authentication in RCPT stage)
                                {
                                    // Always use on-disk queueing to avoid SQLite for queues. Use spawn_blocking since filesystem ops are blocking.
                                    let mr2 = mr.clone();
                                    let rcpt_c = rcpt.clone();
                                    let envelope = mail_from.clone();
                                    let data_c = data.clone();
                                    match tokio::task::spawn_blocking(move || {
                                        rmail_common::outbound::queue_outbound(
                                            &mr2,
                                            &rcpt_c,
                                            &data_c,
                                            envelope.as_deref(),
                                        )
                                    })
                                    .await
                                    {
                                        Ok(Ok(path)) => {
                                            any_accepted = true;
                                            println!(
                                                "SMTP outbound queued peer={:?} rcpt={} path={:?} bytes={}",
                                                peer,
                                                rcpt,
                                                path,
                                                data.len()
                                            );
                                        }
                                        Ok(Err(e)) => {
                                            any_rejected = true;
                                            eprintln!("failed to queue outbound {}: {}", rcpt, e);
                                            let w = reader.get_mut();
                                            w.write_all(
                                            b"451 Requested action aborted: temporary failure\r\n",
                                        )
                                        .await?;
                                            w.flush().await?;
                                        }
                                        Err(e) => {
                                            any_rejected = true;
                                            eprintln!("queue spawn_blocking join error: {}", e);
                                            let w = reader.get_mut();
                                            w.write_all(
                                            b"451 Requested action aborted: temporary failure\r\n",
                                        )
                                        .await?;
                                            w.flush().await?;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Finalize DATA response based on per-recipient outcomes
                    let w = reader.get_mut();
                    if any_accepted {
                        println!(
                            "SMTP DATA completed peer={:?} accepted=true rejected={}",
                            peer, any_rejected
                        );
                        w.write_all(b"250 OK\r\n").await?;
                    } else if any_rejected {
                        println!(
                            "SMTP DATA completed peer={:?} accepted=false rejected=true",
                            peer
                        );
                        w.write_all(b"554 5.7.1 Message rejected by policy\r\n")
                            .await?;
                    } else {
                        println!(
                            "SMTP DATA completed peer={:?} accepted=false rejected=false",
                            peer
                        );
                        w.write_all(b"250 OK\r\n").await?;
                    }
                    w.flush().await?;
                    if let Err(e) = rmail_common::metrics::persist_prometheus_snapshot(
                        std::path::Path::new(&mail_root),
                        "smtpd",
                    ) {
                        eprintln!("metrics snapshot update failed: {}", e);
                    }
                }

                // reset transaction state after DATA
                rcpts.clear();
                mail_from = None;
                mail_from_seen = false;
            }
            SmtpCommand::Rset => {
                mail_from = None;
                mail_from_seen = false;
                rcpts.clear();
                let w = reader.get_mut();
                w.write_all(b"250 OK\r\n").await?;
                w.flush().await?;
            }
            SmtpCommand::Noop => {
                let w = reader.get_mut();
                w.write_all(b"250 OK\r\n").await?;
                w.flush().await?;
            }
            SmtpCommand::Vrfy | SmtpCommand::Expn => {
                let w = reader.get_mut();
                w.write_all(b"252 Cannot VRFY user, but will accept message if valid\r\n")
                    .await?;
                w.flush().await?;
            }
            SmtpCommand::Quit => {
                println!("SMTP QUIT peer={:?}", peer);
                let w = reader.get_mut();
                w.write_all(b"221 Bye\r\n").await?;
                w.flush().await?;
                break;
            }
            SmtpCommand::StartTls => {
                println!("SMTP STARTTLS peer={:?}", peer);
                // if we have an acceptor available, perform TLS handshake and continue inside TLS
                if let Some(acceptor_ctx) = tls_ctx {
                    // Signal readiness and pause plain-text protocol processing while the TLS handshake occurs.
                    // After a successful accept, control is transferred to a new process_stream invocation
                    // running over the negotiated TLS stream with session_encrypted=true to indicate
                    // that authentication is permitted and traffic is protected.
                    let w = reader.get_mut();
                    w.write_all(b"220 Ready to start TLS\r\n").await?;
                    w.flush().await?;
                    // take ownership of the underlying stream and perform TLS accept
                    let inner = reader.into_inner();
                    match timeout(
                        STARTTLS_HANDSHAKE_TIMEOUT,
                        acceptor_ctx.acceptor.accept(inner),
                    )
                    .await
                    {
                        Ok(Ok(tls_stream)) => {
                            println!("SMTP STARTTLS handshake success peer={:?}", peer);
                            // Box the TLS stream to the AsyncStream trait object and recurse inside TLS context.
                            let fut = Box::pin(process_stream(
                                Box::new(tls_stream),
                                mail_root,
                                Some(acceptor_ctx.clone()),
                                db_path.clone(),
                                peer,
                                true,
                                enforce_dmarc,
                                false,
                                security.clone(),
                            ));
                            return fut.await;
                        }
                        Ok(Err(e)) => {
                            eprintln!("SMTP STARTTLS handshake failed peer={:?}: {}", peer, e);
                            // We can't continue; return error to close connection
                            return Err(anyhow::anyhow!("TLS accept error: {}", e));
                        }
                        Err(_) => {
                            eprintln!("SMTP STARTTLS handshake timeout peer={:?}", peer);
                            return Err(anyhow::anyhow!("TLS accept timeout"));
                        }
                    }
                } else {
                    let w = reader.get_mut();
                    w.write_all(b"454 TLS not available\r\n").await?;
                    w.flush().await?;
                }
            }
            SmtpCommand::BadSyntax => {
                let w = reader.get_mut();
                w.write_all(b"501 5.5.2 Syntax error in parameters or arguments\r\n")
                    .await?;
                w.flush().await?;
            }
            SmtpCommand::Unknown => {
                eprintln!(
                    "SMTP unknown or unsupported command peer={:?} encrypted={} cmd={:?}",
                    peer, session_encrypted, cmd
                );
                let w = reader.get_mut();
                w.write_all(b"502 Command not implemented\r\n").await?;
                w.flush().await?;
            }
        }
    }
    println!(
        "SMTP session peer={:?} encrypted={} closed",
        peer, session_encrypted
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{MAX_MESSAGE_BYTES, parse_mail_from_arg, process_stream};
    use rmail_common::config::{ScannerFailureAction, SecurityConfig};
    use std::path::Path;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, duplex};
    use tokio::net::UnixListener;

    fn setup_mailbox() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let td = tempfile::tempdir().expect("tempdir");
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
        (td, mail_root, db_path)
    }

    async fn run_session(input: Vec<u8>, capacity: usize) -> (Vec<String>, tempfile::TempDir) {
        run_session_with_security(input, capacity, SecurityConfig::default()).await
    }

    async fn run_session_with_security(
        input: Vec<u8>,
        capacity: usize,
        security: SecurityConfig,
    ) -> (Vec<String>, tempfile::TempDir) {
        let (td, mail_root, db_path) = setup_mailbox();
        let (client, server) = duplex(capacity);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None,
                Some(db_path.to_string_lossy().to_string()),
                None,
                false,
                false,
                true,
                Arc::new(security),
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("greeting");
        assert!(line.starts_with("220 "));
        reader.get_mut().write_all(&input).await.expect("write");
        reader.get_mut().flush().await.expect("flush");

        let mut responses = Vec::new();
        loop {
            let mut resp = String::new();
            reader.read_line(&mut resp).await.expect("read response");
            if resp.is_empty() {
                break;
            }
            let is_bye = resp.starts_with("221 Bye");
            responses.push(resp);
            if is_bye {
                break;
            }
        }
        server_task.await.expect("join").expect("server");
        (responses, td)
    }

    async fn read_clamav_stream<S: AsyncReadExt + Unpin>(stream: &mut S) -> Vec<u8> {
        let mut command = vec![0u8; b"zINSTREAM\0".len()];
        stream.read_exact(&mut command).await.expect("command");
        assert_eq!(command, b"zINSTREAM\0");
        let mut body = Vec::new();
        loop {
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.expect("chunk len");
            let len = u32::from_be_bytes(len_buf) as usize;
            if len == 0 {
                break;
            }
            let start = body.len();
            body.resize(start + len, 0);
            stream.read_exact(&mut body[start..]).await.expect("chunk");
        }
        body
    }

    #[test]
    fn parse_mail_from_accepts_null_sender() {
        assert_eq!(parse_mail_from_arg("MAIL FROM:<>"), Some(None));
    }

    #[test]
    fn parse_mail_from_accepts_normal_address() {
        assert_eq!(
            parse_mail_from_arg("MAIL FROM:<User@Example.com>"),
            Some(Some("user@example.com".to_string()))
        );
    }

    #[tokio::test]
    async fn smtp_data_preserves_non_utf8_bytes() {
        let (responses, td) = run_session(
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: hi\r\n\r\nbinary:\xff\r\n.\r\nQUIT\r\n".to_vec(),
            16 * 1024,
        )
        .await;
        assert!(responses.iter().any(|r| r.starts_with("250 OK")));
        assert!(responses.iter().any(|r| r.starts_with("221 Bye")));

        let delivered_dir = td.path().join("mail/example.test/user/Maildir/new");
        let entries: Vec<_> = std::fs::read_dir(&delivered_dir)
            .expect("read maildir")
            .map(|e| e.expect("entry").path())
            .collect();
        assert_eq!(entries.len(), 1);
        let body = std::fs::read(&entries[0]).expect("read message");
        assert!(
            body.starts_with(b"Received: from localhost ([unknown]) by rMail SMTPD with ESMTP")
        );
        assert!(body.windows(8).any(|w| w == b"binary:\xff"));
        assert!(Path::new(&entries[0]).exists());
    }

    #[tokio::test]
    async fn disabled_scanners_preserve_delivery() {
        let (responses, td) = run_session_with_security(
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: hi\r\n\r\nbody\r\n.\r\nQUIT\r\n".to_vec(),
            16 * 1024,
            SecurityConfig {
                clamav_enabled: false,
                rspamd_enabled: false,
                ..SecurityConfig::default()
            },
        )
        .await;
        assert!(responses.iter().any(|r| r.starts_with("250 OK")));
        let delivered_dir = td.path().join("mail/example.test/user/Maildir/new");
        assert_eq!(
            std::fs::read_dir(delivered_dir).expect("maildir").count(),
            1
        );
    }

    #[tokio::test]
    async fn scanner_size_limit_tempfails_by_default() {
        let (responses, td) = run_session_with_security(
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: hi\r\n\r\nbody\r\n.\r\nQUIT\r\n".to_vec(),
            16 * 1024,
            SecurityConfig {
                rspamd_enabled: true,
                scanner_max_message_bytes: 1,
                ..SecurityConfig::default()
            },
        )
        .await;
        assert!(
            responses
                .iter()
                .any(|r| r.starts_with("451 4.7.1 Message scanner unavailable"))
        );
        let delivered_dir = td.path().join("mail/example.test/user/Maildir/new");
        assert!(!delivered_dir.exists());
    }

    #[tokio::test]
    async fn scanner_size_limit_accept_policy_delivers() {
        let (responses, td) = run_session_with_security(
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: hi\r\n\r\nbody\r\n.\r\nQUIT\r\n".to_vec(),
            16 * 1024,
            SecurityConfig {
                rspamd_enabled: true,
                scanner_max_message_bytes: 1,
                scanner_failure_action: ScannerFailureAction::Accept,
                ..SecurityConfig::default()
            },
        )
        .await;
        assert!(responses.iter().any(|r| r.starts_with("250 OK")));
        let delivered_dir = td.path().join("mail/example.test/user/Maildir/new");
        assert_eq!(
            std::fs::read_dir(delivered_dir).expect("maildir").count(),
            1
        );
    }

    #[tokio::test]
    async fn clamav_infected_rejects_data_and_does_not_deliver() {
        let td = tempfile::tempdir().expect("tempdir");
        let sock = td.path().join("clamd.sock");
        let listener = UnixListener::bind(&sock).expect("bind");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let body = read_clamav_stream(&mut stream).await;
            assert!(body.starts_with(b"Received:"));
            stream
                .write_all(b"stream: Eicar-Test-Signature FOUND\0")
                .await
                .expect("write");
        });
        let (responses, mail_td) = run_session_with_security(
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: hi\r\n\r\nbody\r\n.\r\nQUIT\r\n".to_vec(),
            16 * 1024,
            SecurityConfig {
                clamav_enabled: true,
                clamav_endpoint: format!("unix:{}", sock.display()),
                ..SecurityConfig::default()
            },
        )
        .await;
        assert!(
            responses
                .iter()
                .any(|r| r.starts_with("554 5.7.1 Message rejected: malware detected"))
        );
        let delivered_dir = mail_td.path().join("mail/example.test/user/Maildir/new");
        assert!(!delivered_dir.exists());
        server.await.expect("server");
    }

    #[tokio::test]
    async fn oversized_data_is_drained_before_next_command() {
        let mut input =
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nDATA\r\n".to_vec();
        while input.len() < MAX_MESSAGE_BYTES + 4096 {
            input.extend(std::iter::repeat(b'a').take(900));
            input.extend_from_slice(b"\r\n");
        }
        input.extend_from_slice(b".\r\nQUIT\r\n");
        let (responses, _td) = run_session(input, MAX_MESSAGE_BYTES + 4096).await;
        let oversized = responses
            .iter()
            .filter(|r| r.starts_with("552 5.3.4"))
            .count();
        assert_eq!(oversized, 1);
        assert!(responses.iter().any(|r| r.starts_with("221 Bye")));
    }

    #[tokio::test]
    async fn overlong_data_line_is_drained_before_next_command() {
        let mut input =
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nDATA\r\n".to_vec();
        input.extend(std::iter::repeat(b'a').take(1001));
        input.extend_from_slice(b"\r\nQUIT\r\n.\r\nQUIT\r\n");
        let (responses, _td) = run_session(input, 16 * 1024).await;
        let line_too_long = responses
            .iter()
            .filter(|r| r.starts_with("500 5.5.2"))
            .count();
        assert_eq!(line_too_long, 1);
        assert!(responses.iter().any(|r| r.starts_with("221 Bye")));
    }

    #[tokio::test]
    async fn strict_commands_and_mail_parameters() {
        let (responses, _td) = run_session(
            b"EHLO localhost\r\nDATA junk\r\nQUITzzz\r\nMAIL FROM:<user@example.test> SIZE=42 BODY=8BITMIME SMTPUTF8\r\nQUIT\r\n".to_vec(),
            16 * 1024,
        )
        .await;
        assert_eq!(
            responses
                .iter()
                .filter(|r| r.starts_with("501 5.5.2"))
                .count(),
            2
        );
        assert!(responses.iter().any(|r| r.starts_with("250 OK")));
        assert!(responses.iter().any(|r| r.starts_with("221 Bye")));
    }

    #[tokio::test]
    async fn command_preflight_enforces_greeting_transaction_and_auth_order() {
        let (responses, _td) = run_session(
            b"MAIL FROM:<user@example.test>\r\nSTARTTLS\r\nEHLO localhost\r\nMAIL FROM:<user@example.test>\r\nAUTH PLAIN =\r\nRSET\r\nAUTH PLAIN =\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("503 5.5.1 Send HELO/EHLO first"))
        );
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("503 5.5.1 Send EHLO before STARTTLS"))
        );
        assert!(responses.iter().any(|response| response
            .starts_with("503 5.5.1 AUTH not permitted during a mail transaction")));
        assert!(responses
            .iter()
            .any(|response| response.starts_with("538 5.7.11 Encryption required")));
        assert!(responses.iter().any(|response| response.starts_with("221 Bye")));
    }

    #[tokio::test]
    async fn declared_mail_size_over_limit_is_rejected_before_data() {
        let input = format!(
            "EHLO localhost\r\nMAIL FROM:<user@example.test> SIZE={}\r\nQUIT\r\n",
            MAX_MESSAGE_BYTES + 1
        );
        let (responses, _td) = run_session(input.into_bytes(), 16 * 1024).await;
        assert!(responses.iter().any(|r| r.starts_with("552 5.3.4")));
        assert!(responses.iter().any(|r| r.starts_with("221 Bye")));
    }
}
