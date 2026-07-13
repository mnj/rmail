#![allow(clippy::too_many_arguments)]

use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use std::{collections::HashMap, path::PathBuf, sync::Arc};

use rmail_common::{
    config::{Config, ScannerFailureAction, SecurityConfig},
    maildir, metrics,
    net::bind_tcp_listener,
    scanner::{ScanAction, ScanEnvelope},
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::timeout;

mod authenticate;
mod protocol;
mod tls;
use protocol::{Command as SmtpCommand, parse_command, parse_mail_from_args, parse_rcpt_to_args};
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

const MAX_MESSAGE_BYTES: usize = 10 * 1024 * 1024;
const MAX_DATA_LINE_BYTES: usize = 1000;
const COMMAND_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const AUTH_CONTINUATION_TIMEOUT: Duration = Duration::from_secs(60);
const DATA_READ_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const STARTTLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

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
    if let Some(info) = m.get(&ip)
        && let Some(until) = info.locked_until
    {
        let now = Instant::now();
        if until > now {
            return Some(until - now);
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
    if let Some(ref dbp) = db_path
        && let Err(e) = rmail_common::db::init_db(dbp)
    {
        eprintln!("Failed to initialize database {}: {}", dbp, e);
        std::process::exit(1);
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
    protocol::validate_sasl_mechanisms(&security.smtp_sasl_mechanisms)
        .context("validating security.smtp_sasl_mechanisms")?;

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
    parse_mail_from_args(cmd.strip_prefix("MAIL")?.trim_start())
        .ok()
        .map(|parsed| parsed.sender)
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
    InvalidLineEnding,
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

        if dline.len() > MAX_DATA_LINE_BYTES && failure.is_none() {
            failure = Some(DataReadResult::LineTooLong);
        }
        let valid_line_ending = dline.ends_with(b"\r\n");
        if !valid_line_ending && failure.is_none() {
            failure = Some(DataReadResult::InvalidLineEnding);
        }
        if valid_line_ending {
            dline.truncate(dline.len() - 2);
        } else if dline.ends_with(b"\n") {
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

async fn read_exact_chunk<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    size: usize,
    retain: bool,
) -> Result<Option<Vec<u8>>> {
    let read = async {
        if retain {
            let mut chunk = vec![0; size];
            reader.read_exact(&mut chunk).await?;
            Ok::<_, std::io::Error>(chunk)
        } else {
            let mut remaining = size;
            let mut scratch = [0; 8192];
            while remaining != 0 {
                let take = remaining.min(scratch.len());
                reader.read_exact(&mut scratch[..take]).await?;
                remaining -= take;
            }
            Ok(Vec::new())
        }
    };
    match timeout(DATA_READ_TIMEOUT, read).await {
        Ok(result) => Ok(Some(result?)),
        Err(_) => Ok(None),
    }
}

fn valid_text_message_form(data: &[u8]) -> bool {
    let mut line_len = 0usize;
    let mut index = 0usize;
    while index < data.len() {
        match data[index] {
            b'\r' if data.get(index + 1) == Some(&b'\n') => {
                if line_len + 2 > MAX_DATA_LINE_BYTES {
                    return false;
                }
                line_len = 0;
                index += 2;
            }
            b'\r' | b'\n' | 0 => return false,
            _ => {
                line_len += 1;
                index += 1;
            }
        }
    }
    line_len <= MAX_DATA_LINE_BYTES - 2
}

fn received_header(
    peer: Option<SocketAddr>,
    helo_name: Option<&str>,
    extended_smtp: bool,
    encrypted: bool,
    authenticated: bool,
) -> Vec<u8> {
    let helo = helo_name.unwrap_or("unknown");
    let protocol = if encrypted && authenticated {
        "ESMTPSA"
    } else if encrypted {
        "ESMTPS"
    } else if authenticated {
        "ESMTPA"
    } else if extended_smtp {
        "ESMTP"
    } else {
        "SMTP"
    };
    let timestamp = chrono_like_utc_timestamp();
    match peer {
        Some(peer) => format!(
            "Received: from {helo} ([{}]) by rMail SMTPD with {protocol}; {timestamp}\r\n",
            peer.ip()
        ),
        None => format!("Received: from {helo} by rMail SMTPD with {protocol}; {timestamp}\r\n"),
    }
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
    let mut mail_body = protocol::MailBody::SevenBit;
    let mut smtp_utf8 = false;
    let mut bdat_buffer = Vec::new();
    let mut bdat_started = false;
    // track authenticated identity when AUTH is used (local mailbox address)
    let mut authenticated_user: Option<String> = None;
    let mut helo_name: Option<String> = None;
    let mut extended_smtp = false;

    loop {
        let line = match timeout(
            COMMAND_IDLE_TIMEOUT,
            protocol::read_bounded_line(&mut reader, protocol::MAX_AUTH_LINE_BYTES),
        )
        .await
        {
            Err(_) => {
                let writer = reader.get_mut();
                let _ = writer.write_all(b"421 4.4.2 Timeout\r\n").await;
                let _ = writer.flush().await;
                break;
            }
            Ok(Err(error)) => return Err(error.into()),
            Ok(Ok(protocol::BoundedLine::Eof)) => break,
            Ok(Ok(protocol::BoundedLine::TooLong)) => {
                let writer = reader.get_mut();
                writer.write_all(b"500 5.5.2 Line too long\r\n").await?;
                writer.flush().await?;
                continue;
            }
            Ok(Ok(protocol::BoundedLine::Line(line))) => line,
        };
        if !line.ends_with(b"\r\n") {
            let writer = reader.get_mut();
            writer
                .write_all(b"500 5.5.2 Command line must end with CRLF\r\n")
                .await?;
            writer.flush().await?;
            continue;
        }
        let cmd = match std::str::from_utf8(&line) {
            Ok(line) => line.trim_end_matches(['\r', '\n']),
            Err(_) => {
                let writer = reader.get_mut();
                writer
                    .write_all(b"500 5.5.2 Command is not valid UTF-8\r\n")
                    .await?;
                writer.flush().await?;
                continue;
            }
        };
        if cmd.is_empty() {
            continue;
        }
        let parsed_command = parse_command(cmd);
        if line.len() > protocol::MAX_COMMAND_LINE_BYTES
            && !matches!(parsed_command, SmtpCommand::Auth(_))
        {
            let writer = reader.get_mut();
            writer.write_all(b"500 5.5.2 Line too long\r\n").await?;
            writer.flush().await?;
            continue;
        }
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
                if !protocol::valid_helo_domain(name) {
                    let writer = reader.get_mut();
                    writer
                        .write_all(b"501 5.5.2 Invalid HELO/EHLO domain\r\n")
                        .await?;
                    writer.flush().await?;
                    continue;
                }
                println!(
                    "SMTP greeting peer={:?} verb={}",
                    peer,
                    if is_ehlo { "EHLO" } else { "HELO" }
                );
                helo_name = Some(name.to_string());
                extended_smtp = is_ehlo;
                let mut resp = if is_ehlo {
                    format!("250-rMail Hello {name}\r\n")
                } else {
                    format!("250 2.0.0 rMail Hello {name}\r\n")
                };
                if is_ehlo {
                    if !session_encrypted && tls_ctx.is_some() {
                        resp.push_str("250-STARTTLS\r\n");
                    }
                    if session_encrypted && db_path.is_some() && authenticated_user.is_none() {
                        resp.push_str(&format!(
                            "250-AUTH {}\r\n",
                            protocol::advertised_sasl_mechanisms(&security.smtp_sasl_mechanisms)
                        ));
                    }
                    resp.push_str(&format!("250-SIZE {}\r\n", MAX_MESSAGE_BYTES));
                    resp.push_str("250-8BITMIME\r\n");
                    resp.push_str("250-CHUNKING\r\n");
                    resp.push_str("250-BINARYMIME\r\n");
                    resp.push_str("250-PIPELINING\r\n");
                    resp.push_str("250-SMTPUTF8\r\n");
                    resp.push_str("250 ENHANCEDSTATUSCODES\r\n");
                }
                let w = reader.get_mut();
                w.write_all(resp.as_bytes()).await?;
                w.flush().await?;
                // reset transaction state
                mail_from = None;
                mail_from_seen = false;
                mail_body = protocol::MailBody::SevenBit;
                smtp_utf8 = false;
                bdat_buffer.clear();
                bdat_started = false;
                rcpts.clear();
            }
            SmtpCommand::Auth(auth_args) => {
                let Some(parsed_auth) = protocol::parse_auth_args(auth_args) else {
                    let writer = reader.get_mut();
                    writer
                        .write_all(b"501 5.5.4 Invalid AUTH parameters\r\n")
                        .await?;
                    writer.flush().await?;
                    continue;
                };
                let mech = parsed_auth.mechanism.to_ascii_uppercase();
                let initial = parsed_auth.initial_response;
                println!(
                    "SMTP AUTH attempt peer={:?} encrypted={} mechanism={}",
                    peer, session_encrypted, mech
                );
                if !security
                    .smtp_sasl_mechanisms
                    .iter()
                    .any(|configured| configured.eq_ignore_ascii_case(&mech))
                {
                    let writer = reader.get_mut();
                    writer
                        .write_all(b"504 5.5.4 Unrecognized authentication mechanism\r\n")
                        .await?;
                    writer.flush().await?;
                    continue;
                }
                // Rate-limiting: block repeated failures per remote IP
                if let Some(peer_addr) = peer
                    && let Some(rem) = auth_block_remaining(peer_addr.ip())
                {
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
                // Require encryption (implicit SMTPS or STARTTLS) for authentication in production
                if !session_encrypted {
                    let w = reader.get_mut();
                    w.write_all(b"538 5.7.11 Encryption required for authentication\r\n")
                        .await?;
                    w.flush().await?;
                    continue;
                }
                if matches!(mech.as_str(), "PLAIN" | "LOGIN") {
                    let outcome = authenticate::handle_password(
                        &mut reader,
                        &mech,
                        initial,
                        db_path.as_ref(),
                        peer,
                    )
                    .await;
                    if outcome.disconnected {
                        break;
                    }
                    if let Some(user) = outcome.authenticated_user {
                        println!("SMTP AUTH success peer={peer:?} user={user}");
                        authenticated_user = Some(user);
                    }
                    continue;
                }
                if mech == "SCRAM-SHA-256" {
                    let outcome =
                        authenticate::handle_scram(&mut reader, initial, db_path.as_ref(), peer)
                            .await;
                    if outcome.disconnected {
                        break;
                    }
                    if let Some(user) = outcome.authenticated_user {
                        println!("SMTP AUTH success peer={peer:?} user={user}");
                        authenticated_user = Some(user);
                    }
                    continue;
                }
            }
            SmtpCommand::Mail(mail_args) => {
                // Parse MAIL FROM and set sender; on syntax error return 501
                match parse_mail_from_args(mail_args) {
                    Ok(parsed) => {
                        if !extended_smtp && parsed.has_esmtp_parameters {
                            let writer = reader.get_mut();
                            writer
                                .write_all(b"555 5.5.4 ESMTP parameters require EHLO\r\n")
                                .await?;
                            writer.flush().await?;
                            continue;
                        }
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
                        mail_body = parsed.body;
                        smtp_utf8 = parsed.smtp_utf8;
                        mail_from = parsed.sender;
                        mail_from_seen = true;
                        bdat_buffer.clear();
                        bdat_started = false;
                        println!("SMTP MAIL FROM peer={:?} parsed={:?}", peer, mail_from);
                    }
                    Err(protocol::EnvelopeError::UnsupportedParameter) => {
                        mail_from = None;
                        mail_from_seen = false;
                        let writer = reader.get_mut();
                        writer
                            .write_all(b"555 5.5.4 Unsupported MAIL FROM parameter\r\n")
                            .await?;
                        writer.flush().await?;
                        continue;
                    }
                    Err(protocol::EnvelopeError::Syntax) => {
                        mail_from = None;
                        mail_from_seen = false;
                        println!("SMTP MAIL FROM peer={:?} parse failed", peer);
                    }
                }
                if !mail_from_seen {
                    let w = reader.get_mut();
                    w.write_all(b"501 5.5.2 Syntax: MAIL FROM:<address>\r\n")
                        .await?;
                    w.flush().await?;
                    continue;
                }
                rcpts.clear();
                let w = reader.get_mut();
                w.write_all(b"250 2.1.0 Sender OK\r\n").await?;
                w.flush().await?;
            }
            SmtpCommand::Rcpt(rcpt_args) => {
                // Require MAIL FROM before RCPT TO
                if !mail_from_seen {
                    let w = reader.get_mut();
                    w.write_all(b"503 5.5.1 MAIL required before RCPT\r\n")
                        .await?;
                    w.flush().await?;
                    continue;
                }
                match parse_rcpt_to_args(rcpt_args, smtp_utf8) {
                    Ok(addr) => {
                        println!("SMTP RCPT TO peer={:?} parsed={}", peer, addr);
                        // DB is authoritative — must be configured at startup
                        if let Some(dbp) = db_path.as_ref() {
                            let dbp2 = dbp.clone();
                            let addr2 = addr.clone();
                            match tokio::task::spawn_blocking(move || {
                                if addr2.contains('@') {
                                    rmail_common::db::get_mailbox(dbp2, &addr2)
                                } else {
                                    rmail_common::db::find_mailbox_by_localpart(dbp2, &addr2)
                                }
                            })
                            .await
                            {
                                Ok(Ok(Some(mailbox))) => {
                                    if rcpts.len() >= MAX_RCPT {
                                        let w = reader.get_mut();
                                        w.write_all(b"452 4.5.3 Too many recipients\r\n").await?;
                                        w.flush().await?;
                                    } else {
                                        rcpts.push(mailbox.address.to_ascii_lowercase());
                                        println!(
                                            "SMTP RCPT accepted peer={:?} rcpt_count={} current_rcpts={:?}",
                                            peer,
                                            rcpts.len(),
                                            rcpts
                                        );
                                        let w = reader.get_mut();
                                        w.write_all(b"250 2.1.5 Recipient OK\r\n").await?;
                                        w.flush().await?;
                                    }
                                }
                                Ok(Ok(None)) => {
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
                                                if targets.is_empty() {
                                                    let writer = reader.get_mut();
                                                    writer
                                                        .write_all(
                                                            b"550 5.1.1 Alias has no targets\r\n",
                                                        )
                                                        .await?;
                                                    writer.flush().await?;
                                                } else if rcpts.len().saturating_add(targets.len())
                                                    > MAX_RCPT
                                                {
                                                    let writer = reader.get_mut();
                                                    writer
                                                        .write_all(
                                                            b"452 4.5.3 Too many recipients\r\n",
                                                        )
                                                        .await?;
                                                    writer.flush().await?;
                                                } else {
                                                    rcpts.extend(
                                                        targets.into_iter().map(|target| {
                                                            target.to_ascii_lowercase()
                                                        }),
                                                    );
                                                    let writer = reader.get_mut();
                                                    writer
                                                        .write_all(b"250 2.1.5 Recipient OK\r\n")
                                                        .await?;
                                                    writer.flush().await?;
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
                                                            w.write_all(
                                                                b"452 4.5.3 Too many recipients\r\n",
                                                            )
                                                            .await?;
                                                            w.flush().await?;
                                                        } else {
                                                            rcpts.push(target.clone());
                                                            let w = reader.get_mut();
                                                            w.write_all(
                                                                b"250 2.1.5 Recipient OK\r\n",
                                                            )
                                                            .await?;
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
                                                                    b"452 4.5.3 Too many recipients\r\n",
                                                                )
                                                                .await?;
                                                                w.flush().await?;
                                                            } else {
                                                                rcpts.push(addr.clone());
                                                                let w = reader.get_mut();
                                                                w.write_all(
                                                                    b"250 2.1.5 Recipient OK\r\n",
                                                                )
                                                                .await?;
                                                                w.flush().await?;
                                                            }
                                                        } else {
                                                            let w = reader.get_mut();
                                                            w.write_all(
                                                                b"550 5.1.1 No such user\r\n",
                                                            )
                                                            .await?;
                                                            w.flush().await?;
                                                        }
                                                    }
                                                    Ok(Err(e)) => {
                                                        eprintln!("db get_catchall error: {}", e);
                                                        let w = reader.get_mut();
                                                        w.write_all(
                                                            b"451 4.3.0 Temporary local error\r\n",
                                                        )
                                                        .await?;
                                                        w.flush().await?;
                                                    }
                                                    Err(e) => {
                                                        eprintln!("db task join error: {}", e);
                                                        let w = reader.get_mut();
                                                        w.write_all(
                                                            b"451 4.3.0 Temporary local error\r\n",
                                                        )
                                                        .await?;
                                                        w.flush().await?;
                                                    }
                                                }
                                            }
                                            Ok(Err(e)) => {
                                                eprintln!("db get_alias_targets error: {}", e);
                                                let w = reader.get_mut();
                                                w.write_all(b"451 4.3.0 Temporary local error\r\n")
                                                    .await?;
                                                w.flush().await?;
                                            }
                                            Err(e) => {
                                                eprintln!("db task join error: {}", e);
                                                let w = reader.get_mut();
                                                w.write_all(b"451 4.3.0 Temporary local error\r\n")
                                                    .await?;
                                                w.flush().await?;
                                            }
                                        }
                                    } else {
                                        let w = reader.get_mut();
                                        w.write_all(b"550 5.1.3 Bad destination address\r\n")
                                            .await?;
                                        w.flush().await?;
                                    }
                                }
                                Ok(Err(e)) => {
                                    eprintln!("db mailbox_exists error: {}", e);
                                    let w = reader.get_mut();
                                    w.write_all(b"451 4.3.0 Temporary local error\r\n").await?;
                                    w.flush().await?;
                                }
                                Err(e) => {
                                    eprintln!("db task join error: {}", e);
                                    let w = reader.get_mut();
                                    w.write_all(b"451 4.3.0 Temporary local error\r\n").await?;
                                    w.flush().await?;
                                }
                            }
                        } else {
                            let w = reader.get_mut();
                            w.write_all(b"451 4.3.0 Recipient database unavailable\r\n")
                                .await?;
                            w.flush().await?;
                        }
                    }
                    Err(protocol::EnvelopeError::UnsupportedParameter) => {
                        let writer = reader.get_mut();
                        writer
                            .write_all(b"555 5.5.4 Unsupported RCPT TO parameter\r\n")
                            .await?;
                        writer.flush().await?;
                    }
                    Err(protocol::EnvelopeError::Syntax) => {
                        let writer = reader.get_mut();
                        writer
                            .write_all(b"501 5.5.2 Syntax: RCPT TO:<address>\r\n")
                            .await?;
                        writer.flush().await?;
                    }
                }
            }
            SmtpCommand::Data | SmtpCommand::Bdat(_) => {
                // DATA requires recipients
                if rcpts.is_empty() {
                    let w = reader.get_mut();
                    w.write_all(b"503 5.5.1 RCPT required before DATA\r\n")
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let incoming = match parsed_command {
                    SmtpCommand::Data => {
                        if bdat_started {
                            let writer = reader.get_mut();
                            writer
                                .write_all(b"503 5.5.1 DATA not permitted after BDAT\r\n")
                                .await?;
                            writer.flush().await?;
                            continue;
                        }
                        if mail_body == protocol::MailBody::BinaryMime {
                            let writer = reader.get_mut();
                            writer
                                .write_all(b"503 5.5.1 BODY=BINARYMIME requires BDAT\r\n")
                                .await?;
                            writer.flush().await?;
                            continue;
                        }
                        println!(
                            "SMTP DATA begin peer={peer:?} mail_from={mail_from:?} rcpts={rcpts:?}"
                        );
                        let writer = reader.get_mut();
                        writer
                            .write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                            .await?;
                        writer.flush().await?;
                        read_smtp_data(&mut reader).await?
                    }
                    SmtpCommand::Bdat(args) => {
                        let Some(chunk) = protocol::parse_bdat_args(args) else {
                            let writer = reader.get_mut();
                            writer
                                .write_all(b"501 5.5.2 Syntax: BDAT chunk-size [LAST]\r\n")
                                .await?;
                            writer.flush().await?;
                            continue;
                        };
                        bdat_started = true;
                        let retain = bdat_buffer
                            .len()
                            .checked_add(chunk.size)
                            .is_some_and(|total| total <= MAX_MESSAGE_BYTES);
                        let Some(bytes) = read_exact_chunk(&mut reader, chunk.size, retain).await?
                        else {
                            let writer = reader.get_mut();
                            let _ = writer
                                .write_all(b"421 4.4.2 Timeout while reading BDAT chunk\r\n")
                                .await;
                            let _ = writer.flush().await;
                            break;
                        };
                        if !retain {
                            let writer = reader.get_mut();
                            writer
                                .write_all(b"552 5.3.4 Message size exceeds fixed maximum\r\n")
                                .await?;
                            writer.flush().await?;
                            rcpts.clear();
                            mail_from = None;
                            mail_from_seen = false;
                            bdat_buffer.clear();
                            bdat_started = false;
                            continue;
                        }
                        bdat_buffer.extend_from_slice(&bytes);
                        if !chunk.last {
                            let writer = reader.get_mut();
                            writer
                                .write_all(b"250 2.0.0 BDAT chunk received\r\n")
                                .await?;
                            writer.flush().await?;
                            continue;
                        }
                        DataReadResult::Complete(std::mem::take(&mut bdat_buffer))
                    }
                    _ => unreachable!(),
                };

                let mut data = match incoming {
                    DataReadResult::Complete(mut data) => {
                        if bdat_started
                            && mail_body != protocol::MailBody::BinaryMime
                            && !valid_text_message_form(&data)
                        {
                            let writer = reader.get_mut();
                            writer.write_all(b"554 5.6.0 BDAT content requires canonical CRLF lines or BODY=BINARYMIME\r\n").await?;
                            writer.flush().await?;
                            rcpts.clear();
                            mail_from = None;
                            mail_from_seen = false;
                            bdat_started = false;
                            continue;
                        }
                        if data.contains(&0) && mail_body != protocol::MailBody::BinaryMime {
                            let writer = reader.get_mut();
                            writer
                                .write_all(b"554 5.6.3 NUL requires BINARYMIME\r\n")
                                .await?;
                            writer.flush().await?;
                            rcpts.clear();
                            mail_from = None;
                            mail_from_seen = false;
                            continue;
                        }
                        if mail_body == protocol::MailBody::SevenBit
                            && data.iter().any(|byte| !byte.is_ascii())
                        {
                            let writer = reader.get_mut();
                            writer
                                .write_all(b"554 5.6.3 8-bit content requires BODY=8BITMIME\r\n")
                                .await?;
                            writer.flush().await?;
                            rcpts.clear();
                            mail_from = None;
                            mail_from_seen = false;
                            continue;
                        }
                        let header_end = data
                            .windows(4)
                            .position(|window| window == b"\r\n\r\n")
                            .map_or(data.len(), |position| position + 4);
                        if !smtp_utf8 && data[..header_end].iter().any(|byte| !byte.is_ascii()) {
                            let writer = reader.get_mut();
                            writer
                                .write_all(b"554 5.6.7 UTF-8 headers require SMTPUTF8\r\n")
                                .await?;
                            writer.flush().await?;
                            rcpts.clear();
                            mail_from = None;
                            mail_from_seen = false;
                            continue;
                        }
                        let mut traced = received_header(
                            peer,
                            helo_name.as_deref(),
                            extended_smtp,
                            session_encrypted,
                            authenticated_user.is_some(),
                        );
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
                    DataReadResult::InvalidLineEnding => {
                        let writer = reader.get_mut();
                        writer
                            .write_all(b"554 5.6.0 DATA lines must end with CRLF\r\n")
                            .await?;
                        writer.flush().await?;
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
                    let data_for_analysis = data.clone();
                    let peer_ip_for_analysis = peer.map(|peer| peer.ip());
                    let envelope_for_analysis = mail_from.clone();
                    let (dkim_res, spf_res, dmarc_res, _header_from_res) =
                        match tokio::task::spawn_blocking(move || {
                            rmail_common::mail_auth::analyze_message(
                                &data_for_analysis,
                                peer_ip_for_analysis,
                                envelope_for_analysis.as_deref(),
                            )
                        })
                        .await
                        {
                            Ok(Ok(results)) => results,
                            Ok(Err(error)) => {
                                eprintln!("mail auth analyze error: {error}");
                                (None, None, None, None)
                            }
                            Err(error) => {
                                eprintln!("mail auth join error: {error}");
                                (None, None, None, None)
                            }
                        };
                    if let Some(result) = dkim_res.as_deref() {
                        if result.starts_with("pass") {
                            rmail_common::metrics::inc_dkim_pass();
                        } else {
                            rmail_common::metrics::inc_dkim_fail();
                        }
                    }
                    if let Some(result) = spf_res.as_deref() {
                        if result == "pass" {
                            rmail_common::metrics::inc_spf_pass();
                        } else {
                            rmail_common::metrics::inc_spf_fail();
                        }
                    }
                    if let Some(result) = dmarc_res.as_deref() {
                        match result {
                            "pass" => rmail_common::metrics::inc_dmarc_pass(),
                            "quarantine" => rmail_common::metrics::inc_dmarc_quarantine(),
                            "reject" => rmail_common::metrics::inc_dmarc_reject(),
                            _ => {}
                        }
                    }
                    if enforce_dmarc && dmarc_res.as_deref() == Some("reject") {
                        let writer = reader.get_mut();
                        writer
                            .write_all(b"554 5.7.1 Message rejected by DMARC policy\r\n")
                            .await?;
                        writer.flush().await?;
                        rcpts.clear();
                        mail_from = None;
                        mail_from_seen = false;
                        continue;
                    }
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
                                        }
                                        Err(e) => {
                                            any_rejected = true;
                                            eprintln!("queue spawn_blocking join error: {}", e);
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
                        w.write_all(b"250 2.0.0 Message accepted\r\n").await?;
                    } else if any_rejected {
                        println!(
                            "SMTP DATA completed peer={:?} accepted=false temporary_failure=true",
                            peer
                        );
                        w.write_all(b"451 4.3.0 Temporary delivery failure\r\n")
                            .await?;
                    } else {
                        println!(
                            "SMTP DATA completed peer={:?} accepted=false rejected=false",
                            peer
                        );
                        w.write_all(b"250 2.0.0 Message accepted\r\n").await?;
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
                mail_body = protocol::MailBody::SevenBit;
                smtp_utf8 = false;
                bdat_buffer.clear();
                bdat_started = false;
            }
            SmtpCommand::Rset => {
                mail_from = None;
                mail_from_seen = false;
                mail_body = protocol::MailBody::SevenBit;
                smtp_utf8 = false;
                bdat_buffer.clear();
                bdat_started = false;
                rcpts.clear();
                let w = reader.get_mut();
                w.write_all(b"250 2.0.0 Reset state\r\n").await?;
                w.flush().await?;
            }
            SmtpCommand::Noop => {
                let w = reader.get_mut();
                w.write_all(b"250 2.0.0 OK\r\n").await?;
                w.flush().await?;
            }
            SmtpCommand::Vrfy | SmtpCommand::Expn => {
                let w = reader.get_mut();
                w.write_all(b"252 2.5.2 Cannot VRFY user, but will accept message if valid\r\n")
                    .await?;
                w.flush().await?;
            }
            SmtpCommand::Quit => {
                println!("SMTP QUIT peer={:?}", peer);
                let w = reader.get_mut();
                w.write_all(b"221 2.0.0 Bye\r\n").await?;
                w.flush().await?;
                break;
            }
            SmtpCommand::StartTls => {
                println!("SMTP STARTTLS peer={:?}", peer);
                // if we have an acceptor available, perform TLS handshake and continue inside TLS
                if let Some(acceptor_ctx) = tls_ctx.clone() {
                    if !reader.buffer().is_empty() {
                        let writer = reader.get_mut();
                        writer
                            .write_all(
                                b"554 5.5.1 Client did not wait for STARTTLS reply before sending more data\r\n",
                            )
                            .await?;
                        writer.flush().await?;
                        continue;
                    }
                    // Signal readiness and pause plain-text protocol processing while the TLS handshake occurs.
                    // After a successful accept, control is transferred to a new process_stream invocation
                    // running over the negotiated TLS stream with session_encrypted=true to indicate
                    // that authentication is permitted and traffic is protected.
                    let w = reader.get_mut();
                    w.write_all(b"220 2.0.0 Ready to start TLS\r\n").await?;
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
                    w.write_all(b"454 4.7.0 TLS not available\r\n").await?;
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
                w.write_all(b"500 5.5.2 Command unrecognized\r\n").await?;
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
    use super::{MAX_MESSAGE_BYTES, parse_mail_from_arg, process_stream, received_header};
    use crate::protocol;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
    use rmail_common::config::{ScannerFailureAction, SecurityConfig};
    use std::path::Path;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, duplex};
    use tokio::net::UnixListener;

    async fn read_until<R: tokio::io::AsyncBufRead + Unpin>(
        reader: &mut R,
        needle: &str,
    ) -> String {
        let mut output = String::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read response");
            if line.is_empty() {
                return output;
            }
            output.push_str(&line);
            if line.contains(needle) {
                return output;
            }
        }
    }

    fn scram_client_final(password: &str, client_first_bare: &str, server_first: &str) -> String {
        use hmac::Mac;
        use hmac::digest::KeyInit;
        use pbkdf2::pbkdf2;
        use sha2::{Digest, Sha256};

        type HmacSha256 = hmac::Hmac<Sha256>;
        let attribute = |name: &str| {
            server_first
                .split(',')
                .find_map(|part| part.strip_prefix(name))
                .expect("SCRAM attribute")
        };
        let salt = BASE64_ENGINE.decode(attribute("s=")).expect("salt");
        let iterations = attribute("i=").parse::<u32>().expect("iterations");
        let nonce = attribute("r=");
        let without_proof = format!("c=biws,r={nonce}");
        let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
        let mut salted_password = [0u8; 32];
        pbkdf2::<HmacSha256>(password.as_bytes(), &salt, iterations, &mut salted_password)
            .expect("derive password");
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&salted_password).unwrap();
        mac.update(b"Client Key");
        let client_key = mac.finalize().into_bytes();
        let stored_key = Sha256::digest(client_key);
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&stored_key).unwrap();
        mac.update(auth_message.as_bytes());
        let signature = mac.finalize().into_bytes();
        let proof = client_key
            .iter()
            .zip(signature.iter())
            .map(|(left, right)| left ^ right)
            .collect::<Vec<_>>();
        format!("{without_proof},p={}", BASE64_ENGINE.encode(proof))
    }

    fn setup_mailbox() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        let scram =
            rmail_common::auth::create_scram_verifier("password", 4096).expect("SCRAM verifier");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            Some(&scram),
        )
        .expect("add mailbox");
        rmail_common::db::add_mailbox(
            &db_path,
            "postmaster@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add postmaster mailbox");
        rmail_common::db::add_alias(
            &db_path,
            "team@example.test",
            &["user@example.test", "postmaster@example.test"],
        )
        .expect("add team alias");
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
            let is_bye = resp.starts_with("221 2.0.0 Bye");
            responses.push(resp);
            if is_bye {
                break;
            }
        }
        server_task.await.expect("join").expect("server");
        (responses, td)
    }

    async fn run_encrypted_session(input: Vec<u8>, capacity: usize) -> Vec<String> {
        let (_td, mail_root, db_path) = setup_mailbox();
        let (client, server) = duplex(capacity);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
                false,
                true,
                Arc::new(SecurityConfig::default()),
            )
            .await
        });
        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        reader.get_mut().write_all(&input).await.expect("commands");
        reader.get_mut().flush().await.expect("flush");
        let mut responses = Vec::new();
        loop {
            let mut response = String::new();
            reader.read_line(&mut response).await.expect("response");
            if response.is_empty() {
                break;
            }
            let finished = response.starts_with("221 ");
            responses.push(response);
            if finished {
                break;
            }
        }
        server_task.await.expect("join").expect("server");
        responses
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
            Some(Some("User@example.com".to_string()))
        );
    }

    #[test]
    fn received_trace_identifies_smtp_transport_and_authentication_phase() {
        let smtp =
            String::from_utf8(received_header(None, Some("client"), false, false, false)).unwrap();
        assert!(smtp.contains(" with SMTP;"));
        let submission =
            String::from_utf8(received_header(None, Some("client"), true, true, true)).unwrap();
        assert!(submission.contains(" with ESMTPSA;"));
        assert!(!submission.contains(" id local"));
    }

    #[tokio::test]
    async fn smtp_data_preserves_non_utf8_bytes() {
        let (responses, td) = run_session(
            b"EHLO localhost\r\nMAIL FROM:<> BODY=8BITMIME\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: hi\r\n\r\nbinary:\xff\r\n.\r\nQUIT\r\n".to_vec(),
            16 * 1024,
        )
        .await;
        assert!(responses.iter().any(|r| r.starts_with("250 ")));
        assert!(responses.iter().any(|r| r.starts_with("221 2.0.0 Bye")));

        let delivered_dir = td.path().join("mail/example.test/user/Maildir/new");
        let entries: Vec<_> = std::fs::read_dir(&delivered_dir)
            .expect("read maildir")
            .map(|e| e.expect("entry").path())
            .collect();
        assert_eq!(entries.len(), 1);
        let body = std::fs::read(&entries[0]).expect("read message");
        assert!(body.starts_with(b"Received: from localhost by rMail SMTPD with ESMTP;"));
        assert!(body.windows(8).any(|w| w == b"binary:\xff"));
        assert!(Path::new(&entries[0]).exists());
    }

    #[tokio::test]
    async fn data_enforces_8bitmime_smtputf8_and_binarymime_declarations() {
        let (seven_bit, seven_bit_td) = run_session(
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: hi\r\n\r\nbody:\xff\r\n.\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
        assert!(
            seven_bit
                .iter()
                .any(|response| response.starts_with("554 5.6.3 8-bit content"))
        );
        assert!(
            !seven_bit_td
                .path()
                .join("mail/example.test/user/Maildir/new")
                .exists()
        );

        let (utf8_header, utf8_header_td) = run_session(
            b"EHLO localhost\r\nMAIL FROM:<> BODY=8BITMIME\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: h\xff\r\n\r\nbody\r\n.\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
        assert!(
            utf8_header
                .iter()
                .any(|response| response.starts_with("554 5.6.7 UTF-8 headers"))
        );
        assert!(
            !utf8_header_td
                .path()
                .join("mail/example.test/user/Maildir/new")
                .exists()
        );

        let (binary, binary_td) = run_session(
            b"EHLO localhost\r\nMAIL FROM:<> BODY=8BITMIME SMTPUTF8\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: hi\r\n\r\nbin:\0\r\n.\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
        assert!(
            binary
                .iter()
                .any(|response| response.starts_with("554 5.6.3 NUL requires BINARYMIME"))
        );
        assert!(
            !binary_td
                .path()
                .join("mail/example.test/user/Maildir/new")
                .exists()
        );

        let (accepted, accepted_td) = run_session(
            "EHLO localhost\r\nMAIL FROM:<> BODY=8BITMIME SMTPUTF8\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: héj\r\n\r\nbody: ø\r\n.\r\nQUIT\r\n"
                .as_bytes()
                .to_vec(),
            16 * 1024,
        )
        .await;
        assert!(accepted.iter().any(|response| response.starts_with("250 ")));
        assert_eq!(
            std::fs::read_dir(
                accepted_td
                    .path()
                    .join("mail/example.test/user/Maildir/new")
            )
            .expect("maildir")
            .count(),
            1
        );
    }

    #[tokio::test]
    async fn bdat_accepts_multiple_binary_chunks_and_data_cannot_mix_with_them() {
        let first = b"Subject: binary\r\n\r\npart";
        let second = b"\0two\r\n";
        let mut commands = format!(
            "EHLO localhost\r\nMAIL FROM:<> BODY=BINARYMIME\r\nRCPT TO:<user@example.test>\r\nBDAT {}\r\n",
            first.len()
        )
        .into_bytes();
        commands.extend_from_slice(first);
        commands.extend_from_slice(format!("BDAT {} LAST\r\n", second.len()).as_bytes());
        commands.extend_from_slice(second);
        commands.extend_from_slice(b"QUIT\r\n");

        let (responses, td) = run_session(commands, 16 * 1024).await;
        assert!(
            responses
                .iter()
                .any(|response| response.contains("BDAT chunk received"))
        );
        assert!(
            responses
                .iter()
                .any(|response| response.contains("Message accepted"))
        );
        let delivered_dir = td.path().join("mail/example.test/user/Maildir/new");
        let path = std::fs::read_dir(delivered_dir)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let delivered = std::fs::read(path).unwrap();
        assert!(
            delivered.windows(first.len() + second.len()).any(|window| {
                window == [first.as_slice(), second.as_slice()].concat().as_slice()
            })
        );

        let (mixed, _) = run_session(
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nBDAT 0\r\nDATA\r\nRSET\r\nQUIT\r\n".to_vec(),
            16 * 1024,
        )
        .await;
        assert!(
            mixed
                .iter()
                .any(|response| response.contains("DATA not permitted after BDAT"))
        );
    }

    #[tokio::test]
    async fn envelope_extensions_return_501_for_syntax_and_555_for_unsupported_parameters() {
        let (responses, _td) = run_session(
            b"HELO localhost\r\nMAIL FROM:<a@example.test> SIZE=1\r\nEHLO localhost\r\nMAIL FROM:<a@example.test> RET=FULL\r\nMAIL FROM:<a..b@example.test>\r\nMAIL FROM:<a@example.test>\r\nRCPT TO:<user@example.test> NOTIFY=SUCCESS\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("555 5.5.4 ESMTP parameters require EHLO"))
        );
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("555 5.5.4 Unsupported MAIL FROM parameter"))
        );
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("501 5.5.2 Syntax: MAIL FROM"))
        );
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("555 5.5.4 Unsupported RCPT TO parameter"))
        );
    }

    #[tokio::test]
    async fn bare_postmaster_forward_path_resolves_to_local_postmaster_mailbox() {
        let (responses, td) = run_session(
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<Postmaster>\r\nDATA\r\nSubject: postmaster\r\n\r\nmessage\r\n.\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("250 "))
        );
        assert_eq!(
            std::fs::read_dir(td.path().join("mail/example.test/postmaster/Maildir/new"))
                .expect("postmaster maildir")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn multi_target_alias_emits_one_rcpt_reply_and_delivers_atomically() {
        let (responses, td) = run_session(
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<team@example.test>\r\nDATA\r\nSubject: team\r\n\r\nmessage\r\n.\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
        for expected in [
            "250 2.1.0 Sender OK",
            "250 2.1.5 Recipient OK",
            "250 2.0.0 Message accepted",
        ] {
            assert_eq!(
                responses
                    .iter()
                    .filter(|response| response.starts_with(expected))
                    .count(),
                1,
                "{expected}"
            );
        }
        for localpart in ["user", "postmaster"] {
            assert_eq!(
                std::fs::read_dir(
                    td.path()
                        .join(format!("mail/example.test/{localpart}/Maildir/new"))
                )
                .expect("alias target maildir")
                .count(),
                1
            );
        }
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
        assert!(responses.iter().any(|r| r.starts_with("250 ")));
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
        assert!(responses.iter().any(|r| r.starts_with("250 ")));
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
            input.extend(std::iter::repeat_n(b'a', 900));
            input.extend_from_slice(b"\r\n");
        }
        input.extend_from_slice(b".\r\nQUIT\r\n");
        let (responses, _td) = run_session(input, MAX_MESSAGE_BYTES + 4096).await;
        let oversized = responses
            .iter()
            .filter(|r| r.starts_with("552 5.3.4"))
            .count();
        assert_eq!(oversized, 1);
        assert!(responses.iter().any(|r| r.starts_with("221 2.0.0 Bye")));
    }

    #[tokio::test]
    async fn overlong_data_line_is_drained_before_next_command() {
        let mut input =
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nDATA\r\n".to_vec();
        input.extend(std::iter::repeat_n(b'a', 1001));
        input.extend_from_slice(b"\r\nQUIT\r\n.\r\nQUIT\r\n");
        let (responses, _td) = run_session(input, 16 * 1024).await;
        let line_too_long = responses
            .iter()
            .filter(|r| r.starts_with("500 5.5.2"))
            .count();
        assert_eq!(line_too_long, 1);
        assert!(responses.iter().any(|r| r.starts_with("221 2.0.0 Bye")));
    }

    #[tokio::test]
    async fn bare_lf_data_is_drained_and_rejected_without_command_desynchronization() {
        let input = b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<user@example.test>\r\nDATA\r\nSubject: bad\n\nbody\n.\nQUIT\r\n"
            .to_vec();
        let (responses, td) = run_session(input, 16 * 1024).await;
        assert_eq!(
            responses
                .iter()
                .filter(|response| response.starts_with("554 5.6.0"))
                .count(),
            1
        );
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("221 2.0.0 Bye"))
        );
        assert!(
            !td.path()
                .join("mail/example.test/user/Maildir/new")
                .exists()
        );
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
            1
        );
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("500 5.5.2 Command unrecognized"))
        );
        assert!(responses.iter().any(|r| r.starts_with("250 ")));
        assert!(responses.iter().any(|r| r.starts_with("221 2.0.0 Bye")));
    }

    #[tokio::test]
    async fn advertised_enhanced_status_codes_are_used_for_command_replies() {
        let (responses, _td) = run_session(
            b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<missing@example.test>\r\nRSET\r\nVRFY user@example.test\r\nNOOP\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
        assert!(
            responses
                .iter()
                .any(|response| response == "250 ENHANCEDSTATUSCODES\r\n")
        );
        for response in responses.iter().filter(|response| {
            !response.starts_with("250-") && response.as_str() != "250 ENHANCEDSTATUSCODES\r\n"
        }) {
            let status = response.split_ascii_whitespace().nth(1).unwrap_or_default();
            let components = status.split('.').collect::<Vec<_>>();
            assert_eq!(components.len(), 3, "{response:?}");
            assert!(
                components.iter().all(|component| !component.is_empty()
                    && component.bytes().all(|byte| byte.is_ascii_digit())),
                "{response:?}"
            );
        }
    }

    #[tokio::test]
    async fn bare_lf_command_is_rejected_without_losing_following_crlf_commands() {
        let (responses, _td) = run_session(
            b"EHLO localhost\nEHLO localhost\r\nNOOP\r\nQUIT\r\n".to_vec(),
            16 * 1024,
        )
        .await;
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("500 5.5.2 Command line must end with CRLF"))
        );
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("250-rMail Hello"))
        );
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("250 "))
        );
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("221 2.0.0 Bye"))
        );
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
        assert!(responses.iter().any(|response| {
            response.starts_with("503 5.5.1 AUTH not permitted during a mail transaction")
        }));
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("538 5.7.11 Encryption required"))
        );
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("221 2.0.0 Bye"))
        );
    }

    #[tokio::test]
    async fn starttls_rejects_pipelined_plaintext_without_losing_commands() {
        let (td, mail_root, db_path) = setup_mailbox();
        let server_config = tokio_rustls::rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(
                tokio_rustls::rustls::server::ResolvesServerCertUsingSni::new(),
            ));
        let tls_context = Arc::new(super::tls::TlsContext {
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(server_config)),
        });
        let (client, server) = duplex(16 * 1024);
        let server_task = tokio::spawn(process_stream(
            Box::new(server),
            mail_root.to_string_lossy().to_string(),
            Some(tls_context),
            Some(db_path.to_string_lossy().to_string()),
            None,
            false,
            false,
            true,
            Arc::new(SecurityConfig::default()),
        ));
        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        reader
            .get_mut()
            .write_all(b"EHLO localhost\r\nSTARTTLS\r\nNOOP\r\nQUIT\r\n")
            .await
            .expect("commands");
        reader.get_mut().flush().await.expect("flush");
        let ehlo = read_until(&mut reader, "250 ENHANCEDSTATUSCODES").await;
        assert!(ehlo.contains("STARTTLS"));
        let rejection = read_until(&mut reader, "554 5.5.1").await;
        assert!(rejection.contains("did not wait for STARTTLS reply"));
        assert!(
            read_until(&mut reader, "250 2.0.0")
                .await
                .contains("250 2.0.0")
        );
        assert!(
            read_until(&mut reader, "221 2.0.0 Bye")
                .await
                .contains("221 2.0.0 Bye")
        );
        server_task.await.expect("join").expect("server");
        drop(td);
    }

    #[tokio::test]
    async fn starttls_completes_real_handshake_and_requires_fresh_ehlo() {
        use std::io::Cursor;
        use std::time::SystemTime;
        use tokio_rustls::TlsConnector;
        use tokio_rustls::rustls::client::{ServerCertVerified, ServerCertVerifier};
        use tokio_rustls::rustls::{
            Certificate, ClientConfig, Error as TlsError, RootCertStore, ServerName,
        };

        struct PinnedCertificate(Vec<u8>);
        impl ServerCertVerifier for PinnedCertificate {
            fn verify_server_cert(
                &self,
                end_entity: &Certificate,
                _intermediates: &[Certificate],
                _server_name: &ServerName,
                _scts: &mut dyn Iterator<Item = &[u8]>,
                _ocsp_response: &[u8],
                _now: SystemTime,
            ) -> Result<ServerCertVerified, TlsError> {
                if end_entity.0 == self.0 {
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(TlsError::General(
                        "STARTTLS test received unexpected certificate".to_string(),
                    ))
                }
            }
        }

        let (_td, mail_root, db_path) = setup_mailbox();
        let cert_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/certs/localhost.crt"
        );
        let key_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/certs/localhost.key"
        );
        let tls_context = super::tls::load_tls_context(cert_path, key_path).expect("TLS context");
        let certificate_pem = std::fs::read(cert_path).expect("certificate");
        let certificates =
            rustls_pemfile::certs(&mut Cursor::new(certificate_pem)).expect("parse certificate");
        let mut client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        client_config
            .dangerous()
            .set_certificate_verifier(Arc::new(PinnedCertificate(certificates[0].clone())));

        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(process_stream(
            Box::new(server),
            mail_root.to_string_lossy().to_string(),
            Some(tls_context),
            Some(db_path.to_string_lossy().to_string()),
            None,
            false,
            false,
            true,
            Arc::new(SecurityConfig::default()),
        ));
        let mut plaintext = BufReader::new(client);
        let mut greeting = String::new();
        plaintext.read_line(&mut greeting).await.expect("greeting");
        plaintext
            .get_mut()
            .write_all(b"EHLO localhost\r\n")
            .await
            .expect("EHLO");
        plaintext.get_mut().flush().await.expect("flush");
        assert!(
            read_until(&mut plaintext, "250 ENHANCEDSTATUSCODES")
                .await
                .contains("STARTTLS")
        );
        plaintext
            .get_mut()
            .write_all(b"STARTTLS\r\n")
            .await
            .expect("STARTTLS");
        plaintext.get_mut().flush().await.expect("flush");
        let mut ready = String::new();
        plaintext.read_line(&mut ready).await.expect("ready");
        assert_eq!(ready, "220 2.0.0 Ready to start TLS\r\n");

        let connector = TlsConnector::from(Arc::new(client_config));
        let tls_stream = connector
            .connect(
                ServerName::try_from("localhost").expect("server name"),
                plaintext.into_inner(),
            )
            .await
            .expect("TLS handshake");
        let mut encrypted = BufReader::new(tls_stream);
        encrypted
            .get_mut()
            .write_all(b"AUTH PLAIN =\r\nEHLO localhost\r\nQUIT\r\n")
            .await
            .expect("post-TLS commands");
        encrypted.get_mut().flush().await.expect("flush");
        assert!(
            read_until(&mut encrypted, "503 5.5.1")
                .await
                .contains("Send EHLO before AUTH")
        );
        let capabilities = read_until(&mut encrypted, "250 ENHANCEDSTATUSCODES").await;
        assert!(capabilities.contains("AUTH PLAIN LOGIN SCRAM-SHA-256"));
        assert!(!capabilities.contains("STARTTLS"));
        assert!(
            read_until(&mut encrypted, "221 2.0.0 Bye")
                .await
                .contains("221 2.0.0 Bye")
        );
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn auth_plain_and_login_use_shared_bounded_exchange_handler() {
        let plain = run_encrypted_session(
            b"EHLO localhost\r\nAUTH PLAIN AHVzZXJAZXhhbXBsZS50ZXN0AHBhc3N3b3Jk\r\nAUTH PLAIN AHVzZXJAZXhhbXBsZS50ZXN0AHBhc3N3b3Jk\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
        assert!(
            plain
                .iter()
                .any(|response| response.starts_with("235 2.7.0"))
        );
        assert!(
            plain
                .iter()
                .any(|response| response.starts_with("503 5.5.0 Already authenticated"))
        );

        let login = run_encrypted_session(
            b"EHLO localhost\r\nAUTH LOGIN\r\ndXNlckBleGFtcGxlLnRlc3Q=\r\ncGFzc3dvcmQ=\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
        assert!(
            login
                .iter()
                .any(|response| response == "334 VXNlcm5hbWU6\r\n")
        );
        assert!(
            login
                .iter()
                .any(|response| response == "334 UGFzc3dvcmQ6\r\n")
        );
        assert!(
            login
                .iter()
                .any(|response| response.starts_with("235 2.7.0"))
        );
    }

    #[tokio::test]
    async fn auth_scram_sha256_verifies_a_real_client_proof() {
        let (_td, mail_root, db_path) = setup_mailbox();
        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(process_stream(
            Box::new(server),
            mail_root.to_string_lossy().to_string(),
            None,
            Some(db_path.to_string_lossy().to_string()),
            None,
            true,
            false,
            true,
            Arc::new(SecurityConfig::default()),
        ));
        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        reader
            .get_mut()
            .write_all(b"EHLO localhost\r\n")
            .await
            .expect("EHLO");
        reader.get_mut().flush().await.expect("flush");
        assert!(
            read_until(&mut reader, "250 ENHANCEDSTATUSCODES")
                .await
                .contains("AUTH")
        );

        let bare = "n=user@example.test,r=clientnonce";
        let first = BASE64_ENGINE.encode(format!("n,,{bare}"));
        reader
            .get_mut()
            .write_all(format!("AUTH SCRAM-SHA-256 {first}\r\n").as_bytes())
            .await
            .expect("AUTH");
        reader.get_mut().flush().await.expect("flush");
        let mut challenge = String::new();
        reader
            .read_line(&mut challenge)
            .await
            .expect("server first");
        assert!(challenge.starts_with("334 "), "{challenge:?}");
        let server_first = String::from_utf8(
            BASE64_ENGINE
                .decode(challenge.trim().strip_prefix("334 ").unwrap())
                .expect("decode server first"),
        )
        .expect("UTF-8 server first");
        let final_message = scram_client_final("password", bare, &server_first);
        reader
            .get_mut()
            .write_all(format!("{}\r\n", BASE64_ENGINE.encode(final_message)).as_bytes())
            .await
            .expect("client final");
        reader.get_mut().flush().await.expect("flush");
        let mut success = String::new();
        reader.read_line(&mut success).await.expect("AUTH success");
        assert!(success.starts_with("235 2.7.0 "));
        let server_final = success
            .trim()
            .strip_prefix("235 2.7.0 ")
            .expect("server final");
        assert!(
            String::from_utf8(BASE64_ENGINE.decode(server_final).unwrap())
                .unwrap()
                .starts_with("v=")
        );
        reader.get_mut().write_all(b"QUIT\r\n").await.expect("QUIT");
        reader.get_mut().flush().await.expect("flush");
        assert!(
            read_until(&mut reader, "221 2.0.0 Bye")
                .await
                .contains("221 2.0.0 Bye")
        );
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn auth_cancellation_and_invalid_parameters_preserve_command_stream() {
        let responses = run_encrypted_session(
            b"EHLO localhost\r\nAUTH LOGIN extra extra\r\nAUTH LOGIN\r\n*\r\nNOOP\r\nQUIT\r\n"
                .to_vec(),
            16 * 1024,
        )
        .await;
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("501 5.5.4 Invalid AUTH parameters"))
        );
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("501 5.7.0 Authentication canceled"))
        );
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("250 "))
        );
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("221 "))
        );
    }

    #[tokio::test]
    async fn overlong_auth_continuation_is_drained_before_next_command() {
        let mut input = b"EHLO localhost\r\nAUTH LOGIN\r\n".to_vec();
        input.extend(std::iter::repeat_n(b'A', protocol::MAX_AUTH_LINE_BYTES + 1));
        input.extend_from_slice(b"\r\nNOOP\r\nQUIT\r\n");
        let responses = run_encrypted_session(input, 32 * 1024).await;
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("500 5.5.2 AUTH response line too long"))
        );
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("250 "))
        );
        assert!(
            responses
                .iter()
                .any(|response| response.starts_with("221 "))
        );
    }

    #[tokio::test]
    async fn declared_mail_size_over_limit_is_rejected_before_data() {
        let input = format!(
            "EHLO localhost\r\nMAIL FROM:<user@example.test> SIZE={}\r\nQUIT\r\n",
            MAX_MESSAGE_BYTES + 1
        );
        let (responses, _td) = run_session(input.into_bytes(), 16 * 1024).await;
        assert!(responses.iter().any(|r| r.starts_with("552 5.3.4")));
        assert!(responses.iter().any(|r| r.starts_with("221 2.0.0 Bye")));
    }
}
