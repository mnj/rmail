use anyhow::{Context, Result};
use std::{collections::{HashMap, HashSet}, path::PathBuf, sync::Arc};

use rmail_common::{config::Config, maildir, metrics, auth, db};
use base64;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

mod tls;
use tls::load_tls_acceptor;
use tokio_rustls::TlsAcceptor;

// Trait object helper: combine AsyncRead + AsyncWrite into a single object-safe trait and require Unpin
// so that boxed trait objects can be used with tokio::io::BufReader.
trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized> AsyncStream for T {}

/// Increment an on-disk counter for delivered messages. Uses an atomic write via a temporary file
/// so that concurrent processes won't corrupt the counter file. This is intentionally simple and
/// avoids pulling in heavier metrics crates — it's a lightweight local metric for the Web UI.
async fn increment_delivery_counter() -> Result<()> {
    let path = std::path::Path::new("/tmp/rmail_delivered.count");
    let mut count: u64 = 0;
    if let Ok(s) = tokio::fs::read_to_string(path).await {
        count = s.trim().parse::<u64>().unwrap_or(0);
    }
    count = count.saturating_add(1);
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, count.to_string()).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}


#[tokio::main]
async fn main() -> Result<()> { 
    // load config (example path)
    let cfg_path = std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let cfg = Config::from_file(&cfg_path).context(format!("loading {}", cfg_path))?;

    let mail_root = cfg.global.mail_root.clone();
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

    // build TLS acceptor if certificate paths present
    let tls_acceptor = if let (Some(cert), Some(key)) = (&cfg.global.tls_cert, &cfg.global.tls_key) {
        match load_tls_acceptor(cert, key) {
            Ok(a) => Some(Arc::new(a)),
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

    // spawn plain SMTP listeners
    for addr in listen_addrs.iter() {
        let addr = addr.clone();
        let mail_root_clone = mail_root.clone();
        let acceptor_clone = tls_acceptor.clone();
        let db_clone = db_path.clone();
        tokio::spawn(async move {
            if let Err(e) = run_plain_listener(&addr, mail_root_clone, acceptor_clone, db_clone).await {
                eprintln!("Listener {} failed: {}", addr, e);
            }
        });
    }

    // spawn SMTPS listener (implicit TLS) if configured
    if let Some(s_acceptor) = tls_acceptor.clone() {
        if let Some(port) = cfg.global.smtps_port {
            let addr_v4 = format!("0.0.0.0:{}", port);
            let addr_v6 = format!("[::]:{}", port);

            // v4 listener
            let mail_root_v4 = mail_root.clone();
            let acceptor_v4 = s_acceptor.clone();
            let db_v4 = db_path.clone();
            tokio::spawn(async move {
                if let Err(e) = run_smtps_listener(&addr_v4, acceptor_v4, mail_root_v4, db_v4).await {
                    eprintln!("SMTPS {} failed: {}", addr_v4, e);
                }
            });

            // v6 listener
            let mail_root_v6 = mail_root.clone();
            let acceptor_v6 = s_acceptor.clone();
            let db_v6 = db_path.clone();
            tokio::spawn(async move {
                if let Err(e) = run_smtps_listener(&addr_v6, acceptor_v6, mail_root_v6, db_v6).await {
                    eprintln!("SMTPS {} failed: {}", addr_v6, e);
                }
            });
        }
    } else {
        println!("TLS not configured; SMTPS disabled (implicit TLS)");
    }

    // keep running
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

async fn run_plain_listener(addr: &str, mail_root: String, tls_acceptor: Option<Arc<TlsAcceptor>>, db_path: Option<String>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("rMail SMTPD listening on {}", addr);
    loop {
        let (stream, _peer) = listener.accept().await?;
        let mail_root = mail_root.clone();
        let acceptor = tls_acceptor.clone();
        let db_clone = db_path.clone();
        tokio::spawn(async move {
            if let Err(e) = process_stream(Box::new(stream), mail_root, acceptor, db_clone).await {
                eprintln!("client error: {}", e);
            }
        });
    }
}

async fn run_smtps_listener(addr: &str, acceptor: Arc<TlsAcceptor>, mail_root: String, db_path: Option<String>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("rMail SMTPS listening on {}", addr);
    loop {
        let (stream, _peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let mail_root = mail_root.clone();
        let db_clone = db_path.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(e) = process_stream(Box::new(tls_stream), mail_root, None, db_clone).await {
                        eprintln!("tls client error: {}", e);
                    }
                }
                Err(e) => eprintln!("TLS accept error: {}", e),
            }
        });
    }
}

// function to extract address
fn extract_addr(s: &str) -> Option<String> {
    let s = s.trim();
    let s = s.trim_matches(|c| c == '<' || c == '>' || c == ' ');
    if s.contains('@') {
        Some(s.to_ascii_lowercase())
    } else {
        None
    }
}

async fn process_stream(stream: Box<dyn AsyncStream + Send + 'static>, mail_root: String, tls_acceptor: Option<Arc<TlsAcceptor>>, db_path: Option<String>) -> Result<()> {
    // Limits to protect against malformed or malicious clients
    // - MAX_LINE_LEN: per-line limit (RFC 5321 recommends 1000 octets including CRLF)
    // - MAX_MESSAGE_BYTES: overall DATA size cap to avoid OOM
    const MAX_LINE_LEN: usize = 1000;
    const MAX_MESSAGE_BYTES: usize = 10 * 1024 * 1024; // 10 MiB

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    {
        let w = reader.get_mut();
        w.write_all(b"220 rMail SMTPD ready\r\n").await?;
        w.flush().await?;
    }

    // SMTP transaction state
    const MAX_RCPT: usize = 100; // limit recipients per transaction to mitigate abuse
    let mut rcpts: Vec<String> = Vec::new();
    let mut mail_from: Option<String> = None;
    // track authenticated identity when AUTH is used (local mailbox address)
    let mut authenticated_user: Option<String> = None;

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 { break; }

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
        if cmd.is_empty() { continue; }
        let up = cmd.to_ascii_uppercase();

        // Simple command parsing; robust parsers can be added later.
        if up.starts_with("HELO") || up.starts_with("EHLO") {
            // Respond with basic capability. If TLS is available advertise STARTTLS.
            let mut resp = String::from("250-Hello\r\n");
            if tls_acceptor.is_some() {
                resp.push_str("250-STARTTLS\r\n");
            }
            // advertise AUTH mechanisms if DB is configured (we support AUTH PLAIN and LOGIN)
            if db_path.is_some() {
                resp.push_str("250-AUTH PLAIN LOGIN\r\n");
            }
            resp.push_str("250 OK\r\n");
            let w = reader.get_mut();
            w.write_all(resp.as_bytes()).await?;
            w.flush().await?;
            // reset transaction state
            mail_from = None;
            rcpts.clear();
        } else if cmd.trim_start().to_ascii_uppercase().starts_with("AUTH") {
            // Simple AUTH implementation supporting PLAIN and LOGIN (only allowed over TLS in production)
            let parts: Vec<&str> = cmd.trim().splitn(3, ' ').collect();
            let mech = parts.get(1).map(|s| s.to_ascii_uppercase()).unwrap_or_default();
            let initial = parts.get(2).map(|s| *s);
            if mech == "PLAIN" {
                if let Some(b64) = initial {
                    match base64::decode(b64) {
                        Ok(bytes) => {
                            // PLAIN: [authz] NUL authcid NUL password
                            let splits: Vec<&[u8]> = bytes.split(|b| *b == 0).collect();
                            let (authcid, password) = if splits.len() >= 3 {
                                (String::from_utf8_lossy(splits[1]).to_string(), String::from_utf8_lossy(splits[2]).to_string())
                            } else if splits.len() == 2 {
                                (String::from_utf8_lossy(splits[0]).to_string(), String::from_utf8_lossy(splits[1]).to_string())
                            } else {
                                ("".to_string(), "".to_string())
                            };
                            if let Some(dbp) = db_path.as_ref() {
                                let dbp2 = dbp.clone();
                                let user_lower = authcid.to_ascii_lowercase();
                                match tokio::task::spawn_blocking(move || rmail_common::db::get_mailbox(&dbp2, &user_lower)).await {
                                    Ok(Ok(Some(mb))) => {
                                        if let Some(pw_hash) = mb.password_hash {
                                            match rmail_common::auth::verify_password(&password, &pw_hash) {
                                                Ok(true) => {
                                                    authenticated_user = Some(mb.address.to_ascii_lowercase());
                                                    let w = reader.get_mut();
                                                    w.write_all(b"235 Authentication succeeded\r\n").await?;
                                                    w.flush().await?;
                                                }
                                                Ok(false) => { let w = reader.get_mut(); w.write_all(b"535 Authentication failed\r\n").await?; w.flush().await?; }
                                                Err(e) => { eprintln!("auth verify error: {}", e); let w = reader.get_mut(); w.write_all(b"451 Temporary error\r\n").await?; w.flush().await?; }
                                            }
                                        } else {
                                            let w = reader.get_mut();
                                            w.write_all(b"535 No password set\r\n").await?;
                                            w.flush().await?;
                                        }
                                    }
                                    Ok(Ok(None)) => { let w = reader.get_mut(); w.write_all(b"535 No such user\r\n").await?; w.flush().await?; }
                                    Ok(Err(e)) => { eprintln!("db error: {}", e); let w = reader.get_mut(); w.write_all(b"451 Temporary error\r\n").await?; w.flush().await?; }
                                    Err(e) => { eprintln!("db task join error: {}", e); let w = reader.get_mut(); w.write_all(b"451 Temporary error\r\n").await?; w.flush().await?; }
                                }
                            } else {
                                let w = reader.get_mut();
                                w.write_all(b"454 TLS not available\r\n").await?;
                                w.flush().await?;
                            }
                        }
                        Err(_) => { let w = reader.get_mut(); w.write_all(b"501 Invalid base64\r\n").await?; w.flush().await?; }
                    }
                } else {
                    // challenge-response not fully implemented: ask for credentials
                    let w = reader.get_mut();
                    w.write_all(b"334 \r\n").await?;
                    w.flush().await?;
                    let mut resp_line = String::new();
                    reader.read_line(&mut resp_line).await?;
                    let b64 = resp_line.trim();
                    match base64::decode(b64) {
                        Ok(bytes) => {
                            let splits: Vec<&[u8]> = bytes.split(|b| *b == 0).collect();
                            let (authcid, password) = if splits.len() >= 3 {
                                (String::from_utf8_lossy(splits[1]).to_string(), String::from_utf8_lossy(splits[2]).to_string())
                            } else if splits.len() == 2 {
                                (String::from_utf8_lossy(splits[0]).to_string(), String::from_utf8_lossy(splits[1]).to_string())
                            } else {
                                ("".to_string(), "".to_string())
                            };
                            if let Some(dbp) = db_path.as_ref() {
                                let dbp2 = dbp.clone();
                                let user_lower = authcid.to_ascii_lowercase();
                                match tokio::task::spawn_blocking(move || rmail_common::db::get_mailbox(&dbp2, &user_lower)).await {
                                    Ok(Ok(Some(mb))) => {
                                        if let Some(pw_hash) = mb.password_hash {
                                            match rmail_common::auth::verify_password(&password, &pw_hash) {
                                                Ok(true) => {
                                                    authenticated_user = Some(mb.address.to_ascii_lowercase());
                                                    let w = reader.get_mut();
                                                    w.write_all(b"235 Authentication succeeded\r\n").await?;
                                                    w.flush().await?;
                                                }
                                                Ok(false) => { let w = reader.get_mut(); w.write_all(b"535 Authentication failed\r\n").await?; w.flush().await?; }
                                                Err(e) => { eprintln!("auth verify error: {}", e); let w = reader.get_mut(); w.write_all(b"451 Temporary error\r\n").await?; w.flush().await?; }
                                            }
                                        } else { let w = reader.get_mut(); w.write_all(b"535 No password set\r\n").await?; w.flush().await?; }
                                    }
                                    Ok(Ok(None)) => { let w = reader.get_mut(); w.write_all(b"535 No such user\r\n").await?; w.flush().await?; }
                                    Ok(Err(e)) => { eprintln!("db error: {}", e); let w = reader.get_mut(); w.write_all(b"451 Temporary error\r\n").await?; w.flush().await?; }
                                    Err(e) => { eprintln!("db task join error: {}", e); let w = reader.get_mut(); w.write_all(b"451 Temporary error\r\n").await?; w.flush().await?; }
                                }
                            } else { let w = reader.get_mut(); w.write_all(b"454 TLS not available\r\n").await?; w.flush().await?; }
                        }
                        Err(_) => { let w = reader.get_mut(); w.write_all(b"501 Invalid base64\r\n").await?; w.flush().await?; }
                    }
                }
            } else if mech == "LOGIN" {
                // LOGIN: two step username/password base64 prompts
                if let Some(b64u) = initial {
                    match base64::decode(b64u) {
                        Ok(u_bytes) => {
                            let username = String::from_utf8_lossy(&u_bytes).to_string();
                            let w = reader.get_mut();
                            w.write_all(b"334 UGFzc3dvcmQ6\r\n").await?; // "Password:" in base64
                            w.flush().await?;
                            let mut pass_line = String::new();
                            reader.read_line(&mut pass_line).await?;
                            let b64p = pass_line.trim();
                            match base64::decode(b64p) {
                                Ok(p_bytes) => {
                                    let password = String::from_utf8_lossy(&p_bytes).to_string();
                                    if let Some(dbp) = db_path.as_ref() {
                                        let dbp2 = dbp.clone();
                                        let user_lower = username.to_ascii_lowercase();
                                        match tokio::task::spawn_blocking(move || rmail_common::db::get_mailbox(&dbp2, &user_lower)).await {
                                            Ok(Ok(Some(mb))) => {
                                                if let Some(pw_hash) = mb.password_hash {
                                                    match rmail_common::auth::verify_password(&password, &pw_hash) {
                                                        Ok(true) => {
                                                            authenticated_user = Some(mb.address.to_ascii_lowercase());
                                                            let w = reader.get_mut();
                                                            w.write_all(b"235 Authentication succeeded\r\n").await?;
                                                            w.flush().await?;
                                                        }
                                                        Ok(false) => { let w = reader.get_mut(); w.write_all(b"535 Authentication failed\r\n").await?; w.flush().await?; }
                                                        Err(e) => { eprintln!("auth verify error: {}", e); let w = reader.get_mut(); w.write_all(b"451 Temporary error\r\n").await?; w.flush().await?; }
                                                    }
                                                } else { let w = reader.get_mut(); w.write_all(b"535 No password set\r\n").await?; w.flush().await?; }
                                            }
                                            Ok(Ok(None)) => { let w = reader.get_mut(); w.write_all(b"535 No such user\r\n").await?; w.flush().await?; }
                                            Ok(Err(e)) => { eprintln!("db error: {}", e); let w = reader.get_mut(); w.write_all(b"451 Temporary error\r\n").await?; w.flush().await?; }
                                            Err(e) => { eprintln!("db task join error: {}", e); let w = reader.get_mut(); w.write_all(b"451 Temporary error\r\n").await?; w.flush().await?; }
                                        }
                                    } else { let w = reader.get_mut(); w.write_all(b"454 TLS not available\r\n").await?; w.flush().await?; }
                                }
                                Err(_) => { let w = reader.get_mut(); w.write_all(b"501 Invalid base64\r\n").await?; w.flush().await?; }
                            }
                        }
                        Err(_) => { let w = reader.get_mut(); w.write_all(b"501 Invalid base64\r\n").await?; w.flush().await?; }
                    }
                } else {
                    let w = reader.get_mut();
                    w.write_all(b"334 VXNlcm5hbWU6\r\n").await?; // "Username:" in base64
                    w.flush().await?;
                    let mut uline = String::new();
                    reader.read_line(&mut uline).await?;
                    let b64u = uline.trim();
                    match base64::decode(b64u) {
                        Ok(u_bytes) => {
                            let username = String::from_utf8_lossy(&u_bytes).to_string();
                            let w = reader.get_mut();
                            w.write_all(b"334 UGFzc3dvcmQ6\r\n").await?; // "Password:" in base64
                            w.flush().await?;
                            let mut pass_line = String::new();
                            reader.read_line(&mut pass_line).await?;
                            let b64p = pass_line.trim();
                            match base64::decode(b64p) {
                                Ok(p_bytes) => {
                                    let password = String::from_utf8_lossy(&p_bytes).to_string();
                                    if let Some(dbp) = db_path.as_ref() {
                                        let dbp2 = dbp.clone();
                                        let user_lower = username.to_ascii_lowercase();
                                        match tokio::task::spawn_blocking(move || rmail_common::db::get_mailbox(&dbp2, &user_lower)).await {
                                            Ok(Ok(Some(mb))) => {
                                                if let Some(pw_hash) = mb.password_hash {
                                                    match rmail_common::auth::verify_password(&password, &pw_hash) {
                                                        Ok(true) => {
                                                            authenticated_user = Some(mb.address.to_ascii_lowercase());
                                                            let w = reader.get_mut();
                                                            w.write_all(b"235 Authentication succeeded\r\n").await?;
                                                            w.flush().await?;
                                                        }
                                                        Ok(false) => { let w = reader.get_mut(); w.write_all(b"535 Authentication failed\r\n").await?; w.flush().await?; }
                                                        Err(e) => { eprintln!("auth verify error: {}", e); let w = reader.get_mut(); w.write_all(b"451 Temporary error\r\n").await?; w.flush().await?; }
                                                    }
                                                } else { let w = reader.get_mut(); w.write_all(b"535 No password set\r\n").await?; w.flush().await?; }
                                            }
                                            Ok(Ok(None)) => { let w = reader.get_mut(); w.write_all(b"535 No such user\r\n").await?; w.flush().await?; }
                                            Ok(Err(e)) => { eprintln!("db error: {}", e); let w = reader.get_mut(); w.write_all(b"451 Temporary error\r\n").await?; w.flush().await?; }
                                            Err(e) => { eprintln!("db task join error: {}", e); let w = reader.get_mut(); w.write_all(b"451 Temporary error\r\n").await?; w.flush().await?; }
                                        }
                                    } else { let w = reader.get_mut(); w.write_all(b"454 TLS not available\r\n").await?; w.flush().await?; }
                                }
                                Err(_) => { let w = reader.get_mut(); w.write_all(b"501 Invalid base64\r\n").await?; w.flush().await?; }
                            }
                        }
                        Err(_) => { let w = reader.get_mut(); w.write_all(b"501 Invalid base64\r\n").await?; w.flush().await?; }
                    }
                }
            } else {
                let w = reader.get_mut();
                w.write_all(b"504 Unrecognized authentication mechanism\r\n").await?;
                w.flush().await?;
            }
        } else if up.starts_with("MAIL FROM:") {
            // Parse MAIL FROM and set sender; on syntax error return 501
            mail_from = extract_addr(cmd).or_else(|| {
                if let Some(idx) = cmd.find(':') { extract_addr(&cmd[idx+1..]) } else { None }
            });
            if mail_from.is_none() {
                let w = reader.get_mut();
                w.write_all(b"501 Syntax: MAIL FROM:<address>\r\n").await?;
                w.flush().await?;
                continue;
            }
            rcpts.clear();
            let w = reader.get_mut();
            w.write_all(b"250 OK\r\n").await?;
            w.flush().await?;
        } else if up.starts_with("RCPT TO:") {
            // Require MAIL FROM before RCPT TO
            if mail_from.is_none() {
                let w = reader.get_mut();
                w.write_all(b"503 Bad sequence of commands: MAIL required before RCPT\r\n").await?;
                w.flush().await?;
                continue;
            }
            let raw = cmd.get(8..).unwrap_or("");
            if let Some(addr) = extract_addr(raw) {
                // DB is authoritative — must be configured at startup
                if let Some(dbp) = db_path.as_ref() {
                    let dbp2 = dbp.clone();
                    let addr2 = addr.clone();
                    match tokio::task::spawn_blocking(move || rmail_common::db::mailbox_exists(dbp2, &addr2)).await {
                        Ok(Ok(true)) => {
                            if rcpts.len() >= MAX_RCPT {
                                let w = reader.get_mut();
                                w.write_all(b"452 Too many recipients\r\n").await?;
                                w.flush().await?;
                            } else {
                                rcpts.push(addr.clone());
                                let w = reader.get_mut();
                                w.write_all(b"250 OK\r\n").await?;
                                w.flush().await?;
                            }
                        }
                        Ok(Ok(false)) => {
                            if let Some(at) = addr.find('@') {
                                let domain = addr[at+1..].to_string();
                                let dbp3 = dbp.clone();
                                match tokio::task::spawn_blocking(move || rmail_common::db::get_catchall(dbp3, &domain)).await {
                                    Ok(Ok(Some(target))) => {
                                        if rcpts.len() >= MAX_RCPT {
                                            let w = reader.get_mut();
                                            w.write_all(b"452 Too many recipients\r\n").await?;
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
                                                w.write_all(b"452 Too many recipients\r\n").await?;
                                                w.flush().await?;
                                            } else {
                                                rcpts.push(addr.clone());
                                                let w = reader.get_mut();
                                                w.write_all(b"250 OK\r\n").await?;
                                                w.flush().await?;
                                            }
                                        } else {
                                            let w = reader.get_mut();
                                            w.write_all(b"550 No such user\r\n").await?;
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
        } else {
            let w = reader.get_mut();
            w.write_all(b"501 Syntax: RCPT TO:<address>\r\n").await?;
            w.flush().await?;
        }
        } else if up.starts_with("DATA") {
            // DATA requires recipients
            if rcpts.is_empty() {
                let w = reader.get_mut();
                w.write_all(b"554 No recipients\r\n").await?;
                w.flush().await?;
                continue;
            }
            let w = reader.get_mut();
            w.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n").await?;
            w.flush().await?;

            // Read message data with dot-stuff handling and enforce size limits
            let mut data: Vec<u8> = Vec::new();
            loop {
                let mut dline = String::new();
                let n = reader.read_line(&mut dline).await?;
                if n == 0 { break; }

                // Protect per-line length inside DATA too
                if dline.len() > MAX_LINE_LEN {
                    let w = reader.get_mut();
                    w.write_all(b"500 Line too long in data\r\n").await?;
                    w.flush().await?;
                    data.clear();
                    break;
                }

                // Normalize to a rust &str without trailing CR/LF
                let mut d = dline.as_str();
                if d.ends_with('\n') { d = &d[..d.len()-1]; }
                if d.ends_with('\r') { d = &d[..d.len()-1]; }

                if d == "." {
                    break;
                }

                // Un-dot-stuff per RFC5321: lines starting with ".." map to "."
                let out = if d.starts_with("..") { &d[1..] } else { d };
                data.extend_from_slice(out.as_bytes());
                data.extend_from_slice(b"\r\n");

                // Enforce overall message size to mitigate DoS
                if data.len() > MAX_MESSAGE_BYTES {
                    let w = reader.get_mut();
                    w.write_all(b"552 Message size exceeds fixed maximum\r\n").await?;
                    w.flush().await?;
                    data.clear();
                    break;
                }
            }

            // Attempt delivery to each recipient; errors are logged and yield temporary failure response
            if !data.is_empty() {
                // account bytes received
                metrics::add_bytes_received(data.len() as u64);
                for rcpt in &rcpts {
                    if let Some(at) = rcpt.find('@') {
                        let local = rcpt[..at].to_string();
                        let domain = rcpt[at+1..].to_string();
                        let mr = PathBuf::from(&mail_root);

                        // determine if this recipient is local (exists in the SQLite DB)
                        let is_local = if let Some(dbp) = db_path.as_ref() {
                            let dbp2 = dbp.clone();
                            let rcpt_clone = rcpt.clone();
                            match tokio::task::spawn_blocking(move || rmail_common::db::mailbox_exists(&dbp2, &rcpt_clone)).await {
                                Ok(Ok(b)) => b,
                                _ => false,
                            }
                        } else {
                            false
                        };

                        if is_local {
                            // measure per-recipient delivery latency
                            let start = std::time::Instant::now();
                            match maildir::deliver(&mr, &domain, &local, &data) {
                                Ok(path) => {
                                    let elapsed_us = start.elapsed().as_micros() as u64;
                                    // update metrics
                                    rmail_common::metrics::inc_deliveries();
                                    rmail_common::metrics::add_delivered_bytes(data.len() as u64);
                                    rmail_common::metrics::observe_delivery_latency_us(elapsed_us);

                                    println!("Delivered to {} -> {:?}", rcpt, path);
                                    // persist metadata to DB if configured
                                    if let Some(dbp) = db_path.as_ref() {
                                        let dbp2 = dbp.clone();
                                        let domain_c = domain.clone();
                                        let local_c = local.clone();
                                        let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
                                        let size = data.len() as i64;
                                        tokio::spawn(async move {
                                            match tokio::task::spawn_blocking(move || rmail_common::db::add_message(&dbp2, &domain_c, &local_c, &fname, size, None, None, None)).await {
                                                Ok(Ok(uid)) => {
                                                    println!("Recorded message UID {} for {}@{}", uid, local_c, domain_c);
                                                }
                                                Ok(Err(e)) => {
                                                    eprintln!("db add_message error: {}", e);
                                                }
                                                Err(e) => {
                                                    eprintln!("db task join error: {}", e);
                                                }
                                            }
                                        });
                                    }

                                    // update simple on-disk metric; failures are non-fatal
                                    if let Err(e) = increment_delivery_counter().await {
                                        eprintln!("metrics update failed: {}", e);
                                    }
                                }
                                Err(e) => {
                                    rmail_common::metrics::inc_failed_deliveries();
                                    eprintln!("deliver error for {}: {}", rcpt, e);
                                    let w = reader.get_mut();
                                    w.write_all(b"451 Requested action aborted: local error in processing\r\n").await?;
                                    w.flush().await?;
                                }
                            }
                        } else {
                            // queue outbound for remote recipients (requires authentication in RCPT stage)
                            match rmail_common::outbound::queue_outbound(&mr, rcpt, &data) {
                                Ok(path) => {
                                    println!("Queued outbound to {} -> {:?}", rcpt, path);
                                }
                                Err(e) => {
                                    eprintln!("failed to queue outbound {}: {}", rcpt, e);
                                    let w = reader.get_mut();
                                    w.write_all(b"451 Requested action aborted: temporary failure\r\n").await?;
                                    w.flush().await?;
                                }
                            }
                        }
                    }
                }
            }

            // reset transaction state after DATA
            rcpts.clear();
            mail_from = None;
            let w = reader.get_mut();
            w.write_all(b"250 OK\r\n").await?;
            w.flush().await?;
        } else if up.starts_with("QUIT") {
            let w = reader.get_mut();
            w.write_all(b"221 Bye\r\n").await?;
            w.flush().await?;
            break;
        } else if up.starts_with("STARTTLS") {
            // if we have an acceptor available, perform TLS handshake and continue inside TLS
            if let Some(acceptor) = tls_acceptor {
                let w = reader.get_mut();
                w.write_all(b"220 Ready to start TLS\r\n").await?;
                w.flush().await?;
                // take ownership of the underlying stream and perform TLS accept
                let inner = reader.into_inner();
                match acceptor.accept(inner).await {
                    Ok(tls_stream) => {
                        // Box the TLS stream to the AsyncStream trait object and recurse inside TLS context.
                        let fut = Box::pin(process_stream(Box::new(tls_stream), mail_root, None, db_path.clone()));
                        return fut.await;
                    }
                    Err(e) => {
                        eprintln!("TLS accept error: {}", e);
                        // We can't continue; return error to close connection
                        return Err(anyhow::anyhow!("TLS accept error: {}", e));
                    }
                }
            } else {
                let w = reader.get_mut();
                w.write_all(b"454 TLS not available\r\n").await?;
                w.flush().await?;
            }
        } else {
            let w = reader.get_mut();
            w.write_all(b"502 Command not implemented\r\n").await?;
            w.flush().await?;
        }
    }
    Ok(())
}
