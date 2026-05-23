use anyhow::{Context, Result};
use std::{collections::{HashMap, HashSet}, path::PathBuf, sync::Arc};

use rmail_common::{config::Config, maildir};
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

    let mut allowed: HashSet<String> = HashSet::new();
    if let Some(mboxes) = &cfg.mailboxes {
        for m in mboxes {
            allowed.insert(m.address.to_ascii_lowercase());
        }
    }
    let catchalls: HashMap<String, String> = cfg.catchalls.clone().unwrap_or_default();
    let mail_root = cfg.global.mail_root.clone();
    // Optional SQLite DB path for mailboxes/catchall overrides
    let db_path = cfg.global.db_path.clone();

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
        let allowed_clone = allowed.clone();
        let catchalls_clone = catchalls.clone();
        let mail_root_clone = mail_root.clone();
        let acceptor_clone = tls_acceptor.clone();
        let db_clone = db_path.clone();
        tokio::spawn(async move {
            if let Err(e) = run_plain_listener(&addr, allowed_clone, catchalls_clone, mail_root_clone, acceptor_clone, db_clone).await {
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
            let allowed_v4 = allowed.clone();
            let catchalls_v4 = catchalls.clone();
            let mail_root_v4 = mail_root.clone();
            let acceptor_v4 = s_acceptor.clone();
            let db_v4 = db_path.clone();
            tokio::spawn(async move {
                if let Err(e) = run_smtps_listener(&addr_v4, acceptor_v4, allowed_v4, catchalls_v4, mail_root_v4, db_v4).await {
                    eprintln!("SMTPS {} failed: {}", addr_v4, e);
                }
            });

            // v6 listener
            let allowed_v6 = allowed.clone();
            let catchalls_v6 = catchalls.clone();
            let mail_root_v6 = mail_root.clone();
            let acceptor_v6 = s_acceptor.clone();
            let db_v6 = db_path.clone();
            tokio::spawn(async move {
                if let Err(e) = run_smtps_listener(&addr_v6, acceptor_v6, allowed_v6, catchalls_v6, mail_root_v6, db_v6).await {
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

async fn run_plain_listener(addr: &str, allowed: HashSet<String>, catchalls: HashMap<String, String>, mail_root: String, tls_acceptor: Option<Arc<TlsAcceptor>>, db_path: Option<String>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("rMail SMTPD listening on {}", addr);
    loop {
        let (stream, _peer) = listener.accept().await?;
        let allowed = allowed.clone();
        let catchalls = catchalls.clone();
        let mail_root = mail_root.clone();
        let acceptor = tls_acceptor.clone();
        let db_clone = db_path.clone();
        tokio::spawn(async move {
            if let Err(e) = process_stream(Box::new(stream), allowed, catchalls, mail_root, acceptor, db_clone).await {
                eprintln!("client error: {}", e);
            }
        });
    }
}

async fn run_smtps_listener(addr: &str, acceptor: Arc<TlsAcceptor>, allowed: HashSet<String>, catchalls: HashMap<String, String>, mail_root: String, db_path: Option<String>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("rMail SMTPS listening on {}", addr);
    loop {
        let (stream, _peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let allowed = allowed.clone();
        let catchalls = catchalls.clone();
        let mail_root = mail_root.clone();
        let db_clone = db_path.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(e) = process_stream(Box::new(tls_stream), allowed, catchalls, mail_root, None, db_clone).await {
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

async fn process_stream(stream: Box<dyn AsyncStream + Send + 'static>, allowed: HashSet<String>, catchalls: HashMap<String, String>, mail_root: String, tls_acceptor: Option<Arc<TlsAcceptor>>, db_path: Option<String>) -> Result<()> {
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
            resp.push_str("250 OK\r\n");
            let w = reader.get_mut();
            w.write_all(resp.as_bytes()).await?;
            w.flush().await?;
            // reset transaction state
            mail_from = None;
            rcpts.clear();
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
            // Prefer DB lookup when configured
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
                        // mailbox not found in DB; check DB catchall
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
                                    // fallback to config-based catchalls
                                    if let Some(at2) = addr.find('@') {
                                        let domain2 = &addr[at2+1..];
                                        if let Some(target) = catchalls.get(domain2) {
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
                                        } else {
                                            let w = reader.get_mut();
                                            w.write_all(b"550 No such user\r\n").await?;
                                            w.flush().await?;
                                        }
                                    } else {
                                        let w = reader.get_mut();
                                        w.write_all(b"550 Bad address\r\n").await?;
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
                        // fallback to config-based checks
                        if allowed.contains(&addr) {
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
                        } else if let Some(at) = addr.find('@') {
                            let domain = &addr[at+1..];
                            if let Some(target) = catchalls.get(domain) {
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
                            } else {
                                let w = reader.get_mut();
                                w.write_all(b"550 No such user\r\n").await?;
                                w.flush().await?;
                            }
                        } else {
                            let w = reader.get_mut();
                            w.write_all(b"550 Bad address\r\n").await?;
                            w.flush().await?;
                        }
                    }
                    Err(e) => {
                        eprintln!("db task join error: {}", e);
                        let w = reader.get_mut();
                        w.write_all(b"451 Temporary error\r\n").await?;
                        w.flush().await?;
                    }
                }
            } else {
                // DB not configured; fallback to config lists
                if allowed.contains(&addr) {
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
                } else if let Some(at) = addr.find('@') {
                    let domain = &addr[at+1..];
                    if let Some(target) = catchalls.get(domain) {
                        // Deliver to catchall target, respect recipient limit
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
                    } else {
                        let w = reader.get_mut();
                        w.write_all(b"550 No such user\r\n").await?;
                        w.flush().await?;
                    }
                } else {
                    let w = reader.get_mut();
                    w.write_all(b"550 Bad address\r\n").await?;
                    w.flush().await?;
                }
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
                for rcpt in &rcpts {
                    if let Some(at) = rcpt.find('@') {
                        let local = &rcpt[..at];
                        let domain = &rcpt[at+1..];
                        let mr = PathBuf::from(&mail_root);
                        match maildir::deliver(&mr, domain, local, &data) {
                            Ok(path) => {
                                println!("Delivered to {} -> {:?}", rcpt, path);
                                // update simple on-disk metric; failures are non-fatal
                                if let Err(e) = increment_delivery_counter().await {
                                    eprintln!("metrics update failed: {}", e);
                                }
                            }
                            Err(e) => {
                                eprintln!("deliver error for {}: {}", rcpt, e);
                                let w = reader.get_mut();
                                w.write_all(b"451 Requested action aborted: local error in processing\r\n").await?;
                                w.flush().await?;
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
                        // Box the recursive future to avoid infinitely-sized future from recursion
                    let fut = Box::pin(process_stream(Box::new(tls_stream), allowed, catchalls, mail_root, None, db_path.clone()));
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
