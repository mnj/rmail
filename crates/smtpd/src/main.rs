use anyhow::{Context, Result};
use std::{collections::{HashMap, HashSet}, path::PathBuf, sync::Arc};

use rmail_common::{config::Config, maildir};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

mod tls;
use tls::load_tls_acceptor;
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() -> Result<()> {
    // load config (example path)
    let cfg = Config::from_file("config/example.toml").context("loading config/example.toml")?;

    let mut allowed: HashSet<String> = HashSet::new();
    if let Some(mboxes) = &cfg.mailboxes {
        for m in mboxes {
            allowed.insert(m.address.to_ascii_lowercase());
        }
    }
    let catchalls: HashMap<String, String> = cfg.catchalls.clone().unwrap_or_default();
    let mail_root = cfg.global.mail_root.clone();

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
        let allowed = allowed.clone();
        let catchalls = catchalls.clone();
        let mail_root = mail_root.clone();
        let acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = run_plain_listener(&addr, allowed, catchalls, mail_root, acceptor).await {
                eprintln!("Listener {} failed: {}", addr, e);
            }
        });
    }

    // spawn SMTPS listener (implicit TLS) if configured
    if let Some(s_acceptor) = tls_acceptor.clone() {
        if let Some(port) = cfg.global.smtps_port {
            let addr_v4 = format!("0.0.0.0:{}", port);
            let addr_v6 = format!("[::]:{}", port);
            let allowed = allowed.clone();
            let catchalls = catchalls.clone();
            let mail_root = mail_root.clone();
            let acceptor = s_acceptor.clone();
            tokio::spawn(async move {
                if let Err(e) = run_smtps_listener(&addr_v4, acceptor, allowed, catchalls, mail_root.clone()).await {
                    eprintln!("SMTPS {} failed: {}", addr_v4, e);
                }
            });
            tokio::spawn(async move {
                if let Err(e) = run_smtps_listener(&addr_v6, s_acceptor.clone(), allowed, catchalls, mail_root).await {
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

async fn run_plain_listener(addr: &str, allowed: HashSet<String>, catchalls: HashMap<String, String>, mail_root: String, tls_acceptor: Option<Arc<TlsAcceptor>>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("rMail SMTPD listening on {}", addr);
    loop {
        let (stream, _peer) = listener.accept().await?;
        let allowed = allowed.clone();
        let catchalls = catchalls.clone();
        let mail_root = mail_root.clone();
        let acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = process_stream(stream, allowed, catchalls, mail_root, acceptor).await {
                eprintln!("client error: {}", e);
            }
        });
    }
}

async fn run_smtps_listener(addr: &str, acceptor: Arc<TlsAcceptor>, allowed: HashSet<String>, catchalls: HashMap<String, String>, mail_root: String) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("rMail SMTPS listening on {}", addr);
    loop {
        let (stream, _peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let allowed = allowed.clone();
        let catchalls = catchalls.clone();
        let mail_root = mail_root.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(e) = process_stream(tls_stream, allowed, catchalls, mail_root, None).await {
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

async fn process_stream<S>(stream: S, allowed: HashSet<String>, catchalls: HashMap<String, String>, mail_root: String, tls_acceptor: Option<Arc<TlsAcceptor>>) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let writer = reader.get_mut();
    writer.write_all(b"220 rMail SMTPD ready\r\n").await?;
    writer.flush().await?;
    let mut rcpts: Vec<String> = Vec::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 { break; }
        let cmd = line.trim_end().to_string();
        let up = cmd.to_ascii_uppercase();
        if up.starts_with("HELO") || up.starts_with("EHLO") {
            writer.write_all(b"250 Hello\r\n").await?;
            writer.flush().await?;
        } else if up.starts_with("MAIL FROM:") {
            writer.write_all(b"250 OK\r\n").await?;
            writer.flush().await?;
            rcpts.clear();
        } else if up.starts_with("RCPT TO:") {
            if let Some(raw) = cmd.get(8..) {
                if let Some(addr) = extract_addr(raw) {
                    if allowed.contains(&addr) {
                        rcpts.push(addr.clone());
                        writer.write_all(b"250 OK\r\n").await?;
                        writer.flush().await?;
                    } else if let Some(at) = addr.find('@') {
                        let domain = &addr[at+1..];
                        if let Some(target) = catchalls.get(domain) {
                            rcpts.push(target.clone());
                            writer.write_all(b"250 OK\r\n").await?;
                            writer.flush().await?;
                        } else {
                            writer.write_all(b"550 No such user\r\n").await?;
                            writer.flush().await?;
                        }
                    } else {
                        writer.write_all(b"550 Bad address\r\n").await?;
                        writer.flush().await?;
                    }
                } else {
                    writer.write_all(b"550 Bad address\r\n").await?;
                    writer.flush().await?;
                }
            } else {
                writer.write_all(b"550 Bad address\r\n").await?;
                writer.flush().await?;
            }
        } else if up.starts_with("DATA") {
            if rcpts.is_empty() {
                writer.write_all(b"554 No recipients\r\n").await?;
                writer.flush().await?;
                continue;
            }
            writer.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n").await?;
            writer.flush().await?;
            // read data lines with dot-stuffing unescape
            let mut data: Vec<u8> = Vec::new();
            loop {
                let mut dline = String::new();
                let n = reader.read_line(&mut dline).await?;
                if n == 0 { break; }
                let d = if dline.ends_with('\n') { dline.trim_end_matches('\n').to_string() } else { dline.clone() };
                let d = d.trim_end_matches('\r');
                if d == "." {
                    break;
                }
                let mut out = d.to_string();
                if out.starts_with("..") {
                    out.remove(0); // un-escape leading dot
                }
                data.extend_from_slice(out.as_bytes());
                data.extend_from_slice(b"\r\n");
            }
            for rcpt in &rcpts {
                if let Some(at) = rcpt.find('@') {
                    let local = &rcpt[..at];
                    let domain = &rcpt[at+1..];
                    let mr = PathBuf::from(&mail_root);
                    match maildir::deliver(&mr, domain, local, &data) {
                        Ok(path) => println!("Delivered to {} -> {:?}", rcpt, path),
                        Err(e) => eprintln!("deliver error for {}: {}", rcpt, e),
                    }
                }
            }
            rcpts.clear();
            writer.write_all(b"250 OK\r\n").await?;
            writer.flush().await?;
        } else if up.starts_with("QUIT") {
            writer.write_all(b"221 Bye\r\n").await?;
            writer.flush().await?;
            break;
        } else if up.starts_with("STARTTLS") {
            // if we have an acceptor available, perform TLS handshake and continue inside TLS
            if let Some(acceptor) = tls_acceptor {
                writer.write_all(b"220 Ready to start TLS\r\n").await?;
                writer.flush().await?;
                // take ownership of the underlying stream and perform TLS accept
                let inner = reader.into_inner();
                match acceptor.accept(inner).await {
                    Ok(tls_stream) => {
                        // enter TLS-protected processing loop (no STARTTLS inside)
                        return process_stream(tls_stream, allowed, catchalls, mail_root, None).await;
                    }
                    Err(e) => {
                        eprintln!("TLS accept error: {}", e);
                        // We can't continue; return error to close connection
                        return Err(anyhow::anyhow!("TLS accept error: {}", e));
                    }
                }
            } else {
                writer.write_all(b"454 TLS not available\r\n").await?;
                writer.flush().await?;
            }
        } else {
            writer.write_all(b"502 Command not implemented\r\n").await?;
            writer.flush().await?;
        }
    }
    Ok(())
}
