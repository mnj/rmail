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
        let allowed_clone = allowed.clone();
        let catchalls_clone = catchalls.clone();
        let mail_root_clone = mail_root.clone();
        let acceptor_clone = tls_acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = run_plain_listener(&addr, allowed_clone, catchalls_clone, mail_root_clone, acceptor_clone).await {
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
            tokio::spawn(async move {
                if let Err(e) = run_smtps_listener(&addr_v4, acceptor_v4, allowed_v4, catchalls_v4, mail_root_v4).await {
                    eprintln!("SMTPS {} failed: {}", addr_v4, e);
                }
            });

            // v6 listener
            let allowed_v6 = allowed.clone();
            let catchalls_v6 = catchalls.clone();
            let mail_root_v6 = mail_root.clone();
            let acceptor_v6 = s_acceptor.clone();
            tokio::spawn(async move {
                if let Err(e) = run_smtps_listener(&addr_v6, acceptor_v6, allowed_v6, catchalls_v6, mail_root_v6).await {
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
            if let Err(e) = process_stream(Box::new(stream), allowed, catchalls, mail_root, acceptor).await {
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
                    if let Err(e) = process_stream(Box::new(tls_stream), allowed, catchalls, mail_root, None).await {
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

async fn process_stream(stream: Box<dyn tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static>, allowed: HashSet<String>, catchalls: HashMap<String, String>, mail_root: String, tls_acceptor: Option<Arc<TlsAcceptor>>) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    {
        let w = reader.get_mut();
        w.write_all(b"220 rMail SMTPD ready\r\n").await?;
        w.flush().await?;
    }
    let mut rcpts: Vec<String> = Vec::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 { break; }
        let cmd = line.trim_end().to_string();
        let up = cmd.to_ascii_uppercase();
        if up.starts_with("HELO") || up.starts_with("EHLO") {
            let w = reader.get_mut();
            w.write_all(b"250 Hello\r\n").await?;
            w.flush().await?;
        } else if up.starts_with("MAIL FROM:") {
            let w = reader.get_mut();
            w.write_all(b"250 OK\r\n").await?;
            w.flush().await?;
            rcpts.clear();
        } else if up.starts_with("RCPT TO:") {
            if let Some(raw) = cmd.get(8..) {
                if let Some(addr) = extract_addr(raw) {
                    if allowed.contains(&addr) {
                        rcpts.push(addr.clone());
                        let w = reader.get_mut();
                        w.write_all(b"250 OK\r\n").await?;
                        w.flush().await?;
                    } else if let Some(at) = addr.find('@') {
                        let domain = &addr[at+1..];
                        if let Some(target) = catchalls.get(domain) {
                            rcpts.push(target.clone());
                            let w = reader.get_mut();
                            w.write_all(b"250 OK\r\n").await?;
                            w.flush().await?;
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
                } else {
                    let w = reader.get_mut();
                    w.write_all(b"550 Bad address\r\n").await?;
                    w.flush().await?;
                }
            } else {
                let w = reader.get_mut();
                w.write_all(b"550 Bad address\r\n").await?;
                w.flush().await?;
            }
        } else if up.starts_with("DATA") {
            if rcpts.is_empty() {
                let w = reader.get_mut();
                w.write_all(b"554 No recipients\r\n").await?;
                w.flush().await?;
                continue;
            }
            let w = reader.get_mut();
            w.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n").await?;
            w.flush().await?;
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
                        // enter TLS-protected processing loop (no STARTTLS inside)
                        return process_stream(Box::new(tls_stream), allowed, catchalls, mail_root, None).await;
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
