use anyhow::{Context, Result};
use rmail_common::config::Mailbox;
use rmail_common::{auth, maildir, config::Config};
use std::{sync::Arc, collections::HashMap};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

mod tls;
use tls::load_tls_acceptor;
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = Config::from_file("config/example.toml").context("loading config/example.toml")?;
    let mail_root = cfg.global.mail_root.clone();

    // Build mailbox map: address -> Mailbox (lowercased)
    let mut mailbox_map: HashMap<String, Mailbox> = HashMap::new();
    if let Some(mboxes) = &cfg.mailboxes {
        for m in mboxes {
            mailbox_map.insert(m.address.to_ascii_lowercase(), m.clone());
        }
    }
    let mailbox_map = Arc::new(mailbox_map);

    // TLS acceptor if certs present
    let tls_acceptor = if let (Some(cert), Some(key)) = (&cfg.global.tls_cert, &cfg.global.tls_key) {
        match load_tls_acceptor(cert, key) {
            Ok(a) => Some(Arc::new(a)),
            Err(e) => { eprintln!("Failed to load TLS: {}", e); None }
        }
    } else {
        None
    };

    // Plain IMAP listener (supports STARTTLS if tls_acceptor present)
    let imap_port = cfg.global.imap_port.unwrap_or(143);
    let imap_addr = format!("0.0.0.0:{}", imap_port);
    let mailbox_map_clone = mailbox_map.clone();
    let mail_root_clone = mail_root.clone();
    let acceptor_clone = tls_acceptor.clone();
    tokio::spawn(async move {
        if let Err(e) = run_plain_listener(&imap_addr, mailbox_map_clone, mail_root_clone, acceptor_clone).await {
            eprintln!("IMAP plain listener failed: {}", e);
        }
    });

    // IMAPS (implicit TLS) listener
    if let Some(acceptor) = tls_acceptor.clone() {
        if let Some(imaps_port) = cfg.global.imaps_port {
            let imaps_addr = format!("0.0.0.0:{}", imaps_port);
            let mailbox_map = mailbox_map.clone();
            let mail_root = mail_root.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Err(e) = run_imaps_listener(&imaps_addr, acceptor, mailbox_map, mail_root).await {
                    eprintln!("IMAPS listener failed: {}", e);
                }
            });
        }
    }

    // keep running
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

async fn run_plain_listener(addr: &str, mailbox_map: Arc<HashMap<String, Mailbox>>, mail_root: String, tls_acceptor: Option<Arc<TlsAcceptor>>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("rMail IMAPD listening on {}", addr);
    loop {
        let (stream, _peer) = listener.accept().await?;
        let mailbox_map = mailbox_map.clone();
        let mail_root = mail_root.clone();
        let acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = process_stream(Box::new(stream), mailbox_map, mail_root, acceptor).await {
                eprintln!("IMAP client error: {}", e);
            }
        });
    }
}

async fn run_imaps_listener(addr: &str, acceptor: Arc<TlsAcceptor>, mailbox_map: Arc<HashMap<String, Mailbox>>, mail_root: String) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("rMail IMAPD (IMAPS) listening on {}", addr);
    loop {
        let (stream, _peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let mailbox_map = mailbox_map.clone();
        let mail_root = mail_root.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(e) = process_stream(Box::new(tls_stream), mailbox_map, mail_root, None).await {
                        eprintln!("IMAPS client error: {}", e);
                    }
                }
                Err(e) => eprintln!("TLS accept error: {}", e),
            }
        });
    }
}

fn unquote(s: &str) -> &str {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        &s[1..(s.len()-1)]
    } else {
        s
    }
}

async fn process_stream(stream: Box<dyn tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send>, mailbox_map: Arc<HashMap<String, Mailbox>>, mail_root: String, tls_acceptor: Option<Arc<TlsAcceptor>>) -> Result<()> {
    let mut reader = BufReader::new(stream);
    {
        let w = reader.get_mut();
        w.write_all(b"* OK rMail IMAPD ready\r\n").await?;
        w.flush().await?;
    }
    let mut line = String::new();
    let mut authed_mailbox: Option<String> = None; // store address lowercase

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 { break; }
        let input = line.trim_end_matches("\r\n");
        if input.is_empty() { continue; }
        let mut parts = input.splitn(3, ' ');
        let tag = parts.next().unwrap_or("*");
        let cmd = parts.next().unwrap_or("").to_uppercase();
        let args = parts.next().unwrap_or("");
        match cmd.as_str() {
            "LOGIN" => {
                // LOGIN requires two args: user and password. Clients may quote them.
                let mut a = args.trim().splitn(2, ' ');
                let user_raw = a.next().unwrap_or("");
                let pass_raw = a.next().unwrap_or("");
                let user = unquote(user_raw);
                let pass = unquote(pass_raw);
                // find mailbox
                let mut mb: Option<Mailbox> = None;
                if user.contains('@') {
                    mb = mailbox_map.get(&user.to_ascii_lowercase()).cloned();
                } else {
                    // try unique localpart match
                    let mut found = None;
                    for (addr, m) in mailbox_map.iter() {
                        if let Some(at) = addr.find('@') {
                            if &addr[..at] == user {
                                if found.is_some() {
                                    found = None; // ambiguous
                                    break;
                                } else {
                                    found = Some(m.clone());
                                }
                            }
                        }
                    }
                    mb = found;
                }
                if let Some(mailbox) = mb {
                    if let Some(ref hash) = mailbox.password_hash {
                        match auth::verify_password(pass, hash) {
                            Ok(true) => {
                                authed_mailbox = Some(mailbox.address.to_ascii_lowercase());
                                let w = reader.get_mut();
                                w.write_all(format!("{} OK LOGIN completed\r\n", tag).as_bytes()).await?;
                                w.flush().await?;
                            },
                            Ok(false) => {
                                let w = reader.get_mut();
                                w.write_all(format!("{} NO Authentication failed\r\n", tag).as_bytes()).await?;
                                w.flush().await?;
                            },
                            Err(e) => {
                                let w = reader.get_mut();
                                w.write_all(format!("{} NO Authentication error\r\n", tag).as_bytes()).await?;
                                w.flush().await?;
                                eprintln!("auth verify error: {}", e);
                            }
                        }
                    } else {
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO No password set for account\r\n", tag).as_bytes()).await?;
                        w.flush().await?;
                    }
                } else {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO No such user\r\n", tag).as_bytes()).await?;
                    w.flush().await?;
                }
            },
            "LIST" => {
                // Require authentication to list user's mailboxes in this simple implementation
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes()).await?;
                    w.flush().await?;
                    continue;
                }
                // Return INBOX only
                let w = reader.get_mut();
                w.write_all(b"* LIST (\"\\HasNoChildren\") \"/\" \"INBOX\"\r\n").await?;
                w.flush().await?;
                let w = reader.get_mut();
                w.write_all(format!("{} OK LIST completed\r\n", tag).as_bytes()).await?;
                w.flush().await?;
            },
            "SELECT" => {
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes()).await?;
                    w.flush().await?;
                    continue;
                }
                let mailbox_name = args.trim();
                if mailbox_name.to_uppercase() != "INBOX" {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Only INBOX supported\r\n", tag).as_bytes()).await?;
                    w.flush().await?;
                    continue;
                }
                let addr = authed_mailbox.as_ref().unwrap();
                // determine maildir path
                if let Some(at) = addr.find('@') {
                    let local = &addr[..at];
                    let domain = &addr[at+1..];
                    let count = maildir::count_messages(&std::path::Path::new(&mail_root), domain, local)?;
                    let w = reader.get_mut();
                    w.write_all(format!("* {} EXISTS\r\n", count).as_bytes()).await?;
                    w.flush().await?;
                    let w = reader.get_mut();
                    w.write_all(b"* 0 RECENT\r\n").await?;
                    w.flush().await?;
                    let w = reader.get_mut();
                    w.write_all(format!("{} OK [READ-WRITE] SELECT completed\r\n", tag).as_bytes()).await?;
                    w.flush().await?;
                } else {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Internal error parsing address\r\n", tag).as_bytes()).await?;
                    w.flush().await?;
                }
            },
            "STARTTLS" => {
                if tls_acceptor.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO TLS not available\r\n", tag).as_bytes()).await?;
                    w.flush().await?;
                    continue;
                }
                let w = reader.get_mut();
                w.write_all(format!("{} OK Begin TLS negotiation now\r\n", tag).as_bytes()).await?;
                w.flush().await?;
                // perform TLS handshake and continue inside TLS context
                let inner = reader.into_inner();
                match tls_acceptor.unwrap().accept(inner).await {
                    Ok(tls_stream) => {
                        return process_stream(tls_stream, mailbox_map, mail_root, None).await;
                    },
                    Err(e) => {
                        eprintln!("TLS accept failed: {}", e);
                        return Err(anyhow::anyhow!("TLS accept failed: {}", e));
                    }
                }
            },
            "LOGOUT" => {
                let w = reader.get_mut();
                w.write_all(b"* BYE Logging out\r\n").await?;
                w.flush().await?;
                let w = reader.get_mut();
                w.write_all(format!("{} OK LOGOUT completed\r\n", tag).as_bytes()).await?;
                w.flush().await?;
                break;
            },
            _ => {
                let w = reader.get_mut();
                w.write_all(format!("{} BAD Unknown or unimplemented command\r\n", tag).as_bytes()).await?;
                w.flush().await?;
            }
        }
    }
    Ok(())
}
