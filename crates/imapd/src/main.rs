use anyhow::{Context, Result};
use rmail_common::config::Mailbox;
use rmail_common::{auth, maildir, config::Config};
use std::{sync::Arc, collections::HashMap};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

mod tls;
use tls::load_tls_acceptor;
use tokio_rustls::TlsAcceptor;

// Trait object helper: combine AsyncRead + AsyncWrite into a single object-safe trait and require Unpin
// so that boxed trait objects can be used with tokio::io::BufReader.
trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized> AsyncStream for T {}

/// SelectedMailbox holds state for the currently selected mailbox in an IMAP session.
/// It maintains the mailbox domain/localpart, the persistent UIDVALIDITY value, and an
/// ordered Vec of (UID, PathBuf) where the order corresponds to IMAP sequence numbers.
/// This lightweight structure is recomputed on SELECT and reused for subsequent FETCH/UID commands
/// during the session to provide stable UIDs and predictable sequence numbers.
struct SelectedMailbox {
    pub domain: String,
    pub local: String,
    pub uidvalidity: u64,
    pub msgs: Vec<(u64, std::path::PathBuf)>,
}


#[tokio::main]
async fn main() -> Result<()> {
    let cfg_path = std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let cfg = Config::from_file(&cfg_path).context(format!("loading {}", cfg_path))?;
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

async fn process_stream(stream: Box<dyn AsyncStream + Send + 'static>, mailbox_map: Arc<HashMap<String, Mailbox>>, mail_root: String, tls_acceptor: Option<Arc<TlsAcceptor>>) -> Result<()> {
    let mut reader = BufReader::new(stream);
    {
        let w = reader.get_mut();
        w.write_all(b"* OK rMail IMAPD ready\r\n").await?;
        w.flush().await?;
    }
    let mut line = String::new();
    let mut authed_mailbox: Option<String> = None; // store address lowercase
    // current mailbox selection state (set by SELECT)
    let mut selected: Option<SelectedMailbox> = None;

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

                    // Load or build UID mapping for this Maildir. This maintains a persistent UIDVALIDITY
                    // and a filename -> UID map stored under Maildir/uidmap.json to provide stable UIDs
                    // across server restarts. list_messages provides stable ordering for sequence numbers.
                    match maildir::load_uid_map(std::path::Path::new(&mail_root), domain, local) {
                        Ok((uidvalidity, msgs)) => {
                            let count = msgs.len();
                            // store selection in session state
                            selected = Some(SelectedMailbox { domain: domain.to_string(), local: local.to_string(), uidvalidity, msgs });
                            let w = reader.get_mut();
                            w.write_all(format!("* {} EXISTS\r\n", count).as_bytes()).await?;
                            w.flush().await?;
                            let w = reader.get_mut();
                            w.write_all(b"* 0 RECENT\r\n").await?;
                            w.flush().await?;
                            let w = reader.get_mut();
                            w.write_all(format!("{} OK [UIDVALIDITY {}] [READ-WRITE] SELECT completed\r\n", tag, uidvalidity).as_bytes()).await?;
                            w.flush().await?;
                        }
                        Err(e) => {
                            let w = reader.get_mut();
                            w.write_all(format!("{} NO Error opening mailbox\r\n", tag).as_bytes()).await?;
                            w.flush().await?;
                            eprintln!("load_uid_map error: {}", e);
                        }
                    }
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
                        // Box the TLS stream to the AsyncStream trait object and recurse inside TLS context.
                        let fut = Box::pin(process_stream(Box::new(tls_stream), mailbox_map, mail_root, None));
                        return fut.await;
                    },
                    Err(e) => {
                        eprintln!("TLS accept failed: {}", e);
                        return Err(anyhow::anyhow!("TLS accept failed: {}", e));
                    }
                }
            },
            "FETCH" => {
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes()).await?;
                    w.flush().await?;
                    continue;
                }
                // Ensure a mailbox has been selected with SELECT first
                if selected.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes()).await?;
                    w.flush().await?;
                    continue;
                }
                let args = args.trim();
                let mut a = args.splitn(2, ' ');
                let seq_set = a.next().unwrap_or("");
                let _what = a.next().unwrap_or("");
                let sel = selected.as_ref().unwrap();
                let total = sel.msgs.len();
                let seqs: Vec<usize> = if seq_set == "1:*" {
                    (1..=total).collect()
                } else if seq_set.contains(':') {
                    let mut parts = seq_set.split(':');
                    let start = parts.next().and_then(|s| s.parse::<usize>().ok()).unwrap_or(1);
                    let end = parts.next().and_then(|s| s.parse::<usize>().ok()).unwrap_or(total);
                    (start..=end).collect()
                } else {
                    if let Ok(v) = seq_set.parse::<usize>() { vec![v] } else { vec![] }
                };
                for seq in seqs {
                    if seq == 0 || seq > total { continue; }
                    let idx = seq - 1;
                    let path = &sel.msgs[idx].1;
                    match std::fs::read(path) {
                        Ok(data) => {
                            let w = reader.get_mut();
                            w.write_all(format!("* {} FETCH (RFC822 {{{}}}\r\n", seq, data.len()).as_bytes()).await?;
                            w.write_all(&data).await?;
                            w.write_all(b"\r\n)\r\n").await?;
                            w.flush().await?;
                        }
                        Err(e) => {
                            let w = reader.get_mut();
                            w.write_all(format!("{} NO Error reading message\r\n", tag).as_bytes()).await?;
                            w.flush().await?;
                            eprintln!("read message error: {}", e);
                        }
                    }
                }
                let w = reader.get_mut();
                w.write_all(format!("{} OK FETCH completed\r\n", tag).as_bytes()).await?;
                w.flush().await?;
            },
            "UID" => {
                let mut a = args.trim().splitn(2, ' ');
                let subcmd = a.next().unwrap_or("").to_uppercase();
                let subargs = a.next().unwrap_or("");
                if subcmd.as_str() == "FETCH" {
                    if selected.is_none() {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes()).await?;
                        w.flush().await?;
                        continue;
                    }
                    let mut b = subargs.splitn(2, ' ');
                    let uid_set = b.next().unwrap_or("");
                    let _what = b.next().unwrap_or("");
                    let sel = selected.as_ref().unwrap();
                    // Build list of UIDs to return, handling ranges
                    let uids: Vec<u64> = if uid_set == "1:*" {
                        sel.msgs.iter().map(|(u,_)| *u).collect()
                    } else if uid_set.contains(':') {
                        let mut parts = uid_set.split(':');
                        let start = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(1);
                        let end = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(|| sel.msgs.last().map(|(u,_)| *u).unwrap_or(start));
                        sel.msgs.iter().filter_map(|(u,_)| {
                            if *u >= start && *u <= end { Some(*u) } else { None }
                        }).collect()
                    } else {
                        if let Ok(v) = uid_set.parse::<u64>() { vec![v] } else { vec![] }
                    };
                    for uid in uids {
                        if let Some(pos) = sel.msgs.iter().position(|(u,_)| *u == uid) {
                            let seq = pos + 1;
                            let path = &sel.msgs[pos].1;
                            match std::fs::read(path) {
                                Ok(data) => {
                                    let w = reader.get_mut();
                                    w.write_all(format!("* {} FETCH (UID {} RFC822 {{{}}}\r\n", seq, uid, data.len()).as_bytes()).await?;
                                    w.write_all(&data).await?;
                                    w.write_all(b"\r\n)\r\n").await?;
                                    w.flush().await?;
                                }
                                Err(e) => {
                                    let w = reader.get_mut();
                                    w.write_all(format!("{} NO Error reading message\r\n", tag).as_bytes()).await?;
                                    w.flush().await?;
                                    eprintln!("read message error: {}", e);
                                }
                            }
                        }
                    }
                    let w = reader.get_mut();
                    w.write_all(format!("{} OK UID FETCH completed\r\n", tag).as_bytes()).await?;
                    w.flush().await?;
                } else {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD Unsupported UID subcommand\r\n", tag).as_bytes()).await?;
                    w.flush().await?;
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
