use anyhow::{Context, Result};
use rmail_common::db::Mailbox;
use rmail_common::{auth, maildir, config::Config, db as rmail_db};
use std::{sync::{Arc, Mutex}, collections::HashMap, net::{IpAddr, SocketAddr}};
use std::time::{Instant, Duration};
use once_cell::sync::Lazy;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

mod tls;
use tls::load_tls_context;

// Trait object helper: combine AsyncRead + AsyncWrite into a single object-safe trait and require Unpin
// so that boxed trait objects can be used with tokio::io::BufReader.
trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized> AsyncStream for T {}

// Simple in-memory rate-limiter for authentication failures keyed by remote IP. This is a
// best-effort defensive measure; for multi-process deployments a shared store (Redis, etc.)
// should be used instead.
#[derive(Clone)]
struct AuthFailInfo {
    count: u32,
    first: Instant,
    locked_until: Option<Instant>,
}

static AUTH_FAILS: Lazy<Mutex<HashMap<IpAddr, AuthFailInfo>>> = Lazy::new(|| Mutex::new(HashMap::new()));

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
    let entry = m.entry(ip).or_insert(AuthFailInfo { count: 0, first: now, locked_until: None });
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

/// SelectedMailbox holds state for the currently selected mailbox in an IMAP session.
/// It maintains the mailbox domain/localpart, the persistent UIDVALIDITY value, and an
/// ordered Vec of (UID, PathBuf) where the order corresponds to IMAP sequence numbers.
/// This lightweight structure is recomputed on SELECT and reused for subsequent FETCH/UID commands
/// during the session to provide stable UIDs and predictable sequence numbers.
struct SelectedMailbox {
    pub domain: String,
    pub local: String,
    pub uidvalidity: u64,
    pub msgs: Vec<(u64, std::path::PathBuf, Vec<String>)>,
}


#[tokio::main]
async fn main() -> Result<()> {
    let cfg_path = std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let cfg = Config::from_file(&cfg_path).context(format!("loading {}", cfg_path))?;
    let mail_root = cfg.global.mail_root.clone();

    // SQLite DB is the authoritative source for mailboxes/catchalls
    let db_path = cfg.global.db_path.clone();
    if db_path.is_none() {
        eprintln!("No db_path configured; SQLite DB is required");
        std::process::exit(1);
    }

    // TLS context if certs present
    let tls_context = if let (Some(cert), Some(key)) = (&cfg.global.tls_cert, &cfg.global.tls_key) {
        match load_tls_context(cert, key) {
            Ok(ctx) => Some(ctx),
            Err(e) => { eprintln!("Failed to load TLS: {}", e); None }
        }
    } else {
        None
    };

    // Plain IMAP listener (supports STARTTLS if tls_context present)
    let imap_port = cfg.global.imap_port.unwrap_or(143);
    let imap_addr = format!("0.0.0.0:{}", imap_port);
    let db_path = cfg.global.db_path.clone();
    let mail_root_clone = mail_root.clone();
    let acceptor_clone = tls_context.clone();
    let db_clone = db_path.clone();
    tokio::spawn(async move {
        if let Err(e) = run_plain_listener(&imap_addr, mail_root_clone, acceptor_clone, db_clone).await {
            eprintln!("IMAP plain listener failed: {}", e);
        }
    });

    // IMAPS (implicit TLS) listener
    if let Some(ctx) = tls_context.clone() {
        if let Some(imaps_port) = cfg.global.imaps_port {
            let imaps_addr = format!("0.0.0.0:{}", imaps_port);
            let mail_root = mail_root.clone();
            let ctx2 = ctx.clone();
            let db_clone = db_path.clone();
            tokio::spawn(async move {
                if let Err(e) = run_imaps_listener(&imaps_addr, ctx2, mail_root, db_clone).await {
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

async fn run_plain_listener(addr: &str, mail_root: String, tls_ctx: Option<Arc<tls::TlsContext>>, db_path: Option<String>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("rMail IMAPD listening on {}", addr);
    loop {
        let (stream, peer) = listener.accept().await?;
        let mail_root = mail_root.clone();
        let acceptor = tls_ctx.clone();
        let db_clone = db_path.clone();
        tokio::spawn(async move {
            if let Err(e) = process_stream(Box::new(stream), mail_root, acceptor, db_clone, Some(peer), false).await {
                eprintln!("IMAP client error: {}", e);
            }
        });
    }
}

async fn run_imaps_listener(addr: &str, ctx: Arc<tls::TlsContext>, mail_root: String, db_path: Option<String>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("rMail IMAPD (IMAPS) listening on {}", addr);
    loop {
        let (stream, peer) = listener.accept().await?;
        let ctx = ctx.clone();
        let mail_root = mail_root.clone();
        let db_clone = db_path.clone();
        tokio::spawn(async move {
            match ctx.acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(e) = process_stream(Box::new(tls_stream), mail_root, Some(ctx.clone()), db_clone, Some(peer), true).await {
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

// session_encrypted indicates whether the current connection is protected by TLS (true for IMAPS
// and after a successful STARTTLS). Enforcing authentication methods (like LOGIN) only on
// encrypted sessions prevents accidental credential disclosure over plain-text.
// session_encrypted indicates whether the current connection is protected by TLS (true for IMAPS
// and after a successful STARTTLS). `peer` is the remote socket address of the client and is used
// for per-IP rate-limiting of authentication attempts.
async fn process_stream(stream: Box<dyn AsyncStream + Send + 'static>, mail_root: String, tls_ctx: Option<Arc<tls::TlsContext>>, db_path: Option<String>, peer: Option<SocketAddr>, session_encrypted: bool) -> Result<()> {
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
                // Rate-limiting: block repeated failures per remote IP
                if let Some(peer_addr) = peer {
                    if let Some(rem) = auth_block_remaining(peer_addr.ip()) {
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO Too many failed auth attempts; try again in {}s\r\n", tag, rem.as_secs()).as_bytes()).await?;
                        w.flush().await?;
                        continue;
                    }
                }
                // Require an encrypted session for LOGIN to avoid sending cleartext passwords
                if !session_encrypted {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Encryption required for authentication\r\n", tag).as_bytes()).await?;
                    w.flush().await?;
                    continue;
                }
                // LOGIN requires two args: user and password. Clients may quote them.
                let mut a = args.trim().splitn(2, ' ');
                let user_raw = a.next().unwrap_or("");
                let pass_raw = a.next().unwrap_or("");
                let user = unquote(user_raw);
                let pass = unquote(pass_raw);
                // find mailbox (prefer DB if configured)
                let mut mb: Option<Mailbox> = None;
                if let Some(dbp) = db_path.as_ref() {
                    let dbp2 = dbp.clone();
                    let user_lookup = user.to_ascii_lowercase();
                    if user_lookup.contains('@') {
                        match tokio::task::spawn_blocking(move || rmail_common::db::get_mailbox(dbp2, &user_lookup)).await {
                            Ok(Ok(Some(m))) => mb = Some(m),
                            Ok(Ok(None)) => {},
                            Ok(Err(e)) => eprintln!("db get_mailbox error: {}", e),
                            Err(e) => eprintln!("db task join error: {}", e),
                        }
                    } else {
                        let dbp3 = dbp.clone();
                        let user_local = user.to_string();
                        match tokio::task::spawn_blocking(move || rmail_common::db::find_mailbox_by_localpart(dbp3, &user_local)).await {
                            Ok(Ok(Some(m))) => mb = Some(m),
                            Ok(Ok(None)) => {},
                            Ok(Err(e)) => eprintln!("db query error: {}", e),
                            Err(e) => eprintln!("db task join error: {}", e),
                        }
                    }
                }
                // If DB lookup didn't find a mailbox, report not found (DB is authoritative)
                if mb.is_none() {
                    if let Some(peer_addr) = peer { record_auth_failure(peer_addr.ip()); }
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO No such user\r\n", tag).as_bytes()).await?;
                    w.flush().await?;
                    continue;
                }
                if let Some(mailbox) = mb {
                    if let Some(ref hash) = mailbox.password_hash {
                        match auth::verify_password(pass, hash) {
                            Ok(true) => {
                                authed_mailbox = Some(mailbox.address.to_ascii_lowercase());
                                if let Some(peer_addr) = peer { reset_auth_failures(peer_addr.ip()); }
                                let w = reader.get_mut();
                                w.write_all(format!("{} OK LOGIN completed\r\n", tag).as_bytes()).await?;
                                w.flush().await?;
                            },
                            Ok(false) => { if let Some(peer_addr) = peer { record_auth_failure(peer_addr.ip()); } let w = reader.get_mut(); w.write_all(format!("{} NO Authentication failed\r\n", tag).as_bytes()).await?; w.flush().await?; },
                            Err(e) => { if let Some(peer_addr) = peer { record_auth_failure(peer_addr.ip()); } let w = reader.get_mut(); w.write_all(format!("{} NO Authentication error\r\n", tag).as_bytes()).await?; w.flush().await?; eprintln!("auth verify error: {}", e); }
                        }
                    } else {
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO No password set for account\r\n", tag).as_bytes()).await?;
                        w.flush().await?;
                    }
                } else {
                    if let Some(peer_addr) = peer { record_auth_failure(peer_addr.ip()); }
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

                    let mr_clone = mail_root.clone();
                    let domain_c = domain.to_string();
                    let local_c = local.to_string();
                    let dbp_opt = db_path.clone();
                    match tokio::task::spawn_blocking(move || {
                        // Use DB to build selection state
                        if let Some(dbp) = dbp_opt {
                            let addr = format!("{}@{}", local_c, domain_c);
                            let uidvalidity = rmail_common::db::get_mailbox_uidvalidity(&dbp, &addr)?;
                            let list = rmail_common::db::list_messages(&dbp, &domain_c, &local_c)?;
                            let mut out_msgs: Vec<(u64, std::path::PathBuf, Vec<String>)> = Vec::new();
                            for (uid, filename, flags) in list.into_iter() {
                                let new_path = std::path::Path::new(&mr_clone).join(&domain_c).join(&local_c).join("Maildir").join("new").join(&filename);
                                let cur_path = std::path::Path::new(&mr_clone).join(&domain_c).join(&local_c).join("Maildir").join("cur").join(&filename);
                                let path = if new_path.exists() { new_path } else { cur_path };
                                out_msgs.push((uid, path, flags));
                            }
                            Ok((uidvalidity, out_msgs))
                        } else {
                            Err(anyhow::anyhow!("No DB configured"))
                        }
                    }).await {
                        Ok(Ok((uidvalidity, msgs))) => {
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
                        Ok(Err(e)) => {
                            let w = reader.get_mut();
                            w.write_all(format!("{} NO Error opening mailbox\r\n", tag).as_bytes()).await?;
                            w.flush().await?;
                            eprintln!("load_uid_map error: {}", e);
                        }
                        Err(e) => {
                            let w = reader.get_mut();
                            w.write_all(format!("{} NO Internal error\r\n", tag).as_bytes()).await?;
                            w.flush().await?;
                            eprintln!("task join error: {}", e);
                        }
                    }
                } else {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Internal error parsing address\r\n", tag).as_bytes()).await?;
                    w.flush().await?;
                }
            },
            "STARTTLS" => {
                if tls_ctx.is_none() {
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
                match tls_ctx.clone().unwrap().acceptor.accept(inner).await {
                    Ok(tls_stream) => {
                        // Box the TLS stream to the AsyncStream trait object and recurse inside TLS context.
                        // Pass the same tls_ctx along and mark the session as encrypted.
                        let fut = Box::pin(process_stream(Box::new(tls_stream), mail_root, tls_ctx.clone(), db_path.clone(), peer, true));
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
                    let uid = sel.msgs[idx].0;
                    let flags = sel.msgs[idx].2.clone();
                    let path = sel.msgs[idx].1.clone();
                    // read data in blocking thread
                    match tokio::task::spawn_blocking(move || std::fs::read(path)).await {
                        Ok(Ok(data)) => {
                            let flags_str = flags.join(" ");
                            let w = reader.get_mut();
                            w.write_all(format!("* {} FETCH (FLAGS ({}) UID {} RFC822 {{{}}}\r\n", seq, flags_str, uid, data.len()).as_bytes()).await?;
                            w.write_all(&data).await?;
                            w.write_all(b"\r\n)\r\n").await?;
                            w.flush().await?;
                        }
                        Ok(Err(e)) => {
                            let w = reader.get_mut();
                            w.write_all(format!("{} NO Error reading message\r\n", tag).as_bytes()).await?;
                            w.flush().await?;
                            eprintln!("read message error: {}", e);
                        }
                        Err(e) => {
                            let w = reader.get_mut();
                            w.write_all(format!("{} NO Internal error\r\n", tag).as_bytes()).await?;
                            w.flush().await?;
                            eprintln!("task join error: {}", e);
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
                        sel.msgs.iter().map(|(u,_,_)| *u).collect()
                    } else if uid_set.contains(':') {
                        let mut parts = uid_set.split(':');
                        let start = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(1);
                        let end = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(|| sel.msgs.last().map(|(u,_,_)| *u).unwrap_or(start));
                        sel.msgs.iter().filter_map(|(u,_,_)| {
                            if *u >= start && *u <= end { Some(*u) } else { None }
                        }).collect()
                    } else {
                        if let Ok(v) = uid_set.parse::<u64>() { vec![v] } else { vec![] }
                    };
                    for uid in uids {
                        if let Some(pos) = sel.msgs.iter().position(|(u,_,_)| *u == uid) {
                            let seq = pos + 1;
                            let uid = sel.msgs[pos].0;
                            let flags = sel.msgs[pos].2.clone();
                            let path = sel.msgs[pos].1.clone();
                            match tokio::task::spawn_blocking(move || std::fs::read(path)).await {
                                Ok(Ok(data)) => {
                                    let flags_str = flags.join(" ");
                                    let w = reader.get_mut();
                                    w.write_all(format!("* {} FETCH (FLAGS ({}) UID {} RFC822 {{{}}}\r\n", seq, flags_str, uid, data.len()).as_bytes()).await?;
                                    w.write_all(&data).await?;
                                    w.write_all(b"\r\n)\r\n").await?;
                                    w.flush().await?;
                                }
                                Ok(Err(e)) => {
                                    let w = reader.get_mut();
                                    w.write_all(format!("{} NO Error reading message\r\n", tag).as_bytes()).await?;
                                    w.flush().await?;
                                    eprintln!("read message error: {}", e);
                                }
                                Err(e) => {
                                    let w = reader.get_mut();
                                    w.write_all(format!("{} NO Internal error\r\n", tag).as_bytes()).await?;
                                    w.flush().await?;
                                    eprintln!("task join error: {}", e);
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
