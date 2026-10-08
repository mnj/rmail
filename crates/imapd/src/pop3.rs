//! POP3 (RFC 1939) with STLS (RFC 2595), CAPA/UIDL/TOP (RFC 2449) and
//! AUTH PLAIN (RFC 5034), for clients that cannot speak IMAP. Served by the
//! IMAP daemon so it shares the mail store, TLS certificate, shutdown and
//! connection limits. It reads the INBOX; deletions apply only on QUIT.
//!
//! Password login is accepted only over TLS (or from loopback).

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use once_cell::sync::Lazy;
use rmail_common::auth::{PasswordAuthResult, authenticate_password};
use rmail_common::imap_state::{self, Message};
use rmail_common::runtime::GracefulShutdown;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::time::timeout;

use crate::RawStream;
use crate::listener::accept_connection_from;
use crate::tls::TlsContext;

const MAX_LINE_BYTES: usize = 4 * 1024;
const MAX_MESSAGE_BYTES: u64 = 256 * 1024 * 1024;
const UNAUTHENTICATED_TIMEOUT: Duration = Duration::from_secs(2 * 60);
// RFC 1939 requires at least 10 minutes in the transaction state.
const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// Accounts with an open POP3 transaction (RFC 1939 section 8 exclusive access).
static LOCKED: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| Mutex::new(HashSet::new()));

struct MailboxLock(String);

impl MailboxLock {
    fn acquire(account: &str) -> Option<Self> {
        LOCKED
            .lock()
            .unwrap()
            .insert(account.to_string())
            .then(|| Self(account.to_string()))
    }
}

impl Drop for MailboxLock {
    fn drop(&mut self) {
        LOCKED.lock().unwrap().remove(&self.0);
    }
}

type Stream = BufReader<Box<dyn RawStream + Send>>;

#[derive(Clone)]
pub(crate) struct Pop3Context {
    pub mail_root: String,
    pub db_path: String,
    pub tls: watch::Receiver<Option<Arc<TlsContext>>>,
    pub session_limit: Arc<Semaphore>,
    pub connection_rate_limit: usize,
    /// POP3S: TLS starts before the greeting instead of via STLS.
    pub implicit_tls: bool,
    pub shutdown: GracefulShutdown,
}

pub(crate) async fn run_listener(
    addr: String,
    listener: TcpListener,
    ctx: Pop3Context,
) -> Result<()> {
    imap_log!("info", "pop3_listener_started", { "address": addr, "tls": ctx.implicit_tls });
    let mut shutdown_signal = ctx.shutdown.subscribe();
    loop {
        if *shutdown_signal.borrow() {
            return Ok(());
        }
        let (mut stream, peer) = tokio::select! {
            changed = shutdown_signal.changed() => {
                changed.context("waiting for POP3 shutdown signal")?;
                return Ok(());
            }
            accepted = rmail_common::net::accept_retrying(&listener, "imapd", &addr) => accepted,
        };
        let tls = ctx.tls.borrow().clone();
        if ctx.implicit_tls && tls.is_none() {
            continue;
        }
        if !accept_connection_from(peer.ip(), ctx.connection_rate_limit) {
            if !ctx.implicit_tls {
                let _ = stream
                    .write_all(b"-ERR [SYS/TEMP] Rate limit exceeded\r\n")
                    .await;
            }
            continue;
        }
        let Ok(permit) = ctx.session_limit.clone().try_acquire_owned() else {
            if !ctx.implicit_tls {
                let _ = stream
                    .write_all(b"-ERR [SYS/TEMP] Too many sessions\r\n")
                    .await;
            }
            continue;
        };
        let session = ctx.shutdown.start_session();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _session = session;
            let _permit = permit;
            let result = async {
                let stream: Box<dyn RawStream + Send> = match (&tls, ctx.implicit_tls) {
                    (Some(tls), true) => {
                        let started = Instant::now();
                        let handshake =
                            timeout(TLS_HANDSHAKE_TIMEOUT, tls.acceptor.accept(stream)).await;
                        rmail_common::metrics::observe_tls_handshake_duration(started.elapsed());
                        Box::new(handshake.context("POP3S handshake timed out")??)
                    }
                    _ => Box::new(stream),
                };
                serve(
                    stream,
                    Some(peer),
                    tls,
                    ctx.implicit_tls,
                    ctx.mail_root.clone(),
                    ctx.db_path.clone(),
                )
                .await
            }
            .await;
            if let Err(error) = result {
                imap_log!("error", "pop3_session_failed", { "peer": peer.to_string(), "error": error.to_string() });
            }
        });
    }
}

struct Session {
    reader: Stream,
    peer: Option<SocketAddr>,
    tls: Option<Arc<TlsContext>>,
    encrypted: bool,
    mail_root: String,
    db_path: String,
    pending_user: Option<String>,
    mailbox: Option<Transaction>,
}

struct Transaction {
    _lock: MailboxLock,
    domain: String,
    local: String,
    uidvalidity: u64,
    messages: Vec<Message>,
    deleted: HashSet<usize>,
}

impl Transaction {
    fn live(&self) -> impl Iterator<Item = (usize, &Message)> {
        self.messages
            .iter()
            .enumerate()
            .filter(|(index, _)| !self.deleted.contains(index))
    }

    /// 1-based message number to an index, if it names a live message.
    fn index(&self, number: &str) -> Option<usize> {
        let number: usize = number.parse().ok()?;
        let index = number.checked_sub(1)?;
        (index < self.messages.len() && !self.deleted.contains(&index)).then_some(index)
    }
}

enum Flow {
    Continue,
    Close,
}

pub(crate) async fn serve(
    stream: Box<dyn RawStream + Send>,
    peer: Option<SocketAddr>,
    tls: Option<Arc<TlsContext>>,
    encrypted: bool,
    mail_root: String,
    db_path: String,
) -> Result<()> {
    let mut session = Session {
        reader: BufReader::new(stream),
        peer,
        tls,
        encrypted,
        mail_root,
        db_path,
        pending_user: None,
        mailbox: None,
    };
    session.send(b"+OK rMail POP3 ready\r\n").await?;
    loop {
        let idle = if session.mailbox.is_some() {
            TRANSACTION_TIMEOUT
        } else {
            UNAUTHENTICATED_TIMEOUT
        };
        let line = match timeout(idle, read_line(&mut session.reader)).await {
            Err(_) => {
                session.send(b"-ERR Idle timeout\r\n").await?;
                return Ok(());
            }
            Ok(Ok(Some(line))) => line,
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(error)) => return Err(error.into()),
        };
        let Some(line) = line else {
            session.send(b"-ERR Command line too long\r\n").await?;
            continue;
        };
        let text = String::from_utf8_lossy(&line).into_owned();
        let mut words = text.split_whitespace();
        let command = words.next().unwrap_or("").to_ascii_uppercase();
        let args: Vec<&str> = words.collect();
        // Everything after the single space that ends the command word,
        // verbatim: a PASS argument may hold any run of spaces (RFC 1939).
        let rest = text
            .trim_start()
            .split_once(' ')
            .map_or("", |(_, rest)| rest);
        // A malformed line must never reveal a password in the log.
        match session.dispatch(&command, &args, rest).await? {
            Flow::Continue => {}
            Flow::Close => return Ok(()),
        }
    }
}

/// `Ok(None)` is end of stream; `Ok(Some(None))` is an over-long line that
/// was discarded.
async fn read_line(reader: &mut Stream) -> std::io::Result<Option<Option<Vec<u8>>>> {
    let mut line = Vec::new();
    let mut overflow = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(None);
        }
        let (take, done) = match available.iter().position(|&b| b == b'\n') {
            Some(index) => (index + 1, true),
            None => (available.len(), false),
        };
        if !overflow {
            line.extend_from_slice(&available[..take]);
            overflow = line.len() > MAX_LINE_BYTES;
        }
        reader.consume(take);
        if done {
            break;
        }
    }
    if overflow {
        return Ok(Some(None));
    }
    while matches!(line.last(), Some(b'\n' | b'\r')) {
        line.pop();
    }
    Ok(Some(Some(line)))
}

/// Dot-stuffed, CRLF-normalized multi-line response body of `lines`,
/// including the terminating `.` line.
fn encode_lines<'a>(lines: impl Iterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    for line in lines {
        if line.first() == Some(&b'.') {
            out.push(b'.');
        }
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

/// Lines of a message without their terminators.
fn message_lines(raw: &[u8]) -> Vec<&[u8]> {
    let mut lines: Vec<&[u8]> = raw
        .split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .collect();
    if raw.ends_with(b"\n") || raw.is_empty() {
        lines.pop();
    }
    lines
}

impl Session {
    async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.reader.get_mut().write_all(bytes).await?;
        self.reader.get_mut().flush().await?;
        Ok(())
    }

    async fn ok(&mut self, text: &str) -> Result<Flow> {
        self.send(format!("+OK {text}\r\n").as_bytes()).await?;
        Ok(Flow::Continue)
    }

    async fn err(&mut self, text: &str) -> Result<Flow> {
        self.send(format!("-ERR {text}\r\n").as_bytes()).await?;
        Ok(Flow::Continue)
    }

    fn password_login_allowed(&self) -> bool {
        self.encrypted || self.peer.is_some_and(|peer| peer.ip().is_loopback())
    }

    async fn dispatch(&mut self, command: &str, args: &[&str], rest: &str) -> Result<Flow> {
        match command {
            "CAPA" => {
                let mut text = String::from(
                    "+OK Capability list follows\r\nTOP\r\nUSER\r\nUIDL\r\nRESP-CODES\r\nPIPELINING\r\nEXPIRE NEVER\r\nIMPLEMENTATION rMail\r\n",
                );
                if self.mailbox.is_none() && self.password_login_allowed() {
                    text.push_str("SASL PLAIN\r\n");
                }
                if !self.encrypted && self.tls.is_some() && self.mailbox.is_none() {
                    text.push_str("STLS\r\n");
                }
                text.push_str(".\r\n");
                self.send(text.as_bytes()).await?;
                Ok(Flow::Continue)
            }
            "NOOP" => self.ok("").await,
            "QUIT" => self.quit().await,
            "STLS" => self.stls().await,
            "USER" | "PASS" | "AUTH" if self.mailbox.is_some() => {
                self.err("Already authenticated").await
            }
            "USER" => match args {
                [name] => {
                    self.pending_user = Some((*name).to_string());
                    self.ok("Send PASS").await
                }
                _ => self.err("USER needs a name").await,
            },
            "PASS" => {
                let Some(user) = self.pending_user.take() else {
                    return self.err("Send USER first").await;
                };
                // The password may contain spaces: take the rest of the line.
                self.login(&user, rest).await
            }
            "AUTH" => self.auth(args).await,
            _ if self.mailbox.is_none() => self.err("Authenticate first").await,
            "STAT" => {
                let tx = self.mailbox.as_ref().unwrap();
                let (count, octets) = tx
                    .live()
                    .fold((0usize, 0u64), |(c, o), (_, m)| (c + 1, o + m.size));
                self.ok(&format!("{count} {octets}")).await
            }
            "LIST" | "UIDL" => self.listing(command, args).await,
            "RETR" | "TOP" => self.retrieve(command, args).await,
            "DELE" => {
                let tx = self.mailbox.as_mut().unwrap();
                match args.first().and_then(|n| tx.index(n)) {
                    Some(index) if args.len() == 1 => {
                        tx.deleted.insert(index);
                        self.ok("Marked for deletion").await
                    }
                    _ => self.err("No such message").await,
                }
            }
            "RSET" => {
                self.mailbox.as_mut().unwrap().deleted.clear();
                self.ok("Reset").await
            }
            _ => self.err("Unknown command").await,
        }
    }

    async fn quit(&mut self) -> Result<Flow> {
        let Some(tx) = self.mailbox.take() else {
            self.send(b"+OK Bye\r\n").await?;
            return Ok(Flow::Close);
        };
        let uids: Vec<u64> = tx
            .messages
            .iter()
            .enumerate()
            .filter(|(index, _)| tx.deleted.contains(index))
            .map(|(_, message)| message.uid)
            .collect();
        if !uids.is_empty() {
            let (root, domain, local) =
                (self.mail_root.clone(), tx.domain.clone(), tx.local.clone());
            let result = tokio::task::spawn_blocking(move || {
                imap_state::delete_messages_by_uid(
                    std::path::Path::new(&root),
                    &domain,
                    &local,
                    "INBOX",
                    &uids,
                )
            })
            .await;
            if !matches!(result, Ok(Ok(_))) {
                self.send(b"-ERR [SYS/TEMP] Some deleted messages were not removed\r\n")
                    .await?;
                return Ok(Flow::Close);
            }
        }
        self.send(b"+OK Bye\r\n").await?;
        Ok(Flow::Close)
    }

    async fn stls(&mut self) -> Result<Flow> {
        if self.encrypted || self.mailbox.is_some() {
            return self.err("STLS is not available now").await;
        }
        let Some(tls) = self.tls.clone() else {
            return self.err("TLS is not available").await;
        };
        self.send(b"+OK Begin TLS negotiation\r\n").await?;
        let (placeholder, _) = tokio::io::duplex(1);
        let plain =
            std::mem::replace(&mut self.reader, BufReader::new(Box::new(placeholder))).into_inner();
        match timeout(TLS_HANDSHAKE_TIMEOUT, tls.acceptor.accept(plain)).await {
            Ok(Ok(stream)) => {
                self.reader = BufReader::new(Box::new(stream));
                self.encrypted = true;
                // Anything learned before TLS must be forgotten (RFC 2595).
                self.pending_user = None;
                Ok(Flow::Continue)
            }
            Ok(Err(error)) => Err(error).context("POP3 STLS handshake failed"),
            Err(_) => anyhow::bail!("POP3 STLS handshake timed out"),
        }
    }

    async fn auth(&mut self, args: &[&str]) -> Result<Flow> {
        let Some(mechanism) = args.first() else {
            // RFC 5034: an empty AUTH lists the mechanisms.
            let list = if self.password_login_allowed() {
                "PLAIN\r\n"
            } else {
                ""
            };
            self.send(format!("+OK\r\n{list}.\r\n").as_bytes()).await?;
            return Ok(Flow::Continue);
        };
        if !mechanism.eq_ignore_ascii_case("PLAIN") {
            return self.err("Unsupported mechanism").await;
        }
        if !self.password_login_allowed() {
            return self.err("[AUTH] TLS required before authentication").await;
        }
        let encoded = match args.get(1) {
            Some(initial) => (*initial).to_string(),
            None => {
                self.send(b"+ \r\n").await?;
                // Same idle limit as an unauthenticated command, so a silent
                // client cannot hold a session slot.
                match timeout(UNAUTHENTICATED_TIMEOUT, read_line(&mut self.reader)).await {
                    Ok(Ok(Some(Some(line)))) => String::from_utf8_lossy(&line).trim().to_string(),
                    Ok(Ok(Some(None))) => return self.err("Invalid response").await,
                    Ok(Ok(None)) => return Ok(Flow::Close),
                    Ok(Err(error)) => return Err(error.into()),
                    Err(_) => {
                        self.send(b"-ERR Idle timeout\r\n").await?;
                        return Ok(Flow::Close);
                    }
                }
            }
        };
        if encoded == "*" {
            return self.err("Authentication cancelled").await;
        }
        let Ok(decoded) = BASE64.decode(encoded.trim()) else {
            return self.err("Invalid base64").await;
        };
        let mut parts = decoded.split(|&b| b == 0);
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(authzid), Some(authcid), Some(password), None) => {
                let (authzid, authcid, password) = (
                    String::from_utf8_lossy(authzid).into_owned(),
                    String::from_utf8_lossy(authcid).into_owned(),
                    String::from_utf8_lossy(password).into_owned(),
                );
                if !authzid.is_empty() && !authzid.eq_ignore_ascii_case(&authcid) {
                    return self
                        .err("[AUTH] Authorization identity not permitted")
                        .await;
                }
                self.login(&authcid, &password).await
            }
            _ => self.err("Malformed PLAIN response").await,
        }
    }

    async fn login(&mut self, user: &str, password: &str) -> Result<Flow> {
        if !self.password_login_allowed() {
            return self.err("[AUTH] TLS required before authentication").await;
        }
        let ip = self.peer.map(|peer| peer.ip());
        if let Some(remaining) = ip.and_then(crate::auth::auth_block_remaining) {
            return self
                .err(&format!(
                    "[AUTH] Too many failed attempts; try again in {} seconds",
                    remaining.as_secs().max(1)
                ))
                .await;
        }
        let mailbox = match authenticate_password(Some(&self.db_path), user, password).await {
            PasswordAuthResult::Success(mailbox) => mailbox,
            PasswordAuthResult::Rejected => {
                if let Some(ip) = ip {
                    crate::auth::record_auth_failure(ip);
                }
                return self.err("[AUTH] Authentication failed").await;
            }
            PasswordAuthResult::Unavailable { .. } => {
                return self.err("[SYS/TEMP] Authentication unavailable").await;
            }
        };
        if let Some(ip) = ip {
            crate::auth::reset_auth_failures(ip);
        }
        let address = mailbox.address.to_ascii_lowercase();
        let Some((local, domain)) = address
            .rsplit_once('@')
            .map(|(l, d)| (l.to_string(), d.to_string()))
        else {
            return self.err("[AUTH] Authentication failed").await;
        };
        let Some(lock) = MailboxLock::acquire(&address) else {
            return self
                .err("[IN-USE] Mailbox is locked by another session")
                .await;
        };
        let root = self.mail_root.clone();
        let (d, l) = (domain.clone(), local.clone());
        let loaded = tokio::task::spawn_blocking(move || {
            imap_state::load_folder(std::path::Path::new(&root), &d, &l, "INBOX")
        })
        .await;
        let Ok(Ok((folder, mut messages))) = loaded else {
            return self.err("[SYS/TEMP] Cannot open mailbox").await;
        };
        // Messages the IMAP side flagged \Deleted are already gone to POP3.
        messages.retain(|m| !m.flags.iter().any(|f| f.eq_ignore_ascii_case("\\Deleted")));
        messages.sort_by_key(|m| m.uid);
        let count = messages.len();
        self.mailbox = Some(Transaction {
            _lock: lock,
            domain,
            local,
            uidvalidity: folder.uidvalidity,
            messages,
            deleted: HashSet::new(),
        });
        self.ok(&format!("Logged in, {count} messages")).await
    }

    async fn listing(&mut self, command: &str, args: &[&str]) -> Result<Flow> {
        let tx = self.mailbox.as_ref().unwrap();
        let line = |index: usize, message: &Message| -> String {
            if command == "LIST" {
                format!("{} {}", index + 1, message.size)
            } else {
                format!("{} {}.{}", index + 1, tx.uidvalidity, message.uid)
            }
        };
        if let Some(number) = args.first() {
            return match tx.index(number) {
                Some(index) if args.len() == 1 => {
                    let text = line(index, &tx.messages[index]);
                    self.ok(&text).await
                }
                _ => self.err("No such message").await,
            };
        }
        let mut text = format!("+OK {} messages\r\n", tx.live().count());
        for (index, message) in tx.live() {
            text.push_str(&line(index, message));
            text.push_str("\r\n");
        }
        text.push_str(".\r\n");
        self.send(text.as_bytes()).await?;
        Ok(Flow::Continue)
    }

    async fn retrieve(&mut self, command: &str, args: &[&str]) -> Result<Flow> {
        let tx = self.mailbox.as_ref().unwrap();
        let (number, top_lines) = match (command, args) {
            ("RETR", [n]) => (*n, None),
            ("TOP", [n, lines]) => match lines.parse::<usize>() {
                Ok(lines) => (*n, Some(lines)),
                Err(_) => return self.err("Invalid line count").await,
            },
            _ => return self.err("Invalid arguments").await,
        };
        let Some(index) = tx.index(number) else {
            return self.err("No such message").await;
        };
        let message = &tx.messages[index];
        if message.size > MAX_MESSAGE_BYTES {
            return self.err("[SYS/PERM] Message too large").await;
        }
        let Ok(raw) = tokio::fs::read(&message.path).await else {
            return self.err("[SYS/TEMP] Cannot read message").await;
        };
        let lines = message_lines(&raw);
        let selected: Vec<&[u8]> = match top_lines {
            None => lines,
            Some(limit) => {
                let blank = lines
                    .iter()
                    .position(|l| l.is_empty())
                    .unwrap_or(lines.len());
                lines
                    .into_iter()
                    .take(blank.saturating_add(1).saturating_add(limit))
                    .collect()
            }
        };
        let mut out = format!("+OK {} octets\r\n", raw.len()).into_bytes();
        out.extend(encode_lines(selected.into_iter()));
        self.send(&out).await?;
        Ok(Flow::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, duplex};

    const LOOPBACK: &str = "127.0.0.1:5000";

    struct Env {
        _td: tempfile::TempDir,
        root: String,
        db: String,
        /// Unique per test: the mailbox lock is process-wide.
        local: String,
    }

    impl Env {
        fn login(&self) -> String {
            format!("USER {}@example.test\r\nPASS password\r\n", self.local)
        }
    }

    fn unique_user() -> String {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        format!(
            "u{}@example.test",
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }

    fn setup(user: &str, messages: &[&[u8]]) -> Env {
        let td = tempfile::tempdir().unwrap();
        let root = td.path().join("mail");
        let db = td.path().join("rmail.db");
        rmail_common::db::init_db(&db).unwrap();
        rmail_common::db::add_mailbox(&db, user, Some("plain:password"), None, None).unwrap();
        let (local, domain) = user.split_once('@').unwrap();
        imap_state::init_account(&root, domain, local).unwrap();
        for message in messages {
            imap_state::deliver_message(&root, domain, local, message).unwrap();
        }
        Env {
            root: root.display().to_string(),
            db: db.display().to_string(),
            local: local.to_string(),
            _td: td,
        }
    }

    const M1: &[u8] = b"Subject: one\r\n\r\nline1\r\n.dot line\r\nlast\r\n";
    const M2: &[u8] = b"Subject: two\nLF only\n\nbody\n";

    fn two() -> Env {
        setup(&unique_user(), &[M1, M2])
    }

    async fn run_session(env: &Env, peer: &str, input: &str) -> String {
        let (mut client, server) = duplex(1 << 22);
        let task = tokio::spawn(serve(
            Box::new(server),
            Some(peer.parse().unwrap()),
            None,
            false,
            env.root.clone(),
            env.db.clone(),
        ));
        client.write_all(input.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        task.await.unwrap().unwrap();
        String::from_utf8(out).unwrap()
    }

    fn inbox_count(env: &Env) -> usize {
        imap_state::load_folder(
            std::path::Path::new(&env.root),
            "example.test",
            &env.local,
            "INBOX",
        )
        .unwrap()
        .1
        .len()
    }

    #[test]
    fn lines_are_dot_stuffed_and_crlf_normalized() {
        let encoded = encode_lines(message_lines(b"a\n.b\r\n..c\nlast").into_iter());
        assert_eq!(encoded, b"a\r\n..b\r\n...c\r\nlast\r\n.\r\n");
        assert_eq!(message_lines(b""), Vec::<&[u8]>::new());
        assert_eq!(message_lines(b"x\r\n"), vec![&b"x"[..]]);
        assert_eq!(encode_lines(std::iter::empty()), b".\r\n");
    }

    #[tokio::test(start_paused = true)]
    async fn silent_auth_continuation_times_out() {
        let env = two();
        let (mut client, server) = duplex(1 << 16);
        let task = tokio::spawn(serve(
            Box::new(server),
            Some(LOOPBACK.parse().unwrap()),
            None,
            false,
            env.root.clone(),
            env.db.clone(),
        ));
        client.write_all(b"AUTH PLAIN\r\n").await.unwrap();
        // The client stays silent; paused time advances to the idle limit.
        let mut out = Vec::new();
        timeout(Duration::from_secs(10 * 60), client.read_to_end(&mut out))
            .await
            .expect("session never timed out")
            .unwrap();
        task.await.unwrap().unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.ends_with("+ \r\n-ERR Idle timeout\r\n"), "{out}");
    }

    #[tokio::test]
    async fn login_and_listing() {
        let env = two();
        let login = env.login();
        let out = run_session(
            &env,
            LOOPBACK,
            &format!(
                "{login}STAT\r\nLIST\r\nLIST 2\r\nLIST 3\r\nUIDL\r\nUIDL 1\r\nNOOP\r\nQUIT\r\n"
            ),
        )
        .await;
        let sizes = (M1.len(), M2.len());
        assert!(
            out.starts_with(
                "+OK rMail POP3 ready\r\n+OK Send PASS\r\n+OK Logged in, 2 messages\r\n"
            ),
            "{out}"
        );
        assert!(
            out.contains(&format!("+OK 2 {}\r\n", sizes.0 + sizes.1)),
            "{out}"
        );
        assert!(
            out.contains(&format!(
                "+OK 2 messages\r\n1 {}\r\n2 {}\r\n.\r\n",
                sizes.0, sizes.1
            )),
            "{out}"
        );
        assert!(out.contains(&format!("+OK 2 {}\r\n", sizes.1)), "{out}");
        assert!(out.contains("-ERR No such message\r\n"), "{out}");
        let uidls: Vec<&str> = out
            .lines()
            .filter(|l| {
                l.starts_with("1 ") && l.contains('.') && !l.ends_with(&sizes.0.to_string())
            })
            .collect();
        assert!(!uidls.is_empty(), "UIDL lines: {out}");
        assert!(out.ends_with("+OK Bye\r\n"), "{out}");
    }

    #[tokio::test]
    async fn retr_and_top_encode_messages() {
        let env = two();
        let login = env.login();
        let out = run_session(
            &env,
            LOOPBACK,
            &format!(
                "{login}RETR 1\r\nRETR 2\r\nTOP 1 1\r\nTOP 2 0\r\nTOP 1 x\r\nRETR 9\r\nQUIT\r\n"
            ),
        )
        .await;
        assert!(
            out.contains(&format!(
                "+OK {} octets\r\nSubject: one\r\n\r\nline1\r\n..dot line\r\nlast\r\n.\r\n",
                M1.len()
            )),
            "{out}"
        );
        // LF-only storage is sent with CRLF.
        assert!(
            out.contains(&format!(
                "+OK {} octets\r\nSubject: two\r\nLF only\r\n\r\nbody\r\n.\r\n",
                M2.len()
            )),
            "{out}"
        );
        // TOP: headers, blank line, then N body lines.
        assert!(out.contains("Subject: one\r\n\r\nline1\r\n.\r\n"), "{out}");
        assert!(
            out.contains("Subject: two\r\nLF only\r\n\r\n.\r\n"),
            "{out}"
        );
        assert!(out.contains("-ERR Invalid line count\r\n"), "{out}");
        assert!(out.contains("-ERR No such message\r\n"), "{out}");
    }

    #[tokio::test]
    async fn deletions_apply_only_on_quit() {
        let env = two();
        let login = env.login();
        // No QUIT: the connection just drops, nothing is removed.
        let out = run_session(&env, LOOPBACK, &format!("{login}DELE 1\r\nSTAT\r\n")).await;
        assert!(out.contains(&format!("+OK 1 {}\r\n", M2.len())), "{out}");
        assert_eq!(inbox_count(&env), 2);
        // RSET undoes marks.
        let out = run_session(
            &env,
            LOOPBACK,
            &format!("{login}DELE 1\r\nRSET\r\nDELE 1\r\nDELE 1\r\nRETR 1\r\nRSET\r\nQUIT\r\n"),
        )
        .await;
        assert!(out.matches("-ERR No such message").count() == 2, "{out}");
        assert_eq!(inbox_count(&env), 2);
        // QUIT in the transaction state removes the marked messages.
        let out = run_session(&env, LOOPBACK, &format!("{login}DELE 1\r\nQUIT\r\n")).await;
        assert!(out.ends_with("+OK Bye\r\n"), "{out}");
        assert_eq!(inbox_count(&env), 1);
        let out = run_session(&env, LOOPBACK, &format!("{login}STAT\r\nQUIT\r\n")).await;
        assert!(out.contains(&format!("+OK 1 {}\r\n", M2.len())), "{out}");
    }

    #[tokio::test]
    async fn imap_deleted_messages_are_hidden() {
        let env = two();
        let login = env.login();
        let root = std::path::Path::new(&env.root);
        let uid = imap_state::load_folder(root, "example.test", &env.local, "INBOX")
            .unwrap()
            .1[0]
            .uid;
        imap_state::set_uid_flags(
            root,
            "example.test",
            &env.local,
            "INBOX",
            uid,
            vec!["\\Deleted".into()],
        )
        .unwrap();
        let out = run_session(&env, LOOPBACK, &format!("{login}STAT\r\nQUIT\r\n")).await;
        assert!(out.contains(&format!("+OK 1 {}\r\n", M2.len())), "{out}");
    }

    #[tokio::test]
    async fn authentication_rules() {
        let env = two();
        let login = env.login();
        let out = run_session(
            &env,
            LOOPBACK,
            &format!(
                "STAT\r\nPASS x\r\nUSER {}@example.test\r\nPASS wrong\r\nSTAT\r\nQUIT\r\n",
                env.local
            ),
        )
        .await;
        assert!(out.contains("-ERR Authenticate first\r\n"), "{out}");
        assert!(out.contains("-ERR Send USER first\r\n"), "{out}");
        assert!(
            out.contains("-ERR [AUTH] Authentication failed\r\n"),
            "{out}"
        );
        // Passwords are taken verbatim: runs of spaces, tabs, and leading
        // or trailing spaces all survive.
        let spaced = setup("sp@example.test", &[]);
        rmail_common::db::add_mailbox(
            &spaced.db,
            "sp@example.test",
            Some("plain: pass  w\tord "),
            None,
            None,
        )
        .unwrap();
        let out = run_session(
            &spaced,
            LOOPBACK,
            "USER sp@example.test\r\nPASS  pass  w\tord \r\nQUIT\r\n",
        )
        .await;
        assert!(out.contains("+OK Logged in, 0 messages"), "{out}");

        // Password login is refused off loopback without TLS.
        let out = run_session(
            &env,
            "203.0.113.5:5000",
            &format!("CAPA\r\n{login}STLS\r\nAUTH PLAIN\r\nQUIT\r\n"),
        )
        .await;
        assert!(!out.contains("SASL"), "{out}");
        assert!(!out.contains("STLS\r\n.\r\n"), "{out}");
        assert!(
            out.contains("-ERR [AUTH] TLS required before authentication\r\n"),
            "{out}"
        );
        assert!(out.contains("-ERR TLS is not available\r\n"), "{out}");
    }

    #[tokio::test]
    async fn auth_plain_works_with_and_without_initial_response() {
        let env = two();
        let blob = BASE64.encode(format!("\0{}@example.test\0password", env.local));
        let out = run_session(
            &env,
            LOOPBACK,
            &format!("AUTH\r\nAUTH PLAIN {blob}\r\nSTAT\r\nQUIT\r\n"),
        )
        .await;
        assert!(out.contains("+OK\r\nPLAIN\r\n.\r\n"), "{out}");
        assert!(out.contains("+OK Logged in, 2 messages"), "{out}");
        let out = run_session(
            &env,
            LOOPBACK,
            &format!("AUTH PLAIN\r\n{blob}\r\nSTAT\r\nQUIT\r\n"),
        )
        .await;
        assert!(out.contains("+ \r\n+OK Logged in, 2 messages"), "{out}");
        let out = run_session(
            &env,
            LOOPBACK,
            "AUTH PLAIN *\r\nAUTH CRAM-MD5\r\nAUTH PLAIN !!!\r\nQUIT\r\n",
        )
        .await;
        assert!(out.contains("-ERR Authentication cancelled"), "{out}");
        assert!(out.contains("-ERR Unsupported mechanism"), "{out}");
        assert!(out.contains("-ERR Invalid base64"), "{out}");
        let other = BASE64.encode(format!(
            "someone@else.test\0{}@example.test\0password",
            env.local
        ));
        let out = run_session(&env, LOOPBACK, &format!("AUTH PLAIN {other}\r\nQUIT\r\n")).await;
        assert!(
            out.contains("-ERR [AUTH] Authorization identity not permitted"),
            "{out}"
        );
    }

    async fn read_reply(reader: &mut (impl AsyncBufReadExt + Unpin)) -> String {
        let mut line = String::new();
        timeout(Duration::from_secs(10), reader.read_line(&mut line))
            .await
            .expect("reply in time")
            .unwrap();
        line
    }

    #[tokio::test]
    async fn a_mailbox_can_only_be_open_once() {
        let env = setup("lock@example.test", &[M1]);
        let open = |env: &Env| {
            let (client, server) = duplex(1 << 20);
            let task = tokio::spawn(serve(
                Box::new(server),
                Some(LOOPBACK.parse().unwrap()),
                None,
                false,
                env.root.clone(),
                env.db.clone(),
            ));
            (BufReader::new(client), task)
        };
        let (mut first, first_task) = open(&env);
        read_reply(&mut first).await;
        first
            .get_mut()
            .write_all(b"USER lock@example.test\r\nPASS password\r\n")
            .await
            .unwrap();
        read_reply(&mut first).await;
        assert!(read_reply(&mut first).await.starts_with("+OK Logged in"));

        let (mut second, second_task) = open(&env);
        read_reply(&mut second).await;
        second
            .get_mut()
            .write_all(b"USER lock@example.test\r\nPASS password\r\n")
            .await
            .unwrap();
        read_reply(&mut second).await;
        assert!(read_reply(&mut second).await.starts_with("-ERR [IN-USE]"));
        second.get_mut().write_all(b"QUIT\r\n").await.unwrap();
        second_task.await.unwrap().unwrap();

        // Closing the first session releases the lock.
        first.get_mut().write_all(b"QUIT\r\n").await.unwrap();
        assert!(read_reply(&mut first).await.starts_with("+OK Bye"));
        first_task.await.unwrap().unwrap();
        let out = run_session(
            &env,
            LOOPBACK,
            "USER lock@example.test\r\nPASS password\r\nQUIT\r\n",
        )
        .await;
        assert!(out.contains("+OK Logged in, 1 messages"), "{out}");
    }

    #[derive(Debug)]
    struct AcceptAnyCertificate;

    impl tokio_rustls::rustls::client::ServerCertVerifier for AcceptAnyCertificate {
        fn verify_server_cert(
            &self,
            _end_entity: &tokio_rustls::rustls::Certificate,
            _intermediates: &[tokio_rustls::rustls::Certificate],
            _server_name: &tokio_rustls::rustls::ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: std::time::SystemTime,
        ) -> Result<tokio_rustls::rustls::client::ServerCertVerified, tokio_rustls::rustls::Error>
        {
            Ok(tokio_rustls::rustls::client::ServerCertVerified::assertion())
        }
    }

    #[tokio::test]
    async fn stls_upgrades_and_then_allows_login() {
        let env = two();
        let login = env.login();
        let (cert, key) = rmail_common::test_support::localhost_cert();
        let tls = crate::tls::load_tls_context(cert, key).unwrap();
        let (client, server) = duplex(1 << 20);
        let task = tokio::spawn(serve(
            Box::new(server),
            Some("203.0.113.9:5000".parse().unwrap()),
            Some(tls),
            false,
            env.root.clone(),
            env.db.clone(),
        ));
        let mut plain = BufReader::new(client);
        assert!(
            read_reply(&mut plain)
                .await
                .starts_with("+OK rMail POP3 ready")
        );
        plain.get_mut().write_all(b"CAPA\r\n").await.unwrap();
        let mut caps = String::new();
        loop {
            let line = read_reply(&mut plain).await;
            caps.push_str(&line);
            if line == ".\r\n" {
                break;
            }
        }
        assert!(
            caps.contains("STLS\r\n") && !caps.contains("SASL"),
            "{caps}"
        );
        plain
            .get_mut()
            .write_all(b"USER user@example.test\r\nPASS password\r\n")
            .await
            .unwrap();
        read_reply(&mut plain).await;
        assert!(
            read_reply(&mut plain)
                .await
                .starts_with("-ERR [AUTH] TLS required")
        );
        plain.get_mut().write_all(b"STLS\r\n").await.unwrap();
        assert!(read_reply(&mut plain).await.starts_with("+OK Begin TLS"));

        let mut config = tokio_rustls::rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(tokio_rustls::rustls::RootCertStore::empty())
            .with_no_client_auth();
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(AcceptAnyCertificate));
        let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(
                tokio_rustls::rustls::ServerName::try_from("localhost").unwrap(),
                plain.into_inner(),
            )
            .await
            .expect("TLS handshake");
        let mut secure = BufReader::new(stream);
        secure
            .get_mut()
            .write_all(format!("{login}STAT\r\nSTLS\r\nQUIT\r\n").as_bytes())
            .await
            .unwrap();
        assert!(read_reply(&mut secure).await.starts_with("+OK Send PASS"));
        assert!(
            read_reply(&mut secure)
                .await
                .starts_with("+OK Logged in, 2")
        );
        assert!(read_reply(&mut secure).await.starts_with("+OK 2 "));
        assert!(
            read_reply(&mut secure)
                .await
                .starts_with("-ERR STLS is not available now")
        );
        assert!(read_reply(&mut secure).await.starts_with("+OK Bye"));
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn over_long_lines_are_rejected_without_ending_the_session() {
        let env = two();
        let out = run_session(
            &env,
            LOOPBACK,
            &format!("{}\r\nNOOP\r\nQUIT\r\n", "A".repeat(MAX_LINE_BYTES * 3)),
        )
        .await;
        assert!(
            out.contains("-ERR Command line too long\r\n+OK \r\n+OK Bye"),
            "{out}"
        );
    }
}
