//! ManageSieve (RFC 5804): lets mail clients upload and activate the Sieve
//! scripts that `rmail_smtpd` runs at delivery. Served by the IMAP daemon so
//! it shares its TLS certificate, hot reload, shutdown and connection limits.
//!
//! Authentication is SASL PLAIN, offered only over TLS (or from loopback).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use once_cell::sync::Lazy;
use rmail_common::auth::{PasswordAuthResult, authenticate_password};
use rmail_common::runtime::GracefulShutdown;
use rmail_common::throttle::AuthThrottle;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::time::timeout;

use crate::RawStream;
use crate::listener::accept_connection_from;
use crate::tls::TlsContext;

const MAX_LINE_BYTES: usize = 8 * 1024;
const MAX_SCRIPT_BYTES: usize = 1 << 20;
const MAX_SCRIPTS: usize = 20;
const MAX_NAME_CHARS: usize = 128;
const MAX_ARGS: usize = 8;
const UNAUTHENTICATED_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const AUTHENTICATED_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

static AUTH_THROTTLE: Lazy<AuthThrottle> = Lazy::new(AuthThrottle::default);

type Stream = BufReader<Box<dyn RawStream + Send>>;

#[derive(Clone)]
pub(crate) struct ManageSieveContext {
    pub db_path: String,
    pub tls: watch::Receiver<Option<Arc<TlsContext>>>,
    pub session_limit: Arc<Semaphore>,
    pub connection_rate_limit: usize,
    pub shutdown: GracefulShutdown,
}

pub(crate) async fn run_listener(
    addr: String,
    listener: TcpListener,
    ctx: ManageSieveContext,
) -> Result<()> {
    imap_log!("info", "managesieve_listener_started", { "address": addr });
    let mut shutdown_signal = ctx.shutdown.subscribe();
    loop {
        if *shutdown_signal.borrow() {
            return Ok(());
        }
        let (mut stream, peer) = tokio::select! {
            changed = shutdown_signal.changed() => {
                changed.context("waiting for ManageSieve shutdown signal")?;
                return Ok(());
            }
            accepted = listener.accept() => accepted?,
        };
        if !accept_connection_from(peer.ip(), ctx.connection_rate_limit) {
            let _ = stream
                .write_all(b"BYE \"Connection rate limit exceeded\"\r\n")
                .await;
            continue;
        }
        let Ok(permit) = ctx.session_limit.clone().try_acquire_owned() else {
            let _ = stream
                .write_all(b"BYE \"Too many concurrent sessions\"\r\n")
                .await;
            continue;
        };
        let session = ctx.shutdown.start_session();
        let tls = ctx.tls.borrow().clone();
        let db_path = ctx.db_path.clone();
        tokio::spawn(async move {
            let _session = session;
            let _permit = permit;
            if let Err(error) = serve(Box::new(stream), Some(peer), tls, db_path).await {
                imap_log!("error", "managesieve_session_failed", { "peer": peer.to_string(), "error": error.to_string() });
            }
        });
    }
}

#[derive(Debug)]
enum ProtoError {
    /// Malformed command; the session continues.
    Syntax(&'static str),
    /// A literal or line over the limits; the session ends.
    TooLarge,
    Closed,
    Io(std::io::Error),
}

impl From<std::io::Error> for ProtoError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// One command argument: a string (quoted or literal) or a bare number/atom.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Arg {
    Str(Vec<u8>),
    Atom(String),
}

impl Arg {
    fn text(&self) -> Option<String> {
        match self {
            Self::Str(bytes) => String::from_utf8(bytes.clone()).ok(),
            Self::Atom(atom) => Some(atom.clone()),
        }
    }
}

async fn read_line(reader: &mut Stream) -> Result<Vec<u8>, ProtoError> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Err(ProtoError::Closed);
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(index) => {
                line.extend_from_slice(&available[..index]);
                reader.consume(index + 1);
                break;
            }
            None => {
                let len = available.len();
                line.extend_from_slice(available);
                reader.consume(len);
            }
        }
        if line.len() > MAX_LINE_BYTES {
            return Err(ProtoError::TooLarge);
        }
    }
    if line.len() > MAX_LINE_BYTES {
        return Err(ProtoError::TooLarge);
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(line)
}

/// Tokens of one line segment, plus the size of a trailing `{n+}` literal.
fn tokenize(line: &[u8]) -> Result<(Vec<Arg>, Option<usize>), ProtoError> {
    let mut args = Vec::new();
    let mut i = 0;
    while i < line.len() {
        match line[i] {
            b' ' | b'\t' => i += 1,
            b'"' => {
                let mut out = Vec::new();
                i += 1;
                loop {
                    match line.get(i) {
                        None => return Err(ProtoError::Syntax("unterminated string")),
                        Some(b'"') => {
                            i += 1;
                            break;
                        }
                        Some(b'\\') => match line.get(i + 1) {
                            Some(&c @ (b'"' | b'\\')) => {
                                out.push(c);
                                i += 2;
                            }
                            _ => return Err(ProtoError::Syntax("invalid escape")),
                        },
                        Some(&c) => {
                            out.push(c);
                            i += 1;
                        }
                    }
                }
                args.push(Arg::Str(out));
            }
            b'{' => {
                let rest = &line[i + 1..];
                let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
                let tail = &rest[digits..];
                if digits == 0 || tail != b"+}" {
                    return Err(ProtoError::Syntax(
                        "literals must be non-synchronizing {n+}",
                    ));
                }
                let size: usize = std::str::from_utf8(&rest[..digits])
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .ok_or(ProtoError::TooLarge)?;
                return Ok((args, Some(size)));
            }
            _ => {
                let start = i;
                while i < line.len() && !matches!(line[i], b' ' | b'\t' | b'"' | b'{') {
                    i += 1;
                }
                args.push(Arg::Atom(
                    String::from_utf8_lossy(&line[start..i]).into_owned(),
                ));
            }
        }
        if args.len() > MAX_ARGS {
            return Err(ProtoError::Syntax("too many arguments"));
        }
    }
    Ok((args, None))
}

/// All tokens of the next command, reading any literals it carries.
async fn read_tokens(reader: &mut Stream) -> Result<Vec<Arg>, ProtoError> {
    let mut all = Vec::new();
    let mut literal_budget = MAX_SCRIPT_BYTES + 1024;
    loop {
        let line = read_line(reader).await?;
        let (mut args, literal) = tokenize(&line)?;
        all.append(&mut args);
        let Some(size) = literal else {
            return Ok(all);
        };
        if size > literal_budget {
            return Err(ProtoError::TooLarge);
        }
        literal_budget -= size;
        let mut data = vec![0u8; size];
        reader.read_exact(&mut data).await?;
        all.push(Arg::Str(data));
        if all.len() > MAX_ARGS {
            return Err(ProtoError::Syntax("too many arguments"));
        }
    }
}

fn quote(text: &str) -> String {
    let clean: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    format!("\"{}\"", clean.replace('\\', "\\\\").replace('"', "\\\""))
}

fn valid_script_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= MAX_NAME_CHARS
        && !name.chars().any(|c| c.is_control())
}

struct Session {
    reader: Stream,
    peer: Option<SocketAddr>,
    tls: Option<Arc<TlsContext>>,
    encrypted: bool,
    db_path: String,
    user: Option<String>,
}

enum Flow {
    Continue,
    Close,
}

pub(crate) async fn serve(
    stream: Box<dyn RawStream + Send>,
    peer: Option<SocketAddr>,
    tls: Option<Arc<TlsContext>>,
    db_path: String,
) -> Result<()> {
    let mut session = Session {
        reader: BufReader::new(stream),
        peer,
        tls,
        encrypted: false,
        db_path,
        user: None,
    };
    session.send_capabilities("rMail ManageSieve ready").await?;
    loop {
        let idle = if session.user.is_some() {
            AUTHENTICATED_TIMEOUT
        } else {
            UNAUTHENTICATED_TIMEOUT
        };
        let tokens = match timeout(idle, read_tokens(&mut session.reader)).await {
            Err(_) => {
                session.send("BYE \"Idle timeout\"\r\n").await?;
                return Ok(());
            }
            Ok(Ok(tokens)) => tokens,
            Ok(Err(ProtoError::Syntax(message))) => {
                session.send(&format!("NO {}\r\n", quote(message))).await?;
                continue;
            }
            Ok(Err(ProtoError::TooLarge)) => {
                session
                    .send("BYE (QUOTA/MAXSIZE) \"Command too large\"\r\n")
                    .await?;
                return Ok(());
            }
            Ok(Err(ProtoError::Closed)) => return Ok(()),
            Ok(Err(ProtoError::Io(error))) => return Err(error.into()),
        };
        let Some(first) = tokens.first() else {
            session.send("NO \"Empty command\"\r\n").await?;
            continue;
        };
        let name = first.text().unwrap_or_default().to_ascii_uppercase();
        let args = &tokens[1..];
        match session.dispatch(&name, args).await? {
            Flow::Continue => {}
            Flow::Close => return Ok(()),
        }
    }
}

impl Session {
    async fn send(&mut self, text: &str) -> Result<()> {
        self.reader.get_mut().write_all(text.as_bytes()).await?;
        self.reader.get_mut().flush().await?;
        Ok(())
    }

    fn plaintext_auth_allowed(&self) -> bool {
        self.encrypted || self.peer.is_some_and(|peer| peer.ip().is_loopback())
    }

    async fn send_capabilities(&mut self, ok_text: &str) -> Result<()> {
        let mut text = String::from("\"IMPLEMENTATION\" \"rMail\"\r\n");
        text.push_str(&format!(
            "\"SIEVE\" {}\r\n",
            quote(&rmail_sieve::SUPPORTED_EXTENSIONS.join(" "))
        ));
        text.push_str(&format!(
            "\"SASL\" {}\r\n",
            quote(if self.plaintext_auth_allowed() {
                "PLAIN"
            } else {
                ""
            })
        ));
        if !self.encrypted && self.tls.is_some() {
            text.push_str("\"STARTTLS\"\r\n");
        }
        text.push_str("\"VERSION\" \"1.0\"\r\n");
        if let Some(user) = &self.user {
            text.push_str(&format!("\"OWNER\" {}\r\n", quote(user)));
        }
        text.push_str(&format!("OK {}\r\n", quote(ok_text)));
        self.send(&text).await
    }

    async fn dispatch(&mut self, name: &str, args: &[Arg]) -> Result<Flow> {
        match name {
            "CAPABILITY" => {
                self.send_capabilities("Capability completed").await?;
            }
            "NOOP" => {
                let reply = match args.first().and_then(Arg::text) {
                    Some(tag) => format!("OK (TAG {}) \"Done\"\r\n", quote(&tag)),
                    None => "OK \"Done\"\r\n".to_string(),
                };
                self.send(&reply).await?;
            }
            "LOGOUT" => {
                self.send("OK \"Logout completed\"\r\n").await?;
                return Ok(Flow::Close);
            }
            "STARTTLS" => self.starttls().await?,
            "AUTHENTICATE" => self.authenticate(args).await?,
            "UNAUTHENTICATE" => {
                if self.user.take().is_some() {
                    self.send("OK \"Unauthenticated\"\r\n").await?;
                } else {
                    self.send("NO \"Not authenticated\"\r\n").await?;
                }
            }
            "HAVESPACE" | "PUTSCRIPT" | "LISTSCRIPTS" | "SETACTIVE" | "GETSCRIPT"
            | "DELETESCRIPT" | "RENAMESCRIPT" | "CHECKSCRIPT" => {
                let Some(user) = self.user.clone() else {
                    self.send("NO \"Authenticate first\"\r\n").await?;
                    return Ok(Flow::Continue);
                };
                let reply = script_command(&self.db_path, &user, name, args).await;
                self.send(&reply).await?;
            }
            _ => self.send("NO \"Unknown command\"\r\n").await?,
        }
        Ok(Flow::Continue)
    }

    async fn starttls(&mut self) -> Result<()> {
        if self.encrypted {
            return self.send("NO \"TLS is already active\"\r\n").await;
        }
        let Some(tls) = self.tls.clone() else {
            return self.send("NO \"TLS is not available\"\r\n").await;
        };
        self.send("OK \"Begin TLS negotiation now\"\r\n").await?;
        // Nothing buffered may be carried across the handshake.
        let (placeholder, _) = tokio::io::duplex(1);
        let plain =
            std::mem::replace(&mut self.reader, BufReader::new(Box::new(placeholder))).into_inner();
        match timeout(TLS_HANDSHAKE_TIMEOUT, tls.acceptor.accept(plain)).await {
            Ok(Ok(stream)) => {
                self.reader = BufReader::new(Box::new(stream));
                self.encrypted = true;
                self.send_capabilities("TLS negotiation completed").await
            }
            Ok(Err(error)) => Err(error).context("ManageSieve TLS handshake failed"),
            Err(_) => anyhow::bail!("ManageSieve TLS handshake timed out"),
        }
    }

    async fn authenticate(&mut self, args: &[Arg]) -> Result<()> {
        if self.user.is_some() {
            return self.send("NO \"Already authenticated\"\r\n").await;
        }
        let Some(mechanism) = args.first().and_then(Arg::text) else {
            return self.send("NO \"AUTHENTICATE needs a mechanism\"\r\n").await;
        };
        if !mechanism.eq_ignore_ascii_case("PLAIN") {
            return self
                .send("NO \"Unsupported authentication mechanism\"\r\n")
                .await;
        }
        if !self.plaintext_auth_allowed() {
            return self
                .send("NO (ENCRYPT-NEEDED) \"Start TLS before authenticating\"\r\n")
                .await;
        }
        let ip: Option<IpAddr> = self.peer.map(|peer| peer.ip());
        if let Some(remaining) = ip.and_then(|ip| AUTH_THROTTLE.blocked_for(ip)) {
            return self
                .send(&format!(
                    "NO \"Too many failed attempts; try again in {} seconds\"\r\n",
                    remaining.as_secs().max(1)
                ))
                .await;
        }
        let initial = match args.get(1) {
            Some(arg) => arg.clone(),
            None => {
                self.send("\"\"\r\n").await?;
                match read_tokens(&mut self.reader).await {
                    Ok(mut tokens) if tokens.len() == 1 => tokens.remove(0),
                    _ => {
                        return self
                            .send("NO \"Invalid authentication response\"\r\n")
                            .await;
                    }
                }
            }
        };
        let Some(encoded) = initial.text() else {
            return self
                .send("NO \"Invalid authentication response\"\r\n")
                .await;
        };
        if encoded == "*" {
            return self.send("NO \"Authentication cancelled\"\r\n").await;
        }
        let decoded = if encoded.is_empty() || encoded == "=" {
            Vec::new()
        } else {
            match BASE64.decode(encoded.trim()) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return self
                        .send("NO \"Invalid base64 in authentication\"\r\n")
                        .await;
                }
            }
        };
        let mut parts = decoded.split(|&b| b == 0);
        let (authzid, authcid, password) =
            match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some(z), Some(c), Some(p), None) => (
                    String::from_utf8_lossy(z).into_owned(),
                    String::from_utf8_lossy(c).into_owned(),
                    String::from_utf8_lossy(p).into_owned(),
                ),
                _ => return self.send("NO \"Malformed PLAIN response\"\r\n").await,
            };
        match authenticate_password(Some(&self.db_path), &authcid, &password).await {
            PasswordAuthResult::Success(mailbox) => {
                let address = mailbox.address.to_ascii_lowercase();
                if !authzid.is_empty()
                    && !authzid.eq_ignore_ascii_case(&authcid)
                    && !authzid.eq_ignore_ascii_case(&address)
                {
                    return self
                        .send("NO \"Authorization identity not permitted\"\r\n")
                        .await;
                }
                if let Some(ip) = ip {
                    AUTH_THROTTLE.reset(ip);
                }
                self.user = Some(address);
                self.send("OK \"Authentication successful\"\r\n").await
            }
            PasswordAuthResult::Rejected => {
                if let Some(ip) = ip {
                    AUTH_THROTTLE.record_failure(ip);
                }
                self.send("NO \"Authentication failed\"\r\n").await
            }
            PasswordAuthResult::Unavailable { .. } => {
                self.send("NO \"Authentication temporarily unavailable\"\r\n")
                    .await
            }
        }
    }
}

/// Run one of the script commands for `user`; returns the full reply.
async fn script_command(db_path: &str, user: &str, name: &str, args: &[Arg]) -> String {
    {
        let db = db_path.to_string();
        let account = user.to_string();
        let text = |index: usize| args.get(index).and_then(Arg::text);
        let blocking_err = |error: String| format!("NO {}\r\n", quote(&error));
        match name {
            "LISTSCRIPTS" => match listing(&db, &account).await {
                Ok(list) => {
                    let mut out = String::new();
                    for (script, active) in list {
                        out.push_str(&quote(&script));
                        out.push_str(if active { " ACTIVE\r\n" } else { "\r\n" });
                    }
                    out.push_str("OK \"Listscripts completed\"\r\n");
                    out
                }
                Err(error) => blocking_err(error),
            },
            "GETSCRIPT" => {
                let Some(script) = text(0) else {
                    return "NO \"GETSCRIPT needs a script name\"\r\n".to_string();
                };
                let result =
                    run_db(move || rmail_common::db::get_sieve_script(&db, &account, &script))
                        .await;
                match result {
                    Ok(Some(content)) => format!(
                        "{{{}}}\r\n{}\r\nOK \"Getscript completed\"\r\n",
                        content.len(),
                        content
                    ),
                    Ok(None) => {
                        "NO (NONEXISTENT) \"There is no script by that name\"\r\n".to_string()
                    }
                    Err(error) => blocking_err(error),
                }
            }
            "CHECKSCRIPT" => match text(0) {
                Some(source) => match rmail_sieve::Script::parse(&source) {
                    Ok(_) => "OK \"Script is valid\"\r\n".to_string(),
                    Err(error) => format!("NO {}\r\n", quote(&error.to_string())),
                },
                None => "NO \"CHECKSCRIPT needs a script\"\r\n".to_string(),
            },
            "HAVESPACE" => {
                let (Some(script), Some(size)) =
                    (text(0), text(1).and_then(|s| s.parse::<usize>().ok()))
                else {
                    return "NO \"HAVESPACE needs a name and a size\"\r\n".to_string();
                };
                if !valid_script_name(&script) {
                    return "NO \"Invalid script name\"\r\n".to_string();
                }
                if size > MAX_SCRIPT_BYTES {
                    return "NO (QUOTA/MAXSIZE) \"Script is too large\"\r\n".to_string();
                }
                match listing(&db, &account).await {
                    Ok(list)
                        if list.len() >= MAX_SCRIPTS
                            && !list.iter().any(|(name, _)| *name == script) =>
                    {
                        "NO (QUOTA/MAXSCRIPTS) \"Too many scripts\"\r\n".to_string()
                    }
                    Ok(_) => "OK \"Space available\"\r\n".to_string(),
                    Err(error) => blocking_err(error),
                }
            }
            "PUTSCRIPT" => {
                let (Some(script), Some(source)) = (text(0), args.get(1).and_then(Arg::text))
                else {
                    return "NO \"PUTSCRIPT needs a name and a script\"\r\n".to_string();
                };
                if !valid_script_name(&script) {
                    return "NO \"Invalid script name\"\r\n".to_string();
                }
                if source.len() > MAX_SCRIPT_BYTES {
                    return "NO (QUOTA/MAXSIZE) \"Script is too large\"\r\n".to_string();
                }
                if let Err(error) = rmail_sieve::Script::parse(&source) {
                    return format!("NO {}\r\n", quote(&error.to_string()));
                }
                match listing(&db, &account).await {
                    Ok(list)
                        if list.len() >= MAX_SCRIPTS
                            && !list.iter().any(|(name, _)| *name == script) =>
                    {
                        return "NO (QUOTA/MAXSCRIPTS) \"Too many scripts\"\r\n".to_string();
                    }
                    Ok(_) => {}
                    Err(error) => return blocking_err(error),
                }
                match run_db(move || {
                    rmail_common::db::put_sieve_script(&db, &account, &script, &source)
                })
                .await
                {
                    Ok(()) => "OK \"Putscript completed\"\r\n".to_string(),
                    Err(error) => blocking_err(error),
                }
            }
            "SETACTIVE" => {
                let Some(script) = text(0) else {
                    return "NO \"SETACTIVE needs a script name\"\r\n".to_string();
                };
                let target = (!script.is_empty()).then_some(script);
                match run_db(move || {
                    rmail_common::db::set_active_sieve_script(&db, &account, target.as_deref())
                })
                .await
                {
                    Ok(true) => "OK \"Setactive completed\"\r\n".to_string(),
                    Ok(false) => {
                        "NO (NONEXISTENT) \"There is no script by that name\"\r\n".to_string()
                    }
                    Err(error) => blocking_err(error),
                }
            }
            "DELETESCRIPT" => {
                let Some(script) = text(0) else {
                    return "NO \"DELETESCRIPT needs a script name\"\r\n".to_string();
                };
                let list = match listing(&db, &account).await {
                    Ok(list) => list,
                    Err(error) => return blocking_err(error),
                };
                match list.iter().find(|(name, _)| *name == script) {
                    None => "NO (NONEXISTENT) \"There is no script by that name\"\r\n".to_string(),
                    Some((_, true)) => {
                        "NO (ACTIVE) \"Cannot delete the active script\"\r\n".to_string()
                    }
                    Some(_) => match run_db(move || {
                        rmail_common::db::delete_sieve_script(&db, &account, &script)
                    })
                    .await
                    {
                        Ok(_) => "OK \"Deletescript completed\"\r\n".to_string(),
                        Err(error) => blocking_err(error),
                    },
                }
            }
            "RENAMESCRIPT" => {
                let (Some(from), Some(to)) = (text(0), text(1)) else {
                    return "NO \"RENAMESCRIPT needs two names\"\r\n".to_string();
                };
                if !valid_script_name(&to) {
                    return "NO \"Invalid script name\"\r\n".to_string();
                }
                let list = match listing(&db, &account).await {
                    Ok(list) => list,
                    Err(error) => return blocking_err(error),
                };
                if !list.iter().any(|(name, _)| *name == from) {
                    return "NO (NONEXISTENT) \"There is no script by that name\"\r\n".to_string();
                }
                if list.iter().any(|(name, _)| *name == to) {
                    return "NO (ALREADYEXISTS) \"A script with that name already exists\"\r\n"
                        .to_string();
                }
                match run_db(move || {
                    rmail_common::db::rename_sieve_script(&db, &account, &from, &to)
                })
                .await
                {
                    Ok(_) => "OK \"Renamescript completed\"\r\n".to_string(),
                    Err(error) => blocking_err(error),
                }
            }
            _ => "NO \"Unknown command\"\r\n".to_string(),
        }
    }
}

async fn run_db<T, F>(work: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(format!("Database error: {error}")),
        Err(error) => Err(format!("Database error: {error}")),
    }
}

async fn listing(db: &str, account: &str) -> Result<Vec<(String, bool)>, String> {
    let (db, account) = (db.to_string(), account.to_string());
    run_db(move || rmail_common::db::list_sieve_scripts(&db, &account)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn setup() -> (tempfile::TempDir, String) {
        let td = tempfile::tempdir().unwrap();
        let db = td.path().join("rmail.db");
        rmail_common::db::init_db(&db).unwrap();
        rmail_common::db::add_mailbox(&db, "user@example.test", Some("plain:password"), None, None)
            .unwrap();
        (td, db.display().to_string())
    }

    async fn run_with(db: &str, peer: &str, input: &str) -> String {
        let (mut client, server) = duplex(1 << 22);
        let task = tokio::spawn(serve(
            Box::new(server),
            Some(peer.parse().unwrap()),
            None,
            db.to_string(),
        ));
        client.write_all(input.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        task.await.unwrap().unwrap();
        String::from_utf8(out).unwrap()
    }

    fn plain(user: &str, password: &str) -> String {
        BASE64.encode(format!("\0{user}\0{password}"))
    }

    fn login() -> String {
        format!(
            "AUTHENTICATE \"PLAIN\" \"{}\"\r\n",
            plain("user@example.test", "password")
        )
    }

    const LOOPBACK: &str = "127.0.0.1:4000";

    #[test]
    fn tokenizer_handles_quotes_atoms_and_literals() {
        let (args, literal) = tokenize(br#"PUTSCRIPT "a \"b\" \\ c" 42"#).unwrap();
        assert_eq!(
            args,
            vec![
                Arg::Atom("PUTSCRIPT".into()),
                Arg::Str(b"a \"b\" \\ c".to_vec()),
                Arg::Atom("42".into()),
            ]
        );
        assert_eq!(literal, None);
        let (args, literal) = tokenize(b"PUTSCRIPT \"n\" {12+}").unwrap();
        assert_eq!(args.len(), 2);
        assert_eq!(literal, Some(12));
        assert!(
            tokenize(b"X {12}").is_err(),
            "synchronizing literals are refused"
        );
        assert!(tokenize(b"X {+}").is_err());
        assert!(tokenize(b"X \"open").is_err());
        assert!(tokenize(br#"X "bad \n escape""#).is_err());
        assert!(tokenize(b"a b c d e f g h i j").is_err(), "argument cap");
    }

    #[test]
    fn quoting_neutralizes_control_characters() {
        assert_eq!(quote("a\"b\\c\r\nd"), "\"a\\\"b\\\\c  d\"");
        assert!(valid_script_name("vacation"));
        assert!(!valid_script_name(""));
        assert!(!valid_script_name("a\nb"));
        assert!(!valid_script_name(&"x".repeat(129)));
    }

    #[tokio::test]
    async fn greeting_advertises_capabilities() {
        let (_td, db) = setup();
        let out = run_with(&db, LOOPBACK, "LOGOUT\r\n").await;
        assert!(out.starts_with("\"IMPLEMENTATION\" \"rMail\"\r\n"), "{out}");
        assert!(
            out.contains("\"SIEVE\" \"fileinto envelope imap4flags copy body relational vacation"),
            "{out}"
        );
        assert!(out.contains("\"SASL\" \"PLAIN\"\r\n"), "{out}");
        assert!(out.contains("\"VERSION\" \"1.0\"\r\n"), "{out}");
        assert!(!out.contains("STARTTLS"), "no TLS configured: {out}");
        assert!(out.contains("OK \"rMail ManageSieve ready\"\r\n"), "{out}");
        assert!(out.ends_with("OK \"Logout completed\"\r\n"), "{out}");
    }

    #[tokio::test]
    async fn plain_login_needs_tls_unless_loopback() {
        let (_td, db) = setup();
        let out = run_with(&db, "203.0.113.5:4000", &format!("{}LOGOUT\r\n", login())).await;
        assert!(out.contains("\"SASL\" \"\"\r\n"), "{out}");
        assert!(out.contains("NO (ENCRYPT-NEEDED)"), "{out}");
        let out = run_with(&db, "203.0.113.5:4000", "STARTTLS\r\nLOGOUT\r\n").await;
        assert!(out.contains("NO \"TLS is not available\""), "{out}");
    }

    #[tokio::test]
    async fn authentication_succeeds_fails_and_gates_commands() {
        let (_td, db) = setup();
        let out = run_with(&db, LOOPBACK, "LISTSCRIPTS\r\nLOGOUT\r\n").await;
        assert!(out.contains("NO \"Authenticate first\""), "{out}");

        let bad = format!(
            "AUTHENTICATE \"PLAIN\" \"{}\"\r\nLISTSCRIPTS\r\nLOGOUT\r\n",
            plain("user@example.test", "wrong")
        );
        let out = run_with(&db, LOOPBACK, &bad).await;
        assert!(out.contains("NO \"Authentication failed\""), "{out}");
        assert!(out.contains("NO \"Authenticate first\""), "{out}");

        // Without an initial response the server prompts with an empty string.
        let prompted = format!(
            "AUTHENTICATE \"PLAIN\"\r\n\"{}\"\r\nLISTSCRIPTS\r\nLOGOUT\r\n",
            plain("user@example.test", "password")
        );
        let out = run_with(&db, LOOPBACK, &prompted).await;
        assert!(
            out.contains("\"\"\r\nOK \"Authentication successful\""),
            "{out}"
        );
        assert!(out.contains("OK \"Listscripts completed\""), "{out}");

        let out = run_with(
            &db,
            LOOPBACK,
            "AUTHENTICATE \"SCRAM-SHA-256\"\r\nAUTHENTICATE \"PLAIN\" \"*\"\r\nBOGUS\r\nLOGOUT\r\n",
        )
        .await;
        assert!(
            out.contains("NO \"Unsupported authentication mechanism\""),
            "{out}"
        );
        assert!(out.contains("NO \"Authentication cancelled\""), "{out}");
        assert!(out.contains("NO \"Unknown command\""), "{out}");
        // Authorization identity must be the user.
        let authz = BASE64.encode("someone@else.test\0user@example.test\0password");
        let out = run_with(
            &db,
            LOOPBACK,
            &format!("AUTHENTICATE \"PLAIN\" \"{authz}\"\r\nLOGOUT\r\n"),
        )
        .await;
        assert!(
            out.contains("NO \"Authorization identity not permitted\""),
            "{out}"
        );
    }

    #[tokio::test]
    async fn script_lifecycle() {
        let (_td, db) = setup();
        let script = "require \"fileinto\";\r\nfileinto \"Work\";\r\n";
        let session = format!(
            "{login}\
             PUTSCRIPT \"work\" \"keep;\"\r\n\
             PUTSCRIPT \"lit\" {{{len}+}}\r\n{script}\r\n\
             LISTSCRIPTS\r\n\
             SETACTIVE \"lit\"\r\n\
             LISTSCRIPTS\r\n\
             GETSCRIPT \"lit\"\r\n\
             DELETESCRIPT \"lit\"\r\n\
             DELETESCRIPT \"work\"\r\n\
             DELETESCRIPT \"work\"\r\n\
             RENAMESCRIPT \"lit\" \"main\"\r\n\
             RENAMESCRIPT \"nope\" \"x\"\r\n\
             RENAMESCRIPT \"main\" \"main\"\r\n\
             SETACTIVE \"\"\r\n\
             SETACTIVE \"ghost\"\r\n\
             DELETESCRIPT \"main\"\r\n\
             LISTSCRIPTS\r\n\
             LOGOUT\r\n",
            login = login(),
            len = script.len(),
        );
        let out = run_with(&db, LOOPBACK, &session).await;
        let expected = [
            "OK \"Authentication successful\"\r\n",
            "OK \"Putscript completed\"\r\n",
            "OK \"Putscript completed\"\r\n",
            "\"lit\"\r\n\"work\"\r\nOK \"Listscripts completed\"\r\n",
            "OK \"Setactive completed\"\r\n",
            "\"lit\" ACTIVE\r\n\"work\"\r\nOK \"Listscripts completed\"\r\n",
            &format!(
                "{{{}}}\r\n{script}\r\nOK \"Getscript completed\"\r\n",
                script.len()
            ),
            "NO (ACTIVE) \"Cannot delete the active script\"\r\n",
            "OK \"Deletescript completed\"\r\n",
            "NO (NONEXISTENT) \"There is no script by that name\"\r\n",
            "OK \"Renamescript completed\"\r\n",
            "NO (NONEXISTENT) \"There is no script by that name\"\r\n",
            "NO (ALREADYEXISTS) \"A script with that name already exists\"\r\n",
            "OK \"Setactive completed\"\r\n",
            "NO (NONEXISTENT) \"There is no script by that name\"\r\n",
            "OK \"Deletescript completed\"\r\n",
            "OK \"Listscripts completed\"\r\n",
            "OK \"Logout completed\"\r\n",
        ];
        let mut rest = out
            .split_once("OK \"rMail ManageSieve ready\"\r\n")
            .unwrap()
            .1;
        for chunk in expected {
            rest = rest
                .strip_prefix(chunk)
                .unwrap_or_else(|| panic!("expected {chunk:?} next, got {rest:?}"));
        }
        assert!(rest.is_empty(), "{rest:?}");
    }

    #[tokio::test]
    async fn active_script_is_what_delivery_reads() {
        let (_td, db) = setup();
        let session = format!(
            "{}PUTSCRIPT \"s\" \"discard;\"\r\nSETACTIVE \"s\"\r\nLOGOUT\r\n",
            login()
        );
        run_with(&db, LOOPBACK, &session).await;
        assert_eq!(
            rmail_common::db::get_active_sieve_script(&db, "user@example.test")
                .unwrap()
                .as_deref(),
            Some("discard;")
        );
    }

    #[tokio::test]
    async fn invalid_scripts_are_rejected_with_a_line_number() {
        let (_td, db) = setup();
        // A literal carries real newlines (`\n` in a quoted string is just `n`).
        let src = "keep;\r\nbogus;\r\n";
        let session = format!(
            "{}CHECKSCRIPT \"keep;\"\r\nCHECKSCRIPT {{{}+}}\r\n{src}\r\nPUTSCRIPT \"bad\" \"fileinto \\\"x\\\";\"\r\nPUTSCRIPT \"\" \"keep;\"\r\nLISTSCRIPTS\r\nLOGOUT\r\n",
            login(),
            src.len()
        );
        let out = run_with(&db, LOOPBACK, &session).await;
        assert!(out.contains("OK \"Script is valid\""), "{out}");
        assert!(
            out.contains("NO \"line 2: unknown command `bogus`\""),
            "{out}"
        );
        assert!(
            out.contains("NO \"line 1: \\\"fileinto\\\" requires `require \\\"fileinto\\\";`\""),
            "{out}"
        );
        assert!(out.contains("NO \"Invalid script name\""), "{out}");
        // Nothing was stored.
        assert!(
            out.contains("OK \"Listscripts completed\"\r\nOK \"Logout"),
            "{out}"
        );
    }

    #[tokio::test]
    async fn script_count_and_size_are_limited() {
        let (_td, db) = setup();
        let mut session = login();
        for i in 0..MAX_SCRIPTS + 1 {
            session.push_str(&format!("PUTSCRIPT \"s{i}\" \"keep;\"\r\n"));
        }
        // Replacing an existing name is still allowed at the limit.
        session.push_str("PUTSCRIPT \"s0\" \"discard;\"\r\nHAVESPACE \"new\" 10\r\nHAVESPACE \"s0\" 10\r\nHAVESPACE \"s0\" 99999999\r\nLOGOUT\r\n");
        let out = run_with(&db, LOOPBACK, &session).await;
        assert_eq!(
            out.matches("OK \"Putscript completed\"").count(),
            MAX_SCRIPTS + 1,
            "{out}"
        );
        assert_eq!(out.matches("NO (QUOTA/MAXSCRIPTS)").count(), 2, "{out}");
        assert!(out.contains("OK \"Space available\""), "{out}");
        assert!(out.contains("NO (QUOTA/MAXSIZE)"), "{out}");
    }

    #[tokio::test]
    async fn oversized_literals_close_the_session() {
        let (_td, db) = setup();
        let session = format!(
            "{}PUTSCRIPT \"big\" {{{}+}}\r\nLISTSCRIPTS\r\n",
            login(),
            MAX_SCRIPT_BYTES * 2
        );
        let out = run_with(&db, LOOPBACK, &session).await;
        assert!(out.contains("BYE (QUOTA/MAXSIZE)"), "{out}");
        assert!(!out.contains("Listscripts completed"), "{out}");
    }

    #[tokio::test]
    async fn malformed_lines_do_not_end_the_session() {
        let (_td, db) = setup();
        let out = run_with(
            &db,
            LOOPBACK,
            "NOOP \"abc\r\nNOOP \"t1\"\r\nNOOP\r\nLOGOUT\r\n",
        )
        .await;
        assert!(out.contains("NO \"unterminated string\""), "{out}");
        assert!(out.contains("OK (TAG \"t1\") \"Done\""), "{out}");
        assert!(out.contains("OK \"Done\""), "{out}");
    }
}
