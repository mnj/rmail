//! One IMAP connection.
//!
//! [`process_stream_inner`] reads command lines (inlining textual literals),
//! enforces framing, rate and state rules, and dispatches to handlers:
//! [`auth`] (CAPABILITY, LOGIN, AUTHENTICATE), [`mailboxes`] (SELECT, LIST,
//! STATUS, APPEND, ...) and [`messages`] (FETCH, STORE, SEARCH, UID, IDLE,
//! ...). The command implementations themselves live in `crate::commands`.

mod auth;
mod mailboxes;
mod messages;

use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use rmail_common::auth::ChannelBindings;
use tokio::io::{AsyncWriteExt, BufReader};

use crate::input::{
    BoundedLine, CommandLiteralError, read_bounded_line, read_textual_command_literals,
    trailing_literal_marker,
};
use crate::mailbox::{self, SelectedMailbox};
use crate::transport::{self, AsyncStream, RawStream, SwitchableStream};
use crate::{
    MAX_AUTHENTICATED_LINE_BYTES, MAX_PREAUTH_LINE_BYTES, auth as sasl, commands, parser, response,
    state, tls,
};

pub(crate) type ImapReader = BufReader<Box<dyn AsyncStream + Send + 'static>>;

/// Sent before closing an inactive session (RFC 3501 §5.4).
pub(crate) const AUTOLOGOUT_BYE: &[u8] = b"* BYE Autologout; idle for too long\r\n";

/// Result of reading one command line.
enum Line {
    Command(Vec<u8>),
    /// An error reply was sent; read the next line.
    Skip,
    /// The client is gone or the stream can no longer be trusted.
    End,
}

/// What the read loop does after a command.
enum Flow {
    Continue,
    Close,
}

/// A parsed command line.
struct Invocation<'a> {
    tag: &'a str,
    /// Upper-case command name, used in logs and some replies.
    name: String,
    args: &'a str,
    command: &'a parser::Command,
}

struct Session {
    mail_root: String,
    tls_ctx: Option<Arc<tls::TlsContext>>,
    db_path: Option<String>,
    peer: Option<SocketAddr>,
    /// The stream is TLS-protected (IMAPS or after STARTTLS).
    encrypted: bool,
    /// Channel-binding data of the TLS connection (SCRAM-SHA-256-PLUS).
    channel_bindings: ChannelBindings,
    auth_policy: Arc<sasl::AuthPolicy>,
    state: state::SessionState,
    selected: Option<SelectedMailbox>,
    command_times: VecDeque<Instant>,
}

#[cfg(test)]
pub(crate) async fn process_stream(
    stream: Box<dyn RawStream + Send + 'static>,
    mail_root: String,
    tls_ctx: Option<Arc<tls::TlsContext>>,
    db_path: Option<String>,
    peer: Option<SocketAddr>,
    session_encrypted: bool,
) -> Result<()> {
    process_stream_with_policy(
        stream,
        mail_root,
        tls_ctx,
        db_path,
        peer,
        session_encrypted,
        Arc::new(sasl::AuthPolicy::default()),
    )
    .await
}

pub(crate) async fn process_stream_with_policy(
    stream: Box<dyn RawStream + Send + 'static>,
    mail_root: String,
    tls_ctx: Option<Arc<tls::TlsContext>>,
    db_path: Option<String>,
    peer: Option<SocketAddr>,
    session_encrypted: bool,
    auth_policy: Arc<sasl::AuthPolicy>,
) -> Result<()> {
    process_stream_inner(
        stream,
        mail_root,
        tls_ctx,
        db_path,
        peer,
        session_encrypted,
        true,
        auth_policy,
    )
    .await
}

/// Run a session on a stream whose TLS handshake (IMAPS) already completed;
/// `channel_bindings` come from that TLS connection.
pub(crate) async fn process_tls_stream(
    stream: Box<dyn RawStream + Send + 'static>,
    mail_root: String,
    tls_ctx: Option<Arc<tls::TlsContext>>,
    db_path: Option<String>,
    peer: Option<SocketAddr>,
    channel_bindings: ChannelBindings,
    auth_policy: Arc<sasl::AuthPolicy>,
) -> Result<()> {
    run_session(
        stream,
        mail_root,
        tls_ctx,
        db_path,
        peer,
        true,
        true,
        auth_policy,
        Some(channel_bindings),
    )
    .await
}

// `session_encrypted` is true for IMAPS and after STARTTLS; password
// mechanisms are refused on plaintext sessions. `peer` keys the per-address
// authentication lockout.
pub(crate) async fn process_stream_inner(
    stream: Box<dyn RawStream + Send + 'static>,
    mail_root: String,
    tls_ctx: Option<Arc<tls::TlsContext>>,
    db_path: Option<String>,
    peer: Option<SocketAddr>,
    session_encrypted: bool,
    send_greeting: bool,
    auth_policy: Arc<sasl::AuthPolicy>,
) -> Result<()> {
    run_session(
        stream,
        mail_root,
        tls_ctx,
        db_path,
        peer,
        session_encrypted,
        send_greeting,
        auth_policy,
        None,
    )
    .await
}

/// `channel_bindings` is `None` when the caller has no TLS connection at
/// hand; an encrypted session then only offers tls-server-end-point from
/// the configured certificate.
async fn run_session(
    stream: Box<dyn RawStream + Send + 'static>,
    mail_root: String,
    tls_ctx: Option<Arc<tls::TlsContext>>,
    db_path: Option<String>,
    peer: Option<SocketAddr>,
    session_encrypted: bool,
    send_greeting: bool,
    auth_policy: Arc<sasl::AuthPolicy>,
    channel_bindings: Option<ChannelBindings>,
) -> Result<()> {
    let channel_bindings = match channel_bindings {
        Some(bindings) => bindings,
        None if session_encrypted => ChannelBindings {
            tls_server_end_point: tls_ctx
                .as_ref()
                .map(|context| context.server_end_point.clone()),
            tls_exporter: None,
        },
        None => ChannelBindings::default(),
    };
    let stream: Box<dyn AsyncStream + Send + 'static> = Box::new(SwitchableStream::new(stream));
    let mut reader = BufReader::new(stream);
    let mut session = Session {
        mail_root,
        tls_ctx,
        db_path,
        peer,
        encrypted: session_encrypted,
        channel_bindings,
        auth_policy,
        state: state::SessionState::default(),
        selected: None,
        command_times: VecDeque::new(),
    };
    imap_log!("info", "session_started", { "peer": session.peer_label(), "encrypted": session_encrypted, "tls_configured": session.tls_ctx.is_some() });
    if send_greeting {
        let phase = if session_encrypted {
            response::CapabilityPhase::NotAuthenticatedTls
        } else {
            response::CapabilityPhase::NotAuthenticatedPlain
        };
        let caps = session.capabilities(phase);
        imap_log!("info", "greeting_sent", { "peer": session.peer_label(), "encrypted": session_encrypted, "capabilities": caps });
        write(&mut reader, response::greeting(&caps).as_bytes()).await?;
    }

    loop {
        let line_limit = if session.state.authenticated_mailbox.is_some() {
            MAX_AUTHENTICATED_LINE_BYTES
        } else {
            MAX_PREAUTH_LINE_BYTES
        };
        let timeouts = session.auth_policy.timeouts();
        let autologout = if session.state.authenticated_mailbox.is_some() {
            timeouts.authenticated
        } else {
            timeouts.unauthenticated
        };
        let read =
            tokio::time::timeout(autologout, session.read_command(&mut reader, line_limit)).await;
        let line = match read {
            Ok(result) => match result? {
                Line::Command(line) => line,
                Line::Skip => continue,
                Line::End => break,
            },
            Err(_) => {
                imap_log!("info", "session_closed", { "peer": session.peer_label(), "encrypted": session.encrypted, "reason": "autologout" });
                let _ = write(&mut reader, AUTOLOGOUT_BYE).await;
                break;
            }
        };
        let Ok(input) = std::str::from_utf8(&line) else {
            write(&mut reader, b"* BAD Command line is not valid UTF-8\r\n").await?;
            continue;
        };
        let input = input.trim_end_matches(['\r', '\n']);
        if input.is_empty() {
            continue;
        }
        if !session.within_command_rate() {
            write(&mut reader, b"* BYE Command rate limit exceeded\r\n").await?;
            break;
        }
        let request = match parser::parse_request_line(input) {
            Ok(request) => request,
            Err(error) => {
                let tag = input
                    .split([' ', '\t'])
                    .next()
                    .filter(|tag| parser::valid_tag(tag))
                    .unwrap_or("*");
                write(
                    &mut reader,
                    format!("{tag} BAD Invalid command framing: {error:?}\r\n").as_bytes(),
                )
                .await?;
                continue;
            }
        };
        let _command_timer = rmail_common::metrics::imap_command_timer();
        let call = Invocation {
            tag: request.tag,
            name: request.command_name().to_string(),
            args: request.raw_args(),
            command: &request.command,
        };
        imap_log!("info", "command_received", { "peer": session.peer_label(), "encrypted": session.encrypted, "tag": call.tag, "command": call.name, "args": logged_command_args(&call.name, call.args), "authenticated": session.state.authenticated_mailbox.is_some(), "selected": session.state.selected_mailbox.is_some() });
        let spec = commands::command_spec(call.command);
        if let Some(reason) = commands::preflight(
            spec,
            commands::SessionContext {
                authenticated: session.state.authenticated_mailbox.is_some(),
                selected: session.state.selected_mailbox.is_some(),
                encrypted: session.encrypted,
            },
        ) {
            write(
                &mut reader,
                format!("{} {}\r\n", call.tag, reason).as_bytes(),
            )
            .await?;
            continue;
        }
        if call.command.requires_empty_arguments() && !call.args.is_empty() {
            write(
                &mut reader,
                format!("{} BAD Invalid {} arguments\r\n", call.tag, call.name).as_bytes(),
            )
            .await?;
            continue;
        }
        if let Some(spec) = spec
            && spec.needs_mailbox_sync()
            && session.selected.is_some()
        {
            let options = session.sync_options(spec.allows_expunge());
            sync_selected_mailbox(
                &mut reader,
                &session.mail_root,
                &mut session.selected,
                options,
            )
            .await?;
        }

        // STARTTLS consumes the reader, so it is handled here.
        if matches!(call.command, parser::Command::StartTls) {
            imap_log!("info", "starttls_started", { "peer": session.peer_label() });
            match transport::start_tls(reader, call.tag, session.tls_ctx.clone()).await {
                Ok(transport::StartTlsOutcome::Rejected(returned)) => {
                    reader = returned;
                    continue;
                }
                Ok(transport::StartTlsOutcome::Upgraded(tls_stream, bindings)) => {
                    imap_log!("info", "starttls_succeeded", { "peer": session.peer_label() });
                    // RFC 3501: no greeting after STARTTLS; state starts over.
                    return Box::pin(run_session(
                        tls_stream,
                        session.mail_root,
                        session.tls_ctx,
                        session.db_path,
                        session.peer,
                        true,
                        false,
                        session.auth_policy,
                        Some(bindings),
                    ))
                    .await;
                }
                Err(error) => {
                    imap_log!("error", "starttls_failed", { "peer": session.peer_label(), "error": error.to_string() });
                    return Err(error);
                }
            }
        }

        match session.dispatch(&mut reader, &call).await? {
            Flow::Continue => {}
            Flow::Close => break,
        }
    }
    Ok(())
}

/// Write bytes to the client and flush.
async fn write(reader: &mut ImapReader, bytes: &[u8]) -> Result<()> {
    let writer = reader.get_mut();
    writer.write_all(bytes).await?;
    writer.flush().await?;
    Ok(())
}

impl Session {
    fn peer_label(&self) -> Option<String> {
        self.peer.map(|address| address.to_string())
    }

    fn capabilities(&self, phase: response::CapabilityPhase) -> String {
        // Before TLS the flag means "STARTTLS can be offered"; on a TLS
        // session it means "channel binding (SCRAM-*-PLUS) can be offered".
        let transport_feature = if phase == response::CapabilityPhase::NotAuthenticatedTls {
            self.channel_bindings.is_available()
        } else {
            self.tls_ctx.is_some()
        };
        response::capability_tokens_with_policy(phase, transport_feature, self.auth_policy.as_ref())
    }

    /// Whether this session advertises SCRAM-SHA-256-PLUS; a plain
    /// SCRAM-SHA-256 client that says it supports channel binding (`y`) is
    /// then being downgraded (RFC 5802 §6).
    fn scram_plus_advertised(&self) -> bool {
        self.encrypted
            && self
                .auth_policy
                .advertised_mechanisms(true, self.channel_bindings.is_available())
                .any(|mechanism| mechanism.channel_binding_required)
    }

    /// The authenticated account. Preflight guarantees it for commands that
    /// need it.
    fn address(&self) -> &str {
        self.state
            .authenticated_mailbox
            .as_deref()
            .expect("preflight requires authentication")
    }

    fn selected(&self) -> &SelectedMailbox {
        self.selected
            .as_ref()
            .expect("preflight requires selected mailbox")
    }

    fn set_authenticated(&mut self, mailbox: Option<String>) {
        if let Some(mailbox) = mailbox {
            self.state.authenticated_mailbox = Some(mailbox);
        }
    }

    fn clear_selection(&mut self) {
        self.selected = None;
        self.state.selected_mailbox = None;
    }

    /// Read one command line and any textual literals it announces.
    async fn read_command(&self, reader: &mut ImapReader, line_limit: usize) -> Result<Line> {
        let line = match read_bounded_line(reader, line_limit).await {
            Ok(BoundedLine::Line(line)) => line,
            Ok(BoundedLine::Eof) => {
                imap_log!("info", "session_closed", { "peer": self.peer_label(), "encrypted": self.encrypted, "reason": "client_eof" });
                return Ok(Line::End);
            }
            Ok(BoundedLine::TooLong) => {
                write(reader, b"* BAD Command line too long\r\n").await?;
                return Ok(Line::Skip);
            }
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => {
                imap_log!("info", "session_closed", { "peer": self.peer_label(), "encrypted": self.encrypted, "reason": "missing_tls_close_notify" });
                return Ok(Line::End);
            }
            Err(error) => {
                imap_log!("error", "session_read_failed", { "peer": self.peer_label(), "encrypted": self.encrypted, "error": error.to_string() });
                return Err(error.into());
            }
        };
        // APPEND streams its own literals; other commands get them inlined.
        let is_append = std::str::from_utf8(&line)
            .ok()
            .and_then(|line| line.split_ascii_whitespace().nth(1))
            .is_some_and(|command| command.eq_ignore_ascii_case("APPEND"));
        if is_append || trailing_literal_marker(&line).is_none() {
            return Ok(Line::Command(line));
        }
        let rejection: &[u8] = match read_textual_command_literals(reader, line, line_limit).await {
            Ok(line) => return Ok(Line::Command(line)),
            Err(CommandLiteralError::Eof) => return Ok(Line::End),
            Err(CommandLiteralError::Io) => return Err(anyhow!("command literal read error")),
            Err(CommandLiteralError::NonSyncLiteral8) => {
                write(
                    reader,
                    b"* BYE Non-synchronizing literal8 desynchronized command stream\r\n",
                )
                .await?;
                return Ok(Line::End);
            }
            Err(CommandLiteralError::TooLarge) => b"* BAD Command literal too large\r\n",
            Err(CommandLiteralError::Literal8) => {
                b"* BAD Literal8 is not valid for this command\r\n"
            }
            Err(CommandLiteralError::InvalidUtf8) => {
                b"* BAD Textual command literal is not valid UTF-8\r\n"
            }
        };
        write(reader, rejection).await?;
        Ok(Line::Skip)
    }

    /// Sliding one-minute command budget per session.
    fn within_command_rate(&mut self) -> bool {
        let now = Instant::now();
        while self
            .command_times
            .front()
            .is_some_and(|timestamp| now.duration_since(*timestamp) >= Duration::from_secs(60))
        {
            self.command_times.pop_front();
        }
        if self.command_times.len() >= self.auth_policy.max_commands_per_minute() {
            return false;
        }
        self.command_times.push_back(now);
        true
    }

    async fn dispatch(&mut self, reader: &mut ImapReader, call: &Invocation<'_>) -> Result<Flow> {
        use parser::Command;
        match call.command {
            Command::Capability => self.capability(reader, call).await,
            Command::Compress => {
                transport::enable_deflate(reader, call.tag, call.args).await?;
                Ok(Flow::Continue)
            }
            Command::Login => self.login(reader, call).await,
            Command::Authenticate => self.authenticate(reader, call).await,
            Command::Noop => {
                self.send(
                    reader,
                    commands::basic::completed(call.tag, "NOOP").encode(),
                )
                .await
            }
            Command::Check => {
                self.send(reader, commands::session::check(call.tag).response.encode())
                    .await
            }
            Command::Logout => {
                write(
                    reader,
                    commands::basic::logout(call.tag).encode().as_bytes(),
                )
                .await?;
                Ok(Flow::Close)
            }
            Command::Id => self.id(reader, call).await,
            Command::Namespace => self.namespace(reader, call).await,
            Command::Enable => self.enable(reader, call).await,
            Command::GetQuota | Command::GetQuotaRoot | Command::SetQuota => {
                self.quota(reader, call).await
            }
            Command::GetMetadata | Command::SetMetadata => self.metadata(reader, call).await,
            Command::Unselect => self.unselect(reader, call).await,
            Command::Unauthenticate => {
                // RFC 8437: back to the not-authenticated state as if the
                // connection were new; TLS and compression stay active.
                let account = self.state.authenticated_mailbox.clone();
                self.clear_selection();
                self.state = state::SessionState::default();
                imap_log!("info", "unauthenticated", { "peer": self.peer_label(), "mailbox": account });
                self.send(
                    reader,
                    commands::basic::completed(call.tag, "UNAUTHENTICATE").encode(),
                )
                .await
            }
            Command::Append => self.append(reader, call).await,
            Command::List { .. } | Command::Lsub => self.list(reader, call).await,
            Command::Create | Command::Delete | Command::Rename | Command::Subscribe { .. } => {
                self.manage_mailbox(reader, call).await
            }
            Command::Select { .. } => self.select(reader, call).await,
            Command::Status => self.status(reader, call).await,
            Command::Fetch => self.fetch(reader, call.tag, call.args, false).await,
            Command::Copy | Command::Move => {
                self.transfer(reader, call.tag, &call.name, call.args, false)
                    .await
            }
            Command::Uid { command } => self.uid(reader, call, command.as_str()).await,
            Command::Search => self.search(reader, call.tag, call.args, false).await,
            Command::Thread => self.thread(reader, call.tag, call.args, false).await,
            Command::Sort => self.sort(reader, call.tag, call.args, false).await,
            Command::Store => self.store(reader, call.tag, call.args, false).await,
            Command::Expunge | Command::Close => self.expunge(reader, call).await,
            Command::Idle => self.idle(reader, call).await,
            Command::StartTls => unreachable!("STARTTLS is handled by the read loop"),
            Command::Unknown { .. } => {
                log_unsupported_imap(self.peer, &self.selected, call.tag, &call.name, call.args);
                self.send(reader, commands::basic::unknown(call.tag).encode())
                    .await
            }
        }
    }

    /// Write an encoded response.
    async fn send(&self, reader: &mut ImapReader, response: String) -> Result<Flow> {
        write(reader, response.as_bytes()).await?;
        Ok(Flow::Continue)
    }

    /// Log and write an encoded response.
    async fn respond(
        &self,
        reader: &mut ImapReader,
        tag: &str,
        command: &str,
        response: String,
    ) -> Result<Flow> {
        response::log_imap_response(self.peer, tag, command, &response);
        self.send(reader, response).await
    }

    /// How untagged updates are reported in this session.
    fn sync_options(&self, allow_expunge: bool) -> mailbox::SyncOptions {
        mailbox::SyncOptions {
            allow_expunge,
            qresync: self.state.feature_enabled("QRESYNC"),
            condstore: self.state.condstore_enabled(),
            imap4rev2: self.state.imap4rev2_enabled(),
        }
    }

    /// Mirror the account quota from the database before commands that add
    /// messages or report usage.
    async fn sync_quota(&self) -> Result<()> {
        sync_account_storage_quota(&self.mail_root, self.address(), self.db_path.as_deref()).await
    }
}

pub(crate) fn logged_command_args<'a>(command: &str, args: &'a str) -> &'a str {
    if matches!(
        command.to_ascii_uppercase().as_str(),
        "AUTHENTICATE" | "LOGIN"
    ) {
        "[REDACTED]"
    } else {
        args
    }
}

fn log_unsupported_imap(
    peer: Option<SocketAddr>,
    selected: &Option<SelectedMailbox>,
    tag: &str,
    command: &str,
    raw_args: &str,
) {
    imap_log!("warn", "unsupported_command", { "peer": peer.map(|address| address.to_string()), "selected_mailbox": mailbox::selected_mailbox_for_log(selected), "tag": tag, "command": command, "raw_args": raw_args });
}

/// Send untagged updates (EXISTS, EXPUNGE, FETCH FLAGS) for changes made by
/// other sessions or deliveries.
pub(crate) async fn sync_selected_mailbox(
    reader: &mut ImapReader,
    mail_root: &str,
    selected: &mut Option<SelectedMailbox>,
    options: mailbox::SyncOptions,
) -> Result<()> {
    let Some(current) = selected.as_ref() else {
        return Ok(());
    };
    let (refreshed, events) =
        mailbox::refresh_selected_mailbox(mail_root, current, options).await?;
    if !events.is_empty() {
        let writer = reader.get_mut();
        for event in &events {
            writer
                .write_all(event.response_line(options).as_bytes())
                .await?;
        }
        writer.flush().await?;
    }
    *selected = Some(refreshed);
    Ok(())
}

async fn sync_account_storage_quota(
    mail_root: &str,
    address: &str,
    db_path: Option<&str>,
) -> Result<()> {
    let Some(db_path) = db_path else {
        return Ok(());
    };
    let (local, domain) = mailbox::address_parts(address)?;
    let db_path = db_path.to_string();
    let address = address.to_string();
    let mail_root = mail_root.to_string();
    tokio::task::spawn_blocking(move || {
        let mailbox = rmail_common::db::get_mailbox(&db_path, &address)?
            .ok_or_else(|| anyhow!("authenticated mailbox no longer exists"))?;
        rmail_common::imap_state::set_storage_quota(
            Path::new(&mail_root),
            &domain,
            &local,
            mailbox.quota_bytes,
        )
    })
    .await??;
    Ok(())
}
