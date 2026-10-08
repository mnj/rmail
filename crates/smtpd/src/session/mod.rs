//! One SMTP/LMTP conversation.
//!
//! [`process_stream`] reads command lines and hands each one to
//! [`Session::handle_command`]. Command handlers live here (greeting, AUTH,
//! MAIL, RSET, STARTTLS), in [`recipients`] (RCPT) and in [`message`]
//! (DATA/BDAT through delivery). Handlers return a [`Flow`] telling the read
//! loop whether to continue, close, or upgrade to TLS.

mod delivery;
mod message;
mod recipients;

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rmail_common::auth::{ChannelBindings, ScramChannelBindingPolicy};
use rmail_common::config::SecurityConfig;
use rmail_common::metrics;
use rmail_common::oauth::OAuthValidator;
use rmail_common::outbound::DsnOptions;
use rmail_common::tracking::new_tracking_id;
use tokio::io::{AsyncWrite, AsyncWriteExt, BufReader};
use tokio::time::timeout;

use crate::limits::{
    SenderLimit, auth_block_remaining, sender_limit_reached, submission_quota_available,
};
use crate::protocol::{self, Command as SmtpCommand, parse_command, parse_mail_from_args};
use crate::trace::{ConnectionTrace, ReplyTrackingStream, emit_tracking};
use crate::{
    AsyncStream, COMMAND_IDLE_TIMEOUT, MAX_MESSAGE_BYTES, STARTTLS_HANDSHAKE_TIMEOUT, SmtpService,
    authenticate, server_hostname, tls,
};

#[cfg(test)]
pub(crate) use delivery::is_forwarded_recipient;

pub(crate) type SmtpReader = BufReader<ReplyTrackingStream>;

/// Log an event tagged with this session's connection ID and peer.
macro_rules! session_log {
    ($session:expr, $level:expr, $event:expr, { $($key:literal : $value:expr),* $(,)? }) => {
        smtp_log!($level, $event, {
            "connection_id": $session.trace.id,
            "peer": $session.peer.map(|address| address.to_string())
            $(, $key: $value)*
        })
    };
}
pub(super) use session_log;

/// What the read loop does after a command.
pub(super) enum Flow {
    Continue,
    Close,
    /// The 220 reply was sent; hand the stream to TLS.
    StartTls(Arc<tls::TlsContext>),
}

/// Envelope state of the current MAIL transaction.
struct Transaction {
    mail_from: Option<String>,
    /// MAIL FROM was accepted and RCPT/DATA may follow.
    active: bool,
    body: protocol::MailBody,
    smtp_utf8: bool,
    require_tls: bool,
    /// RFC 4954 AUTH= submitter, kept only when the session's authenticated
    /// identity vouches for it; otherwise it is treated as `AUTH=<>`.
    auth_submitter: Option<String>,
    dsn: DsnOptions,
    rcpts: Vec<String>,
    bdat_buffer: Vec<u8>,
    bdat_started: bool,
}

impl Default for Transaction {
    fn default() -> Self {
        Self {
            mail_from: None,
            active: false,
            body: protocol::MailBody::SevenBit,
            smtp_utf8: false,
            require_tls: false,
            auth_submitter: None,
            dsn: DsnOptions::default(),
            rcpts: Vec::new(),
            bdat_buffer: Vec::new(),
            bdat_started: false,
        }
    }
}

pub(super) struct Session {
    mail_root: String,
    tls_ctx: Option<Arc<tls::TlsContext>>,
    /// Channel-binding data of this TLS session (empty when plaintext).
    channel_bindings: ChannelBindings,
    db_path: Option<String>,
    peer: Option<SocketAddr>,
    /// The stream is TLS-protected (SMTPS or after STARTTLS).
    encrypted: bool,
    implicit_tls: bool,
    enforce_dmarc: bool,
    security: Arc<SecurityConfig>,
    service: SmtpService,
    trace: ConnectionTrace,
    oauth: Option<OAuthValidator>,
    max_recipients: usize,
    command_limit: usize,
    recent_commands: VecDeque<Instant>,
    helo_name: Option<String>,
    extended_smtp: bool,
    authenticated_user: Option<String>,
    /// Webmail on this host authenticated with the local submission secret
    /// (`X-RMAIL-WEBMAIL`); loopback traffic stands in for TLS.
    local_trusted: bool,
    /// Tracking ID of the current transaction (set by MAIL).
    message_id: Option<String>,
    tx: Transaction,
    /// Incremented by every MAIL; recipient bookkeeping below is keyed by it
    /// so state from earlier transactions is never reused.
    generation: u64,
    recipient_dsn: HashMap<String, (u64, DsnOptions)>,
    /// Alias/catchall targets, which receive ARC seals when relayed.
    forwarded_recipient: HashMap<String, u64>,
    /// LMTP: (generation, RCPT address as given, expanded targets). LMTP
    /// sends one final reply per accepted RCPT.
    lmtp_recipient_groups: Vec<(u64, String, Vec<String>)>,
}

// session_encrypted indicates whether the stream is protected by TLS (SMTPS,
// or after a successful STARTTLS upgrade). Password mechanisms are only
// offered on encrypted sessions.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn process_stream(
    stream: Box<dyn AsyncStream + Send + 'static>,
    mail_root: String,
    tls_ctx: Option<Arc<tls::TlsContext>>,
    db_path: Option<String>,
    peer: Option<SocketAddr>,
    session_encrypted: bool,
    enforce_dmarc: bool,
    send_greeting: bool,
    security: Arc<SecurityConfig>,
    service: SmtpService,
    trace: Option<ConnectionTrace>,
) -> Result<()> {
    process_stream_with_bindings(
        stream,
        mail_root,
        tls_ctx,
        db_path,
        peer,
        session_encrypted,
        enforce_dmarc,
        send_greeting,
        security,
        service,
        trace,
        None,
    )
    .await
}

// `channel_bindings` carries the TLS channel-binding data captured at the
// handshake. Without it an encrypted session only offers
// tls-server-end-point from the TLS context.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn process_stream_with_bindings(
    stream: Box<dyn AsyncStream + Send + 'static>,
    mail_root: String,
    tls_ctx: Option<Arc<tls::TlsContext>>,
    db_path: Option<String>,
    peer: Option<SocketAddr>,
    session_encrypted: bool,
    enforce_dmarc: bool,
    send_greeting: bool,
    security: Arc<SecurityConfig>,
    service: SmtpService,
    trace: Option<ConnectionTrace>,
    channel_bindings: Option<ChannelBindings>,
) -> Result<()> {
    let channel_bindings = match channel_bindings {
        Some(bindings) => bindings,
        None if session_encrypted => ChannelBindings {
            tls_server_end_point: tls_ctx
                .as_ref()
                .map(|context| context.server_end_point.clone())
                .filter(|binding| !binding.is_empty()),
            tls_exporter: None,
        },
        None => ChannelBindings::default(),
    };
    let oauth = security
        .oauth
        .clone()
        .map(OAuthValidator::new)
        .transpose()
        .context("initializing OAuth token introspection")?;
    let trace = trace.unwrap_or_else(|| ConnectionTrace::new(None));
    let mut reader = BufReader::new(ReplyTrackingStream::new(stream, trace.clone(), peer));
    let command_limit = security.smtp_max_commands_per_minute.max(1);
    let mut session = Session {
        mail_root,
        tls_ctx,
        channel_bindings,
        db_path,
        peer,
        encrypted: session_encrypted,
        implicit_tls: session_encrypted,
        enforce_dmarc,
        max_recipients: match service {
            SmtpService::Mta | SmtpService::Lmtp => security.smtp_max_recipients.max(1),
            SmtpService::Submission => security.submission_max_recipients.max(1),
        },
        security,
        service,
        trace,
        oauth,
        command_limit,
        recent_commands: VecDeque::with_capacity(command_limit.min(1_024)),
        helo_name: None,
        extended_smtp: false,
        authenticated_user: None,
        local_trusted: false,
        message_id: None,
        tx: Transaction::default(),
        generation: 0,
        recipient_dsn: HashMap::new(),
        forwarded_recipient: HashMap::new(),
        lmtp_recipient_groups: Vec::new(),
    };
    session_log!(session, "info", "session_started", { "service": service.as_str(), "encrypted": session_encrypted, "tls_configured": session.tls_ctx.is_some(), "dmarc_enforced": enforce_dmarc });
    if send_greeting {
        // RFC 5321 section 4.2: the greeting starts with the server's domain.
        let host = server_hostname();
        let greeting = if service == SmtpService::Lmtp {
            format!("220 {host} LMTP rMail ready\r\n")
        } else {
            format!("220 {host} ESMTP rMail ready\r\n")
        };
        send(&mut reader, greeting.as_bytes()).await?;
    }

    loop {
        let line = match timeout(
            COMMAND_IDLE_TIMEOUT,
            protocol::read_bounded_line(&mut reader, protocol::MAX_AUTH_LINE_BYTES),
        )
        .await
        {
            Err(_) => {
                let writer = reader.get_mut();
                let _ = writer.write_all(b"421 4.4.2 Timeout\r\n").await;
                let _ = writer.flush().await;
                break;
            }
            Ok(Err(error)) => return Err(error.into()),
            Ok(Ok(protocol::BoundedLine::Eof)) => break,
            Ok(Ok(protocol::BoundedLine::TooLong)) => {
                send(&mut reader, b"500 5.5.2 Line too long\r\n").await?;
                continue;
            }
            Ok(Ok(protocol::BoundedLine::Line(line))) => line,
        };
        match session.handle_command(&mut reader, &line).await? {
            Flow::Continue => {}
            Flow::Close => break,
            Flow::StartTls(acceptor) => {
                // Stop tracking plaintext bytes; the TLS session reports its own.
                reader.get_mut().disable();
                let inner = reader.into_inner();
                let started = Instant::now();
                let handshake =
                    timeout(STARTTLS_HANDSHAKE_TIMEOUT, acceptor.acceptor.accept(inner)).await;
                metrics::observe_tls_handshake_duration(started.elapsed());
                return match handshake {
                    Ok(Ok(tls_stream)) => {
                        session_log!(session, "info", "starttls_completed", {});
                        let channel_bindings = acceptor.channel_bindings(tls_stream.get_ref().1);
                        // RFC 3207: all state is discarded; the client must EHLO again.
                        Box::pin(process_stream_with_bindings(
                            Box::new(tls_stream),
                            session.mail_root,
                            Some(acceptor),
                            session.db_path,
                            peer,
                            true,
                            enforce_dmarc,
                            false,
                            session.security,
                            service,
                            Some(session.trace),
                            Some(channel_bindings),
                        ))
                        .await
                    }
                    Ok(Err(error)) => {
                        session_log!(session, "warn", "starttls_failed", { "error": error.to_string() });
                        Err(anyhow::anyhow!("TLS accept error: {error}"))
                    }
                    Err(_) => {
                        session_log!(session, "warn", "starttls_failed", { "error": "handshake timed out" });
                        Err(anyhow::anyhow!("TLS accept timeout"))
                    }
                };
            }
        }
    }
    session_log!(session, "info", "session_closed", { "encrypted": session.encrypted });
    emit_tracking(session.trace.event(
        peer,
        session.message_id.clone(),
        "connection",
        "disconnected",
    ));
    Ok(())
}

/// Write a reply and flush.
pub(super) async fn send(reader: &mut SmtpReader, reply: &[u8]) -> Result<()> {
    let writer = reader.get_mut();
    writer.write_all(reply).await?;
    writer.flush().await?;
    Ok(())
}

/// Write a reply and continue with the next command.
pub(super) async fn reply(reader: &mut SmtpReader, reply: &[u8]) -> Result<Flow> {
    send(reader, reply).await?;
    Ok(Flow::Continue)
}

#[cfg(test)]
pub(crate) fn parse_mail_from_arg(cmd: &str) -> Option<Option<String>> {
    parse_mail_from_args(cmd.strip_prefix("MAIL")?.trim_start())
        .ok()
        .map(|parsed| parsed.sender)
}

impl Session {
    async fn handle_command(&mut self, reader: &mut SmtpReader, line: &[u8]) -> Result<Flow> {
        if !line.ends_with(b"\r\n") {
            return reply(reader, b"500 5.5.2 Command line must end with CRLF\r\n").await;
        }
        let Ok(cmd) = std::str::from_utf8(line) else {
            return reply(reader, b"500 5.5.2 Command is not valid UTF-8\r\n").await;
        };
        let cmd = cmd.trim_end_matches(['\r', '\n']);
        if cmd.is_empty() {
            return Ok(Flow::Continue);
        }
        let command = parse_command(cmd);
        if !self.within_command_rate() {
            send(reader, b"421 4.7.0 Command rate limit exceeded\r\n").await?;
            return Ok(Flow::Close);
        }
        if line.len() > protocol::command_line_limit(&command) {
            return reply(reader, b"500 5.5.2 Line too long\r\n").await;
        }
        self.record_command(&command, cmd);
        if let Some(rejection) = self.policy_rejection(&command) {
            return reply(reader, rejection).await;
        }

        match command {
            SmtpCommand::Helo(name) => self.greet(reader, name, "HELO").await,
            SmtpCommand::Ehlo(name) => self.greet(reader, name, "EHLO").await,
            SmtpCommand::Lhlo(name) => self.greet(reader, name, "LHLO").await,
            SmtpCommand::Auth(args) => self.auth(reader, args).await,
            SmtpCommand::Mail(args) => self.mail(reader, args).await,
            SmtpCommand::Rcpt(args) => self.rcpt(reader, args).await,
            SmtpCommand::Data => self.message(reader, None).await,
            SmtpCommand::Bdat(args) => self.message(reader, Some(args)).await,
            SmtpCommand::Rset => {
                self.reset_transaction();
                reply(reader, b"250 2.0.0 Reset state\r\n").await
            }
            SmtpCommand::Noop => reply(reader, b"250 2.0.0 OK\r\n").await,
            SmtpCommand::Vrfy | SmtpCommand::Expn => {
                reply(
                    reader,
                    b"252 2.5.2 Cannot VRFY user, but will accept message if valid\r\n",
                )
                .await
            }
            SmtpCommand::Help => {
                reply(
                    reader,
                    b"214 2.0.0 Commands: HELO EHLO MAIL RCPT DATA BDAT RSET NOOP QUIT STARTTLS AUTH VRFY HELP\r\n",
                )
                .await
            }
            SmtpCommand::Quit => {
                send(reader, b"221 2.0.0 Bye\r\n").await?;
                Ok(Flow::Close)
            }
            SmtpCommand::StartTls => self.starttls(reader).await,
            SmtpCommand::BadSyntax => {
                reply(
                    reader,
                    b"501 5.5.2 Syntax error in parameters or arguments\r\n",
                )
                .await
            }
            SmtpCommand::Unknown => {
                session_log!(self, "warn", "unknown_command", { "encrypted": self.encrypted });
                reply(reader, b"500 5.5.2 Command unrecognized\r\n").await
            }
        }
    }

    /// Sliding one-minute command budget per session.
    fn within_command_rate(&mut self) -> bool {
        let now = Instant::now();
        while self
            .recent_commands
            .front()
            .is_some_and(|seen| now.duration_since(*seen) >= Duration::from_secs(60))
        {
            self.recent_commands.pop_front();
        }
        if self.recent_commands.len() >= self.command_limit {
            return false;
        }
        self.recent_commands.push_back(now);
        true
    }

    /// Emit tracking and log events for a command. AUTH arguments carry
    /// credentials, so only the mechanism is recorded.
    fn record_command(&mut self, command: &SmtpCommand<'_>, raw: &str) {
        let logged = match command {
            SmtpCommand::Auth(args) => {
                format!("AUTH {}", args.split_whitespace().next().unwrap_or(""))
            }
            _ => raw.to_string(),
        };
        if matches!(command, SmtpCommand::Mail(_)) {
            self.message_id = Some(new_tracking_id("message"));
            self.trace.set_message_id(self.message_id.clone());
        }
        let verb = logged
            .split_ascii_whitespace()
            .next()
            .unwrap_or("unknown")
            .to_ascii_lowercase();
        let mut event = self
            .trace
            .event(self.peer, self.message_id.clone(), "command", &verb);
        event.detail = Some(logged.clone());
        emit_tracking(event);
        session_log!(self, "info", "command_received", { "message_id": self.message_id, "encrypted": self.encrypted, "command": logged, "authenticated_user": self.authenticated_user, "mail_from": self.tx.mail_from, "recipient_count": self.tx.rcpts.len() });
    }

    /// Service rules (LMTP, submission) and RFC sequencing checks that apply
    /// before a command runs.
    fn policy_rejection(&self, command: &SmtpCommand<'_>) -> Option<&'static [u8]> {
        if self.service == SmtpService::Lmtp {
            if matches!(command, SmtpCommand::Helo(_) | SmtpCommand::Ehlo(_)) {
                return Some(b"500 5.5.1 LMTP requires LHLO\r\n");
            }
            if matches!(command, SmtpCommand::Auth(_) | SmtpCommand::StartTls) {
                return Some(b"502 5.5.1 Command not supported by LMTP\r\n");
            }
            if self.helo_name.is_none()
                && matches!(
                    command,
                    SmtpCommand::Mail(_)
                        | SmtpCommand::Rcpt(_)
                        | SmtpCommand::Data
                        | SmtpCommand::Bdat(_)
                )
            {
                return Some(b"503 5.5.1 Send LHLO first\r\n");
            }
        } else if matches!(command, SmtpCommand::Lhlo(_)) {
            return Some(b"500 5.5.1 LHLO is only valid for LMTP\r\n");
        }

        let local_webmail_auth = self.local_webmail_auth(command);
        let protected = self.encrypted || self.local_trusted || local_webmail_auth;
        if self.service == SmtpService::Submission {
            if !protected
                && !matches!(
                    command,
                    SmtpCommand::Ehlo(_)
                        | SmtpCommand::Helo(_)
                        | SmtpCommand::StartTls
                        | SmtpCommand::Noop
                        | SmtpCommand::Rset
                        | SmtpCommand::Help
                        | SmtpCommand::Quit
                )
            {
                return Some(b"530 5.7.0 Must issue STARTTLS first\r\n");
            }
            if protected
                && self.authenticated_user.is_none()
                && matches!(command, SmtpCommand::Mail(_))
            {
                return Some(b"530 5.7.0 Authentication required\r\n");
            }
        }

        protocol::preflight(
            command,
            protocol::SessionContext {
                greeted: self.helo_name.is_some(),
                extended_smtp: self.extended_smtp,
                encrypted: protected,
                authenticated: self.authenticated_user.is_some(),
                transaction_active: self.tx.active,
                recipients: self.tx.rcpts.len(),
            },
        )
    }

    /// Discard the transaction (RSET, new greeting, completed message).
    fn reset_transaction(&mut self) {
        self.tx = Transaction::default();
        self.message_id = None;
        self.trace.set_message_id(None);
    }

    /// Abandon the transaction after a rejected message; the client must
    /// start over with MAIL.
    fn abort_transaction(&mut self) {
        self.tx.rcpts.clear();
        self.tx.mail_from = None;
        self.tx.active = false;
        self.tx.bdat_buffer.clear();
        self.tx.bdat_started = false;
    }

    /// This TLS session has channel-binding data for SCRAM-SHA-256-PLUS.
    fn channel_binding_available(&self) -> bool {
        self.encrypted && self.channel_bindings.is_available()
    }

    /// SCRAM-SHA-256-PLUS is configured and listed in the EHLO reply.
    fn scram_plus_advertised(&self) -> bool {
        self.channel_binding_available()
            && self
                .security
                .smtp_sasl_mechanisms
                .iter()
                .any(|mechanism| mechanism.eq_ignore_ascii_case("SCRAM-SHA-256-PLUS"))
    }

    /// `AUTH X-RMAIL-WEBMAIL` from this host's loopback on the submission
    /// service: webmail sending as its signed-in user.
    fn local_webmail_auth(&self, command: &SmtpCommand<'_>) -> bool {
        self.service == SmtpService::Submission
            && self.peer.is_some_and(|peer| peer.ip().is_loopback())
            && matches!(command, SmtpCommand::Auth(args) if args
                .split_ascii_whitespace()
                .next()
                .is_some_and(|mechanism| mechanism.eq_ignore_ascii_case(authenticate::WEBMAIL_MECHANISM)))
    }

    /// The AUTH extension is offered on this session (EHLO lists it until
    /// the client authenticates).
    fn auth_supported(&self) -> bool {
        self.service != SmtpService::Lmtp && self.encrypted && self.db_path.is_some()
    }

    async fn greet(&mut self, reader: &mut SmtpReader, name: &str, verb: &str) -> Result<Flow> {
        if !protocol::valid_helo_domain(name) {
            return reply(reader, b"501 5.5.2 Invalid HELO/EHLO domain\r\n").await;
        }
        let extended = verb != "HELO";
        session_log!(self, "info", "greeting_received", { "verb": verb });
        self.helo_name = Some(name.to_string());
        self.extended_smtp = extended;
        let response = if extended {
            let mut response = format!("250-{} Hello {name}\r\n", server_hostname());
            if self.service != SmtpService::Lmtp && !self.encrypted && self.tls_ctx.is_some() {
                response.push_str("250-STARTTLS\r\n");
            }
            if self.auth_supported() && self.authenticated_user.is_none() {
                response.push_str(&format!(
                    "250-AUTH {}\r\n",
                    protocol::advertised_sasl_mechanisms(
                        &self.security.smtp_sasl_mechanisms,
                        self.channel_binding_available()
                    )
                ));
            }
            response.push_str(&format!("250-SIZE {MAX_MESSAGE_BYTES}\r\n"));
            for extension in [
                "8BITMIME",
                "CHUNKING",
                "BINARYMIME",
                "PIPELINING",
                "SMTPUTF8",
                "DSN",
            ] {
                response.push_str(&format!("250-{extension}\r\n"));
            }
            // RFC 8689: REQUIRETLS is only offered on TLS-protected sessions.
            if self.encrypted {
                response.push_str("250-REQUIRETLS\r\n");
            }
            response.push_str("250 ENHANCEDSTATUSCODES\r\n");
            response
        } else {
            // RFC 2034: HELO/EHLO replies carry no enhanced status code.
            format!("250 {} Hello {name}\r\n", server_hostname())
        };
        send(reader, response.as_bytes()).await?;
        self.reset_transaction();
        Ok(Flow::Continue)
    }

    async fn auth(&mut self, reader: &mut SmtpReader, args: &str) -> Result<Flow> {
        let Some(parsed) = protocol::parse_auth_args(args) else {
            return reply(reader, b"501 5.5.4 Invalid AUTH parameters\r\n").await;
        };
        let mechanism = parsed.mechanism.to_ascii_uppercase();
        let initial = parsed.initial_response;
        session_log!(self, "info", "authentication_attempted", { "encrypted": self.encrypted, "mechanism": mechanism });
        // Webmail on this host: not advertised, loopback submission only.
        if mechanism == authenticate::WEBMAIL_MECHANISM {
            let loopback = self.peer.is_some_and(|peer| peer.ip().is_loopback());
            if self.service != SmtpService::Submission || !loopback {
                return reply(
                    reader,
                    b"504 5.5.4 Unrecognized authentication mechanism\r\n",
                )
                .await;
            }
            if let Some(remaining) = self.peer.and_then(|peer| auth_block_remaining(peer.ip())) {
                let message = format!(
                    "454 4.7.1 Too many failed auth attempts; try again in {}s\r\n",
                    remaining.as_secs()
                );
                return reply(reader, message.as_bytes()).await;
            }
            let outcome = authenticate::handle_webmail(
                reader,
                initial,
                self.db_path.as_ref(),
                self.peer,
                std::path::Path::new(&self.mail_root),
            )
            .await;
            if outcome.disconnected {
                return Ok(Flow::Close);
            }
            if let Some(user) = outcome.authenticated_user {
                session_log!(self, "info", "authentication_succeeded", { "user": user, "mechanism": authenticate::WEBMAIL_MECHANISM });
                self.authenticated_user = Some(user);
                self.local_trusted = true;
            }
            return Ok(Flow::Continue);
        }
        if !self
            .security
            .smtp_sasl_mechanisms
            .iter()
            .any(|configured| configured.eq_ignore_ascii_case(&mechanism))
        {
            return reply(
                reader,
                b"504 5.5.4 Unrecognized authentication mechanism\r\n",
            )
            .await;
        }
        if let Some(remaining) = self.peer.and_then(|peer| auth_block_remaining(peer.ip())) {
            let message = format!(
                "454 4.7.1 Too many failed auth attempts; try again in {}s\r\n",
                remaining.as_secs()
            );
            return reply(reader, message.as_bytes()).await;
        }
        // Credentials only travel over TLS (SMTPS or after STARTTLS).
        if !self.encrypted {
            return reply(
                reader,
                b"538 5.7.11 Encryption required for authentication\r\n",
            )
            .await;
        }
        let db_path = self.db_path.as_ref();
        let outcome = match mechanism.as_str() {
            "PLAIN" | "LOGIN" => {
                authenticate::handle_password(reader, &mechanism, initial, db_path, self.peer).await
            }
            "SCRAM-SHA-256" => {
                let policy = if self.scram_plus_advertised() {
                    ScramChannelBindingPolicy::OfferedButNotSelected
                } else {
                    ScramChannelBindingPolicy::NotOffered
                };
                authenticate::handle_scram(
                    reader,
                    initial,
                    db_path,
                    self.peer,
                    policy,
                    &self.channel_bindings,
                )
                .await
            }
            "SCRAM-SHA-256-PLUS" => {
                if !self.channel_binding_available() {
                    return reply(
                        reader,
                        b"504 5.5.4 SCRAM-SHA-256-PLUS requires TLS channel binding\r\n",
                    )
                    .await;
                }
                authenticate::handle_scram(
                    reader,
                    initial,
                    db_path,
                    self.peer,
                    ScramChannelBindingPolicy::Required,
                    &self.channel_bindings,
                )
                .await
            }
            "OAUTHBEARER" | "XOAUTH2" => {
                let Some(validator) = self.oauth.as_ref() else {
                    return reply(reader, b"454 4.7.0 OAuth authentication is unavailable\r\n")
                        .await;
                };
                authenticate::handle_oauth(
                    reader, &mechanism, initial, db_path, self.peer, validator,
                )
                .await
            }
            // Configuration validation only admits the mechanisms above.
            _ => return Ok(Flow::Continue),
        };
        if outcome.disconnected {
            return Ok(Flow::Close);
        }
        if let Some(user) = outcome.authenticated_user {
            session_log!(self, "info", "authentication_succeeded", { "user": user });
            self.authenticated_user = Some(user);
        }
        Ok(Flow::Continue)
    }

    /// Blocklist check for unauthenticated inbound (port 25) clients only.
    async fn dnsbl_listing(&self) -> Option<rmail_common::dnsbl::Listing> {
        if self.security.dnsbl_zones.is_empty()
            || self.service != SmtpService::Mta
            || self.authenticated_user.is_some()
        {
            return None;
        }
        rmail_common::dnsbl::check(
            self.peer?.ip(),
            &self.security.dnsbl_zones,
            Duration::from_millis(self.security.dnsbl_timeout_ms),
        )
        .await
    }

    async fn mail(&mut self, reader: &mut SmtpReader, args: &str) -> Result<Flow> {
        let parsed = match parse_mail_from_args(args) {
            Ok(parsed) => parsed,
            Err(protocol::EnvelopeError::UnsupportedParameter) => {
                self.tx.mail_from = None;
                self.tx.active = false;
                return reply(reader, b"555 5.5.4 Unsupported MAIL FROM parameter\r\n").await;
            }
            Err(protocol::EnvelopeError::Syntax) => {
                self.tx.mail_from = None;
                self.tx.active = false;
                session_log!(self, "debug", "mail_from_rejected", { "reason": "syntax" });
                return reply(reader, b"501 5.5.2 Syntax: MAIL FROM:<address>\r\n").await;
            }
        };
        if !self.extended_smtp && parsed.has_esmtp_parameters {
            return reply(reader, b"555 5.5.4 ESMTP parameters require EHLO\r\n").await;
        }
        if parsed.require_tls && !self.encrypted {
            return reply(
                reader,
                b"530 5.7.10 REQUIRETLS requires a TLS-protected session\r\n",
            )
            .await;
        }
        if parsed.auth_mailbox.is_some() && !self.auth_supported() {
            return reply(
                reader,
                b"555 5.5.4 AUTH parameter requires the AUTH extension\r\n",
            )
            .await;
        }
        if parsed
            .declared_size
            .is_some_and(|size| size > MAX_MESSAGE_BYTES)
        {
            return reply(reader, b"552 5.3.4 Message size exceeds fixed maximum\r\n").await;
        }
        if let Some(listing) = self.dnsbl_listing().await {
            session_log!(self, "warn", "client_rejected_by_dnsbl", { "zone": listing.zone, "code": listing.code.to_string() });
            self.tx.mail_from = None;
            self.tx.active = false;
            let line = format!(
                "554 5.7.1 Service unavailable; client host blocked using {}\r\n",
                listing.zone
            );
            return reply(reader, line.as_bytes()).await;
        }
        self.tx.body = parsed.body;
        self.tx.smtp_utf8 = parsed.smtp_utf8;
        self.tx.require_tls = parsed.require_tls;
        // RFC 4954 section 5: an AUTH= mailbox from a client that is not
        // authenticated (or that names someone else) is not trusted and is
        // handled as AUTH=<>, so it is never propagated.
        self.tx.auth_submitter = match (parsed.auth_mailbox, self.authenticated_user.as_deref()) {
            (Some(Some(mailbox)), Some(user)) if mailbox.eq_ignore_ascii_case(user) => {
                Some(mailbox)
            }
            _ => None,
        };
        self.tx.dsn = DsnOptions {
            envelope_id: parsed.dsn_envelope_id,
            return_content: parsed.dsn_return,
            ..DsnOptions::default()
        };
        self.generation = self.generation.wrapping_add(1);
        self.tx.mail_from = parsed.sender;
        if self.service == SmtpService::Submission {
            let user = self.authenticated_user.as_deref();
            let sender_matches_identity =
                self.tx.mail_from.as_deref().is_some_and(|sender| {
                    user.is_some_and(|user| sender.eq_ignore_ascii_case(user))
                });
            if !sender_matches_identity {
                self.tx.mail_from = None;
                self.tx.active = false;
                return reply(
                    reader,
                    b"553 5.7.1 Sender address not owned by authenticated user\r\n",
                )
                .await;
            }
            if user.is_some_and(|user| {
                !submission_quota_available(user, self.security.submission_max_messages_per_minute)
            }) {
                self.tx.mail_from = None;
                self.tx.active = false;
                return reply(
                    reader,
                    b"452 4.7.0 Submission message rate limit exceeded\r\n",
                )
                .await;
            }
            if let Some(limit) = user.and_then(|user| {
                sender_limit_reached(
                    user,
                    self.security.submission_max_messages_per_user_per_day,
                    self.security.submission_max_messages_per_domain_per_hour,
                )
            }) {
                self.tx.mail_from = None;
                self.tx.active = false;
                let line: &[u8] = match limit {
                    SenderLimit::UserDaily => {
                        b"452 4.7.0 Daily submission limit exceeded for this account\r\n"
                    }
                    SenderLimit::DomainHourly => {
                        b"452 4.7.0 Hourly submission limit exceeded for this domain\r\n"
                    }
                };
                return reply(reader, line).await;
            }
        }
        self.tx.active = true;
        self.tx.bdat_buffer.clear();
        self.tx.bdat_started = false;
        self.tx.rcpts.clear();
        session_log!(self, "debug", "mail_from_accepted", { "mail_from": self.tx.mail_from, "auth_submitter": self.tx.auth_submitter });
        reply(reader, b"250 2.1.0 Sender OK\r\n").await
    }

    async fn starttls(&mut self, reader: &mut SmtpReader) -> Result<Flow> {
        let Some(acceptor) = self.tls_ctx.clone() else {
            return reply(reader, b"454 4.7.0 TLS not available\r\n").await;
        };
        // RFC 3207: commands pipelined after STARTTLS must not survive the upgrade.
        if !reader.buffer().is_empty() {
            return reply(
                reader,
                b"554 5.5.1 Client did not wait for STARTTLS reply before sending more data\r\n",
            )
            .await;
        }
        send(reader, b"220 2.0.0 Ready to start TLS\r\n").await?;
        self.trace.set_message_id(None);
        Ok(Flow::StartTls(acceptor))
    }

    /// Final reply for a message: one line, or one per RCPT group for LMTP.
    async fn complete_message(&self, reader: &mut SmtpReader, status: &str) -> Result<()> {
        write_message_completion(
            reader.get_mut(),
            self.service,
            &self.lmtp_recipient_groups,
            self.generation,
            status,
        )
        .await?;
        Ok(())
    }

    /// Reject the message with `status` and abandon the transaction.
    async fn fail_message(&mut self, reader: &mut SmtpReader, status: &str) -> Result<Flow> {
        self.complete_message(reader, status).await?;
        self.abort_transaction();
        Ok(Flow::Continue)
    }
}

async fn write_message_completion<W: AsyncWrite + Unpin>(
    writer: &mut W,
    service: SmtpService,
    recipient_groups: &[(u64, String, Vec<String>)],
    transaction_generation: u64,
    status: &str,
) -> std::io::Result<()> {
    if service == SmtpService::Lmtp {
        for (_, original, _) in recipient_groups
            .iter()
            .filter(|(generation, _, _)| *generation == transaction_generation)
        {
            writer
                .write_all(format!("{status} <{original}>\r\n").as_bytes())
                .await?;
        }
    } else {
        writer.write_all(format!("{status}\r\n").as_bytes()).await?;
    }
    writer.flush().await
}
