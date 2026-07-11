use anyhow::{Context, Result, anyhow};
use async_compression::tokio::bufread::ZlibDecoder;
use async_compression::tokio::write::ZlibEncoder;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use rmail_common::db::Mailbox;
use rmail_common::{auth as common_auth, config::Config, maildir, net::bind_tcp_listener};
use std::io::ErrorKind;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::{net::SocketAddr, sync::Arc};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

mod auth;
mod commands;
mod mailbox;
mod parser;
mod response;
mod sort;
mod state;
mod thread;
mod tls;
use mailbox::SelectedMailbox;
use tls::load_tls_context;

const MAX_APPEND_LITERAL_BYTES: usize = 100 * 1024 * 1024;
const MAX_PREAUTH_LINE_BYTES: usize = 8 * 1024;
const MAX_AUTHENTICATED_LINE_BYTES: usize = 64 * 1024;
const MAX_SASL_RESPONSE_BYTES: usize = 64 * 1024;

// Trait object helper: combine AsyncRead + AsyncWrite into a single object-safe trait and require Unpin
// so that boxed trait objects can be used with tokio::io::BufReader.
trait RawStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized> RawStream for T {}

trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {
    fn enable_deflate(&mut self) -> std::io::Result<()>;
    fn compression_active(&self) -> bool;
}

enum SwitchableState {
    Raw(Box<dyn RawStream + Send + 'static>),
    Deflate {
        reader: ZlibDecoder<BufReader<tokio::io::ReadHalf<Box<dyn RawStream + Send + 'static>>>>,
        writer: ZlibEncoder<tokio::io::WriteHalf<Box<dyn RawStream + Send + 'static>>>,
    },
    Transition,
}

struct SwitchableStream {
    state: SwitchableState,
}

impl SwitchableStream {
    fn new(stream: Box<dyn RawStream + Send + 'static>) -> Self {
        Self {
            state: SwitchableState::Raw(stream),
        }
    }
}

impl AsyncStream for SwitchableStream {
    fn enable_deflate(&mut self) -> std::io::Result<()> {
        let state = std::mem::replace(&mut self.state, SwitchableState::Transition);
        match state {
            SwitchableState::Raw(stream) => {
                let (read, write) = tokio::io::split(stream);
                self.state = SwitchableState::Deflate {
                    reader: ZlibDecoder::new(BufReader::new(read)),
                    writer: ZlibEncoder::new(write),
                };
                Ok(())
            }
            other => {
                self.state = other;
                Err(std::io::Error::new(
                    ErrorKind::AlreadyExists,
                    "compression already active",
                ))
            }
        }
    }

    fn compression_active(&self) -> bool {
        matches!(self.state, SwitchableState::Deflate { .. })
    }
}

impl tokio::io::AsyncRead for SwitchableStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.state {
            SwitchableState::Raw(stream) => Pin::new(stream).poll_read(cx, buf),
            SwitchableState::Deflate { reader, .. } => Pin::new(reader).poll_read(cx, buf),
            SwitchableState::Transition => Poll::Ready(Err(std::io::Error::other(
                "compression transition in progress",
            ))),
        }
    }
}

impl tokio::io::AsyncWrite for SwitchableStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut self.state {
            SwitchableState::Raw(stream) => Pin::new(stream).poll_write(cx, buf),
            SwitchableState::Deflate { writer, .. } => Pin::new(writer).poll_write(cx, buf),
            SwitchableState::Transition => Poll::Ready(Err(std::io::Error::other(
                "compression transition in progress",
            ))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.state {
            SwitchableState::Raw(stream) => Pin::new(stream).poll_flush(cx),
            SwitchableState::Deflate { writer, .. } => Pin::new(writer).poll_flush(cx),
            SwitchableState::Transition => Poll::Ready(Err(std::io::Error::other(
                "compression transition in progress",
            ))),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.state {
            SwitchableState::Raw(stream) => Pin::new(stream).poll_shutdown(cx),
            SwitchableState::Deflate { writer, .. } => Pin::new(writer).poll_shutdown(cx),
            SwitchableState::Transition => Poll::Ready(Err(std::io::Error::other(
                "compression transition in progress",
            ))),
        }
    }
}

enum BoundedLine {
    Eof,
    Line(Vec<u8>),
    TooLong,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SaslProtocolError {
    Cancelled,
    InvalidResponse,
    ResponseTooLarge,
    Eof,
}

async fn read_sasl_wire_response(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
) -> std::result::Result<String, SaslProtocolError> {
    let line = match read_bounded_line(reader, MAX_SASL_RESPONSE_BYTES)
        .await
        .map_err(|_| SaslProtocolError::Eof)?
    {
        BoundedLine::Eof => return Err(SaslProtocolError::Eof),
        BoundedLine::TooLong => return Err(SaslProtocolError::ResponseTooLarge),
        BoundedLine::Line(line) => line,
    };
    let line = std::str::from_utf8(&line)
        .map_err(|_| SaslProtocolError::InvalidResponse)?
        .trim_end_matches(['\r', '\n']);
    if line == "*" {
        Err(SaslProtocolError::Cancelled)
    } else {
        Ok(line.to_string())
    }
}

async fn run_password_sasl_exchange(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    exchange: &mut dyn auth::SaslExchange,
    initial: Option<&str>,
) -> std::result::Result<auth::SaslCredentials, SaslProtocolError> {
    let mut progress = exchange
        .start(initial)
        .map_err(|_| SaslProtocolError::InvalidResponse)?;
    loop {
        match progress {
            auth::SaslProgress::Credentials(credentials) => return Ok(credentials),
            auth::SaslProgress::Challenge(challenge) => {
                let w = reader.get_mut();
                w.write_all(format!("+ {}\r\n", challenge).as_bytes())
                    .await
                    .map_err(|_| SaslProtocolError::Eof)?;
                w.flush().await.map_err(|_| SaslProtocolError::Eof)?;
                let line = read_sasl_wire_response(reader).await?;
                progress = exchange
                    .receive(&line)
                    .map_err(|_| SaslProtocolError::InvalidResponse)?;
            }
            auth::SaslProgress::ScramClientFirst(_)
            | auth::SaslProgress::ScramClientFinal(_)
            | auth::SaslProgress::Complete => return Err(SaslProtocolError::InvalidResponse),
        }
    }
}

async fn read_bounded_line(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    limit: usize,
) -> std::io::Result<BoundedLine> {
    let mut line = Vec::new();
    let mut too_long = false;
    loop {
        let (consume, found_newline) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                return if line.is_empty() {
                    Ok(BoundedLine::Eof)
                } else if too_long {
                    Ok(BoundedLine::TooLong)
                } else {
                    Ok(BoundedLine::Line(line))
                };
            }
            let consume = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|index| index + 1)
                .unwrap_or(available.len());
            if !too_long {
                if line.len().saturating_add(consume) > limit {
                    too_long = true;
                    line.clear();
                } else {
                    line.extend_from_slice(&available[..consume]);
                }
            }
            (
                consume,
                available.get(consume.saturating_sub(1)) == Some(&b'\n'),
            )
        };
        reader.consume(consume);
        if found_newline {
            return if too_long {
                Ok(BoundedLine::TooLong)
            } else {
                Ok(BoundedLine::Line(line))
            };
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrailingLiteralMarker {
    start: usize,
    size: usize,
    non_sync: bool,
    literal8: bool,
}

fn trailing_literal_marker(line: &[u8]) -> Option<TrailingLiteralMarker> {
    let end = line
        .iter()
        .rposition(|byte| !matches!(byte, b'\r' | b'\n'))?
        + 1;
    if line.get(end.checked_sub(1)?) != Some(&b'}') {
        return None;
    }
    let open = line[..end].iter().rposition(|byte| *byte == b'{')?;
    let literal8 = open > 0 && line[open - 1] == b'~';
    let start = if literal8 { open - 1 } else { open };
    let mut digits = &line[open + 1..end - 1];
    let non_sync = digits.last() == Some(&b'+');
    if non_sync {
        digits = &digits[..digits.len().checked_sub(1)?];
    }
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let size = std::str::from_utf8(digits).ok()?.parse::<usize>().ok()?;
    Some(TrailingLiteralMarker {
        start,
        size,
        non_sync,
        literal8,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandLiteralError {
    TooLarge,
    Literal8,
    NonSyncLiteral8,
    InvalidUtf8,
    Eof,
    Io,
}

async fn read_textual_command_literals(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    mut command: Vec<u8>,
    line_limit: usize,
) -> std::result::Result<Vec<u8>, CommandLiteralError> {
    let mut total_literal_bytes = 0usize;
    loop {
        let Some(marker) = trailing_literal_marker(&command) else {
            return Ok(command);
        };
        if marker.literal8 {
            return Err(if marker.non_sync {
                CommandLiteralError::NonSyncLiteral8
            } else {
                CommandLiteralError::Literal8
            });
        }
        total_literal_bytes = total_literal_bytes
            .checked_add(marker.size)
            .ok_or(CommandLiteralError::TooLarge)?;
        if total_literal_bytes > MAX_APPEND_LITERAL_BYTES {
            return Err(CommandLiteralError::TooLarge);
        }
        if !marker.non_sync {
            let w = reader.get_mut();
            w.write_all(b"+ Ready for literal data\r\n")
                .await
                .map_err(|_| CommandLiteralError::Io)?;
            w.flush().await.map_err(|_| CommandLiteralError::Io)?;
        }
        let mut literal = vec![0; marker.size];
        reader
            .read_exact(&mut literal)
            .await
            .map_err(|error| match error.kind() {
                ErrorKind::UnexpectedEof => CommandLiteralError::Eof,
                _ => CommandLiteralError::Io,
            })?;
        let literal_is_utf8 = std::str::from_utf8(&literal).is_ok();
        command.truncate(marker.start);
        command.push(b'"');
        for byte in literal {
            if matches!(byte, b'"' | b'\\') {
                command.push(b'\\');
            }
            command.push(byte);
        }
        command.push(b'"');
        let tail = match read_bounded_line(reader, line_limit)
            .await
            .map_err(|_| CommandLiteralError::Io)?
        {
            BoundedLine::Line(line) => line,
            BoundedLine::Eof => return Err(CommandLiteralError::Eof),
            BoundedLine::TooLong => return Err(CommandLiteralError::TooLarge),
        };
        command.extend_from_slice(&tail);
        if !literal_is_utf8 {
            return Err(CommandLiteralError::InvalidUtf8);
        }
        if command.len() > line_limit.saturating_add(total_literal_bytes) {
            return Err(CommandLiteralError::TooLarge);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{process_stream, process_stream_inner};
    use crate::response::{CapabilityPhase, capability_tokens};
    use async_compression::tokio::bufread::ZlibDecoder;
    use async_compression::tokio::write::ZlibEncoder;
    use base64::Engine;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, duplex};

    async fn read_until_contains<R>(reader: &mut R, needle: &str) -> Vec<String>
    where
        R: tokio::io::AsyncBufRead + Unpin,
    {
        let mut out = Vec::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read line");
            if line.is_empty() {
                break;
            }
            out.push(line.clone());
            if line.contains(needle) {
                return out;
            }
        }
        out
    }

    async fn run_scripted_fixture(reader: &mut BufReader<tokio::io::DuplexStream>, fixture: &str) {
        for raw_line in fixture.lines() {
            let line = raw_line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(command) = line.strip_prefix("C: ") {
                reader
                    .get_mut()
                    .write_all(format!("{}\r\n", command).as_bytes())
                    .await
                    .expect("write fixture command");
                reader.get_mut().flush().await.expect("flush fixture");
            } else if let Some(expected) = line.strip_prefix("S: ") {
                let lines = read_until_contains(reader, expected).await;
                assert!(
                    lines.iter().any(|line| line.contains(expected)),
                    "expected fixture response containing {expected:?}, got {lines:?}"
                );
            } else {
                panic!("invalid fixture line: {line}");
            }
        }
    }

    async fn run_compatibility_fixture(fixture: &str) {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Date: Sun, 14 Jun 2026 12:00:00 +0000\r\nFrom: alice@example.test\r\nTo: user@example.test\r\nSubject: one\r\nMessage-ID: <one@example.test>\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nfirst body\r\n",
        )
        .expect("deliver first");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Date: Mon, 15 Jun 2026 12:00:00 +0000\r\nFrom: bob@example.test\r\nTo: user@example.test\r\nSubject: two\r\nMessage-ID: <two@example.test>\r\nReferences: <one@example.test>\r\nContent-Type: multipart/alternative; boundary=\"alt\"\r\n\r\n--alt\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nsecond plain\r\n--alt\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<p>second html</p>\r\n--alt--\r\n",
        )
        .expect("deliver second");

        let (client, server) = duplex(128 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });
        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        run_scripted_fixture(&mut reader, fixture).await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn fetch_refreshes_after_new_delivery() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Subject: one\r\n\r\nfirst\r\n",
        )
        .expect("deliver first");

        let (client, server) = duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        assert!(greeting.starts_with("* OK"));

        reader
            .get_mut()
            .write_all(b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\n")
            .await
            .expect("write login/select");
        reader.get_mut().flush().await.expect("flush");

        let select_lines = read_until_contains(&mut reader, "A002 OK").await;
        assert!(select_lines.iter().any(|l| l.contains("* 1 EXISTS")));

        rmail_common::maildir::deliver(
            td.path().join("mail").as_path(),
            "example.test",
            "user",
            b"Subject: two\r\n\r\nsecond\r\n",
        )
        .expect("deliver second");

        reader
            .get_mut()
            .write_all(b"A003 FETCH 1:* RFC822\r\nA004 LOGOUT\r\n")
            .await
            .expect("write fetch");
        reader.get_mut().flush().await.expect("flush");

        let fetch_lines = read_until_contains(&mut reader, "A003 OK").await;
        let fetched = fetch_lines
            .iter()
            .filter(|l| l.starts_with("* ") && l.contains(" FETCH "))
            .count();
        assert_eq!(fetched, 2);

        let logout_lines = read_until_contains(&mut reader, "A004 OK").await;
        assert!(logout_lines.iter().any(|l| l.starts_with("* BYE")));

        server_task.await.expect("join").expect("server");
    }

    #[test]
    fn capability_advertises_starttls_and_login_policy() {
        let plain_caps = capability_tokens(CapabilityPhase::NotAuthenticatedPlain, false);
        assert!(plain_caps.contains("LOGINDISABLED"));
        assert!(plain_caps.contains("SASL-IR"));
        assert!(plain_caps.contains("ENABLE"));
        assert!(plain_caps.contains("LITERAL-"));
        assert!(plain_caps.contains("LITERAL+"));
        assert!(!plain_caps.contains("AUTH=PLAIN"));
        assert!(plain_caps.contains("AUTH=SCRAM-SHA-256"));
        assert!(!plain_caps.contains("STARTTLS"));
        assert!(!plain_caps.contains("CONDSTORE"));
        assert!(!plain_caps.contains("QRESYNC"));
        assert!(!plain_caps.contains("COMPRESS=DEFLATE"));

        let starttls_caps = capability_tokens(CapabilityPhase::NotAuthenticatedPlain, true);
        assert!(starttls_caps.contains("STARTTLS"));

        let tls_caps = capability_tokens(CapabilityPhase::NotAuthenticatedTls, false);
        assert!(!tls_caps.contains("LOGINDISABLED"));
        assert!(tls_caps.contains("SASL-IR"));
        assert!(tls_caps.contains("ENABLE"));
        assert!(tls_caps.contains("AUTH=PLAIN"));
        assert!(tls_caps.contains("AUTH=LOGIN"));
        assert!(tls_caps.contains("AUTH=SCRAM-SHA-256"));
        assert!(!tls_caps.contains("AUTH=SCRAM-SHA-256-PLUS"));
        assert!(tls_caps.contains("LITERAL-"));
        assert!(tls_caps.contains("LITERAL+"));
        assert!(!tls_caps.contains("STARTTLS"));
        assert!(!tls_caps.contains("CONDSTORE"));
        assert!(!tls_caps.contains("QRESYNC"));
        assert!(!tls_caps.contains("COMPRESS=DEFLATE"));

        let tls_binding_caps = capability_tokens(CapabilityPhase::NotAuthenticatedTls, true);
        assert!(tls_binding_caps.contains("AUTH=SCRAM-SHA-256-PLUS"));

        let authenticated = capability_tokens(CapabilityPhase::Authenticated, false);
        assert!(authenticated.contains("UIDPLUS"));
        assert!(authenticated.contains("CONDSTORE"));
        assert!(authenticated.contains("UNSELECT"));
        assert!(!authenticated.contains("AUTH=PLAIN"));
        assert!(!authenticated.contains("LOGINDISABLED"));
        assert!(!authenticated.contains("STARTTLS"));
        assert_eq!(
            authenticated,
            capability_tokens(CapabilityPhase::Selected, false)
        );
    }

    #[tokio::test]
    async fn compress_deflate_round_trip_and_rejects_duplicate_activation() {
        let td = tempfile::tempdir().expect("tempdir");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("mailbox");
        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(process_stream(
            Box::new(server),
            td.path().join("mail").to_string_lossy().to_string(),
            None,
            Some(db_path.to_string_lossy().to_string()),
            None,
            true,
        ));
        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("greeting");
        line.clear();
        reader.read_line(&mut line).await.expect("capability");
        reader
            .get_mut()
            .write_all(b"A001 LOGIN \"user@example.test\" \"password\"\r\n")
            .await
            .expect("login");
        reader.get_mut().flush().await.expect("flush");
        let _login = read_until_contains(&mut reader, "A001 OK").await;
        reader
            .get_mut()
            .write_all(b"A002 CAPABILITY\r\n")
            .await
            .expect("capability");
        reader.get_mut().flush().await.expect("flush");
        let caps = read_until_contains(&mut reader, "A002 OK").await.join("");
        assert!(caps.contains("COMPRESS=DEFLATE"));
        reader
            .get_mut()
            .write_all(b"A003 COMPRESS DEFLATE\r\n")
            .await
            .expect("compress");
        reader.get_mut().flush().await.expect("flush");
        let switched = read_until_contains(&mut reader, "A003 OK").await.join("");
        assert!(switched.contains("Begin compression"));

        let (read, write) = tokio::io::split(reader.into_inner());
        let mut compressed_reader = BufReader::new(ZlibDecoder::new(BufReader::new(read)));
        let mut compressed_writer = ZlibEncoder::new(write);
        compressed_writer
            .write_all(b"A004 NOOP\r\nA005 CAPABILITY\r\nA006 COMPRESS DEFLATE\r\nA007 LOGOUT\r\n")
            .await
            .expect("compressed commands");
        compressed_writer.flush().await.expect("compressed flush");
        let noop = read_until_contains(&mut compressed_reader, "A004 OK")
            .await
            .join("");
        assert!(noop.contains("NOOP completed"));
        let compressed_caps = read_until_contains(&mut compressed_reader, "A005 OK")
            .await
            .join("");
        assert!(compressed_caps.contains("COMPRESS=DEFLATE"));
        let duplicate = read_until_contains(&mut compressed_reader, "A006 NO")
            .await
            .join("");
        assert!(duplicate.contains("COMPRESSIONACTIVE"));
        let _logout = read_until_contains(&mut compressed_reader, "A007 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn compress_rejects_pipelined_plaintext_without_switching_streams() {
        let td = tempfile::tempdir().expect("tempdir");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("mailbox");
        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(process_stream(
            Box::new(server),
            td.path().join("mail").to_string_lossy().to_string(),
            None,
            Some(db_path.to_string_lossy().to_string()),
            None,
            true,
        ));
        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("greeting");
        line.clear();
        reader.read_line(&mut line).await.expect("capability");
        reader
            .get_mut()
            .write_all(b"A001 LOGIN \"user@example.test\" \"password\"\r\n")
            .await
            .expect("login");
        reader.get_mut().flush().await.expect("flush");
        let _login = read_until_contains(&mut reader, "A001 OK").await;
        reader
            .get_mut()
            .write_all(b"A002 COMPRESS DEFLATE\r\nA003 NOOP\r\n")
            .await
            .expect("pipeline");
        reader.get_mut().flush().await.expect("flush");
        let rejected = read_until_contains(&mut reader, "A002 BAD").await.join("");
        assert!(rejected.contains("did not wait for COMPRESS reply"));
        let noop = read_until_contains(&mut reader, "A003 OK").await.join("");
        assert!(noop.contains("NOOP completed"));
        reader
            .get_mut()
            .write_all(b"A004 LOGOUT\r\n")
            .await
            .expect("logout");
        reader.get_mut().flush().await.expect("flush");
        let _logout = read_until_contains(&mut reader, "A004 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn post_starttls_session_continues_without_a_second_greeting() {
        let td = tempfile::tempdir().expect("tempdir");
        let (client, server) = duplex(8 * 1024);
        let server_task = tokio::spawn(process_stream_inner(
            Box::new(server),
            td.path().to_string_lossy().to_string(),
            None::<Arc<super::tls::TlsContext>>,
            None,
            None,
            true,
            false,
        ));
        let mut reader = BufReader::new(client);
        reader
            .get_mut()
            .write_all(b"A001 CAPABILITY\r\nA002 LOGOUT\r\n")
            .await
            .expect("commands");
        reader.get_mut().flush().await.expect("flush");

        let mut first = String::new();
        reader.read_line(&mut first).await.expect("first response");
        assert!(first.starts_with("* CAPABILITY "));
        assert!(!first.contains("rMail IMAPD ready"));
        let _capability = read_until_contains(&mut reader, "A001 OK").await;
        let _logout = read_until_contains(&mut reader, "A002 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn id_accepts_nil_and_client_fields_and_rejects_malformed_lists() {
        let td = tempfile::tempdir().expect("tempdir");
        let (client, server) = duplex(8 * 1024);
        let server_task = tokio::spawn(process_stream(
            Box::new(server),
            td.path().to_string_lossy().to_string(),
            None::<Arc<super::tls::TlsContext>>,
            None,
            None,
            true,
        ));
        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        reader
            .get_mut()
            .write_all(
                b"A001 ID NIL\r\nA002 ID (\"name\" \"Geary\" \"version\" \"46.0\")\r\nA003 ID (\"name\")\r\nA004 LOGOUT\r\n",
            )
            .await
            .expect("commands");
        reader.get_mut().flush().await.expect("flush");

        let nil = read_until_contains(&mut reader, "A001 OK").await.join("");
        assert!(nil.contains("* ID (\"name\" \"rMail\""));
        let fields = read_until_contains(&mut reader, "A002 OK").await.join("");
        assert!(fields.contains(&format!("\"version\" \"{}\"", env!("CARGO_PKG_VERSION"))));
        let malformed = read_until_contains(&mut reader, "A003 BAD").await.join("");
        assert!(malformed.contains("Invalid ID arguments"));
        let _logout = read_until_contains(&mut reader, "A004 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn command_framing_rejects_invalid_tags_utf8_and_oversized_lines_then_recovers() {
        let td = tempfile::tempdir().expect("tempdir");
        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(process_stream(
            Box::new(server),
            td.path().to_string_lossy().to_string(),
            None::<Arc<super::tls::TlsContext>>,
            None,
            None,
            true,
        ));
        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        let mut input = Vec::new();
        input.extend_from_slice(b"bad+tag NOOP\r\n");
        input.extend_from_slice(b"A001\r\n");
        input.extend_from_slice(b"A002 NOOP \xff\r\n");
        input.extend_from_slice(&vec![b'x'; super::MAX_PREAUTH_LINE_BYTES + 1]);
        input.extend_from_slice(b"\r\nA003 NOOP\r\nA004 LOGOUT\r\n");
        reader.get_mut().write_all(&input).await.expect("commands");
        reader.get_mut().flush().await.expect("flush");

        let invalid_tag = read_until_contains(&mut reader, "* BAD").await.join("");
        assert!(invalid_tag.contains("InvalidTag"));
        let missing_command = read_until_contains(&mut reader, "A001 BAD").await.join("");
        assert!(missing_command.contains("MissingCommand"));
        let invalid_utf8 = read_until_contains(&mut reader, "* BAD").await.join("");
        assert!(invalid_utf8.contains("not valid UTF-8"));
        let oversized = read_until_contains(&mut reader, "* BAD").await.join("");
        assert!(oversized.contains("Command line too long"));
        let recovered = read_until_contains(&mut reader, "A003 OK").await.join("");
        assert!(recovered.contains("NOOP completed"));
        let _logout = read_until_contains(&mut reader, "A004 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[test]
    fn unsupported_log_selected_mailbox_placeholder_is_stable() {
        assert_eq!(super::selected_mailbox_for_log(&None), "-");
    }

    #[tokio::test]
    async fn enable_tracks_supported_session_features_only_after_authentication() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");

        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        assert!(capability.contains("ENABLE"));

        reader
            .get_mut()
            .write_all(
                b"A001 ENABLE IMAP4rev1\r\nA002 LOGIN \"user@example.test\" \"password\"\r\nA003 ENABLE IMAP4rev1 CONDSTORE QRESYNC UTF8=ACCEPT\r\nA004 ENABLE QRESYNC\r\nA005 LOGOUT\r\n",
            )
            .await
            .expect("write enable commands");
        reader.get_mut().flush().await.expect("flush");

        let preauth = read_until_contains(&mut reader, "A001 NO").await;
        assert!(
            preauth
                .iter()
                .any(|l| l.contains("Authentication required"))
        );
        let _login = read_until_contains(&mut reader, "A002 OK").await;
        let enabled = read_until_contains(&mut reader, "A003 OK").await;
        assert!(
            enabled
                .iter()
                .any(|l| l.trim_end() == "* ENABLED CONDSTORE IMAP4REV1 QRESYNC UTF8=ACCEPT")
        );
        assert!(enabled.iter().any(|l| l.contains("QRESYNC")));
        assert!(enabled.iter().any(|l| l.contains("UTF8=ACCEPT")));
        let ignored = read_until_contains(&mut reader, "A004 OK").await;
        assert!(ignored.iter().any(|l| l.trim_end() == "* ENABLED QRESYNC"));
        let _logout = read_until_contains(&mut reader, "A005 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn condstore_select_fetch_status_and_conditional_store_work() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        rmail_common::imap_state::append_message(
            mail_root.as_path(),
            "example.test",
            "user",
            "INBOX",
            b"Subject: one\r\n\r\nfirst",
            vec![],
        )
        .expect("append first");
        rmail_common::imap_state::append_message(
            mail_root.as_path(),
            "example.test",
            "user",
            "INBOX",
            b"Subject: two\r\n\r\nsecond",
            vec![],
        )
        .expect("append second");

        let server_mail_root = mail_root.clone();
        let server_db_path = db_path.clone();
        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                server_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(server_db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        assert!(!capability.contains("CONDSTORE"));
        assert!(!capability.contains("QRESYNC"));

        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 ENABLE CONDSTORE\r\nA003 SELECT INBOX (CONDSTORE)\r\nA004 STATUS INBOX (MESSAGES UIDNEXT HIGHESTMODSEQ)\r\nA005 UID FETCH 1:* (UID FLAGS MODSEQ)\r\nA006 UID FETCH 1:* (UID FLAGS MODSEQ) (CHANGEDSINCE 999999)\r\nA007 UID STORE 1 (UNCHANGEDSINCE 1) +FLAGS (\\Seen)\r\nA008 UID STORE 1 (UNCHANGEDSINCE 999999) +FLAGS (\\Seen)\r\nA009 UID FETCH 1:* (UID FLAGS MODSEQ) (CHANGEDSINCE 1)\r\nA010 LOGOUT\r\n",
            )
            .await
            .expect("write condstore commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let enabled = read_until_contains(&mut reader, "A002 OK").await;
        assert!(
            enabled
                .iter()
                .any(|line| line.trim_end() == "* ENABLED CONDSTORE")
        );
        let select = read_until_contains(&mut reader, "A003 OK").await;
        assert!(select.iter().any(|line| line.contains("[HIGHESTMODSEQ ")));
        let status = read_until_contains(&mut reader, "A004 OK").await;
        assert!(
            status
                .iter()
                .any(|line| line.contains("HIGHESTMODSEQ") && line.contains("MESSAGES 2"))
        );
        let fetch = read_until_contains(&mut reader, "A005 OK").await;
        assert_eq!(
            fetch
                .iter()
                .filter(|line| line.starts_with("* ") && line.contains(" FETCH "))
                .count(),
            2
        );
        assert!(fetch.iter().all(|line| {
            !(line.starts_with("* ") && line.contains(" FETCH "))
                || (line.contains("UID ") && line.contains("MODSEQ ("))
        }));
        let changed_since_future = read_until_contains(&mut reader, "A006 OK").await;
        assert!(
            !changed_since_future
                .iter()
                .any(|line| line.starts_with("* ") && line.contains(" FETCH "))
        );
        let conditional_fail = read_until_contains(&mut reader, "A007 OK").await;
        assert!(
            conditional_fail
                .iter()
                .any(|line| line.contains("[MODIFIED 1]"))
        );
        let conditional_success = read_until_contains(&mut reader, "A008 OK").await;
        assert!(
            conditional_success
                .iter()
                .any(|line| line.contains("FETCH") && line.contains("MODSEQ ("))
        );
        let changed_since_past = read_until_contains(&mut reader, "A009 OK").await;
        assert!(
            changed_since_past
                .iter()
                .filter(|line| line.starts_with("* ") && line.contains(" FETCH "))
                .count()
                >= 1
        );
        let _logout = read_until_contains(&mut reader, "A010 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn qresync_select_returns_vanished_changes_and_uses_vanished_for_live_expunges() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        let mut uids = Vec::new();
        for subject in ["one", "two", "three"] {
            let (_, uid) = rmail_common::imap_state::append_message(
                &mail_root,
                "example.test",
                "user",
                "INBOX",
                format!("Subject: {}\r\n\r\n", subject).as_bytes(),
                Vec::new(),
            )
            .expect("append");
            uids.push(uid);
        }
        let (baseline_folder, _) =
            rmail_common::imap_state::load_folder(&mail_root, "example.test", "user", "INBOX")
                .expect("baseline");
        rmail_common::imap_state::set_uid_flags(
            &mail_root,
            "example.test",
            "user",
            "INBOX",
            uids[0],
            vec!["\\Seen".to_string()],
        )
        .expect("flag change");
        rmail_common::imap_state::delete_message_by_uid(
            &mail_root,
            "example.test",
            "user",
            "INBOX",
            uids[1],
        )
        .expect("delete");
        rmail_common::imap_state::append_message(
            &mail_root,
            "example.test",
            "user",
            "INBOX",
            b"Subject: new\r\n\r\n",
            Vec::new(),
        )
        .expect("new delivery");

        let server_mail_root = mail_root.clone();
        let server_db_path = db_path.clone();
        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                server_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(server_db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });
        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        reader
            .get_mut()
            .write_all(
                format!(
                    "A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX (QRESYNC ({} {} 1:3))\r\nA003 ENABLE QRESYNC\r\nA004 SELECT INBOX (QRESYNC ({} {} 1:3))\r\n",
                    baseline_folder.uidvalidity,
                    baseline_folder.highest_modseq,
                    baseline_folder.uidvalidity,
                    baseline_folder.highest_modseq
                )
                .as_bytes(),
            )
            .await
            .expect("initial commands");
        reader.get_mut().flush().await.expect("flush");
        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let disabled = read_until_contains(&mut reader, "A002 BAD").await.join("");
        assert!(disabled.contains("QRESYNC is not enabled"));
        let _enable = read_until_contains(&mut reader, "A003 OK").await;
        let select = read_until_contains(&mut reader, "A004 OK").await.join("");
        assert!(select.contains("* VANISHED (EARLIER) 2"));
        assert!(select.contains("FETCH (UID 1 FLAGS (\\Seen) MODSEQ"));
        assert!(!select.contains("FETCH (UID 4 "));

        reader
            .get_mut()
            .write_all(b"A005 UID STORE 1 +FLAGS (\\Deleted)\r\nA006 UID EXPUNGE 1\r\n")
            .await
            .expect("expunge commands");
        reader.get_mut().flush().await.expect("flush");
        let _store = read_until_contains(&mut reader, "A005 OK").await;
        let expunge = read_until_contains(&mut reader, "A006 OK").await.join("");
        assert!(expunge.contains("* VANISHED 1"));
        assert!(!expunge.contains("* 1 EXPUNGE"));

        let (_, current) =
            rmail_common::imap_state::load_folder(&mail_root, "example.test", "user", "INBOX")
                .expect("current folder");
        let uid3 = current.iter().find(|message| message.uid == 3).unwrap();
        std::fs::remove_file(&uid3.path).expect("external remove");
        reader
            .get_mut()
            .write_all(
                format!(
                    "A007 NOOP\r\nA008 SELECT INBOX (QRESYNC ({} 1))\r\nA009 SELECT INBOX (QRESYNC ({} 1))\r\nA010 LOGOUT\r\n",
                    baseline_folder.uidvalidity,
                    baseline_folder.uidvalidity.saturating_add(1)
                )
                .as_bytes(),
            )
            .await
            .expect("final commands");
        reader.get_mut().flush().await.expect("flush");
        let noop = read_until_contains(&mut reader, "A007 OK").await.join("");
        assert!(noop.contains("* VANISHED 3"));
        let reselect = read_until_contains(&mut reader, "A008 OK").await.join("");
        assert!(reselect.contains("* OK [CLOSED]"));
        let mismatch = read_until_contains(&mut reader, "A009 OK").await.join("");
        assert!(mismatch.contains("* OK [CLOSED]"));
        assert!(!mismatch.contains("VANISHED (EARLIER)"));
        let _logout = read_until_contains(&mut reader, "A010 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn examine_selected_mailbox_is_read_only_for_mutating_commands() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        let (_uidvalidity, uid) = rmail_common::imap_state::append_message(
            mail_root.as_path(),
            "example.test",
            "user",
            "INBOX",
            b"Subject: read only\r\n\r\nbody",
            vec!["\\Deleted".to_string()],
        )
        .expect("append");

        let server_mail_root = mail_root.clone();
        let server_db_path = db_path.clone();
        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                server_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(server_db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 EXAMINE INBOX\r\nA003 UID STORE 1 +FLAGS (\\Seen)\r\nA004 STORE 1 +FLAGS (\\Seen)\r\nA005 EXPUNGE\r\nA006 UID EXPUNGE 1\r\nA007 MOVE 1 Trash\r\nA008 UID MOVE 1 Trash\r\nA009 UID COPY 1 Archive\r\nA010 CLOSE\r\nA011 SELECT INBOX\r\nA012 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let examine = read_until_contains(&mut reader, "A002 OK").await;
        assert!(
            examine
                .iter()
                .any(|line| line.contains("OK [READ-ONLY] EXAMINE completed"))
        );
        for tag in ["A003", "A004", "A005", "A006", "A007", "A008"] {
            let lines = read_until_contains(&mut reader, &format!("{tag} NO")).await;
            assert!(
                lines
                    .iter()
                    .any(|line| line.contains("Mailbox is read-only")),
                "expected read-only rejection for {tag}, got {lines:?}"
            );
        }
        let copy = read_until_contains(&mut reader, "A009 OK").await;
        assert!(copy.iter().any(|line| line.contains("COPY completed")));
        let close = read_until_contains(&mut reader, "A010 OK").await;
        assert!(close.iter().any(|line| line.contains("CLOSE completed")));
        let select = read_until_contains(&mut reader, "A011 OK").await;
        assert!(select.iter().any(|line| line.trim_end() == "* 1 EXISTS"));
        let _logout = read_until_contains(&mut reader, "A012 OK").await;
        server_task.await.expect("join").expect("server");

        let (_folder, messages) = rmail_common::imap_state::load_folder(
            mail_root.as_path(),
            "example.test",
            "user",
            "INBOX",
        )
        .expect("load inbox");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].uid, uid);
        assert_eq!(messages[0].flags, vec!["\\Deleted"]);
    }

    #[tokio::test]
    async fn authenticate_plain_is_tls_only_and_logs_in() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");

        let payload = crate::BASE64_ENGINE.encode(b"\0user@example.test\0password");
        let (client, server) = duplex(32 * 1024);
        let encrypted_mail_root = mail_root.clone();
        let encrypted_db_path = db_path.clone();
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                encrypted_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(encrypted_db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        assert!(capability.contains("AUTH=PLAIN"));
        reader
            .get_mut()
            .write_all(
                format!(
                    "A001 AUTHENTICATE PLAIN {}\r\nA002 SELECT INBOX\r\nA003 LOGOUT\r\n",
                    payload
                )
                .as_bytes(),
            )
            .await
            .expect("write encrypted auth commands");
        reader.get_mut().flush().await.expect("flush");
        let auth_lines = read_until_contains(&mut reader, "A001 OK").await;
        assert!(
            auth_lines
                .iter()
                .any(|l| l.contains("AUTHENTICATE completed"))
        );
        let select_lines = read_until_contains(&mut reader, "A002 OK").await;
        assert!(select_lines.iter().any(|l| l.contains("SELECT completed")));
        let _logout = read_until_contains(&mut reader, "A003 OK").await;
        server_task.await.expect("join").expect("server");

        let (client, server) = duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                false,
            )
            .await
        });
        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader
            .read_line(&mut greeting)
            .await
            .expect("plain greeting");
        let mut capability = String::new();
        reader
            .read_line(&mut capability)
            .await
            .expect("plain capability");
        assert!(!capability.contains("AUTH=PLAIN"));
        reader
            .get_mut()
            .write_all(format!("A001 AUTHENTICATE PLAIN {}\r\nA002 LOGOUT\r\n", payload).as_bytes())
            .await
            .expect("write plain auth commands");
        reader.get_mut().flush().await.expect("flush");
        let auth_lines = read_until_contains(&mut reader, "A001 NO").await;
        assert!(auth_lines.iter().any(|l| l.contains("Encryption required")));
        let _logout = read_until_contains(&mut reader, "A002 OK").await;
        server_task.await.expect("join").expect("plain server");
    }

    #[tokio::test]
    async fn authenticate_login_sasl_is_tls_only_and_logs_in() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");

        let (client, server) = duplex(32 * 1024);
        let encrypted_mail_root = mail_root.clone();
        let encrypted_db_path = db_path.clone();
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                encrypted_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(encrypted_db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        assert!(capability.contains("AUTH=LOGIN"));
        reader
            .get_mut()
            .write_all(b"A000 AUTHENTICATE PLAIN\r\n")
            .await
            .expect("plain cancellation command");
        reader.get_mut().flush().await.expect("flush");
        let empty_challenge = read_until_contains(&mut reader, "+ ").await;
        assert!(empty_challenge.iter().any(|line| line == "+ \r\n"));
        reader.get_mut().write_all(b"*\r\n").await.expect("cancel");
        reader.get_mut().flush().await.expect("flush");
        let cancelled = read_until_contains(&mut reader, "A000 BAD").await.join("");
        assert!(cancelled.contains("AUTHENTICATE cancelled"));
        let forbidden_authzid =
            crate::BASE64_ENGINE.encode(b"admin@example.test\0user@example.test\0password");
        reader
            .get_mut()
            .write_all(format!("A000B AUTHENTICATE PLAIN {forbidden_authzid}\r\n").as_bytes())
            .await
            .expect("authzid");
        reader.get_mut().flush().await.expect("flush");
        let authzid = read_until_contains(&mut reader, "A000B NO").await.join("");
        assert!(authzid.contains("Authorization identity is not permitted"));
        reader
            .get_mut()
            .write_all(b"A001 AUTHENTICATE LOGIN\r\n")
            .await
            .expect("write auth command");
        reader.get_mut().flush().await.expect("flush");
        let username_challenge = read_until_contains(&mut reader, "+ VXNlcm5hbWU6").await;
        assert!(username_challenge.iter().any(|l| l.starts_with("+ ")));
        reader
            .get_mut()
            .write_all(
                format!("{}\r\n", crate::BASE64_ENGINE.encode(b"user@example.test")).as_bytes(),
            )
            .await
            .expect("write username");
        reader.get_mut().flush().await.expect("flush");
        let password_challenge = read_until_contains(&mut reader, "+ UGFzc3dvcmQ6").await;
        assert!(password_challenge.iter().any(|l| l.starts_with("+ ")));
        reader
            .get_mut()
            .write_all(
                format!(
                    "{}\r\nA002 SELECT INBOX\r\nA003 LOGOUT\r\n",
                    crate::BASE64_ENGINE.encode(b"password")
                )
                .as_bytes(),
            )
            .await
            .expect("write password and commands");
        reader.get_mut().flush().await.expect("flush");
        let auth_lines = read_until_contains(&mut reader, "A001 OK").await;
        assert!(
            auth_lines
                .iter()
                .any(|l| l.contains("AUTHENTICATE completed"))
        );
        let select_lines = read_until_contains(&mut reader, "A002 OK").await;
        assert!(select_lines.iter().any(|l| l.contains("SELECT completed")));
        let _logout = read_until_contains(&mut reader, "A003 OK").await;
        server_task.await.expect("join").expect("server");

        let (client, server) = duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                false,
            )
            .await
        });
        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader
            .read_line(&mut greeting)
            .await
            .expect("plain greeting");
        let mut capability = String::new();
        reader
            .read_line(&mut capability)
            .await
            .expect("plain capability");
        assert!(!capability.contains("AUTH=LOGIN"));
        reader
            .get_mut()
            .write_all(b"A001 AUTHENTICATE LOGIN\r\nA002 LOGOUT\r\n")
            .await
            .expect("write plain auth commands");
        reader.get_mut().flush().await.expect("flush");
        let auth_lines = read_until_contains(&mut reader, "A001 NO").await;
        assert!(auth_lines.iter().any(|l| l.contains("Encryption required")));
        let _logout = read_until_contains(&mut reader, "A002 OK").await;
        server_task.await.expect("join").expect("plain server");
    }

    fn scram_client_final(password: &str, client_first_bare: &str, server_first: &str) -> String {
        scram_client_final_with_binding(password, client_first_bare, server_first, b"n,,", &[])
    }

    fn scram_client_final_with_binding(
        password: &str,
        client_first_bare: &str,
        server_first: &str,
        gs2_header: &[u8],
        channel_binding_data: &[u8],
    ) -> String {
        use hmac::Mac;
        use hmac::digest::KeyInit;
        use pbkdf2::pbkdf2;
        use sha2::{Digest, Sha256};

        type HmacSha256 = hmac::Hmac<Sha256>;

        let salt_b64 = super::parse_scram_attr(server_first, "s=").expect("salt");
        let iterations = super::parse_scram_attr(server_first, "i=")
            .expect("iterations")
            .parse::<u32>()
            .expect("parse iterations");
        let nonce = super::parse_scram_attr(server_first, "r=").expect("nonce");
        let salt = crate::BASE64_ENGINE.decode(salt_b64).expect("decode salt");
        let channel_binding = [gs2_header, channel_binding_data].concat();
        let client_final_without_proof = format!(
            "c={},r={}",
            crate::BASE64_ENGINE.encode(channel_binding),
            nonce
        );
        let auth_message = format!(
            "{},{},{}",
            client_first_bare, server_first, client_final_without_proof
        );

        let mut salted_password = [0u8; 32];
        pbkdf2::<HmacSha256>(password.as_bytes(), &salt, iterations, &mut salted_password)
            .expect("derive salted password");
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&salted_password).unwrap();
        mac.update(b"Client Key");
        let client_key = mac.finalize().into_bytes();
        let stored_key = Sha256::digest(&client_key);
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&stored_key).unwrap();
        mac.update(auth_message.as_bytes());
        let client_signature = mac.finalize().into_bytes();
        let proof = client_key
            .iter()
            .zip(client_signature.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<_>>();
        format!(
            "{},p={}",
            client_final_without_proof,
            crate::BASE64_ENGINE.encode(proof)
        )
    }

    #[tokio::test]
    async fn authenticate_scram_sha256_logs_in_with_real_proof_without_tls() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        let scram = rmail_common::auth::create_scram_verifier("password", 4096)
            .expect("create scram verifier");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            Some(&scram),
        )
        .expect("add mailbox");

        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                false,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        assert!(capability.contains("AUTH=SCRAM-SHA-256"));

        let client_first_bare = "n=user@example.test,r=clientnonce";
        let client_first = format!("n,,{}", client_first_bare);
        let client_first_b64 = crate::BASE64_ENGINE.encode(client_first.as_bytes());
        reader
            .get_mut()
            .write_all(
                format!("A001 AUTHENTICATE SCRAM-SHA-256 {}\r\n", client_first_b64).as_bytes(),
            )
            .await
            .expect("write client first");
        reader.get_mut().flush().await.expect("flush");

        let server_first_lines = read_until_contains(&mut reader, "+ ").await;
        let server_first_line = server_first_lines
            .iter()
            .find(|line| line.starts_with("+ "))
            .expect("server first")
            .trim();
        let server_first_b64 = server_first_line.trim_start_matches("+ ").trim();
        let server_first = String::from_utf8(
            crate::BASE64_ENGINE
                .decode(server_first_b64)
                .expect("decode server first"),
        )
        .expect("server first utf8");
        let client_final = scram_client_final("password", client_first_bare, &server_first);
        reader
            .get_mut()
            .write_all(format!("{}\r\n", crate::BASE64_ENGINE.encode(client_final)).as_bytes())
            .await
            .expect("write client final");
        reader.get_mut().flush().await.expect("flush");

        let server_final_lines = read_until_contains(&mut reader, "+ ").await;
        assert!(
            server_final_lines
                .iter()
                .any(|line| line.starts_with("+ ") && line.contains('='))
        );
        reader
            .get_mut()
            .write_all(b"\r\nA002 SELECT INBOX\r\nA003 LOGOUT\r\n")
            .await
            .expect("finish scram and write commands");
        reader.get_mut().flush().await.expect("flush");

        let auth_lines = read_until_contains(&mut reader, "A001 OK").await;
        assert!(
            auth_lines
                .iter()
                .any(|line| line.contains("AUTHENTICATE completed"))
        );
        let select_lines = read_until_contains(&mut reader, "A002 OK").await;
        assert!(
            select_lines
                .iter()
                .any(|line| line.contains("SELECT completed"))
        );
        let _logout = read_until_contains(&mut reader, "A003 OK").await;

        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn authenticate_scram_sha256_plus_verifies_tls_server_endpoint_binding() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        let scram = rmail_common::auth::create_scram_verifier("password", 4096)
            .expect("create scram verifier");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            Some(&scram),
        )
        .expect("add mailbox");

        let server_end_point = vec![0x5a; 32];
        let server_config = tokio_rustls::rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(
                tokio_rustls::rustls::server::ResolvesServerCertUsingSni::new(),
            ));
        let tls_context = Arc::new(super::tls::TlsContext {
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(server_config)),
            server_end_point: server_end_point.clone(),
        });
        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                Some(tls_context),
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });
        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        assert!(capability.contains("AUTH=SCRAM-SHA-256-PLUS"));

        let client_first_bare = "n=user@example.test,r=plusnonce";
        let gs2_header = b"p=tls-server-end-point,,";
        let client_first = format!(
            "{}{}",
            std::str::from_utf8(gs2_header).unwrap(),
            client_first_bare
        );
        reader
            .get_mut()
            .write_all(
                format!(
                    "A001 AUTHENTICATE SCRAM-SHA-256-PLUS {}\r\n",
                    crate::BASE64_ENGINE.encode(client_first)
                )
                .as_bytes(),
            )
            .await
            .expect("client first");
        reader.get_mut().flush().await.expect("flush");
        let server_first_line = read_until_contains(&mut reader, "+ ")
            .await
            .into_iter()
            .find(|line| line.starts_with("+ "))
            .expect("server first");
        let server_first = String::from_utf8(
            crate::BASE64_ENGINE
                .decode(server_first_line.trim().trim_start_matches("+ "))
                .expect("decode server first"),
        )
        .expect("server first UTF-8");
        let client_final = scram_client_final_with_binding(
            "password",
            client_first_bare,
            &server_first,
            gs2_header,
            &server_end_point,
        );
        reader
            .get_mut()
            .write_all(format!("{}\r\n", crate::BASE64_ENGINE.encode(client_final)).as_bytes())
            .await
            .expect("client final");
        reader.get_mut().flush().await.expect("flush");
        let server_final = read_until_contains(&mut reader, "+ ").await;
        assert!(server_final.iter().any(|line| line.starts_with("+ ")));
        reader
            .get_mut()
            .write_all(b"\r\nA002 LOGOUT\r\n")
            .await
            .expect("finish");
        reader.get_mut().flush().await.expect("flush");
        let auth = read_until_contains(&mut reader, "A001 OK").await.join("");
        assert!(auth.contains("AUTHENTICATE completed"));
        let _logout = read_until_contains(&mut reader, "A002 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn select_accepts_quoted_inbox_name() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");

        let (client, server) = duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        assert!(greeting.starts_with("* OK"));
        let mut capability = String::new();
        reader
            .read_line(&mut capability)
            .await
            .expect("capability greeting");

        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT \"Inbox\"\r\nA003 LOGOUT\r\n",
            )
            .await
            .expect("write login/select");
        reader.get_mut().flush().await.expect("flush");

        let select_lines = read_until_contains(&mut reader, "A002 OK").await;
        assert!(select_lines.iter().any(|l| l.contains("SELECT completed")));

        let logout_lines = read_until_contains(&mut reader, "A003 OK").await;
        assert!(logout_lines.iter().any(|l| l.starts_with("* BYE")));

        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn uid_fetch_flags_does_not_send_full_message_literal() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Subject: one\r\n\r\nfirst\r\n",
        )
        .expect("deliver");

        let (client, server) = duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader
            .read_line(&mut capability)
            .await
            .expect("capability greeting");

        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID FETCH 1:* (FLAGS)\r\nA004 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _select_lines = read_until_contains(&mut reader, "A002 OK").await;
        let fetch_lines = read_until_contains(&mut reader, "A003 OK").await;
        assert!(fetch_lines.iter().any(|l| l.contains("FLAGS")));
        assert!(fetch_lines.iter().any(|l| l.contains("UID ")));
        assert!(!fetch_lines.iter().any(|l| l.contains("RFC822 {")));
        assert!(!fetch_lines.iter().any(|l| l.contains("BODY[] {")));

        let _logout_lines = read_until_contains(&mut reader, "A004 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn uid_fetch_header_fields_uses_matching_body_section_name() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"From: a@example.test\r\nTo: user@example.test\r\nSubject: one\r\n\r\nfirst\r\n",
        )
        .expect("deliver");

        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");

        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID FETCH 1:* (UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT)])\r\nA004 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _select_lines = read_until_contains(&mut reader, "A002 OK").await;
        let fetch_lines = read_until_contains(&mut reader, "A003 OK").await;
        assert!(
            fetch_lines
                .iter()
                .any(|l| l.contains("BODY[HEADER.FIELDS (FROM TO SUBJECT)] {"))
        );
        let joined = fetch_lines.join("");
        assert!(joined.contains("From: a@example.test"));
        assert!(joined.contains("To: user@example.test"));
        assert!(joined.contains("Subject: one"));
        assert!(!joined.contains("Date:"));
        assert!(!joined.contains("\r\n\r\nfirst"));

        let _logout_lines = read_until_contains(&mut reader, "A004 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[test]
    fn normalize_fetch_items_keeps_nested_header_fields_together() {
        let items = super::normalize_fetch_items(
            "(UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (From To Cc Bcc Subject Date Message-ID Priority X-Priority References Newsgroups In-Reply-To Content-Type Reply-To Received)])",
        );

        assert_eq!(
            items,
            vec![
                "BODY.PEEK[HEADER.FIELDS (FROM TO CC BCC SUBJECT DATE MESSAGE-ID PRIORITY X-PRIORITY REFERENCES NEWSGROUPS IN-REPLY-TO CONTENT-TYPE REPLY-TO RECEIVED)]",
                "FLAGS",
                "RFC822.SIZE",
                "UID",
            ]
        );
    }

    #[tokio::test]
    async fn uid_fetch_header_fields_not_excludes_requested_headers() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"From: a@example.test\r\nTo: user@example.test\r\nSubject: one\r\nX-Spam: no\r\n\r\nfirst\r\n",
        )
        .expect("deliver");

        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");

        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID FETCH 1:* (UID BODY.PEEK[HEADER.FIELDS.NOT (SUBJECT)])\r\nA004 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _select_lines = read_until_contains(&mut reader, "A002 OK").await;
        let fetch_lines = read_until_contains(&mut reader, "A003 OK").await;
        let joined = fetch_lines.join("");
        assert!(joined.contains("BODY[HEADER.FIELDS.NOT (SUBJECT)] {"));
        assert!(joined.contains("From: a@example.test"));
        assert!(joined.contains("X-Spam: no"));
        assert!(!joined.contains("Subject: one"));

        let _logout_lines = read_until_contains(&mut reader, "A004 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn uid_fetch_supports_body_text_and_partial_literals() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"From: a@example.test\r\nSubject: body ranges\r\n\r\n0123456789abcdef\r\n",
        )
        .expect("deliver");

        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");

        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID FETCH 1:* (UID BODY[TEXT]<2.5>)\r\nA004 UID FETCH 1:* (UID BODY.PEEK[HEADER] BODY.PEEK[]<0.12>)\r\nA005 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _select_lines = read_until_contains(&mut reader, "A002 OK").await;
        let text_lines = read_until_contains(&mut reader, "A003 OK").await;
        let joined_text = text_lines.join("");
        assert!(joined_text.contains("BODY[TEXT]<2> {5}"));
        assert!(joined_text.contains("23456"));
        assert!(!joined_text.contains("Subject: body ranges"));

        let partial_lines = read_until_contains(&mut reader, "A004 OK").await;
        let joined_partial = partial_lines.join("");
        assert!(joined_partial.contains("BODY[HEADER] {"));
        assert!(joined_partial.contains("Subject: body ranges"));
        assert!(joined_partial.contains("BODY[]<0> {12}"));
        assert!(joined_partial.contains("From: a@exam"));
        assert!(!joined_partial.contains("0123456789abcdef"));

        let _logout_lines = read_until_contains(&mut reader, "A005 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn fetch_body_seen_side_effect_respects_peek_headers_and_examine() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        for subject in ["peek", "body", "examine"] {
            rmail_common::maildir::deliver(
                &mail_root,
                "example.test",
                "user",
                format!("Subject: {subject}\r\n\r\ncontents\r\n").as_bytes(),
            )
            .expect("deliver");
        }

        let server_mail_root = mail_root.clone();
        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                server_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });
        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 FETCH 1 (FLAGS MODSEQ BODY.PEEK[])\r\nA004 FETCH 1 (FLAGS MODSEQ RFC822.HEADER)\r\nA005 FETCH 2 (FLAGS MODSEQ BODY[TEXT])\r\nA006 FETCH 2 (FLAGS MODSEQ BODY[TEXT])\r\nA007 EXAMINE INBOX\r\nA008 FETCH 3 (FLAGS MODSEQ RFC822.TEXT)\r\nA009 LOGOUT\r\n",
            )
            .await
            .expect("commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let _select = read_until_contains(&mut reader, "A002 OK").await;
        let peek = read_until_contains(&mut reader, "A003 OK").await.join("");
        assert!(!peek.contains("\\Seen"));
        let header = read_until_contains(&mut reader, "A004 OK").await.join("");
        assert!(!header.contains("\\Seen"));
        let body = read_until_contains(&mut reader, "A005 OK").await.join("");
        assert!(body.contains("FLAGS (\\Seen)"));
        let body_modseq = body
            .split("MODSEQ (")
            .nth(1)
            .and_then(|value| value.split(')').next())
            .expect("body modseq")
            .to_string();
        let repeated = read_until_contains(&mut reader, "A006 OK").await.join("");
        assert!(repeated.contains(&format!("MODSEQ ({body_modseq})")));
        let _examine = read_until_contains(&mut reader, "A007 OK").await;
        let examined = read_until_contains(&mut reader, "A008 OK").await.join("");
        assert!(!examined.contains("\\Seen"));

        let _logout = read_until_contains(&mut reader, "A009 OK").await;
        server_task.await.expect("join").expect("server");
        let (_, messages) =
            rmail_common::imap_state::load_folder(&mail_root, "example.test", "user", "INBOX")
                .expect("folder");
        assert!(!messages[0].flags.iter().any(|flag| flag == "\\Seen"));
        assert!(messages[1].flags.iter().any(|flag| flag == "\\Seen"));
        assert!(!messages[2].flags.iter().any(|flag| flag == "\\Seen"));
    }

    #[tokio::test]
    async fn binary_fetch_decodes_sizes_partials_failures_and_seen_semantics() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8Ad29ybGQ=\r\n--x\r\nContent-Transfer-Encoding: base64\r\n\r\n%%%\r\n--x--\r\n",
        )
        .expect("deliver");

        let server_mail_root = mail_root.clone();
        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                server_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });
        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CAPABILITY\r\nA003 SELECT INBOX\r\nA004 UID FETCH 1 (FLAGS BODY[0])\r\nA005 UID FETCH 1 (FLAGS BINARY.SIZE[1] BINARY.PEEK[1]<6.5> BINARY.PEEK[2])\r\nA006 UID FETCH 1 (FLAGS MODSEQ BINARY[1]<0.5>)\r\nA007 LOGOUT\r\n",
            )
            .await
            .expect("commands");
        reader.get_mut().flush().await.expect("flush");
        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let caps = read_until_contains(&mut reader, "A002 OK").await.join("");
        assert!(caps.contains(" BINARY"));
        let _select = read_until_contains(&mut reader, "A003 OK").await;
        let invalid = read_until_contains(&mut reader, "A004 BAD").await.join("");
        assert!(invalid.contains("Invalid UID FETCH arguments"));
        let peek = read_until_contains(&mut reader, "A005 OK").await.join("");
        assert!(peek.contains("BINARY.SIZE[1] 11"));
        assert!(peek.contains("BINARY[1]<6> ~{5}\r\nworld"));
        assert!(peek.contains("BINARY[2] NIL"));
        assert!(!peek.contains("\\Seen"));
        let body = read_until_contains(&mut reader, "A006 OK").await.join("");
        assert!(body.contains("FLAGS (\\Seen)"));
        assert!(body.contains("BINARY[1]<0> ~{5}\r\nhello"));
        let _logout = read_until_contains(&mut reader, "A007 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn idle_completes_after_done() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");

        let (client, server) = duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        assert!(capability.contains("IDLE"));

        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 IDLE\r\nDONE\r\nA004 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _login_lines = read_until_contains(&mut reader, "A001 OK").await;
        let _select_lines = read_until_contains(&mut reader, "A002 OK").await;
        let idle_start = read_until_contains(&mut reader, "+ idling").await;
        assert!(idle_start.iter().any(|line| line.contains("+ idling")));
        let idle_done = read_until_contains(&mut reader, "A003 OK").await;
        assert!(idle_done.iter().any(|line| line.contains("IDLE completed")));
        let _logout_lines = read_until_contains(&mut reader, "A004 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn noop_and_idle_send_unsolicited_exists_for_new_delivery() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");

        let server_mail_root = mail_root.clone();
        let server_db_path = db_path.clone();
        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                server_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(server_db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");

        reader
            .get_mut()
            .write_all(b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\n")
            .await
            .expect("write login select");
        reader.get_mut().flush().await.expect("flush");
        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let select = read_until_contains(&mut reader, "A002 OK").await;
        assert!(select.iter().any(|line| line.contains("* 0 EXISTS")));

        rmail_common::imap_state::append_message(
            mail_root.as_path(),
            "example.test",
            "user",
            "INBOX",
            b"From: a@example.test\r\nSubject: noop sync\r\n\r\nhello",
            vec![],
        )
        .expect("append first message");
        reader
            .get_mut()
            .write_all(b"A003 NOOP\r\n")
            .await
            .expect("write noop");
        reader.get_mut().flush().await.expect("flush");
        let noop = read_until_contains(&mut reader, "A003 OK").await;
        assert!(noop.iter().any(|line| line.trim_end() == "* 1 EXISTS"));

        reader
            .get_mut()
            .write_all(b"A004 IDLE\r\n")
            .await
            .expect("write idle");
        reader.get_mut().flush().await.expect("flush");
        let idle_start = read_until_contains(&mut reader, "+ idling").await;
        assert!(idle_start.iter().any(|line| line.contains("+ idling")));
        rmail_common::imap_state::append_message(
            mail_root.as_path(),
            "example.test",
            "user",
            "INBOX",
            b"From: b@example.test\r\nSubject: idle sync\r\n\r\nhello",
            vec![],
        )
        .expect("append second message");
        let exists = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            read_until_contains(&mut reader, "* 2 EXISTS"),
        )
        .await
        .expect("idle exists timeout");
        assert!(exists.iter().any(|line| line.trim_end() == "* 2 EXISTS"));
        reader
            .get_mut()
            .write_all(b"DONE\r\nA005 LOGOUT\r\n")
            .await
            .expect("done logout");
        reader.get_mut().flush().await.expect("flush");
        let idle_done = read_until_contains(&mut reader, "A004 OK").await;
        assert!(idle_done.iter().any(|line| line.contains("IDLE completed")));
        let _logout = read_until_contains(&mut reader, "A005 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn noop_sync_reports_external_expunge_before_flag_changes() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        let (_uidvalidity, uid1) = rmail_common::imap_state::append_message(
            mail_root.as_path(),
            "example.test",
            "user",
            "INBOX",
            b"From: a@example.test\r\nSubject: first\r\n\r\nhello",
            vec![],
        )
        .expect("append first");
        let (_uidvalidity, uid2) = rmail_common::imap_state::append_message(
            mail_root.as_path(),
            "example.test",
            "user",
            "INBOX",
            b"From: b@example.test\r\nSubject: second\r\n\r\nhello",
            vec![],
        )
        .expect("append second");

        let server_mail_root = mail_root.clone();
        let server_db_path = db_path.clone();
        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                server_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(server_db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        reader
            .get_mut()
            .write_all(b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\n")
            .await
            .expect("write login select");
        reader.get_mut().flush().await.expect("flush");
        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let select = read_until_contains(&mut reader, "A002 OK").await;
        assert!(select.iter().any(|line| line.contains("* 2 EXISTS")));

        rmail_common::imap_state::set_uid_flags(
            mail_root.as_path(),
            "example.test",
            "user",
            "INBOX",
            uid1,
            vec!["\\Seen".to_string()],
        )
        .expect("set flags");
        rmail_common::imap_state::delete_message_by_uid(
            mail_root.as_path(),
            "example.test",
            "user",
            "INBOX",
            uid2,
        )
        .expect("delete uid2");

        reader
            .get_mut()
            .write_all(b"A003 NOOP\r\nA004 LOGOUT\r\n")
            .await
            .expect("write noop logout");
        reader.get_mut().flush().await.expect("flush");
        let noop = read_until_contains(&mut reader, "A003 OK").await;
        let expunge_pos = noop
            .iter()
            .position(|line| line.trim_end() == "* 2 EXPUNGE")
            .expect("expunge response");
        let fetch_pos = noop
            .iter()
            .position(|line| {
                line.contains("* 1 FETCH")
                    && line.contains("FLAGS (\\Seen)")
                    && line.contains(&format!("UID {}", uid1))
            })
            .expect("flag fetch response");
        assert!(expunge_pos < fetch_pos);
        assert!(noop.iter().any(|line| line.trim_end() == "* 1 EXISTS"));
        let _logout = read_until_contains(&mut reader, "A004 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn store_deleted_and_expunge_removes_message() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Subject: one\r\n\r\nfirst\r\n",
        )
        .expect("deliver one");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Subject: two\r\n\r\nsecond\r\n",
        )
        .expect("deliver two");

        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");

        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID STORE 1 +FLAGS (\\Deleted)\r\nA004 EXPUNGE\r\nA005 SELECT INBOX\r\nA006 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _select1 = read_until_contains(&mut reader, "A002 OK").await;
        let store_lines = read_until_contains(&mut reader, "A003 OK").await;
        assert!(
            store_lines
                .iter()
                .any(|l| l.contains("\\Deleted") || l.contains("\\DELETED"))
        );

        let expunge_lines = read_until_contains(&mut reader, "A004 OK").await;
        assert!(expunge_lines.iter().any(|l| l.contains("EXPUNGE")));

        let select2 = read_until_contains(&mut reader, "A005 OK").await;
        assert!(select2.iter().any(|l| l.contains("* 1 EXISTS")));

        let _logout = read_until_contains(&mut reader, "A006 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn search_supports_headers_text_dates_ranges_or_and_not() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Date: Sun, 14 Jun 2026 12:00:00 +0000\r\nFrom: alice@example.test\r\nTo: user@example.test\r\nCc: team@example.test\r\nSubject: Alpha Project\r\n\r\nbody has rocket text\r\n",
        )
        .expect("deliver one");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Date: Mon, 15 Jun 2026 12:00:00 +0000\r\nFrom: bob@example.test\r\nTo: user@example.test\r\nSubject: Beta Report\r\n\r\nbody has invoice text\r\n",
        )
        .expect("deliver two");

        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");

        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID STORE 1 +FLAGS (\\Seen)\r\nA004 SEARCH UNSEEN\r\nA005 SEARCH FROM alice\r\nA006 SEARCH BODY invoice\r\nA007 SEARCH TEXT rocket\r\nA008 UID SEARCH UID 2:*\r\nA009 SEARCH OR SUBJECT Alpha SUBJECT Beta\r\nA010 SEARCH NOT FROM alice\r\nA011 SEARCH 2\r\nA012 UID SEARCH SENTSINCE 15-Jun-2026 SENTBEFORE 16-Jun-2026\r\nA013 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _select = read_until_contains(&mut reader, "A002 OK").await;
        let _store = read_until_contains(&mut reader, "A003 OK").await;

        let unseen = read_until_contains(&mut reader, "A004 OK").await;
        assert!(unseen.iter().any(|l| l.trim_end() == "* SEARCH 2"));

        let from = read_until_contains(&mut reader, "A005 OK").await;
        assert!(from.iter().any(|l| l.trim_end() == "* SEARCH 1"));

        let body = read_until_contains(&mut reader, "A006 OK").await;
        assert!(body.iter().any(|l| l.trim_end() == "* SEARCH 2"));

        let text = read_until_contains(&mut reader, "A007 OK").await;
        assert!(text.iter().any(|l| l.trim_end() == "* SEARCH 1"));

        let uid_range = read_until_contains(&mut reader, "A008 OK").await;
        assert!(uid_range.iter().any(|l| l.trim_end() == "* SEARCH 2"));

        let or_lines = read_until_contains(&mut reader, "A009 OK").await;
        assert!(or_lines.iter().any(|l| l.trim_end() == "* SEARCH 1 2"));

        let not_lines = read_until_contains(&mut reader, "A010 OK").await;
        assert!(not_lines.iter().any(|l| l.trim_end() == "* SEARCH 2"));

        let seq_range = read_until_contains(&mut reader, "A011 OK").await;
        assert!(seq_range.iter().any(|l| l.trim_end() == "* SEARCH 2"));

        let sent_date = read_until_contains(&mut reader, "A012 OK").await;
        assert!(sent_date.iter().any(|l| l.trim_end() == "* SEARCH 2"));

        let _logout = read_until_contains(&mut reader, "A013 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn textual_command_literals_resume_search_list_and_nested_arguments() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("mailbox");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Subject: needle\r\n\r\nbody\r\n",
        )
        .expect("delivery");
        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(process_stream(
            Box::new(server),
            mail_root.to_string_lossy().to_string(),
            None,
            Some(db_path.to_string_lossy().to_string()),
            None,
            true,
        ));
        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("greeting");
        line.clear();
        reader.read_line(&mut line).await.expect("capability");
        reader
            .get_mut()
            .write_all(b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\n")
            .await
            .expect("setup");
        reader.get_mut().flush().await.expect("flush");
        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let _select = read_until_contains(&mut reader, "A002 OK").await;

        reader
            .get_mut()
            .write_all(b"A003 SEARCH SUBJECT {6}\r\n")
            .await
            .expect("search marker");
        reader.get_mut().flush().await.expect("flush");
        let continuation = read_until_contains(&mut reader, "+ Ready").await.join("");
        assert!(continuation.contains("+ Ready for literal data"));
        reader
            .get_mut()
            .write_all(b"needle\r\n")
            .await
            .expect("search literal");
        reader.get_mut().flush().await.expect("flush");
        let search = read_until_contains(&mut reader, "A003 OK").await.join("");
        assert!(search.contains("* SEARCH 1"));

        reader
            .get_mut()
            .write_all(
                b"A004 SEARCH OR SUBJECT {6}\r\nneedle SUBJECT {7+}\r\nmissing\r\nA005 LIST \"\" {5+}\r\nINBOX\r\nA006 ID (\"name\" {6+}\r\nGearyX)\r\nA007 LOGOUT\r\n",
            )
            .await
            .expect("multi literal pipeline");
        reader.get_mut().flush().await.expect("flush");
        let second_continuation = read_until_contains(&mut reader, "+ Ready").await.join("");
        assert!(second_continuation.contains("+ Ready for literal data"));
        let multi = read_until_contains(&mut reader, "A004 OK").await.join("");
        assert!(multi.contains("* SEARCH 1"));
        let list = read_until_contains(&mut reader, "A005 OK").await.join("");
        assert!(list.contains("* LIST") && list.contains("\"INBOX\""));
        let id = read_until_contains(&mut reader, "A006 OK").await.join("");
        assert!(id.contains("* ID (\"name\" \"rMail\""));
        let _logout = read_until_contains(&mut reader, "A007 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn search_supports_base_flags_keywords_sizes_headers_and_charset() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        let large_body = "x".repeat(1500);
        rmail_common::imap_state::append_message(
            &mail_root,
            "example.test",
            "user",
            "INBOX",
            format!(
                "Date: Wed, 10 Jun 2026 12:00:00 +0000\r\nFrom: one@example.test\r\nSubject: First\r\nMessage-ID: <one@example.test>\r\n\r\n{}\r\n",
                large_body
            )
            .as_bytes(),
            vec!["\\Answered".to_string(), "$Work".to_string()],
        )
        .expect("append one");
        rmail_common::imap_state::append_message(
            &mail_root,
            "example.test",
            "user",
            "INBOX",
            b"Date: Thu, 11 Jun 2026 12:00:00 +0000\r\nFrom: two@example.test\r\nSubject: Second\r\nMessage-ID: <two@example.test>\r\n\r\nshort\r\n",
            vec!["\\Flagged".to_string(), "\\Draft".to_string()],
        )
        .expect("append two");
        rmail_common::imap_state::append_message(
            &mail_root,
            "example.test",
            "user",
            "INBOX",
            b"Date: Fri, 12 Jun 2026 12:00:00 +0000\r\nFrom: three@example.test\r\nSubject: Third\r\nMessage-ID: <three@example.test>\r\n\r\nshort\r\n",
            vec!["\\Recent".to_string()],
        )
        .expect("append three");

        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 SEARCH ANSWERED\r\nA004 SEARCH UNANSWERED\r\nA005 SEARCH FLAGGED DRAFT\r\nA006 SEARCH KEYWORD $Work\r\nA007 SEARCH UNKEYWORD $Work\r\nA008 SEARCH NEW\r\nA009 SEARCH OLD\r\nA010 SEARCH SENTON 11-Jun-2026\r\nA011 SEARCH HEADER Message-ID two\r\nA012 SEARCH LARGER 1000\r\nA013 SEARCH SMALLER 1000\r\nA014 SEARCH CHARSET US-ASCII SUBJECT First\r\nA015 SEARCH CHARSET KOI8-R SUBJECT First\r\nA016 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let _select = read_until_contains(&mut reader, "A002 OK").await;
        let answered = read_until_contains(&mut reader, "A003 OK").await;
        assert!(answered.iter().any(|l| l.trim_end() == "* SEARCH 1"));
        let unanswered = read_until_contains(&mut reader, "A004 OK").await;
        assert!(unanswered.iter().any(|l| l.trim_end() == "* SEARCH 2 3"));
        let flagged_draft = read_until_contains(&mut reader, "A005 OK").await;
        assert!(flagged_draft.iter().any(|l| l.trim_end() == "* SEARCH 2"));
        let keyword = read_until_contains(&mut reader, "A006 OK").await;
        assert!(keyword.iter().any(|l| l.trim_end() == "* SEARCH 1"));
        let unkeyword = read_until_contains(&mut reader, "A007 OK").await;
        assert!(unkeyword.iter().any(|l| l.trim_end() == "* SEARCH 2 3"));
        let new = read_until_contains(&mut reader, "A008 OK").await;
        assert!(new.iter().any(|l| l.trim_end() == "* SEARCH 3"));
        let old = read_until_contains(&mut reader, "A009 OK").await;
        assert!(old.iter().any(|l| l.trim_end() == "* SEARCH 1 2"));
        let sent_on = read_until_contains(&mut reader, "A010 OK").await;
        assert!(sent_on.iter().any(|l| l.trim_end() == "* SEARCH 2"));
        let header = read_until_contains(&mut reader, "A011 OK").await;
        assert!(header.iter().any(|l| l.trim_end() == "* SEARCH 2"));
        let larger = read_until_contains(&mut reader, "A012 OK").await;
        assert!(larger.iter().any(|l| l.trim_end() == "* SEARCH 1"));
        let smaller = read_until_contains(&mut reader, "A013 OK").await;
        assert!(smaller.iter().any(|l| l.trim_end() == "* SEARCH 2 3"));
        let charset_supported = read_until_contains(&mut reader, "A014 OK").await;
        assert!(
            charset_supported
                .iter()
                .any(|l| l.trim_end() == "* SEARCH 1")
        );
        let charset_unsupported = read_until_contains(&mut reader, "A015 NO").await;
        assert!(
            charset_unsupported
                .iter()
                .any(|line| line.contains("[BADCHARSET (US-ASCII UTF-8)]"))
        );
        let _logout = read_until_contains(&mut reader, "A016 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn esearch_returns_requested_aggregates_ranges_uid_marker_and_empty_counts() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        for index in 1..=5 {
            rmail_common::imap_state::append_message(
                &mail_root,
                "example.test",
                "user",
                "INBOX",
                format!("Subject: message {}\r\n\r\nbody\r\n", index).as_bytes(),
                if index == 2 {
                    vec!["\\Seen".to_string()]
                } else {
                    Vec::new()
                },
            )
            .expect("append");
        }

        let server_mail_root = mail_root.clone();
        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                server_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });
        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        assert!(!capability.contains("ESEARCH"));
        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CAPABILITY\r\nA003 SELECT INBOX\r\nA004 SEARCH RETURN (MIN MAX ALL COUNT) UNSEEN\r\nA005 UID SEARCH RETURN (MIN MAX COUNT) SEEN\r\nA006 SEARCH RETURN (ALL COUNT) SUBJECT \"missing\"\r\nA007 SEARCH RETURN (PARTIAL) ALL\r\nA008 LOGOUT\r\n",
            )
            .await
            .expect("commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let post_auth_capability = read_until_contains(&mut reader, "A002 OK").await.join("");
        assert!(post_auth_capability.contains("ESEARCH"));
        let _select = read_until_contains(&mut reader, "A003 OK").await;
        let unseen = read_until_contains(&mut reader, "A004 OK").await.join("");
        assert!(unseen.contains("* ESEARCH (TAG \"A004\") MIN 1 MAX 5 ALL 1,3:5 COUNT 4"));
        let seen = read_until_contains(&mut reader, "A005 OK").await.join("");
        assert!(seen.contains("* ESEARCH (TAG \"A005\") UID MIN 2 MAX 2 COUNT 1"));
        let empty = read_until_contains(&mut reader, "A006 OK").await.join("");
        assert!(empty.contains("* ESEARCH (TAG \"A006\") COUNT 0"));
        assert!(!empty.contains(" ALL "));
        let unsupported = read_until_contains(&mut reader, "A007 BAD").await.join("");
        assert!(unsupported.contains("Invalid SEARCH arguments"));
        let _logout = read_until_contains(&mut reader, "A008 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn searchres_save_tracks_uids_across_expunge_and_resolves_dollar_everywhere() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        for index in 1..=3 {
            rmail_common::imap_state::append_message(
                &mail_root,
                "example.test",
                "user",
                "INBOX",
                format!("Subject: message {}\r\n\r\nbody\r\n", index).as_bytes(),
                if index == 2 {
                    vec!["\\Seen".to_string()]
                } else {
                    Vec::new()
                },
            )
            .expect("append");
        }

        let server_mail_root = mail_root.clone();
        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                server_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });
        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CAPABILITY\r\nA003 SELECT INBOX\r\nA004 UID SEARCH RETURN (SAVE) SEEN\r\nA005 STORE 1 +FLAGS (\\Deleted)\r\nA006 EXPUNGE\r\nA007 FETCH $ (UID FLAGS)\r\nA008 UID STORE $ +FLAGS (\\Flagged)\r\nA009 UID SEARCH RETURN (SAVE ALL COUNT) $\r\nA010 UID SEARCH RETURN (SAVE) SUBJECT \"missing\"\r\nA011 UID FETCH $ (UID FLAGS)\r\nA012 LOGOUT\r\n",
            )
            .await
            .expect("commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let caps = read_until_contains(&mut reader, "A002 OK").await.join("");
        assert!(caps.contains("SEARCHRES"));
        let _select = read_until_contains(&mut reader, "A003 OK").await;
        let save_only = read_until_contains(&mut reader, "A004 OK").await.join("");
        assert!(!save_only.contains("* ESEARCH"));
        let _store = read_until_contains(&mut reader, "A005 OK").await;
        let expunge = read_until_contains(&mut reader, "A006 OK").await.join("");
        assert!(expunge.contains("* 1 EXPUNGE"));
        let fetch = read_until_contains(&mut reader, "A007 OK").await.join("");
        assert!(fetch.contains("* 1 FETCH"));
        assert!(fetch.contains("UID 2"));
        let uid_store = read_until_contains(&mut reader, "A008 OK").await.join("");
        assert!(uid_store.contains("UID 2"));
        assert!(uid_store.contains("\\FLAGGED"));
        let resave = read_until_contains(&mut reader, "A009 OK").await.join("");
        assert!(resave.contains("* ESEARCH (TAG \"A009\") UID ALL 2 COUNT 1"));
        let clear = read_until_contains(&mut reader, "A010 OK").await.join("");
        assert!(!clear.contains("* ESEARCH"));
        let empty_fetch = read_until_contains(&mut reader, "A011 OK").await;
        assert!(
            !empty_fetch
                .iter()
                .any(|line| line.starts_with("* ") && line.contains(" FETCH "))
        );
        let _logout = read_until_contains(&mut reader, "A012 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn sort_and_uid_sort_apply_rfc5256_keys_reverse_and_search_filtering() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        let messages: [(&[u8], Vec<String>, i64); 3] = [
            (
                b"Date: Tue, 2 Jan 2024 00:00:00 +0000\r\nFrom: Zed <zed@example.test>\r\nTo: beta@example.test\r\nCc: charlie@example.test\r\nSubject: Re: Zebra\r\n\r\nlarge body one\r\n",
                Vec::new(),
                1_704_153_600,
            ),
            (
                b"Date: Mon, 1 Jan 2024 00:00:00 +0000\r\nFrom: Alice <alice@example.test>\r\nTo: alpha@example.test\r\nCc: delta@example.test\r\nSubject: =?UTF-8?Q?Apple?=\r\n\r\nx\r\n",
                vec!["\\Seen".to_string()],
                1_704_067_200,
            ),
            (
                b"From: Bob <bob@example.test>\r\nTo: gamma@example.test\r\nCc: able@example.test\r\nSubject: Fwd: Zebra (fwd)\r\n\r\nmedium\r\n",
                Vec::new(),
                1_704_240_000,
            ),
        ];
        for (data, flags, internal_date) in messages {
            rmail_common::imap_state::append_message_with_internal_date(
                &mail_root,
                "example.test",
                "user",
                "INBOX",
                data,
                flags,
                Some((internal_date, 0)),
            )
            .expect("append");
        }

        let server_mail_root = mail_root.clone();
        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                server_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });
        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        assert!(!capability.contains(" SORT"));
        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CAPABILITY\r\nA003 SELECT INBOX\r\nA004 SORT (DATE) UTF-8 ALL\r\nA005 UID SORT (SUBJECT DATE) UTF-8 ALL\r\nA006 SORT (REVERSE FROM) US-ASCII ALL\r\nA007 SORT (CC) UTF-8 ALL\r\nA008 SORT (TO) UTF-8 ALL\r\nA009 SORT (ARRIVAL) UTF-8 SEEN\r\nA010 SORT (DATE REVERSE) UTF-8 ALL\r\nA011 SORT (DATE) ISO-8859-1 ALL\r\nA012 LOGOUT\r\n",
            )
            .await
            .expect("commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let caps = read_until_contains(&mut reader, "A002 OK").await.join("");
        assert!(caps.contains(" SORT"));
        let _select = read_until_contains(&mut reader, "A003 OK").await;
        assert!(
            read_until_contains(&mut reader, "A004 OK")
                .await
                .join("")
                .contains("* SORT 2 1 3")
        );
        assert!(
            read_until_contains(&mut reader, "A005 OK")
                .await
                .join("")
                .contains("* SORT 2 1 3")
        );
        assert!(
            read_until_contains(&mut reader, "A006 OK")
                .await
                .join("")
                .contains("* SORT 1 3 2")
        );
        assert!(
            read_until_contains(&mut reader, "A007 OK")
                .await
                .join("")
                .contains("* SORT 3 1 2")
        );
        assert!(
            read_until_contains(&mut reader, "A008 OK")
                .await
                .join("")
                .contains("* SORT 2 1 3")
        );
        assert!(
            read_until_contains(&mut reader, "A009 OK")
                .await
                .join("")
                .contains("* SORT 2")
        );
        let malformed = read_until_contains(&mut reader, "A010 BAD").await.join("");
        assert!(malformed.contains("Invalid SORT arguments"));
        let charset = read_until_contains(&mut reader, "A011 NO").await.join("");
        assert!(charset.contains("[BADCHARSET (US-ASCII UTF-8)]"));
        let _logout = read_until_contains(&mut reader, "A012 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn thread_and_uid_thread_build_references_and_orderedsubject_trees() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        let (_, discarded_uid) = rmail_common::imap_state::append_message(
            &mail_root,
            "example.test",
            "user",
            "INBOX",
            b"Subject: discarded\r\n\r\n",
            Vec::new(),
        )
        .expect("append discarded");
        rmail_common::maildir::delete_message_by_uid_for_mailbox(
            &mail_root,
            "example.test",
            "user",
            "INBOX",
            discarded_uid,
        )
        .expect("expunge discarded");
        let messages: [(&[u8], Vec<String>); 4] = [
            (
                b"Date: Mon, 1 Jan 2024 00:00:00 +0000\r\nMessage-ID: <root@x>\r\nSubject: Topic\r\n\r\n",
                Vec::new(),
            ),
            (
                b"Date: Tue, 2 Jan 2024 00:00:00 +0000\r\nMessage-ID: <child@x>\r\nReferences: <root@x>\r\nSubject: Re: Topic\r\n\r\n",
                vec!["\\Seen".to_string()],
            ),
            (
                b"Date: Wed, 3 Jan 2024 00:00:00 +0000\r\nMessage-ID: <leaf@x>\r\nReferences: <root@x> <child@x>\r\nSubject: Re: Topic\r\n\r\n",
                Vec::new(),
            ),
            (
                b"Date: Thu, 4 Jan 2024 00:00:00 +0000\r\nMessage-ID: <orphan@x>\r\nReferences: <missing@x>\r\nSubject: Other\r\n\r\n",
                Vec::new(),
            ),
        ];
        for (data, flags) in messages {
            rmail_common::imap_state::append_message(
                &mail_root,
                "example.test",
                "user",
                "INBOX",
                data,
                flags,
            )
            .expect("append threaded message");
        }

        let server_mail_root = mail_root.clone();
        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                server_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });
        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        assert!(!capability.contains("THREAD="));
        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CAPABILITY\r\nA003 SELECT INBOX\r\nA004 THREAD REFERENCES UTF-8 ALL\r\nA005 UID THREAD REFERENCES UTF-8 ALL\r\nA006 THREAD ORDEREDSUBJECT UTF-8 ALL\r\nA007 THREAD REFERENCES UTF-8 SEEN\r\nA008 THREAD REFS UTF-8 ALL\r\nA009 THREAD UNKNOWN UTF-8 ALL\r\nA010 THREAD REFERENCES ISO-8859-1 ALL\r\nA011 LOGOUT\r\n",
            )
            .await
            .expect("commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let caps = read_until_contains(&mut reader, "A002 OK").await.join("");
        assert!(caps.contains("THREAD=REFERENCES"));
        assert!(caps.contains("THREAD=REFS"));
        assert!(caps.contains("THREAD=ORDEREDSUBJECT"));
        let _select = read_until_contains(&mut reader, "A003 OK").await;
        let refs = read_until_contains(&mut reader, "A004 OK").await.join("");
        assert!(refs.contains("* THREAD (1 2 3)(4)"));
        let uid_refs = read_until_contains(&mut reader, "A005 OK").await.join("");
        assert!(uid_refs.contains("* THREAD (2 3 4)(5)"));
        let ordered = read_until_contains(&mut reader, "A006 OK").await.join("");
        assert!(ordered.contains("* THREAD (1 (2)(3))(4)"));
        let filtered = read_until_contains(&mut reader, "A007 OK").await.join("");
        assert!(filtered.contains("* THREAD (2)"));
        let refs2 = read_until_contains(&mut reader, "A008 OK").await.join("");
        assert!(refs2.contains("* THREAD (1 2 3)(4)"));
        let unknown = read_until_contains(&mut reader, "A009 BAD").await.join("");
        assert!(unknown.contains("Invalid THREAD arguments"));
        let charset = read_until_contains(&mut reader, "A010 NO").await.join("");
        assert!(charset.contains("[BADCHARSET (US-ASCII UTF-8)]"));
        let _logout = read_until_contains(&mut reader, "A011 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn within_younger_and_older_use_persisted_internal_dates() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        let now = chrono::Utc::now().timestamp();
        for (index, age) in [60_i64, 3_600, 86_400].into_iter().enumerate() {
            rmail_common::imap_state::append_message_with_internal_date(
                &mail_root,
                "example.test",
                "user",
                "INBOX",
                format!("Subject: age {}\r\n\r\n", age).as_bytes(),
                Vec::new(),
                Some((now - age, 0)),
            )
            .unwrap_or_else(|error| panic!("append message {}: {}", index, error));
        }
        let server_mail_root = mail_root.clone();
        let (client, server) = duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                server_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });
        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CAPABILITY\r\nA003 SELECT INBOX\r\nA004 SEARCH YOUNGER 300\r\nA005 SEARCH OLDER 300\r\nA006 UID SEARCH YOUNGER 4000\r\nA007 SORT (ARRIVAL) UTF-8 YOUNGER 4000\r\nA008 LOGOUT\r\n",
            )
            .await
            .expect("commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let caps = read_until_contains(&mut reader, "A002 OK").await.join("");
        assert!(caps.contains("WITHIN"));
        let _select = read_until_contains(&mut reader, "A003 OK").await;
        assert!(
            read_until_contains(&mut reader, "A004 OK")
                .await
                .join("")
                .contains("* SEARCH 1")
        );
        assert!(
            read_until_contains(&mut reader, "A005 OK")
                .await
                .join("")
                .contains("* SEARCH 2 3")
        );
        assert!(
            read_until_contains(&mut reader, "A006 OK")
                .await
                .join("")
                .contains("* SEARCH 1 2")
        );
        assert!(
            read_until_contains(&mut reader, "A007 OK")
                .await
                .join("")
                .contains("* SORT 2 1")
        );
        let _logout = read_until_contains(&mut reader, "A008 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn savedate_and_status_size_use_persisted_message_metadata() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        let first = b"Subject: one\r\n\r\nfirst body\r\n";
        let second = b"Subject: two\r\n\r\nsecond body is longer\r\n";
        for data in [first.as_slice(), second.as_slice()] {
            rmail_common::imap_state::append_message_with_internal_date(
                &mail_root,
                "example.test",
                "user",
                "INBOX",
                data,
                Vec::new(),
                Some((837_596_665, -420)),
            )
            .expect("append");
        }
        let expected_size = first.len() + second.len();
        let server_mail_root = mail_root.clone();
        let (client, server) = duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                server_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });
        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CAPABILITY\r\nA003 STATUS INBOX (MESSAGES SIZE)\r\nA004 SELECT INBOX\r\nA005 UID FETCH 1:* (UID INTERNALDATE SAVEDATE RFC822.SIZE)\r\nA006 STATUS INBOX (BOGUS)\r\nA007 LOGOUT\r\n",
            )
            .await
            .expect("commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let caps = read_until_contains(&mut reader, "A002 OK").await.join("");
        assert!(caps.contains("STATUS=SIZE"));
        assert!(caps.contains("SAVEDATE"));
        let status = read_until_contains(&mut reader, "A003 OK").await.join("");
        assert!(status.contains(&format!("MESSAGES 2 SIZE {}", expected_size)));
        let _select = read_until_contains(&mut reader, "A004 OK").await;
        let fetch = read_until_contains(&mut reader, "A005 OK").await.join("");
        assert_eq!(fetch.matches("SAVEDATE \"").count(), 2);
        assert_eq!(
            fetch
                .matches("INTERNALDATE \"17-Jul-1996 02:44:25 -0700\"")
                .count(),
            2
        );
        assert!(!fetch.contains("SAVEDATE \"17-Jul-1996"));
        let invalid = read_until_contains(&mut reader, "A006 BAD").await.join("");
        assert!(invalid.contains("Invalid STATUS item"));
        let _logout = read_until_contains(&mut reader, "A007 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn check_unselect_uid_copy_and_uid_move_work() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Subject: one\r\n\r\nfirst\r\n",
        )
        .expect("deliver one");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Subject: two\r\n\r\nsecond\r\n",
        )
        .expect("deliver two");

        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        assert!(!capability.contains("MOVE"));

        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 CHECK\r\nA004 UID COPY 1 Archive\r\nA005 UID MOVE 2 Archive\r\nA006 UNSELECT\r\nA007 SELECT INBOX\r\nA008 STATUS Archive (UIDNEXT MESSAGES UNSEEN RECENT)\r\nA009 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _select1 = read_until_contains(&mut reader, "A002 OK").await;
        let check_lines = read_until_contains(&mut reader, "A003 OK").await;
        assert!(check_lines.iter().any(|l| l.contains("CHECK completed")));

        let copy_lines = read_until_contains(&mut reader, "A004 OK").await;
        assert!(copy_lines.iter().any(|l| l.contains("COPYUID")));

        let move_lines = read_until_contains(&mut reader, "A005 OK").await;
        assert!(move_lines.iter().any(|l| l.contains("COPYUID")));

        let unselect_lines = read_until_contains(&mut reader, "A006 OK").await;
        assert!(
            unselect_lines
                .iter()
                .any(|l| l.contains("UNSELECT completed"))
        );

        let select2 = read_until_contains(&mut reader, "A007 OK").await;
        assert!(select2.iter().any(|l| l.contains("* 1 EXISTS")));

        let status = read_until_contains(&mut reader, "A008 OK").await;
        assert!(
            status.iter().any(
                |l| l.contains("* STATUS \"Archive\" (MESSAGES 2 UIDNEXT 3 UNSEEN 2 RECENT 0)")
            )
        );

        let _logout = read_until_contains(&mut reader, "A009 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn append_preserves_literal_bytes_returns_appenduid_and_requires_existing_mailbox() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");

        let server_mail_root = mail_root.clone();
        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                server_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        assert!(!capability.contains("UIDPLUS"));
        assert!(capability.contains("LITERAL-"));
        assert!(capability.contains("LITERAL+"));

        let raw = b"Subject: appended\r\nX-Raw: \xff\r\n\r\nbody\x00bytes\r\n";
        let raw_non_sync = b"Subject: non-sync\r\n\r\nliteral-minus\r\n";
        let mut commands = Vec::new();
        commands.extend_from_slice(b"A001 LOGIN \"user@example.test\" \"password\"\r\n");
        commands.extend_from_slice(
            format!("A002 APPEND Sent (\\Seen) {{{}}}\r\n", raw.len()).as_bytes(),
        );
        commands.extend_from_slice(raw);
        commands.extend_from_slice(b"\r\n");
        commands.extend_from_slice(
            format!("A003 APPEND Archive {{{}+}}\r\n", raw_non_sync.len()).as_bytes(),
        );
        commands.extend_from_slice(raw_non_sync);
        commands.extend_from_slice(b"\r\n");
        commands.extend_from_slice(b"A004 APPEND Sent ~{3+}\r\n");
        commands.extend_from_slice(b"x\0y\r\n");
        let large_non_sync = vec![b'x'; 4097];
        commands.extend_from_slice(b"A005 APPEND Sent {4097+}\r\n");
        commands.extend_from_slice(&large_non_sync);
        commands.extend_from_slice(b"\r\n");
        commands.extend_from_slice(format!("A006 APPEND Missing {{{}}}\r\n", raw.len()).as_bytes());
        commands.extend_from_slice(raw);
        commands.extend_from_slice(b"\r\nA007 LOGOUT\r\n");
        reader
            .get_mut()
            .write_all(&commands)
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let append_lines = read_until_contains(&mut reader, "A002 OK").await;
        assert!(append_lines.iter().any(|l| l.starts_with("+ ")));
        assert!(append_lines.iter().any(|l| l.contains("APPENDUID")));

        let non_sync_append_lines = read_until_contains(&mut reader, "A003 OK").await;
        assert!(!non_sync_append_lines.iter().any(|l| l.starts_with("+ ")));
        assert!(
            non_sync_append_lines
                .iter()
                .any(|l| l.contains("APPENDUID"))
        );

        let literal8_lines = read_until_contains(&mut reader, "A004 OK").await;
        assert!(literal8_lines.iter().any(|l| l.contains("APPENDUID")));

        let large_non_sync_lines = read_until_contains(&mut reader, "A005 OK").await;
        assert!(!large_non_sync_lines.iter().any(|l| l.starts_with("+ ")));
        assert!(large_non_sync_lines.iter().any(|l| l.contains("APPENDUID")));

        let missing_lines = read_until_contains(&mut reader, "A006 NO").await;
        assert!(missing_lines.iter().any(|l| l.contains("APPEND failed")));

        let _logout = read_until_contains(&mut reader, "A007 OK").await;
        server_task.await.expect("join").expect("server");

        let (_, sent) =
            rmail_common::imap_state::load_folder(&mail_root, "example.test", "user", "Sent")
                .expect("load sent");
        assert_eq!(sent.len(), 3);
        assert!(sent.iter().any(|message| {
            std::fs::read(&message.path).is_ok_and(|bytes| bytes == large_non_sync)
        }));
        assert!(
            sent[0]
                .flags
                .iter()
                .any(|f| f.eq_ignore_ascii_case("\\Seen"))
        );
        assert_eq!(std::fs::read(&sent[0].path).expect("read appended"), raw);
        assert_eq!(
            std::fs::read(&sent[1].path).expect("read binary appended"),
            b"x\0y"
        );
        let (_, archive) =
            rmail_common::imap_state::load_folder(&mail_root, "example.test", "user", "Archive")
                .expect("load archive");
        assert_eq!(archive.len(), 1);
        assert_eq!(
            std::fs::read(&archive[0].path).expect("read non-sync appended"),
            raw_non_sync
        );
        assert!(
            !rmail_common::imap_state::folder_exists(&mail_root, "example.test", "user", "Missing")
                .expect("missing folder check")
        );
    }

    #[tokio::test]
    async fn append_internal_date_is_validated_persisted_and_fetched_with_timezone() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");

        let server_mail_root = mail_root.clone();
        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                server_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");

        let raw = b"Subject: dated\r\n\r\nbody\r\n";
        let mut commands = Vec::new();
        commands.extend_from_slice(b"A001 LOGIN \"user@example.test\" \"password\"\r\n");
        commands.extend_from_slice(
            format!(
                "A002 APPEND Sent (\\Seen) \"17-Jul-1996 02:44:25 -0700\" {{{}}}\r\n",
                raw.len()
            )
            .as_bytes(),
        );
        commands.extend_from_slice(raw);
        commands.extend_from_slice(b"\r\nA003 SELECT Sent\r\nA004 FETCH 1 (UID INTERNALDATE)\r\n");
        commands.extend_from_slice(
            b"A005 APPEND Sent \"31-Apr-2025 12:00:00 +0000\" {1}\r\nA006 LOGOUT\r\n",
        );
        reader.get_mut().write_all(&commands).await.expect("write");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let append = read_until_contains(&mut reader, "A002 OK").await;
        assert!(append.iter().any(|line| line.starts_with("+ ")));
        let _select = read_until_contains(&mut reader, "A003 OK").await;
        let fetch = read_until_contains(&mut reader, "A004 OK").await.join("");
        assert!(fetch.contains("INTERNALDATE \"17-Jul-1996 02:44:25 -0700\""));
        let invalid = read_until_contains(&mut reader, "A005 BAD").await;
        assert!(
            invalid
                .iter()
                .any(|line| line.contains("Invalid APPEND internal date"))
        );
        let _logout = read_until_contains(&mut reader, "A006 OK").await;
        server_task.await.expect("join").expect("server");

        let (_, messages) =
            rmail_common::imap_state::load_folder(&mail_root, "example.test", "user", "Sent")
                .expect("reload Sent");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].internaldate, 837_596_665);
        assert_eq!(messages[0].internaldate_tz, -420);
    }

    #[tokio::test]
    async fn unsupported_commands_return_bad_after_logging_context() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");

        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");

        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID SORT RETURN (ALL)\r\nA004 XLIST \"\" \"*\"\r\nA005 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let _select = read_until_contains(&mut reader, "A002 OK").await;

        let uid_sort = read_until_contains(&mut reader, "A003 BAD").await;
        assert!(
            uid_sort
                .iter()
                .any(|l| l.contains("Invalid UID SORT arguments"))
        );

        let xlist = read_until_contains(&mut reader, "A004 OK").await;
        assert!(
            xlist
                .iter()
                .any(|l| l.contains("\\Inbox") && l.contains("\"INBOX\""))
        );

        let _logout = read_until_contains(&mut reader, "A005 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn command_preflight_enforces_auth_and_selected_states() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");

        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");

        reader
            .get_mut()
            .write_all(
                b"A001 LIST \"\" \"*\"\r\nA002 FETCH 1:* FLAGS\r\nA003 LOGIN \"user@example.test\" \"password\"\r\nA004 LOGIN \"user@example.test\" \"password\"\r\nA005 FETCH 1:* FLAGS\r\nA006 SELECT INBOX\r\nA007 FETCH 1:* FLAGS\r\nA008 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let list = read_until_contains(&mut reader, "A001 NO").await;
        assert!(list.iter().any(|l| l.contains("Authentication required")));
        let fetch_before_auth = read_until_contains(&mut reader, "A002 NO").await;
        assert!(
            fetch_before_auth
                .iter()
                .any(|l| l.contains("Authentication required"))
        );
        let login = read_until_contains(&mut reader, "A003 OK").await;
        assert!(login.iter().any(|l| l.contains("LOGIN completed")));
        let login_after_auth = read_until_contains(&mut reader, "A004 BAD").await;
        assert!(
            login_after_auth
                .iter()
                .any(|l| l.contains("Command not allowed after authentication"))
        );
        let fetch_before_select = read_until_contains(&mut reader, "A005 BAD").await;
        assert!(
            fetch_before_select
                .iter()
                .any(|l| l.contains("No mailbox selected"))
        );
        let _select = read_until_contains(&mut reader, "A006 OK").await;
        let fetch_after_select = read_until_contains(&mut reader, "A007 OK").await;
        assert!(fetch_after_select.iter().any(|l| l.contains("FETCH")));
        let _logout = read_until_contains(&mut reader, "A008 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn scripted_thunderbird_compatibility_fixture_completes() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Date: Sun, 14 Jun 2026 12:00:00 +0000\r\nFrom: alice@example.test\r\nTo: user@example.test\r\nSubject: one\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nfirst body\r\n",
        )
        .expect("deliver first");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Date: Mon, 15 Jun 2026 12:00:00 +0000\r\nFrom: bob@example.test\r\nTo: user@example.test\r\nSubject: two\r\nContent-Type: multipart/alternative; boundary=\"alt\"\r\n\r\n--alt\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nsecond plain\r\n--alt\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<p>second html</p>\r\n--alt--\r\n",
        )
        .expect("deliver second");

        let (client, server) = duplex(128 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");

        run_scripted_fixture(
            &mut reader,
            include_str!("../fixtures/thunderbird_compat.imap"),
        )
        .await;

        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn scripted_evolution_compatibility_fixture_completes() {
        run_compatibility_fixture(include_str!("../fixtures/evolution_compat.imap")).await;
    }

    #[tokio::test]
    async fn scripted_geary_compatibility_fixture_completes() {
        run_compatibility_fixture(include_str!("../fixtures/geary_compat.imap")).await;
    }

    #[tokio::test]
    async fn scripted_mailspring_compatibility_fixture_completes() {
        run_compatibility_fixture(include_str!("../fixtures/mailspring_compat.imap")).await;
    }

    #[tokio::test]
    async fn rename_mailbox_updates_list_and_preserves_messages() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        rmail_common::imap_state::create_folder(&mail_root, "example.test", "user", "Projects")
            .expect("create folder");
        rmail_common::imap_state::append_message(
            &mail_root,
            "example.test",
            "user",
            "Projects",
            b"Subject: project\r\n\r\nbody\r\n",
            Vec::new(),
        )
        .expect("append project");

        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");

        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 RENAME Projects \"Renamed\"\r\nA003 LIST \"\" \"*\"\r\nA004 SELECT Renamed\r\nA005 RENAME INBOX Nope\r\nA006 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let rename = read_until_contains(&mut reader, "A002 OK").await;
        assert!(rename.iter().any(|l| l.contains("RENAME completed")));

        let list = read_until_contains(&mut reader, "A003 OK").await;
        let joined = list.join("");
        assert!(joined.contains("\"Renamed\""));
        assert!(!joined.contains("\"Projects\""));

        let select = read_until_contains(&mut reader, "A004 OK").await;
        assert!(select.iter().any(|l| l.contains("* 1 EXISTS")));

        let inbox_rename = read_until_contains(&mut reader, "A005 NO").await;
        assert!(
            inbox_rename
                .iter()
                .any(|l| l.contains("cannot rename INBOX"))
        );

        let _logout = read_until_contains(&mut reader, "A006 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn list_exposes_standard_special_use_folders() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");

        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        assert!(!capability.contains("SPECIAL-USE"));

        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 LIST \"\" \"*\"\r\nA003 SELECT Sent\r\nA004 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let list_lines = read_until_contains(&mut reader, "A002 OK").await;
        assert!(list_lines.iter().any(|l| l.contains("\"INBOX\"")));
        assert!(!list_lines.iter().any(|l| l.contains("\\Inbox")));
        assert!(
            list_lines
                .iter()
                .any(|l| l.contains("\\Sent") && l.contains("\"Sent\""))
        );
        assert!(
            list_lines
                .iter()
                .any(|l| l.contains("\\Drafts") && l.contains("\"Drafts\""))
        );
        assert!(
            list_lines
                .iter()
                .any(|l| l.contains("\\Trash") && l.contains("\"Trash\""))
        );
        assert!(
            list_lines
                .iter()
                .any(|l| l.contains("\\Junk") && l.contains("\"Junk\""))
        );
        assert!(
            list_lines
                .iter()
                .any(|l| l.contains("\\Archive") && l.contains("\"Archive\""))
        );

        let select_lines = read_until_contains(&mut reader, "A003 OK").await;
        assert!(select_lines.iter().any(|l| l.contains("* 0 EXISTS")));

        let _logout = read_until_contains(&mut reader, "A004 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn list_extended_returns_special_use_children_and_status() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");

        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        assert!(!capability.contains("LIST-EXTENDED"));
        assert!(!capability.contains("CHILDREN"));
        assert!(!capability.contains("LIST-STATUS"));

        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CREATE Projects\r\nA003 CREATE Projects/Child\r\nA004 LIST \"\" \"Projects\" RETURN (CHILDREN)\r\nA005 LIST (SPECIAL-USE) \"\" (\"INBOX\" \"Sent\") RETURN (SPECIAL-USE STATUS (MESSAGES UIDNEXT UNSEEN))\r\nA006 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let _create_parent = read_until_contains(&mut reader, "A002 OK").await;
        let _create_child = read_until_contains(&mut reader, "A003 OK").await;
        let children = read_until_contains(&mut reader, "A004 OK").await;
        assert!(
            children
                .iter()
                .any(|l| l.contains("* LIST (\\HasChildren)") && l.contains("\"Projects\""))
        );
        let special_status = read_until_contains(&mut reader, "A005 OK").await;
        assert!(
            special_status
                .iter()
                .any(|l| l.contains("* LIST (\\Sent)") && l.contains("\"Sent\""))
        );
        assert!(
            special_status
                .iter()
                .any(|l| l.contains("* STATUS \"Sent\"") && l.contains("MESSAGES 0"))
        );
        assert!(
            !special_status
                .iter()
                .any(|l| l.contains("* STATUS \"INBOX\""))
        );
        let _logout = read_until_contains(&mut reader, "A006 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn mailbox_names_use_modified_utf7_on_the_imap_wire() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");

        let server_mail_root = mail_root.clone();
        let server_db_path = db_path.clone();
        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                server_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(server_db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CREATE &ZeVnLIqe-\r\nA003 LIST \"\" \"&ZeVnLIqe-\"\r\nA004 STATUS &ZeVnLIqe- (MESSAGES UIDNEXT)\r\nA005 SELECT &ZeVnLIqe-\r\nA006 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let create = read_until_contains(&mut reader, "A002 OK").await;
        assert!(create.iter().any(|line| line.contains("CREATE completed")));
        let list = read_until_contains(&mut reader, "A003 OK").await;
        assert!(
            list.iter()
                .any(|line| line.contains("* LIST") && line.contains("\"&ZeVnLIqe-\""))
        );
        assert!(!list.iter().any(|line| line.contains("日本語")));
        let status = read_until_contains(&mut reader, "A004 OK").await;
        assert!(
            status
                .iter()
                .any(|line| line.contains("* STATUS \"&ZeVnLIqe-\""))
        );
        let select = read_until_contains(&mut reader, "A005 OK").await;
        assert!(select.iter().any(|line| line.contains("SELECT completed")));
        let _logout = read_until_contains(&mut reader, "A006 OK").await;
        server_task.await.expect("join").expect("server");

        assert!(
            rmail_common::imap_state::folder_exists(
                mail_root.as_path(),
                "example.test",
                "user",
                "日本語"
            )
            .expect("folder exists")
        );
    }

    #[tokio::test]
    async fn utf8_accept_switches_mailbox_wire_format_append_and_search_rules() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        let server_mail_root = mail_root.clone();
        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                server_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });
        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        reader
            .get_mut()
            .write_all(
                "A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CAPABILITY\r\nA003 ENABLE UTF8=ACCEPT\r\nA004 CREATE \"旅行 & Stuff\"\r\nA005 LIST \"\" \"旅行 & Stuff\"\r\nA006 SELECT \"旅行 & Stuff\"\r\nA007 SEARCH CHARSET UTF-8 ALL\r\n"
                    .as_bytes(),
            )
            .await
            .expect("commands");
        reader.get_mut().flush().await.expect("flush");
        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let caps = read_until_contains(&mut reader, "A002 OK").await.join("");
        assert!(caps.contains("UTF8=ACCEPT"));
        let enabled = read_until_contains(&mut reader, "A003 OK").await.join("");
        assert!(enabled.contains("* ENABLED UTF8=ACCEPT"));
        let _create = read_until_contains(&mut reader, "A004 OK").await;
        let list = read_until_contains(&mut reader, "A005 OK").await.join("");
        assert!(list.contains("\"旅行 & Stuff\""));
        assert!(!list.contains("&ZcWITA-"));
        let _select = read_until_contains(&mut reader, "A006 OK").await;
        let search = read_until_contains(&mut reader, "A007 BAD").await.join("");
        assert!(search.contains("Cannot set SEARCH charset"));

        let utf8_message = "Subject: 日本語\r\n\r\nこんにちは\r\n".as_bytes();
        reader
            .get_mut()
            .write_all(
                format!(
                    "A008 APPEND \"旅行 & Stuff\" UTF8 (~{{{}}})\r\n",
                    utf8_message.len()
                )
                .as_bytes(),
            )
            .await
            .expect("utf8 append command");
        reader.get_mut().flush().await.expect("flush");
        let continuation = read_until_contains(&mut reader, "+ Ready").await.join("");
        assert!(continuation.contains("+ Ready"));
        reader
            .get_mut()
            .write_all(utf8_message)
            .await
            .expect("utf8 message");
        reader.get_mut().flush().await.expect("flush");
        let appended = read_until_contains(&mut reader, "A008 OK").await.join("");
        assert!(appended.contains("APPENDUID"));

        reader
            .get_mut()
            .write_all(b"A009 APPEND INBOX ~{3+}\r\na\0b\r\nA010 LOGOUT\r\n")
            .await
            .expect("binary append and logout");
        reader.get_mut().flush().await.expect("flush");
        let binary = read_until_contains(&mut reader, "A009 OK").await.join("");
        assert!(binary.contains("APPENDUID"));
        let _logout = read_until_contains(&mut reader, "A010 OK").await;
        server_task.await.expect("join").expect("server");

        assert!(
            rmail_common::imap_state::folder_exists(
                &mail_root,
                "example.test",
                "user",
                "旅行 & Stuff"
            )
            .expect("utf8 folder")
        );
    }

    #[tokio::test]
    async fn geary_account_probe_gets_inbox_special_use_and_namespace() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");

        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");

        reader
            .get_mut()
            .write_all(
                b"A001 CAPABILITY\r\nA002 LOGIN user@example.test password\r\nA003 CAPABILITY\r\nA004 LIST \"\" INBOX\r\nA005 NAMESPACE\r\nA006 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _initial_capability = read_until_contains(&mut reader, "A001 OK").await;
        let _login = read_until_contains(&mut reader, "A002 OK").await;
        let _authed_capability = read_until_contains(&mut reader, "A003 OK").await;
        let inbox = read_until_contains(&mut reader, "A004 OK").await;
        assert!(inbox.iter().any(|l| l.contains("\"INBOX\"")));
        assert!(!inbox.iter().any(|l| l.contains("\\Inbox")));

        let namespace = read_until_contains(&mut reader, "A005 OK").await;
        assert!(
            namespace
                .iter()
                .any(|l| l == "* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n")
        );

        let _logout = read_until_contains(&mut reader, "A006 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn list_and_lsub_honor_reference_and_patterns() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        rmail_common::imap_state::create_folder(&mail_root, "example.test", "user", "Projects")
            .expect("create projects");
        rmail_common::imap_state::set_subscription(
            &mail_root,
            "example.test",
            "user",
            "Projects",
            false,
        )
        .expect("unsubscribe projects");

        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");

        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 LIST \"\" \"Pro*\"\r\nA003 LIST \"\" \"INBOX\"\r\nA004 LIST \"Projects\" \"\"\r\nA005 LSUB \"\" \"Pro*\"\r\nA006 LSUB \"\" \"*\"\r\nA007 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;

        let pro_star = read_until_contains(&mut reader, "A002 OK").await;
        let joined = pro_star.join("");
        assert!(joined.contains("\"Projects\""));
        assert!(!joined.contains("\"INBOX\""));

        let inbox = read_until_contains(&mut reader, "A003 OK").await;
        let joined = inbox.join("");
        assert!(joined.contains("\"INBOX\""));
        assert!(!joined.contains("\"Projects\""));

        let reference = read_until_contains(&mut reader, "A004 OK").await;
        let joined = reference.join("");
        assert!(joined.contains("\"Projects\""));
        assert!(!joined.contains("\"INBOX\""));

        let unsubscribed = read_until_contains(&mut reader, "A005 OK").await;
        assert!(!unsubscribed.join("").contains("\"Projects\""));

        let subscribed = read_until_contains(&mut reader, "A006 OK").await;
        let joined = subscribed.join("");
        assert!(joined.contains("\"INBOX\""));
        assert!(!joined.contains("\"Projects\""));

        let _logout = read_until_contains(&mut reader, "A007 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn subscribe_and_unsubscribe_update_lsub_state() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        rmail_common::imap_state::create_folder(&mail_root, "example.test", "user", "Projects")
            .expect("create projects");
        rmail_common::imap_state::set_subscription(
            &mail_root,
            "example.test",
            "user",
            "Projects",
            false,
        )
        .expect("initial unsubscribe");

        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");

        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 LSUB \"\" \"Projects\"\r\nA003 SUBSCRIBE Projects\r\nA004 LSUB \"\" \"Projects\"\r\nA005 UNSUBSCRIBE Projects\r\nA006 LSUB \"\" \"Projects\"\r\nA007 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;

        let initial = read_until_contains(&mut reader, "A002 OK").await;
        assert!(!initial.join("").contains("\"Projects\""));

        let subscribe = read_until_contains(&mut reader, "A003 OK").await;
        assert!(subscribe.iter().any(|l| l.contains("SUBSCRIBE completed")));

        let subscribed = read_until_contains(&mut reader, "A004 OK").await;
        assert!(subscribed.join("").contains("\"Projects\""));

        let unsubscribe = read_until_contains(&mut reader, "A005 OK").await;
        assert!(
            unsubscribe
                .iter()
                .any(|l| l.contains("UNSUBSCRIBE completed"))
        );

        let final_lsub = read_until_contains(&mut reader, "A006 OK").await;
        assert!(!final_lsub.join("").contains("\"Projects\""));

        let _logout = read_until_contains(&mut reader, "A007 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn fetch_macros_envelope_and_bodystructure_are_parseable() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Date: Sun, 14 Jun 2026 12:00:00 +0000\r\nFrom: Sender Name <sender@example.test>\r\nTo: User <user@example.test>\r\nCc: copy@example.test\r\nMessage-ID: <m1@example.test>\r\nSubject: macro\r\n\r\nbody\r\n",
        )
        .expect("deliver");

        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");

        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 FETCH 1 FULL\r\nA004 UID FETCH 1:* (UID BODYSTRUCTURE ENVELOPE)\r\nA005 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _select = read_until_contains(&mut reader, "A002 OK").await;
        let full_lines = read_until_contains(&mut reader, "A003 OK").await;
        let joined_full = full_lines.join("");
        assert!(joined_full.contains("FLAGS"));
        assert!(joined_full.contains("INTERNALDATE"));
        assert!(joined_full.contains("RFC822.SIZE"));
        assert!(joined_full.contains("ENVELOPE"));
        assert!(joined_full.contains("BODYSTRUCTURE"));

        let uid_lines = read_until_contains(&mut reader, "A004 OK").await;
        let joined_uid = uid_lines.join("");
        assert!(joined_uid.contains("UID "));
        assert!(joined_uid.contains("BODYSTRUCTURE"));
        assert!(joined_uid.contains("ENVELOPE"));
        assert!(joined_uid.contains("(\"Sender Name\" NIL \"sender\" \"example.test\")"));
        assert!(joined_uid.contains("(\"User\" NIL \"user\" \"example.test\")"));
        assert!(joined_uid.contains("(NIL NIL \"copy\" \"example.test\")"));
        assert!(joined_uid.contains("\"<m1@example.test>\""));

        let _logout = read_until_contains(&mut reader, "A005 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn bodystructure_describes_multipart_html_inline_and_attachment_parts() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"From: a@example.test\r\nSubject: multipart\r\nContent-Type: multipart/mixed; boundary=\"mix\"\r\n\r\n--mix\r\nContent-Type: multipart/alternative; boundary=\"alt\"\r\n\r\n--alt\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nPlain body\r\n--alt\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<p>HTML body</p>\r\n--alt--\r\n--mix\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\nContent-ID: <logo@example.test>\r\nContent-Disposition: inline; filename=\"logo.png\"\r\n\r\naGVsbG8=\r\n--mix\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"file.pdf\"\r\n\r\n%PDF\r\n--mix--\r\n",
        )
        .expect("deliver");

        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");

        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID FETCH 1:* (UID BODYSTRUCTURE)\r\nA004 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _select = read_until_contains(&mut reader, "A002 OK").await;
        let fetch_lines = read_until_contains(&mut reader, "A003 OK").await;
        let joined = fetch_lines.join("");
        assert!(joined.contains("BODYSTRUCTURE"));
        assert!(joined.contains("\"MIXED\""));
        assert!(joined.contains("\"ALTERNATIVE\""));
        assert!(joined.contains("\"TEXT\" \"HTML\""));
        assert!(joined.contains("\"IMAGE\" \"PNG\""));
        assert!(joined.contains("\"APPLICATION\" \"PDF\""));
        assert!(joined.contains("\"INLINE\" (\"FILENAME\" \"logo.png\")"));
        assert!(joined.contains("\"ATTACHMENT\" (\"FILENAME\" \"file.pdf\")"));
        assert!(joined.contains("logo@example.test"));

        let _logout = read_until_contains(&mut reader, "A004 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn fetch_body_sections_return_mime_part_content_and_headers() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            None,
        )
        .expect("add mailbox");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"From: a@example.test\r\nSubject: sections\r\nContent-Type: multipart/mixed; boundary=\"mix\"\r\n\r\n--mix\r\nContent-Type: text/plain; charset=UTF-8\r\nX-Part: one\r\n\r\nPlain part body\r\n--mix\r\nContent-Type: multipart/alternative; boundary=\"alt\"\r\n\r\n--alt\r\nContent-Type: text/plain\r\n\r\nAlt plain\r\n--alt\r\nContent-Type: text/html\r\n\r\n<p>Alt HTML</p>\r\n--alt--\r\n--mix--\r\n",
        )
        .expect("deliver");

        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                true,
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.expect("greeting");
        let mut capability = String::new();
        reader.read_line(&mut capability).await.expect("capability");
        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID FETCH 1:* (UID BODY.PEEK[1])\r\nA004 UID FETCH 1:* (UID BODY.PEEK[1.MIME])\r\nA005 UID FETCH 1:* (UID BODY.PEEK[2.2])\r\nA006 UID FETCH 1:* (UID BODY.PEEK[2.2]<3.8>)\r\nA007 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let _select = read_until_contains(&mut reader, "A002 OK").await;

        let part_body = read_until_contains(&mut reader, "A003 OK").await;
        let joined = part_body.join("");
        assert!(joined.contains("BODY[1]"));
        assert!(joined.contains("Plain part body"));
        assert!(!joined.contains("Content-Type: text/plain; charset=UTF-8"));
        assert!(!joined.contains("<p>Alt HTML</p>"));

        let part_mime = read_until_contains(&mut reader, "A004 OK").await;
        let joined = part_mime.join("");
        assert!(joined.contains("BODY[1.MIME]"));
        assert!(joined.contains("Content-Type: text/plain; charset=UTF-8"));
        assert!(joined.contains("X-Part: one"));
        assert!(!joined.contains("Plain part body"));

        let nested_html = read_until_contains(&mut reader, "A005 OK").await;
        let joined = nested_html.join("");
        assert!(joined.contains("BODY[2.2]"));
        assert!(joined.contains("<p>Alt HTML</p>"));
        assert!(!joined.contains("Alt plain"));

        let partial_html = read_until_contains(&mut reader, "A006 OK").await;
        let joined = partial_html.join("");
        assert!(joined.contains("BODY[2.2]<3> {8}"));
        assert!(joined.contains("Alt HTML"));
        assert!(!joined.contains("<p>"));

        let _logout = read_until_contains(&mut reader, "A007 OK").await;
        server_task.await.expect("join").expect("server");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg_path =
        std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let cfg = Config::from_file(&cfg_path).context(format!("loading {}", cfg_path))?;
    let mail_root = cfg.global.mail_root.clone();
    rmail_common::runtime::redirect_stdio_to_log(std::path::Path::new(&mail_root), "imapd")
        .context("redirecting logs")?;

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
            Err(e) => {
                eprintln!("Failed to load TLS: {}", e);
                None
            }
        }
    } else {
        None
    };

    let db_path = cfg.global.db_path.clone();
    // Plain IMAP listener (supports STARTTLS if tls_context present)
    let imap_port = cfg.global.imap_port.unwrap_or(143);
    let imap_addrs = cfg
        .global
        .imap_listen_addrs
        .clone()
        .unwrap_or_else(|| vec![format!("0.0.0.0:{}", imap_port)]);
    let mut listener_count = 0usize;
    for addr in imap_addrs {
        let listener = bind_tcp_listener(&addr)
            .with_context(|| format!("starting IMAP plain listener on {addr}"))?;
        println!("rMail IMAPD listening on {}", addr);
        listener_count += 1;
        let mail_root_clone = mail_root.clone();
        let acceptor_clone = tls_context.clone();
        let db_clone = db_path.clone();
        tokio::spawn(async move {
            if let Err(e) =
                run_plain_listener(addr, listener, mail_root_clone, acceptor_clone, db_clone).await
            {
                eprintln!("IMAP plain listener failed: {}", e);
            }
        });
    }

    // IMAPS (implicit TLS) listener
    if let Some(ctx) = tls_context.clone() {
        if let Some(imaps_port) = cfg.global.imaps_port {
            let imaps_addrs = cfg
                .global
                .imaps_listen_addrs
                .clone()
                .unwrap_or_else(|| vec![format!("0.0.0.0:{}", imaps_port)]);
            for addr in imaps_addrs {
                let listener = bind_tcp_listener(&addr)
                    .with_context(|| format!("starting IMAPS listener on {addr}"))?;
                println!("rMail IMAPD (IMAPS) listening on {}", addr);
                listener_count += 1;
                let mail_root_clone = mail_root.clone();
                let ctx_clone = ctx.clone();
                let db_clone = db_path.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        run_imaps_listener(addr, listener, ctx_clone, mail_root_clone, db_clone)
                            .await
                    {
                        eprintln!("IMAPS listener failed: {}", e);
                    }
                });
            }
        }
    } else if cfg.global.imaps_port.is_some() || cfg.global.imaps_listen_addrs.is_some() {
        eprintln!("IMAPS listener not started because TLS certificate/key could not be loaded");
    }

    if listener_count == 0 {
        return Err(anyhow!("no IMAP listeners were started"));
    }

    // keep running
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

async fn run_plain_listener(
    addr: String,
    listener: tokio::net::TcpListener,
    mail_root: String,
    tls_ctx: Option<Arc<tls::TlsContext>>,
    db_path: Option<String>,
) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        println!(
            "Accepted IMAP plaintext connection on {} from {} (starttls_available={})",
            addr,
            peer,
            tls_ctx.is_some()
        );
        let mail_root = mail_root.clone();
        let acceptor = tls_ctx.clone();
        let db_clone = db_path.clone();
        tokio::spawn(async move {
            if let Err(e) = process_stream(
                Box::new(stream),
                mail_root,
                acceptor,
                db_clone,
                Some(peer),
                false,
            )
            .await
            {
                eprintln!("IMAP client error: {}", e);
            }
        });
    }
}

async fn run_imaps_listener(
    addr: String,
    listener: tokio::net::TcpListener,
    ctx: Arc<tls::TlsContext>,
    mail_root: String,
    db_path: Option<String>,
) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        println!("Accepted IMAPS TCP connection on {} from {}", addr, peer);
        let ctx = ctx.clone();
        let mail_root = mail_root.clone();
        let db_clone = db_path.clone();
        tokio::spawn(async move {
            match ctx.acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(e) = process_stream(
                        Box::new(tls_stream),
                        mail_root,
                        Some(ctx.clone()),
                        db_clone,
                        Some(peer),
                        true,
                    )
                    .await
                    {
                        eprintln!("IMAPS client error: {}", e);
                    }
                }
                Err(e) => eprintln!("IMAPS TLS accept error from {}: {}", peer, e),
            }
        });
    }
}

fn unquote(s: &str) -> &str {
    parser::unquote(s)
}

fn log_imap_response(peer: Option<SocketAddr>, tag: &str, cmd: &str, response: &str) {
    response::log_imap_response(peer, tag, cmd, response)
}

fn address_parts(address: &str) -> Result<(String, String)> {
    mailbox::address_parts(address)
}

fn selected_mailbox_name(selected: &Option<SelectedMailbox>) -> &str {
    mailbox::selected_mailbox_name(selected)
}

fn selected_mailbox_for_log(selected: &Option<SelectedMailbox>) -> &str {
    mailbox::selected_mailbox_for_log(selected)
}

fn log_unsupported_imap(
    peer: Option<SocketAddr>,
    selected: &Option<SelectedMailbox>,
    tag: &str,
    command: &str,
    raw_args: &str,
) {
    eprintln!(
        "imap_unsupported peer={:?} selected_mailbox={} tag={} command={} raw_args={:?}",
        peer,
        selected_mailbox_for_log(selected),
        tag,
        command,
        raw_args
    );
}

fn next_uid(sel: &SelectedMailbox) -> u64 {
    mailbox::next_uid(sel)
}

fn first_unseen(sel: &SelectedMailbox) -> u64 {
    mailbox::first_unseen(sel)
}

fn unseen_count(sel: &SelectedMailbox) -> usize {
    mailbox::unseen_count(sel)
}

fn seqs_from_set(seq_set: &str, total: usize) -> Vec<usize> {
    parser::seqs_from_set(seq_set, total)
}

fn uids_from_set(uid_set: &str, msgs: &[(u64, std::path::PathBuf, Vec<String>, u64)]) -> Vec<u64> {
    parser::uids_from_set(uid_set, msgs)
}

fn seqs_from_set_or_saved(
    sequence_set: &str,
    selected: &SelectedMailbox,
    saved_uids: &[u64],
) -> Vec<usize> {
    if sequence_set == "$" {
        selected
            .msgs
            .iter()
            .enumerate()
            .filter_map(|(index, (uid, _, _, _))| {
                saved_uids.binary_search(uid).is_ok().then_some(index + 1)
            })
            .collect()
    } else {
        seqs_from_set(sequence_set, selected.msgs.len())
    }
}

fn uids_from_set_or_saved(
    uid_set: &str,
    selected: &SelectedMailbox,
    saved_uids: &[u64],
) -> Vec<u64> {
    if uid_set == "$" {
        saved_uids
            .iter()
            .copied()
            .filter(|saved_uid| selected.msgs.iter().any(|(uid, _, _, _)| uid == saved_uid))
            .collect()
    } else {
        uids_from_set(uid_set, &selected.msgs)
    }
}

fn copy_uid_pairs(
    source_set: &[u64],
    destination_uids: &[u64],
    uidvalidity: u64,
) -> Option<String> {
    mailbox::copy_uid_pairs(source_set, destination_uids, uidvalidity)
}

fn normalize_fetch_items(spec: &str) -> Vec<String> {
    parser::normalize_fetch_items(spec)
}

fn fetch_marks_seen(requested: &[String]) -> bool {
    requested.iter().any(|item| {
        item == "RFC822"
            || item == "RFC822.TEXT"
            || (item.starts_with("BODY[") && item.contains(']'))
            || (item.starts_with("BINARY[") && item.contains(']'))
    })
}

fn apply_implicit_seen(
    mail_root: &str,
    sel: &SelectedMailbox,
    uid: u64,
    flags: &mut Vec<String>,
) -> Result<u64> {
    if sel.read_only || flags.iter().any(|flag| flag.eq_ignore_ascii_case("\\Seen")) {
        return Ok(0);
    }
    flags.push("\\Seen".to_string());
    flags.sort();
    flags.dedup();
    rmail_common::imap_state::set_uid_flags(
        Path::new(mail_root),
        &sel.domain,
        &sel.local,
        &sel.mailbox,
        uid,
        flags.clone(),
    )
}

fn parse_store_items(spec: &str) -> Vec<String> {
    parser::parse_store_items(spec)
}

#[derive(Debug, Default, PartialEq, Eq)]
struct FetchModifiers {
    changed_since: Option<u64>,
    vanished: bool,
}

fn parse_fetch_modifiers(spec: &str) -> Result<FetchModifiers, &'static str> {
    let modifier = spec.trim();
    if modifier.is_empty() {
        return Ok(FetchModifiers::default());
    }
    let upper = modifier.to_ascii_uppercase();
    if !upper.starts_with("(CHANGEDSINCE") {
        return Err("Unsupported FETCH modifier");
    }
    if !modifier.ends_with(')') {
        return Err("Malformed FETCH modifiers");
    }
    let tokens = modifier[1..modifier.len() - 1]
        .split_whitespace()
        .collect::<Vec<_>>();
    if tokens.len() < 2 || !tokens[0].eq_ignore_ascii_case("CHANGEDSINCE") {
        return Err("Malformed FETCH modifiers");
    }
    let changed_since = tokens[1]
        .parse::<u64>()
        .map_err(|_| "Invalid CHANGEDSINCE value")?;
    let mut vanished = false;
    for token in &tokens[2..] {
        if token.eq_ignore_ascii_case("VANISHED") && !vanished {
            vanished = true;
        } else {
            return Err("Unsupported FETCH modifier");
        }
    }
    Ok(FetchModifiers {
        changed_since: Some(changed_since),
        vanished,
    })
}

fn parse_store_command_args(input: &str) -> Option<(String, Option<u64>, String, String)> {
    let input = input.trim();
    let (message_set, rest) = input.split_once(char::is_whitespace)?;
    let mut rest = rest.trim_start();
    let mut unchanged_since = None;
    if rest.to_ascii_uppercase().starts_with("(UNCHANGEDSINCE") {
        let close = rest.find(')')?;
        let option = &rest[1..close];
        let mut option_parts = option.split_whitespace();
        if !option_parts
            .next()
            .map(|name| name.eq_ignore_ascii_case("UNCHANGEDSINCE"))
            .unwrap_or(false)
        {
            return None;
        }
        unchanged_since = option_parts
            .next()
            .and_then(|value| value.parse::<u64>().ok());
        unchanged_since?;
        rest = rest[close + 1..].trim_start();
    }
    let (op, flags) = rest.split_once(char::is_whitespace)?;
    Some((
        message_set.to_string(),
        unchanged_since,
        op.to_string(),
        flags.trim().to_string(),
    ))
}

fn split_first_imap_astring(input: &str) -> Option<(String, &str)> {
    parser::split_first_imap_astring(input)
}

fn parse_append_args(args: &str) -> Result<parser::AppendRequest, parser::ParseError> {
    parser::parse_append_args(args)
}

fn mailbox_pattern_matches(name: &str, reference: &str, pattern: &str) -> bool {
    parser::mailbox_pattern_matches(name, reference, pattern)
}

fn quote_imap_string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{}\"", escaped)
}

fn imap_wire_mailbox_name(name: &str, utf8_accept: bool) -> String {
    if utf8_accept {
        name.to_string()
    } else {
        rmail_common::maildir::utf8_to_imap_utf7(name).unwrap_or_else(|_| name.to_string())
    }
}

fn quote_imap_mailbox_name(name: &str, utf8_accept: bool) -> String {
    quote_imap_string(&imap_wire_mailbox_name(name, utf8_accept))
}

fn decode_imap_mailbox_arg(name: &str, utf8_accept: bool) -> Result<String> {
    if !utf8_accept && name.contains('&') {
        rmail_common::maildir::imap_utf7_to_utf8(name).map_err(Into::into)
    } else {
        Ok(name.to_string())
    }
}

fn decode_list_request(
    mut request: parser::ListRequest,
    utf8_accept: bool,
) -> Result<parser::ListRequest> {
    request.reference = decode_imap_mailbox_arg(&request.reference, utf8_accept)?;
    request.patterns = request
        .patterns
        .into_iter()
        .map(|pattern| decode_imap_mailbox_arg(&pattern, utf8_accept))
        .collect::<Result<Vec<_>>>()?;
    Ok(request)
}

fn has_child_folder(name: &str, folders: &[rmail_common::imap_state::FolderSummary]) -> bool {
    let prefix = format!("{}/", name);
    folders
        .iter()
        .any(|candidate| candidate.folder.name.starts_with(&prefix))
}

fn list_status_value(summary: &rmail_common::imap_state::FolderSummary, item: &str) -> String {
    match item.to_ascii_uppercase().as_str() {
        "MESSAGES" => format!("MESSAGES {}", summary.messages),
        "UIDNEXT" => format!("UIDNEXT {}", summary.folder.uidnext),
        "UIDVALIDITY" => format!("UIDVALIDITY {}", summary.folder.uidvalidity),
        "HIGHESTMODSEQ" => format!("HIGHESTMODSEQ {}", summary.folder.highest_modseq),
        "UNSEEN" => format!("UNSEEN {}", summary.unseen),
        "RECENT" => "RECENT 0".to_string(),
        unsupported => format!("{} 0", unsupported),
    }
}

fn append_list_response(
    response: &mut String,
    command_name: &str,
    request: &parser::ListRequest,
    summary: &rmail_common::imap_state::FolderSummary,
    all_folders: &[rmail_common::imap_state::FolderSummary],
    utf8_accept: bool,
) {
    let mut attrs = Vec::new();
    if request.returns.children {
        if has_child_folder(&summary.folder.name, all_folders) {
            attrs.push("\\HasChildren".to_string());
        } else {
            attrs.push("\\HasNoChildren".to_string());
        }
    }
    if request.returns.subscribed && summary.folder.subscribed {
        attrs.push("\\Subscribed".to_string());
    }
    if command_name == "XLIST" && summary.folder.name.eq_ignore_ascii_case("INBOX") {
        attrs.push("\\Inbox".to_string());
    }
    if request.returns.special_use {
        if let Some(special) = summary.folder.special_use.as_ref() {
            attrs.push(special.clone());
        }
    }
    response.push_str(&format!(
        "* {} ({}) \"/\" {}\r\n",
        command_name,
        attrs.join(" "),
        quote_imap_mailbox_name(&summary.folder.name, utf8_accept)
    ));
    if !request.returns.status.is_empty() {
        let values = request
            .returns
            .status
            .iter()
            .map(|item| list_status_value(summary, item))
            .collect::<Vec<_>>()
            .join(" ");
        response.push_str(&format!(
            "* STATUS {} ({})\r\n",
            quote_imap_mailbox_name(&summary.folder.name, utf8_accept),
            values
        ));
    }
}

#[cfg(test)]
fn parse_scram_attr<'a>(message: &'a str, key: &str) -> Option<&'a str> {
    auth::parse_scram_attr(message, key)
}

fn generate_scram_nonce() -> String {
    auth::generate_scram_nonce()
}

enum PasswordAuthResult {
    Success(Mailbox),
    NoSuchUser,
    NoPassword,
    BadPassword(Mailbox),
    Error {
        mailbox: Option<Mailbox>,
        message: String,
    },
}

async fn lookup_mailbox_for_auth(db_path: Option<&String>, user: &str) -> Option<Mailbox> {
    let db_path = db_path?;
    let user_lookup = common_auth::saslprep(user).to_ascii_lowercase();
    if user_lookup.contains('@') {
        let dbp = db_path.clone();
        match tokio::task::spawn_blocking(move || rmail_common::db::get_mailbox(dbp, &user_lookup))
            .await
        {
            Ok(Ok(Some(mailbox))) => Some(mailbox),
            Ok(Ok(None)) => None,
            Ok(Err(e)) => {
                eprintln!("db get_mailbox error: {}", e);
                None
            }
            Err(e) => {
                eprintln!("db task join error: {}", e);
                None
            }
        }
    } else {
        let dbp = db_path.clone();
        match tokio::task::spawn_blocking(move || {
            rmail_common::db::find_mailbox_by_localpart(dbp, &user_lookup)
        })
        .await
        {
            Ok(Ok(Some(mailbox))) => Some(mailbox),
            Ok(Ok(None)) => None,
            Ok(Err(e)) => {
                eprintln!("db find_mailbox_by_localpart error: {}", e);
                None
            }
            Err(e) => {
                eprintln!("db task join error: {}", e);
                None
            }
        }
    }
}

async fn authenticate_password(
    db_path: Option<&String>,
    user: &str,
    password: &str,
) -> PasswordAuthResult {
    let Some(mailbox) = lookup_mailbox_for_auth(db_path, user).await else {
        return PasswordAuthResult::NoSuchUser;
    };
    let Some(hash) = mailbox.password_hash.as_ref() else {
        return PasswordAuthResult::NoPassword;
    };
    match common_auth::verify_password(password, hash) {
        Ok(true) => PasswordAuthResult::Success(mailbox),
        Ok(false) => PasswordAuthResult::BadPassword(mailbox),
        Err(e) => PasswordAuthResult::Error {
            mailbox: Some(mailbox),
            message: e.to_string(),
        },
    }
}

fn apply_flag_operation(existing: &[String], op: &str, flags: &[String]) -> Vec<String> {
    let mut current = existing.to_vec();
    let silent_op = op.trim_end_matches(".SILENT");
    match silent_op {
        "FLAGS" => current = flags.to_vec(),
        "+FLAGS" => {
            for flag in flags {
                if !current.iter().any(|f| f == flag) {
                    current.push(flag.clone());
                }
            }
        }
        "-FLAGS" => {
            current.retain(|f| !flags.iter().any(|x| x == f));
        }
        _ => {}
    }
    current.sort();
    current.dedup();
    current
}

async fn write_fetch_response(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    seq: usize,
    uid: u64,
    flags: &[String],
    modseq: u64,
    internal_date: (i64, i32),
    save_date: i64,
    path: std::path::PathBuf,
    requested: &[String],
    raw_spec: &str,
    force_uid: bool,
) -> Result<()> {
    mailbox::write_fetch_response(
        reader,
        seq,
        uid,
        flags,
        modseq,
        internal_date,
        save_date,
        path,
        requested,
        raw_spec,
        force_uid,
    )
    .await
}

async fn execute_search(
    selected: &SelectedMailbox,
    criterion: &parser::SearchCriterion,
    saved_search_uids: &[u64],
) -> Result<Vec<(u64, u64)>> {
    let mut matches = Vec::new();
    let now = chrono::Utc::now().timestamp();
    for (idx, (uid, path, flags, _)) in selected.msgs.iter().enumerate() {
        let data = tokio::task::spawn_blocking({
            let path = path.clone();
            move || std::fs::read(path)
        })
        .await??;
        let msg = parser::SearchMessage {
            seq: idx + 1,
            uid: *uid,
            flags,
            internal_date: selected
                .internal_dates
                .get(uid)
                .map(|date| date.0)
                .unwrap_or(0),
            in_saved_result: saved_search_uids.binary_search(uid).is_ok(),
            now,
            data: &data,
        };
        if parser::search_matches(criterion, &msg, selected.msgs.len()) {
            matches.push((idx as u64 + 1, *uid));
        }
    }
    Ok(matches)
}

async fn execute_sort(
    selected: &SelectedMailbox,
    request: &parser::SortRequest,
    saved_search_uids: &[u64],
) -> Result<Vec<sort::SortRecord>> {
    debug_assert!(request.charset == "UTF-8" || request.charset == "US-ASCII");
    let mut records = Vec::new();
    let now = chrono::Utc::now().timestamp();
    for (index, (uid, path, flags, _)) in selected.msgs.iter().enumerate() {
        let data = tokio::task::spawn_blocking({
            let path = path.clone();
            move || std::fs::read(path)
        })
        .await??;
        let internal_date = selected
            .internal_dates
            .get(uid)
            .map(|date| date.0)
            .unwrap_or(0);
        let message = parser::SearchMessage {
            seq: index + 1,
            uid: *uid,
            flags,
            internal_date,
            in_saved_result: saved_search_uids.binary_search(uid).is_ok(),
            now,
            data: &data,
        };
        if parser::search_matches(&request.search, &message, selected.msgs.len()) {
            records.push(sort::SortRecord::from_message(
                index as u64 + 1,
                *uid,
                internal_date,
                &data,
            ));
        }
    }
    records.sort_by(|left, right| sort::compare_records(left, right, &request.criteria));
    Ok(records)
}

async fn execute_thread(
    selected: &SelectedMailbox,
    request: &parser::ThreadRequest,
    saved_search_uids: &[u64],
) -> Result<Vec<thread::ThreadMessage>> {
    debug_assert!(request.charset == "UTF-8" || request.charset == "US-ASCII");
    let mut messages = Vec::new();
    let now = chrono::Utc::now().timestamp();
    for (index, (uid, path, flags, _)) in selected.msgs.iter().enumerate() {
        let data = tokio::task::spawn_blocking({
            let path = path.clone();
            move || std::fs::read(path)
        })
        .await??;
        let internal_date = selected
            .internal_dates
            .get(uid)
            .map(|date| date.0)
            .unwrap_or(0);
        let search_message = parser::SearchMessage {
            seq: index + 1,
            uid: *uid,
            flags,
            internal_date,
            in_saved_result: saved_search_uids.binary_search(uid).is_ok(),
            now,
            data: &data,
        };
        if parser::search_matches(&request.search, &search_message, selected.msgs.len()) {
            messages.push(thread::ThreadMessage::from_message(
                index as u64 + 1,
                *uid,
                internal_date,
                &data,
            ));
        }
    }
    Ok(messages)
}

fn compress_search_ids(ids: &[u64]) -> String {
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < ids.len() {
        let mut end = start;
        while end + 1 < ids.len() && ids[end + 1] == ids[end].saturating_add(1) {
            end += 1;
        }
        if start == end {
            ranges.push(ids[start].to_string());
        } else {
            ranges.push(format!("{}:{}", ids[start], ids[end]));
        }
        start = end + 1;
    }
    ranges.join(",")
}

fn search_result_response(
    tag: &str,
    uid_mode: bool,
    ids: &[u64],
    return_options: Option<&parser::SearchReturnOptions>,
) -> String {
    let Some(options) = return_options else {
        return format!(
            "* SEARCH {}\r\n",
            ids.iter().map(u64::to_string).collect::<Vec<_>>().join(" ")
        );
    };
    if options.save && !options.min && !options.max && !options.all && !options.count {
        return String::new();
    }
    let escaped_tag = tag.replace('\\', "\\\\").replace('"', "\\\"");
    let mut response = format!("* ESEARCH (TAG \"{}\")", escaped_tag);
    if uid_mode {
        response.push_str(" UID");
    }
    if options.min {
        if let Some(min) = ids.first() {
            response.push_str(&format!(" MIN {}", min));
        }
    }
    if options.max {
        if let Some(max) = ids.last() {
            response.push_str(&format!(" MAX {}", max));
        }
    }
    if options.all && !ids.is_empty() {
        response.push_str(&format!(" ALL {}", compress_search_ids(ids)));
    }
    if options.count {
        response.push_str(&format!(" COUNT {}", ids.len()));
    }
    response.push_str("\r\n");
    response
}

async fn sync_selected_mailbox(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    mail_root: &str,
    selected: &mut Option<SelectedMailbox>,
    qresync_enabled: bool,
) -> Result<()> {
    let Some(current) = selected.as_ref().cloned() else {
        return Ok(());
    };
    let (refreshed, events) = mailbox::refresh_selected_mailbox(mail_root, &current).await?;
    if !events.is_empty() {
        let w = reader.get_mut();
        for event in &events {
            w.write_all(event.response_line(qresync_enabled).as_bytes())
                .await?;
        }
        w.flush().await?;
    }
    *selected = Some(refreshed);
    Ok(())
}

async fn reload_selected_mailbox_preserving_mode(
    mail_root: &str,
    address: &str,
    mailbox_name: &str,
    previous: &Option<SelectedMailbox>,
) -> Result<SelectedMailbox> {
    let read_only = previous
        .as_ref()
        .map(|selected| selected.read_only)
        .unwrap_or(false);
    let mut refreshed = mailbox::load_selected_mailbox(mail_root, address, mailbox_name).await?;
    refreshed.read_only = read_only;
    Ok(refreshed)
}

fn command_preflight_response(
    command: &str,
    args: &str,
    authenticated: bool,
    selected: bool,
    encrypted: bool,
) -> Option<&'static str> {
    let spec = commands::command_spec(command, args)?;
    match spec.auth {
        commands::CommandAuth::Any => {}
        commands::CommandAuth::NotAuthenticated if authenticated => {
            return Some("BAD Command not allowed after authentication");
        }
        commands::CommandAuth::NotAuthenticated => {}
        commands::CommandAuth::Authenticated if !authenticated => {
            return Some("NO Authentication required");
        }
        commands::CommandAuth::Authenticated => {}
        commands::CommandAuth::Selected if !authenticated => {
            return Some("NO Authentication required");
        }
        commands::CommandAuth::Selected if !selected => return Some("BAD No mailbox selected"),
        commands::CommandAuth::Selected => {}
    }
    if spec.tls_required && !encrypted {
        return Some("NO Encryption required for authentication");
    }
    None
}

// session_encrypted indicates whether the current connection is protected by TLS (true for IMAPS
// and after a successful STARTTLS). Enforcing authentication methods (like LOGIN) only on
// encrypted sessions prevents accidental credential disclosure over plain-text.
// session_encrypted indicates whether the current connection is protected by TLS (true for IMAPS
// and after a successful STARTTLS). `peer` is the remote socket address of the client and is used
// for per-IP rate-limiting of authentication attempts.
async fn process_stream(
    stream: Box<dyn RawStream + Send + 'static>,
    mail_root: String,
    tls_ctx: Option<Arc<tls::TlsContext>>,
    db_path: Option<String>,
    peer: Option<SocketAddr>,
    session_encrypted: bool,
) -> Result<()> {
    process_stream_inner(
        stream,
        mail_root,
        tls_ctx,
        db_path,
        peer,
        session_encrypted,
        true,
    )
    .await
}

async fn process_stream_inner(
    stream: Box<dyn RawStream + Send + 'static>,
    mail_root: String,
    tls_ctx: Option<Arc<tls::TlsContext>>,
    db_path: Option<String>,
    peer: Option<SocketAddr>,
    session_encrypted: bool,
    send_greeting: bool,
) -> Result<()> {
    let stream: Box<dyn AsyncStream + Send + 'static> = Box::new(SwitchableStream::new(stream));
    let mut reader = BufReader::new(stream);
    println!(
        "Starting IMAP session peer={:?} encrypted={} tls_configured={}",
        peer,
        session_encrypted,
        tls_ctx.is_some()
    );
    if send_greeting {
        let w = reader.get_mut();
        let phase = if session_encrypted {
            response::CapabilityPhase::NotAuthenticatedTls
        } else {
            response::CapabilityPhase::NotAuthenticatedPlain
        };
        let caps = response::capability_tokens(phase, tls_ctx.is_some());
        println!(
            "Greeting peer={:?} encrypted={} capabilities={}",
            peer, session_encrypted, caps
        );
        w.write_all(response::greeting(&caps).as_bytes()).await?;
        w.flush().await?;
    }
    let mut session_state = state::SessionState::default();
    let mut authed_mailbox: Option<String> = None; // store address lowercase
    // current mailbox selection state (set by SELECT)
    let mut selected: Option<SelectedMailbox> = None;

    loop {
        let line_limit = if session_state.authenticated_mailbox.is_some() {
            MAX_AUTHENTICATED_LINE_BYTES
        } else {
            MAX_PREAUTH_LINE_BYTES
        };
        let mut line = match read_bounded_line(&mut reader, line_limit).await {
            Ok(BoundedLine::Line(line)) => line,
            Ok(BoundedLine::Eof) => {
                println!(
                    "IMAP session peer={:?} encrypted={} closed by client",
                    peer, session_encrypted
                );
                break;
            }
            Ok(BoundedLine::TooLong) => {
                let w = reader.get_mut();
                w.write_all(b"* BAD Command line too long\r\n").await?;
                w.flush().await?;
                continue;
            }
            Err(e) => {
                if e.kind() == ErrorKind::UnexpectedEof {
                    println!(
                        "IMAP session peer={:?} encrypted={} closed by client without TLS close_notify",
                        peer, session_encrypted
                    );
                    break;
                }
                eprintln!(
                    "IMAP read error peer={:?} encrypted={} err={}",
                    peer, session_encrypted, e
                );
                return Err(e.into());
            }
        };
        let is_append = std::str::from_utf8(&line)
            .ok()
            .and_then(|line| line.split_ascii_whitespace().nth(1))
            .is_some_and(|command| command.eq_ignore_ascii_case("APPEND"));
        if !is_append && trailing_literal_marker(&line).is_some() {
            line = match read_textual_command_literals(&mut reader, line, line_limit).await {
                Ok(line) => line,
                Err(CommandLiteralError::Eof) => break,
                Err(CommandLiteralError::NonSyncLiteral8) => {
                    let w = reader.get_mut();
                    w.write_all(
                        b"* BYE Non-synchronizing literal8 desynchronized command stream\r\n",
                    )
                    .await?;
                    w.flush().await?;
                    break;
                }
                Err(CommandLiteralError::TooLarge) => {
                    let w = reader.get_mut();
                    w.write_all(b"* BAD Command literal too large\r\n").await?;
                    w.flush().await?;
                    continue;
                }
                Err(CommandLiteralError::Literal8) => {
                    let w = reader.get_mut();
                    w.write_all(b"* BAD Literal8 is not valid for this command\r\n")
                        .await?;
                    w.flush().await?;
                    continue;
                }
                Err(CommandLiteralError::InvalidUtf8) => {
                    let w = reader.get_mut();
                    w.write_all(b"* BAD Textual command literal is not valid UTF-8\r\n")
                        .await?;
                    w.flush().await?;
                    continue;
                }
                Err(CommandLiteralError::Io) => return Err(anyhow!("command literal read error")),
            };
        }
        let input = match std::str::from_utf8(&line) {
            Ok(input) => input.trim_end_matches(['\r', '\n']),
            Err(_) => {
                let w = reader.get_mut();
                w.write_all(b"* BAD Command line is not valid UTF-8\r\n")
                    .await?;
                w.flush().await?;
                continue;
            }
        };
        if input.is_empty() {
            continue;
        }
        let request = match parser::parse_request_line(input) {
            Ok(request) => request,
            Err(error) => {
                let candidate_tag = input
                    .split(|ch: char| ch == ' ' || ch == '\t')
                    .next()
                    .filter(|tag| parser::valid_tag(tag));
                let response_tag = candidate_tag.unwrap_or("*");
                let w = reader.get_mut();
                w.write_all(
                    format!(
                        "{} BAD Invalid command framing: {:?}\r\n",
                        response_tag, error
                    )
                    .as_bytes(),
                )
                .await?;
                w.flush().await?;
                continue;
            }
        };
        let tag = request.tag;
        let cmd = request.command_name().to_string();
        let args = request.raw_args();
        println!(
            "IMAP peer={:?} encrypted={} tag={} cmd={} args={:?} authed={} selected={}",
            peer,
            session_encrypted,
            tag,
            cmd,
            args,
            session_state.authenticated_mailbox.is_some(),
            session_state.selected_mailbox.is_some()
        );
        if let Some(reason) = command_preflight_response(
            &cmd,
            args,
            session_state.authenticated_mailbox.is_some(),
            session_state.selected_mailbox.is_some(),
            session_encrypted,
        ) {
            let w = reader.get_mut();
            w.write_all(format!("{} {}\r\n", tag, reason).as_bytes())
                .await?;
            w.flush().await?;
            continue;
        }
        match cmd.as_str() {
            "CAPABILITY" => {
                let w = reader.get_mut();
                let phase = if session_state.selected_mailbox.is_some() {
                    response::CapabilityPhase::Selected
                } else if session_state.authenticated_mailbox.is_some() {
                    response::CapabilityPhase::Authenticated
                } else if session_encrypted {
                    response::CapabilityPhase::NotAuthenticatedTls
                } else {
                    response::CapabilityPhase::NotAuthenticatedPlain
                };
                let caps = response::capability_tokens(phase, tls_ctx.is_some());
                let response = response::capability_response(tag, &caps);
                log_imap_response(peer, tag, &cmd, &response);
                w.write_all(response.as_bytes()).await?;
                w.flush().await?;
            }
            "COMPRESS" => {
                if !args.eq_ignore_ascii_case("DEFLATE") {
                    let w = reader.get_mut();
                    w.write_all(
                        format!("{} NO Unsupported compression mechanism\r\n", tag).as_bytes(),
                    )
                    .await?;
                    w.flush().await?;
                    continue;
                }
                if reader.get_ref().compression_active() {
                    let w = reader.get_mut();
                    w.write_all(
                        format!(
                            "{} NO [COMPRESSIONACTIVE] DEFLATE compression already enabled\r\n",
                            tag
                        )
                        .as_bytes(),
                    )
                    .await?;
                    w.flush().await?;
                    continue;
                }
                if !reader.buffer().is_empty() {
                    let w = reader.get_mut();
                    w.write_all(
                        format!(
                            "{} BAD Client did not wait for COMPRESS reply before sending more data\r\n",
                            tag
                        )
                        .as_bytes(),
                    )
                    .await?;
                    w.flush().await?;
                    continue;
                }
                {
                    let w = reader.get_mut();
                    w.write_all(format!("{} OK Begin compression\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    w.enable_deflate()?;
                }
            }
            "LOGIN" => {
                // Rate-limiting: block repeated failures per remote IP
                if let Some(peer_addr) = peer {
                    if let Some(rem) = auth::auth_block_remaining(peer_addr.ip()) {
                        let w = reader.get_mut();
                        w.write_all(
                            format!(
                                "{} NO Too many failed auth attempts; try again in {}s\r\n",
                                tag,
                                rem.as_secs()
                            )
                            .as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    }
                }
                // Require an encrypted session for LOGIN to avoid sending cleartext passwords
                if !session_encrypted {
                    let w = reader.get_mut();
                    w.write_all(
                        format!("{} NO Encryption required for authentication\r\n", tag).as_bytes(),
                    )
                    .await?;
                    w.flush().await?;
                    continue;
                }
                let (user, pass) = match parser::parse_login_args(args) {
                    Ok(parsed) => parsed,
                    Err(err) => {
                        let w = reader.get_mut();
                        w.write_all(
                            format!("{} BAD Invalid LOGIN arguments: {:?}\r\n", tag, err)
                                .as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                println!(
                    "IMAP LOGIN attempt peer={:?} encrypted={} user={:?} password_len={}",
                    peer,
                    session_encrypted,
                    user,
                    pass.len()
                );
                match authenticate_password(db_path.as_ref(), &user, &pass).await {
                    PasswordAuthResult::Success(mailbox) => {
                        authed_mailbox = Some(mailbox.address.to_ascii_lowercase());
                        session_state.authenticated_mailbox = authed_mailbox.clone();
                        println!(
                            "IMAP LOGIN success peer={:?} mailbox={}",
                            peer, mailbox.address
                        );
                        if let Some(peer_addr) = peer {
                            auth::reset_auth_failures(peer_addr.ip());
                        }
                        let w = reader.get_mut();
                        let response = format!("{} OK LOGIN completed\r\n", tag);
                        log_imap_response(peer, tag, &cmd, &response);
                        w.write_all(response.as_bytes()).await?;
                        w.flush().await?;
                    }
                    PasswordAuthResult::NoSuchUser => {
                        println!(
                            "IMAP LOGIN user lookup failed peer={:?} user={:?}",
                            peer, user
                        );
                        if let Some(peer_addr) = peer {
                            auth::record_auth_failure(peer_addr.ip());
                        }
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO No such user\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                    PasswordAuthResult::NoPassword => {
                        let w = reader.get_mut();
                        w.write_all(
                            format!("{} NO No password set for account\r\n", tag).as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                    }
                    PasswordAuthResult::BadPassword(mailbox) => {
                        println!(
                            "IMAP LOGIN bad password peer={:?} mailbox={}",
                            peer, mailbox.address
                        );
                        if let Some(peer_addr) = peer {
                            auth::record_auth_failure(peer_addr.ip());
                        }
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO Authentication failed\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                    PasswordAuthResult::Error { mailbox, message } => {
                        eprintln!(
                            "IMAP LOGIN auth verify error peer={:?} mailbox={} err={}",
                            peer,
                            mailbox.as_ref().map(|m| m.address.as_str()).unwrap_or("-"),
                            message
                        );
                        if let Some(peer_addr) = peer {
                            auth::record_auth_failure(peer_addr.ip());
                        }
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO Authentication error\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                }
            }
            "AUTHENTICATE" => {
                let (mechanism, initial_response) = match parser::parse_authenticate_args(args) {
                    Ok(parsed) => parsed,
                    Err(err) => {
                        let w = reader.get_mut();
                        w.write_all(
                            format!("{} BAD Invalid AUTHENTICATE arguments: {:?}\r\n", tag, err)
                                .as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                let Some(mechanism_metadata) = auth::sasl_mechanism(&mechanism) else {
                    let w = reader.get_mut();
                    w.write_all(
                        format!("{} NO Unsupported authentication mechanism\r\n", tag).as_bytes(),
                    )
                    .await?;
                    w.flush().await?;
                    continue;
                };
                if let Some(peer_addr) = peer {
                    if let Some(rem) = auth::auth_block_remaining(peer_addr.ip()) {
                        let w = reader.get_mut();
                        w.write_all(
                            format!(
                                "{} NO Too many failed auth attempts; try again in {}s\r\n",
                                tag,
                                rem.as_secs()
                            )
                            .as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    }
                }
                if !session_encrypted
                    && mechanism_metadata.security == auth::SaslSecurity::PlaintextPassword
                {
                    let w = reader.get_mut();
                    w.write_all(
                        format!("{} NO Encryption required for authentication\r\n", tag).as_bytes(),
                    )
                    .await?;
                    w.flush().await?;
                    continue;
                }
                if mechanism_metadata.channel_binding_required
                    && (!session_encrypted || tls_ctx.is_none())
                {
                    let w = reader.get_mut();
                    w.write_all(
                        format!("{} NO Channel binding is not available\r\n", tag).as_bytes(),
                    )
                    .await?;
                    w.flush().await?;
                    continue;
                }
                if mechanism == "LOGIN" {
                    let mut exchange = auth::LoginExchange::default();
                    let credentials = match run_password_sasl_exchange(
                        &mut reader,
                        &mut exchange,
                        initial_response.as_deref(),
                    )
                    .await
                    {
                        Ok(credentials) => credentials,
                        Err(SaslProtocolError::Eof) => return Ok(()),
                        Err(SaslProtocolError::Cancelled) => {
                            let w = reader.get_mut();
                            w.write_all(
                                format!("{} BAD AUTHENTICATE cancelled\r\n", tag).as_bytes(),
                            )
                            .await?;
                            w.flush().await?;
                            continue;
                        }
                        Err(SaslProtocolError::ResponseTooLarge) => {
                            let w = reader.get_mut();
                            w.write_all(
                                format!("{} BAD AUTHENTICATE response too large\r\n", tag)
                                    .as_bytes(),
                            )
                            .await?;
                            w.flush().await?;
                            continue;
                        }
                        Err(SaslProtocolError::InvalidResponse) => {
                            let w = reader.get_mut();
                            w.write_all(
                                format!("{} BAD Invalid AUTHENTICATE LOGIN response\r\n", tag)
                                    .as_bytes(),
                            )
                            .await?;
                            w.flush().await?;
                            continue;
                        }
                    };
                    let user = credentials.authcid;
                    let pass = credentials.password;
                    println!(
                        "IMAP AUTHENTICATE LOGIN attempt peer={:?} encrypted={} user={:?} password_len={}",
                        peer,
                        session_encrypted,
                        user,
                        pass.len()
                    );
                    match authenticate_password(db_path.as_ref(), &user, &pass).await {
                        PasswordAuthResult::Success(mailbox) => {
                            authed_mailbox = Some(mailbox.address.to_ascii_lowercase());
                            session_state.authenticated_mailbox = authed_mailbox.clone();
                            if let Some(peer_addr) = peer {
                                auth::reset_auth_failures(peer_addr.ip());
                            }
                            let w = reader.get_mut();
                            w.write_all(
                                format!("{} OK AUTHENTICATE completed\r\n", tag).as_bytes(),
                            )
                            .await?;
                            w.flush().await?;
                        }
                        PasswordAuthResult::NoSuchUser | PasswordAuthResult::BadPassword(_) => {
                            if let Some(peer_addr) = peer {
                                auth::record_auth_failure(peer_addr.ip());
                            }
                            let w = reader.get_mut();
                            w.write_all(format!("{} NO Authentication failed\r\n", tag).as_bytes())
                                .await?;
                            w.flush().await?;
                        }
                        PasswordAuthResult::NoPassword => {
                            let w = reader.get_mut();
                            w.write_all(
                                format!("{} NO No password set for account\r\n", tag).as_bytes(),
                            )
                            .await?;
                            w.flush().await?;
                        }
                        PasswordAuthResult::Error { mailbox, message } => {
                            if let Some(peer_addr) = peer {
                                auth::record_auth_failure(peer_addr.ip());
                            }
                            eprintln!(
                                "IMAP AUTHENTICATE LOGIN verify error peer={:?} mailbox={} err={}",
                                peer,
                                mailbox.as_ref().map(|m| m.address.as_str()).unwrap_or("-"),
                                message
                            );
                            let w = reader.get_mut();
                            w.write_all(format!("{} NO Authentication error\r\n", tag).as_bytes())
                                .await?;
                            w.flush().await?;
                        }
                    }
                    continue;
                }
                let plain_credentials = if mechanism == "PLAIN" {
                    let mut exchange = auth::PlainExchange::default();
                    match run_password_sasl_exchange(
                        &mut reader,
                        &mut exchange,
                        initial_response.as_deref(),
                    )
                    .await
                    {
                        Ok(credentials) => Some(credentials),
                        Err(SaslProtocolError::Eof) => return Ok(()),
                        Err(error) => {
                            let (status, message) = match error {
                                SaslProtocolError::Cancelled => ("BAD", "AUTHENTICATE cancelled"),
                                SaslProtocolError::ResponseTooLarge => {
                                    ("BAD", "AUTHENTICATE response too large")
                                }
                                SaslProtocolError::InvalidResponse => {
                                    ("BAD", "Invalid AUTHENTICATE PLAIN response")
                                }
                                SaslProtocolError::Eof => unreachable!(),
                            };
                            let w = reader.get_mut();
                            w.write_all(format!("{} {} {}\r\n", tag, status, message).as_bytes())
                                .await?;
                            w.flush().await?;
                            continue;
                        }
                    }
                } else {
                    None
                };
                let response = if plain_credentials.is_some() {
                    String::new()
                } else if let Some(initial_response) = initial_response {
                    initial_response
                } else {
                    {
                        let w = reader.get_mut();
                        w.write_all(b"+ \r\n").await?;
                        w.flush().await?;
                    }
                    match read_sasl_wire_response(&mut reader).await {
                        Ok(line) => line,
                        Err(SaslProtocolError::Eof) => return Ok(()),
                        Err(SaslProtocolError::Cancelled) => {
                            let w = reader.get_mut();
                            w.write_all(
                                format!("{} BAD AUTHENTICATE cancelled\r\n", tag).as_bytes(),
                            )
                            .await?;
                            w.flush().await?;
                            continue;
                        }
                        Err(SaslProtocolError::ResponseTooLarge) => {
                            let w = reader.get_mut();
                            w.write_all(
                                format!("{} BAD AUTHENTICATE response too large\r\n", tag)
                                    .as_bytes(),
                            )
                            .await?;
                            w.flush().await?;
                            continue;
                        }
                        Err(SaslProtocolError::InvalidResponse) => {
                            let w = reader.get_mut();
                            w.write_all(
                                format!("{} BAD Invalid AUTHENTICATE response\r\n", tag).as_bytes(),
                            )
                            .await?;
                            w.flush().await?;
                            continue;
                        }
                    }
                };
                if mechanism == "SCRAM-SHA-256" || mechanism == "SCRAM-SHA-256-PLUS" {
                    let mut scram_exchange =
                        auth::ScramExchange::new(mechanism_metadata.channel_binding_required);
                    let client_first =
                        match auth::SaslExchange::start(&mut scram_exchange, Some(&response)) {
                            Ok(auth::SaslProgress::ScramClientFirst(first)) => first,
                            _ => {
                                let w = reader.get_mut();
                                w.write_all(
                                    format!("{} BAD Invalid SCRAM client-first message\r\n", tag)
                                        .as_bytes(),
                                )
                                .await?;
                                w.flush().await?;
                                continue;
                            }
                        };
                    let user_lookup =
                        common_auth::saslprep(&client_first.username).to_ascii_lowercase();
                    if client_first.authzid.as_ref().is_some_and(|authzid| {
                        common_auth::saslprep(authzid).to_ascii_lowercase() != user_lookup
                    }) {
                        let w = reader.get_mut();
                        w.write_all(
                            format!("{} NO Authorization identity is not permitted\r\n", tag)
                                .as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    }
                    let mut mb: Option<Mailbox> = None;
                    if let Some(dbp) = db_path.as_ref() {
                        let dbp2 = dbp.clone();
                        if user_lookup.contains('@') {
                            match tokio::task::spawn_blocking(move || {
                                rmail_common::db::get_mailbox(dbp2, &user_lookup)
                            })
                            .await
                            {
                                Ok(Ok(Some(m))) => mb = Some(m),
                                Ok(Ok(None)) => {}
                                Ok(Err(e)) => eprintln!("db get_mailbox error: {}", e),
                                Err(e) => eprintln!("db task join error: {}", e),
                            }
                        } else {
                            match tokio::task::spawn_blocking(move || {
                                rmail_common::db::find_mailbox_by_localpart(dbp2, &user_lookup)
                            })
                            .await
                            {
                                Ok(Ok(Some(m))) => mb = Some(m),
                                Ok(Ok(None)) => {}
                                Ok(Err(e)) => eprintln!("db query error: {}", e),
                                Err(e) => eprintln!("db task join error: {}", e),
                            }
                        }
                    }
                    let Some(mailbox) = mb else {
                        if let Some(peer_addr) = peer {
                            auth::record_auth_failure(peer_addr.ip());
                        }
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO Authentication failed\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    };
                    let Some(scram_json) = mailbox.scram.as_ref() else {
                        if let Some(peer_addr) = peer {
                            auth::record_auth_failure(peer_addr.ip());
                        }
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO Authentication failed\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    };
                    let (salt_b64, iterations) = match common_auth::parse_scram_verifier(scram_json)
                    {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!(
                                "IMAP SCRAM verifier parse error peer={:?} mailbox={} err={}",
                                peer, mailbox.address, e
                            );
                            let w = reader.get_mut();
                            w.write_all(format!("{} NO Authentication error\r\n", tag).as_bytes())
                                .await?;
                            w.flush().await?;
                            continue;
                        }
                    };
                    let combined_nonce =
                        format!("{}{}", client_first.nonce, generate_scram_nonce());
                    let server_first =
                        format!("r={},s={},i={}", combined_nonce, salt_b64, iterations);
                    let server_first_b64 = BASE64_ENGINE.encode(server_first.as_bytes());
                    {
                        let w = reader.get_mut();
                        w.write_all(format!("+ {}\r\n", server_first_b64).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                    let final_line = match read_sasl_wire_response(&mut reader).await {
                        Ok(line) => line,
                        Err(SaslProtocolError::Eof) => return Ok(()),
                        Err(SaslProtocolError::Cancelled) => {
                            let w = reader.get_mut();
                            w.write_all(
                                format!("{} BAD AUTHENTICATE cancelled\r\n", tag).as_bytes(),
                            )
                            .await?;
                            w.flush().await?;
                            continue;
                        }
                        Err(SaslProtocolError::ResponseTooLarge) => {
                            let w = reader.get_mut();
                            w.write_all(
                                format!("{} BAD AUTHENTICATE response too large\r\n", tag)
                                    .as_bytes(),
                            )
                            .await?;
                            w.flush().await?;
                            continue;
                        }
                        Err(SaslProtocolError::InvalidResponse) => {
                            let w = reader.get_mut();
                            w.write_all(
                                format!("{} BAD Invalid SCRAM client-final response\r\n", tag)
                                    .as_bytes(),
                            )
                            .await?;
                            w.flush().await?;
                            continue;
                        }
                    };
                    let client_final =
                        match auth::SaslExchange::receive(&mut scram_exchange, &final_line) {
                            Ok(auth::SaslProgress::ScramClientFinal(final_message)) => {
                                final_message
                            }
                            _ => {
                                let w = reader.get_mut();
                                w.write_all(
                                    format!("{} BAD Invalid SCRAM client-final message\r\n", tag)
                                        .as_bytes(),
                                )
                                .await?;
                                w.flush().await?;
                                continue;
                            }
                        };
                    let channel_binding_valid = if mechanism_metadata.channel_binding_required {
                        common_auth::verify_tls_server_end_point_binding(
                            &client_first.gs2_header,
                            &tls_ctx
                                .as_ref()
                                .expect("checked TLS context")
                                .server_end_point,
                            &client_final.channel_binding,
                        )
                        .is_ok()
                    } else {
                        client_final.channel_binding
                            == BASE64_ENGINE.encode(client_first.gs2_header.as_bytes())
                    };
                    if client_final.nonce != combined_nonce || !channel_binding_valid {
                        if let Some(peer_addr) = peer {
                            auth::record_auth_failure(peer_addr.ip());
                        }
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO Authentication failed\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                    let auth_message = format!(
                        "{},{},{}",
                        client_first.bare, server_first, client_final.without_proof
                    );
                    match common_auth::verify_scram_proof(
                        scram_json,
                        &auth_message,
                        &client_final.proof,
                    ) {
                        Ok(server_signature) => {
                            let server_final =
                                format!("v={}", BASE64_ENGINE.encode(server_signature));
                            let server_final_b64 = BASE64_ENGINE.encode(server_final.as_bytes());
                            {
                                let w = reader.get_mut();
                                w.write_all(format!("+ {}\r\n", server_final_b64).as_bytes())
                                    .await?;
                                w.flush().await?;
                            }
                            auth::ScramExchange::expect_final_acknowledgment(&mut scram_exchange)
                                .map_err(|_| anyhow!("invalid SCRAM exchange state"))?;
                            let acknowledgment = match read_sasl_wire_response(&mut reader).await {
                                Ok(line) => line,
                                Err(SaslProtocolError::Eof) => return Ok(()),
                                Err(SaslProtocolError::Cancelled) => {
                                    let w = reader.get_mut();
                                    w.write_all(
                                        format!("{} BAD AUTHENTICATE cancelled\r\n", tag)
                                            .as_bytes(),
                                    )
                                    .await?;
                                    w.flush().await?;
                                    continue;
                                }
                                Err(_) => {
                                    let w = reader.get_mut();
                                    w.write_all(
                                        format!(
                                            "{} BAD Invalid SCRAM final acknowledgment\r\n",
                                            tag
                                        )
                                        .as_bytes(),
                                    )
                                    .await?;
                                    w.flush().await?;
                                    continue;
                                }
                            };
                            if !matches!(
                                auth::SaslExchange::receive(&mut scram_exchange, &acknowledgment,),
                                Ok(auth::SaslProgress::Complete)
                            ) {
                                let w = reader.get_mut();
                                w.write_all(
                                    format!("{} BAD Invalid SCRAM final acknowledgment\r\n", tag)
                                        .as_bytes(),
                                )
                                .await?;
                                w.flush().await?;
                                continue;
                            }
                            authed_mailbox = Some(mailbox.address.to_ascii_lowercase());
                            session_state.authenticated_mailbox = authed_mailbox.clone();
                            if let Some(peer_addr) = peer {
                                auth::reset_auth_failures(peer_addr.ip());
                            }
                            let w = reader.get_mut();
                            w.write_all(
                                format!("{} OK AUTHENTICATE completed\r\n", tag).as_bytes(),
                            )
                            .await?;
                            w.flush().await?;
                        }
                        Err(e) => {
                            if let Some(peer_addr) = peer {
                                auth::record_auth_failure(peer_addr.ip());
                            }
                            eprintln!(
                                "IMAP SCRAM verify error peer={:?} mailbox={} err={}",
                                peer, mailbox.address, e
                            );
                            let w = reader.get_mut();
                            w.write_all(format!("{} NO Authentication failed\r\n", tag).as_bytes())
                                .await?;
                            w.flush().await?;
                        }
                    }
                    continue;
                }
                let credentials = plain_credentials.expect("non-SCRAM mechanism is PLAIN");
                let user = credentials.authcid;
                if credentials.authzid.as_ref().is_some_and(|authzid| {
                    common_auth::saslprep(authzid).to_ascii_lowercase()
                        != common_auth::saslprep(&user).to_ascii_lowercase()
                }) {
                    let w = reader.get_mut();
                    w.write_all(
                        format!("{} NO Authorization identity is not permitted\r\n", tag)
                            .as_bytes(),
                    )
                    .await?;
                    w.flush().await?;
                    continue;
                }
                let pass = credentials.password;
                println!(
                    "IMAP AUTHENTICATE PLAIN attempt peer={:?} encrypted={} user={:?} password_len={}",
                    peer,
                    session_encrypted,
                    user,
                    pass.len()
                );
                match authenticate_password(db_path.as_ref(), &user, &pass).await {
                    PasswordAuthResult::Success(mailbox) => {
                        authed_mailbox = Some(mailbox.address.to_ascii_lowercase());
                        session_state.authenticated_mailbox = authed_mailbox.clone();
                        if let Some(peer_addr) = peer {
                            auth::reset_auth_failures(peer_addr.ip());
                        }
                        let w = reader.get_mut();
                        w.write_all(format!("{} OK AUTHENTICATE completed\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                    PasswordAuthResult::NoSuchUser | PasswordAuthResult::BadPassword(_) => {
                        if let Some(peer_addr) = peer {
                            auth::record_auth_failure(peer_addr.ip());
                        }
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO Authentication failed\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                    PasswordAuthResult::NoPassword => {
                        let w = reader.get_mut();
                        w.write_all(
                            format!("{} NO No password set for account\r\n", tag).as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                    }
                    PasswordAuthResult::Error { mailbox, message } => {
                        if let Some(peer_addr) = peer {
                            auth::record_auth_failure(peer_addr.ip());
                        }
                        eprintln!(
                            "IMAP AUTHENTICATE PLAIN verify error peer={:?} mailbox={} err={}",
                            peer,
                            mailbox.as_ref().map(|m| m.address.as_str()).unwrap_or("-"),
                            message
                        );
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO Authentication error\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                }
            }
            "NOOP" => {
                sync_selected_mailbox(
                    &mut reader,
                    &mail_root,
                    &mut selected,
                    session_state.feature_enabled("QRESYNC"),
                )
                .await?;
                let w = reader.get_mut();
                w.write_all(format!("{} OK NOOP completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "CHECK" => {
                if selected.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                sync_selected_mailbox(
                    &mut reader,
                    &mail_root,
                    &mut selected,
                    session_state.feature_enabled("QRESYNC"),
                )
                .await?;
                let w = reader.get_mut();
                w.write_all(format!("{} OK CHECK completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "UNSELECT" => {
                if selected.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                selected = None;
                session_state.selected_mailbox = None;
                let w = reader.get_mut();
                w.write_all(format!("{} OK UNSELECT completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "APPEND" => {
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let append_request = match parse_append_args(args) {
                    Ok(request) => request,
                    Err(parser::ParseError::InvalidDateTime) => {
                        let w = reader.get_mut();
                        w.write_all(
                            format!("{} BAD Invalid APPEND internal date\r\n", tag).as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    }
                    Err(_) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD Invalid APPEND arguments\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                if append_request.utf8 && !session_state.feature_enabled("UTF8=ACCEPT") {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD UTF8=ACCEPT is not enabled\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                if append_request.literal_len > MAX_APPEND_LITERAL_BYTES {
                    let w = reader.get_mut();
                    w.write_all(
                        format!("{} NO [TOOBIG] APPEND literal too large\r\n", tag).as_bytes(),
                    )
                    .await?;
                    w.flush().await?;
                    continue;
                }
                if !append_request.non_sync {
                    let w = reader.get_mut();
                    w.write_all(b"+ Ready for literal data\r\n").await?;
                    w.flush().await?;
                }
                let mut literal = vec![0u8; append_request.literal_len];
                if let Err(e) = reader.read_exact(&mut literal).await {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Error reading literal\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    eprintln!("IMAP APPEND literal read error peer={:?}: {}", peer, e);
                    continue;
                }
                if append_request.utf8 && std::str::from_utf8(&literal).is_err() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO [UTF8] Invalid UTF-8 message\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let addr = authed_mailbox.as_ref().unwrap();
                let (local, domain) = address_parts(addr)?;
                let mail_root_clone = mail_root.clone();
                let mailbox_name = match decode_imap_mailbox_arg(
                    &append_request.mailbox,
                    session_state.feature_enabled("UTF8=ACCEPT"),
                ) {
                    Ok(name) => name,
                    Err(_) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD Invalid mailbox name\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                let mailbox_for_task = mailbox_name.clone();
                let flags = append_request.flags;
                const INTERNALDATE_MAX_FUTURE_SECONDS: i64 = 2 * 60 * 60;
                let internal_date = append_request
                    .internal_date
                    .filter(|date| {
                        date.timestamp
                            <= chrono::Utc::now().timestamp() + INTERNALDATE_MAX_FUTURE_SECONDS
                    })
                    .map(|date| (date.timestamp, date.timezone_offset_minutes));
                let append_result = tokio::task::spawn_blocking(move || {
                    rmail_common::imap_state::append_message_with_internal_date(
                        Path::new(&mail_root_clone),
                        &domain,
                        &local,
                        &mailbox_for_task,
                        &literal,
                        flags,
                        internal_date,
                    )
                })
                .await?;
                match append_result {
                    Ok((uidvalidity, uid)) => {
                        if let Some(addr) = authed_mailbox.as_ref() {
                            if selected
                                .as_ref()
                                .map(|sel| sel.mailbox.eq_ignore_ascii_case(&mailbox_name))
                                .unwrap_or(false)
                            {
                                selected = Some(
                                    reload_selected_mailbox_preserving_mode(
                                        &mail_root,
                                        addr,
                                        &mailbox_name,
                                        &selected,
                                    )
                                    .await?,
                                );
                            }
                        }
                        let w = reader.get_mut();
                        w.write_all(
                            format!(
                                "{} OK [APPENDUID {} {}] APPEND completed\r\n",
                                tag, uidvalidity, uid
                            )
                            .as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                    }
                    Err(e) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO APPEND failed: {}\r\n", tag, e).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                }
            }
            "LIST" | "XLIST" => {
                // Require authentication to list user's mailboxes in this simple implementation
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let utf8_accept = session_state.feature_enabled("UTF8=ACCEPT");
                let request = match parser::parse_list_request(args, false).and_then(|request| {
                    decode_list_request(request, utf8_accept)
                        .map_err(|_| parser::ParseError::InvalidAtom)
                }) {
                    Ok(request) => request,
                    Err(err) => {
                        let w = reader.get_mut();
                        w.write_all(
                            format!("{} BAD Invalid {} arguments: {:?}\r\n", tag, cmd, err)
                                .as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                let addr = authed_mailbox.as_ref().unwrap();
                let (local, domain) = address_parts(addr)?;
                let mail_root_clone = mail_root.clone();
                let summaries = tokio::task::spawn_blocking(move || {
                    rmail_common::imap_state::list_folder_summaries(
                        Path::new(&mail_root_clone),
                        &domain,
                        &local,
                    )
                })
                .await??;
                println!(
                    "IMAP {} peer={:?} returning {} mailboxes extended={}",
                    cmd,
                    peer,
                    summaries.len(),
                    request.extended
                );
                let w = reader.get_mut();
                let mut response = String::new();
                if !request.extended
                    && request.reference.is_empty()
                    && request.patterns.iter().any(|pattern| pattern.is_empty())
                {
                    response.push_str("* LIST (\\Noselect \\HasChildren) \"/\" \"\"\r\n");
                }
                for summary in &summaries {
                    if request.selection.subscribed && !summary.folder.subscribed {
                        continue;
                    }
                    if request.selection.special_use && summary.folder.special_use.is_none() {
                        continue;
                    }
                    if !request.patterns.iter().any(|pattern| {
                        mailbox_pattern_matches(&summary.folder.name, &request.reference, pattern)
                    }) {
                        continue;
                    }
                    append_list_response(
                        &mut response,
                        &cmd,
                        &request,
                        summary,
                        &summaries,
                        utf8_accept,
                    );
                }
                response.push_str(&format!("{} OK {} completed\r\n", tag, cmd));
                log_imap_response(peer, tag, &cmd, &response);
                w.write_all(response.as_bytes()).await?;
                w.flush().await?;
            }
            "LSUB" => {
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let utf8_accept = session_state.feature_enabled("UTF8=ACCEPT");
                let request = match parser::parse_list_request(args, true).and_then(|request| {
                    decode_list_request(request, utf8_accept)
                        .map_err(|_| parser::ParseError::InvalidAtom)
                }) {
                    Ok(request) => request,
                    Err(err) => {
                        let w = reader.get_mut();
                        w.write_all(
                            format!("{} BAD Invalid LSUB arguments: {:?}\r\n", tag, err).as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                let addr = authed_mailbox.as_ref().unwrap();
                let (local, domain) = address_parts(addr)?;
                let mail_root_clone = mail_root.clone();
                let summaries = tokio::task::spawn_blocking(move || {
                    rmail_common::imap_state::list_folder_summaries(
                        Path::new(&mail_root_clone),
                        &domain,
                        &local,
                    )
                })
                .await??;
                println!("IMAP LSUB peer={:?} returning subscriptions", peer);
                let w = reader.get_mut();
                let mut response = String::new();
                for summary in &summaries {
                    if !summary.folder.subscribed {
                        continue;
                    }
                    if !request.patterns.iter().any(|pattern| {
                        mailbox_pattern_matches(&summary.folder.name, &request.reference, pattern)
                    }) {
                        continue;
                    }
                    append_list_response(
                        &mut response,
                        "LSUB",
                        &request,
                        summary,
                        &summaries,
                        utf8_accept,
                    );
                }
                response.push_str(&format!("{} OK LSUB completed\r\n", tag));
                log_imap_response(peer, tag, "LSUB", &response);
                w.write_all(response.as_bytes()).await?;
                w.flush().await?;
            }
            "NAMESPACE" => {
                println!("IMAP NAMESPACE peer={:?}", peer);
                let w = reader.get_mut();
                let response = response::namespace_response(tag);
                log_imap_response(peer, tag, &cmd, &response);
                w.write_all(response.as_bytes()).await?;
                w.flush().await?;
            }
            "ENABLE" => {
                let args = match parser::parse_imap_args(args) {
                    Ok(args) => args,
                    Err(err) => {
                        let w = reader.get_mut();
                        w.write_all(
                            format!("{} BAD Invalid ENABLE arguments: {:?}\r\n", tag, err)
                                .as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                let mut newly_enabled = Vec::new();
                let mut invalid_args = false;
                for arg in args {
                    let Some(feature) = arg.as_text() else {
                        invalid_args = true;
                        break;
                    };
                    if session_state.enable_feature(feature) {
                        newly_enabled.push(feature.to_ascii_uppercase());
                    }
                }
                if invalid_args {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD Invalid ENABLE arguments\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                newly_enabled.sort();
                newly_enabled.dedup();
                let mut response_text = String::new();
                if !newly_enabled.is_empty() {
                    response_text.push_str(&format!("* ENABLED {}\r\n", newly_enabled.join(" ")));
                }
                if newly_enabled.iter().any(|feature| feature == "CONDSTORE") {
                    if let Some(sel) = selected.as_ref() {
                        response_text.push_str(&format!(
                            "* OK [HIGHESTMODSEQ {}] Highest\r\n",
                            sel.highest_modseq
                        ));
                    }
                }
                response_text.push_str(&format!("{} OK ENABLE completed\r\n", tag));
                log_imap_response(peer, tag, &cmd, &response_text);
                let w = reader.get_mut();
                w.write_all(response_text.as_bytes()).await?;
                w.flush().await?;
            }
            "CREATE" => {
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let mailbox_name = match decode_imap_mailbox_arg(
                    unquote(args.trim()),
                    session_state.feature_enabled("UTF8=ACCEPT"),
                ) {
                    Ok(name) => name,
                    Err(_) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD Invalid mailbox name\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                let addr = authed_mailbox.as_ref().unwrap();
                let (local, domain) = address_parts(addr)?;
                let mail_root_clone = mail_root.clone();
                tokio::task::spawn_blocking(move || {
                    maildir::create_mailbox(
                        Path::new(&mail_root_clone),
                        &domain,
                        &local,
                        &mailbox_name,
                    )
                })
                .await??;
                let w = reader.get_mut();
                w.write_all(format!("{} OK CREATE completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "DELETE" => {
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let mailbox_name = match decode_imap_mailbox_arg(
                    unquote(args.trim()),
                    session_state.feature_enabled("UTF8=ACCEPT"),
                ) {
                    Ok(name) => name,
                    Err(_) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD Invalid mailbox name\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                let addr = authed_mailbox.as_ref().unwrap();
                let (local, domain) = address_parts(addr)?;
                let mail_root_clone = mail_root.clone();
                match tokio::task::spawn_blocking(move || {
                    maildir::delete_mailbox(
                        Path::new(&mail_root_clone),
                        &domain,
                        &local,
                        &mailbox_name,
                    )
                })
                .await?
                {
                    Ok(()) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} OK DELETE completed\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                    Err(e) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO DELETE failed: {}\r\n", tag, e).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                }
            }
            "RENAME" => {
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let Some((source_mailbox, rest)) = split_first_imap_astring(args) else {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD Invalid RENAME arguments\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                };
                let Some((destination_mailbox, _)) = split_first_imap_astring(rest) else {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD Invalid RENAME arguments\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                };
                let utf8_accept = session_state.feature_enabled("UTF8=ACCEPT");
                let (source_mailbox, destination_mailbox) = match (
                    decode_imap_mailbox_arg(&source_mailbox, utf8_accept),
                    decode_imap_mailbox_arg(&destination_mailbox, utf8_accept),
                ) {
                    (Ok(source), Ok(destination)) => (source, destination),
                    _ => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD Invalid mailbox name\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                let addr = authed_mailbox.as_ref().unwrap();
                let (local, domain) = address_parts(addr)?;
                let mail_root_clone = mail_root.clone();
                let source_for_task = source_mailbox.clone();
                let destination_for_task = destination_mailbox.clone();
                match tokio::task::spawn_blocking(move || {
                    maildir::rename_mailbox(
                        Path::new(&mail_root_clone),
                        &domain,
                        &local,
                        &source_for_task,
                        &destination_for_task,
                    )
                })
                .await?
                {
                    Ok(()) => {
                        if let Some(addr) = authed_mailbox.as_ref() {
                            if selected
                                .as_ref()
                                .map(|sel| sel.mailbox.eq_ignore_ascii_case(&source_mailbox))
                                .unwrap_or(false)
                            {
                                selected = Some(
                                    mailbox::load_selected_mailbox(
                                        &mail_root,
                                        addr,
                                        &destination_mailbox,
                                    )
                                    .await?,
                                );
                            }
                        }
                        let w = reader.get_mut();
                        w.write_all(format!("{} OK RENAME completed\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                    Err(e) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO RENAME failed: {}\r\n", tag, e).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                }
            }
            "SUBSCRIBE" | "UNSUBSCRIBE" => {
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let mailbox_name = match decode_imap_mailbox_arg(
                    unquote(args.trim()),
                    session_state.feature_enabled("UTF8=ACCEPT"),
                ) {
                    Ok(name) => name,
                    Err(_) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD Invalid mailbox name\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                let addr = authed_mailbox.as_ref().unwrap();
                let (local, domain) = address_parts(addr)?;
                let mail_root_clone = mail_root.clone();
                let subscribed = cmd == "SUBSCRIBE";
                match tokio::task::spawn_blocking(move || {
                    maildir::set_mailbox_subscription(
                        Path::new(&mail_root_clone),
                        &domain,
                        &local,
                        &mailbox_name,
                        subscribed,
                    )
                })
                .await?
                {
                    Ok(()) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} OK {} completed\r\n", tag, cmd).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                    Err(e) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO {} failed: {}\r\n", tag, cmd, e).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                }
            }
            "ID" => {
                let client_id = match parser::parse_id_args(args) {
                    Ok(fields) => fields,
                    Err(_) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD Invalid ID arguments\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                if let Some(fields) = client_id {
                    let keys = fields.into_iter().map(|(key, _)| key).collect::<Vec<_>>();
                    println!("IMAP ID peer={:?} field_keys={:?}", peer, keys);
                }
                let w = reader.get_mut();
                w.write_all(
                    format!(
                        "* ID (\"name\" \"rMail\" \"vendor\" \"rMail\" \"version\" \"{}\")\r\n",
                        env!("CARGO_PKG_VERSION")
                    )
                    .as_bytes(),
                )
                .await?;
                w.write_all(format!("{} OK ID completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "SELECT" | "EXAMINE" => {
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let select_request = match parser::parse_select_request(args) {
                    Ok(request) => request,
                    Err(_) => {
                        let w = reader.get_mut();
                        w.write_all(
                            format!("{} BAD Invalid {} arguments\r\n", tag, cmd).as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                if select_request.qresync.is_some() && !session_state.feature_enabled("QRESYNC") {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD QRESYNC is not enabled\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let mailbox_name = match decode_imap_mailbox_arg(
                    &select_request.mailbox,
                    session_state.feature_enabled("UTF8=ACCEPT"),
                ) {
                    Ok(name) => name,
                    Err(_) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD Invalid mailbox name\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                let condstore_requested =
                    select_request.condstore || session_state.feature_enabled("CONDSTORE");
                println!(
                    "IMAP {} peer={:?} raw_args={:?} normalized_mailbox={:?}",
                    cmd, peer, args, mailbox_name
                );
                let addr = authed_mailbox.as_ref().unwrap();
                match mailbox::load_selected_mailbox(&mail_root, addr, &mailbox_name).await {
                    Ok(mut sel) => {
                        let had_selected_mailbox = selected.is_some();
                        let count = sel.msgs.len();
                        let uidvalidity = sel.uidvalidity;
                        let uidnext = next_uid(&sel);
                        let unseen = first_unseen(&sel);
                        let highest_modseq = sel.highest_modseq;
                        let qresync_changes = if let Some(qresync) = select_request.qresync.as_ref()
                        {
                            if qresync.uidvalidity == uidvalidity {
                                let mail_root = mail_root.clone();
                                let domain = sel.domain.clone();
                                let local = sel.local.clone();
                                let mailbox = sel.mailbox.clone();
                                let since = qresync.modseq;
                                let known = qresync.known_uids.clone();
                                let sample_endpoints = qresync
                                    .sample
                                    .as_ref()
                                    .and_then(|(sequences, uids)| {
                                        parser::SequenceSet::qresync_sample_endpoints(
                                            sequences, uids,
                                        )
                                    })
                                    .unwrap_or_default();
                                let mut changes = tokio::task::spawn_blocking(move || {
                                    rmail_common::imap_state::qresync_changes(
                                        Path::new(&mail_root),
                                        &domain,
                                        &local,
                                        &mailbox,
                                        since,
                                        None,
                                    )
                                })
                                .await??;
                                if let Some(known) = known {
                                    changes.vanished_uids.retain(|uid| known.contains(*uid));
                                    changes
                                        .changed_messages
                                        .retain(|message| known.contains(message.uid));
                                }
                                for (_, sampled_uid) in sample_endpoints {
                                    let known_allows = qresync
                                        .known_uids
                                        .as_ref()
                                        .is_none_or(|known| known.contains(sampled_uid));
                                    if sampled_uid < uidnext
                                        && known_allows
                                        && !sel.msgs.iter().any(|message| message.0 == sampled_uid)
                                    {
                                        changes.vanished_uids.push(sampled_uid);
                                    }
                                }
                                changes.vanished_uids.sort_unstable();
                                changes.vanished_uids.dedup();
                                Some(changes)
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                        let mut qresync_response = String::new();
                        if let Some(changes) = qresync_changes.as_ref() {
                            if !changes.vanished_uids.is_empty() {
                                qresync_response.push_str(&format!(
                                    "* VANISHED (EARLIER) {}\r\n",
                                    compress_search_ids(&changes.vanished_uids)
                                ));
                            }
                            for message in &changes.changed_messages {
                                if let Some(sequence) = sel
                                    .msgs
                                    .iter()
                                    .position(|(uid, _, _, _)| *uid == message.uid)
                                {
                                    qresync_response.push_str(&format!(
                                        "* {} FETCH (UID {} FLAGS ({}) MODSEQ ({}))\r\n",
                                        sequence + 1,
                                        message.uid,
                                        message.flags.join(" "),
                                        message.modseq
                                    ));
                                }
                            }
                        }
                        sel.read_only = cmd == "EXAMINE";
                        println!(
                            "IMAP {} success peer={:?} mailbox={} exists={} uidvalidity={}",
                            cmd, peer, mailbox_name, count, uidvalidity
                        );
                        selected = Some(sel);
                        session_state.selected_mailbox = Some(mailbox_name.clone());
                        let w = reader.get_mut();
                        if had_selected_mailbox && session_state.feature_enabled("QRESYNC") {
                            w.write_all(b"* OK [CLOSED] Previous mailbox closed\r\n")
                                .await?;
                        }
                        w.write_all(b"* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n")
                            .await?;
                        w.flush().await?;
                        let w = reader.get_mut();
                        w.write_all(
                            b"* OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft \\*)] Flags permitted.\r\n",
                        )
                        .await?;
                        w.flush().await?;
                        let w = reader.get_mut();
                        w.write_all(format!("* {} EXISTS\r\n", count).as_bytes())
                            .await?;
                        w.flush().await?;
                        let w = reader.get_mut();
                        w.write_all(b"* 0 RECENT\r\n").await?;
                        w.flush().await?;
                        let w = reader.get_mut();
                        w.write_all(
                            format!("* OK [UIDVALIDITY {}] UIDs valid\r\n", uidvalidity).as_bytes(),
                        )
                        .await?;
                        w.write_all(
                            format!("* OK [UIDNEXT {}] Predicted next UID\r\n", uidnext).as_bytes(),
                        )
                        .await?;
                        w.write_all(
                            format!("* OK [UNSEEN {}] First unseen\r\n", unseen).as_bytes(),
                        )
                        .await?;
                        if condstore_requested {
                            w.write_all(
                                format!("* OK [HIGHESTMODSEQ {}] Highest\r\n", highest_modseq)
                                    .as_bytes(),
                            )
                            .await?;
                        }
                        if !qresync_response.is_empty() {
                            w.write_all(qresync_response.as_bytes()).await?;
                        }
                        w.write_all(
                            format!(
                                "{} OK [{}] {} completed\r\n",
                                tag,
                                if cmd == "EXAMINE" {
                                    "READ-ONLY"
                                } else {
                                    "READ-WRITE"
                                },
                                cmd
                            )
                            .as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                    }
                    Err(e) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO Error opening mailbox\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        eprintln!("load_selected_mailbox error: {}", e);
                    }
                }
            }
            "STATUS" => {
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let Some((mailbox_name, items)) = split_first_imap_astring(args) else {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD Invalid STATUS arguments\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                };
                let mailbox_name = match decode_imap_mailbox_arg(
                    &mailbox_name,
                    session_state.feature_enabled("UTF8=ACCEPT"),
                ) {
                    Ok(name) => name,
                    Err(_) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD Invalid mailbox name\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                let addr = authed_mailbox.as_ref().unwrap();
                let sel =
                    match mailbox::load_selected_mailbox(&mail_root, addr, &mailbox_name).await {
                        Ok(sel) => sel,
                        Err(_) => {
                            let w = reader.get_mut();
                            w.write_all(format!("{} NO No such mailbox\r\n", tag).as_bytes())
                                .await?;
                            w.flush().await?;
                            continue;
                        }
                    };
                let items_upper = normalize_fetch_items(items);
                let supported_status_items = [
                    "MESSAGES",
                    "UIDNEXT",
                    "UIDVALIDITY",
                    "HIGHESTMODSEQ",
                    "UNSEEN",
                    "RECENT",
                    "SIZE",
                ];
                if items_upper.iter().any(|item| {
                    !supported_status_items
                        .iter()
                        .any(|supported| item == supported)
                }) {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD Invalid STATUS item\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                println!(
                    "IMAP STATUS peer={:?} mailbox={:?} items={:?}",
                    peer, mailbox_name, items_upper
                );
                let mut values = Vec::new();
                if items_upper.iter().any(|i| i == "MESSAGES") {
                    values.push(format!("MESSAGES {}", sel.msgs.len()));
                }
                if items_upper.iter().any(|i| i == "UIDNEXT") {
                    values.push(format!("UIDNEXT {}", next_uid(&sel)));
                }
                if items_upper.iter().any(|i| i == "UIDVALIDITY") {
                    values.push(format!("UIDVALIDITY {}", sel.uidvalidity));
                }
                if items_upper.iter().any(|i| i == "HIGHESTMODSEQ") {
                    values.push(format!("HIGHESTMODSEQ {}", sel.highest_modseq));
                }
                if items_upper.iter().any(|i| i == "UNSEEN") {
                    values.push(format!("UNSEEN {}", unseen_count(&sel)));
                }
                if items_upper.iter().any(|i| i == "RECENT") {
                    values.push("RECENT 0".to_string());
                }
                if items_upper.iter().any(|i| i == "SIZE") {
                    values.push(format!("SIZE {}", sel.sizes.values().copied().sum::<u64>()));
                }
                let w = reader.get_mut();
                println!(
                    "IMAP STATUS response peer={:?} mailbox={} values={:?}",
                    peer, sel.mailbox, values
                );
                w.write_all(
                    format!(
                        "* STATUS {} ({})\r\n",
                        quote_imap_mailbox_name(
                            &sel.mailbox,
                            session_state.feature_enabled("UTF8=ACCEPT"),
                        ),
                        values.join(" ")
                    )
                    .as_bytes(),
                )
                .await?;
                w.write_all(format!("{} OK STATUS completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "STARTTLS" => {
                if tls_ctx.is_none() {
                    println!("IMAP STARTTLS unavailable peer={:?}", peer);
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO TLS not available\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let w = reader.get_mut();
                w.write_all(format!("{} OK Begin TLS negotiation now\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
                println!("IMAP STARTTLS begin peer={:?}", peer);
                // perform TLS handshake and continue inside TLS context
                let inner = reader.into_inner();
                match tls_ctx.clone().unwrap().acceptor.accept(inner).await {
                    Ok(tls_stream) => {
                        println!("IMAP STARTTLS handshake success peer={:?}", peer);
                        // Box the TLS stream to the AsyncStream trait object and recurse inside TLS context.
                        // Pass the same tls_ctx along and mark the session as encrypted.
                        let fut = Box::pin(process_stream_inner(
                            Box::new(tls_stream),
                            mail_root,
                            tls_ctx.clone(),
                            db_path.clone(),
                            peer,
                            true,
                            false,
                        ));
                        return fut.await;
                    }
                    Err(e) => {
                        eprintln!("IMAP STARTTLS handshake failed peer={:?}: {}", peer, e);
                        return Err(anyhow::anyhow!("TLS accept failed: {}", e));
                    }
                }
            }

            "FETCH" => {
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                // Ensure a mailbox has been selected with SELECT first
                if selected.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let args = args.trim();
                if let Some(addr) = authed_mailbox.as_ref() {
                    let mailbox = selected_mailbox_name(&selected).to_string();
                    selected = Some(
                        reload_selected_mailbox_preserving_mode(
                            &mail_root, addr, &mailbox, &selected,
                        )
                        .await?,
                    );
                }
                let mut a = args.splitn(2, ' ');
                let seq_set = a.next().unwrap_or("");
                let what = a.next().unwrap_or("");
                let fetch_request = match parser::parse_fetch_request(what) {
                    Ok(request) => request,
                    Err(_) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD Invalid FETCH arguments\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                let modifiers = match parse_fetch_modifiers(
                    fetch_request.modifier_spec.as_deref().unwrap_or(""),
                ) {
                    Ok(modifiers) if !modifiers.vanished => modifiers,
                    Ok(_) => {
                        let w = reader.get_mut();
                        w.write_all(
                            format!("{} BAD VANISHED requires UID FETCH\r\n", tag).as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    }
                    Err(message) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD {}\r\n", tag, message).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                let requested = fetch_request.items;
                let changed_since = modifiers.changed_since;
                println!(
                    "IMAP FETCH peer={:?} seq_set={} requested={:?} changed_since={:?}",
                    peer, seq_set, requested, changed_since
                );
                let sel = selected.as_ref().unwrap();
                let total = sel.msgs.len();
                let seqs = seqs_from_set_or_saved(seq_set, sel, session_state.saved_search_uids());
                for seq in seqs {
                    if seq == 0 || seq > total {
                        continue;
                    }
                    let idx = seq - 1;
                    let uid = sel.msgs[idx].0;
                    let mut flags = sel.msgs[idx].2.clone();
                    let mut modseq = sel.msgs[idx].3;
                    let internal_date = sel.internal_dates.get(&uid).copied().unwrap_or((0, 0));
                    let save_date = sel.save_dates.get(&uid).copied().unwrap_or(0);
                    if changed_since
                        .map(|threshold| modseq <= threshold)
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    if fetch_marks_seen(&requested) {
                        let updated_modseq = apply_implicit_seen(&mail_root, sel, uid, &mut flags)?;
                        if updated_modseq != 0 {
                            modseq = updated_modseq;
                        }
                    }
                    let path = sel.msgs[idx].1.clone();
                    match write_fetch_response(
                        &mut reader,
                        seq,
                        uid,
                        &flags,
                        modseq,
                        internal_date,
                        save_date,
                        path,
                        &requested,
                        what,
                        false,
                    )
                    .await
                    {
                        Ok(()) => {}
                        Err(e) => {
                            let w = reader.get_mut();
                            w.write_all(format!("{} NO Error reading message\r\n", tag).as_bytes())
                                .await?;
                            w.flush().await?;
                            eprintln!("FETCH response error peer={:?}: {}", peer, e);
                        }
                    }
                }
                let w = reader.get_mut();
                w.write_all(format!("{} OK FETCH completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }

            "COPY" | "MOVE" => {
                if selected.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let mut parts = args.trim().splitn(2, ' ');
                let seq_set = parts.next().unwrap_or("");
                let destination = match decode_imap_mailbox_arg(
                    unquote(parts.next().unwrap_or("").trim()),
                    session_state.feature_enabled("UTF8=ACCEPT"),
                ) {
                    Ok(name) => name,
                    Err(_) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD Invalid mailbox name\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                let sel = selected.as_ref().unwrap();
                if cmd == "MOVE" && sel.read_only {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Mailbox is read-only\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let seqs = seqs_from_set_or_saved(seq_set, sel, session_state.saved_search_uids());
                let source_uids = seqs
                    .iter()
                    .filter_map(|seq| {
                        (*seq > 0 && *seq <= sel.msgs.len()).then_some(sel.msgs[*seq - 1].0)
                    })
                    .collect::<Vec<_>>();
                let batch_result = tokio::task::spawn_blocking({
                    let mail_root = mail_root.clone();
                    let domain = sel.domain.clone();
                    let local = sel.local.clone();
                    let mailbox = sel.mailbox.clone();
                    let destination = destination.clone();
                    let source_uids = source_uids.clone();
                    let move_messages = cmd == "MOVE";
                    move || {
                        rmail_common::imap_state::transfer_messages_by_uid(
                            Path::new(&mail_root),
                            &domain,
                            &local,
                            &mailbox,
                            &source_uids,
                            &destination,
                            move_messages,
                        )
                    }
                })
                .await?;
                let mappings = match batch_result {
                    Ok(mappings) => mappings,
                    Err(error) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO {} failed: {}\r\n", tag, cmd, error).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                let mapped_source_uids =
                    mappings.iter().map(|mapping| mapping.0).collect::<Vec<_>>();
                let destination_uids = mappings.iter().map(|mapping| mapping.1).collect::<Vec<_>>();
                let destination_sel = match mailbox::load_selected_mailbox(
                    &mail_root,
                    authed_mailbox.as_ref().unwrap(),
                    &destination,
                )
                .await
                {
                    Ok(sel) => sel,
                    Err(e) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO {} failed: {}\r\n", tag, cmd, e).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                if let Some(addr) = authed_mailbox.as_ref() {
                    let mailbox = selected_mailbox_name(&selected).to_string();
                    selected = Some(
                        reload_selected_mailbox_preserving_mode(
                            &mail_root, addr, &mailbox, &selected,
                        )
                        .await?,
                    );
                }
                let copyuid = copy_uid_pairs(
                    &mapped_source_uids,
                    &destination_uids,
                    destination_sel.uidvalidity,
                )
                .unwrap_or_default();
                let w = reader.get_mut();
                w.write_all(format!("{} OK {}{} completed\r\n", tag, copyuid, cmd).as_bytes())
                    .await?;
                w.flush().await?;
            }

            "UID" => {
                let mut a = args.trim().splitn(2, ' ');
                let subcmd = a.next().unwrap_or("").to_uppercase();
                let subargs = a.next().unwrap_or("");
                if subcmd.as_str() == "FETCH" {
                    if selected.is_none() {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                    if let Some(addr) = authed_mailbox.as_ref() {
                        let mailbox = selected_mailbox_name(&selected).to_string();
                        selected = Some(
                            reload_selected_mailbox_preserving_mode(
                                &mail_root, addr, &mailbox, &selected,
                            )
                            .await?,
                        );
                    }
                    let mut b = subargs.splitn(2, ' ');
                    let uid_set = b.next().unwrap_or("");
                    let what = b.next().unwrap_or("");
                    let fetch_request = match parser::parse_fetch_request(what) {
                        Ok(request) => request,
                        Err(_) => {
                            let w = reader.get_mut();
                            w.write_all(
                                format!("{} BAD Invalid UID FETCH arguments\r\n", tag).as_bytes(),
                            )
                            .await?;
                            w.flush().await?;
                            continue;
                        }
                    };
                    let modifiers = match parse_fetch_modifiers(
                        fetch_request.modifier_spec.as_deref().unwrap_or(""),
                    ) {
                        Ok(modifiers) => modifiers,
                        Err(message) => {
                            let w = reader.get_mut();
                            w.write_all(format!("{} BAD {}\r\n", tag, message).as_bytes())
                                .await?;
                            w.flush().await?;
                            continue;
                        }
                    };
                    if modifiers.vanished && !session_state.feature_enabled("QRESYNC") {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD QRESYNC is not enabled\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                    let requested = fetch_request.items;
                    let changed_since = modifiers.changed_since;
                    println!(
                        "IMAP UID FETCH peer={:?} uid_set={} requested={:?} changed_since={:?}",
                        peer, uid_set, requested, changed_since
                    );
                    let sel = selected.as_ref().unwrap();
                    if modifiers.vanished {
                        let changes = rmail_common::imap_state::qresync_changes(
                            Path::new(&mail_root),
                            &sel.domain,
                            &sel.local,
                            &sel.mailbox,
                            changed_since.unwrap_or(0),
                            None,
                        )?;
                        let max_uid = changes
                            .vanished_uids
                            .iter()
                            .copied()
                            .chain(sel.msgs.iter().map(|message| message.0))
                            .max()
                            .unwrap_or_else(|| sel.uidnext.saturating_sub(1));
                        let Some(requested_uids) = parser::SequenceSet::parse(uid_set, max_uid)
                        else {
                            let w = reader.get_mut();
                            w.write_all(format!("{} BAD Invalid UID set\r\n", tag).as_bytes())
                                .await?;
                            w.flush().await?;
                            continue;
                        };
                        let vanished = changes
                            .vanished_uids
                            .into_iter()
                            .filter(|uid| requested_uids.contains(*uid))
                            .collect::<Vec<_>>();
                        if !vanished.is_empty() {
                            let w = reader.get_mut();
                            w.write_all(
                                format!(
                                    "* VANISHED (EARLIER) {}\r\n",
                                    compress_search_ids(&vanished)
                                )
                                .as_bytes(),
                            )
                            .await?;
                        }
                    }
                    // Build list of UIDs to return, handling ranges
                    let uids =
                        uids_from_set_or_saved(uid_set, sel, session_state.saved_search_uids());
                    for uid in uids {
                        if let Some(pos) = sel.msgs.iter().position(|(u, _, _, _)| *u == uid) {
                            let seq = pos + 1;
                            let uid = sel.msgs[pos].0;
                            let mut flags = sel.msgs[pos].2.clone();
                            let mut modseq = sel.msgs[pos].3;
                            let internal_date =
                                sel.internal_dates.get(&uid).copied().unwrap_or((0, 0));
                            let save_date = sel.save_dates.get(&uid).copied().unwrap_or(0);
                            if changed_since
                                .map(|threshold| modseq <= threshold)
                                .unwrap_or(false)
                            {
                                continue;
                            }
                            if fetch_marks_seen(&requested) {
                                let updated_modseq =
                                    apply_implicit_seen(&mail_root, sel, uid, &mut flags)?;
                                if updated_modseq != 0 {
                                    modseq = updated_modseq;
                                }
                            }
                            let path = sel.msgs[pos].1.clone();
                            match write_fetch_response(
                                &mut reader,
                                seq,
                                uid,
                                &flags,
                                modseq,
                                internal_date,
                                save_date,
                                path,
                                &requested,
                                what,
                                true,
                            )
                            .await
                            {
                                Ok(()) => {}
                                Err(e) => {
                                    let w = reader.get_mut();
                                    w.write_all(
                                        format!("{} NO Error reading message\r\n", tag).as_bytes(),
                                    )
                                    .await?;
                                    w.flush().await?;
                                    eprintln!("UID FETCH response error peer={:?}: {}", peer, e);
                                }
                            }
                        }
                    }
                    let w = reader.get_mut();
                    w.write_all(format!("{} OK UID FETCH completed\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                } else if subcmd.as_str() == "THREAD" {
                    let request = match parser::parse_thread_request(subargs) {
                        Ok(request) => request,
                        Err(error) => {
                            let response = match error {
                                parser::SortParseError::UnsupportedCharset(_) => format!(
                                    "{} NO [BADCHARSET (US-ASCII UTF-8)] Unsupported charset\r\n",
                                    tag
                                ),
                                parser::SortParseError::Syntax => {
                                    format!("{} BAD Invalid UID THREAD arguments\r\n", tag)
                                }
                            };
                            let w = reader.get_mut();
                            w.write_all(response.as_bytes()).await?;
                            w.flush().await?;
                            continue;
                        }
                    };
                    let sel = selected
                        .as_ref()
                        .expect("preflight requires selected mailbox");
                    let messages =
                        execute_thread(sel, &request, session_state.saved_search_uids()).await?;
                    let body = match request.algorithm {
                        parser::ThreadAlgorithm::OrderedSubject => {
                            thread::ordered_subject(&messages, true)
                        }
                        parser::ThreadAlgorithm::References => thread::references(&messages, true),
                        parser::ThreadAlgorithm::Refs => thread::refs(&messages, true),
                    };
                    let w = reader.get_mut();
                    w.write_all(format!("* THREAD {}\r\n", body).as_bytes())
                        .await?;
                    w.write_all(format!("{} OK UID THREAD completed\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                } else if subcmd.as_str() == "SORT" {
                    let request = match parser::parse_sort_request(subargs) {
                        Ok(request) => request,
                        Err(error) => {
                            let response = match error {
                                parser::SortParseError::UnsupportedCharset(_) => format!(
                                    "{} NO [BADCHARSET (US-ASCII UTF-8)] Unsupported charset\r\n",
                                    tag
                                ),
                                parser::SortParseError::Syntax => {
                                    format!("{} BAD Invalid UID SORT arguments\r\n", tag)
                                }
                            };
                            let w = reader.get_mut();
                            w.write_all(response.as_bytes()).await?;
                            w.flush().await?;
                            continue;
                        }
                    };
                    let sel = selected
                        .as_ref()
                        .expect("preflight requires selected mailbox");
                    let records =
                        execute_sort(sel, &request, session_state.saved_search_uids()).await?;
                    let ids = records
                        .iter()
                        .map(|record| record.uid.to_string())
                        .collect::<Vec<_>>()
                        .join(" ");
                    let w = reader.get_mut();
                    w.write_all(format!("* SORT {}\r\n", ids).as_bytes())
                        .await?;
                    w.write_all(format!("{} OK UID SORT completed\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                } else if subcmd.as_str() == "SEARCH" {
                    if selected.is_none() {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                    let request = match parser::parse_search_request(subargs) {
                        Ok(request) => request,
                        Err(error) => {
                            let response = match error {
                                parser::SearchParseError::UnsupportedCharset(_) => format!(
                                    "{} NO [BADCHARSET (US-ASCII UTF-8)] Unsupported charset\r\n",
                                    tag
                                ),
                                parser::SearchParseError::Syntax => {
                                    format!("{} BAD Invalid UID SEARCH arguments\r\n", tag)
                                }
                            };
                            let w = reader.get_mut();
                            w.write_all(response.as_bytes()).await?;
                            w.flush().await?;
                            continue;
                        }
                    };
                    if session_state.feature_enabled("UTF8=ACCEPT") && request.charset.is_some() {
                        let w = reader.get_mut();
                        w.write_all(
                            format!(
                                "{} BAD Cannot set SEARCH charset when UTF8=ACCEPT is enabled\r\n",
                                tag
                            )
                            .as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    }
                    let sel = selected.as_ref().unwrap();
                    println!(
                        "IMAP UID SEARCH peer={:?} criteria={:?}",
                        peer, request.criterion
                    );
                    let matches =
                        execute_search(sel, &request.criterion, session_state.saved_search_uids())
                            .await?;
                    let ids = matches.iter().map(|(_, uid)| *uid).collect::<Vec<_>>();
                    if request
                        .return_options
                        .as_ref()
                        .is_some_and(|options| options.save)
                    {
                        session_state.save_search_uids(ids.clone());
                    }
                    let w = reader.get_mut();
                    println!("IMAP UID SEARCH matches peer={:?} uids={:?}", peer, ids);
                    w.write_all(
                        search_result_response(tag, true, &ids, request.return_options.as_ref())
                            .as_bytes(),
                    )
                    .await?;
                    w.write_all(format!("{} OK UID SEARCH completed\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                } else if subcmd.as_str() == "STORE" {
                    if selected.is_none() {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                    let sel = selected.as_ref().unwrap();
                    if sel.read_only {
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO Mailbox is read-only\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                    let Some((uid_set, unchanged_since, op, flags_raw)) =
                        parse_store_command_args(subargs)
                    else {
                        let w = reader.get_mut();
                        w.write_all(
                            format!("{} BAD Invalid UID STORE arguments\r\n", tag).as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    };
                    let flags = parse_store_items(&flags_raw);
                    let silent = op.to_uppercase().ends_with(".SILENT");
                    let ids =
                        uids_from_set_or_saved(&uid_set, sel, session_state.saved_search_uids());
                    let mut modified = Vec::new();
                    println!(
                        "IMAP UID STORE peer={:?} uid_set={} ids={:?} op={} flags={:?} silent={} unchanged_since={:?}",
                        peer, uid_set, ids, op, flags, silent, unchanged_since
                    );
                    let mut updates = Vec::new();
                    for uid in ids {
                        if let Some(pos) = sel.msgs.iter().position(|(u, _, _, _)| *u == uid) {
                            let seq = pos + 1;
                            let current = sel.msgs[pos].2.clone();
                            let modseq = sel.msgs[pos].3;
                            if unchanged_since
                                .map(|threshold| modseq > threshold)
                                .unwrap_or(false)
                            {
                                modified.push(uid.to_string());
                                continue;
                            }
                            let updated =
                                apply_flag_operation(&current, &op.to_uppercase(), &flags);
                            println!(
                                "IMAP UID STORE apply peer={:?} seq={} uid={} old_flags={:?} new_flags={:?}",
                                peer, seq, uid, current, updated
                            );
                            updates.push((seq, uid, updated));
                        }
                    }
                    let flag_updates = updates
                        .iter()
                        .map(|(_, uid, flags)| (*uid, flags.clone()))
                        .collect::<Vec<_>>();
                    let modseqs = rmail_common::imap_state::set_uid_flags_batch(
                        Path::new(&mail_root),
                        &sel.domain,
                        &sel.local,
                        &sel.mailbox,
                        &flag_updates,
                    )?;
                    if !silent {
                        let w = reader.get_mut();
                        for ((seq, uid, updated), (_, updated_modseq)) in
                            updates.iter().zip(modseqs.iter())
                        {
                            w.write_all(
                                format!(
                                    "* {} FETCH (FLAGS ({}) UID {} MODSEQ ({}))\r\n",
                                    seq,
                                    updated.join(" "),
                                    uid,
                                    updated_modseq
                                )
                                .as_bytes(),
                            )
                            .await?;
                        }
                        w.flush().await?;
                    }
                    if let Some(addr) = authed_mailbox.as_ref() {
                        let mailbox = selected_mailbox_name(&selected).to_string();
                        selected = Some(
                            reload_selected_mailbox_preserving_mode(
                                &mail_root, addr, &mailbox, &selected,
                            )
                            .await?,
                        );
                    }
                    let w = reader.get_mut();
                    if modified.is_empty() {
                        w.write_all(format!("{} OK UID STORE completed\r\n", tag).as_bytes())
                            .await?;
                    } else {
                        w.write_all(
                            format!(
                                "{} OK [MODIFIED {}] UID STORE completed\r\n",
                                tag,
                                modified.join(",")
                            )
                            .as_bytes(),
                        )
                        .await?;
                    }
                    w.flush().await?;
                } else if subcmd.as_str() == "EXPUNGE" {
                    if selected.is_none() {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                    let uid_set = subargs.trim();
                    let sel = selected.as_ref().unwrap();
                    if sel.read_only {
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO Mailbox is read-only\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                    let requested =
                        uids_from_set_or_saved(uid_set, sel, session_state.saved_search_uids());
                    let requested: std::collections::HashSet<u64> = requested.into_iter().collect();
                    let mut deleted: Vec<(usize, u64)> = sel
                        .msgs
                        .iter()
                        .enumerate()
                        .filter_map(|(idx, (uid, _, flags, _))| {
                            (requested.contains(uid)
                                && flags.iter().any(|f| f.eq_ignore_ascii_case("\\Deleted")))
                            .then_some((idx + 1, *uid))
                        })
                        .collect();
                    deleted.sort_by(|a, b| b.0.cmp(&a.0));
                    let deleted_uids = deleted.iter().map(|(_, uid)| *uid).collect::<Vec<_>>();
                    rmail_common::imap_state::delete_messages_by_uid(
                        Path::new(&mail_root),
                        &sel.domain,
                        &sel.local,
                        &sel.mailbox,
                        &deleted_uids,
                    )?;
                    let w = reader.get_mut();
                    if session_state.feature_enabled("QRESYNC") && !deleted.is_empty() {
                        let uids = deleted.iter().map(|(_, uid)| *uid).collect::<Vec<_>>();
                        w.write_all(
                            format!("* VANISHED {}\r\n", compress_search_ids(&uids)).as_bytes(),
                        )
                        .await?;
                    } else {
                        for (seq, _) in &deleted {
                            w.write_all(format!("* {} EXPUNGE\r\n", seq).as_bytes())
                                .await?;
                        }
                    }
                    if let Some(addr) = authed_mailbox.as_ref() {
                        let mailbox = selected_mailbox_name(&selected).to_string();
                        selected = Some(
                            reload_selected_mailbox_preserving_mode(
                                &mail_root, addr, &mailbox, &selected,
                            )
                            .await?,
                        );
                    }
                    w.write_all(format!("{} OK UID EXPUNGE completed\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                } else if subcmd.as_str() == "COPY" || subcmd.as_str() == "MOVE" {
                    if selected.is_none() {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                    let mut parts = subargs.trim().splitn(2, ' ');
                    let uid_set = parts.next().unwrap_or("");
                    let destination = match decode_imap_mailbox_arg(
                        unquote(parts.next().unwrap_or("").trim()),
                        session_state.feature_enabled("UTF8=ACCEPT"),
                    ) {
                        Ok(name) => name,
                        Err(_) => {
                            let w = reader.get_mut();
                            w.write_all(format!("{} BAD Invalid mailbox name\r\n", tag).as_bytes())
                                .await?;
                            w.flush().await?;
                            continue;
                        }
                    };
                    let sel = selected.as_ref().unwrap();
                    if subcmd == "MOVE" && sel.read_only {
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO Mailbox is read-only\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                    let source_uids =
                        uids_from_set_or_saved(uid_set, sel, session_state.saved_search_uids());
                    let batch_result = tokio::task::spawn_blocking({
                        let mail_root = mail_root.clone();
                        let domain = sel.domain.clone();
                        let local = sel.local.clone();
                        let mailbox = sel.mailbox.clone();
                        let destination = destination.clone();
                        let source_uids = source_uids.clone();
                        let move_messages = subcmd == "MOVE";
                        move || {
                            rmail_common::imap_state::transfer_messages_by_uid(
                                Path::new(&mail_root),
                                &domain,
                                &local,
                                &mailbox,
                                &source_uids,
                                &destination,
                                move_messages,
                            )
                        }
                    })
                    .await?;
                    let mappings = match batch_result {
                        Ok(mappings) => mappings,
                        Err(error) => {
                            let w = reader.get_mut();
                            w.write_all(
                                format!("{} NO UID {} failed: {}\r\n", tag, subcmd, error)
                                    .as_bytes(),
                            )
                            .await?;
                            w.flush().await?;
                            continue;
                        }
                    };
                    let mapped_source_uids =
                        mappings.iter().map(|mapping| mapping.0).collect::<Vec<_>>();
                    let destination_uids =
                        mappings.iter().map(|mapping| mapping.1).collect::<Vec<_>>();
                    let destination_sel = match mailbox::load_selected_mailbox(
                        &mail_root,
                        authed_mailbox.as_ref().unwrap(),
                        &destination,
                    )
                    .await
                    {
                        Ok(sel) => sel,
                        Err(e) => {
                            let w = reader.get_mut();
                            w.write_all(
                                format!("{} NO UID {} failed: {}\r\n", tag, subcmd, e).as_bytes(),
                            )
                            .await?;
                            w.flush().await?;
                            continue;
                        }
                    };
                    if let Some(addr) = authed_mailbox.as_ref() {
                        let mailbox = selected_mailbox_name(&selected).to_string();
                        selected = Some(
                            reload_selected_mailbox_preserving_mode(
                                &mail_root, addr, &mailbox, &selected,
                            )
                            .await?,
                        );
                    }
                    let copyuid = copy_uid_pairs(
                        &mapped_source_uids,
                        &destination_uids,
                        destination_sel.uidvalidity,
                    )
                    .unwrap_or_default();
                    let w = reader.get_mut();
                    w.write_all(
                        format!("{} OK {}UID {} completed\r\n", tag, copyuid, subcmd).as_bytes(),
                    )
                    .await?;
                    w.flush().await?;
                } else {
                    log_unsupported_imap(peer, &selected, tag, &format!("UID {}", subcmd), subargs);
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD Unsupported UID subcommand\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                }
            }
            "SEARCH" => {
                if selected.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let request = match parser::parse_search_request(args) {
                    Ok(request) => request,
                    Err(error) => {
                        let response = match error {
                            parser::SearchParseError::UnsupportedCharset(_) => format!(
                                "{} NO [BADCHARSET (US-ASCII UTF-8)] Unsupported charset\r\n",
                                tag
                            ),
                            parser::SearchParseError::Syntax => {
                                format!("{} BAD Invalid SEARCH arguments\r\n", tag)
                            }
                        };
                        let w = reader.get_mut();
                        w.write_all(response.as_bytes()).await?;
                        w.flush().await?;
                        continue;
                    }
                };
                if session_state.feature_enabled("UTF8=ACCEPT") && request.charset.is_some() {
                    let w = reader.get_mut();
                    w.write_all(
                        format!(
                            "{} BAD Cannot set SEARCH charset when UTF8=ACCEPT is enabled\r\n",
                            tag
                        )
                        .as_bytes(),
                    )
                    .await?;
                    w.flush().await?;
                    continue;
                }
                let sel = selected.as_ref().unwrap();
                println!(
                    "IMAP SEARCH peer={:?} criteria={:?}",
                    peer, request.criterion
                );
                let matches =
                    execute_search(sel, &request.criterion, session_state.saved_search_uids())
                        .await?;
                let ids = matches.iter().map(|(seq, _)| *seq).collect::<Vec<_>>();
                if request
                    .return_options
                    .as_ref()
                    .is_some_and(|options| options.save)
                {
                    session_state.save_search_uids(matches.iter().map(|(_, uid)| *uid).collect());
                }
                let w = reader.get_mut();
                println!("IMAP SEARCH matches peer={:?} seqs={:?}", peer, ids);
                w.write_all(
                    search_result_response(tag, false, &ids, request.return_options.as_ref())
                        .as_bytes(),
                )
                .await?;
                w.write_all(format!("{} OK SEARCH completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "THREAD" => {
                let request = match parser::parse_thread_request(args) {
                    Ok(request) => request,
                    Err(error) => {
                        let response = match error {
                            parser::SortParseError::UnsupportedCharset(_) => format!(
                                "{} NO [BADCHARSET (US-ASCII UTF-8)] Unsupported charset\r\n",
                                tag
                            ),
                            parser::SortParseError::Syntax => {
                                format!("{} BAD Invalid THREAD arguments\r\n", tag)
                            }
                        };
                        let w = reader.get_mut();
                        w.write_all(response.as_bytes()).await?;
                        w.flush().await?;
                        continue;
                    }
                };
                let sel = selected
                    .as_ref()
                    .expect("preflight requires selected mailbox");
                let messages =
                    execute_thread(sel, &request, session_state.saved_search_uids()).await?;
                let body = match request.algorithm {
                    parser::ThreadAlgorithm::OrderedSubject => {
                        thread::ordered_subject(&messages, false)
                    }
                    parser::ThreadAlgorithm::References => thread::references(&messages, false),
                    parser::ThreadAlgorithm::Refs => thread::refs(&messages, false),
                };
                let w = reader.get_mut();
                w.write_all(format!("* THREAD {}\r\n", body).as_bytes())
                    .await?;
                w.write_all(format!("{} OK THREAD completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "SORT" => {
                let request = match parser::parse_sort_request(args) {
                    Ok(request) => request,
                    Err(error) => {
                        let response = match error {
                            parser::SortParseError::UnsupportedCharset(_) => format!(
                                "{} NO [BADCHARSET (US-ASCII UTF-8)] Unsupported charset\r\n",
                                tag
                            ),
                            parser::SortParseError::Syntax => {
                                format!("{} BAD Invalid SORT arguments\r\n", tag)
                            }
                        };
                        let w = reader.get_mut();
                        w.write_all(response.as_bytes()).await?;
                        w.flush().await?;
                        continue;
                    }
                };
                let sel = selected
                    .as_ref()
                    .expect("preflight requires selected mailbox");
                let records =
                    execute_sort(sel, &request, session_state.saved_search_uids()).await?;
                let ids = records
                    .iter()
                    .map(|record| record.seq.to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                let w = reader.get_mut();
                w.write_all(format!("* SORT {}\r\n", ids).as_bytes())
                    .await?;
                w.write_all(format!("{} OK SORT completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "STORE" => {
                if selected.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let sel = selected.as_ref().unwrap();
                if sel.read_only {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Mailbox is read-only\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let Some((seq_set, unchanged_since, op, flags_raw)) =
                    parse_store_command_args(args)
                else {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD Invalid STORE arguments\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                };
                let flags = parse_store_items(&flags_raw);
                let silent = op.to_uppercase().ends_with(".SILENT");
                println!(
                    "IMAP STORE peer={:?} seq_set={} op={} flags={:?} silent={} unchanged_since={:?}",
                    peer, seq_set, op, flags, silent, unchanged_since
                );
                let mut modified = Vec::new();
                let mut updates = Vec::new();
                for seq in seqs_from_set_or_saved(&seq_set, sel, session_state.saved_search_uids())
                {
                    if seq == 0 || seq > sel.msgs.len() {
                        continue;
                    }
                    let idx = seq - 1;
                    let uid = sel.msgs[idx].0;
                    let current = sel.msgs[idx].2.clone();
                    let modseq = sel.msgs[idx].3;
                    if unchanged_since
                        .map(|threshold| modseq > threshold)
                        .unwrap_or(false)
                    {
                        modified.push(seq.to_string());
                        continue;
                    }
                    let updated = apply_flag_operation(&current, &op.to_uppercase(), &flags);
                    println!(
                        "IMAP STORE apply peer={:?} seq={} uid={} old_flags={:?} new_flags={:?}",
                        peer, seq, uid, current, updated
                    );
                    updates.push((seq, uid, updated));
                }
                let flag_updates = updates
                    .iter()
                    .map(|(_, uid, flags)| (*uid, flags.clone()))
                    .collect::<Vec<_>>();
                let modseqs = rmail_common::imap_state::set_uid_flags_batch(
                    Path::new(&mail_root),
                    &sel.domain,
                    &sel.local,
                    &sel.mailbox,
                    &flag_updates,
                )?;
                if !silent {
                    let w = reader.get_mut();
                    for ((seq, uid, updated), (_, updated_modseq)) in
                        updates.iter().zip(modseqs.iter())
                    {
                        w.write_all(
                            format!(
                                "* {} FETCH (FLAGS ({}) UID {} MODSEQ ({}))\r\n",
                                seq,
                                updated.join(" "),
                                uid,
                                updated_modseq
                            )
                            .as_bytes(),
                        )
                        .await?;
                    }
                    w.flush().await?;
                }
                if let Some(addr) = authed_mailbox.as_ref() {
                    let mailbox = selected_mailbox_name(&selected).to_string();
                    selected = Some(
                        reload_selected_mailbox_preserving_mode(
                            &mail_root, addr, &mailbox, &selected,
                        )
                        .await?,
                    );
                }
                let w = reader.get_mut();
                if modified.is_empty() {
                    w.write_all(format!("{} OK STORE completed\r\n", tag).as_bytes())
                        .await?;
                } else {
                    w.write_all(
                        format!(
                            "{} OK [MODIFIED {}] STORE completed\r\n",
                            tag,
                            modified.join(",")
                        )
                        .as_bytes(),
                    )
                    .await?;
                }
                w.flush().await?;
            }
            "EXPUNGE" => {
                if selected.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let sel = selected.as_ref().unwrap();
                if sel.read_only {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Mailbox is read-only\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let deleted = mailbox::expunge_deleted(&mail_root, sel).await?;
                println!("IMAP EXPUNGE peer={:?} removed={:?}", peer, deleted);
                let w = reader.get_mut();
                if session_state.feature_enabled("QRESYNC") && !deleted.is_empty() {
                    let mut uids = deleted.iter().map(|(_, uid)| *uid).collect::<Vec<_>>();
                    uids.sort_unstable();
                    w.write_all(
                        format!("* VANISHED {}\r\n", compress_search_ids(&uids)).as_bytes(),
                    )
                    .await?;
                } else {
                    for (seq, _) in &deleted {
                        w.write_all(format!("* {} EXPUNGE\r\n", seq).as_bytes())
                            .await?;
                    }
                }
                selected = if let Some(addr) = authed_mailbox.as_ref() {
                    let mailbox = selected_mailbox_name(&selected).to_string();
                    Some(
                        reload_selected_mailbox_preserving_mode(
                            &mail_root, addr, &mailbox, &selected,
                        )
                        .await?,
                    )
                } else {
                    None
                };
                w.write_all(format!("{} OK EXPUNGE completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "CLOSE" => {
                if selected.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let sel = selected.as_ref().unwrap();
                if sel.read_only {
                    selected = None;
                    session_state.selected_mailbox = None;
                    let w = reader.get_mut();
                    w.write_all(format!("{} OK CLOSE completed\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let deleted = mailbox::expunge_deleted(&mail_root, sel).await?;
                println!("IMAP CLOSE peer={:?} expunged={:?}", peer, deleted);
                selected = None;
                session_state.selected_mailbox = None;
                let w = reader.get_mut();
                w.write_all(format!("{} OK CLOSE completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "IDLE" => {
                if selected.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                sync_selected_mailbox(
                    &mut reader,
                    &mail_root,
                    &mut selected,
                    session_state.feature_enabled("QRESYNC"),
                )
                .await?;
                let idle_tag = tag.to_string();
                let w = reader.get_mut();
                w.write_all(b"+ idling\r\n").await?;
                w.flush().await?;
                let mut idle_line = String::new();
                let mut idle_bad = false;
                loop {
                    idle_line.clear();
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(1),
                        reader.read_line(&mut idle_line),
                    )
                    .await
                    {
                        Ok(Ok(0)) => return Ok(()),
                        Ok(Ok(_)) => {
                            if idle_line
                                .trim_end_matches("\r\n")
                                .eq_ignore_ascii_case("DONE")
                            {
                                break;
                            }
                            let w = reader.get_mut();
                            w.write_all(format!("{} BAD Expected DONE\r\n", idle_tag).as_bytes())
                                .await?;
                            w.flush().await?;
                            idle_bad = true;
                            break;
                        }
                        Ok(Err(e)) => return Err(e.into()),
                        Err(_) => {
                            sync_selected_mailbox(
                                &mut reader,
                                &mail_root,
                                &mut selected,
                                session_state.feature_enabled("QRESYNC"),
                            )
                            .await?;
                        }
                    }
                }
                if idle_bad {
                    continue;
                }
                let w = reader.get_mut();
                w.write_all(format!("{} OK IDLE completed\r\n", idle_tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "LOGOUT" => {
                let w = reader.get_mut();
                w.write_all(b"* BYE Logging out\r\n").await?;
                w.flush().await?;
                let w = reader.get_mut();
                w.write_all(format!("{} OK LOGOUT completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
                break;
            }
            _ => {
                log_unsupported_imap(peer, &selected, tag, &cmd, args);
                let w = reader.get_mut();
                w.write_all(format!("{} BAD Unknown or unimplemented command\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
        }
    }
    Ok(())
}
