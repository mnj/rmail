//! Reading message content (DATA and BDAT) and building trace headers.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::time::timeout;

use crate::{
    DATA_READ_TIMEOUT, MAX_DATA_LINE_BYTES, MAX_MESSAGE_BYTES, SmtpService, server_hostname,
};

async fn timed_read_until<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    byte: u8,
    buf: &mut Vec<u8>,
    duration: Duration,
) -> Result<Option<usize>> {
    match timeout(duration, reader.read_until(byte, buf)).await {
        Ok(Ok(n)) => Ok(Some(n)),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Ok(None),
    }
}

pub(crate) enum DataReadResult {
    Complete(Vec<u8>),
    TooLarge,
    LineTooLong,
    InvalidLineEnding,
    /// A "." line that is not a strict `<CRLF>.<CRLF>` (bare LF or CR before
    /// or after the dot). Other implementations may treat it as the end of
    /// data, so the rest of the stream cannot be trusted (SMTP smuggling).
    AmbiguousTerminator,
    Timeout,
    Eof,
}

/// The line ends with CRLF and contains no other CR or LF.
fn strictly_terminated(line: &[u8]) -> bool {
    line.strip_suffix(b"\r\n")
        .is_some_and(|content| !content.iter().any(|byte| matches!(byte, b'\r' | b'\n')))
}

/// Read DATA content up to `<CRLF>.<CRLF>` (RFC 5321 section 4.1.1.4).
///
/// Only a "." line that ends with CRLF and follows a CRLF-terminated line
/// (or the DATA command itself) ends the message. Lines with a bare LF or
/// bare CR mark the message as failed while the content is drained to the
/// real terminator. A "." line terminated or preceded by a bare LF/CR is an
/// ambiguous end-of-data sequence that another server may have honoured, so
/// the caller must reply and close the connection instead of interpreting
/// the following bytes as commands.
pub(crate) async fn read_smtp_data<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<DataReadResult> {
    let mut data: Vec<u8> = Vec::new();
    let mut failure: Option<DataReadResult> = None;
    // The DATA command line itself ended with CRLF.
    let mut previous_strict = true;
    loop {
        let mut dline: Vec<u8> = Vec::new();
        let Some(n) = timed_read_until(reader, b'\n', &mut dline, DATA_READ_TIMEOUT).await? else {
            return Ok(DataReadResult::Timeout);
        };
        if n == 0 {
            return Ok(DataReadResult::Eof);
        }

        let strict = strictly_terminated(&dline);
        let content = dline.strip_suffix(b"\n").unwrap_or(&dline);
        let content = content.strip_suffix(b"\r").unwrap_or(content);
        if content
            .iter()
            .filter(|byte| **byte != b'\r')
            .eq(b".".iter())
        {
            if strict && previous_strict {
                return Ok(failure.unwrap_or(DataReadResult::Complete(data)));
            }
            return Ok(DataReadResult::AmbiguousTerminator);
        }
        previous_strict = strict;

        if dline.len() > MAX_DATA_LINE_BYTES && failure.is_none() {
            failure = Some(DataReadResult::LineTooLong);
        }
        if !strict && failure.is_none() {
            failure = Some(DataReadResult::InvalidLineEnding);
        }

        if failure.is_none() {
            let mut line = &dline[..dline.len() - 2];
            if line.starts_with(b"..") {
                line = &line[1..];
            }
            data.extend_from_slice(line);
            data.extend_from_slice(b"\r\n");
            if data.len() > MAX_MESSAGE_BYTES {
                failure = Some(DataReadResult::TooLarge);
            }
        }
    }
}

pub(crate) async fn read_exact_chunk<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    size: usize,
    retain: bool,
) -> Result<Option<Vec<u8>>> {
    let read = async {
        if retain {
            let mut chunk = vec![0; size];
            reader.read_exact(&mut chunk).await?;
            Ok::<_, std::io::Error>(chunk)
        } else {
            let mut remaining = size;
            let mut scratch = [0; 8192];
            while remaining != 0 {
                let take = remaining.min(scratch.len());
                reader.read_exact(&mut scratch[..take]).await?;
                remaining -= take;
            }
            Ok(Vec::new())
        }
    };
    match timeout(DATA_READ_TIMEOUT, read).await {
        Ok(result) => Ok(Some(result?)),
        Err(_) => Ok(None),
    }
}

pub(crate) fn valid_text_message_form(data: &[u8]) -> bool {
    let mut line_len = 0usize;
    let mut index = 0usize;
    while index < data.len() {
        match data[index] {
            b'\r' if data.get(index + 1) == Some(&b'\n') => {
                if line_len + 2 > MAX_DATA_LINE_BYTES {
                    return false;
                }
                line_len = 0;
                index += 2;
            }
            b'\r' | b'\n' | 0 => return false,
            _ => {
                line_len += 1;
                index += 1;
            }
        }
    }
    line_len <= MAX_DATA_LINE_BYTES - 2
}

pub(crate) fn received_header(
    peer: Option<SocketAddr>,
    helo_name: Option<&str>,
    service: SmtpService,
    extended_smtp: bool,
    encrypted: bool,
    authenticated: bool,
    priority: Option<i8>,
) -> Vec<u8> {
    let helo = helo_name.unwrap_or("unknown");
    let protocol = if service == SmtpService::Lmtp {
        "LMTP"
    } else if encrypted && authenticated {
        "ESMTPSA"
    } else if encrypted {
        "ESMTPS"
    } else if authenticated {
        "ESMTPA"
    } else if extended_smtp {
        "ESMTP"
    } else {
        "SMTP"
    };
    let timestamp = chrono_like_utc_timestamp();
    // RFC 5321 section 4.4: "by" names the receiving host.
    let host = server_hostname();
    // RFC 6710 section 6: the PRIORITY clause records the priority this
    // server assigned.
    let priority = priority
        .map(|priority| format!(" PRIORITY {priority}"))
        .unwrap_or_default();
    match peer {
        Some(peer) => format!(
            "Received: from {helo} ([{}]) by {host} (rMail) with {protocol}{priority}; {timestamp}\r\n",
            peer.ip()
        ),
        None => format!(
            "Received: from {helo} by {host} (rMail) with {protocol}{priority}; {timestamp}\r\n"
        ),
    }
    .into_bytes()
}

fn chrono_like_utc_timestamp() -> String {
    chrono::Utc::now().to_rfc2822()
}
