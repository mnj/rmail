//! Reading message content (DATA and BDAT) and building trace headers.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::time::timeout;

use crate::{DATA_READ_TIMEOUT, MAX_DATA_LINE_BYTES, MAX_MESSAGE_BYTES, SmtpService};

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
    Timeout,
    Eof,
}

pub(crate) async fn read_smtp_data<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<DataReadResult> {
    let mut data: Vec<u8> = Vec::new();
    let mut failure: Option<DataReadResult> = None;
    loop {
        let mut dline: Vec<u8> = Vec::new();
        let Some(n) = timed_read_until(reader, b'\n', &mut dline, DATA_READ_TIMEOUT).await? else {
            return Ok(DataReadResult::Timeout);
        };
        if n == 0 {
            return Ok(DataReadResult::Eof);
        }

        if dline.len() > MAX_DATA_LINE_BYTES && failure.is_none() {
            failure = Some(DataReadResult::LineTooLong);
        }
        let valid_line_ending = dline.ends_with(b"\r\n");
        if !valid_line_ending && failure.is_none() {
            failure = Some(DataReadResult::InvalidLineEnding);
        }
        if valid_line_ending {
            dline.truncate(dline.len() - 2);
        } else if dline.ends_with(b"\n") {
            dline.pop();
        }

        if dline == b"." {
            return Ok(failure.unwrap_or(DataReadResult::Complete(data)));
        }

        if failure.is_none() {
            if dline.starts_with(b"..") {
                dline.remove(0);
            }
            data.extend_from_slice(&dline);
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
    match peer {
        Some(peer) => format!(
            "Received: from {helo} ([{}]) by rMail SMTPD with {protocol}; {timestamp}\r\n",
            peer.ip()
        ),
        None => format!("Received: from {helo} by rMail SMTPD with {protocol}; {timestamp}\r\n"),
    }
    .into_bytes()
}

fn chrono_like_utc_timestamp() -> String {
    chrono::Utc::now().to_rfc2822()
}
