//! Reading bounded command lines and inlining textual literals.

use std::io::ErrorKind;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::MAX_APPEND_LITERAL_BYTES;
use crate::transport::AsyncStream;

pub(crate) enum BoundedLine {
    Eof,
    Line(Vec<u8>),
    TooLong,
}

pub(crate) async fn read_bounded_line(
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
pub(crate) struct TrailingLiteralMarker {
    start: usize,
    size: usize,
    non_sync: bool,
    literal8: bool,
}

pub(crate) fn trailing_literal_marker(line: &[u8]) -> Option<TrailingLiteralMarker> {
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
pub(crate) enum CommandLiteralError {
    TooLarge,
    Literal8,
    NonSyncLiteral8,
    InvalidUtf8,
    Eof,
    Io,
}

pub(crate) async fn read_textual_command_literals(
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
