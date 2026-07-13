use std::path::Path;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

const APPEND_STREAM_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug)]
enum LiteralStreamError {
    Io(std::io::Error),
    InvalidUtf8,
}

#[derive(Debug, Default)]
struct Utf8StreamValidator {
    tail: Vec<u8>,
    invalid: bool,
}

impl Utf8StreamValidator {
    fn push(&mut self, chunk: &[u8]) {
        if self.invalid {
            return;
        }
        let mut combined = Vec::with_capacity(self.tail.len() + chunk.len());
        combined.extend_from_slice(&self.tail);
        combined.extend_from_slice(chunk);
        match std::str::from_utf8(&combined) {
            Ok(_) => self.tail.clear(),
            Err(error) if error.error_len().is_some() => self.invalid = true,
            Err(error) => {
                self.tail.clear();
                self.tail
                    .extend_from_slice(&combined[error.valid_up_to()..]);
                if self.tail.len() > 3 {
                    self.invalid = true;
                }
            }
        }
    }

    fn is_valid(&self) -> bool {
        !self.invalid && self.tail.is_empty()
    }
}

async fn stream_literal_to_stage(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    path: &Path,
    length: usize,
    validate_utf8: bool,
) -> std::result::Result<usize, LiteralStreamError> {
    let mut remaining = length;
    let mut buffer = vec![0_u8; APPEND_STREAM_CHUNK_BYTES.min(length.max(1))];
    let mut file = match tokio::fs::File::create(path).await {
        Ok(file) => file,
        Err(create_error) => {
            while remaining != 0 {
                let chunk_len = remaining.min(buffer.len());
                reader
                    .read_exact(&mut buffer[..chunk_len])
                    .await
                    .map_err(LiteralStreamError::Io)?;
                remaining -= chunk_len;
            }
            return Err(LiteralStreamError::Io(create_error));
        }
    };
    let mut max_chunk = 0;
    let mut validator = Utf8StreamValidator::default();
    let mut write_error = None;
    while remaining != 0 {
        let chunk_len = remaining.min(buffer.len());
        if let Err(error) = reader.read_exact(&mut buffer[..chunk_len]).await {
            return Err(LiteralStreamError::Io(error));
        }
        max_chunk = max_chunk.max(chunk_len);
        if validate_utf8 {
            validator.push(&buffer[..chunk_len]);
        }
        if write_error.is_none()
            && let Err(error) = file.write_all(&buffer[..chunk_len]).await
        {
            write_error = Some(error);
        }
        remaining -= chunk_len;
    }
    if let Some(error) = write_error {
        return Err(LiteralStreamError::Io(error));
    }
    file.sync_all().await.map_err(LiteralStreamError::Io)?;
    if validate_utf8 && !validator.is_valid() {
        return Err(LiteralStreamError::InvalidUtf8);
    }
    Ok(max_chunk)
}

use crate::{
    AsyncStream, MAX_APPEND_LITERAL_BYTES, mailbox, parser,
    response::{Response, Status, StatusLine},
};

pub(crate) struct Outcome {
    pub(crate) appended_mailbox: Option<String>,
}

pub(crate) async fn handle(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    tag: &str,
    raw_args: &str,
    mail_root: &str,
    address: &str,
    utf8_accept: bool,
) -> Result<Outcome> {
    let request = match parser::parse_append_args(raw_args) {
        Ok(request) => request,
        Err(parser::ParseError::InvalidDateTime) => {
            write_response(reader, bad(tag, "Invalid APPEND internal date")).await?;
            return Ok(failure());
        }
        Err(_) => {
            write_response(reader, bad(tag, "Invalid APPEND arguments")).await?;
            return Ok(failure());
        }
    };
    if request.utf8 && !utf8_accept {
        write_response(reader, bad(tag, "UTF8=ACCEPT is not enabled")).await?;
        return Ok(failure());
    }
    if request.literal_len > MAX_APPEND_LITERAL_BYTES {
        write_response(
            reader,
            Response::new().status(
                StatusLine::tagged(tag, Status::No, "APPEND literal too large").with_code("TOOBIG"),
            ),
        )
        .await?;
        return Ok(failure());
    }
    let mailbox_name = match mailbox::decode_wire_mailbox_name(&request.mailbox, utf8_accept) {
        Ok(name) => name,
        Err(_) => {
            write_response(reader, bad(tag, "Invalid mailbox name")).await?;
            return Ok(failure());
        }
    };
    let (local, domain) = match mailbox::address_parts(address) {
        Ok(parts) => parts,
        Err(error) => {
            write_response(reader, unavailable(tag, error)).await?;
            return Ok(failure());
        }
    };

    if !request.non_sync {
        let root = mail_root.to_string();
        let domain_for_check = domain.clone();
        let local_for_check = local.clone();
        let mailbox_for_check = mailbox_name.clone();
        let exists = tokio::task::spawn_blocking(move || {
            rmail_common::imap_state::folder_exists(
                Path::new(&root),
                &domain_for_check,
                &local_for_check,
                &mailbox_for_check,
            )
        })
        .await;
        let exists = match exists {
            Ok(Ok(exists)) => exists,
            Ok(Err(error)) => {
                write_response(reader, unavailable(tag, error)).await?;
                return Ok(failure());
            }
            Err(error) => {
                write_response(reader, unavailable(tag, error)).await?;
                return Ok(failure());
            }
        };
        if !exists {
            write_response(reader, missing_mailbox(tag)).await?;
            return Ok(failure());
        }
        let continuation = Response::new()
            .continuation("Ready for literal data")
            .encode();
        reader.get_mut().write_all(continuation.as_bytes()).await?;
        reader.get_mut().flush().await?;
    }

    let root = mail_root.to_string();
    let stage_root = root.clone();
    let stage_domain = domain.clone();
    let stage_local = local.clone();
    let staged_path = tokio::task::spawn_blocking(move || {
        rmail_common::imap_state::append_staging_path(
            Path::new(&stage_root),
            &stage_domain,
            &stage_local,
        )
    })
    .await??;
    if let Err(error) =
        stream_literal_to_stage(reader, &staged_path, request.literal_len, request.utf8).await
    {
        let _ = tokio::fs::remove_file(&staged_path).await;
        let response = match error {
            LiteralStreamError::InvalidUtf8 => Response::new().status(
                StatusLine::tagged(tag, Status::No, "Invalid UTF-8 message").with_code("UTF8"),
            ),
            LiteralStreamError::Io(error) => Response::new().status(
                StatusLine::tagged(tag, Status::No, format!("Error reading literal: {error}"))
                    .with_code("UNAVAILABLE"),
            ),
        };
        write_response(reader, response).await?;
        return Ok(failure());
    }

    let mailbox_for_task = mailbox_name.clone();
    let flags = request.flags;
    let internal_date = request
        .internal_date
        .filter(|date| date.timestamp <= chrono::Utc::now().timestamp() + 2 * 60 * 60)
        .map(|date| (date.timestamp, date.timezone_offset_minutes));
    let append = tokio::task::spawn_blocking(move || {
        let result = rmail_common::imap_state::publish_staged_append(
            Path::new(&root),
            &domain,
            &local,
            &mailbox_for_task,
            &staged_path,
            flags,
            internal_date,
        );
        let _ = std::fs::remove_file(&staged_path);
        result
    })
    .await?;
    match append {
        Ok((uidvalidity, uid)) => {
            write_response(
                reader,
                Response::new().status(
                    StatusLine::tagged(tag, Status::Ok, "APPEND completed")
                        .with_code(format!("APPENDUID {uidvalidity} {uid}")),
                ),
            )
            .await?;
            Ok(Outcome {
                appended_mailbox: Some(mailbox_name),
            })
        }
        Err(error) => {
            let message = error.to_string();
            let mut line = StatusLine::tagged(tag, Status::No, format!("APPEND failed: {message}"));
            if message.contains("does not exist") {
                line = line.with_code("TRYCREATE");
            }
            write_response(reader, Response::new().status(line)).await?;
            Ok(failure())
        }
    }
}

fn failure() -> Outcome {
    Outcome {
        appended_mailbox: None,
    }
}

fn bad(tag: &str, text: &str) -> Response {
    Response::new().status(StatusLine::tagged(tag, Status::Bad, text))
}

fn missing_mailbox(tag: &str) -> Response {
    Response::new().status(
        StatusLine::tagged(tag, Status::No, "Mailbox does not exist").with_code("TRYCREATE"),
    )
}

fn unavailable(tag: &str, error: impl std::fmt::Display) -> Response {
    Response::new().status(
        StatusLine::tagged(tag, Status::No, format!("APPEND failed: {error}"))
            .with_code("UNAVAILABLE"),
    )
}

async fn write_response(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    response: Response,
) -> Result<()> {
    let response = response.encode();
    reader.get_mut().write_all(response.as_bytes()).await?;
    reader.get_mut().flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    fn buffered_stream(bytes: Vec<u8>) -> BufReader<Box<dyn AsyncStream + Send + 'static>> {
        let capacity = bytes.len().max(1);
        let (mut writer, reader) = tokio::io::duplex(capacity);
        tokio::spawn(async move {
            writer.write_all(&bytes).await.unwrap();
            writer.shutdown().await.unwrap();
        });
        BufReader::new(Box::new(crate::transport::SwitchableStream::new(Box::new(
            reader,
        ))))
    }

    #[test]
    fn utf8_validator_accepts_split_codepoints_and_rejects_invalid_sequences() {
        let mut validator = Utf8StreamValidator::default();
        validator.push(&[b'a', 0xe2]);
        assert!(!validator.is_valid());
        validator.push(&[0x82]);
        assert!(!validator.is_valid());
        validator.push(&[0xac, b'z']);
        assert!(validator.is_valid());

        validator.push(&[0xff]);
        assert!(!validator.is_valid());
    }

    #[tokio::test]
    async fn streams_large_literal_byte_exactly_in_bounded_chunks() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("staged");
        let mut literal = Vec::with_capacity(2 * 1024 * 1024 + 3);
        literal.extend(std::iter::repeat_n(b'a', APPEND_STREAM_CHUNK_BYTES - 1));
        literal.extend_from_slice("€".as_bytes());
        literal.extend(std::iter::repeat_n(b'b', 2 * 1024 * 1024));
        let mut reader = buffered_stream(literal.clone());

        let max_chunk = stream_literal_to_stage(&mut reader, &path, literal.len(), true)
            .await
            .unwrap();

        assert_eq!(max_chunk, APPEND_STREAM_CHUNK_BYTES);
        assert_eq!(tokio::fs::read(path).await.unwrap(), literal);
    }

    #[tokio::test]
    async fn drains_literal_after_invalid_utf8() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("staged");
        let literal = b"valid\xffremaining";
        let mut input = literal.to_vec();
        input.extend_from_slice(b"A2 NOOP\r\n");
        let mut reader = buffered_stream(input);

        assert!(matches!(
            stream_literal_to_stage(&mut reader, &path, literal.len(), true).await,
            Err(LiteralStreamError::InvalidUtf8)
        ));
        let mut command = String::new();
        reader.read_line(&mut command).await.unwrap();
        assert_eq!(command, "A2 NOOP\r\n");
    }

    #[tokio::test]
    async fn drains_literal_when_staging_file_cannot_be_created() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("missing").join("staged");
        let literal = b"message body";
        let mut input = literal.to_vec();
        input.extend_from_slice(b"A2 NOOP\r\n");
        let mut reader = buffered_stream(input);

        assert!(matches!(
            stream_literal_to_stage(&mut reader, &path, literal.len(), false).await,
            Err(LiteralStreamError::Io(_))
        ));
        let mut command = String::new();
        reader.read_line(&mut command).await.unwrap();
        assert_eq!(command, "A2 NOOP\r\n");
    }
}
