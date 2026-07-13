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
    let mut file = match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
    {
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
    pub(crate) close_connection: bool,
}

pub(crate) async fn handle(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    tag: &str,
    raw_args: &str,
    mail_root: &str,
    address: &str,
    utf8_accept: bool,
    selected_mailbox: Option<&str>,
) -> Result<Outcome> {
    if let Some((prefix, parts)) = split_catenate_args(raw_args) {
        return handle_catenate(
            reader,
            tag,
            prefix,
            parts,
            mail_root,
            address,
            utf8_accept,
            selected_mailbox,
        )
        .await;
    }
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
                close_connection: false,
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

fn split_catenate_args(args: &str) -> Option<(&str, &str)> {
    let bytes = args.as_bytes();
    let mut quoted = false;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
        } else if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if !quoted && byte == b'(' {
            depth += 1;
        } else if !quoted && byte == b')' {
            depth = depth.saturating_sub(1);
        } else if !quoted && depth == 0 && byte.is_ascii_alphabetic() {
            let start = index;
            while index < bytes.len() && bytes[index].is_ascii_alphabetic() {
                index += 1;
            }
            if args[start..index].eq_ignore_ascii_case("CATENATE")
                && bytes
                    .get(start.wrapping_sub(1))
                    .is_none_or(u8::is_ascii_whitespace)
                && bytes.get(index).is_none_or(u8::is_ascii_whitespace)
            {
                return Some((args[..start].trim_end(), args[index..].trim_start()));
            }
            continue;
        }
        index += 1;
    }
    None
}

#[allow(clippy::too_many_arguments)]
async fn handle_catenate(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    tag: &str,
    prefix: &str,
    initial_parts: &str,
    mail_root: &str,
    address: &str,
    utf8_accept: bool,
    selected_mailbox: Option<&str>,
) -> Result<Outcome> {
    let request = match parser::parse_append_args(&format!("{prefix} {{0+}}")) {
        Ok(request) if !request.utf8 => request,
        Ok(_) | Err(_) => {
            write_response(reader, bad(tag, "Invalid CATENATE arguments")).await?;
            return Ok(failure());
        }
    };
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
    let root = mail_root.to_string();
    let check_root = root.clone();
    let check_domain = domain.clone();
    let check_local = local.clone();
    let check_mailbox = mailbox_name.clone();
    let exists = tokio::task::spawn_blocking(move || {
        rmail_common::imap_state::folder_exists(
            Path::new(&check_root),
            &check_domain,
            &check_local,
            &check_mailbox,
        )
    })
    .await??;
    if !exists {
        write_response(reader, missing_mailbox(tag)).await?;
        return Ok(failure());
    }

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

    let result = stream_catenate_parts(
        reader,
        initial_parts,
        &staged_path,
        mail_root,
        &domain,
        &local,
        selected_mailbox,
    )
    .await;
    if let Err(error) = result {
        let _ = tokio::fs::remove_file(&staged_path).await;
        let close_connection = matches!(error, CatenateError::TooBigDesynchronized);
        let response = match error {
            CatenateError::BadUrl(url) => Response::new().status(
                StatusLine::tagged(tag, Status::No, "CATENATE URL could not be resolved")
                    .with_code(format!("BADURL {}", quote_response_code(&url))),
            ),
            CatenateError::TooBig => Response::new().status(
                StatusLine::tagged(tag, Status::No, "CATENATE result is too large")
                    .with_code("TOOBIG"),
            ),
            CatenateError::TooBigDesynchronized => Response::new().status(
                StatusLine::tagged(tag, Status::No, "CATENATE result is too large")
                    .with_code("TOOBIG"),
            ),
            CatenateError::Syntax => bad(tag, "Invalid CATENATE arguments"),
            CatenateError::Io(error) => unavailable(tag, error),
        };
        write_response(reader, response).await?;
        return Ok(Outcome {
            appended_mailbox: None,
            close_connection,
        });
    }

    let flags = request.flags;
    let internal_date = request
        .internal_date
        .filter(|date| date.timestamp <= chrono::Utc::now().timestamp() + 2 * 60 * 60)
        .map(|date| (date.timestamp, date.timezone_offset_minutes));
    let mailbox_for_task = mailbox_name.clone();
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
                    StatusLine::tagged(tag, Status::Ok, "CATENATE APPEND completed")
                        .with_code(format!("APPENDUID {uidvalidity} {uid}")),
                ),
            )
            .await?;
            Ok(Outcome {
                appended_mailbox: Some(mailbox_name),
                close_connection: false,
            })
        }
        Err(error) => {
            write_response(reader, unavailable(tag, error)).await?;
            Ok(failure())
        }
    }
}

#[derive(Debug)]
enum CatenateError {
    Syntax,
    TooBig,
    TooBigDesynchronized,
    BadUrl(String),
    Io(std::io::Error),
}

async fn stream_catenate_parts(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    initial_parts: &str,
    staged_path: &Path,
    mail_root: &str,
    domain: &str,
    local: &str,
    selected_mailbox: Option<&str>,
) -> std::result::Result<(), CatenateError> {
    let mut tail = initial_parts.trim().to_string();
    if !tail.starts_with('(') {
        return Err(CatenateError::Syntax);
    }
    tail.remove(0);
    let mut total = 0usize;
    let mut parts = 0usize;
    loop {
        let remaining = tail.trim_start();
        if let Some(after) = remaining.strip_prefix(')') {
            if parts == 0 || !after.trim().is_empty() {
                return Err(CatenateError::Syntax);
            }
            return Ok(());
        }
        if atom_prefix(remaining, "URL") {
            let argument = remaining[3..].trim_start();
            let (url, after) =
                if let Some((length, non_sync)) = parse_catenate_literal_marker(argument) {
                    if length > crate::MAX_AUTHENTICATED_LINE_BYTES {
                        return Err(if non_sync {
                            CatenateError::TooBigDesynchronized
                        } else {
                            CatenateError::TooBig
                        });
                    }
                    if !non_sync {
                        reader
                            .get_mut()
                            .write_all(b"+ Ready for URL literal data\r\n")
                            .await
                            .map_err(CatenateError::Io)?;
                        reader.get_mut().flush().await.map_err(CatenateError::Io)?;
                    }
                    let mut bytes = vec![0; length];
                    reader
                        .read_exact(&mut bytes)
                        .await
                        .map_err(CatenateError::Io)?;
                    let url = String::from_utf8(bytes).map_err(|_| CatenateError::Syntax)?;
                    let after =
                        match crate::read_bounded_line(reader, crate::MAX_AUTHENTICATED_LINE_BYTES)
                            .await
                            .map_err(CatenateError::Io)?
                        {
                            crate::BoundedLine::Line(line) => {
                                String::from_utf8(line).map_err(|_| CatenateError::Syntax)?
                            }
                            crate::BoundedLine::Eof | crate::BoundedLine::TooLong => {
                                return Err(CatenateError::Syntax);
                            }
                        };
                    (url, after)
                } else if let Some((url, after)) = parse_catenate_astring(argument) {
                    (url, after.to_string())
                } else {
                    return Err(CatenateError::Syntax);
                };
            let bytes = resolve_catenate_url(mail_root, domain, local, selected_mailbox, &url)
                .await
                .map_err(|_| CatenateError::BadUrl(url.clone()))?;
            total = total
                .checked_add(bytes.len())
                .ok_or(CatenateError::TooBig)?;
            if total > MAX_APPEND_LITERAL_BYTES {
                return Err(CatenateError::TooBig);
            }
            append_stage_bytes(staged_path, &bytes).await?;
            parts += 1;
            tail = after;
            continue;
        }
        if atom_prefix(remaining, "TEXT") {
            let marker_text = remaining[4..].trim_start();
            let (length, non_sync) =
                parse_catenate_literal_marker(marker_text).ok_or(CatenateError::Syntax)?;
            total = total.checked_add(length).ok_or(CatenateError::TooBig)?;
            if total > MAX_APPEND_LITERAL_BYTES {
                return Err(if non_sync {
                    CatenateError::TooBigDesynchronized
                } else {
                    CatenateError::TooBig
                });
            }
            if !non_sync {
                reader
                    .get_mut()
                    .write_all(b"+ Ready for literal data\r\n")
                    .await
                    .map_err(CatenateError::Io)?;
                reader.get_mut().flush().await.map_err(CatenateError::Io)?;
            }
            stream_literal_to_stage(reader, staged_path, length, false)
                .await
                .map_err(|error| match error {
                    LiteralStreamError::Io(error) => CatenateError::Io(error),
                    LiteralStreamError::InvalidUtf8 => CatenateError::Syntax,
                })?;
            parts += 1;
            tail = match crate::read_bounded_line(reader, crate::MAX_AUTHENTICATED_LINE_BYTES)
                .await
                .map_err(CatenateError::Io)?
            {
                crate::BoundedLine::Line(line) => {
                    String::from_utf8(line).map_err(|_| CatenateError::Syntax)?
                }
                crate::BoundedLine::Eof | crate::BoundedLine::TooLong => {
                    return Err(CatenateError::Syntax);
                }
            };
            continue;
        }
        return Err(CatenateError::Syntax);
    }
}

fn atom_prefix(value: &str, atom: &str) -> bool {
    value
        .get(..atom.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(atom))
        && value
            .as_bytes()
            .get(atom.len())
            .is_some_and(u8::is_ascii_whitespace)
}

fn parse_catenate_literal_marker(value: &str) -> Option<(usize, bool)> {
    let value = value.trim();
    let inner = value.strip_prefix('{')?.strip_suffix('}')?;
    let (digits, non_sync) = inner
        .strip_suffix('+')
        .map_or((inner, false), |digits| (digits, true));
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some((digits.parse().ok()?, non_sync))
}

fn parse_catenate_astring(value: &str) -> Option<(String, &str)> {
    if let Some(mut rest) = value.strip_prefix('"') {
        let mut output = String::new();
        while !rest.is_empty() {
            if let Some(after) = rest.strip_prefix('"') {
                return Some((output, after));
            }
            if let Some(after) = rest.strip_prefix('\\') {
                let character = after.chars().next()?;
                if !matches!(character, '"' | '\\') {
                    return None;
                }
                output.push(character);
                rest = &after[character.len_utf8()..];
            } else {
                let character = rest.chars().next()?;
                if character == '\r' || character == '\n' || character == '\0' {
                    return None;
                }
                output.push(character);
                rest = &rest[character.len_utf8()..];
            }
        }
        None
    } else {
        let end = value
            .find(|character: char| character.is_ascii_whitespace() || character == ')')
            .unwrap_or(value.len());
        (end != 0).then(|| (value[..end].to_string(), &value[end..]))
    }
}

async fn append_stage_bytes(path: &Path, bytes: &[u8]) -> std::result::Result<(), CatenateError> {
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .map_err(CatenateError::Io)?;
    file.write_all(bytes).await.map_err(CatenateError::Io)?;
    file.sync_all().await.map_err(CatenateError::Io)
}

async fn resolve_catenate_url(
    mail_root: &str,
    domain: &str,
    local: &str,
    selected_mailbox: Option<&str>,
    url: &str,
) -> Result<Vec<u8>> {
    let parsed = parse_relative_imap_url(url, selected_mailbox)?;
    let root = mail_root.to_string();
    let domain = domain.to_string();
    let local = local.to_string();
    tokio::task::spawn_blocking(move || {
        let (folder, messages) = rmail_common::imap_state::load_folder(
            Path::new(&root),
            &domain,
            &local,
            &parsed.mailbox,
        )?;
        if parsed
            .uidvalidity
            .is_some_and(|expected| expected != folder.uidvalidity)
        {
            anyhow::bail!("UIDVALIDITY mismatch");
        }
        let message = messages
            .into_iter()
            .find(|message| message.uid == parsed.uid)
            .ok_or_else(|| anyhow::anyhow!("message UID not found"))?;
        if message.size > MAX_APPEND_LITERAL_BYTES as u64 {
            anyhow::bail!("source message exceeds CATENATE size limit");
        }
        let data = std::fs::read(message.path)?;
        parsed.section.map_or(Ok(data.clone()), |section| {
            mailbox::extract_catenate_section(&data, &section)
                .ok_or_else(|| anyhow::anyhow!("message section not found"))
        })
    })
    .await?
}

struct RelativeImapUrl {
    mailbox: String,
    uidvalidity: Option<u64>,
    uid: u64,
    section: Option<String>,
}

fn parse_relative_imap_url(url: &str, selected_mailbox: Option<&str>) -> Result<RelativeImapUrl> {
    if url.contains("://") || url.contains(['\r', '\n', '\0']) {
        anyhow::bail!("absolute or unsafe IMAP URL");
    }
    let mut segments = url.trim_start_matches('/').split("/;");
    let first = segments.next().unwrap_or_default();
    let (mailbox_raw, first_parameter) = first
        .split_once(';')
        .map_or((first, None), |(mailbox, parameter)| {
            (mailbox, Some(parameter))
        });
    let mailbox = if mailbox_raw.is_empty() {
        selected_mailbox
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("relative URL needs a selected mailbox"))?
    } else {
        mailbox::decode_wire_mailbox_name(&percent_decode(mailbox_raw)?, false)?
    };
    let mut uidvalidity = None;
    let mut uid = None;
    let mut section = None;
    for parameter in first_parameter.into_iter().chain(segments) {
        let (name, value) = parameter
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("invalid IMAP URL parameter"))?;
        if name.eq_ignore_ascii_case("UIDVALIDITY") && uidvalidity.is_none() {
            uidvalidity = Some(value.parse()?);
        } else if name.eq_ignore_ascii_case("UID") && uid.is_none() {
            uid = Some(value.parse()?);
        } else if name.eq_ignore_ascii_case("SECTION") && section.is_none() {
            section = Some(percent_decode(value)?);
        } else {
            anyhow::bail!("duplicate or unknown IMAP URL parameter");
        }
    }
    Ok(RelativeImapUrl {
        mailbox,
        uidvalidity,
        uid: uid.ok_or_else(|| anyhow::anyhow!("IMAP URL has no UID"))?,
        section,
    })
}

fn percent_decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = std::str::from_utf8(
                bytes
                    .get(index + 1..index + 3)
                    .ok_or_else(|| anyhow::anyhow!("truncated URL escape"))?,
            )?;
            output.push(u8::from_str_radix(hex, 16)?);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    Ok(String::from_utf8(output)?)
}

fn quote_response_code(value: &str) -> String {
    format!("\"{}\"", value.replace(['\r', '\n', '"', '\\'], "?"))
}

fn failure() -> Outcome {
    Outcome {
        appended_mailbox: None,
        close_connection: false,
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

    #[test]
    fn catenate_prefix_and_relative_urls_are_strict() {
        let (prefix, parts) =
            split_catenate_args("Sent (\\Seen) \"17-Jul-1996 02:44:25 -0700\" CATENATE (TEXT {3+}")
                .unwrap();
        assert_eq!(prefix, "Sent (\\Seen) \"17-Jul-1996 02:44:25 -0700\"");
        assert_eq!(parts, "(TEXT {3+}");
        assert!(split_catenate_args("\"CATENATE\" {3}").is_none());

        let url =
            parse_relative_imap_url("/Drafts;UIDVALIDITY=42/;UID=7/;section=1.MIME", None).unwrap();
        assert_eq!(url.mailbox, "Drafts");
        assert_eq!(url.uidvalidity, Some(42));
        assert_eq!(url.uid, 7);
        assert_eq!(url.section.as_deref(), Some("1.MIME"));
        assert!(parse_relative_imap_url("imap://other.example/INBOX/;UID=1", None).is_err());
        assert!(parse_relative_imap_url("/INBOX/;UID=1/;UID=2", None).is_err());
    }

    #[tokio::test]
    async fn oversized_non_sync_catenate_is_marked_desynchronized_before_reading_payload() {
        let mut reader = buffered_stream(Vec::new());
        let temp = tempfile::tempdir().unwrap();
        let stage = temp.path().join("stage");
        let result = stream_catenate_parts(
            &mut reader,
            &format!("(TEXT {{{}+}}", MAX_APPEND_LITERAL_BYTES + 1),
            &stage,
            temp.path().to_str().unwrap(),
            "example.test",
            "user",
            None,
        )
        .await;
        assert!(matches!(result, Err(CatenateError::TooBigDesynchronized)));
        assert!(!stage.exists());
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
