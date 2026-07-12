use std::path::Path;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

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

    let mut literal = vec![0; request.literal_len];
    if let Err(error) = reader.read_exact(&mut literal).await {
        write_response(
            reader,
            Response::new().status(
                StatusLine::tagged(tag, Status::No, format!("Error reading literal: {error}"))
                    .with_code("UNAVAILABLE"),
            ),
        )
        .await?;
        return Ok(failure());
    }
    if request.utf8 && std::str::from_utf8(&literal).is_err() {
        write_response(
            reader,
            Response::new().status(
                StatusLine::tagged(tag, Status::No, "Invalid UTF-8 message").with_code("UTF8"),
            ),
        )
        .await?;
        return Ok(failure());
    }

    let root = mail_root.to_string();
    let mailbox_for_task = mailbox_name.clone();
    let flags = request.flags;
    let internal_date = request
        .internal_date
        .filter(|date| date.timestamp <= chrono::Utc::now().timestamp() + 2 * 60 * 60)
        .map(|date| (date.timestamp, date.timezone_offset_minutes));
    let append = tokio::task::spawn_blocking(move || {
        rmail_common::imap_state::append_message_with_internal_date(
            Path::new(&root),
            &domain,
            &local,
            &mailbox_for_task,
            &literal,
            flags,
            internal_date,
        )
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
