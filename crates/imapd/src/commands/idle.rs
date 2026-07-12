use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::{
    AsyncStream, MAX_AUTHENTICATED_LINE_BYTES,
    mailbox::SelectedMailbox,
    response::{Response, Status, StatusLine},
    sync_selected_mailbox,
};

const SYNC_INTERVAL: Duration = Duration::from_secs(1);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Completed,
    Disconnected,
}

pub(crate) async fn handle(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    tag: &str,
    mail_root: &str,
    selected: &mut Option<SelectedMailbox>,
    qresync_enabled: bool,
) -> Result<Outcome> {
    write(reader, Response::new().continuation("idling")).await?;

    // Synchronize after entering IDLE so changes racing with the continuation
    // cannot be missed before the periodic notification loop starts.
    sync_selected_mailbox(reader, mail_root, selected, qresync_enabled).await?;

    let mut keepalive_elapsed = Duration::ZERO;
    let mut line = Vec::new();
    let mut line_too_long = false;
    loop {
        match read_event(reader, &mut line, &mut line_too_long).await? {
            ReadEvent::Line => {
                let done = std::str::from_utf8(&line)
                    .ok()
                    .map(|line| line.trim_end_matches(['\r', '\n']))
                    .is_some_and(|line| line.eq_ignore_ascii_case("DONE"));
                let response = if done {
                    Response::new().status(StatusLine::tagged(tag, Status::Ok, "IDLE completed"))
                } else {
                    Response::new().status(StatusLine::tagged(tag, Status::Bad, "Expected DONE"))
                };
                write(reader, response).await?;
                return Ok(Outcome::Completed);
            }
            ReadEvent::Eof => return Ok(Outcome::Disconnected),
            ReadEvent::TooLong => {
                write(
                    reader,
                    Response::new().status(StatusLine::tagged(tag, Status::Bad, "Expected DONE")),
                )
                .await?;
                return Ok(Outcome::Completed);
            }
            ReadEvent::Tick => {
                sync_selected_mailbox(reader, mail_root, selected, qresync_enabled).await?;
                keepalive_elapsed += SYNC_INTERVAL;
                if keepalive_elapsed >= KEEPALIVE_INTERVAL {
                    write(
                        reader,
                        Response::new().status(StatusLine::untagged(Status::Ok, "Still here")),
                    )
                    .await?;
                    keepalive_elapsed = Duration::ZERO;
                }
            }
        }
    }
}

enum ReadEvent {
    Line,
    TooLong,
    Eof,
    Tick,
}

async fn read_event(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    line: &mut Vec<u8>,
    too_long: &mut bool,
) -> std::io::Result<ReadEvent> {
    loop {
        let available = match tokio::time::timeout(SYNC_INTERVAL, reader.fill_buf()).await {
            Ok(result) => result?,
            Err(_) => return Ok(ReadEvent::Tick),
        };
        if available.is_empty() {
            return Ok(ReadEvent::Eof);
        }

        let consume = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|index| index + 1)
            .unwrap_or(available.len());
        let found_newline = available.get(consume.saturating_sub(1)) == Some(&b'\n');
        if !*too_long {
            if line.len().saturating_add(consume) > MAX_AUTHENTICATED_LINE_BYTES {
                *too_long = true;
                line.clear();
            } else {
                line.extend_from_slice(&available[..consume]);
            }
        }
        reader.consume(consume);

        if found_newline {
            return Ok(if *too_long {
                ReadEvent::TooLong
            } else {
                ReadEvent::Line
            });
        }
    }
}

async fn write(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    response: Response,
) -> Result<()> {
    reader
        .get_mut()
        .write_all(response.encode().as_bytes())
        .await?;
    reader.get_mut().flush().await?;
    Ok(())
}
