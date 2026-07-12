use std::net::SocketAddr;

use tokio::io::{AsyncWriteExt, BufReader};

use crate::{
    AsyncStream, BoundedLine, MAX_SASL_RESPONSE_BYTES, auth, read_bounded_line,
    response::{Response, Status, StatusLine},
};

pub(crate) struct Outcome {
    pub(crate) response: Option<Response>,
    pub(crate) authenticated_mailbox: Option<String>,
    pub(crate) disconnected: bool,
}

pub(crate) async fn handle_password(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    tag: &str,
    mechanism: &str,
    initial: Option<&str>,
    db_path: Option<&String>,
    peer: Option<SocketAddr>,
) -> Outcome {
    let mut exchange: Box<dyn auth::SaslExchange> = match mechanism {
        "PLAIN" => Box::new(auth::PlainExchange::default()),
        "LOGIN" => Box::new(auth::LoginExchange::default()),
        _ => {
            return terminal(
                tag,
                Status::No,
                "Unsupported authentication mechanism",
                None,
            );
        }
    };
    let credentials = match run_password_exchange(reader, exchange.as_mut(), initial).await {
        Ok(credentials) => credentials,
        Err(ProtocolError::Eof) => {
            return Outcome {
                response: None,
                authenticated_mailbox: None,
                disconnected: true,
            };
        }
        Err(ProtocolError::Cancelled) => {
            return terminal(tag, Status::Bad, "AUTHENTICATE cancelled", None);
        }
        Err(ProtocolError::ResponseTooLarge) => {
            return terminal(tag, Status::Bad, "AUTHENTICATE response too large", None);
        }
        Err(ProtocolError::InvalidResponse) => {
            return terminal(
                tag,
                Status::Bad,
                format!("Invalid AUTHENTICATE {mechanism} response"),
                None,
            );
        }
    };

    let user = credentials.authcid;
    if credentials.authzid.as_ref().is_some_and(|authzid| {
        rmail_common::auth::saslprep(authzid).to_ascii_lowercase()
            != rmail_common::auth::saslprep(&user).to_ascii_lowercase()
    }) {
        record_failure(peer);
        return terminal(
            tag,
            Status::No,
            "Authorization identity is not permitted",
            Some("AUTHORIZATIONFAILED"),
        );
    }

    match auth::verify_password(db_path, &user, &credentials.password).await {
        auth::PasswordAuthResult::Success(mailbox) => {
            if let Some(peer) = peer {
                auth::reset_auth_failures(peer.ip());
            }
            Outcome {
                response: Some(Response::new().status(StatusLine::tagged(
                    tag,
                    Status::Ok,
                    "AUTHENTICATE completed",
                ))),
                authenticated_mailbox: Some(mailbox.address.to_ascii_lowercase()),
                disconnected: false,
            }
        }
        auth::PasswordAuthResult::Rejected => {
            record_failure(peer);
            terminal(
                tag,
                Status::No,
                "Authentication failed",
                Some("AUTHENTICATIONFAILED"),
            )
        }
        auth::PasswordAuthResult::Unavailable { mailbox, message } => {
            record_failure(peer);
            eprintln!(
                "IMAP AUTHENTICATE {mechanism} verification error peer={peer:?} mailbox={} err={message}",
                mailbox
                    .as_ref()
                    .map(|mailbox| mailbox.address.as_str())
                    .unwrap_or("-")
            );
            terminal(tag, Status::No, "Authentication error", Some("UNAVAILABLE"))
        }
    }
}

fn record_failure(peer: Option<SocketAddr>) {
    if let Some(peer) = peer {
        auth::record_auth_failure(peer.ip());
    }
}

fn terminal(tag: &str, status: Status, text: impl Into<String>, code: Option<&str>) -> Outcome {
    let mut line = StatusLine::tagged(tag, status, text);
    if let Some(code) = code {
        line = line.with_code(code);
    }
    Outcome {
        response: Some(Response::new().status(line)),
        authenticated_mailbox: None,
        disconnected: false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtocolError {
    Cancelled,
    InvalidResponse,
    ResponseTooLarge,
    Eof,
}

pub(crate) async fn read_response(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
) -> Result<String, ProtocolError> {
    let line = match read_bounded_line(reader, MAX_SASL_RESPONSE_BYTES)
        .await
        .map_err(|_| ProtocolError::Eof)?
    {
        BoundedLine::Eof => return Err(ProtocolError::Eof),
        BoundedLine::TooLong => return Err(ProtocolError::ResponseTooLarge),
        BoundedLine::Line(line) => line,
    };
    let line = std::str::from_utf8(&line)
        .map_err(|_| ProtocolError::InvalidResponse)?
        .trim_end_matches(['\r', '\n']);
    if line == "*" {
        Err(ProtocolError::Cancelled)
    } else {
        Ok(line.to_string())
    }
}

pub(crate) async fn run_password_exchange(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    exchange: &mut dyn auth::SaslExchange,
    initial: Option<&str>,
) -> Result<auth::SaslCredentials, ProtocolError> {
    let mut progress = exchange
        .start(initial)
        .map_err(|_| ProtocolError::InvalidResponse)?;
    loop {
        match progress {
            auth::SaslProgress::Credentials(credentials) => return Ok(credentials),
            auth::SaslProgress::Challenge(challenge) => {
                let continuation = Response::new().continuation(challenge).encode();
                reader
                    .get_mut()
                    .write_all(continuation.as_bytes())
                    .await
                    .map_err(|_| ProtocolError::Eof)?;
                reader
                    .get_mut()
                    .flush()
                    .await
                    .map_err(|_| ProtocolError::Eof)?;
                let line = read_response(reader).await?;
                progress = exchange
                    .receive(&line)
                    .map_err(|_| ProtocolError::InvalidResponse)?;
            }
            auth::SaslProgress::ScramClientFirst(_)
            | auth::SaslProgress::ScramClientFinal(_)
            | auth::SaslProgress::Complete => return Err(ProtocolError::InvalidResponse),
        }
    }
}
