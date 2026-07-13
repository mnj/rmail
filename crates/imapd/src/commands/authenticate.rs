use std::net::SocketAddr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
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
    authenticated_capabilities: &str,
) -> Outcome {
    let mut exchange: Box<dyn rmail_common::auth::PasswordSaslExchange> = match mechanism {
        "PLAIN" => Box::new(rmail_common::auth::PlainExchange::default()),
        "LOGIN" => Box::new(rmail_common::auth::LoginExchange::default()),
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
        !rmail_common::auth::saslprep(authzid)
            .eq_ignore_ascii_case(&rmail_common::auth::saslprep(&user))
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
                response: Some(
                    Response::new().status(
                        StatusLine::tagged(tag, Status::Ok, "AUTHENTICATE completed")
                            .with_code(format!("CAPABILITY {authenticated_capabilities}")),
                    ),
                ),
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

pub(crate) async fn handle_scram(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    tag: &str,
    initial: Option<&str>,
    db_path: Option<&String>,
    peer: Option<SocketAddr>,
    channel_binding_required: bool,
    tls_server_end_point: Option<&[u8]>,
    authenticated_capabilities: &str,
) -> Outcome {
    let initial = match initial {
        Some(initial) => initial.to_string(),
        None => {
            if write_continuation(reader, "").await.is_err() {
                return disconnected();
            }
            match read_response(reader).await {
                Ok(response) => response,
                Err(error) => return protocol_failure(tag, error, "AUTHENTICATE response"),
            }
        }
    };
    let mut exchange = auth::ScramExchange::new(channel_binding_required);
    let client_first = match auth::SaslExchange::start(&mut exchange, Some(&initial)) {
        Ok(auth::SaslProgress::ScramClientFirst(first)) => first,
        _ => return terminal(tag, Status::Bad, "Invalid SCRAM client-first message", None),
    };
    let user = rmail_common::auth::saslprep(&client_first.username).to_ascii_lowercase();
    if client_first
        .authzid
        .as_ref()
        .is_some_and(|authzid| rmail_common::auth::saslprep(authzid).to_ascii_lowercase() != user)
    {
        record_failure(peer);
        return terminal(
            tag,
            Status::No,
            "Authorization identity is not permitted",
            Some("AUTHORIZATIONFAILED"),
        );
    }
    let mailbox = match auth::lookup_mailbox(db_path, &user).await {
        Ok(Some(mailbox)) => mailbox,
        Ok(None) => {
            record_failure(peer);
            return terminal(
                tag,
                Status::No,
                "Authentication failed",
                Some("AUTHENTICATIONFAILED"),
            );
        }
        Err(error) => {
            eprintln!("IMAP SCRAM mailbox lookup error peer={peer:?}: {error}");
            return terminal(tag, Status::No, "Authentication error", Some("UNAVAILABLE"));
        }
    };
    let Some(verifier) = mailbox.scram.as_ref() else {
        record_failure(peer);
        return terminal(
            tag,
            Status::No,
            "Authentication failed",
            Some("AUTHENTICATIONFAILED"),
        );
    };
    let (salt, iterations) = match rmail_common::auth::parse_scram_verifier(verifier) {
        Ok(verifier) => verifier,
        Err(error) => {
            eprintln!(
                "IMAP SCRAM verifier parse error peer={peer:?} mailbox={} err={error}",
                mailbox.address
            );
            return terminal(tag, Status::No, "Authentication error", Some("UNAVAILABLE"));
        }
    };
    let nonce = format!("{}{}", client_first.nonce, auth::generate_scram_nonce());
    let server_first = format!("r={nonce},s={salt},i={iterations}");
    if write_continuation(reader, &BASE64_ENGINE.encode(server_first.as_bytes()))
        .await
        .is_err()
    {
        return disconnected();
    }
    let final_wire = match read_response(reader).await {
        Ok(response) => response,
        Err(error) => return protocol_failure(tag, error, "SCRAM client-final response"),
    };
    let client_final = match auth::SaslExchange::receive(&mut exchange, &final_wire) {
        Ok(auth::SaslProgress::ScramClientFinal(final_message)) => final_message,
        _ => return terminal(tag, Status::Bad, "Invalid SCRAM client-final message", None),
    };
    let binding_valid = if channel_binding_required {
        tls_server_end_point.is_some_and(|binding| {
            rmail_common::auth::verify_tls_server_end_point_binding(
                &client_first.gs2_header,
                binding,
                &client_final.channel_binding,
            )
            .is_ok()
        })
    } else {
        client_final.channel_binding == BASE64_ENGINE.encode(client_first.gs2_header.as_bytes())
    };
    if client_final.nonce != nonce || !binding_valid {
        record_failure(peer);
        return terminal(
            tag,
            Status::No,
            "Authentication failed",
            Some("AUTHENTICATIONFAILED"),
        );
    }
    let auth_message = format!(
        "{},{},{}",
        client_first.bare, server_first, client_final.without_proof
    );
    let server_signature = match rmail_common::auth::verify_scram_proof(
        verifier,
        &auth_message,
        &client_final.proof,
    ) {
        Ok(signature) => signature,
        Err(error) => {
            record_failure(peer);
            eprintln!(
                "IMAP SCRAM verification error peer={peer:?} mailbox={} err={error}",
                mailbox.address
            );
            return terminal(
                tag,
                Status::No,
                "Authentication failed",
                Some("AUTHENTICATIONFAILED"),
            );
        }
    };
    let server_final =
        BASE64_ENGINE.encode(format!("v={}", BASE64_ENGINE.encode(server_signature)).as_bytes());
    if write_continuation(reader, &server_final).await.is_err() {
        return disconnected();
    }
    if auth::ScramExchange::expect_final_acknowledgment(&mut exchange).is_err() {
        return terminal(tag, Status::Bad, "Invalid SCRAM exchange state", None);
    }
    let acknowledgment = match read_response(reader).await {
        Ok(response) => response,
        Err(ProtocolError::Eof) => return disconnected(),
        Err(ProtocolError::Cancelled) => {
            return terminal(tag, Status::Bad, "AUTHENTICATE cancelled", None);
        }
        Err(_) => return terminal(tag, Status::Bad, "Invalid SCRAM final acknowledgment", None),
    };
    if !matches!(
        auth::SaslExchange::receive(&mut exchange, &acknowledgment),
        Ok(auth::SaslProgress::Complete)
    ) {
        return terminal(tag, Status::Bad, "Invalid SCRAM final acknowledgment", None);
    }
    if let Some(peer) = peer {
        auth::reset_auth_failures(peer.ip());
    }
    Outcome {
        response: Some(
            Response::new().status(
                StatusLine::tagged(tag, Status::Ok, "AUTHENTICATE completed")
                    .with_code(format!("CAPABILITY {authenticated_capabilities}")),
            ),
        ),
        authenticated_mailbox: Some(mailbox.address.to_ascii_lowercase()),
        disconnected: false,
    }
}

fn protocol_failure(tag: &str, error: ProtocolError, context: &str) -> Outcome {
    match error {
        ProtocolError::Eof => disconnected(),
        ProtocolError::Cancelled => terminal(tag, Status::Bad, "AUTHENTICATE cancelled", None),
        ProtocolError::ResponseTooLarge => {
            terminal(tag, Status::Bad, "AUTHENTICATE response too large", None)
        }
        ProtocolError::InvalidResponse => {
            terminal(tag, Status::Bad, format!("Invalid {context}"), None)
        }
    }
}

fn disconnected() -> Outcome {
    Outcome {
        response: None,
        authenticated_mailbox: None,
        disconnected: true,
    }
}

async fn write_continuation(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    challenge: &str,
) -> Result<(), ProtocolError> {
    let response = Response::new().continuation(challenge).encode();
    reader
        .get_mut()
        .write_all(response.as_bytes())
        .await
        .map_err(|_| ProtocolError::Eof)?;
    reader
        .get_mut()
        .flush()
        .await
        .map_err(|_| ProtocolError::Eof)
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
    exchange: &mut dyn rmail_common::auth::PasswordSaslExchange,
    initial: Option<&str>,
) -> Result<rmail_common::auth::SaslCredentials, ProtocolError> {
    let mut progress = exchange
        .start(initial)
        .map_err(|_| ProtocolError::InvalidResponse)?;
    loop {
        match progress {
            rmail_common::auth::PasswordSaslProgress::Credentials(credentials) => {
                return Ok(credentials);
            }
            rmail_common::auth::PasswordSaslProgress::Challenge(challenge) => {
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
        }
    }
}
