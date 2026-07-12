use std::net::SocketAddr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use rmail_common::auth::{
    LoginExchange, PasswordAuthResult, PasswordSaslExchange, PasswordSaslProgress, PlainExchange,
};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::time::timeout;

use crate::{AUTH_CONTINUATION_TIMEOUT, AsyncStream, protocol};

pub(crate) struct Outcome {
    pub(crate) authenticated_user: Option<String>,
    pub(crate) disconnected: bool,
}

pub(crate) async fn handle_password(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    mechanism: &str,
    initial_response: Option<&str>,
    db_path: Option<&String>,
    peer: Option<SocketAddr>,
) -> Outcome {
    let mut exchange: Box<dyn PasswordSaslExchange> = match mechanism {
        "PLAIN" => Box::new(PlainExchange::default()),
        "LOGIN" => Box::new(LoginExchange::default()),
        _ => {
            return failure(
                reader,
                b"504 5.5.4 Unrecognized authentication mechanism\r\n",
            )
            .await;
        }
    };
    let credentials = match run_exchange(reader, exchange.as_mut(), initial_response).await {
        Ok(credentials) => credentials,
        Err(ExchangeError::Disconnected) => {
            return Outcome {
                authenticated_user: None,
                disconnected: true,
            };
        }
        Err(ExchangeError::Timeout) => {
            return failure(reader, b"454 4.7.0 Authentication exchange timed out\r\n").await;
        }
        Err(ExchangeError::Cancelled) => {
            return failure(reader, b"501 5.7.0 Authentication canceled\r\n").await;
        }
        Err(ExchangeError::TooLong) => {
            return failure(reader, b"500 5.5.2 AUTH response line too long\r\n").await;
        }
        Err(ExchangeError::Invalid) => {
            return failure(reader, b"501 5.5.2 Invalid AUTH response\r\n").await;
        }
    };

    let normalized_authcid =
        rmail_common::auth::saslprep(&credentials.authcid).to_ascii_lowercase();
    if credentials.authzid.as_ref().is_some_and(|authzid| {
        rmail_common::auth::saslprep(authzid).to_ascii_lowercase() != normalized_authcid
    }) {
        record_failure(peer);
        return failure(
            reader,
            b"535 5.7.8 Authorization identity is not permitted\r\n",
        )
        .await;
    }

    match rmail_common::auth::authenticate_password(
        db_path,
        &normalized_authcid,
        &credentials.password,
    )
    .await
    {
        PasswordAuthResult::Success(mailbox) => {
            if let Some(peer) = peer {
                crate::reset_auth_failures(peer.ip());
            }
            if write_reply(reader, b"235 2.7.0 Authentication succeeded\r\n")
                .await
                .is_err()
            {
                return Outcome {
                    authenticated_user: None,
                    disconnected: true,
                };
            }
            Outcome {
                authenticated_user: Some(mailbox.address.to_ascii_lowercase()),
                disconnected: false,
            }
        }
        PasswordAuthResult::Rejected => {
            record_failure(peer);
            failure(reader, b"535 5.7.8 Authentication credentials invalid\r\n").await
        }
        PasswordAuthResult::Unavailable { mailbox, message } => {
            eprintln!(
                "SMTP AUTH {mechanism} verification error peer={peer:?} mailbox={} err={message}",
                mailbox
                    .as_ref()
                    .map(|mailbox| mailbox.address.as_str())
                    .unwrap_or("-")
            );
            failure(reader, b"454 4.7.0 Temporary authentication failure\r\n").await
        }
    }
}

pub(crate) async fn handle_scram(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    initial_response: Option<&str>,
    db_path: Option<&String>,
    peer: Option<SocketAddr>,
) -> Outcome {
    let first_wire = match initial_response {
        Some(response) => response.to_string(),
        None => {
            if write_reply(reader, b"334 \r\n").await.is_err() {
                return disconnected();
            }
            match read_response(reader).await {
                Ok(response) => response,
                Err(error) => return exchange_failure(reader, error).await,
            }
        }
    };
    let first_message = match decode_sasl_message(&first_wire) {
        Some(message) => message,
        None => return failure(reader, b"501 5.5.2 Invalid SCRAM client-first message\r\n").await,
    };
    let client_first = match rmail_common::auth::parse_scram_client_first(&first_message, false) {
        Some(first) => first,
        None => return failure(reader, b"501 5.5.2 Invalid SCRAM client-first message\r\n").await,
    };
    let user = rmail_common::auth::saslprep(&client_first.username).to_ascii_lowercase();
    if client_first
        .authzid
        .as_ref()
        .is_some_and(|authzid| rmail_common::auth::saslprep(authzid).to_ascii_lowercase() != user)
    {
        record_failure(peer);
        return failure(
            reader,
            b"535 5.7.8 Authorization identity is not permitted\r\n",
        )
        .await;
    }
    let mailbox = match rmail_common::auth::lookup_mailbox(db_path, &user).await {
        Ok(Some(mailbox)) => mailbox,
        Ok(None) => {
            record_failure(peer);
            return failure(reader, b"535 5.7.8 Authentication credentials invalid\r\n").await;
        }
        Err(error) => {
            eprintln!("SMTP SCRAM mailbox lookup error peer={peer:?}: {error}");
            return failure(reader, b"454 4.7.0 Temporary authentication failure\r\n").await;
        }
    };
    let Some(verifier) = mailbox.scram.as_ref() else {
        record_failure(peer);
        return failure(reader, b"535 5.7.8 Authentication credentials invalid\r\n").await;
    };
    let (salt, iterations) = match rmail_common::auth::parse_scram_verifier(verifier) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!(
                "SMTP SCRAM verifier parse error peer={peer:?} mailbox={} err={error}",
                mailbox.address
            );
            return failure(reader, b"454 4.7.0 Temporary authentication failure\r\n").await;
        }
    };
    let nonce = format!(
        "{}{}",
        client_first.nonce,
        rmail_common::auth::generate_scram_nonce()
    );
    let server_first = format!("r={nonce},s={salt},i={iterations}");
    let challenge = format!("334 {}\r\n", BASE64_ENGINE.encode(server_first.as_bytes()));
    if write_reply(reader, challenge.as_bytes()).await.is_err() {
        return disconnected();
    }
    let final_wire = match read_response(reader).await {
        Ok(response) => response,
        Err(error) => return exchange_failure(reader, error).await,
    };
    let final_message = match decode_sasl_message(&final_wire) {
        Some(message) => message,
        None => return failure(reader, b"501 5.5.2 Invalid SCRAM client-final message\r\n").await,
    };
    let client_final = match rmail_common::auth::parse_scram_client_final(&final_message) {
        Some(final_message) => final_message,
        None => return failure(reader, b"501 5.5.2 Invalid SCRAM client-final message\r\n").await,
    };
    let expected_binding = BASE64_ENGINE.encode(client_first.gs2_header.as_bytes());
    if client_final.nonce != nonce || client_final.channel_binding != expected_binding {
        record_failure(peer);
        return failure(reader, b"535 5.7.8 Authentication credentials invalid\r\n").await;
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
                "SMTP SCRAM proof error peer={peer:?} mailbox={} err={error}",
                mailbox.address
            );
            return failure(reader, b"535 5.7.8 Authentication credentials invalid\r\n").await;
        }
    };
    let server_final =
        BASE64_ENGINE.encode(format!("v={}", BASE64_ENGINE.encode(server_signature)).as_bytes());
    if write_reply(reader, format!("235 2.7.0 {server_final}\r\n").as_bytes())
        .await
        .is_err()
    {
        return disconnected();
    }
    if let Some(peer) = peer {
        crate::reset_auth_failures(peer.ip());
    }
    Outcome {
        authenticated_user: Some(mailbox.address.to_ascii_lowercase()),
        disconnected: false,
    }
}

fn decode_sasl_message(response: &str) -> Option<String> {
    if response == "=" {
        return Some(String::new());
    }
    String::from_utf8(BASE64_ENGINE.decode(response).ok()?).ok()
}

async fn run_exchange(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    exchange: &mut dyn PasswordSaslExchange,
    initial_response: Option<&str>,
) -> Result<rmail_common::auth::SaslCredentials, ExchangeError> {
    let mut progress = exchange
        .start(initial_response)
        .map_err(|_| ExchangeError::Invalid)?;
    loop {
        match progress {
            PasswordSaslProgress::Credentials(credentials) => return Ok(credentials),
            PasswordSaslProgress::Challenge(challenge) => {
                write_reply(reader, format!("334 {challenge}\r\n").as_bytes())
                    .await
                    .map_err(|_| ExchangeError::Disconnected)?;
                let response = read_response(reader).await?;
                progress = exchange
                    .receive(&response)
                    .map_err(|_| ExchangeError::Invalid)?;
            }
        }
    }
}

async fn read_response(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
) -> Result<String, ExchangeError> {
    let line = match timeout(
        AUTH_CONTINUATION_TIMEOUT,
        protocol::read_bounded_line(reader, protocol::MAX_AUTH_LINE_BYTES),
    )
    .await
    {
        Err(_) => return Err(ExchangeError::Timeout),
        Ok(Err(_)) | Ok(Ok(protocol::BoundedLine::Eof)) => {
            return Err(ExchangeError::Disconnected);
        }
        Ok(Ok(protocol::BoundedLine::TooLong)) => return Err(ExchangeError::TooLong),
        Ok(Ok(protocol::BoundedLine::Line(line))) => line,
    };
    let response = std::str::from_utf8(&line)
        .map_err(|_| ExchangeError::Invalid)?
        .trim_end_matches(['\r', '\n']);
    if response == "*" {
        Err(ExchangeError::Cancelled)
    } else {
        Ok(response.to_string())
    }
}

async fn write_reply(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    reply: &[u8],
) -> std::io::Result<()> {
    reader.get_mut().write_all(reply).await?;
    reader.get_mut().flush().await
}

async fn failure(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    reply: &[u8],
) -> Outcome {
    let disconnected = write_reply(reader, reply).await.is_err();
    Outcome {
        authenticated_user: None,
        disconnected,
    }
}

fn disconnected() -> Outcome {
    Outcome {
        authenticated_user: None,
        disconnected: true,
    }
}

async fn exchange_failure(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    error: ExchangeError,
) -> Outcome {
    match error {
        ExchangeError::Cancelled => failure(reader, b"501 5.7.0 Authentication canceled\r\n").await,
        ExchangeError::Disconnected => disconnected(),
        ExchangeError::Invalid => failure(reader, b"501 5.5.2 Invalid AUTH response\r\n").await,
        ExchangeError::Timeout => {
            failure(reader, b"454 4.7.0 Authentication exchange timed out\r\n").await
        }
        ExchangeError::TooLong => {
            failure(reader, b"500 5.5.2 AUTH response line too long\r\n").await
        }
    }
}

fn record_failure(peer: Option<SocketAddr>) {
    if let Some(peer) = peer {
        crate::record_auth_failure(peer.ip());
    }
}

enum ExchangeError {
    Cancelled,
    Disconnected,
    Invalid,
    Timeout,
    TooLong,
}
