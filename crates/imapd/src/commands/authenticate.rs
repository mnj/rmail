use tokio::io::{AsyncWriteExt, BufReader};

use crate::{
    AsyncStream, BoundedLine, MAX_SASL_RESPONSE_BYTES, auth, read_bounded_line, response::Response,
};

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
