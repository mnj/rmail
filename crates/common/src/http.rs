//! Minimal, bounded HTTP/1.1 request reading shared by the admin and webmail
//! daemons.
//!
//! Both web services speak a deliberately small subset of HTTP/1.1: one
//! request per connection, no chunked request bodies. Every read is bounded in
//! time and size so a slow or malicious client cannot hold a connection open
//! indefinitely or make the server buffer unbounded input.

use std::collections::HashMap;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::Instant;

#[derive(Debug, Clone, Copy)]
pub struct HttpLimits {
    /// Maximum size of the request line plus all headers.
    pub max_header_bytes: usize,
    /// Maximum accepted `Content-Length`.
    pub max_body_bytes: usize,
    /// Deadline for receiving the complete request.
    pub request_timeout: Duration,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            max_header_bytes: 16 * 1024,
            max_body_bytes: 1024 * 1024,
            request_timeout: Duration::from_secs(15),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct HttpRequest {
    pub method: String,
    /// Request target exactly as sent, including any query string.
    pub target: String,
    /// Path component of the target (not percent-decoded).
    pub path: String,
    /// Raw query string without the leading `?`.
    pub query: String,
    /// Header names are lower-cased. Repeated headers keep the last value.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    /// Percent-decoded query parameters.
    pub fn query_params(&self) -> HashMap<String, String> {
        parse_query(&self.query)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpReadError {
    /// The peer closed the connection before sending a request.
    Closed,
    Timeout,
    HeadersTooLarge,
    BodyTooLarge,
    /// Request bodies with `Transfer-Encoding` are not supported.
    UnsupportedTransferEncoding,
    Malformed,
    Io,
}

impl HttpReadError {
    /// Status code to answer with, or `None` when no response should be sent.
    pub fn status(self) -> Option<u16> {
        match self {
            Self::Closed | Self::Io => None,
            Self::Timeout => Some(408),
            Self::HeadersTooLarge => Some(431),
            Self::BodyTooLarge => Some(413),
            Self::UnsupportedTransferEncoding => Some(501),
            Self::Malformed => Some(400),
        }
    }
}

pub async fn read_request<S: AsyncRead + Unpin>(
    stream: &mut S,
    limits: HttpLimits,
) -> Result<HttpRequest, HttpReadError> {
    let deadline = Instant::now() + limits.request_timeout;
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() > limits.max_header_bytes {
            return Err(HttpReadError::HeadersTooLarge);
        }
        let n = read_some(stream, &mut chunk, deadline).await?;
        if n == 0 {
            return Err(if buf.is_empty() {
                HttpReadError::Closed
            } else {
                HttpReadError::Malformed
            });
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    if header_end > limits.max_header_bytes {
        return Err(HttpReadError::HeadersTooLarge);
    }

    let head = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| HttpReadError::Malformed)?
        .to_string();
    let mut lines = head.split("\r\n").filter(|line| !line.is_empty());
    let request_line = lines.next().ok_or(HttpReadError::Malformed)?;
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method.is_empty()
        || !method.bytes().all(|b| b.is_ascii_uppercase())
        || !target.starts_with('/')
        || !version.starts_with("HTTP/1.")
        || parts.next().is_some()
    {
        return Err(HttpReadError::Malformed);
    }

    let mut headers = HashMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(HttpReadError::Malformed)?;
        if name.is_empty() || name.contains(char::is_whitespace) {
            return Err(HttpReadError::Malformed);
        }
        headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
    }
    if headers.contains_key("transfer-encoding") {
        return Err(HttpReadError::UnsupportedTransferEncoding);
    }
    let content_length = match headers.get("content-length") {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| HttpReadError::Malformed)?,
        None => 0,
    };
    if content_length > limits.max_body_bytes {
        return Err(HttpReadError::BodyTooLarge);
    }

    let body_start = header_end + 4;
    let mut body = buf.split_off(body_start.min(buf.len()));
    while body.len() < content_length {
        let n = read_some(stream, &mut chunk, deadline).await?;
        if n == 0 {
            return Err(HttpReadError::Malformed);
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);

    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    Ok(HttpRequest {
        method: method.to_string(),
        target: target.to_string(),
        path: path.to_string(),
        query: query.to_string(),
        headers,
        body,
    })
}

async fn read_some<S: AsyncRead + Unpin>(
    stream: &mut S,
    chunk: &mut [u8],
    deadline: Instant,
) -> Result<usize, HttpReadError> {
    match tokio::time::timeout_at(deadline, stream.read(chunk)).await {
        Ok(Ok(n)) => Ok(n),
        Ok(Err(_)) => Err(HttpReadError::Io),
        Err(_) => Err(HttpReadError::Timeout),
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

pub fn parse_query(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let key = percent_decode(key);
            (!key.is_empty()).then(|| (key, percent_decode(value)))
        })
        .collect()
}

/// Decode `%XX` escapes and `+` (as space). Invalid escapes are kept literally.
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                (Some(hi), Some(lo)) => {
                    out.push(hi << 4 | lo);
                    i += 3;
                    continue;
                }
                _ => out.push(b'%'),
            },
            byte => out.push(byte),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Content Too Large",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    }
}

/// Returns true for socket addresses that only accept connections from the
/// local host.
pub fn is_loopback_bind(addr: &str) -> bool {
    addr.parse::<std::net::SocketAddr>()
        .map(|socket| socket.ip().is_loopback())
        .unwrap_or(false)
}

/// Constant-time byte comparison.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read(input: &[u8], limits: HttpLimits) -> Result<HttpRequest, HttpReadError> {
        let mut stream = input;
        read_request(&mut stream, limits).await
    }

    #[tokio::test]
    async fn parses_request_with_body_and_query() {
        let request = read(
            b"POST /api/x?a=1&b=hello%20world HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nbody",
            HttpLimits::default(),
        )
        .await
        .expect("request");
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/api/x");
        assert_eq!(request.header("host"), Some("h"));
        assert_eq!(request.body, b"body");
        assert_eq!(request.query_params()["b"], "hello world");
    }

    #[tokio::test]
    async fn rejects_oversized_declared_body_without_allocating_it() {
        let error = read(
            b"POST / HTTP/1.1\r\nContent-Length: 99999999999\r\n\r\n",
            HttpLimits::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(error, HttpReadError::BodyTooLarge);
    }

    #[tokio::test]
    async fn rejects_oversized_headers() {
        let mut input = b"GET / HTTP/1.1\r\nX: ".to_vec();
        input.extend(std::iter::repeat_n(b'a', 20_000));
        let error = read(&input, HttpLimits::default()).await.unwrap_err();
        assert_eq!(error, HttpReadError::HeadersTooLarge);
    }

    #[tokio::test]
    async fn rejects_chunked_bodies_and_bad_request_lines() {
        assert_eq!(
            read(
                b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
                HttpLimits::default()
            )
            .await
            .unwrap_err(),
            HttpReadError::UnsupportedTransferEncoding
        );
        assert_eq!(
            read(b"GET nope HTTP/1.1\r\n\r\n", HttpLimits::default())
                .await
                .unwrap_err(),
            HttpReadError::Malformed
        );
    }

    #[tokio::test]
    async fn times_out_slow_clients() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::io::AsyncWriteExt::write_all(&mut client, b"GET / HTTP/1.1\r\n")
            .await
            .unwrap();
        let limits = HttpLimits {
            request_timeout: Duration::from_millis(50),
            ..HttpLimits::default()
        };
        let error = read_request(&mut server, limits).await.unwrap_err();
        assert_eq!(error, HttpReadError::Timeout);
        drop(client);
    }

    #[test]
    fn percent_decoding_handles_invalid_escapes() {
        assert_eq!(percent_decode("a%2Fb"), "a/b");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_bind("127.0.0.1:8080"));
        assert!(is_loopback_bind("[::1]:8080"));
        assert!(!is_loopback_bind("0.0.0.0:8080"));
        assert!(!is_loopback_bind("[::]:8080"));
    }
}
