use crate::config::SecurityConfig;
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use serde::Deserialize;
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::time::timeout;

const CLAMAV_CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanAction {
    Clean,
    Quarantine,
    Reject,
}

#[derive(Debug, Clone)]
pub struct ScanVerdict {
    pub action: ScanAction,
    pub headers: Vec<(String, String)>,
    pub reason: Option<String>,
}

impl ScanVerdict {
    fn clean() -> Self {
        Self {
            action: ScanAction::Clean,
            headers: Vec::new(),
            reason: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanEnvelope {
    pub mail_from: Option<String>,
    pub rcpts: Vec<String>,
    pub peer_ip: Option<IpAddr>,
    pub helo: Option<String>,
    pub hostname: Option<String>,
    pub user: Option<String>,
}

pub async fn scan_message(
    cfg: &SecurityConfig,
    message: Bytes,
    envelope: &ScanEnvelope,
) -> Result<ScanVerdict> {
    if !cfg.scanners_enabled() {
        return Ok(ScanVerdict::clean());
    }
    if message.len() > cfg.scanner_max_message_bytes {
        bail!("message exceeds scanner_max_message_bytes");
    }

    let duration = Duration::from_millis(cfg.scanner_timeout_ms);
    let mut verdict = ScanVerdict::clean();

    if cfg.clamav_enabled {
        let infected = timeout(duration, scan_clamav(&cfg.clamav_endpoint, &message))
            .await
            .context("ClamAV scan timed out")??;
        if let Some(sig) = infected {
            return Ok(ScanVerdict {
                action: ScanAction::Reject,
                headers: Vec::new(),
                reason: Some(format!("malware detected: {}", sig)),
            });
        }
    }

    if cfg.rspamd_enabled {
        let rspamd = timeout(duration, scan_rspamd(cfg, message.clone(), envelope))
            .await
            .context("Rspamd scan timed out")??;
        if rspamd.action == ScanAction::Reject {
            return Ok(rspamd);
        }
        if rspamd.action == ScanAction::Quarantine {
            verdict.action = ScanAction::Quarantine;
        }
        verdict.headers.extend(rspamd.headers);
        verdict.reason = rspamd.reason;
    }

    Ok(verdict)
}

async fn scan_clamav(endpoint: &str, message: &[u8]) -> Result<Option<String>> {
    enum Conn {
        Unix(UnixStream),
        Tcp(TcpStream),
    }
    impl Conn {
        async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
            match self {
                Conn::Unix(s) => s.write_all(buf).await,
                Conn::Tcp(s) => s.write_all(buf).await,
            }
        }
        async fn read_to_end(&mut self, buf: &mut Vec<u8>) -> std::io::Result<usize> {
            match self {
                Conn::Unix(s) => s.read_to_end(buf).await,
                Conn::Tcp(s) => s.read_to_end(buf).await,
            }
        }
    }

    let mut conn = if let Some(path) = endpoint.strip_prefix("unix:") {
        Conn::Unix(UnixStream::connect(path).await?)
    } else if let Some(addr) = endpoint.strip_prefix("tcp:") {
        Conn::Tcp(TcpStream::connect(addr).await?)
    } else {
        bail!("unsupported ClamAV endpoint: {}", endpoint);
    };

    conn.write_all(b"zINSTREAM\0").await?;
    for chunk in message.chunks(CLAMAV_CHUNK_SIZE) {
        conn.write_all(&(chunk.len() as u32).to_be_bytes()).await?;
        conn.write_all(chunk).await?;
    }
    conn.write_all(&0u32.to_be_bytes()).await?;

    let mut reply = Vec::new();
    conn.read_to_end(&mut reply).await?;
    while reply.last() == Some(&0) {
        reply.pop();
    }
    let text = String::from_utf8_lossy(&reply).trim().to_string();
    if text.ends_with(" OK") || text == "stream: OK" {
        return Ok(None);
    }
    if let Some(found) = text.strip_suffix(" FOUND") {
        let sig = found
            .rsplit_once(": ")
            .map(|(_, sig)| sig)
            .unwrap_or(found)
            .to_string();
        return Ok(Some(sig));
    }
    bail!("unexpected ClamAV response: {}", text);
}

#[derive(Debug, Deserialize)]
struct RspamdResponse {
    action: Option<String>,
    score: Option<f64>,
    required_score: Option<f64>,
    #[serde(default)]
    symbols: serde_json::Value,
}

async fn scan_rspamd(
    cfg: &SecurityConfig,
    message: Bytes,
    envelope: &ScanEnvelope,
) -> Result<ScanVerdict> {
    let client = reqwest::Client::new();
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_LENGTH,
        message.len().to_string().parse()?,
    );
    if let Some(from) = envelope.mail_from.as_deref() {
        headers.insert("From", from.parse()?);
    }
    for rcpt in &envelope.rcpts {
        headers.append("Rcpt", rcpt.parse()?);
    }
    if let Some(ip) = envelope.peer_ip {
        headers.insert("IP", ip.to_string().parse()?);
    }
    if let Some(helo) = envelope.helo.as_deref() {
        headers.insert("Helo", helo.parse()?);
    }
    if let Some(hostname) = envelope.hostname.as_deref() {
        headers.insert("Hostname", hostname.parse()?);
    }
    if let Some(user) = envelope.user.as_deref() {
        headers.insert("User", user.parse()?);
    }

    let resp = client
        .post(&cfg.rspamd_url)
        .headers(headers)
        .body(message)
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("Rspamd returned {}", resp.status());
    }
    let parsed: RspamdResponse = resp.json().await?;
    let action = parsed.action.unwrap_or_else(|| "no action".to_string());
    let action_lc = action.to_ascii_lowercase();
    let reason = Some(format!(
        "rspamd action={} score={:?} required={:?}",
        action, parsed.score, parsed.required_score
    ));

    let headers = vec![
        ("X-Rspamd-Action".to_string(), action.clone()),
        (
            "X-Rspamd-Score".to_string(),
            parsed
                .score
                .map(|s| s.to_string())
                .unwrap_or_else(|| "0".to_string()),
        ),
        (
            "X-Rspamd-Required-Score".to_string(),
            parsed
                .required_score
                .map(|s| s.to_string())
                .unwrap_or_else(|| "0".to_string()),
        ),
        (
            "X-RMail-Spam".to_string(),
            if action_lc == "no action" || action_lc == "greylist" {
                "No".to_string()
            } else {
                "Yes".to_string()
            },
        ),
        (
            "X-Rspamd-Symbols".to_string(),
            parsed.symbols.to_string().replace(['\r', '\n'], " "),
        ),
    ];

    if cfg
        .rspamd_reject_actions
        .iter()
        .any(|a| a.eq_ignore_ascii_case(&action))
    {
        return Ok(ScanVerdict {
            action: ScanAction::Reject,
            headers,
            reason,
        });
    }
    if cfg
        .rspamd_quarantine_actions
        .iter()
        .any(|a| a.eq_ignore_ascii_case(&action))
    {
        return Ok(ScanVerdict {
            action: ScanAction::Quarantine,
            headers,
            reason,
        });
    }
    Ok(ScanVerdict {
        action: ScanAction::Clean,
        headers,
        reason,
    })
}

pub fn prepend_scan_headers(message: Bytes, headers: &[(String, String)]) -> Bytes {
    if headers.is_empty() {
        return message;
    }
    let mut out = Vec::new();
    for (name, value) in headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.replace(['\r', '\n'], " ").as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(&message);
    out.into()
}

#[cfg(test)]
mod tests {
    use super::{ScanAction, ScanEnvelope, prepend_scan_headers, scan_clamav, scan_message};
    use crate::config::SecurityConfig;
    use bytes::Bytes;
    use std::net::IpAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UnixListener};

    async fn read_clamav_stream<S: AsyncReadExt + Unpin>(stream: &mut S) -> Vec<u8> {
        let mut command = vec![0u8; b"zINSTREAM\0".len()];
        stream.read_exact(&mut command).await.expect("command");
        assert_eq!(command, b"zINSTREAM\0");
        let mut body = Vec::new();
        loop {
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.expect("chunk len");
            let len = u32::from_be_bytes(len_buf) as usize;
            if len == 0 {
                break;
            }
            let start = body.len();
            body.resize(start + len, 0);
            stream.read_exact(&mut body[start..]).await.expect("chunk");
        }
        body
    }

    #[test]
    fn unchanged_scan_result_preserves_shared_message_storage() {
        let message = Bytes::from_static(b"Subject: shared\r\n\r\nbody");
        let original = message.as_ptr();
        let unchanged = prepend_scan_headers(message, &[]);

        assert_eq!(unchanged.as_ptr(), original);
        assert_eq!(
            unchanged,
            Bytes::from_static(b"Subject: shared\r\n\r\nbody")
        );
    }

    #[test]
    fn scan_headers_are_prepended_to_shared_message_bytes() {
        let message = Bytes::from_static(b"Subject: scanned\r\n\r\nbody");
        let result = prepend_scan_headers(
            message,
            &[("X-Scan".to_string(), "clean\r\ninjected".to_string())],
        );

        assert_eq!(
            result,
            Bytes::from_static(b"X-Scan: clean  injected\r\nSubject: scanned\r\n\r\nbody")
        );
    }

    #[tokio::test]
    async fn clamav_unix_clean_response() {
        let td = tempfile::tempdir().expect("tempdir");
        let sock = td.path().join("clamd.sock");
        let listener = UnixListener::bind(&sock).expect("bind");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            assert_eq!(read_clamav_stream(&mut stream).await, b"hello");
            stream.write_all(b"stream: OK\0").await.expect("write");
        });

        let verdict = scan_clamav(&format!("unix:{}", sock.display()), b"hello")
            .await
            .expect("scan");
        assert_eq!(verdict, None);
        server.await.expect("server");
    }

    #[tokio::test]
    async fn clamav_tcp_infected_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            assert_eq!(read_clamav_stream(&mut stream).await, b"hello");
            stream
                .write_all(b"stream: Eicar-Test-Signature FOUND\0")
                .await
                .expect("write");
        });

        let verdict = scan_clamav(&format!("tcp:{}", addr), b"hello")
            .await
            .expect("scan");
        assert_eq!(verdict.as_deref(), Some("Eicar-Test-Signature"));
        server.await.expect("server");
    }

    #[tokio::test]
    async fn rspamd_add_header_quarantines_and_sends_envelope_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.expect("read");
            let request = String::from_utf8_lossy(&buf[..n]);
            let request_lc = request.to_ascii_lowercase();
            assert!(request.starts_with("POST /checkv2 "));
            assert!(request_lc.contains("\r\nfrom: sender@example.test\r\n"));
            assert!(request_lc.contains("\r\nrcpt: one@example.test\r\n"));
            assert!(request_lc.contains("\r\nrcpt: two@example.test\r\n"));
            assert!(request_lc.contains("\r\nip: 127.0.0.1\r\n"));
            let body = br#"{"action":"add header","score":7.1,"required_score":6.0,"symbols":{"TEST":{"score":7.1}}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.expect("head");
            stream.write_all(body).await.expect("body");
        });

        let cfg = SecurityConfig {
            rspamd_enabled: true,
            rspamd_url: format!("http://{}/checkv2", addr),
            ..SecurityConfig::default()
        };
        let env = ScanEnvelope {
            mail_from: Some("sender@example.test".to_string()),
            rcpts: vec![
                "one@example.test".to_string(),
                "two@example.test".to_string(),
            ],
            peer_ip: Some(IpAddr::from([127, 0, 0, 1])),
            helo: Some("mx.example.test".to_string()),
            hostname: Some("mx.example.test".to_string()),
            user: Some("user@example.test".to_string()),
        };
        let verdict = scan_message(&cfg, Bytes::from_static(b"Subject: hi\r\n\r\nbody"), &env)
            .await
            .expect("scan");
        assert_eq!(verdict.action, ScanAction::Quarantine);
        assert!(verdict.headers.iter().any(|(k, _)| k == "X-Rspamd-Action"));
        server.await.expect("server");
    }
}
