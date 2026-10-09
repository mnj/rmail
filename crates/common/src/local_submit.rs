//! Sending through this server's own submission service, so mail from
//! webmail, JMAP and released scheduled messages gets exactly the checks,
//! routing, signing and limits of any other authenticated client. The
//! caller authenticates over loopback with the local submission secret as
//! the user it acts for (SASL `X-RMAIL-WEBMAIL`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(120);

/// The loopback address to reach a submission listener: wildcard listeners
/// map to loopback; specific non-loopback addresses cannot be used, since
/// the server only accepts webmail's credential from loopback.
pub fn local_submission_address(listeners: &[String]) -> Option<SocketAddr> {
    listeners.iter().find_map(|listener| {
        let address: SocketAddr = listener.parse().ok()?;
        let ip = match address.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
            ip if ip.is_loopback() => ip,
            _ => return None,
        };
        Some(SocketAddr::new(ip, address.port()))
    })
}

/// A refusal from the submission service, with its reply text, which is
/// meant for the user (such as a refused recipient or a rate limit).
#[derive(Debug)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

struct Client {
    stream: BufReader<TcpStream>,
}

impl Client {
    /// One reply, possibly multi-line: (code, text of the last line).
    async fn reply(&mut self) -> anyhow::Result<(u16, String)> {
        loop {
            let mut line = String::new();
            if self.stream.read_line(&mut line).await? == 0 {
                anyhow::bail!("submission service closed the connection");
            }
            if line.len() < 4 {
                anyhow::bail!("malformed reply from submission service: {line:?}");
            }
            let code: u16 = line[..3].parse()?;
            let text = line[4..].trim_end().to_string();
            if line.as_bytes()[3] != b'-' {
                return Ok((code, text));
            }
        }
    }

    async fn command(&mut self, line: &str) -> anyhow::Result<(u16, String)> {
        self.stream.get_mut().write_all(line.as_bytes()).await?;
        self.stream.get_mut().write_all(b"\r\n").await?;
        self.reply().await
    }

    async fn expect(&mut self, line: &str, code: u16, what: &str) -> anyhow::Result<()> {
        let (got, text) = self.command(line).await?;
        if got != code {
            return Err(Refused(format!("{what}: {got} {text}")).into());
        }
        Ok(())
    }
}

/// Submit `data` from `user` to `recipients`.
pub async fn submit(
    address: SocketAddr,
    mail_root: &Path,
    user: &str,
    recipients: &[String],
    data: &[u8],
) -> anyhow::Result<()> {
    submit_as(address, mail_root, user, user, recipients, data).await
}

/// Submit `data` as the signed-in `user` with envelope sender `mail_from`
/// (an alias of theirs, say); the submission service decides whether the
/// user may use it.
pub async fn submit_as(
    address: SocketAddr,
    mail_root: &Path,
    user: &str,
    mail_from: &str,
    recipients: &[String],
    data: &[u8],
) -> anyhow::Result<()> {
    // Addresses go into SMTP commands; a line break would start another.
    for address in std::iter::once(mail_from).chain(recipients.iter().map(String::as_str)) {
        if !envelope_address(address) {
            return Err(Refused(format!("invalid envelope address {address:?}")).into());
        }
    }
    let key = {
        let mail_root = mail_root.to_path_buf();
        tokio::task::spawn_blocking(move || crate::runtime::webmail_submission_key(&mail_root))
            .await??
    };
    let exchange = async {
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
            .await
            .map_err(|_| anyhow::anyhow!("submission service at {address} did not answer"))??;
        let mut client = Client {
            stream: BufReader::new(stream),
        };
        let (code, text) = client.reply().await?;
        if code != 220 {
            anyhow::bail!("submission service greeting: {code} {text}");
        }
        client
            .expect("EHLO webmail.localhost", 250, "greeting")
            .await?;
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}\0{key}"));
        let (code, text) = client
            .command(&format!("AUTH X-RMAIL-WEBMAIL {token}"))
            .await?;
        if code != 235 {
            anyhow::bail!("submission service refused webmail's credential: {code} {text}");
        }
        let utf8 = !mail_from.is_ascii() || recipients.iter().any(|r| !r.is_ascii());
        client
            .expect(
                &format!(
                    "MAIL FROM:<{mail_from}>{}",
                    if utf8 { " SMTPUTF8" } else { "" }
                ),
                250,
                "sender refused",
            )
            .await?;
        let mut refused = Vec::new();
        for recipient in recipients {
            let (code, text) = client.command(&format!("RCPT TO:<{recipient}>")).await?;
            if code != 250 && code != 251 {
                refused.push(format!("{recipient} ({code} {text})"));
            }
        }
        if !refused.is_empty() {
            let _ = client.command("RSET").await;
            return Err(Refused(format!("recipients refused: {}", refused.join(", "))).into());
        }
        let (code, text) = client.command("DATA").await?;
        if code != 354 {
            return Err(Refused(format!("message refused: {code} {text}")).into());
        }
        let mut body = Vec::with_capacity(data.len() + 64);
        for line in data.split_inclusive(|&b| b == b'\n') {
            if line.first() == Some(&b'.') {
                body.push(b'.');
            }
            body.extend_from_slice(line);
        }
        if !body.ends_with(b"\r\n") {
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(b".\r\n");
        client.stream.get_mut().write_all(&body).await?;
        let (code, text) = client.reply().await?;
        if code != 250 {
            return Err(Refused(format!("message refused: {code} {text}")).into());
        }
        let _ = client.command("QUIT").await;
        Ok(())
    };
    tokio::time::timeout(EXCHANGE_TIMEOUT, exchange)
        .await
        .map_err(|_| anyhow::anyhow!("submission service timed out"))?
}

/// An address that can stand between `<` and `>` in MAIL or RCPT.
fn envelope_address(address: &str) -> bool {
    !address.is_empty()
        && address.len() <= 320
        && address.contains('@')
        && !address
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '<' || c == '>')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_map_to_loopback_and_remote_addresses_are_skipped() {
        let pick = |list: &[&str]| {
            local_submission_address(&list.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        };
        assert_eq!(
            pick(&["0.0.0.0:587"]),
            Some("127.0.0.1:587".parse().unwrap())
        );
        assert_eq!(pick(&["[::]:587"]), Some("[::1]:587".parse().unwrap()));
        assert_eq!(
            pick(&["192.0.2.5:587", "127.0.0.1:2587"]),
            Some("127.0.0.1:2587".parse().unwrap())
        );
        assert_eq!(pick(&["192.0.2.5:587"]), None);
        assert_eq!(pick(&[]), None);
    }

    #[test]
    fn envelope_addresses_cannot_carry_commands() {
        assert!(envelope_address("a@example.test"));
        assert!(!envelope_address("a@example.test>\r\nRCPT TO:<b@x.test"));
        assert!(!envelope_address("a b@example.test"));
        assert!(!envelope_address(""));
    }
}
