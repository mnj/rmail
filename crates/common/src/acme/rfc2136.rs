//! Minimal RFC 2136 dynamic update client with RFC 8945 TSIG signing, used
//! to add and remove the `_acme-challenge` TXT records.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::TsigAlgorithm;

const TYPE_SOA: u16 = 6;
const TYPE_TXT: u16 = 16;
const TYPE_TSIG: u16 = 250;
const CLASS_IN: u16 = 1;
const CLASS_NONE: u16 = 254;
const CLASS_ANY: u16 = 255;
const OPCODE_UPDATE: u16 = 5;
const TSIG_FUDGE: u16 = 300;
const RECORD_TTL: u32 = 60;
const TIMEOUT: Duration = Duration::from_secs(15);

pub(super) struct TsigKey {
    pub name: String,
    pub secret: Vec<u8>,
    pub algorithm: TsigAlgorithm,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    Add,
    Delete,
}

/// Wire-format domain name, lowercased (canonical form for TSIG).
fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<()> {
    for label in name
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
    {
        if label.len() > 63 {
            bail!("DNS label {label:?} is longer than 63 octets");
        }
        out.push(label.len() as u8);
        out.extend(label.bytes().map(|b| b.to_ascii_lowercase()));
    }
    out.push(0);
    Ok(())
}

fn txt_rdata(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in value.as_bytes().chunks(255) {
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
    }
    if value.is_empty() {
        out.push(0);
    }
    out
}

fn algorithm_name(algorithm: TsigAlgorithm) -> &'static str {
    match algorithm {
        TsigAlgorithm::HmacSha256 => "hmac-sha256.",
        TsigAlgorithm::HmacSha512 => "hmac-sha512.",
    }
}

fn mac(algorithm: TsigAlgorithm, secret: &[u8], data: &[u8]) -> Vec<u8> {
    match algorithm {
        TsigAlgorithm::HmacSha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        TsigAlgorithm::HmacSha512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(secret).expect("HMAC accepts any key");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// Build a signed UPDATE message for `zone` that adds or deletes the given
/// TXT values at `name`.
pub(super) fn build_update(
    id: u16,
    zone: &str,
    name: &str,
    values: &[String],
    action: Action,
    key: &TsigKey,
    time_signed: u64,
) -> Result<Vec<u8>> {
    let mut msg = Vec::with_capacity(512);
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&(OPCODE_UPDATE << 11).to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // ZOCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // PRCOUNT
    msg.extend_from_slice(&(values.len() as u16).to_be_bytes()); // UPCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ADCOUNT (TSIG added below)
    encode_name(zone, &mut msg)?;
    msg.extend_from_slice(&TYPE_SOA.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    for value in values {
        encode_name(name, &mut msg)?;
        msg.extend_from_slice(&TYPE_TXT.to_be_bytes());
        let (class, ttl) = match action {
            Action::Add => (CLASS_IN, RECORD_TTL),
            // RFC 2136 section 2.5.4: delete an RR from an RRset.
            Action::Delete => (CLASS_NONE, 0),
        };
        msg.extend_from_slice(&class.to_be_bytes());
        msg.extend_from_slice(&ttl.to_be_bytes());
        let rdata = txt_rdata(value);
        msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        msg.extend_from_slice(&rdata);
    }

    // RFC 8945 section 4.3.3: MAC over the message and the TSIG variables.
    let mut key_name = Vec::new();
    encode_name(&key.name, &mut key_name)?;
    let mut algorithm = Vec::new();
    encode_name(algorithm_name(key.algorithm), &mut algorithm)?;
    let time = &time_signed.to_be_bytes()[2..8];
    let mut signed = msg.clone();
    signed.extend_from_slice(&key_name);
    signed.extend_from_slice(&CLASS_ANY.to_be_bytes());
    signed.extend_from_slice(&0u32.to_be_bytes());
    signed.extend_from_slice(&algorithm);
    signed.extend_from_slice(time);
    signed.extend_from_slice(&TSIG_FUDGE.to_be_bytes());
    signed.extend_from_slice(&0u16.to_be_bytes()); // error
    signed.extend_from_slice(&0u16.to_be_bytes()); // other len
    let digest = mac(key.algorithm, &key.secret, &signed);

    let mut rdata = Vec::new();
    rdata.extend_from_slice(&algorithm);
    rdata.extend_from_slice(time);
    rdata.extend_from_slice(&TSIG_FUDGE.to_be_bytes());
    rdata.extend_from_slice(&(digest.len() as u16).to_be_bytes());
    rdata.extend_from_slice(&digest);
    rdata.extend_from_slice(&id.to_be_bytes());
    rdata.extend_from_slice(&0u16.to_be_bytes()); // error
    rdata.extend_from_slice(&0u16.to_be_bytes()); // other len

    msg.extend_from_slice(&key_name);
    msg.extend_from_slice(&TYPE_TSIG.to_be_bytes());
    msg.extend_from_slice(&CLASS_ANY.to_be_bytes());
    msg.extend_from_slice(&0u32.to_be_bytes());
    msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    msg.extend_from_slice(&rdata);
    msg[10..12].copy_from_slice(&1u16.to_be_bytes()); // ADCOUNT
    Ok(msg)
}

fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH (TSIG key or signature rejected)",
        10 => "NOTZONE",
        _ => "unknown error",
    }
}

fn server_address(server: &str) -> String {
    let server = server.trim();
    if server.parse::<std::net::SocketAddr>().is_ok() {
        return server.to_string();
    }
    if server.parse::<std::net::IpAddr>().is_ok() {
        return if server.contains(':') {
            format!("[{server}]:53")
        } else {
            format!("{server}:53")
        };
    }
    match server.rsplit_once(':') {
        Some((_, port)) if port.parse::<u16>().is_ok() => server.to_string(),
        _ => format!("{server}:53"),
    }
}

/// Send one update over TCP and check the response code.
pub(super) async fn send_update(
    server: &str,
    zone: &str,
    name: &str,
    values: &[String],
    action: Action,
    key: &TsigKey,
) -> Result<()> {
    let id: u16 = rand::random();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let message = build_update(id, zone, name, values, action, key, now)?;
    let address = server_address(server);
    let exchange = async {
        let mut stream = TcpStream::connect(&address)
            .await
            .with_context(|| format!("connecting to {address}"))?;
        stream
            .write_all(&(message.len() as u16).to_be_bytes())
            .await?;
        stream.write_all(&message).await?;
        let length = stream.read_u16().await.context("reading response length")? as usize;
        let mut response = vec![0u8; length];
        stream
            .read_exact(&mut response)
            .await
            .context("reading response")?;
        Ok::<_, anyhow::Error>(response)
    };
    let response = tokio::time::timeout(TIMEOUT, exchange)
        .await
        .map_err(|_| anyhow!("DNS update to {address} timed out"))??;
    if response.len() < 12 {
        bail!("short DNS update response from {address}");
    }
    if u16::from_be_bytes([response[0], response[1]]) != id || response[2] & 0x80 == 0 {
        bail!("unexpected DNS update response from {address}");
    }
    let rcode = response[3] & 0x0f;
    if rcode != 0 {
        bail!(
            "{address} rejected the update for {name}: {}",
            rcode_name(rcode)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_addresses_default_to_port_53() {
        assert_eq!(server_address("192.0.2.1"), "192.0.2.1:53");
        assert_eq!(server_address("2001:db8::1"), "[2001:db8::1]:53");
        assert_eq!(server_address("[2001:db8::1]:5353"), "[2001:db8::1]:5353");
        assert_eq!(server_address("ns1.example.com"), "ns1.example.com:53");
        assert_eq!(
            server_address("ns1.example.com:5353"),
            "ns1.example.com:5353"
        );
    }

    /// Against a real server, e.g. BIND with
    /// `update-policy { grant <key> name _acme-challenge.<zone>. TXT; };`:
    /// RMAIL_TEST_RFC2136="127.0.0.1:53 example.test hmac-sha256 key-name base64secret"
    #[tokio::test]
    #[ignore = "needs RMAIL_TEST_RFC2136 pointing at a name server"]
    async fn adds_and_deletes_records_on_a_real_server() {
        let spec = std::env::var("RMAIL_TEST_RFC2136").expect("RMAIL_TEST_RFC2136");
        let parts = spec.split_whitespace().collect::<Vec<_>>();
        let [server, zone, algorithm, name, secret] = parts[..] else {
            panic!("expected: server zone algorithm key-name secret");
        };
        let key = TsigKey {
            name: name.to_string(),
            secret: super::super::dns::decode_tsig_secret(secret).unwrap(),
            algorithm: match algorithm {
                "hmac-sha512" => TsigAlgorithm::HmacSha512,
                _ => TsigAlgorithm::HmacSha256,
            },
        };
        let fqdn = format!("_acme-challenge.mail.{zone}");
        let values = vec!["first-value".to_string(), "second-value".to_string()];
        send_update(server, zone, &fqdn, &values, Action::Add, &key)
            .await
            .unwrap();
        send_update(server, zone, &fqdn, &values, Action::Delete, &key)
            .await
            .unwrap();
        let wrong = TsigKey {
            secret: b"wrong".to_vec(),
            ..key
        };
        let error = send_update(server, zone, &fqdn, &values, Action::Add, &wrong)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("NOTAUTH"), "{error}");
    }

    #[test]
    fn update_message_is_signed_over_the_unsigned_message() {
        let key = TsigKey {
            name: "acme-key.".to_string(),
            secret: b"0123456789abcdef0123456789abcdef".to_vec(),
            algorithm: TsigAlgorithm::HmacSha256,
        };
        let values = vec!["token-value".to_string()];
        let msg = build_update(
            0x1234,
            "example.com",
            "_acme-challenge.example.com",
            &values,
            Action::Add,
            &key,
            1_700_000_000,
        )
        .unwrap();
        // Header: id, UPDATE opcode, one zone, one update, one additional.
        assert_eq!(&msg[0..2], &[0x12, 0x34]);
        assert_eq!(&msg[2..4], &[0x28, 0x00]);
        assert_eq!(&msg[4..6], &[0, 1]);
        assert_eq!(&msg[8..10], &[0, 1]);
        assert_eq!(&msg[10..12], &[0, 1]);

        // Recompute the MAC from the message without the TSIG record.
        let mut key_name = Vec::new();
        encode_name(&key.name, &mut key_name).unwrap();
        let tsig_start = msg
            .windows(key_name.len() + 2)
            .rposition(|window| {
                window[..key_name.len()] == key_name[..]
                    && window[key_name.len()..] == TYPE_TSIG.to_be_bytes()
            })
            .unwrap();
        let mut unsigned = msg[..tsig_start].to_vec();
        unsigned[10..12].copy_from_slice(&0u16.to_be_bytes());
        let mut algorithm = Vec::new();
        encode_name("hmac-sha256.", &mut algorithm).unwrap();
        let mut signed = unsigned.clone();
        signed.extend_from_slice(&key_name);
        signed.extend_from_slice(&CLASS_ANY.to_be_bytes());
        signed.extend_from_slice(&0u32.to_be_bytes());
        signed.extend_from_slice(&algorithm);
        signed.extend_from_slice(&1_700_000_000u64.to_be_bytes()[2..8]);
        signed.extend_from_slice(&TSIG_FUDGE.to_be_bytes());
        signed.extend_from_slice(&[0, 0, 0, 0]);
        let expected = mac(TsigAlgorithm::HmacSha256, &key.secret, &signed);
        assert!(
            msg.windows(expected.len()).any(|window| window == expected),
            "TSIG MAC must cover the unsigned message"
        );
        // The TXT value is carried as one character-string.
        assert!(msg.windows(12).any(|w| w == b"\x0btoken-value"));
    }
}
