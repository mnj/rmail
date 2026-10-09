//! HAProxy PROXY protocol (v1 and v2) for listeners behind a load balancer.
//!
//! Connections from `security.proxy_protocol_trusted_networks` must start
//! with a PROXY header; the address it carries replaces the proxy's own for
//! rate limits, DNSBL, SPF, logs and Received fields. Connections from other
//! addresses are handled as before and never parsed for a header, so a
//! client cannot spoof its address.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::RwLock;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// How long a trusted proxy may take to send its header.
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest v1 header, CRLF included (the spec's limit).
const V1_MAX: usize = 107;
const V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";

/// An address block such as `10.0.0.0/8`, `2001:db8::/32` or a single address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    address: IpAddr,
    prefix: u8,
}

impl Network {
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let address: IpAddr = address
            .parse()
            .with_context(|| format!("invalid network address {text:?}"))?;
        let max = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix
                .parse::<u8>()
                .ok()
                .filter(|prefix| *prefix <= max)
                .with_context(|| format!("invalid prefix length in {text:?}"))?,
            None => max,
        };
        Ok(Self { address, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        // An IPv4 client on a dual-stack socket shows up as ::ffff:a.b.c.d.
        match (self.address, ip.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                prefix_matches(&network.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                prefix_matches(&network.octets(), &ip.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

fn prefix_matches(network: &[u8], ip: &[u8], prefix: u8) -> bool {
    let full = usize::from(prefix / 8);
    if network[..full] != ip[..full] {
        return false;
    }
    let rest = prefix % 8;
    rest == 0 || {
        let mask = 0xffu8 << (8 - rest);
        network[full] & mask == ip[full] & mask
    }
}

static TRUSTED: RwLock<Vec<Network>> = RwLock::new(Vec::new());

/// Set the proxy networks whose connections carry a PROXY header.
pub fn set_trusted_networks(networks: &[String]) -> Result<()> {
    let parsed = networks
        .iter()
        .map(|network| Network::parse(network))
        .collect::<Result<Vec<_>>>()?;
    *TRUSTED.write().unwrap() = parsed;
    Ok(())
}

pub fn is_trusted_proxy(ip: IpAddr) -> bool {
    TRUSTED
        .read()
        .unwrap()
        .iter()
        .any(|network| network.contains(ip))
}

/// Read a PROXY header from the start of `stream`. Returns the client
/// address it carries, or `None` for `UNKNOWN` (v1) and `LOCAL` (v2)
/// connections such as proxy health checks. Reads exactly the header.
pub async fn read_header<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Option<SocketAddr>> {
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await?;
    match first[0] {
        b'P' => read_v1(stream).await,
        b'\r' => read_v2(stream).await,
        _ => bail!("connection from a trusted proxy did not start with a PROXY header"),
    }
}

async fn read_v1<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Option<SocketAddr>> {
    let mut line = vec![b'P'];
    while !line.ends_with(b"\r\n") {
        if line.len() >= V1_MAX {
            bail!("PROXY v1 header is too long");
        }
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        line.push(byte[0]);
    }
    let line = std::str::from_utf8(&line[..line.len() - 2]).context("PROXY v1 header")?;
    let fields = line.split(' ').collect::<Vec<_>>();
    match fields.as_slice() {
        ["PROXY", "UNKNOWN", ..] => Ok(None),
        [
            "PROXY",
            family @ ("TCP4" | "TCP6"),
            source,
            _destination,
            port,
            _,
        ] => {
            let ip: IpAddr = source.parse().context("PROXY v1 source address")?;
            if ip.is_ipv4() != (*family == "TCP4") {
                bail!("PROXY v1 address does not match {family}");
            }
            let port: u16 = port.parse().context("PROXY v1 source port")?;
            Ok(Some(SocketAddr::new(ip, port)))
        }
        _ => bail!("malformed PROXY v1 header"),
    }
}

async fn read_v2<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Option<SocketAddr>> {
    let mut header = [0u8; 15];
    stream.read_exact(&mut header).await?;
    if header[..11] != V2_SIGNATURE[1..] {
        bail!("malformed PROXY v2 signature");
    }
    let version_command = header[11];
    let family = header[12];
    let length = usize::from(u16::from_be_bytes([header[13], header[14]]));
    if version_command >> 4 != 2 {
        bail!("unsupported PROXY protocol version");
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await?;
    match version_command & 0x0f {
        // LOCAL: the proxy's own connection, e.g. a health check.
        0 => return Ok(None),
        1 => {}
        _ => bail!("unsupported PROXY v2 command"),
    }
    match family {
        // TCP over IPv4: source, destination, source port, destination port.
        0x11 if length >= 12 => {
            let ip = std::net::Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let port = u16::from_be_bytes([body[8], body[9]]);
            Ok(Some(SocketAddr::new(ip.into(), port)))
        }
        0x21 if length >= 36 => {
            let octets: [u8; 16] = body[..16].try_into().unwrap();
            let port = u16::from_be_bytes([body[32], body[33]]);
            Ok(Some(SocketAddr::new(
                std::net::Ipv6Addr::from(octets).into(),
                port,
            )))
        }
        // UNSPEC and non-TCP transports carry no usable client address.
        0x00 => Ok(None),
        _ => bail!("unsupported PROXY v2 address family"),
    }
}

/// Accepts connections on a listener, resolving PROXY headers from trusted
/// proxies off the accept path so a slow proxy cannot stall the listener.
pub struct ClientAcceptor {
    clients: mpsc::Receiver<(TcpStream, SocketAddr)>,
    task: JoinHandle<()>,
}

impl ClientAcceptor {
    pub fn new(listener: TcpListener, component: &'static str, address: String) -> Self {
        let (sender, clients) = mpsc::channel(64);
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, peer) =
                    crate::net::accept_retrying(&listener, component, &address).await;
                if !is_trusted_proxy(peer.ip()) {
                    if sender.send((stream, peer)).await.is_err() {
                        return;
                    }
                    continue;
                }
                let sender = sender.clone();
                let address = address.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(HEADER_TIMEOUT, read_header(&mut stream)).await {
                        Ok(Ok(client)) => {
                            // LOCAL and UNKNOWN headers carry no client
                            // address. The proxy's own address would hand
                            // the client its trust (a loopback proxy makes
                            // every such client local), so use the
                            // unspecified address, which earns none.
                            let client = client.unwrap_or_else(|| {
                                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                            });
                            let _ = sender.send((stream, client)).await;
                        }
                        Ok(Err(error)) => {
                            crate::structured_log!("warn", component, "proxy_header_rejected", {
                                "listener": address,
                                "proxy": peer.to_string(),
                                "error": format!("{error:#}"),
                            });
                        }
                        Err(_) => {
                            crate::structured_log!("warn", component, "proxy_header_rejected", {
                                "listener": address,
                                "proxy": peer.to_string(),
                                "error": "timed out waiting for the PROXY header",
                            });
                        }
                    }
                });
            }
        });
        Self { clients, task }
    }

    /// The next client connection and its address.
    pub async fn accept(&mut self) -> (TcpStream, SocketAddr) {
        match self.clients.recv().await {
            Some(client) => client,
            // The accept task never ends while the acceptor holds the receiver.
            None => std::future::pending().await,
        }
    }
}

impl Drop for ClientAcceptor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn parse(bytes: &[u8]) -> Result<Option<SocketAddr>> {
        let mut input = bytes;
        read_header(&mut input).await
    }

    #[test]
    fn networks_match_by_prefix() {
        let v4 = Network::parse("10.1.0.0/16").unwrap();
        assert!(v4.contains("10.1.200.3".parse().unwrap()));
        assert!(!v4.contains("10.2.0.1".parse().unwrap()));
        assert!(v4.contains("::ffff:10.1.0.9".parse().unwrap()));
        let odd = Network::parse("192.0.2.128/25").unwrap();
        assert!(odd.contains("192.0.2.200".parse().unwrap()));
        assert!(!odd.contains("192.0.2.100".parse().unwrap()));
        let v6 = Network::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8:1::1".parse().unwrap()));
        assert!(!v6.contains("10.1.0.1".parse().unwrap()));
        assert_eq!(
            Network::parse("192.0.2.7").unwrap(),
            Network::parse("192.0.2.7/32").unwrap()
        );
        assert!(Network::parse("10.0.0.0/33").is_err());
        assert!(Network::parse("example").is_err());
    }

    #[tokio::test]
    async fn v1_headers() {
        assert_eq!(
            parse(b"PROXY TCP4 198.51.100.7 192.0.2.1 40000 25\r\nEHLO x\r\n")
                .await
                .unwrap(),
            Some("198.51.100.7:40000".parse().unwrap())
        );
        assert_eq!(
            parse(b"PROXY TCP6 2001:db8::7 2001:db8::1 40000 993\r\n")
                .await
                .unwrap(),
            Some("[2001:db8::7]:40000".parse().unwrap())
        );
        assert_eq!(parse(b"PROXY UNKNOWN\r\n").await.unwrap(), None);
        assert!(
            parse(b"PROXY TCP4 2001:db8::7 192.0.2.1 1 2\r\n")
                .await
                .is_err()
        );
        assert!(parse(b"EHLO client\r\n").await.is_err());
        assert!(parse(&[b'P'; 200]).await.is_err());
    }

    #[tokio::test]
    async fn v1_reads_only_the_header() {
        let mut input: &[u8] = b"PROXY TCP4 198.51.100.7 192.0.2.1 40000 25\r\nEHLO x\r\n";
        read_header(&mut input).await.unwrap();
        assert_eq!(input, b"EHLO x\r\n");
    }

    #[tokio::test]
    async fn v2_headers() {
        let mut v4 = V2_SIGNATURE.to_vec();
        v4.extend([0x21, 0x11, 0, 12]);
        v4.extend([198, 51, 100, 7, 192, 0, 2, 1]);
        v4.extend(40000u16.to_be_bytes());
        v4.extend(25u16.to_be_bytes());
        v4.extend(b"EHLO x\r\n");
        let mut input = v4.as_slice();
        assert_eq!(
            read_header(&mut input).await.unwrap(),
            Some("198.51.100.7:40000".parse().unwrap())
        );
        assert_eq!(input, b"EHLO x\r\n");

        let mut v6 = V2_SIGNATURE.to_vec();
        v6.extend([0x21, 0x21, 0, 39]);
        let source: std::net::Ipv6Addr = "2001:db8::7".parse().unwrap();
        v6.extend(source.octets());
        v6.extend([0u8; 16]);
        v6.extend(40000u16.to_be_bytes());
        v6.extend(993u16.to_be_bytes());
        v6.extend([0x01, 0x00, 0x00]); // An empty ALPN TLV, skipped.
        assert_eq!(
            parse(&v6).await.unwrap(),
            Some("[2001:db8::7]:40000".parse().unwrap())
        );

        let mut local = V2_SIGNATURE.to_vec();
        local.extend([0x20, 0x00, 0, 0]);
        assert_eq!(parse(&local).await.unwrap(), None);

        let mut truncated = V2_SIGNATURE.to_vec();
        truncated.extend([0x21, 0x11, 0, 4, 1, 2, 3, 4]);
        assert!(parse(&truncated).await.is_err());
    }

    #[tokio::test]
    async fn trusted_proxies_are_resolved_and_others_pass_through() {
        use tokio::io::AsyncWriteExt;
        set_trusted_networks(&["127.0.0.1/32".to_string()]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut acceptor = ClientAcceptor::new(listener, "test", address.to_string());

        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"PROXY TCP4 198.51.100.7 192.0.2.1 40000 25\r\n")
            .await
            .unwrap();
        let (_stream, peer) = acceptor.accept().await;
        assert_eq!(peer, "198.51.100.7:40000".parse().unwrap());

        set_trusted_networks(&[]).unwrap();
        let client = TcpStream::connect(address).await.unwrap();
        let (_stream, peer) = acceptor.accept().await;
        assert_eq!(peer, client.local_addr().unwrap());
    }
}
