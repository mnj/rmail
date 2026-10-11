//! Checks on how this server looks to the servers it sends to: whether it
//! can reach them on port 25 at all, whether the address it sends from has
//! reverse DNS that names it, and whether that address is on a blocklist.
//!
//! These are the usual reasons mail from a new server is refused or filed as
//! spam, and none of them shows in the domain's own DNS records (see
//! [`crate::dnscheck`] for those).

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use futures_util::future::join_all;
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::dnsbl;
use crate::dnscheck::{Dns, Host, Lookup, Status};

/// Large mailbox providers whose MX hosts answer on port 25 from anywhere.
/// Reaching any one of them shows that outbound SMTP is not blocked.
const PROBE_DOMAINS: &[&str] = &["gmail.com", "outlook.com"];
const CONNECT_TIMEOUT: Duration = Duration::from_secs(6);
/// Some servers pause before greeting; the port is open either way.
const GREETING_TIMEOUT: Duration = Duration::from_secs(6);
/// A greeting and an EHLO reply fit in far less; the rest is not read.
const MAX_REPLY_BYTES: u64 = 16 * 1024;

/// Blocklists that large receivers consult, with whether they list IPv6.
const BLOCKLISTS: &[(&str, &str, bool)] = &[
    ("zen.spamhaus.org", "Spamhaus ZEN", true),
    ("bl.spamcop.net", "SpamCop", false),
    ("b.barracudacentral.org", "Barracuda", false),
    ("psbl.surriel.com", "PSBL", false),
];

/// Whether other mail servers can be reached on port 25 over one address
/// family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum Reach {
    Open {
        /// The MX host that answered.
        target: String,
        /// The local end of the connection.
        #[serde(skip)]
        local: IpAddr,
        /// This server's address as the other side reported it, when it did.
        #[serde(skip)]
        seen_as: Option<IpAddr>,
    },
    /// Nothing answered: a firewall or the hosting provider drops port 25.
    Blocked { error: String },
    /// The server has no connectivity in this address family.
    Unavailable,
    /// The probe targets could not be resolved, so nothing was tried.
    Unknown { error: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Port25 {
    pub v4: Reach,
    pub v6: Reach,
}

impl Port25 {
    pub fn open(&self) -> bool {
        matches!(self.v4, Reach::Open { .. }) || matches!(self.v6, Reach::Open { .. })
    }
}

/// Where an outbound address was learned from, most trustworthy first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// Reported back by the server the probe connected to.
    Seen,
    /// The public address of this machine's own interface.
    Local,
    /// The host name's address record, for want of anything better.
    Dns,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reverse {
    pub status: Status,
    /// The PTR names found.
    pub names: Vec<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Listed {
    Clean,
    Listed,
    /// The list did not answer, or refused the query.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Blocklist {
    pub zone: &'static str,
    pub name: &'static str,
    pub status: Listed,
    /// The 127.0.0.x answer of a listing.
    pub code: Option<String>,
    pub detail: Option<String>,
}

/// One address this server sends mail from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Address {
    pub address: IpAddr,
    pub source: Source,
    pub reverse: Reverse,
    pub blocklists: Vec<Blocklist>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Deliverability {
    pub port25: Port25,
    pub addresses: Vec<Address>,
}

/// An address other servers could see mail arrive from: not private,
/// loopback, link-local or carrier-grade NAT space.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let shared = v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64;
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || shared)
        }
        // Global unicast is 2000::/3.
        IpAddr::V6(v6) => (v6.segments()[0] & 0xe000) == 0x2000,
    }
}

/// The address in a reply such as `250-mx.example.net at your service,
/// [203.0.113.5]` or `250 Hello [IPv6:2001:db8::1]`.
fn echoed_address(reply: &str) -> Option<IpAddr> {
    reply.split('[').skip(1).find_map(|rest| {
        let inner = rest.split(']').next()?;
        let inner = inner
            .get(..5)
            .filter(|prefix| prefix.eq_ignore_ascii_case("ipv6:"))
            .map_or(inner, |_| &inner[5..]);
        inner.trim().parse().ok()
    })
}

/// Read one SMTP reply (all its continuation lines), or `None` when the peer
/// sends something else or stops.
async fn read_reply<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Option<String> {
    let mut reply = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await.ok()? == 0 {
            return None;
        }
        let bytes = line.as_bytes();
        if bytes.len() < 4 || !bytes[..3].iter().all(u8::is_ascii_digit) {
            return None;
        }
        reply.push_str(&line);
        if bytes[3] != b'-' {
            return Some(reply);
        }
    }
}

/// Greet the server and ask who it thinks we are. Best effort: the port is
/// already known to be open, so any failure here just means "did not say".
async fn ask_own_address(stream: TcpStream, helo: &str) -> Option<IpAddr> {
    let mut reader = BufReader::new(stream.take(MAX_REPLY_BYTES));
    if !read_reply(&mut reader).await?.starts_with("220") {
        return None;
    }
    let ehlo = format!("EHLO {helo}\r\n");
    reader
        .get_mut()
        .get_mut()
        .write_all(ehlo.as_bytes())
        .await
        .ok()?;
    let reply = read_reply(&mut reader).await?;
    // Leave politely; the answer is already in hand.
    let _ = reader.get_mut().get_mut().write_all(b"QUIT\r\n").await;
    reply
        .starts_with("250")
        .then(|| echoed_address(&reply))
        .flatten()
}

/// Whether an error means "this machine has no such network" rather than
/// "something in the way dropped the connection".
fn no_route(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::AddrNotAvailable
    )
}

/// Try one mail server. `target` is only for the report.
async fn knock(target: &str, address: SocketAddr, helo: &str) -> Reach {
    let stream = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) if no_route(&error) => return Reach::Unavailable,
        Ok(Err(error)) => {
            return Reach::Blocked {
                error: format!("{target}: {error}"),
            };
        }
        Err(_) => {
            return Reach::Blocked {
                error: format!("{target}: no answer"),
            };
        }
    };
    let Ok(local) = stream.local_addr().map(|local| local.ip()) else {
        return Reach::Blocked {
            error: format!("{target}: the connection closed at once"),
        };
    };
    let seen_as = tokio::time::timeout(GREETING_TIMEOUT, ask_own_address(stream, helo))
        .await
        .ok()
        .flatten();
    Reach::Open {
        target: target.to_string(),
        local,
        seen_as,
    }
}

/// The best MX host of `domain` and its addresses.
async fn mail_host(dns: &impl Dns, domain: &str) -> Result<(String, Vec<IpAddr>), String> {
    let mut exchanges = match dns.mx(domain).await {
        Lookup::Found(exchanges) => exchanges,
        Lookup::Missing => return Err(format!("{domain} has no MX")),
        Lookup::Failed(error) => return Err(format!("{domain}: {error}")),
    };
    exchanges.sort();
    let host = exchanges.swap_remove(0).1;
    match dns.ips(&host).await {
        Lookup::Found(addresses) => Ok((host, addresses)),
        Lookup::Missing => Err(format!("{host} has no address")),
        Lookup::Failed(error) => Err(format!("{host}: {error}")),
    }
}

/// Combine the answers of every target tried over one address family.
fn summarize(attempts: Vec<Reach>, unresolved: &[String]) -> Reach {
    if let Some(open) = attempts
        .iter()
        .find(|reach| matches!(reach, Reach::Open { .. }))
    {
        return open.clone();
    }
    if attempts.contains(&Reach::Unavailable) {
        return Reach::Unavailable;
    }
    let errors = attempts
        .into_iter()
        .filter_map(|reach| match reach {
            Reach::Blocked { error } => Some(error),
            _ => None,
        })
        .collect::<Vec<_>>();
    if errors.is_empty() {
        Reach::Unknown {
            error: unresolved.join("; "),
        }
    } else {
        Reach::Blocked {
            error: errors.join("; "),
        }
    }
}

/// Connect to well-known mail servers on `port` (25 outside tests) over IPv4
/// and IPv6, to see whether outbound SMTP gets through and from which
/// address.
pub async fn probe_port25(dns: &impl Dns, helo: &str, port: u16) -> Port25 {
    let mut targets = Vec::new();
    let mut unresolved = Vec::new();
    for resolved in join_all(PROBE_DOMAINS.iter().map(|domain| mail_host(dns, domain))).await {
        match resolved {
            Ok(target) => targets.push(target),
            Err(error) => unresolved.push(error),
        }
    }
    let family = |want_v4: bool| {
        let attempts = targets.iter().filter_map(move |(host, addresses)| {
            let address = addresses.iter().find(|ip| ip.is_ipv4() == want_v4)?;
            Some(knock(host, SocketAddr::new(*address, port), helo))
        });
        join_all(attempts)
    };
    let (v4, v6) = tokio::join!(family(true), family(false));
    Port25 {
        v4: summarize(v4, &unresolved),
        // Probe targets without AAAA records say nothing about this server.
        v6: if v6.is_empty() && !targets.is_empty() {
            Reach::Unavailable
        } else {
            summarize(v6, &unresolved)
        },
    }
}

/// The addresses mail leaves from, one per address family in use.
fn outbound_addresses(port25: &Port25, host: &Host) -> Vec<(IpAddr, Source)> {
    let mut addresses = Vec::new();
    for reach in [&port25.v4, &port25.v6] {
        if let Reach::Open { local, seen_as, .. } = reach {
            if let Some(seen) = seen_as.filter(|seen| is_public(*seen)) {
                addresses.push((seen, Source::Seen));
            } else if is_public(*local) {
                addresses.push((*local, Source::Local));
            }
        }
    }
    // Behind NAT with a peer that did not say: the host name's own records
    // are the best remaining guess for the families that are in use.
    if let Lookup::Found(published) = &host.addresses {
        for ip in published {
            let reach = if ip.is_ipv4() { &port25.v4 } else { &port25.v6 };
            let known = addresses
                .iter()
                .any(|(known, _)| known.is_ipv4() == ip.is_ipv4());
            if !known && !matches!(reach, Reach::Unavailable) && is_public(*ip) {
                addresses.push((*ip, Source::Dns));
            }
        }
    }
    addresses
}

/// Forward-confirmed reverse DNS: the address must reverse to a name, and
/// that name must resolve back to the address. Receivers also compare the
/// name with the one the server introduces itself as.
async fn check_reverse(dns: &impl Dns, host: &Host, ip: IpAddr) -> Reverse {
    let names = match dns.ptr(ip).await {
        Lookup::Found(names) => names,
        Lookup::Missing => {
            return Reverse {
                status: Status::Missing,
                names: Vec::new(),
                detail: Some(format!(
                    "{ip} has no reverse DNS. Ask whoever provides the address (usually your hosting provider) to set its PTR record to {}.",
                    host.name
                )),
            };
        }
        Lookup::Failed(error) => {
            return Reverse {
                status: Status::Unknown,
                names: Vec::new(),
                detail: Some(format!("The reverse lookup failed: {error}")),
            };
        }
    };
    if names.contains(&host.name) {
        let (status, detail) = match &host.addresses {
            Lookup::Found(forward) if forward.contains(&ip) => (Status::Ok, None),
            Lookup::Failed(error) => (
                Status::Unknown,
                Some(format!(
                    "Could not resolve {} to confirm: {error}",
                    host.name
                )),
            ),
            _ => (
                Status::Problem,
                Some(format!(
                    "{ip} reverses to {}, but {} does not resolve back to {ip}, so receivers do not accept the name. Add an address record for it.",
                    host.name, host.name
                )),
            ),
        };
        return Reverse {
            status,
            names,
            detail,
        };
    }
    // Some other name: fine for receivers that only want the round trip to
    // work, wrong for those that compare it with the HELO name.
    let confirmed = match dns.ips(&names[0]).await {
        Lookup::Found(forward) => forward.contains(&ip),
        _ => false,
    };
    let (status, detail) = if confirmed {
        (
            Status::Improve,
            format!(
                "{ip} reverses to {}, a valid name, but not {}, which is how this server introduces itself. Stricter receivers treat the mismatch as a spam signal.",
                names[0], host.name
            ),
        )
    } else {
        (
            Status::Different,
            format!(
                "{ip} reverses to {}, which does not resolve back to it. Ask whoever provides the address to set its PTR record to {}.",
                names[0], host.name
            ),
        )
    };
    Reverse {
        status,
        names,
        detail: Some(detail),
    }
}

/// What a listing's return code means, for the lists that encode it.
fn listing_detail(zone: &str, code: std::net::Ipv4Addr) -> String {
    let last = code.octets()[3];
    match (zone, last) {
        ("zen.spamhaus.org", 10 | 11) => "Listed in the Spamhaus Policy Blocklist: the address is in a range its owner says should not send mail directly (home connections and some cloud ranges). Send through a smarthost, or ask your provider for an address meant for mail.".to_string(),
        ("zen.spamhaus.org", 4..=7) => "Listed in the Spamhaus Exploits Blocklist: the address showed signs of a compromised or misconfigured machine. Find the cause, then request removal at check.spamhaus.org.".to_string(),
        ("zen.spamhaus.org", _) => "Listed in the Spamhaus Blocklist as a source of spam. See check.spamhaus.org for the reason and how to be removed.".to_string(),
        _ => "Listed. Receivers that use this list reject or junk mail from the address; look it up on the list's website to see why and to request removal.".to_string(),
    }
}

async fn check_blocklist(
    dns: &impl Dns,
    ip: IpAddr,
    zone: &'static str,
    name: &'static str,
) -> Blocklist {
    let (status, code, detail) = match dns.ips(&dnsbl::query_name(ip, zone)).await {
        Lookup::Missing => (Listed::Clean, None, None),
        Lookup::Found(answers) => match dnsbl::listed_code(&answers) {
            Some(code) => (
                Listed::Listed,
                Some(code.to_string()),
                Some(listing_detail(zone, code)),
            ),
            // 127.255.255.x: the list will not answer this resolver.
            None => (
                Listed::Unknown,
                None,
                Some("The list refused the query, which it does for large public resolvers and heavy users. Check the address on the list's website instead.".to_string()),
            ),
        },
        Lookup::Failed(error) => (
            Listed::Unknown,
            None,
            Some(format!("The lookup failed: {error}")),
        ),
    };
    Blocklist {
        zone,
        name,
        status,
        code,
        detail,
    }
}

/// Judge the addresses found by a port 25 probe.
pub async fn check(dns: &impl Dns, host: &Host, port25: Port25) -> Deliverability {
    let addresses = join_all(outbound_addresses(&port25, host).into_iter().map(
        |(address, source)| async move {
            let lists = BLOCKLISTS
                .iter()
                .filter(|(_, _, lists_v6)| address.is_ipv4() || *lists_v6)
                .map(|(zone, name, _)| check_blocklist(dns, address, zone, name));
            let (reverse, blocklists) =
                tokio::join!(check_reverse(dns, host, address), join_all(lists));
            Address {
                address,
                source,
                reverse,
                blocklists,
            }
        },
    ))
    .await;
    Deliverability { port25, addresses }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnscheck::{SpfVerdict, Srv};
    use std::collections::HashMap;
    use tokio::net::TcpListener;

    const HOST: &str = "mail.example.com";

    #[derive(Default)]
    struct FakeDns {
        mx: HashMap<String, Vec<(u16, String)>>,
        ips: HashMap<String, Vec<IpAddr>>,
        ptr: HashMap<IpAddr, Vec<String>>,
        broken: Vec<String>,
    }

    impl FakeDns {
        fn ips(mut self, name: &str, values: &[&str]) -> Self {
            self.ips.insert(
                name.to_string(),
                values.iter().map(|ip| ip.parse().unwrap()).collect(),
            );
            self
        }

        fn ptr(mut self, ip: &str, names: &[&str]) -> Self {
            self.ptr.insert(
                ip.parse().unwrap(),
                names.iter().map(|name| name.to_string()).collect(),
            );
            self
        }

        fn mx(mut self, domain: &str, host: &str) -> Self {
            self.mx
                .insert(domain.to_string(), vec![(10, host.to_string())]);
            self
        }
    }

    impl Dns for FakeDns {
        async fn txt(&self, _name: &str) -> Lookup<String> {
            Lookup::Missing
        }
        async fn mx(&self, name: &str) -> Lookup<(u16, String)> {
            self.mx
                .get(name)
                .map_or(Lookup::Missing, |found| Lookup::Found(found.clone()))
        }
        async fn cname(&self, _name: &str) -> Lookup<String> {
            Lookup::Missing
        }
        async fn srv(&self, _name: &str) -> Lookup<Srv> {
            Lookup::Missing
        }
        async fn ips(&self, name: &str) -> Lookup<IpAddr> {
            if self.broken.iter().any(|broken| name.ends_with(broken)) {
                return Lookup::Failed("SERVFAIL".to_string());
            }
            self.ips
                .get(name)
                .map_or(Lookup::Missing, |found| Lookup::Found(found.clone()))
        }
        async fn ptr(&self, ip: IpAddr) -> Lookup<String> {
            self.ptr
                .get(&ip)
                .map_or(Lookup::Missing, |found| Lookup::Found(found.clone()))
        }
        async fn spf(&self, _domain: &str, _ip: IpAddr, _helo: &str) -> SpfVerdict {
            SpfVerdict::Unknown
        }
    }

    fn open(local: &str, seen_as: Option<&str>) -> Reach {
        Reach::Open {
            target: "mx.example.net".to_string(),
            local: local.parse().unwrap(),
            seen_as: seen_as.map(|ip| ip.parse().unwrap()),
        }
    }

    fn blocked() -> Reach {
        Reach::Blocked {
            error: "no answer".to_string(),
        }
    }

    #[test]
    fn echoed_addresses_are_found_in_common_reply_shapes() {
        for (reply, expected) in [
            (
                "250-mx.google.com at your service, [203.0.113.5]\r\n250 SMTPUTF8\r\n",
                Some("203.0.113.5"),
            ),
            (
                "250-mx.example.net Hello [IPv6:2001:db8::25]\r\n250 OK\r\n",
                Some("2001:db8::25"),
            ),
            ("250-mx.example.net Hello mail.example.com\r\n", None),
            (
                "250 hello [not an address] [198.51.100.7]\r\n",
                Some("198.51.100.7"),
            ),
            ("250 [", None),
        ] {
            assert_eq!(
                echoed_address(reply),
                expected.map(|ip| ip.parse().unwrap()),
                "{reply}"
            );
        }
    }

    #[test]
    fn only_public_addresses_count_as_outbound() {
        for private in [
            "10.1.2.3",
            "192.168.1.9",
            "100.64.0.1",
            "127.0.0.1",
            "fd00::1",
            "fe80::1",
            "::1",
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
        for public in ["203.0.113.5", "100.128.0.1", "2001:db8::1", "2a01:4f8::1"] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
    }

    /// A one-connection SMTP server that says `lines` and reports what the
    /// client sent.
    async fn smtp_server(lines: &'static [&'static str]) -> (u16, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut heard = Vec::new();
            for (index, line) in lines.iter().enumerate() {
                stream.write_all(line.as_bytes()).await.unwrap();
                if index + 1 < lines.len() || lines.len() == 1 {
                    let mut buffer = [0u8; 256];
                    let read = stream.read(&mut buffer).await.unwrap_or(0);
                    heard.extend_from_slice(&buffer[..read]);
                }
            }
            String::from_utf8_lossy(&heard).into_owned()
        });
        (port, task)
    }

    #[tokio::test]
    async fn probe_reports_an_open_port_and_the_address_the_peer_saw() {
        let (port, server) = smtp_server(&[
            "220 mx.example.net ESMTP\r\n",
            "250-mx.example.net at your service, [203.0.113.5]\r\n250 SMTPUTF8\r\n",
        ])
        .await;
        let dns = FakeDns::default()
            .mx("gmail.com", "mx.example.net")
            .ips("mx.example.net", &["127.0.0.1"]);
        let result = probe_port25(&dns, HOST, port).await;
        assert_eq!(result.v4, open("127.0.0.1", Some("203.0.113.5")));
        // The target has no IPv6 address, which says nothing about us.
        assert_eq!(result.v6, Reach::Unavailable);
        assert!(result.open());
        assert!(
            server
                .await
                .unwrap()
                .starts_with("EHLO mail.example.com\r\n")
        );
    }

    #[tokio::test]
    async fn probe_survives_peers_that_do_not_speak_smtp() {
        // Garbage, a refusal and an endless line: the port is open all the
        // same, and nothing is believed about our address.
        for lines in [
            &["HTTP/1.1 400 Bad Request\r\n"][..],
            &["554 5.7.1 [203.0.113.5] blocked\r\n"][..],
            &["220 ok\r\n", "250-no newline ever [203.0.113.5]"][..],
        ] {
            let (port, _server) = smtp_server(lines).await;
            let dns = FakeDns::default()
                .mx("outlook.com", "mx.example.net")
                .ips("mx.example.net", &["127.0.0.1"]);
            let result = probe_port25(&dns, HOST, port).await;
            assert_eq!(result.v4, open("127.0.0.1", None), "{lines:?}");
        }
    }

    #[tokio::test]
    async fn probe_tells_blocked_from_unresolved() {
        // Nothing listens on the port: refused, like a firewall reject.
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let dns = FakeDns::default()
            .mx("gmail.com", "mx.example.net")
            .ips("mx.example.net", &["127.0.0.1"]);
        let result = probe_port25(&dns, HOST, port).await;
        assert!(
            matches!(&result.v4, Reach::Blocked { error } if error.starts_with("mx.example.net: ")),
            "{result:?}"
        );
        assert!(!result.open());

        // No target resolves: no verdict either way.
        let result = probe_port25(&FakeDns::default(), HOST, port).await;
        assert!(
            matches!(&result.v4, Reach::Unknown { error } if error.contains("gmail.com has no MX")),
            "{result:?}"
        );
        assert!(matches!(result.v6, Reach::Unknown { .. }));
    }

    #[test]
    fn one_open_target_outweighs_the_others() {
        let attempts = vec![blocked(), open("192.0.2.1", None)];
        assert!(matches!(summarize(attempts, &[]), Reach::Open { .. }));
        assert_eq!(
            summarize(vec![blocked(), Reach::Unavailable], &[]),
            Reach::Unavailable
        );
        assert_eq!(
            summarize(vec![blocked(), blocked()], &[]),
            Reach::Blocked {
                error: "no answer; no answer".to_string()
            }
        );
    }

    #[tokio::test]
    async fn outbound_address_prefers_what_the_peer_saw() {
        let dns = FakeDns::default().ips(HOST, &["198.51.100.1", "2001:db8::1"]);
        let host = Host::resolve(&dns, HOST).await;
        let found = |v4, v6| {
            outbound_addresses(&Port25 { v4, v6 }, &host)
                .into_iter()
                .map(|(ip, source)| (ip.to_string(), source))
                .collect::<Vec<_>>()
        };
        // Behind NAT, told by the peer; IPv6 straight from the interface.
        assert_eq!(
            found(
                open("10.0.0.5", Some("203.0.113.5")),
                open("2001:db8::25", None)
            ),
            [
                ("203.0.113.5".to_string(), Source::Seen),
                ("2001:db8::25".to_string(), Source::Local)
            ]
        );
        // Behind NAT and not told: fall back to the host's A record. IPv6 is
        // not in use, so its AAAA record is not judged.
        assert_eq!(
            found(open("10.0.0.5", None), Reach::Unavailable),
            [("198.51.100.1".to_string(), Source::Dns)]
        );
        // A peer that echoes a private address is not believed.
        assert_eq!(
            found(open("203.0.113.9", Some("10.9.9.9")), Reach::Unavailable),
            [("203.0.113.9".to_string(), Source::Local)]
        );
        // Blocked still leaves the published addresses worth checking.
        assert_eq!(found(blocked(), blocked()).len(), 2);
    }

    #[tokio::test]
    async fn reverse_dns_must_round_trip_to_the_host_name() {
        let dns = FakeDns::default()
            .ips(HOST, &["203.0.113.5"])
            .ips("static-6.provider.net", &["203.0.113.6"])
            .ptr("203.0.113.5", &[HOST])
            .ptr("203.0.113.6", &["static-6.provider.net"])
            .ptr("203.0.113.7", &["gone.provider.net"])
            .ptr("203.0.113.8", &[HOST]);
        let host = Host::resolve(&dns, HOST).await;
        let status = |ip: &'static str| {
            let (dns, host) = (&dns, &host);
            async move { check_reverse(dns, host, ip.parse().unwrap()).await }
        };
        let ok = status("203.0.113.5").await;
        assert_eq!((ok.status, ok.detail), (Status::Ok, None));
        // Valid, but not the name the server says HELO with.
        let other = status("203.0.113.6").await;
        assert_eq!(other.status, Status::Improve);
        assert_eq!(other.names, ["static-6.provider.net"]);
        assert_eq!(status("203.0.113.7").await.status, Status::Different);
        // Names the host, but the host does not point back.
        let unconfirmed = status("203.0.113.8").await;
        assert_eq!(unconfirmed.status, Status::Problem);
        assert!(
            unconfirmed
                .detail
                .unwrap()
                .contains("does not resolve back")
        );
        let missing = status("2001:db8::25").await;
        assert_eq!(missing.status, Status::Missing);
        assert!(
            missing
                .detail
                .unwrap()
                .contains("PTR record to mail.example.com")
        );
    }

    #[tokio::test]
    async fn blocklists_distinguish_listed_clean_and_refused() {
        let mut dns = FakeDns::default()
            .ips(HOST, &["203.0.113.5", "2001:db8::25"])
            .ips("5.113.0.203.zen.spamhaus.org", &["127.0.0.11"])
            .ips("5.113.0.203.bl.spamcop.net", &["127.255.255.254"])
            .ptr("203.0.113.5", &[HOST]);
        dns.broken.push("psbl.surriel.com".to_string());
        let host = Host::resolve(&dns, HOST).await;
        let port25 = Port25 {
            v4: open("203.0.113.5", None),
            v6: open("2001:db8::25", None),
        };
        let report = check(&dns, &host, port25).await;
        assert_eq!(report.addresses.len(), 2);
        let v4 = &report.addresses[0];
        assert_eq!(v4.reverse.status, Status::Ok);
        let by_name = |name: &str| v4.blocklists.iter().find(|list| list.name == name).unwrap();
        let spamhaus = by_name("Spamhaus ZEN");
        assert_eq!(spamhaus.status, Listed::Listed);
        assert_eq!(spamhaus.code.as_deref(), Some("127.0.0.11"));
        assert!(
            spamhaus
                .detail
                .as_deref()
                .unwrap()
                .contains("Policy Blocklist")
        );
        // An error code is not a listing.
        assert_eq!(by_name("SpamCop").status, Listed::Unknown);
        assert_eq!(by_name("Barracuda").status, Listed::Clean);
        assert_eq!(by_name("PSBL").status, Listed::Unknown);
        // Only lists that cover IPv6 are asked about an IPv6 address.
        let v6 = &report.addresses[1];
        assert_eq!(
            v6.blocklists
                .iter()
                .map(|list| list.name)
                .collect::<Vec<_>>(),
            ["Spamhaus ZEN"]
        );
        assert_eq!(v6.blocklists[0].status, Listed::Clean);
    }
}
