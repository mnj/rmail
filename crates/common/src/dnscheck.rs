//! Live checks of the DNS records a hosted domain should publish.
//!
//! [`crate::discovery::dns_records`] says what to publish; this module looks
//! each record up and says whether it is there and whether it works. The
//! verdicts are deliberately about outcomes, not text: an SPF record that
//! differs from the suggestion but covers this server is fine, and one that
//! matches it but does not is a problem.
//!
//! Lookups go through the [`Dns`] trait so the rules can be tested without a
//! network; [`SystemDns`] is the real resolver.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use futures_util::future::join_all;
use serde::Serialize;

use crate::discovery::DnsRecord;

/// A lookup that takes longer than this counts as failed, so one dead name
/// server cannot hold a whole report up.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);
/// How far up the tree to look for an inherited DMARC policy.
const DMARC_PARENT_LIMIT: usize = 3;

/// The answer to one DNS question. "No such record" and "could not find out"
/// are kept apart: only the first means the admin has something to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup<T> {
    Found(Vec<T>),
    Missing,
    Failed(String),
}

impl<T> Lookup<T> {
    fn from_vec(values: Vec<T>) -> Self {
        if values.is_empty() {
            Self::Missing
        } else {
            Self::Found(values)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

/// Whether a domain's SPF record lets one address send its mail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpfVerdict {
    Pass,
    /// Evaluated, with a result other than pass (`fail`, `softfail`, ...).
    NotPass(&'static str),
    /// A lookup failed part-way, so there is no verdict.
    Unknown,
}

/// The DNS questions the checks ask. Names are plain (`example.com`); results
/// are lowercase host names without the trailing dot.
#[allow(async_fn_in_trait)]
pub trait Dns {
    /// Each TXT record as one string, its character-strings joined.
    async fn txt(&self, name: &str) -> Lookup<String>;
    /// `(preference, exchange)` pairs.
    async fn mx(&self, name: &str) -> Lookup<(u16, String)>;
    async fn cname(&self, name: &str) -> Lookup<String>;
    async fn srv(&self, name: &str) -> Lookup<Srv>;
    /// A and AAAA addresses, following CNAMEs.
    async fn ips(&self, name: &str) -> Lookup<IpAddr>;
    async fn ptr(&self, ip: IpAddr) -> Lookup<String>;
    /// Evaluate `domain`'s SPF policy for mail arriving from `ip`.
    async fn spf(&self, domain: &str, ip: IpAddr, helo: &str) -> SpfVerdict;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    /// Published and working, but worth strengthening.
    Improve,
    Missing,
    /// Something is published, but not what this server expects.
    Different,
    /// Published in a way that breaks the feature.
    Problem,
    /// The lookup failed, so there is no verdict.
    Unknown,
}

impl Status {
    /// The record does its job (possibly with room for improvement).
    pub fn works(self) -> bool {
        matches!(self, Self::Ok | Self::Improve)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Need {
    /// Mail is lost or lands in spam without it.
    Required,
    Recommended,
    Optional,
}

/// The verdict on one suggested record. `name`, `type` and `value` repeat the
/// suggestion so a client can match the two lists up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecordCheck {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub value: String,
    pub need: Need,
    pub status: Status,
    /// What DNS answered, in zone-file form.
    pub published: Vec<String>,
    /// Why the status is not plain OK, in a sentence an admin can act on.
    pub detail: Option<String>,
}

/// What a suggested record is for, which decides how it is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Mx,
    Spf,
    Dkim,
    Dmarc,
    TlsRpt,
    MtaSts,
    /// A CNAME pointing a service name at this server.
    Alias,
    Srv,
    /// Any other TXT record, compared literally.
    Text,
}

impl Role {
    fn of(record: &DnsRecord) -> Self {
        match record.kind {
            "MX" => Self::Mx,
            "CNAME" => Self::Alias,
            "SRV" => Self::Srv,
            _ => {
                let version = record
                    .value
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                match version.as_str() {
                    "v=spf1" => Self::Spf,
                    "v=dkim1" => Self::Dkim,
                    "v=dmarc1" => Self::Dmarc,
                    "v=tlsrptv1" => Self::TlsRpt,
                    "v=stsv1" => Self::MtaSts,
                    _ => Self::Text,
                }
            }
        }
    }

    fn need(self) -> Need {
        match self {
            Self::Mx | Self::Spf | Self::Dkim | Self::Dmarc => Need::Required,
            _ => Need::Recommended,
        }
    }
}

/// What a check concluded, before it is attached to its record.
struct Verdict {
    status: Status,
    published: Vec<String>,
    detail: Option<String>,
}

impl Verdict {
    fn new(status: Status, published: Vec<String>, detail: impl Into<String>) -> Self {
        Self {
            status,
            published,
            detail: Some(detail.into()),
        }
    }

    fn ok(published: Vec<String>) -> Self {
        Self {
            status: Status::Ok,
            published,
            detail: None,
        }
    }

    fn missing() -> Self {
        Self {
            status: Status::Missing,
            published: Vec::new(),
            detail: None,
        }
    }

    fn unknown(error: &str) -> Self {
        Self::new(
            Status::Unknown,
            Vec::new(),
            format!("The lookup failed: {error}"),
        )
    }
}

/// This server as DNS sees it: the name the records point at and the
/// addresses that name resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    pub name: String,
    pub addresses: Lookup<IpAddr>,
}

impl Host {
    pub async fn resolve(dns: &impl Dns, hostname: &str) -> Self {
        let name = plain_name(hostname);
        let addresses = dns.ips(&name).await;
        Self { name, addresses }
    }
}

/// Lowercase, without the root dot.
fn plain_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// `tag=value` pairs of a DKIM/DMARC-style record, tags lowercased.
fn tags(record: &str) -> BTreeMap<String, String> {
    record
        .split(';')
        .filter_map(|part| part.split_once('='))
        .map(|(tag, value)| (tag.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect()
}

/// The TXT records at a name that start with `version` (`v=spf1`, ...).
fn versioned(records: &[String], version: &str) -> Vec<String> {
    records
        .iter()
        .filter(|record| {
            let record = record.trim_start();
            record
                .get(..version.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(version))
                && record[version.len()..]
                    .chars()
                    .next()
                    .is_none_or(|next| next == ';' || next.is_whitespace())
        })
        .cloned()
        .collect()
}

/// Cloudflare's published proxy ranges (cloudflare.com/ips). A name that
/// resolves into them is proxied ("orange cloud"), not pointing at a server.
const CLOUDFLARE_V4: &[(&str, u8)] = &[
    ("173.245.48.0", 20),
    ("103.21.244.0", 22),
    ("103.22.200.0", 22),
    ("103.31.4.0", 22),
    ("141.101.64.0", 18),
    ("108.162.192.0", 18),
    ("190.93.240.0", 20),
    ("188.114.96.0", 20),
    ("197.234.240.0", 22),
    ("198.41.128.0", 17),
    ("162.158.0.0", 15),
    ("104.16.0.0", 13),
    ("104.24.0.0", 14),
    ("172.64.0.0", 13),
    ("131.0.72.0", 22),
];
const CLOUDFLARE_V6: &[(&str, u8)] = &[
    ("2400:cb00::", 32),
    ("2606:4700::", 32),
    ("2803:f800::", 32),
    ("2405:b500::", 32),
    ("2405:8100::", 32),
    ("2a06:98c0::", 29),
    ("2c0f:f248::", 32),
];

fn in_cloudflare(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => CLOUDFLARE_V4.iter().any(|(net, bits)| {
            let net: std::net::Ipv4Addr = net.parse().expect("constant address");
            let mask = u32::MAX << (32 - bits);
            u32::from(ip) & mask == u32::from(net) & mask
        }),
        IpAddr::V6(ip) => CLOUDFLARE_V6.iter().any(|(net, bits)| {
            let net: std::net::Ipv6Addr = net.parse().expect("constant address");
            let mask = u128::MAX << (128 - bits);
            u128::from(ip) & mask == u128::from(net) & mask
        }),
    }
}

/// Whether `name` is this server: the same name, or one resolving to an
/// address the host name also resolves to. `None` when a lookup failed.
async fn names_this_server(dns: &impl Dns, host: &Host, name: &str) -> Option<bool> {
    if name == host.name {
        return Some(true);
    }
    let Lookup::Found(ours) = &host.addresses else {
        return matches!(host.addresses, Lookup::Missing).then_some(false);
    };
    match dns.ips(name).await {
        Lookup::Found(theirs) => Some(theirs.iter().any(|ip| ours.contains(ip))),
        Lookup::Missing => Some(false),
        Lookup::Failed(_) => None,
    }
}

async fn check_mx(dns: &impl Dns, domain: &str, host: &Host) -> Verdict {
    let mut records = match dns.mx(domain).await {
        Lookup::Found(records) => records,
        Lookup::Missing => return Verdict::missing(),
        Lookup::Failed(error) => return Verdict::unknown(&error),
    };
    records.sort();
    let published = records
        .iter()
        .map(|(preference, exchange)| format!("{preference} {exchange}."))
        .collect::<Vec<_>>();
    // RFC 7505: a lone "0 ." says the domain accepts no mail at all.
    if records.iter().all(|(_, exchange)| exchange.is_empty()) {
        return Verdict::new(
            Status::Problem,
            published,
            "A null MX is published, which tells other servers the domain accepts no mail.",
        );
    }
    let best = records[0].0;
    let mut ours_is_backup = false;
    for (preference, exchange) in &records {
        match names_this_server(dns, host, exchange).await {
            Some(true) if *preference == best => return Verdict::ok(published),
            Some(true) => ours_is_backup = true,
            Some(false) => {}
            None => {
                return Verdict::new(
                    Status::Unknown,
                    published,
                    format!("Could not resolve {exchange} to see whether it is this server."),
                );
            }
        }
    }
    if ours_is_backup {
        return Verdict::new(
            Status::Different,
            published,
            format!(
                "Mail goes to {} first; this server is only a backup MX.",
                records[0].1
            ),
        );
    }
    Verdict::new(
        Status::Problem,
        published,
        format!(
            "MX points to {}, not to {}, so mail for the domain is delivered elsewhere.",
            records[0].1, host.name
        ),
    )
}

async fn check_spf(dns: &impl Dns, domain: &str, host: &Host) -> Verdict {
    let published = match dns.txt(domain).await {
        Lookup::Found(records) => versioned(&records, "v=spf1"),
        Lookup::Missing => Vec::new(),
        Lookup::Failed(error) => return Verdict::unknown(&error),
    };
    match published.len() {
        0 => return Verdict::missing(),
        1 => {}
        count => {
            return Verdict::new(
                Status::Problem,
                published,
                format!(
                    "{count} SPF records are published. Receivers treat that as an error and ignore all of them; merge them into one."
                ),
            );
        }
    }
    let allows_anyone = published[0]
        .split_whitespace()
        .any(|term| matches!(term.to_ascii_lowercase().as_str(), "all" | "+all"));
    if allows_anyone {
        return Verdict::new(
            Status::Problem,
            published,
            "The record ends in +all, which lets any server on the internet send as this domain.",
        );
    }
    let addresses = match &host.addresses {
        Lookup::Found(addresses) => addresses,
        Lookup::Missing => {
            return Verdict::new(
                Status::Problem,
                published,
                format!(
                    "{} has no address record, so nothing shows that SPF covers this server.",
                    host.name
                ),
            );
        }
        Lookup::Failed(error) => {
            return Verdict::new(
                Status::Unknown,
                published,
                format!(
                    "Could not resolve {} to test the record: {error}",
                    host.name
                ),
            );
        }
    };
    let mut unknown = false;
    for ip in addresses {
        match dns.spf(domain, *ip, &host.name).await {
            SpfVerdict::Pass => {}
            SpfVerdict::NotPass(result) => {
                return Verdict::new(
                    Status::Problem,
                    published,
                    format!(
                        "The record does not cover this server's address {ip} (SPF result: {result}), so mail sent from it fails SPF."
                    ),
                );
            }
            SpfVerdict::Unknown => unknown = true,
        }
    }
    if unknown {
        return Verdict::new(
            Status::Unknown,
            published,
            "A lookup failed while evaluating the record.",
        );
    }
    Verdict::ok(published)
}

/// A DKIM public key with whitespace removed, as verifiers compare it.
fn dkim_public_key(record: &str) -> Option<String> {
    tags(record)
        .get("p")
        .map(|key| key.split_whitespace().collect())
}

async fn check_dkim(dns: &impl Dns, record: &DnsRecord) -> Verdict {
    let published = match dns.txt(&record.name).await {
        Lookup::Found(records) => records,
        Lookup::Missing => return Verdict::missing(),
        Lookup::Failed(error) => return Verdict::unknown(&error),
    };
    if published.len() > 1 {
        return Verdict::new(
            Status::Problem,
            published,
            "More than one TXT record is published at this selector, so verifiers cannot tell which key to use.",
        );
    }
    let expected = dkim_public_key(&record.value);
    match dkim_public_key(&published[0]) {
        Some(key) if Some(&key) == expected.as_ref() => Verdict::ok(published),
        Some(key) if key.is_empty() => Verdict::new(
            Status::Problem,
            published,
            "The published key is revoked (empty p=), so signatures made with this selector fail.",
        ),
        _ => Verdict::new(
            Status::Problem,
            published,
            "The key in DNS is not the key this server signs with, so its signatures fail to verify. Replace the record with the value shown.",
        ),
    }
}

/// The DMARC record that applies to `domain`: its own, or the nearest
/// parent's (receivers fall back to the organizational domain). The second
/// value names the parent when the policy is inherited.
async fn dmarc_records(
    dns: &impl Dns,
    domain: &str,
) -> Result<(Vec<String>, Option<String>), String> {
    let mut candidate = domain.to_string();
    for depth in 0..=DMARC_PARENT_LIMIT {
        let records = match dns.txt(&format!("_dmarc.{candidate}")).await {
            Lookup::Found(records) => versioned(&records, "v=DMARC1"),
            Lookup::Missing => Vec::new(),
            Lookup::Failed(error) => return Err(error),
        };
        if !records.is_empty() {
            return Ok((records, (depth > 0).then_some(candidate)));
        }
        // Stop before asking a top-level domain.
        match candidate.split_once('.') {
            Some((_, parent)) if parent.contains('.') => candidate = parent.to_string(),
            _ => break,
        }
    }
    Ok((Vec::new(), None))
}

async fn check_dmarc(dns: &impl Dns, domain: &str) -> Verdict {
    let (published, inherited_from) = match dmarc_records(dns, domain).await {
        Ok(found) => found,
        Err(error) => return Verdict::unknown(&error),
    };
    match published.len() {
        0 => return Verdict::missing(),
        1 => {}
        count => {
            return Verdict::new(
                Status::Problem,
                published,
                format!("{count} DMARC records are published, so receivers apply none of them."),
            );
        }
    }
    let tags = tags(&published[0]);
    // A parent's sp= is what applies to its subdomains.
    let policy = inherited_from
        .as_ref()
        .and_then(|_| tags.get("sp"))
        .or_else(|| tags.get("p"))
        .map(|policy| policy.to_ascii_lowercase());
    let Some(policy) = policy.filter(|p| matches!(p.as_str(), "none" | "quarantine" | "reject"))
    else {
        return Verdict::new(
            Status::Problem,
            published,
            "The record has no valid policy (p=none, quarantine or reject), so receivers ignore it.",
        );
    };
    let mut advice = Vec::new();
    if let Some(parent) = &inherited_from {
        advice.push(format!("Inherited from _dmarc.{parent}."));
    }
    if tags.get("rua").is_none_or(|rua| rua.is_empty()) {
        advice.push(
            "No reporting address (rua=), so you never learn who sends mail as this domain."
                .to_string(),
        );
    }
    if policy == "none" {
        advice.push(
            "The policy is still p=none: receivers report forgeries but deliver them. Once the reports show your own mail passing, tighten it to quarantine or reject."
                .to_string(),
        );
    }
    // Inheriting a strict policy is fine as it is; only real advice downgrades.
    let improvable = advice.len() > usize::from(inherited_from.is_some());
    Verdict {
        status: if improvable {
            Status::Improve
        } else {
            Status::Ok
        },
        published,
        detail: (!advice.is_empty()).then(|| advice.join(" ")),
    }
}

async fn check_tls_rpt(dns: &impl Dns, record: &DnsRecord) -> Verdict {
    let published = match dns.txt(&record.name).await {
        Lookup::Found(records) => versioned(&records, "v=TLSRPTv1"),
        Lookup::Missing => Vec::new(),
        Lookup::Failed(error) => return Verdict::unknown(&error),
    };
    match published.len() {
        0 => Verdict::missing(),
        1 if tags(&published[0])
            .get("rua")
            .is_some_and(|rua| !rua.is_empty()) =>
        {
            Verdict::ok(published)
        }
        1 => Verdict::new(
            Status::Problem,
            published,
            "The record names no report address (rua=), so no reports are sent.",
        ),
        count => Verdict::new(
            Status::Problem,
            published,
            format!("{count} TLS-RPT records are published, so senders ignore all of them."),
        ),
    }
}

async fn check_mta_sts(dns: &impl Dns, record: &DnsRecord) -> Verdict {
    let published = match dns.txt(&record.name).await {
        Lookup::Found(records) => versioned(&records, "v=STSv1"),
        Lookup::Missing => Vec::new(),
        Lookup::Failed(error) => return Verdict::unknown(&error),
    };
    match published.len() {
        0 => Verdict::missing(),
        1 if tags(&published[0]).get("id") == tags(&record.value).get("id") => {
            Verdict::ok(published)
        }
        1 => Verdict::new(
            Status::Different,
            published,
            "The id is not the current policy's, so senders keep using the policy they cached. Publish the id shown.",
        ),
        count => Verdict::new(
            Status::Problem,
            published,
            format!("{count} MTA-STS records are published, so senders ignore the policy."),
        ),
    }
}

async fn check_alias(dns: &impl Dns, record: &DnsRecord, host: &Host) -> Verdict {
    let target = match dns.cname(&record.name).await {
        Lookup::Found(targets) => targets.into_iter().next(),
        Lookup::Missing => None,
        Lookup::Failed(error) => return Verdict::unknown(&error),
    };
    if target.as_deref() == Some(host.name.as_str()) {
        return Verdict::ok(vec![format!("{}.", host.name)]);
    }
    // No CNAME to the host name: address records for the same machine do the
    // same job, and are all a zone apex or a proxied record can offer.
    let addresses = match dns.ips(&record.name).await {
        Lookup::Found(addresses) => addresses,
        Lookup::Missing => {
            return match target {
                Some(target) => Verdict::new(
                    Status::Different,
                    vec![format!("{target}.")],
                    format!("Points to {target}, which does not resolve."),
                ),
                None => Verdict::missing(),
            };
        }
        Lookup::Failed(error) => return Verdict::unknown(&error),
    };
    let published = match &target {
        Some(target) => vec![format!("{target}.")],
        None => addresses.iter().map(IpAddr::to_string).collect(),
    };
    if addresses.iter().copied().any(in_cloudflare) {
        return Verdict::new(
            Status::Problem,
            published,
            "The name is behind Cloudflare's proxy, which answers in place of this server. Switch the record to \"DNS only\".",
        );
    }
    match &host.addresses {
        Lookup::Found(ours) if addresses.iter().any(|ip| ours.contains(ip)) => {
            Verdict::ok(published)
        }
        Lookup::Failed(error) => Verdict::new(
            Status::Unknown,
            published,
            format!("Could not resolve {} to compare: {error}", host.name),
        ),
        _ => Verdict::new(
            Status::Different,
            published,
            format!("Points somewhere other than {}.", host.name),
        ),
    }
}

async fn check_srv(dns: &impl Dns, record: &DnsRecord, host: &Host) -> Verdict {
    let records = match dns.srv(&record.name).await {
        Lookup::Found(records) => records,
        Lookup::Missing => return Verdict::missing(),
        Lookup::Failed(error) => return Verdict::unknown(&error),
    };
    let published = records
        .iter()
        .map(|srv| {
            format!(
                "{} {} {} {}.",
                srv.priority, srv.weight, srv.port, srv.target
            )
        })
        .collect::<Vec<_>>();
    // "priority weight port target."
    let port = record
        .value
        .split_whitespace()
        .nth(2)
        .and_then(|port| port.parse::<u16>().ok());
    if records
        .iter()
        .any(|srv| srv.target == host.name && Some(srv.port) == port)
    {
        Verdict::ok(published)
    } else {
        Verdict::new(
            Status::Different,
            published,
            "Points at a different host or port, so clients look in the wrong place.",
        )
    }
}

async fn check_text(dns: &impl Dns, record: &DnsRecord) -> Verdict {
    match dns.txt(&record.name).await {
        Lookup::Found(published) if published.iter().any(|text| text.trim() == record.value) => {
            Verdict::ok(published)
        }
        Lookup::Found(published) => Verdict {
            status: Status::Different,
            published,
            detail: None,
        },
        Lookup::Missing => Verdict::missing(),
        Lookup::Failed(error) => Verdict::unknown(&error),
    }
}

/// Look one suggested record up and judge it.
pub async fn check_record(
    dns: &impl Dns,
    domain: &str,
    host: &Host,
    record: &DnsRecord,
) -> RecordCheck {
    let role = Role::of(record);
    let verdict = match role {
        Role::Mx => check_mx(dns, domain, host).await,
        Role::Spf => check_spf(dns, domain, host).await,
        Role::Dkim => check_dkim(dns, record).await,
        Role::Dmarc => check_dmarc(dns, domain).await,
        Role::TlsRpt => check_tls_rpt(dns, record).await,
        Role::MtaSts => check_mta_sts(dns, record).await,
        Role::Alias => check_alias(dns, record, host).await,
        Role::Srv => check_srv(dns, record, host).await,
        Role::Text => check_text(dns, record).await,
    };
    RecordCheck {
        name: record.name.clone(),
        kind: record.kind,
        value: record.value.clone(),
        need: role.need(),
        status: verdict.status,
        published: verdict.published,
        detail: verdict.detail,
    }
}

/// Check every suggested record of `domain`, in the order given.
pub async fn check_domain(
    dns: &impl Dns,
    domain: &str,
    host: &Host,
    records: &[DnsRecord],
) -> Vec<RecordCheck> {
    join_all(
        records
            .iter()
            .map(|record| check_record(dns, domain, host, record)),
    )
    .await
}

/// The process-wide resolver, as [`Dns`].
pub struct SystemDns;

impl SystemDns {
    /// Forget cached answers, so a re-check sees what was just published
    /// (as far as the upstream resolver's own cache allows).
    pub fn forget_cached_answers() {
        if let Ok(authenticator) = crate::mail_auth::authenticator() {
            authenticator.resolver().clear_cache();
        }
    }
}

mod system {
    use super::*;
    use mail_auth::hickory_resolver::lookup::Lookup as Answer;
    use mail_auth::hickory_resolver::net::NetError;
    use mail_auth::hickory_resolver::proto::rr::{Name, RData, RecordType};
    use mail_auth::spf::verify::SpfParameters;
    use mail_auth::{MessageAuthenticator, SpfResult};

    fn fqdn(name: &str) -> String {
        format!("{}.", name.trim_end_matches('.'))
    }

    /// Run one lookup with a deadline and turn its answer records into values.
    async fn ask<T, F>(lookup: F, pick: impl Fn(&RData) -> Option<T>) -> Lookup<T>
    where
        F: std::future::Future<Output = Result<Answer, NetError>>,
    {
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(LOOKUP_TIMEOUT, lookup).await;
        crate::metrics::observe_dns_duration(started.elapsed());
        match result {
            Ok(Ok(answer)) => Lookup::from_vec(
                answer
                    .answers()
                    .iter()
                    .filter_map(|record| pick(&record.data))
                    .collect(),
            ),
            Ok(Err(error)) if error.is_no_records_found() => Lookup::Missing,
            Ok(Err(error)) => Lookup::Failed(error.to_string()),
            Err(_) => Lookup::Failed("timed out".to_string()),
        }
    }

    fn resolver() -> Result<&'static MessageAuthenticator, String> {
        crate::mail_auth::authenticator().map_err(|error| format!("{error:#}"))
    }

    fn host(name: &Name) -> String {
        plain_name(&name.to_utf8())
    }

    impl Dns for SystemDns {
        async fn txt(&self, name: &str) -> Lookup<String> {
            let resolver = match resolver() {
                Ok(resolver) => resolver,
                Err(error) => return Lookup::Failed(error),
            };
            ask(
                resolver.resolver().txt_lookup(fqdn(name)),
                |data| match data {
                    RData::TXT(txt) => Some(
                        txt.txt_data
                            .iter()
                            .map(|part| String::from_utf8_lossy(part))
                            .collect::<String>(),
                    ),
                    _ => None,
                },
            )
            .await
        }

        async fn mx(&self, name: &str) -> Lookup<(u16, String)> {
            let resolver = match resolver() {
                Ok(resolver) => resolver,
                Err(error) => return Lookup::Failed(error),
            };
            ask(
                resolver.resolver().mx_lookup(fqdn(name)),
                |data| match data {
                    RData::MX(mx) => Some((mx.preference, host(&mx.exchange))),
                    _ => None,
                },
            )
            .await
        }

        async fn cname(&self, name: &str) -> Lookup<String> {
            let resolver = match resolver() {
                Ok(resolver) => resolver,
                Err(error) => return Lookup::Failed(error),
            };
            ask(
                resolver.resolver().lookup(fqdn(name), RecordType::CNAME),
                |data| match data {
                    RData::CNAME(target) => Some(host(&target.0)),
                    _ => None,
                },
            )
            .await
        }

        async fn srv(&self, name: &str) -> Lookup<Srv> {
            let resolver = match resolver() {
                Ok(resolver) => resolver,
                Err(error) => return Lookup::Failed(error),
            };
            ask(
                resolver.resolver().srv_lookup(fqdn(name)),
                |data| match data {
                    RData::SRV(srv) => Some(Srv {
                        priority: srv.priority,
                        weight: srv.weight,
                        port: srv.port,
                        target: host(&srv.target),
                    }),
                    _ => None,
                },
            )
            .await
        }

        async fn ips(&self, name: &str) -> Lookup<IpAddr> {
            let resolver = match resolver() {
                Ok(resolver) => resolver,
                Err(error) => return Lookup::Failed(error),
            };
            let started = std::time::Instant::now();
            let result =
                tokio::time::timeout(LOOKUP_TIMEOUT, resolver.resolver().lookup_ip(fqdn(name)))
                    .await;
            crate::metrics::observe_dns_duration(started.elapsed());
            match result {
                Ok(Ok(answer)) => Lookup::from_vec(answer.iter().collect()),
                Ok(Err(error)) if error.is_no_records_found() => Lookup::Missing,
                Ok(Err(error)) => Lookup::Failed(error.to_string()),
                Err(_) => Lookup::Failed("timed out".to_string()),
            }
        }

        async fn ptr(&self, ip: IpAddr) -> Lookup<String> {
            let resolver = match resolver() {
                Ok(resolver) => resolver,
                Err(error) => return Lookup::Failed(error),
            };
            ask(
                resolver.resolver().reverse_lookup(Name::from(ip)),
                |data| match data {
                    RData::PTR(name) => Some(host(&name.0)),
                    _ => None,
                },
            )
            .await
        }

        async fn spf(&self, domain: &str, ip: IpAddr, helo: &str) -> SpfVerdict {
            let Ok(resolver) = resolver() else {
                return SpfVerdict::Unknown;
            };
            let sender = format!("postmaster@{domain}");
            let started = std::time::Instant::now();
            // An SPF policy can fan out into ten lookups of its own.
            let output = tokio::time::timeout(
                LOOKUP_TIMEOUT * 3,
                resolver.verify_spf(SpfParameters::verify_mail_from(ip, helo, helo, &sender)),
            )
            .await;
            crate::metrics::observe_dns_duration(started.elapsed());
            match output.map(|output| output.result()) {
                Ok(SpfResult::Pass) => SpfVerdict::Pass,
                Ok(SpfResult::Fail) => SpfVerdict::NotPass("fail"),
                Ok(SpfResult::SoftFail) => SpfVerdict::NotPass("softfail"),
                Ok(SpfResult::Neutral) => SpfVerdict::NotPass("neutral"),
                Ok(SpfResult::PermError) => SpfVerdict::NotPass("permerror"),
                Ok(SpfResult::None) => SpfVerdict::NotPass("none"),
                Ok(SpfResult::TempError) | Err(_) => SpfVerdict::Unknown,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{MtaStsMode, ServiceEndpoints, dns_records};
    use std::collections::HashMap;

    const HOST: &str = "mail.example.com";
    const IP: &str = "203.0.113.5";

    /// DNS answers from tables; anything not listed does not exist, and names
    /// in `broken` fail to resolve.
    #[derive(Default)]
    struct FakeDns {
        txt: HashMap<String, Vec<String>>,
        mx: HashMap<String, Vec<(u16, String)>>,
        cname: HashMap<String, String>,
        srv: HashMap<String, Vec<Srv>>,
        ips: HashMap<String, Vec<IpAddr>>,
        ptr: HashMap<IpAddr, Vec<String>>,
        spf: HashMap<(String, IpAddr), SpfVerdict>,
        broken: Vec<String>,
    }

    impl FakeDns {
        fn answer<T: Clone>(&self, table: &HashMap<String, Vec<T>>, name: &str) -> Lookup<T> {
            if self.broken.iter().any(|broken| broken == name) {
                return Lookup::Failed("SERVFAIL".to_string());
            }
            table
                .get(name)
                .map_or(Lookup::Missing, |values| Lookup::from_vec(values.clone()))
        }

        fn txt(mut self, name: &str, values: &[&str]) -> Self {
            self.txt
                .entry(name.to_string())
                .or_default()
                .extend(values.iter().map(|value| value.to_string()));
            self
        }

        fn ips(mut self, name: &str, values: &[&str]) -> Self {
            self.ips.insert(
                name.to_string(),
                values.iter().map(|ip| ip.parse().unwrap()).collect(),
            );
            self
        }

        fn broken(mut self, name: &str) -> Self {
            self.broken.push(name.to_string());
            self
        }
    }

    impl Dns for FakeDns {
        async fn txt(&self, name: &str) -> Lookup<String> {
            self.answer(&self.txt, name)
        }
        async fn mx(&self, name: &str) -> Lookup<(u16, String)> {
            self.answer(&self.mx, name)
        }
        async fn cname(&self, name: &str) -> Lookup<String> {
            if self.broken.iter().any(|broken| broken == name) {
                return Lookup::Failed("SERVFAIL".to_string());
            }
            self.cname.get(name).map_or(Lookup::Missing, |target| {
                Lookup::Found(vec![target.clone()])
            })
        }
        async fn srv(&self, name: &str) -> Lookup<Srv> {
            self.answer(&self.srv, name)
        }
        async fn ips(&self, name: &str) -> Lookup<IpAddr> {
            // Like a resolver, follow a CNAME to its target's addresses.
            let name = self.cname.get(name).map_or(name, String::as_str);
            self.answer(&self.ips, name)
        }
        async fn ptr(&self, ip: IpAddr) -> Lookup<String> {
            self.ptr
                .get(&ip)
                .map_or(Lookup::Missing, |names| Lookup::from_vec(names.clone()))
        }
        async fn spf(&self, domain: &str, ip: IpAddr, _helo: &str) -> SpfVerdict {
            self.spf
                .get(&(domain.to_string(), ip))
                .cloned()
                .unwrap_or(SpfVerdict::NotPass("fail"))
        }
    }

    fn suggested() -> Vec<DnsRecord> {
        let endpoints = ServiceEndpoints {
            hostname: HOST.to_string(),
            imap: None,
            smtp: None,
            jmap_port: 443,
        };
        let mut records = dns_records(
            "example.com",
            &endpoints,
            MtaStsMode::Enforce,
            86400,
            "postmaster@example.com",
        );
        records.push(DnsRecord {
            name: "mail2026._domainkey.example.com".to_string(),
            kind: "TXT",
            value: "v=DKIM1; k=rsa; p=MIIBIjANBgkq".to_string(),
            purpose: "DKIM",
        });
        records
    }

    /// A zone that publishes exactly what is suggested.
    fn perfect() -> FakeDns {
        let mut dns = FakeDns::default().ips(HOST, &[IP]);
        for record in suggested() {
            match record.kind {
                "MX" => {
                    dns.mx
                        .insert(record.name.clone(), vec![(10, HOST.to_string())]);
                }
                "CNAME" => {
                    dns.cname.insert(record.name.clone(), HOST.to_string());
                }
                "SRV" => {
                    let port = record.value.split(' ').nth(2).unwrap().parse().unwrap();
                    dns.srv.entry(record.name.clone()).or_default().push(Srv {
                        priority: 0,
                        weight: 1,
                        port,
                        target: HOST.to_string(),
                    });
                }
                _ => dns = dns.txt(&record.name, &[&record.value]),
            }
        }
        dns.spf.insert(
            ("example.com".to_string(), IP.parse().unwrap()),
            SpfVerdict::Pass,
        );
        dns
    }

    async fn run(dns: &FakeDns) -> Vec<RecordCheck> {
        let host = Host::resolve(dns, HOST).await;
        check_domain(dns, "example.com", &host, &suggested()).await
    }

    fn find<'a>(checks: &'a [RecordCheck], name: &str, kind: &str) -> &'a RecordCheck {
        checks
            .iter()
            .find(|check| check.name == name && check.kind == kind)
            .unwrap_or_else(|| panic!("no {kind} check for {name}"))
    }

    #[tokio::test]
    async fn a_zone_that_follows_the_suggestions_passes_except_for_dmarc_advice() {
        let checks = run(&perfect()).await;
        assert_eq!(checks.len(), suggested().len());
        for check in &checks {
            if check.name == "_dmarc.example.com" {
                // The suggested starting policy is p=none, which works but
                // should not be left there.
                assert_eq!(check.status, Status::Improve);
                assert!(check.detail.as_deref().unwrap().contains("p=none"));
            } else {
                assert_eq!(check.status, Status::Ok, "{check:?}");
                assert_eq!(check.detail, None, "{check:?}");
            }
        }
        let required = checks
            .iter()
            .filter(|check| check.need == Need::Required)
            .map(|check| check.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            required,
            [
                "example.com",
                "example.com",
                "_dmarc.example.com",
                "mail2026._domainkey.example.com"
            ]
        );
    }

    #[tokio::test]
    async fn an_empty_zone_is_missing_everything_and_a_dead_resolver_is_unknown() {
        let checks = run(&FakeDns::default().ips(HOST, &[IP])).await;
        assert!(checks.iter().all(|check| check.status == Status::Missing));

        let mut dns = FakeDns::default().ips(HOST, &[IP]);
        for record in suggested() {
            dns = dns.broken(&record.name);
        }
        let checks = run(&dns).await;
        for check in &checks {
            assert_eq!(check.status, Status::Unknown, "{check:?}");
            assert!(check.detail.as_deref().unwrap().contains("SERVFAIL"));
        }
    }

    #[tokio::test]
    async fn mx_must_lead_to_this_server() {
        let mut dns = perfect();
        dns.mx
            .insert("example.com".into(), vec![(10, "mx.other.net".into())]);
        let checks = run(&dns).await;
        let mx = find(&checks, "example.com", "MX");
        assert_eq!(mx.status, Status::Problem);
        assert_eq!(mx.published, ["10 mx.other.net."]);
        assert!(mx.detail.as_deref().unwrap().contains("mx.other.net"));

        // Another name for the same machine is as good as the host name.
        let dns = dns.ips("mx.other.net", &[IP]);
        assert_eq!(
            find(&run(&dns).await, "example.com", "MX").status,
            Status::Ok
        );

        // Listed, but behind a preferred exchange elsewhere.
        let mut dns = perfect();
        dns.mx.insert(
            "example.com".into(),
            vec![(20, HOST.into()), (5, "filter.example.net".into())],
        );
        let checks = run(&dns).await;
        let mx = find(&checks, "example.com", "MX");
        assert_eq!(mx.status, Status::Different);
        assert_eq!(mx.published[0], "5 filter.example.net.");

        let mut dns = perfect();
        dns.mx
            .insert("example.com".into(), vec![(0, String::new())]);
        let checks = run(&dns).await;
        let mx = find(&checks, "example.com", "MX");
        assert_eq!(mx.status, Status::Problem);
        assert!(mx.detail.as_deref().unwrap().contains("null MX"));
    }

    #[tokio::test]
    async fn spf_is_judged_by_whether_it_covers_this_server() {
        // A different record that still passes is fine.
        let mut dns = perfect();
        dns.txt.insert(
            "example.com".into(),
            vec![
                "google-site-verification=abc".into(),
                "v=spf1 ip4:203.0.113.5 ~all".into(),
            ],
        );
        let checks = run(&dns).await;
        let spf = find(&checks, "example.com", "TXT");
        assert_eq!(spf.status, Status::Ok);
        assert_eq!(spf.published, ["v=spf1 ip4:203.0.113.5 ~all"]);

        // The suggested text, but evaluation says this address is not covered.
        let mut dns = perfect();
        dns.spf.clear();
        let checks = run(&dns).await;
        let spf = find(&checks, "example.com", "TXT");
        assert_eq!(spf.status, Status::Problem);
        assert!(spf.detail.as_deref().unwrap().contains(IP));

        let dns = perfect().txt("example.com", &["v=spf1 include:_spf.other.net -all"]);
        let checks = run(&dns).await;
        let spf = find(&checks, "example.com", "TXT");
        assert_eq!(spf.status, Status::Problem);
        assert!(spf.detail.as_deref().unwrap().starts_with("2 SPF records"));

        let mut dns = perfect();
        dns.txt
            .insert("example.com".into(), vec!["v=spf1 mx +all".into()]);
        let checks = run(&dns).await;
        assert!(
            find(&checks, "example.com", "TXT")
                .detail
                .as_deref()
                .unwrap()
                .contains("+all")
        );

        // "v=spf10" is not an SPF record.
        let mut dns = perfect();
        dns.txt
            .insert("example.com".into(), vec!["v=spf10 mx -all".into()]);
        assert_eq!(
            find(&run(&dns).await, "example.com", "TXT").status,
            Status::Missing
        );

        // Without an address for the host there is nothing to test against.
        let mut dns = perfect();
        dns.ips.clear();
        assert_eq!(
            find(&run(&dns).await, "example.com", "TXT").status,
            Status::Problem
        );
        let mut dns = perfect();
        dns.spf.insert(
            ("example.com".to_string(), IP.parse().unwrap()),
            SpfVerdict::Unknown,
        );
        assert_eq!(
            find(&run(&dns).await, "example.com", "TXT").status,
            Status::Unknown
        );
    }

    #[tokio::test]
    async fn dkim_key_in_dns_must_be_the_signing_key() {
        let name = "mail2026._domainkey.example.com";
        // Folded differently, same key.
        let mut dns = perfect();
        dns.txt
            .insert(name.into(), vec!["k=rsa; v=DKIM1; p=MIIBIjAN Bgkq".into()]);
        assert_eq!(find(&run(&dns).await, name, "TXT").status, Status::Ok);

        dns.txt
            .insert(name.into(), vec!["v=DKIM1; k=rsa; p=OTHERKEY".into()]);
        let checks = run(&dns).await;
        let dkim = find(&checks, name, "TXT");
        assert_eq!(dkim.status, Status::Problem);
        assert!(dkim.detail.as_deref().unwrap().contains("not the key"));

        dns.txt.insert(name.into(), vec!["v=DKIM1; p=".into()]);
        let checks = run(&dns).await;
        assert!(
            find(&checks, name, "TXT")
                .detail
                .as_deref()
                .unwrap()
                .contains("revoked")
        );

        let dns = perfect().txt(name, &["v=DKIM1; k=rsa; p=OTHERKEY"]);
        assert_eq!(find(&run(&dns).await, name, "TXT").status, Status::Problem);
    }

    #[tokio::test]
    async fn dmarc_policy_and_reporting_are_weighed() {
        let name = "_dmarc.example.com";
        let with = |record: &str| {
            let mut dns = perfect();
            dns.txt.insert(name.into(), vec![record.into()]);
            dns
        };
        let checks = run(&with("v=DMARC1; p=reject; rua=mailto:d@example.com")).await;
        let dmarc = find(&checks, name, "TXT");
        assert_eq!((dmarc.status, dmarc.detail.clone()), (Status::Ok, None));

        let checks = run(&with("v=DMARC1; p=quarantine")).await;
        let dmarc = find(&checks, name, "TXT");
        assert_eq!(dmarc.status, Status::Improve);
        assert!(dmarc.detail.as_deref().unwrap().contains("rua="));
        assert!(!dmarc.detail.as_deref().unwrap().contains("p=none"));

        assert_eq!(
            find(
                &run(&with("v=DMARC1; rua=mailto:d@example.com")).await,
                name,
                "TXT"
            )
            .status,
            Status::Problem
        );
        let dns = perfect().txt(name, &["v=DMARC1; p=reject"]);
        assert_eq!(find(&run(&dns).await, name, "TXT").status, Status::Problem);
    }

    #[tokio::test]
    async fn dmarc_is_inherited_from_a_parent_domain() {
        let dns = FakeDns::default().ips(HOST, &[IP]).txt(
            "_dmarc.example.com",
            &["v=DMARC1; p=none; sp=reject; rua=mailto:d@example.com"],
        );
        let host = Host::resolve(&dns, HOST).await;
        let record = DnsRecord {
            name: "_dmarc.lists.eu.example.com".to_string(),
            kind: "TXT",
            value: "v=DMARC1; p=none".to_string(),
            purpose: "DMARC",
        };
        let check = check_record(&dns, "lists.eu.example.com", &host, &record).await;
        // sp=reject is what applies to the subdomain, so nothing to improve.
        assert_eq!(check.status, Status::Ok);
        assert_eq!(
            check.detail.as_deref(),
            Some("Inherited from _dmarc.example.com.")
        );
        // The walk stops before the top-level domain.
        let check = check_record(&FakeDns::default(), "example.com", &host, &record).await;
        assert_eq!(check.status, Status::Missing);
    }

    #[tokio::test]
    async fn service_names_must_reach_this_server_directly() {
        let name = "autoconfig.example.com";
        // An address record for the same machine works like the CNAME.
        let mut dns = perfect();
        dns.cname.remove(name);
        let dns = dns.ips(name, &[IP]);
        let checks = run(&dns).await;
        let alias = find(&checks, name, "CNAME");
        assert_eq!(alias.status, Status::Ok);
        assert_eq!(alias.published, [IP]);

        let dns = dns.ips(name, &["104.21.7.9", "2606:4700:3030::1"]);
        let checks = run(&dns).await;
        let alias = find(&checks, name, "CNAME");
        assert_eq!(alias.status, Status::Problem);
        assert!(alias.detail.as_deref().unwrap().contains("Cloudflare"));

        let dns = dns.ips(name, &["198.51.100.9"]);
        assert_eq!(
            find(&run(&dns).await, name, "CNAME").status,
            Status::Different
        );

        let mut dns = perfect();
        dns.cname.insert(name.into(), "gone.example.net".into());
        let checks = run(&dns).await;
        let alias = find(&checks, name, "CNAME");
        assert_eq!(alias.status, Status::Different);
        assert_eq!(alias.published, ["gone.example.net."]);
    }

    #[tokio::test]
    async fn srv_mta_sts_and_tls_rpt_are_compared_by_meaning() {
        let mut dns = perfect();
        dns.srv.insert(
            "_jmap._tcp.example.com".into(),
            vec![Srv {
                priority: 5,
                weight: 0,
                port: 8443,
                target: HOST.into(),
            }],
        );
        dns.txt.insert(
            "_mta-sts.example.com".into(),
            vec!["v=STSv1; id=stale".into()],
        );
        dns.txt.insert(
            "_smtp._tls.example.com".into(),
            vec!["v=TLSRPTv1; rua=https://reports.example.net/tls".into()],
        );
        dns.txt.insert(
            "_caldavs._tcp.example.com".into(),
            vec!["path=/calendars/".into()],
        );
        let checks = run(&dns).await;
        let srv = find(&checks, "_jmap._tcp.example.com", "SRV");
        assert_eq!(srv.status, Status::Different);
        assert_eq!(srv.published, ["5 0 8443 mail.example.com."]);
        // Priority and weight are the admin's business.
        assert_eq!(
            find(&checks, "_caldavs._tcp.example.com", "SRV").status,
            Status::Ok
        );
        assert_eq!(
            find(&checks, "_mta-sts.example.com", "TXT").status,
            Status::Different
        );
        // Reports may go anywhere.
        assert_eq!(
            find(&checks, "_smtp._tls.example.com", "TXT").status,
            Status::Ok
        );
        assert_eq!(
            find(&checks, "_caldavs._tcp.example.com", "TXT").status,
            Status::Different
        );
    }

    #[test]
    fn cloudflare_ranges_are_matched_by_prefix() {
        for inside in [
            "104.16.0.1",
            "172.71.255.255",
            "2a06:98c7::1",
            "2606:4700::6810:1",
        ] {
            assert!(in_cloudflare(inside.parse().unwrap()), "{inside}");
        }
        for outside in [
            "104.32.0.1",
            "172.72.0.0",
            "203.0.113.5",
            "2a06:98c8::1",
            "2001:db8::1",
        ] {
            assert!(!in_cloudflare(outside.parse().unwrap()), "{outside}");
        }
    }
}
