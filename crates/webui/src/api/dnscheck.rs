//! Live DNS and deliverability checks, and the setup checklist built on them.
//!
//! Looking every record up and knocking on port 25 takes a moment, so the answers are kept in memory
//! and refreshed on a timer, on request, and whenever the records this server
//! expects change (a new DKIM key, another domain). The checklist's other
//! steps (certificate, settings) are cheap and read fresh on every request.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use rmail_common::config::Config;
use rmail_common::deliverability::{self, Deliverability, Listed, Reach};
use rmail_common::discovery::{DnsRecord, MtaStsMode};
use rmail_common::dmarc_reports::{self, DomainSummary};
use rmail_common::dnscheck::{self, Dns, Host, Lookup, Need, RecordCheck, Status, SystemDns};
use rmail_common::feedback::{self, Unrecorded};
use rmail_common::transport::{self, RouteAction};
use serde::Serialize;

use super::{ApiError, Shared, blocking, require_db};

/// How often the background task looks everything up again.
const CHECK_INTERVAL: Duration = Duration::from_secs(30 * 60);
/// Give the listeners and the resolver time to settle before the first pass.
const FIRST_CHECK: Duration = Duration::from_secs(90);
const SMTP_PORT: u16 = 25;
/// The stretch of DMARC reports a recommendation is based on.
const DMARC_WINDOW: Duration = Duration::from_secs(14 * 24 * 3600);
/// Fewer reported messages than this say too little to advise on.
const DMARC_MIN_MESSAGES: u64 = 20;
/// The reports must span about a week, so weekday-only senders are in them.
const DMARC_MIN_SPAN_SECS: i64 = 6 * 24 * 3600;
/// Independent reporters that must agree before advising a policy change.
const DMARC_MIN_REPORTERS: usize = 2;
const FEEDBACK_WINDOW: Duration = Duration::from_secs(30 * 24 * 3600);

pub(crate) fn routes() -> Router<Shared> {
    Router::new().route("/api/dns-checks", get(cached).post(recheck))
}

/// The last round of lookups. Holding the lock while checking makes
/// concurrent requests wait for one pass instead of each starting their own.
#[derive(Default)]
pub(crate) struct Cache(tokio::sync::Mutex<Option<Arc<Snapshot>>>);

/// What DNS said, and what was asked.
pub(crate) struct Snapshot {
    checked_at: i64,
    host: Host,
    /// How the server looks from outside; `None` when a smarthost sends its
    /// mail, so its own address is not what receivers see.
    outbound: Option<Deliverability>,
    /// Per domain, in the order of `expected`.
    domains: Vec<(String, Vec<RecordCheck>)>,
    /// The records looked up; a different set means the snapshot is stale.
    expected: Vec<(String, Vec<DnsRecord>)>,
}

/// Everything the report needs that is not a DNS answer.
struct Inputs {
    hostname: String,
    domains: Vec<DomainInput>,
    certificate: Certificate,
    mta_sts: bool,
    feedback_loop: bool,
    dane: bool,
    smarthost: bool,
    compose_ai: bool,
    acme: bool,
    /// What other mail systems reported about each domain's mail lately.
    dmarc_reports: Vec<DomainSummary>,
    /// Abuse reports that arrived with no feedback-loop address to record them.
    unrecorded_feedback: Vec<Unrecorded>,
}

struct DomainInput {
    domain: String,
    records: Vec<DnsRecord>,
    dkim_keys: usize,
}

enum Certificate {
    Trusted,
    SelfSigned,
    Expired,
    Unreadable(String),
    None,
}

impl Inputs {
    fn load(config_path: &str, db: &str) -> anyhow::Result<Self> {
        let config = Config::load(config_path)?;
        let domains = super::discovery::suggested_records(&config, db)?
            .into_iter()
            .map(|entry| DomainInput {
                domain: entry.domain,
                records: entry.records,
                dkim_keys: entry.dkim.len(),
            })
            .collect();
        let certificate = match super::certificates::installed_certificate(&config) {
            (Some(info), _) if info.not_after < now() => Certificate::Expired,
            (Some(info), _) if info.self_signed => Certificate::SelfSigned,
            (Some(_), _) => Certificate::Trusted,
            (None, Some(error)) => Certificate::Unreadable(error),
            (None, None) => Certificate::None,
        };
        let smarthost = transport::list_routes(std::path::Path::new(db))?
            .iter()
            .any(|route| route.domain == "*" && matches!(route.action, RouteAction::Relay { .. }));
        Ok(Self {
            hostname: config.global.server_hostname(),
            domains,
            certificate,
            mta_sts: config.security.mta_sts_mode != MtaStsMode::None,
            feedback_loop: !config.security.feedback_addresses.is_empty(),
            dane: config.security.dane_enabled,
            smarthost,
            compose_ai: config.compose_ai.available(),
            acme: config.acme.enabled,
            dmarc_reports: dmarc_reports::summary(
                std::path::Path::new(db),
                now() - DMARC_WINDOW.as_secs() as i64,
            )?,
            unrecorded_feedback: feedback::unrecorded(
                std::path::Path::new(db),
                now() - FEEDBACK_WINDOW.as_secs() as i64,
            )?,
        })
    }

    fn expected(&self) -> Vec<(String, Vec<DnsRecord>)> {
        self.domains
            .iter()
            .map(|entry| (entry.domain.clone(), entry.records.clone()))
            .collect()
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64)
}

async fn take_snapshot(dns: &impl Dns, inputs: &Inputs) -> Snapshot {
    let host = Host::resolve(dns, &inputs.hostname).await;
    let outbound = if inputs.smarthost {
        None
    } else {
        let port25 = deliverability::probe_port25(dns, &host.name, SMTP_PORT).await;
        Some(deliverability::check(dns, &host, port25).await)
    };
    let mut domains = Vec::with_capacity(inputs.domains.len());
    for entry in &inputs.domains {
        let checks = dnscheck::check_domain(dns, &entry.domain, &host, &entry.records).await;
        domains.push((entry.domain.clone(), checks));
    }
    Snapshot {
        checked_at: now(),
        host,
        outbound,
        domains,
        expected: inputs.expected(),
    }
}

impl Snapshot {
    fn answers(&self, inputs: &Inputs) -> bool {
        self.host.name == inputs.hostname.trim_end_matches('.').to_ascii_lowercase()
            && self.expected == inputs.expected()
    }

    fn fresh(&self) -> bool {
        now() - self.checked_at < CHECK_INTERVAL.as_secs() as i64
    }

    /// Required checks that got no answer, as the prefix their entry in
    /// `failures` would have.
    fn unchecked(&self) -> Vec<String> {
        self.domains
            .iter()
            .flat_map(|(domain, checks)| {
                checks
                    .iter()
                    .filter(|check| check.need == Need::Required && check.status == Status::Unknown)
                    .map(move |check| format!("{domain}: {} {} ", check.name, check.kind))
            })
            .chain(self.outbound.iter().flat_map(|outbound| {
                let port25 = [&outbound.port25.v4, &outbound.port25.v6]
                    .into_iter()
                    .any(|reach| matches!(reach, Reach::Unknown { .. }))
                    .then(|| "server: port 25 ".to_string());
                let lists = outbound.addresses.iter().flat_map(|address| {
                    address
                        .blocklists
                        .iter()
                        .filter(|list| list.status == Listed::Unknown)
                        .map(move |list| format!("server: {} {} ", address.address, list.zone))
                });
                port25.into_iter().chain(lists).collect::<Vec<_>>()
            }))
            .collect()
    }

    /// Required records that are published wrongly or not at all, as
    /// `domain: name TYPE status`.
    fn failures(&self) -> Vec<String> {
        let records = self
            .domains
            .iter()
            .flat_map(|(domain, checks)| {
                checks
                    .iter()
                    .filter(|check| {
                        check.need == Need::Required
                            && !check.status.works()
                            && check.status != Status::Unknown
                    })
                    .map(move |check| {
                        format!(
                            "{domain}: {} {} {}",
                            check.name,
                            check.kind,
                            serde_json::to_value(check.status)
                                .ok()
                                .and_then(|status| status.as_str().map(str::to_string))
                                .unwrap_or_default()
                        )
                    })
            })
            .collect::<Vec<_>>();
        records
            .into_iter()
            .chain(self.outbound_failures())
            .collect()
    }

    /// What stops mail leaving or being accepted, as `server: what state`.
    fn outbound_failures(&self) -> Vec<String> {
        let Some(outbound) = &self.outbound else {
            return Vec::new();
        };
        let mut failures = Vec::new();
        let blocked = |reach: &Reach| matches!(reach, Reach::Blocked { .. });
        if !outbound.port25.open() && (blocked(&outbound.port25.v4) || blocked(&outbound.port25.v6))
        {
            failures.push("server: port 25 blocked".to_string());
        }
        for address in &outbound.addresses {
            for list in &address.blocklists {
                if list.status == Listed::Listed {
                    failures.push(format!("server: {} {} listed", address.address, list.zone));
                }
            }
        }
        failures
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum StepState {
    Done,
    Todo,
    /// A lookup failed, so there is no telling.
    Unknown,
}

/// One line of the setup checklist.
#[derive(Debug, Serialize)]
struct Step {
    id: &'static str,
    need: Need,
    title: &'static str,
    /// Why the step matters, for someone who has not run a mail server.
    why: &'static str,
    state: StepState,
    detail: Option<String>,
    /// The console page where it is fixed, when there is one.
    page: Option<&'static str>,
}

#[derive(Serialize)]
struct DomainReport<'a> {
    domain: &'a str,
    records: &'a [RecordCheck],
    steps: Vec<Step>,
    /// Totals of the DMARC reports received about the domain, when any came.
    dmarc_reports: Option<&'a DomainSummary>,
}

/// Something the server noticed that the admin may want to act on. Unlike a
/// checklist step it comes from what happened, not from what is configured.
#[derive(Debug, Serialize)]
struct Recommendation {
    id: String,
    title: String,
    detail: String,
    page: &'static str,
}

#[derive(Serialize)]
struct Report<'a> {
    checked_at: i64,
    hostname: &'a str,
    addresses: Vec<String>,
    server: Vec<Step>,
    domains: Vec<DomainReport<'a>>,
    outbound: Option<&'a Deliverability>,
    recommendations: Vec<Recommendation>,
}

fn describe(check: &RecordCheck) -> String {
    match (&check.detail, check.status) {
        (Some(detail), _) => detail.clone(),
        (None, Status::Missing) => format!("{} ({}) is not published.", check.name, check.kind),
        (None, _) => format!(
            "{} ({}) is not what this server expects.",
            check.name, check.kind
        ),
    }
}

/// A step that is done when all of `checks` work.
fn from_checks(checks: &[&RecordCheck]) -> (StepState, Option<String>) {
    let failing = checks
        .iter()
        .filter(|check| !check.status.works() && check.status != Status::Unknown)
        .collect::<Vec<_>>();
    match failing.as_slice() {
        [] => {}
        [one] if checks.len() == 1 => return (StepState::Todo, Some(describe(one))),
        [one] => {
            return (
                StepState::Todo,
                Some(format!("{}: {}", one.name, describe(one))),
            );
        }
        many => {
            return (
                StepState::Todo,
                Some(format!(
                    "{} of {} records are missing or wrong.",
                    many.len(),
                    checks.len()
                )),
            );
        }
    }
    if let Some(unknown) = checks.iter().find(|check| check.status == Status::Unknown) {
        return (StepState::Unknown, unknown.detail.clone());
    }
    let advice = checks
        .iter()
        .find(|check| check.status == Status::Improve)
        .and_then(|check| check.detail.clone());
    (StepState::Done, advice)
}

fn domain_steps(checks: &[RecordCheck], dkim_keys: usize, mta_sts: bool) -> Vec<Step> {
    let mut mx = Vec::new();
    let mut spf = Vec::new();
    let mut dkim = Vec::new();
    let mut dmarc = Vec::new();
    let mut transport_security = Vec::new();
    let mut clients = Vec::new();
    for check in checks {
        let label = check.name.split('.').next().unwrap_or("");
        let group = if check.kind == "MX" {
            &mut mx
        } else if check.name.contains("._domainkey.") {
            &mut dkim
        } else if label == "_dmarc" {
            &mut dmarc
        } else if check.value.starts_with("v=spf1") {
            &mut spf
        } else if matches!(label, "_mta-sts" | "mta-sts") || check.name.starts_with("_smtp._tls.") {
            &mut transport_security
        } else {
            &mut clients
        };
        group.push(check);
    }
    let step = |id, need, title, why, (state, detail): (StepState, Option<String>)| Step {
        id,
        need,
        title,
        why,
        state,
        detail,
        page: Some("domains"),
    };
    let mut steps = vec![
        step(
            "mx",
            Need::Required,
            "MX record",
            "Tells other servers to deliver the domain's mail here. Without it, mail goes elsewhere or bounces.",
            from_checks(&mx),
        ),
        step(
            "spf",
            Need::Required,
            "SPF record",
            "Lists the servers allowed to send for the domain. Receivers distrust mail from domains without one.",
            from_checks(&spf),
        ),
        step(
            "dkim",
            Need::Required,
            "DKIM signing",
            "Signs outgoing mail so receivers can tell it is really yours. The large mailbox providers expect it.",
            if dkim_keys == 0 {
                (
                    StepState::Todo,
                    Some("No signing key yet. Create one, then publish its record.".to_string()),
                )
            } else {
                from_checks(&dkim)
            },
        ),
        step(
            "dmarc",
            Need::Required,
            "DMARC policy",
            "Tells receivers what to do with mail that fails SPF and DKIM, and where to send reports about it.",
            from_checks(&dmarc),
        ),
    ];
    let mut sts = step(
        "mta_sts",
        Need::Recommended,
        "MTA-STS and TLS reports",
        "Makes other servers insist on an encrypted, verified connection when delivering to you, and report when that fails.",
        from_checks(&transport_security),
    );
    if !mta_sts {
        sts.state = StepState::Todo;
        sts.detail = Some(
            "MTA-STS is off. Turn it on under Settings (TLS), then publish its records."
                .to_string(),
        );
        sts.page = Some("settings");
    }
    steps.push(sts);
    steps.push(step(
        "clients",
        Need::Recommended,
        "Automatic client setup",
        "Lets mail and calendar apps find the server from just an email address, so users do not type host names and ports.",
        from_checks(&clients),
    ));
    steps
}

/// The steps about sending mail directly: reaching other servers, and how
/// the sending address looks to them.
fn outbound_steps(outbound: &Deliverability) -> Vec<Step> {
    let port25 = &outbound.port25;
    let (reachable, reachable_detail) = match (&port25.v4, &port25.v6) {
        (Reach::Open { .. }, _) | (Reach::Unavailable, Reach::Open { .. }) => {
            (StepState::Done, None)
        }
        (Reach::Blocked { .. }, Reach::Open { .. }) => (
            StepState::Todo,
            Some("Port 25 is open over IPv6 only. Most mail servers are reached over IPv4, where it is blocked: ask your hosting provider to open it, or send through a smarthost.".to_string()),
        ),
        (Reach::Blocked { .. }, _) | (Reach::Unavailable, Reach::Blocked { .. }) => (
            StepState::Todo,
            Some("No mail server could be reached on port 25, so outgoing mail will sit in the queue. Hosting providers often block the port by default: ask yours to open it, or send through a smarthost (Routing).".to_string()),
        ),
        (Reach::Unavailable, Reach::Unavailable) => (
            StepState::Todo,
            Some("This server has no route to the internet.".to_string()),
        ),
        (Reach::Unknown { error }, _) | (_, Reach::Unknown { error }) => (
            StepState::Unknown,
            Some(format!("Could not find a mail server to try: {error}")),
        ),
    };

    let reverses = outbound.addresses.iter().map(|address| &address.reverse);
    let (reverse, reverse_detail) = if outbound.addresses.is_empty() {
        (
            StepState::Unknown,
            Some("The address this server sends from could not be determined.".to_string()),
        )
    } else if let Some(wrong) = reverses.clone().find(|reverse| {
        matches!(
            reverse.status,
            Status::Missing | Status::Different | Status::Problem
        )
    }) {
        (StepState::Todo, wrong.detail.clone())
    } else if let Some(unknown) = reverses
        .clone()
        .find(|reverse| reverse.status == Status::Unknown)
    {
        (StepState::Unknown, unknown.detail.clone())
    } else {
        let advice = reverses
            .clone()
            .find(|reverse| reverse.status == Status::Improve)
            .and_then(|reverse| reverse.detail.clone());
        (StepState::Done, advice)
    };

    let lists = outbound
        .addresses
        .iter()
        .flat_map(|address| address.blocklists.iter().map(move |list| (address, list)))
        .collect::<Vec<_>>();
    let listed = lists
        .iter()
        .filter(|(_, list)| list.status == Listed::Listed)
        .map(|(address, list)| format!("{} is on {}", address.address, list.name))
        .collect::<Vec<_>>();
    let unchecked = lists
        .iter()
        .filter(|(_, list)| list.status == Listed::Unknown)
        .count();
    let (blocklists, blocklists_detail) = if !listed.is_empty() {
        (
            StepState::Todo,
            Some(format!(
                "{}. Receivers that use the list reject or junk your mail until the address is removed.",
                listed.join(", ")
            )),
        )
    } else if lists.is_empty() || unchecked == lists.len() {
        (
            StepState::Unknown,
            Some("None of the blocklists could be checked.".to_string()),
        )
    } else if unchecked > 0 {
        (
            StepState::Done,
            Some(format!(
                "Not listed where it could be checked; {unchecked} of {} lookups got no answer.",
                lists.len()
            )),
        )
    } else {
        (StepState::Done, None)
    };

    vec![
        Step {
            id: "port25",
            need: Need::Required,
            title: "Outbound port 25",
            why: "Mail is handed to other servers on port 25. Many cloud and home providers block it by default to stop spam.",
            state: reachable,
            detail: reachable_detail,
            page: Some("delivery"),
        },
        Step {
            id: "reverse_dns",
            need: Need::Recommended,
            title: "Reverse DNS (PTR)",
            why: "Receivers look up the name behind the sending address. Mail from an address that does not reverse to this server's name is often rejected or filed as spam.",
            state: reverse,
            detail: reverse_detail,
            page: Some("delivery"),
        },
        Step {
            id: "blocklists",
            need: Need::Required,
            title: "Not on a blocklist",
            why: "Receivers check the sending address against lists of known spam sources. A new server can inherit a listing from whoever had the address before.",
            state: blocklists,
            detail: blocklists_detail,
            page: Some("delivery"),
        },
    ]
}

fn server_steps(inputs: &Inputs, snapshot: &Snapshot) -> Vec<Step> {
    let (certificate, certificate_detail) = match &inputs.certificate {
        Certificate::Trusted => (StepState::Done, None),
        Certificate::SelfSigned => (
            StepState::Todo,
            Some("The certificate is self-signed. Turn on automatic certificates (ACME) or install one from a certificate authority.".to_string()),
        ),
        Certificate::Expired => (
            StepState::Todo,
            Some("The certificate has expired.".to_string()),
        ),
        Certificate::Unreadable(error) => (
            StepState::Todo,
            Some(format!("The certificate cannot be read: {error}")),
        ),
        Certificate::None => (
            StepState::Todo,
            Some("No certificate is installed.".to_string()),
        ),
    };
    let setting = |on: bool| {
        if on { StepState::Done } else { StepState::Todo }
    };
    let mut steps = vec![
        Step {
            id: "certificate",
            need: Need::Required,
            title: "A trusted TLS certificate",
            why: "Mail apps warn about a self-signed or expired certificate, and some servers refuse to deliver to one.",
            state: certificate,
            detail: certificate_detail,
            page: Some("certificates"),
        },
        Step {
            id: "feedback_loop",
            need: Need::Recommended,
            title: "A feedback-loop address",
            why: "Mailbox providers send a report there when someone marks your mail as spam, which is how you notice a compromised account early.",
            state: setting(inputs.feedback_loop),
            detail: None,
            page: Some("settings"),
        },
        Step {
            id: "dane",
            need: Need::Optional,
            title: "Outbound DANE",
            why: "Verifies the receiving server's certificate through DNSSEC where the recipient publishes TLSA records. Needs a resolver that validates DNSSEC.",
            state: setting(inputs.dane),
            detail: None,
            page: Some("settings"),
        },
        Step {
            id: "smarthost",
            need: Need::Optional,
            title: "A smarthost",
            why: "Sends outgoing mail through a relay provider. Only needed when your host blocks port 25 or your address has a poor reputation.",
            state: setting(inputs.smarthost),
            detail: None,
            page: Some("routing"),
        },
        Step {
            id: "compose_ai",
            need: Need::Optional,
            title: "AI writing suggestions",
            why: "Offers webmail users help while composing, using a language model you choose. Nothing depends on it.",
            state: setting(inputs.compose_ai),
            detail: None,
            page: Some("settings"),
        },
    ];
    // After the certificate, ahead of the settings-only steps.
    let outbound = match &snapshot.outbound {
        Some(outbound) => outbound_steps(outbound),
        None => vec![Step {
            id: "port25",
            need: Need::Required,
            title: "Outbound port 25",
            why: "Mail is handed to other servers on port 25. Many cloud and home providers block it by default to stop spam.",
            state: StepState::Done,
            detail: Some("Outgoing mail leaves through the smarthost, so this server needs neither port 25 nor a good reputation for its own address.".to_string()),
            page: Some("routing"),
        }],
    };
    steps.splice(1..1, outbound);
    steps
}

/// The policy (`p=`) of the DMARC record a domain publishes, when the check
/// found a working one of its own.
fn published_dmarc_policy(checks: &[RecordCheck]) -> Option<String> {
    let check = checks
        .iter()
        .find(|check| check.name.starts_with("_dmarc.") && check.status.works())?;
    check.published.first()?.split(';').find_map(|tag| {
        let (name, value) = tag.split_once('=')?;
        (name.trim().eq_ignore_ascii_case("p")).then(|| value.trim().to_ascii_lowercase())
    })
}

fn dmarc_recommendation(
    domain: &str,
    policy: Option<&str>,
    summary: &DomainSummary,
) -> Option<Recommendation> {
    if summary.messages < DMARC_MIN_MESSAGES {
        return None;
    }
    let days = DMARC_WINDOW.as_secs() / 86400;
    let failed = summary.messages - summary.passed.min(summary.messages);
    let seen = format!(
        "In the last {days} days, {} from {} covered {} messages claiming to be from {domain}",
        plural(summary.reports, "DMARC report"),
        reporters(summary),
        summary.messages
    );
    // Forgeries always fail, so "all passing" allows for a little noise.
    if summary.passed.saturating_mul(100) >= summary.messages.saturating_mul(98) {
        // One sender's word is not enough to change a policy on: a report
        // is only authenticated as coming from its sender, and anyone with
        // a domain can send one.
        if policy != Some("none")
            || summary.end - summary.begin < DMARC_MIN_SPAN_SECS
            || summary.reporters.len() < DMARC_MIN_REPORTERS
        {
            return None;
        }
        return Some(Recommendation {
            id: format!("dmarc-tighten-{domain}"),
            title: format!("Tighten the DMARC policy of {domain}"),
            detail: format!(
                "{seen}, and {} passed. Your own mail is authenticating, so it is safe to change p=none to p=quarantine in the _dmarc.{domain} record: receivers will then junk forgeries instead of delivering them.",
                if failed == 0 {
                    "all of them".to_string()
                } else {
                    format!("all but {failed}")
                }
            ),
            page: "domains",
        });
    }
    if summary.passed.saturating_mul(100) >= summary.messages.saturating_mul(90) {
        return None;
    }
    let sources = summary
        .failing
        .iter()
        .take(3)
        .map(|source| format!("{} ({})", source.source_ip, source.messages))
        .collect::<Vec<_>>()
        .join(", ");
    Some(Recommendation {
        id: format!("dmarc-failing-{domain}"),
        title: format!("Mail from {domain} is failing DMARC"),
        detail: format!(
            "{seen}, and {failed} failed, mostly from {sources}. If those are servers of yours, add them to the SPF record or have them sign with DKIM. If they are not, they are forgeries, which a stricter policy would stop{}.",
            if policy == Some("none") {
                " once your own mail passes"
            } else {
                ""
            }
        ),
        page: "domains",
    })
}

/// Who vouches for the numbers, so the admin can judge whether to believe
/// them: reports are only as trustworthy as their senders.
fn reporters(summary: &DomainSummary) -> String {
    let shown = summary
        .reporters
        .iter()
        .take(4)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    match summary.reporters.len() {
        0..=4 => shown,
        more => format!("{shown} and {} more", more - 4),
    }
}

fn plural(count: u64, word: &str) -> String {
    format!("{count} {word}{}", if count == 1 { "" } else { "s" })
}

fn recommendations(inputs: &Inputs, snapshot: &Snapshot) -> Vec<Recommendation> {
    let mut found = Vec::new();
    if !inputs.acme
        && matches!(
            inputs.certificate,
            Certificate::SelfSigned | Certificate::None
        )
    {
        found.push(Recommendation {
            id: "acme".to_string(),
            title: "Turn on automatic certificates".to_string(),
            detail: "The server has no certificate from a certificate authority, so mail apps warn about it. Let's Encrypt issues them free of charge and this server can request and renew one by itself.".to_string(),
            page: "certificates",
        });
    }
    for (domain, checks) in &snapshot.domains {
        let Some(summary) = inputs
            .dmarc_reports
            .iter()
            .find(|summary| &summary.domain == domain)
        else {
            continue;
        };
        let policy = published_dmarc_policy(checks);
        found.extend(dmarc_recommendation(domain, policy.as_deref(), summary));
    }
    if !inputs.feedback_loop
        && let Some(busiest) = inputs.unrecorded_feedback.first()
    {
        let total = inputs
            .unrecorded_feedback
            .iter()
            .map(|entry| entry.reports)
            .sum::<u64>();
        found.push(Recommendation {
            id: "feedback-loop".to_string(),
            title: "Record the abuse reports you are receiving".to_string(),
            detail: format!(
                "{} arrived in the last {} days, most at {}. They were delivered but not recorded, because no feedback-loop address is configured. Add {} under Settings (Filtering) and each complaint is tied to the account that sent the reported mail.",
                plural(total, "abuse report"),
                FEEDBACK_WINDOW.as_secs() / 86400,
                busiest.recipient,
                busiest.recipient
            ),
            page: "settings",
        });
    }
    found
}

fn report<'a>(inputs: &'a Inputs, snapshot: &'a Snapshot) -> Report<'a> {
    Report {
        checked_at: snapshot.checked_at,
        hostname: &snapshot.host.name,
        addresses: match &snapshot.host.addresses {
            Lookup::Found(addresses) => addresses.iter().map(ToString::to_string).collect(),
            _ => Vec::new(),
        },
        server: server_steps(inputs, snapshot),
        domains: snapshot
            .domains
            .iter()
            .zip(&inputs.domains)
            .map(|((domain, records), input)| DomainReport {
                domain,
                records,
                steps: domain_steps(records, input.dkim_keys, inputs.mta_sts),
                dmarc_reports: inputs
                    .dmarc_reports
                    .iter()
                    .find(|summary| &summary.domain == domain),
            })
            .collect(),
        outbound: snapshot.outbound.as_ref(),
        recommendations: recommendations(inputs, snapshot),
    }
}

async fn load_inputs(state: &Shared) -> Result<Inputs, ApiError> {
    let db = require_db(state)?;
    let Some(path) = state.config_path.clone() else {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "no configuration file is loaded".to_string(),
        ));
    };
    blocking(move || Inputs::load(&path, &db))
        .await
        .map_err(|err| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{err:#}")))
}

/// The snapshot for `inputs`, looked up again when `force` is set or the
/// cached one is old or about different records.
async fn snapshot_for(state: &Shared, inputs: &Inputs, force: bool) -> Arc<Snapshot> {
    let mut cache = state.dns_checks.0.lock().await;
    if !force
        && let Some(snapshot) = cache.as_ref()
        && snapshot.fresh()
        && snapshot.answers(inputs)
    {
        return snapshot.clone();
    }
    if force {
        SystemDns::forget_cached_answers();
    }
    let snapshot = Arc::new(take_snapshot(&SystemDns, inputs).await);
    *cache = Some(snapshot.clone());
    snapshot
}

async fn respond(state: Shared, force: bool) -> Response {
    let inputs = match load_inputs(&state).await {
        Ok(inputs) => inputs,
        Err(err) => return err.into_response(),
    };
    let snapshot = snapshot_for(&state, &inputs, force).await;
    Json(report(&inputs, &snapshot)).into_response()
}

async fn cached(State(state): State<Shared>) -> Response {
    respond(state, false).await
}

async fn recheck(State(state): State<Shared>) -> Response {
    respond(state, true).await
}

/// What is known to be broken after a pass: what it found, plus what was
/// reported before for records it could not look up. A resolver outage hides
/// broken records, it does not fix them.
fn known_failures(
    reported: &[String],
    mut found: Vec<String>,
    unchecked: &[String],
) -> Vec<String> {
    for earlier in reported {
        if unchecked.iter().any(|record| earlier.starts_with(record)) {
            found.push(earlier.clone());
        }
    }
    found.sort();
    found
}

/// Keep the snapshot current, and say so in the log when a domain's required
/// records break or recover, so it is noticed without anyone opening the
/// console.
pub(crate) fn spawn_check_task(state: Shared) {
    tokio::spawn(async move {
        tokio::time::sleep(FIRST_CHECK).await;
        let mut reported = Vec::new();
        loop {
            match load_inputs(&state).await {
                Ok(inputs) => {
                    let snapshot = snapshot_for(&state, &inputs, true).await;
                    let failures =
                        known_failures(&reported, snapshot.failures(), &snapshot.unchecked());
                    if failures != reported {
                        if failures.is_empty() {
                            web_log!("info", "dns_check_recovered", {});
                        } else {
                            web_log!("warn", "dns_check_failed", { "records": failures });
                        }
                        reported = failures;
                    }
                }
                Err(err) => {
                    web_log!("warn", "dns_check_skipped", { "error": err.1 })
                }
            }
            tokio::time::sleep(CHECK_INTERVAL).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmail_common::dnscheck::{SpfVerdict, Srv};
    use std::collections::HashMap;
    use std::net::IpAddr;

    const HOST: &str = "mail.example.com";

    /// A zone holding only what the test puts in it.
    #[derive(Default)]
    struct Zone {
        txt: HashMap<String, Vec<String>>,
        mx: HashMap<String, Vec<(u16, String)>>,
        cname: HashMap<String, String>,
        ips: HashMap<String, Vec<IpAddr>>,
        ptr: HashMap<IpAddr, Vec<String>>,
        spf_passes: bool,
        down: bool,
    }

    impl Zone {
        fn get<T: Clone>(&self, table: &HashMap<String, Vec<T>>, name: &str) -> Lookup<T> {
            match table.get(name) {
                _ if self.down => Lookup::Failed("timed out".into()),
                Some(values) => Lookup::Found(values.clone()),
                None => Lookup::Missing,
            }
        }
    }

    impl Dns for Zone {
        async fn txt(&self, name: &str) -> Lookup<String> {
            self.get(&self.txt, name)
        }
        async fn mx(&self, name: &str) -> Lookup<(u16, String)> {
            self.get(&self.mx, name)
        }
        async fn cname(&self, name: &str) -> Lookup<String> {
            match self.cname.get(name) {
                _ if self.down => Lookup::Failed("timed out".into()),
                Some(target) => Lookup::Found(vec![target.clone()]),
                None => Lookup::Missing,
            }
        }
        async fn srv(&self, _name: &str) -> Lookup<Srv> {
            Lookup::Missing
        }
        async fn ips(&self, name: &str) -> Lookup<IpAddr> {
            self.get(&self.ips, name)
        }
        async fn ptr(&self, ip: IpAddr) -> Lookup<String> {
            match self.ptr.get(&ip) {
                Some(names) => Lookup::Found(names.clone()),
                None => Lookup::Missing,
            }
        }
        async fn spf(&self, _domain: &str, _ip: IpAddr, _helo: &str) -> SpfVerdict {
            if self.spf_passes {
                SpfVerdict::Pass
            } else {
                SpfVerdict::NotPass("fail")
            }
        }
    }

    fn record(name: &str, kind: &'static str, value: &str) -> DnsRecord {
        DnsRecord {
            name: name.to_string(),
            kind,
            value: value.to_string(),
            purpose: "",
        }
    }

    fn inputs() -> Inputs {
        Inputs {
            hostname: HOST.to_string(),
            domains: vec![DomainInput {
                domain: "example.com".to_string(),
                records: vec![
                    record("example.com", "MX", "10 mail.example.com."),
                    record("example.com", "TXT", "v=spf1 mx -all"),
                    record("_dmarc.example.com", "TXT", "v=DMARC1; p=none"),
                    record("autoconfig.example.com", "CNAME", "mail.example.com."),
                    record(
                        "_smtp._tls.example.com",
                        "TXT",
                        "v=TLSRPTv1; rua=mailto:p@example.com",
                    ),
                    record(
                        "mail._domainkey.example.com",
                        "TXT",
                        "v=DKIM1; k=rsa; p=KEY",
                    ),
                ],
                dkim_keys: 1,
            }],
            certificate: Certificate::Trusted,
            mta_sts: false,
            feedback_loop: true,
            dane: false,
            smarthost: false,
            compose_ai: false,
            acme: false,
            dmarc_reports: Vec::new(),
            unrecorded_feedback: Vec::new(),
        }
    }

    fn zone() -> Zone {
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let mut zone = Zone {
            spf_passes: true,
            ..Zone::default()
        };
        zone.ips.insert(HOST.into(), vec![ip]);
        zone.ptr.insert(ip, vec![HOST.into()]);
        zone.mx
            .insert("example.com".into(), vec![(10, HOST.into())]);
        zone.txt
            .insert("example.com".into(), vec!["v=spf1 mx -all".into()]);
        zone.txt.insert(
            "_dmarc.example.com".into(),
            vec!["v=DMARC1; p=none; rua=mailto:p@example.com".into()],
        );
        zone.txt.insert(
            "mail._domainkey.example.com".into(),
            vec!["v=DKIM1; k=rsa; p=KEY".into()],
        );
        zone
    }

    fn step<'a>(steps: &'a [Step], id: &str) -> &'a Step {
        steps.iter().find(|step| step.id == id).unwrap()
    }

    #[tokio::test]
    async fn checklist_follows_dns_and_settings() {
        let inputs = inputs();
        let snapshot = take_snapshot(&zone(), &inputs).await;
        let report = report(&inputs, &snapshot);
        assert_eq!(report.hostname, HOST);
        assert_eq!(report.addresses, ["203.0.113.5"]);
        // The probe targets do not resolve in this zone, so port 25 is the
        // one thing left unchecked.
        assert!(snapshot.failures().is_empty());
        assert_eq!(snapshot.unchecked(), ["server: port 25 "]);

        let steps = &report.domains[0].steps;
        let ids = steps.iter().map(|step| step.id).collect::<Vec<_>>();
        assert_eq!(ids, ["mx", "spf", "dkim", "dmarc", "mta_sts", "clients"]);
        for id in ["mx", "spf", "dkim"] {
            let step = step(steps, id);
            assert_eq!((step.state, step.need), (StepState::Done, Need::Required));
            assert_eq!(step.detail, None);
        }
        // Done, with the advice about p=none carried along.
        let dmarc = step(steps, "dmarc");
        assert_eq!(dmarc.state, StepState::Done);
        assert!(dmarc.detail.as_deref().unwrap().contains("p=none"));
        // Off in the settings: fixed there, not in DNS.
        let sts = step(steps, "mta_sts");
        assert_eq!((sts.state, sts.page), (StepState::Todo, Some("settings")));
        let clients = step(steps, "clients");
        assert_eq!(clients.state, StepState::Todo);
        assert_eq!(
            clients.detail.as_deref(),
            Some("autoconfig.example.com (CNAME) is not published.")
        );

        let server = &report.server;
        assert_eq!(step(server, "certificate").state, StepState::Done);
        assert_eq!(step(server, "port25").state, StepState::Unknown);
        assert_eq!(step(server, "reverse_dns").state, StepState::Done);
        assert_eq!(step(server, "blocklists").state, StepState::Done);
        assert_eq!(step(server, "feedback_loop").state, StepState::Done);
        for id in ["dane", "smarthost", "compose_ai"] {
            let step = step(server, id);
            assert_eq!((step.state, step.need), (StepState::Todo, Need::Optional));
        }
    }

    #[tokio::test]
    async fn broken_records_become_todo_steps_and_logged_failures() {
        let mut inputs = inputs();
        inputs.certificate = Certificate::SelfSigned;
        inputs.domains[0].dkim_keys = 0;
        inputs.domains[0].records.pop();
        let mut zone = zone();
        zone.mx
            .insert("example.com".into(), vec![(10, "mx.elsewhere.net".into())]);
        zone.txt.remove("example.com");
        zone.ptr.clear();
        let snapshot = take_snapshot(&zone, &inputs).await;
        assert_eq!(
            snapshot.failures(),
            [
                "example.com: example.com MX problem",
                "example.com: example.com TXT missing"
            ]
        );
        let report = report(&inputs, &snapshot);
        let steps = &report.domains[0].steps;
        let mx = step(steps, "mx");
        assert_eq!(mx.state, StepState::Todo);
        assert!(mx.detail.as_deref().unwrap().contains("mx.elsewhere.net"));
        assert_eq!(
            step(steps, "spf").detail.as_deref(),
            Some("example.com (TXT) is not published.")
        );
        let dkim = step(steps, "dkim");
        assert_eq!(dkim.state, StepState::Todo);
        assert!(dkim.detail.as_deref().unwrap().contains("No signing key"));

        let certificate = step(&report.server, "certificate");
        assert_eq!(certificate.state, StepState::Todo);
        assert!(
            certificate
                .detail
                .as_deref()
                .unwrap()
                .contains("self-signed")
        );
        let reverse = step(&report.server, "reverse_dns");
        assert_eq!(reverse.state, StepState::Todo);
        assert!(
            reverse
                .detail
                .as_deref()
                .unwrap()
                .starts_with("203.0.113.5 has no reverse DNS")
        );
    }

    fn outbound(v4: Reach, v6: Reach, listed: bool) -> Deliverability {
        use rmail_common::deliverability::{Address, Blocklist, Port25, Reverse, Source};
        Deliverability {
            port25: Port25 { v4, v6 },
            addresses: vec![Address {
                address: "203.0.113.5".parse().unwrap(),
                source: Source::Seen,
                reverse: Reverse {
                    status: Status::Improve,
                    names: vec!["static.provider.net".into()],
                    detail: Some("reverses to static.provider.net".into()),
                },
                blocklists: vec![
                    Blocklist {
                        zone: "zen.spamhaus.org",
                        name: "Spamhaus ZEN",
                        status: if listed {
                            Listed::Listed
                        } else {
                            Listed::Unknown
                        },
                        code: None,
                        detail: None,
                    },
                    Blocklist {
                        zone: "bl.spamcop.net",
                        name: "SpamCop",
                        status: Listed::Clean,
                        code: None,
                        detail: None,
                    },
                ],
            }],
        }
    }

    fn open() -> Reach {
        Reach::Open {
            target: "mx.example.net".into(),
            local: "203.0.113.5".parse().unwrap(),
            seen_as: None,
        }
    }

    fn blocked() -> Reach {
        Reach::Blocked {
            error: "mx.example.net: no answer".into(),
        }
    }

    #[tokio::test]
    async fn outbound_steps_follow_the_probe() {
        let mut inputs = inputs();
        let mut snapshot = take_snapshot(&zone(), &inputs).await;

        snapshot.outbound = Some(outbound(blocked(), Reach::Unavailable, true));
        assert_eq!(
            snapshot.failures(),
            [
                "server: port 25 blocked",
                "server: 203.0.113.5 zen.spamhaus.org listed"
            ]
        );
        let steps = server_steps(&inputs, &snapshot);
        let ids = steps.iter().map(|step| step.id).collect::<Vec<_>>();
        assert_eq!(
            ids,
            [
                "certificate",
                "port25",
                "reverse_dns",
                "blocklists",
                "feedback_loop",
                "dane",
                "smarthost",
                "compose_ai"
            ]
        );
        let port25 = step(&steps, "port25");
        assert_eq!(
            (port25.state, port25.need),
            (StepState::Todo, Need::Required)
        );
        assert!(port25.detail.as_deref().unwrap().contains("smarthost"));
        let lists = step(&steps, "blocklists");
        assert_eq!(lists.state, StepState::Todo);
        assert!(
            lists
                .detail
                .as_deref()
                .unwrap()
                .starts_with("203.0.113.5 is on Spamhaus ZEN.")
        );
        // A valid name that is not the host's: done, with the advice kept.
        let reverse = step(&steps, "reverse_dns");
        assert_eq!(reverse.state, StepState::Done);
        assert!(reverse.detail.is_some());

        // Open over IPv6 alone is not enough; a list that will not answer
        // does not hide the ones that did.
        snapshot.outbound = Some(outbound(blocked(), open(), false));
        assert!(snapshot.failures().is_empty());
        assert_eq!(
            snapshot.unchecked(),
            ["server: 203.0.113.5 zen.spamhaus.org "]
        );
        let steps = server_steps(&inputs, &snapshot);
        let port25 = step(&steps, "port25");
        assert_eq!(port25.state, StepState::Todo);
        assert!(port25.detail.as_deref().unwrap().contains("IPv6 only"));
        let lists = step(&steps, "blocklists");
        assert_eq!(lists.state, StepState::Done);
        assert!(lists.detail.as_deref().unwrap().contains("1 of 2"));

        snapshot.outbound = Some(outbound(open(), blocked(), false));
        assert_eq!(
            step(&server_steps(&inputs, &snapshot), "port25").state,
            StepState::Done
        );

        // With a smarthost nothing is probed, and the server's own address
        // is nobody's concern.
        inputs.smarthost = true;
        let snapshot = take_snapshot(&zone(), &inputs).await;
        assert!(snapshot.outbound.is_none());
        let steps = server_steps(&inputs, &snapshot);
        let port25 = step(&steps, "port25");
        assert_eq!(port25.state, StepState::Done);
        assert!(port25.detail.as_deref().unwrap().contains("smarthost"));
        assert!(
            steps
                .iter()
                .all(|step| step.id != "reverse_dns" && step.id != "blocklists")
        );
        assert_eq!(step(&steps, "smarthost").state, StepState::Done);
    }

    fn reports(messages: u64, passed: u64, days: i64) -> DomainSummary {
        DomainSummary {
            domain: "example.com".to_string(),
            reports: 9,
            reporters: vec![
                "google.com".into(),
                "outlook.com".into(),
                "yahoo.com".into(),
            ],
            messages,
            passed,
            begin: 1_790_000_000,
            end: 1_790_000_000 + days * 86400,
            failing: vec![
                dmarc_reports::FailingSource {
                    source_ip: "198.51.100.9".into(),
                    messages: 40,
                    dkim: "fail".into(),
                    spf: "fail".into(),
                },
                dmarc_reports::FailingSource {
                    source_ip: "192.0.2.77".into(),
                    messages: 3,
                    dkim: "fail".into(),
                    spf: "fail".into(),
                },
            ],
        }
    }

    #[tokio::test]
    async fn recommendations_come_from_what_the_server_saw() {
        let mut inputs = inputs();
        let snapshot = take_snapshot(&zone(), &inputs).await;
        // Trusted certificate, a feedback address, no reports: nothing to say.
        assert!(recommendations(&inputs, &snapshot).is_empty());
        assert_eq!(
            published_dmarc_policy(&snapshot.domains[0].1).as_deref(),
            Some("none")
        );

        // A week of reports with nearly everything passing, at p=none.
        inputs.dmarc_reports = vec![reports(1210, 1204, 13)];
        let found = recommendations(&inputs, &snapshot);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "dmarc-tighten-example.com");
        assert_eq!(found[0].page, "domains");
        assert!(
            found[0]
                .detail
                .contains("9 DMARC reports from google.com, outlook.com, yahoo.com covered")
        );
        // A single sender's reports do not justify changing the policy.
        let mut lone = reports(1210, 1204, 13);
        lone.reporters.truncate(1);
        inputs.dmarc_reports = vec![lone];
        assert!(recommendations(&inputs, &snapshot).is_empty());
        inputs.dmarc_reports = vec![reports(1210, 1204, 13)];
        assert!(found[0].detail.contains("all but 6 passed"));
        assert!(found[0].detail.contains("p=quarantine"));
        let report = report(&inputs, &snapshot);
        assert_eq!(report.domains[0].dmarc_reports.unwrap().messages, 1210);
        assert_eq!(report.recommendations.len(), 1);

        // Too few messages, or too short a stretch, is not enough to go on.
        inputs.dmarc_reports = vec![reports(19, 19, 13)];
        assert!(recommendations(&inputs, &snapshot).is_empty());
        inputs.dmarc_reports = vec![reports(1210, 1210, 2)];
        assert!(recommendations(&inputs, &snapshot).is_empty());
        // Reports about a domain that is not hosted here are ignored.
        let mut foreign = reports(1210, 1210, 13);
        foreign.domain = "example.net".to_string();
        inputs.dmarc_reports = vec![foreign];
        assert!(recommendations(&inputs, &snapshot).is_empty());

        // A lot failing: say who, and do not suggest tightening.
        inputs.dmarc_reports = vec![reports(200, 157, 13)];
        let found = recommendations(&inputs, &snapshot);
        assert_eq!(found[0].id, "dmarc-failing-example.com");
        assert!(found[0].detail.contains("43 failed"));
        assert!(
            found[0]
                .detail
                .contains("198.51.100.9 (40), 192.0.2.77 (3)")
        );
        // In between (a few forwarders failing) there is nothing useful to say.
        inputs.dmarc_reports = vec![reports(200, 190, 13)];
        assert!(recommendations(&inputs, &snapshot).is_empty());

        // Already past p=none: nothing to tighten on this evidence.
        assert!(
            dmarc_recommendation("example.com", Some("quarantine"), &reports(500, 500, 13))
                .is_none()
        );
        assert!(dmarc_recommendation("example.com", None, &reports(500, 500, 13)).is_none());

        // Self-signed with ACME off; abuse reports with nowhere to go.
        inputs.dmarc_reports.clear();
        inputs.certificate = Certificate::SelfSigned;
        inputs.feedback_loop = false;
        inputs.unrecorded_feedback = vec![
            Unrecorded {
                recipient: "abuse@example.com".into(),
                reports: 4,
                last_received_at: 0,
            },
            Unrecorded {
                recipient: "postmaster@example.com".into(),
                reports: 1,
                last_received_at: 0,
            },
        ];
        let found = recommendations(&inputs, &snapshot);
        let ids = found.iter().map(|rec| rec.id.as_str()).collect::<Vec<_>>();
        assert_eq!(ids, ["acme", "feedback-loop"]);
        assert!(found[1].detail.starts_with(
            "5 abuse reports arrived in the last 30 days, most at abuse@example.com."
        ));
        // With ACME on the certificate is on its way; with an address set
        // the reports are being recorded.
        inputs.acme = true;
        inputs.feedback_loop = true;
        assert!(recommendations(&inputs, &snapshot).is_empty());
    }

    #[tokio::test]
    async fn failed_lookups_are_unknown_not_failures() {
        let inputs = inputs();
        let mut zone = zone();
        zone.down = true;
        let snapshot = take_snapshot(&zone, &inputs).await;
        // A resolver outage must not be reported as broken records, nor as
        // their recovery.
        assert!(snapshot.failures().is_empty());
        let unchecked = snapshot.unchecked();
        assert!(unchecked.contains(&"example.com: example.com MX ".to_string()));

        // What was broken before the outage stays reported, a record that
        // was looked up and is fine now drops out, and one newly found
        // broken is added even though other lookups failed.
        let reported = vec![
            "example.com: example.com MX problem".to_string(),
            "example.org: example.org MX missing".to_string(),
        ];
        assert_eq!(
            known_failures(&reported, Vec::new(), &unchecked),
            ["example.com: example.com MX problem"]
        );
        assert_eq!(
            known_failures(
                &reported,
                vec!["example.net: example.net TXT missing".to_string()],
                &unchecked
            ),
            [
                "example.com: example.com MX problem",
                "example.net: example.net TXT missing"
            ]
        );
        let report = report(&inputs, &snapshot);
        assert!(report.addresses.is_empty());
        for id in ["mx", "spf", "dkim", "dmarc", "clients"] {
            assert_eq!(
                step(&report.domains[0].steps, id).state,
                StepState::Unknown,
                "{id}"
            );
        }
        assert_eq!(
            step(&report.server, "reverse_dns").state,
            StepState::Unknown
        );
    }

    #[tokio::test]
    async fn a_snapshot_goes_stale_when_the_expected_records_change() {
        let mut inputs = inputs();
        let snapshot = take_snapshot(&zone(), &inputs).await;
        assert!(snapshot.fresh() && snapshot.answers(&inputs));
        inputs.domains[0].records.push(record(
            "new._domainkey.example.com",
            "TXT",
            "v=DKIM1; p=NEW",
        ));
        assert!(!snapshot.answers(&inputs));
        let mut inputs = self::inputs();
        inputs.hostname = "mx.example.com".to_string();
        assert!(!snapshot.answers(&inputs));
    }
}
