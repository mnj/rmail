//! Live DNS checks and the setup checklist built on them.
//!
//! Looking every record up takes a moment, so the answers are kept in memory
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
use rmail_common::discovery::{DnsRecord, MtaStsMode};
use rmail_common::dnscheck::{
    self, Dns, Host, Lookup, Need, RecordCheck, ReverseCheck, Status, SystemDns,
};
use rmail_common::transport::{self, RouteAction};
use serde::Serialize;

use super::{Shared, blocking, error, require_db};

/// How often the background task looks everything up again.
const CHECK_INTERVAL: Duration = Duration::from_secs(30 * 60);
/// Give the listeners and the resolver time to settle before the first pass.
const FIRST_CHECK: Duration = Duration::from_secs(90);

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
    reverse: Vec<ReverseCheck>,
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
    let reverse = dnscheck::check_reverse(dns, &host).await;
    let mut domains = Vec::with_capacity(inputs.domains.len());
    for entry in &inputs.domains {
        let checks = dnscheck::check_domain(dns, &entry.domain, &host, &entry.records).await;
        domains.push((entry.domain.clone(), checks));
    }
    Snapshot {
        checked_at: now(),
        host,
        reverse,
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

    /// Required records that are published wrongly or not at all, as
    /// `domain: name TYPE status`.
    fn failures(&self) -> Vec<String> {
        self.domains
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
            .collect()
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
}

#[derive(Serialize)]
struct Report<'a> {
    checked_at: i64,
    hostname: &'a str,
    addresses: Vec<String>,
    server: Vec<Step>,
    domains: Vec<DomainReport<'a>>,
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

fn reverse_step(host: &Host, reverse: &[ReverseCheck]) -> (StepState, Option<String>) {
    match &host.addresses {
        Lookup::Found(_) => {}
        Lookup::Missing => {
            return (
                StepState::Todo,
                Some(format!(
                    "{} has no address record, so there is nothing to check yet.",
                    host.name
                )),
            );
        }
        Lookup::Failed(error) => {
            return (
                StepState::Unknown,
                Some(format!("Could not resolve {}: {error}", host.name)),
            );
        }
    }
    let wrong = reverse
        .iter()
        .find(|check| matches!(check.status, Status::Missing | Status::Different));
    if let Some(check) = wrong {
        let found = if check.published.is_empty() {
            "has no reverse DNS".to_string()
        } else {
            format!("reverses to {}", check.published.join(", "))
        };
        return (
            StepState::Todo,
            Some(format!(
                "{} {found}. Ask whoever provides the address (usually your hosting provider) to set its PTR record to {}.",
                check.address, host.name
            )),
        );
    }
    if reverse.iter().any(|check| check.status == Status::Unknown) {
        return (
            StepState::Unknown,
            Some("The reverse lookup failed.".to_string()),
        );
    }
    (StepState::Done, None)
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
    let (reverse, reverse_detail) = reverse_step(&snapshot.host, &snapshot.reverse);
    let setting = |on: bool| {
        if on { StepState::Done } else { StepState::Todo }
    };
    vec![
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
            id: "reverse_dns",
            need: Need::Recommended,
            title: "Reverse DNS (PTR)",
            why: "Receivers look up the name behind the sending address. Mail from an address that does not reverse to this server's name is often rejected or filed as spam.",
            state: reverse,
            detail: reverse_detail,
            page: None,
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
    ]
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
            })
            .collect(),
    }
}

async fn load_inputs(state: &Shared) -> Result<Inputs, Response> {
    let db = require_db(state).map_err(IntoResponse::into_response)?;
    let Some(path) = state.config_path.clone() else {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "no configuration file is loaded",
        ));
    };
    blocking(move || Inputs::load(&path, &db))
        .await
        .map_err(|err| error(StatusCode::INTERNAL_SERVER_ERROR, format!("{err:#}")))
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
        Err(response) => return response,
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
                    let failures = snapshot_for(&state, &inputs, true).await.failures();
                    if failures != reported {
                        if failures.is_empty() {
                            web_log!("info", "dns_check_recovered", {});
                        } else {
                            web_log!("warn", "dns_check_failed", { "records": failures });
                        }
                        reported = failures;
                    }
                }
                Err(response) => {
                    web_log!("warn", "dns_check_skipped", { "status": response.status().as_u16() })
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
        assert!(snapshot.failures().is_empty());

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
        assert_eq!(step(server, "reverse_dns").state, StepState::Done);
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

    #[tokio::test]
    async fn failed_lookups_are_unknown_not_failures() {
        let inputs = inputs();
        let mut zone = zone();
        zone.down = true;
        let snapshot = take_snapshot(&zone, &inputs).await;
        // A resolver outage must not be reported as broken records.
        assert!(snapshot.failures().is_empty());
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
