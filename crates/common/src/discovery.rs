//! Client auto-configuration (Thunderbird autoconfig, Outlook autodiscover),
//! MTA-STS policy publishing (RFC 8461) and the DNS records an operator
//! should publish for a hosted domain.

use crate::config::Global;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// How a client protects its connection to a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    /// TLS from the first byte (IMAPS 993, SMTPS 465).
    Tls,
    /// Plain connection upgraded with STARTTLS (IMAP 143, submission 587).
    StartTls,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    pub port: u16,
    pub security: Security,
}

/// What mail clients should connect to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceEndpoints {
    pub hostname: String,
    pub imap: Option<Endpoint>,
    pub smtp: Option<Endpoint>,
}

fn first_port(addresses: &[String]) -> Option<u16> {
    addresses
        .iter()
        .find_map(|address| address.rsplit_once(':')?.1.parse().ok())
}

impl ServiceEndpoints {
    /// Prefer implicit TLS (RFC 8314) over STARTTLS for each service.
    pub fn from_global(global: &Global) -> Self {
        let pick = |tls: Vec<String>, starttls: Vec<String>| {
            first_port(&tls)
                .map(|port| Endpoint {
                    port,
                    security: Security::Tls,
                })
                .or_else(|| {
                    first_port(&starttls).map(|port| Endpoint {
                        port,
                        security: Security::StartTls,
                    })
                })
        };
        Self {
            hostname: global.server_hostname(),
            imap: pick(global.imaps_listeners(), global.imap_listeners()),
            smtp: pick(global.smtps_listeners(), global.submission_listeners()),
        }
    }
}

/// Escape text for an XML element or attribute value.
fn xml(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&apos;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

/// Thunderbird "autoconfig" (config-v1.1.xml). Usernames are the full address.
pub fn thunderbird_config(domain: &str, endpoints: &ServiceEndpoints) -> String {
    let socket = |security| match security {
        Security::Tls => "SSL",
        Security::StartTls => "STARTTLS",
    };
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<clientConfig version=\"1.1\">\n  <emailProvider id=\"{d}\">\n    <domain>{d}</domain>\n    <displayName>{d} Mail</displayName>\n    <displayShortName>{d}</displayShortName>\n",
        d = xml(domain)
    );
    if let Some(imap) = &endpoints.imap {
        out.push_str(&format!(
            "    <incomingServer type=\"imap\">\n      <hostname>{}</hostname>\n      <port>{}</port>\n      <socketType>{}</socketType>\n      <authentication>password-cleartext</authentication>\n      <username>%EMAILADDRESS%</username>\n    </incomingServer>\n",
            xml(&endpoints.hostname),
            imap.port,
            socket(imap.security)
        ));
    }
    if let Some(smtp) = &endpoints.smtp {
        out.push_str(&format!(
            "    <outgoingServer type=\"smtp\">\n      <hostname>{}</hostname>\n      <port>{}</port>\n      <socketType>{}</socketType>\n      <authentication>password-cleartext</authentication>\n      <username>%EMAILADDRESS%</username>\n    </outgoingServer>\n",
            xml(&endpoints.hostname),
            smtp.port,
            socket(smtp.security)
        ));
    }
    out.push_str("  </emailProvider>\n</clientConfig>\n");
    out
}

/// Outlook "autodiscover" POX response for `email`.
pub fn outlook_autodiscover(email: &str, endpoints: &ServiceEndpoints) -> String {
    let protocol = |kind: &str, endpoint: &Endpoint| {
        let (ssl, encryption) = match endpoint.security {
            Security::Tls => ("on", "SSL"),
            Security::StartTls => ("on", "TLS"),
        };
        format!(
            "      <Protocol>\n        <Type>{kind}</Type>\n        <Server>{}</Server>\n        <Port>{}</Port>\n        <DomainRequired>off</DomainRequired>\n        <LoginName>{}</LoginName>\n        <SPA>off</SPA>\n        <SSL>{ssl}</SSL>\n        <Encryption>{encryption}</Encryption>\n        <AuthRequired>on</AuthRequired>\n      </Protocol>\n",
            xml(&endpoints.hostname),
            endpoint.port,
            xml(email)
        )
    };
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\">\n  <Response xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a\">\n    <Account>\n      <AccountType>email</AccountType>\n      <Action>settings</Action>\n",
    );
    if let Some(imap) = &endpoints.imap {
        out.push_str(&protocol("IMAP", imap));
    }
    if let Some(smtp) = &endpoints.smtp {
        out.push_str(&protocol("SMTP", smtp));
    }
    out.push_str("    </Account>\n  </Response>\n</Autodiscover>\n");
    out
}

/// Pull `<EMailAddress>` out of an Outlook autodiscover request body.
pub fn autodiscover_request_email(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<emailaddress>")? + "<emailaddress>".len();
    let end = start + lower[start..].find("</emailaddress>")?;
    let email = body[start..end].trim();
    (!email.is_empty() && email.len() <= 320 && !email.contains(['<', '>', '&']))
        .then(|| email.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MtaStsMode {
    /// Not published.
    #[default]
    None,
    Testing,
    Enforce,
}

impl MtaStsMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Testing => "testing",
            Self::Enforce => "enforce",
        }
    }
}

/// The policy file for `mta-sts.<domain>/.well-known/mta-sts.txt`, or `None`
/// when publishing is off. MX is the server hostname.
pub fn mta_sts_policy(mode: MtaStsMode, hostname: &str, max_age_secs: u64) -> Option<String> {
    (mode != MtaStsMode::None).then(|| {
        format!(
            "version: STSv1\r\nmode: {}\r\nmx: {hostname}\r\nmax_age: {max_age_secs}\r\n",
            mode.as_str()
        )
    })
}

/// Policy id for the `_mta-sts` TXT record; changes whenever the policy does.
pub fn mta_sts_id(policy: &str) -> String {
    let digest = Sha256::digest(policy.as_bytes());
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub value: String,
    pub purpose: &'static str,
}

/// Records worth publishing for `domain`. `tls_rpt_mailbox` is where aggregate
/// TLS reports should go (usually postmaster@domain).
pub fn dns_records(
    domain: &str,
    endpoints: &ServiceEndpoints,
    mode: MtaStsMode,
    max_age_secs: u64,
    tls_rpt_mailbox: &str,
) -> Vec<DnsRecord> {
    let host = &endpoints.hostname;
    let mut records = vec![
        DnsRecord {
            name: domain.to_string(),
            kind: "MX",
            value: format!("10 {host}."),
            purpose: "Deliver mail for the domain to this server",
        },
        DnsRecord {
            name: domain.to_string(),
            kind: "TXT",
            value: "v=spf1 mx -all".to_string(),
            purpose: "SPF: only the domain's MX hosts send its mail (RFC 7208)",
        },
        DnsRecord {
            name: format!("_dmarc.{domain}"),
            kind: "TXT",
            value: format!("v=DMARC1; p=none; rua=mailto:{tls_rpt_mailbox}"),
            purpose: "DMARC: start with p=none and aggregate reports, then tighten to quarantine or reject",
        },
        DnsRecord {
            name: format!("autoconfig.{domain}"),
            kind: "CNAME",
            value: format!("{host}."),
            purpose: "Thunderbird and other clients find their settings",
        },
        DnsRecord {
            name: format!("autodiscover.{domain}"),
            kind: "CNAME",
            value: format!("{host}."),
            purpose: "Outlook finds its settings",
        },
        DnsRecord {
            name: format!("_smtp._tls.{domain}"),
            kind: "TXT",
            value: format!("v=TLSRPTv1; rua=mailto:{tls_rpt_mailbox}"),
            purpose: "Receive SMTP TLS reports from other servers (RFC 8460)",
        },
    ];
    if let Some(imap) = &endpoints.imap {
        let service = match imap.security {
            Security::Tls => "_imaps",
            Security::StartTls => "_imap",
        };
        records.push(DnsRecord {
            name: format!("{service}._tcp.{domain}"),
            kind: "SRV",
            value: format!("0 1 {} {host}.", imap.port),
            purpose: "IMAP service discovery (RFC 6186)",
        });
    }
    if let Some(smtp) = &endpoints.smtp {
        let service = match smtp.security {
            Security::Tls => "_submissions",
            Security::StartTls => "_submission",
        };
        records.push(DnsRecord {
            name: format!("{service}._tcp.{domain}"),
            kind: "SRV",
            value: format!("0 1 {} {host}.", smtp.port),
            purpose: "Message submission discovery (RFC 6186/8314)",
        });
    }
    if let Some(policy) = mta_sts_policy(mode, host, max_age_secs) {
        records.push(DnsRecord {
            name: format!("_mta-sts.{domain}"),
            kind: "TXT",
            value: format!("v=STSv1; id={}", mta_sts_id(&policy)),
            purpose: "Announce the MTA-STS policy (RFC 8461)",
        });
        records.push(DnsRecord {
            name: format!("mta-sts.{domain}"),
            kind: "CNAME",
            value: format!("{host}."),
            purpose: "Host that serves /.well-known/mta-sts.txt over HTTPS",
        });
    }
    records
}

/// `mta-sts.example.com` -> `example.com`; `autoconfig.`/`autodiscover.` likewise.
/// The host may carry a port. Returns a lowercase domain.
pub fn domain_from_host(host: &str, prefix: &str) -> Option<String> {
    let host = host.rsplit_once(':').map_or(host, |(name, port)| {
        if port.bytes().all(|b| b.is_ascii_digit()) {
            name
        } else {
            host
        }
    });
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let domain = host.strip_prefix(prefix)?.strip_prefix('.')?;
    (domain.contains('.')
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
    .then(|| domain.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoints() -> ServiceEndpoints {
        ServiceEndpoints {
            hostname: "mail.example.com".to_string(),
            imap: Some(Endpoint {
                port: 993,
                security: Security::Tls,
            }),
            smtp: Some(Endpoint {
                port: 587,
                security: Security::StartTls,
            }),
        }
    }

    #[test]
    fn thunderbird_config_lists_both_servers() {
        let xml = thunderbird_config("example.com", &endpoints());
        assert!(xml.contains("<incomingServer type=\"imap\">"));
        assert!(xml.contains("<port>993</port>"));
        assert!(xml.contains("<socketType>SSL</socketType>"));
        assert!(xml.contains("<outgoingServer type=\"smtp\">"));
        assert!(xml.contains("<port>587</port>"));
        assert!(xml.contains("<socketType>STARTTLS</socketType>"));
        assert!(xml.contains("<username>%EMAILADDRESS%</username>"));
    }

    #[test]
    fn xml_output_is_escaped() {
        let xml = thunderbird_config("a&b<c>.test", &endpoints());
        assert!(xml.contains("a&amp;b&lt;c&gt;.test"));
        let pox = outlook_autodiscover("x\"y@e.test", &endpoints());
        assert!(pox.contains("x&quot;y@e.test"));
    }

    #[test]
    fn outlook_response_has_imap_and_smtp() {
        let pox = outlook_autodiscover("me@example.com", &endpoints());
        assert!(pox.contains("<Type>IMAP</Type>"));
        assert!(pox.contains("<Type>SMTP</Type>"));
        assert!(pox.contains("<LoginName>me@example.com</LoginName>"));
        assert!(pox.contains("<Encryption>TLS</Encryption>"));
    }

    #[test]
    fn autodiscover_request_email_is_extracted_and_validated() {
        let body = "<Autodiscover><Request><EMailAddress> me@example.com </EMailAddress></Request></Autodiscover>";
        assert_eq!(
            autodiscover_request_email(body).as_deref(),
            Some("me@example.com")
        );
        assert_eq!(autodiscover_request_email("<x/>"), None);
        assert_eq!(
            autodiscover_request_email("<EMailAddress><b>x</b></EMailAddress>"),
            None
        );
    }

    #[test]
    fn mta_sts_policy_is_crlf_and_off_when_none() {
        assert_eq!(
            mta_sts_policy(MtaStsMode::None, "mail.example.com", 1),
            None
        );
        let policy = mta_sts_policy(MtaStsMode::Enforce, "mail.example.com", 604800).unwrap();
        assert_eq!(
            policy,
            "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmax_age: 604800\r\n"
        );
    }

    #[test]
    fn policy_id_changes_with_policy() {
        let a = mta_sts_policy(MtaStsMode::Testing, "m.example.com", 100).unwrap();
        let b = mta_sts_policy(MtaStsMode::Enforce, "m.example.com", 100).unwrap();
        assert_eq!(mta_sts_id(&a).len(), 16);
        assert_ne!(mta_sts_id(&a), mta_sts_id(&b));
        assert_eq!(mta_sts_id(&a), mta_sts_id(&a));
    }

    #[test]
    fn dns_records_cover_discovery_and_optional_mta_sts() {
        let without = dns_records(
            "example.com",
            &endpoints(),
            MtaStsMode::None,
            1,
            "p@example.com",
        );
        assert!(without.iter().all(|r| !r.name.starts_with("_mta-sts")));
        let names: Vec<_> = without.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"_imaps._tcp.example.com"));
        assert!(names.contains(&"_submission._tcp.example.com"));
        assert!(names.contains(&"_smtp._tls.example.com"));
        let with = dns_records(
            "example.com",
            &endpoints(),
            MtaStsMode::Enforce,
            604800,
            "p@example.com",
        );
        let txt = with
            .iter()
            .find(|r| r.name == "_mta-sts.example.com")
            .unwrap();
        assert!(txt.value.starts_with("v=STSv1; id="));
        assert!(with.iter().any(|r| r.name == "mta-sts.example.com"));
    }

    #[test]
    fn domain_from_host_strips_prefix_and_port() {
        assert_eq!(
            domain_from_host("mta-sts.Example.com:443", "mta-sts").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            domain_from_host("autoconfig.example.com", "autoconfig").as_deref(),
            Some("example.com")
        );
        assert_eq!(domain_from_host("example.com", "mta-sts"), None);
        assert_eq!(domain_from_host("mta-sts.localhost", "mta-sts"), None);
        assert_eq!(domain_from_host("mta-sts.exa mple.com", "mta-sts"), None);
    }

    #[test]
    fn endpoints_prefer_implicit_tls_and_parse_ports() {
        let global: Global = toml::from_str(
            "mail_root = \"m\"\nhostname = \"mail.example.com\"\n[listeners]\nimaps = [\"[::]:993\"]\nsubmission = [\"0.0.0.0:587\"]\n",
        )
        .unwrap();
        let e = ServiceEndpoints::from_global(&global);
        assert_eq!(
            e.imap,
            Some(Endpoint {
                port: 993,
                security: Security::Tls
            })
        );
        assert_eq!(
            e.smtp,
            Some(Endpoint {
                port: 587,
                security: Security::StartTls
            })
        );
        assert_eq!(e.hostname, "mail.example.com");
    }
}
