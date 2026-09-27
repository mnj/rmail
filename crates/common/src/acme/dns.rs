//! DNS-01 challenge records: provider APIs, zone discovery and propagation
//! checks against the zone's authoritative name servers.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};

use super::rfc2136;
use crate::config::{AcmeDnsConfig, DnsProviderKind};

const API_TIMEOUT: Duration = Duration::from_secs(30);
const RECORD_TTL: u32 = 120;

/// A configured DNS provider able to publish and remove TXT records.
pub(super) enum Provider {
    Cloudflare {
        token: String,
        base: String,
    },
    DigitalOcean {
        token: String,
        base: String,
    },
    Desec {
        token: String,
        base: String,
    },
    Gandi {
        token: String,
        base: String,
    },
    Route53 {
        key_id: String,
        secret: String,
        base: String,
    },
    Rfc2136 {
        server: String,
        key: rfc2136::TsigKey,
    },
}

/// Provider-side handles needed to remove what [`Provider::present`] created.
#[derive(Debug, Default)]
pub(super) struct Published {
    record_ids: Vec<String>,
}

fn required<'a>(value: &'a Option<String>, what: &str) -> Result<&'a str> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("{what} is required for this DNS provider"))
}

fn required_secret<'a>(
    value: &'a Option<crate::config::SecretString>,
    what: &str,
) -> Result<&'a str> {
    value
        .as_ref()
        .map(|secret| secret.expose().trim())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("{what} is required for this DNS provider"))
}

/// Check that the provider's required settings are present and well formed,
/// without copying or decoding any secret value (used when settings are
/// saved; [`Provider::from_config`] builds the real client at issuance).
pub(super) fn check_config(config: &AcmeDnsConfig) -> Result<()> {
    let present = |value: &Option<String>| value.as_deref().is_some_and(|v| !v.trim().is_empty());
    let secret_present = |value: &Option<crate::config::SecretString>| {
        value
            .as_ref()
            .is_some_and(|v| !v.expose().trim().is_empty())
    };
    let missing = |what: &str| anyhow!("{what} is required for this DNS provider");
    let kind = config
        .provider
        .ok_or_else(|| anyhow!("acme.dns.provider is required for the dns-01 challenge"))?;
    match kind {
        DnsProviderKind::Cloudflare
        | DnsProviderKind::DigitalOcean
        | DnsProviderKind::Desec
        | DnsProviderKind::Gandi => {
            if !secret_present(&config.api_token) {
                return Err(missing("acme.dns.api_token"));
            }
        }
        DnsProviderKind::Route53 => {
            if !present(&config.aws_access_key_id) {
                return Err(missing("acme.dns.aws_access_key_id"));
            }
            if !secret_present(&config.aws_secret_access_key) {
                return Err(missing("acme.dns.aws_secret_access_key"));
            }
        }
        DnsProviderKind::Rfc2136 => {
            if !present(&config.rfc2136_server) {
                return Err(missing("acme.dns.rfc2136_server"));
            }
            if !present(&config.tsig_key_name) {
                return Err(missing("acme.dns.tsig_key_name"));
            }
            if !secret_present(&config.tsig_secret) {
                return Err(missing("acme.dns.tsig_secret"));
            }
            let decodes = config.tsig_secret.as_ref().is_some_and(|secret| {
                base64::engine::general_purpose::STANDARD
                    .decode(secret.expose().trim())
                    .is_ok()
            });
            if !decodes {
                bail!("acme.dns.tsig_secret must be base64 (as in a BIND key file)");
            }
        }
    }
    Ok(())
}

pub(super) fn decode_tsig_secret(secret: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(secret.trim())
        .map_err(|_| anyhow!("acme.dns.tsig_secret must be base64 (as in a BIND key file)"))
}

impl Provider {
    pub fn from_config(config: &AcmeDnsConfig) -> Result<Self> {
        let kind = config
            .provider
            .ok_or_else(|| anyhow!("acme.dns.provider is required for the dns-01 challenge"))?;
        let token = || required_secret(&config.api_token, "acme.dns.api_token").map(str::to_string);
        Ok(match kind {
            DnsProviderKind::Cloudflare => Provider::Cloudflare {
                token: token()?,
                base: "https://api.cloudflare.com/client/v4".into(),
            },
            DnsProviderKind::DigitalOcean => Provider::DigitalOcean {
                token: token()?,
                base: "https://api.digitalocean.com/v2".into(),
            },
            DnsProviderKind::Desec => Provider::Desec {
                token: token()?,
                base: "https://desec.io/api/v1".into(),
            },
            DnsProviderKind::Gandi => Provider::Gandi {
                token: token()?,
                base: "https://api.gandi.net/v5/livedns".into(),
            },
            DnsProviderKind::Route53 => Provider::Route53 {
                key_id: required(&config.aws_access_key_id, "acme.dns.aws_access_key_id")?
                    .to_string(),
                secret: required_secret(
                    &config.aws_secret_access_key,
                    "acme.dns.aws_secret_access_key",
                )?
                .to_string(),
                base: "https://route53.amazonaws.com".into(),
            },
            DnsProviderKind::Rfc2136 => Provider::Rfc2136 {
                server: required(&config.rfc2136_server, "acme.dns.rfc2136_server")?.to_string(),
                key: rfc2136::TsigKey {
                    name: required(&config.tsig_key_name, "acme.dns.tsig_key_name")?.to_string(),
                    secret: decode_tsig_secret(required_secret(
                        &config.tsig_secret,
                        "acme.dns.tsig_secret",
                    )?)?,
                    algorithm: config.tsig_algorithm,
                },
            },
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Provider::Cloudflare { .. } => "Cloudflare",
            Provider::DigitalOcean { .. } => "DigitalOcean",
            Provider::Desec { .. } => "deSEC",
            Provider::Gandi { .. } => "Gandi",
            Provider::Route53 { .. } => "Route 53",
            Provider::Rfc2136 { .. } => "RFC 2136",
        }
    }

    /// Publish `values` as TXT records at `fqdn` inside `zone`.
    pub async fn present(&self, zone: &str, fqdn: &str, values: &[String]) -> Result<Published> {
        let client = http_client()?;
        let mut published = Published::default();
        match self {
            Provider::Cloudflare { token, base } => {
                let zone_id = cloudflare_zone_id(&client, base, token, zone).await?;
                for value in values {
                    let body = json!({
                        "type": "TXT",
                        "name": fqdn,
                        // Cloudflare expects TXT content in zone-file quoting.
                        "content": format!("\"{value}\""),
                        "ttl": RECORD_TTL,
                        "comment": "rMail ACME challenge",
                    });
                    let response = api_json(
                        client
                            .post(format!("{base}/zones/{zone_id}/dns_records"))
                            .bearer_auth(token)
                            .json(&body),
                    )
                    .await?;
                    let id = response
                        .pointer("/result/id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| anyhow!("Cloudflare returned no record id"))?;
                    published.record_ids.push(format!("{zone_id}/{id}"));
                }
            }
            Provider::DigitalOcean { token, base } => {
                let name = relative_name(fqdn, zone);
                for value in values {
                    let response = api_json(
                        client
                            .post(format!("{base}/domains/{zone}/records"))
                            .bearer_auth(token)
                            .json(&json!({"type": "TXT", "name": name, "data": value, "ttl": 30})),
                    )
                    .await?;
                    let id = response
                        .pointer("/domain_record/id")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| anyhow!("DigitalOcean returned no record id"))?;
                    published.record_ids.push(id.to_string());
                }
            }
            Provider::Desec { token, base } => {
                let records = values
                    .iter()
                    .map(|v| format!("\"{v}\""))
                    .collect::<Vec<_>>();
                // The bulk endpoint creates or replaces the RRset.
                api_json(
                    client
                        .put(format!("{base}/domains/{zone}/rrsets/"))
                        .header("Authorization", format!("Token {token}"))
                        .json(&json!([{
                            "subname": relative_name(fqdn, zone),
                            "type": "TXT",
                            "ttl": 3600,
                            "records": records,
                        }])),
                )
                .await?;
            }
            Provider::Gandi { token, base } => {
                let name = relative_name(fqdn, zone);
                let name = if name.is_empty() {
                    "@".to_string()
                } else {
                    name
                };
                api_json(
                    client
                        .put(format!("{base}/domains/{zone}/records/{name}/TXT"))
                        .bearer_auth(token)
                        .json(&json!({"rrset_values": values, "rrset_ttl": 300})),
                )
                .await?;
            }
            Provider::Route53 {
                key_id,
                secret,
                base,
            } => {
                let zone_id = route53_zone_id(&client, base, key_id, secret, zone).await?;
                route53_change(
                    &client, base, key_id, secret, &zone_id, "UPSERT", fqdn, values,
                )
                .await?;
                published.record_ids.push(zone_id);
            }
            Provider::Rfc2136 { server, key } => {
                rfc2136::send_update(server, zone, fqdn, values, rfc2136::Action::Add, key).await?;
            }
        }
        Ok(published)
    }

    /// Remove what [`Provider::present`] published.
    pub async fn cleanup(
        &self,
        zone: &str,
        fqdn: &str,
        values: &[String],
        published: &Published,
    ) -> Result<()> {
        let client = http_client()?;
        match self {
            Provider::Cloudflare { token, base } => {
                for id in &published.record_ids {
                    let (zone_id, record) = id.split_once('/').unwrap_or(("", id));
                    api_json(
                        client
                            .delete(format!("{base}/zones/{zone_id}/dns_records/{record}"))
                            .bearer_auth(token),
                    )
                    .await?;
                }
            }
            Provider::DigitalOcean { token, base } => {
                for id in &published.record_ids {
                    api_json(
                        client
                            .delete(format!("{base}/domains/{zone}/records/{id}"))
                            .bearer_auth(token),
                    )
                    .await?;
                }
            }
            Provider::Desec { token, base } => {
                let name = relative_name(fqdn, zone);
                api_json(
                    client
                        .delete(format!("{base}/domains/{zone}/rrsets/{name}/TXT/"))
                        .header("Authorization", format!("Token {token}")),
                )
                .await?;
            }
            Provider::Gandi { token, base } => {
                let name = relative_name(fqdn, zone);
                let name = if name.is_empty() {
                    "@".to_string()
                } else {
                    name
                };
                api_json(
                    client
                        .delete(format!("{base}/domains/{zone}/records/{name}/TXT"))
                        .bearer_auth(token),
                )
                .await?;
            }
            Provider::Route53 {
                key_id,
                secret,
                base,
            } => {
                if let Some(zone_id) = published.record_ids.first() {
                    route53_change(
                        &client, base, key_id, secret, zone_id, "DELETE", fqdn, values,
                    )
                    .await?;
                }
            }
            Provider::Rfc2136 { server, key } => {
                rfc2136::send_update(server, zone, fqdn, values, rfc2136::Action::Delete, key)
                    .await?;
            }
        }
        Ok(())
    }
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(API_TIMEOUT)
        .user_agent(concat!("rMail-ACME/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building HTTP client")
}

/// Send a request and return its JSON body (or `null`), turning HTTP and
/// API-level failures into readable errors.
async fn api_json(request: reqwest::RequestBuilder) -> Result<Value> {
    let response = request
        .send()
        .await
        .map_err(|error| anyhow!("DNS provider request failed: {}", error.without_url()))?;
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if !status.is_success() || body.get("success") == Some(&Value::Bool(false)) {
        let detail = body
            .pointer("/errors/0/message")
            .or_else(|| body.get("message"))
            .or_else(|| body.get("detail"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| text.chars().take(300).collect());
        bail!("DNS provider API returned {status}: {detail}");
    }
    Ok(body)
}

async fn cloudflare_zone_id(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    zone: &str,
) -> Result<String> {
    let response = api_json(
        client
            .get(format!("{base}/zones"))
            .query(&[("name", zone)])
            .bearer_auth(token),
    )
    .await?;
    response
        .pointer("/result/0/id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            anyhow!(
                "Cloudflare has no zone {zone} for this token (it needs Zone:Read and DNS:Edit)"
            )
        })
}

/// `fqdn` relative to `zone`: `_acme-challenge.mail` in `example.com`.
pub(super) fn relative_name(fqdn: &str, zone: &str) -> String {
    let fqdn = fqdn.trim_end_matches('.');
    let zone = zone.trim_end_matches('.');
    if fqdn.eq_ignore_ascii_case(zone) {
        return String::new();
    }
    let suffix = format!(".{zone}");
    if fqdn.len() > suffix.len() && fqdn[fqdn.len() - suffix.len()..].eq_ignore_ascii_case(&suffix)
    {
        fqdn[..fqdn.len() - suffix.len()].to_string()
    } else {
        fqdn.to_string()
    }
}

// ---------------------------------------------------------------------------
// Route 53 (AWS Signature Version 4)

const AWS_REGION: &str = "us-east-1";
const AWS_SERVICE: &str = "route53";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac_sha256(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn aws_encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

struct SignedRequest {
    authorization: String,
    amz_date: String,
}

/// AWS Signature Version 4 for a request whose signed headers are `headers`
/// (lowercase names) plus `host` and `x-amz-date`.
fn sigv4(
    method: &str,
    host: &str,
    path: &str,
    query: &[(&str, &str)],
    headers: &[(&str, &str)],
    payload: &[u8],
    key_id: &str,
    secret: &str,
    region: &str,
    service: &str,
    amz_date: &str,
) -> SignedRequest {
    let date = &amz_date[..8];
    let mut query = query
        .iter()
        .map(|(k, v)| (aws_encode(k), aws_encode(v)))
        .collect::<Vec<_>>();
    query.sort();
    let canonical_query = query
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let mut all_headers: BTreeMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    all_headers.insert("host".into(), host.into());
    all_headers.insert("x-amz-date".into(), amz_date.into());
    let canonical_headers = all_headers
        .iter()
        .map(|(k, v)| format!("{k}:{v}\n"))
        .collect::<String>();
    let signed_headers = all_headers.keys().cloned().collect::<Vec<_>>().join(";");
    let canonical_request = format!(
        "{method}\n{path}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{}",
        hex(&Sha256::digest(payload))
    );
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&Sha256::digest(canonical_request.as_bytes()))
    );
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date);
    let k_region = hmac_sha256(&k_date, region);
    let k_service = hmac_sha256(&k_region, service);
    let k_signing = hmac_sha256(&k_service, "aws4_request");
    let signature = hex(&hmac_sha256(&k_signing, &string_to_sign));
    SignedRequest {
        authorization: format!(
            "AWS4-HMAC-SHA256 Credential={key_id}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
        ),
        amz_date: amz_date.to_string(),
    }
}

fn amz_now() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

async fn route53_request(
    client: &reqwest::Client,
    base: &str,
    key_id: &str,
    secret: &str,
    method: reqwest::Method,
    path: &str,
    query: &[(&str, &str)],
    body: Option<String>,
) -> Result<String> {
    let url = reqwest::Url::parse(base).context("Route 53 endpoint")?;
    let host = url
        .host_str()
        .unwrap_or("route53.amazonaws.com")
        .to_string();
    let payload = body.clone().unwrap_or_default();
    let signed = sigv4(
        method.as_str(),
        &host,
        path,
        query,
        &[],
        payload.as_bytes(),
        key_id,
        secret,
        AWS_REGION,
        AWS_SERVICE,
        &amz_now(),
    );
    let mut request = client
        .request(method, format!("{base}{path}"))
        .query(query)
        .header("x-amz-date", &signed.amz_date)
        .header("Authorization", &signed.authorization);
    if let Some(body) = body {
        request = request.header("Content-Type", "application/xml").body(body);
    }
    let response = request
        .send()
        .await
        .map_err(|error| anyhow!("Route 53 request failed: {}", error.without_url()))?;
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        let message =
            xml_value(&text, "Message").unwrap_or_else(|| text.chars().take(300).collect());
        bail!("Route 53 returned {status}: {message}");
    }
    Ok(text)
}

fn xml_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{tag}>"))? + start;
    Some(xml[start..end].to_string())
}

async fn route53_zone_id(
    client: &reqwest::Client,
    base: &str,
    key_id: &str,
    secret: &str,
    zone: &str,
) -> Result<String> {
    let text = route53_request(
        client,
        base,
        key_id,
        secret,
        reqwest::Method::GET,
        "/2013-04-01/hostedzonesbyname",
        &[("dnsname", zone), ("maxitems", "1")],
        None,
    )
    .await?;
    let name = xml_value(&text, "Name").unwrap_or_default();
    let id = xml_value(&text, "Id").unwrap_or_default();
    if !name.trim_end_matches('.').eq_ignore_ascii_case(zone) || id.is_empty() {
        bail!("Route 53 has no hosted zone {zone} for these credentials");
    }
    Ok(id.trim_start_matches("/hostedzone/").to_string())
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn route53_change(
    client: &reqwest::Client,
    base: &str,
    key_id: &str,
    secret: &str,
    zone_id: &str,
    action: &str,
    fqdn: &str,
    values: &[String],
) -> Result<()> {
    let records = values
        .iter()
        .map(|value| {
            format!(
                "<ResourceRecord><Value>{}</Value></ResourceRecord>",
                xml_escape(&format!("\"{value}\""))
            )
        })
        .collect::<String>();
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ChangeBatch><Comment>rMail ACME challenge</Comment><Changes><Change><Action>{action}</Action><ResourceRecordSet><Name>{}.</Name><Type>TXT</Type><TTL>{RECORD_TTL}</TTL><ResourceRecords>{records}</ResourceRecords></ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>"#,
        xml_escape(fqdn.trim_end_matches('.'))
    );
    route53_request(
        client,
        base,
        key_id,
        secret,
        reqwest::Method::POST,
        &format!("/2013-04-01/hostedzone/{zone_id}/rrset"),
        &[],
        Some(body),
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Zone discovery and propagation

fn system_resolver() -> Result<TokioAsyncResolver> {
    let (config, mut options) = trust_dns_resolver::system_conf::read_system_conf()
        .unwrap_or_else(|_| (ResolverConfig::default(), ResolverOpts::default()));
    options.cache_size = 0;
    TokioAsyncResolver::tokio(config, options).context("creating DNS resolver")
}

fn same_name(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}

/// The closest enclosing zone of `name`: the nearest ancestor (or the name
/// itself) that has an SOA record of its own.
pub(super) async fn find_zone(name: &str) -> Result<String> {
    let resolver = system_resolver()?;
    let name = name.trim_end_matches('.');
    let labels = name.split('.').collect::<Vec<_>>();
    for start in 0..labels.len().saturating_sub(1) {
        let candidate = labels[start..].join(".");
        if let Ok(lookup) = resolver.soa_lookup(format!("{candidate}.")).await
            && lookup
                .as_lookup()
                .records()
                .iter()
                .any(|record| same_name(&record.name().to_string(), &candidate))
        {
            return Ok(candidate);
        }
    }
    bail!("could not find the DNS zone for {name}; set acme.dns.zone")
}

async fn authoritative_resolvers(zone: &str) -> Result<Vec<(String, TokioAsyncResolver)>> {
    let resolver = system_resolver()?;
    let servers = resolver
        .ns_lookup(format!("{zone}."))
        .await
        .map_err(|_| anyhow!("no NS records found for {zone}"))?;
    let mut out = Vec::new();
    for server in servers.iter() {
        let host = server.to_string();
        let Ok(ips) = resolver.lookup_ip(host.as_str()).await else {
            continue;
        };
        let ips = ips.iter().collect::<Vec<IpAddr>>();
        if ips.is_empty() {
            continue;
        }
        let group = NameServerConfigGroup::from_ips_clear(&ips, 53, true);
        let mut options = ResolverOpts::default();
        options.cache_size = 0;
        options.recursion_desired = false;
        options.timeout = Duration::from_secs(5);
        options.attempts = 1;
        let authoritative =
            TokioAsyncResolver::tokio(ResolverConfig::from_parts(None, vec![], group), options)
                .context("creating authoritative resolver")?;
        out.push((host.trim_end_matches('.').to_string(), authoritative));
    }
    if out.is_empty() {
        bail!("no reachable name servers found for {zone}");
    }
    Ok(out)
}

async fn txt_values(resolver: &TokioAsyncResolver, fqdn: &str) -> Vec<String> {
    match resolver.txt_lookup(format!("{fqdn}.")).await {
        Ok(lookup) => lookup
            .iter()
            .map(|txt| {
                txt.txt_data()
                    .iter()
                    .map(|part| String::from_utf8_lossy(part).into_owned())
                    .collect::<String>()
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Wait until every authoritative server of `zone` serves all `values` at
/// `fqdn`. Returns a description of what is still missing on timeout.
pub(super) async fn wait_for_propagation(
    zone: &str,
    records: &[(String, Vec<String>)],
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let mut note = None;
    let servers = match authoritative_resolvers(zone).await {
        Ok(servers) => servers,
        Err(error) => {
            // Fall back to the system resolver (for example split-horizon DNS).
            note = Some(format!(
                "could not query the authoritative name servers directly: {error:#}"
            ));
            match system_resolver() {
                Ok(resolver) => vec![("the system resolver".to_string(), resolver)],
                Err(_) => return Err(format!("{error:#}")),
            }
        }
    };
    loop {
        let mut missing = Vec::new();
        for (fqdn, values) in records {
            for (server, resolver) in &servers {
                let seen = txt_values(resolver, fqdn).await;
                if !values.iter().all(|value| seen.contains(value)) {
                    missing.push(if seen.is_empty() {
                        format!("{server} has no TXT record at {fqdn}")
                    } else {
                        format!("{server} serves {seen:?} at {fqdn}")
                    });
                }
            }
        }
        if missing.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let missing = missing.join("; ");
            return Err(match &note {
                Some(note) => format!("{note}; {missing}"),
                None => missing,
            });
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_made_relative_to_their_zone() {
        assert_eq!(
            relative_name("_acme-challenge.mail.example.com", "example.com"),
            "_acme-challenge.mail"
        );
        assert_eq!(
            relative_name("_acme-challenge.Example.com.", "example.com"),
            "_acme-challenge"
        );
        assert_eq!(relative_name("example.com", "example.com"), "");
    }

    /// Worked example from the AWS Signature Version 4 documentation
    /// (IAM ListUsers, 2015-08-30).
    #[test]
    fn sigv4_matches_the_aws_reference_example() {
        let signed = sigv4(
            "GET",
            "iam.amazonaws.com",
            "/",
            &[("Action", "ListUsers"), ("Version", "2010-05-08")],
            &[(
                "content-type",
                "application/x-www-form-urlencoded; charset=utf-8",
            )],
            b"",
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "iam",
            "20150830T123600Z",
        );
        assert_eq!(
            signed.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, \
             Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    #[test]
    fn xml_values_are_extracted() {
        let xml = "<HostedZone><Id>/hostedzone/Z1</Id><Name>example.com.</Name></HostedZone>";
        assert_eq!(xml_value(xml, "Id").as_deref(), Some("/hostedzone/Z1"));
        assert_eq!(xml_value(xml, "Name").as_deref(), Some("example.com."));
        assert_eq!(xml_value(xml, "Missing"), None);
    }

    #[tokio::test]
    async fn cloudflare_records_are_created_and_removed_through_the_api() {
        use axum::routing::{delete, get, post};
        use std::sync::{Arc, Mutex};

        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let log = seen.clone();
        let app = axum::Router::new()
            .route(
                "/zones",
                get(|query: axum::extract::RawQuery| async move {
                    assert_eq!(query.0.as_deref(), Some("name=example.com"));
                    axum::Json(json!({"success": true, "result": [{"id": "zone1"}]}))
                }),
            )
            .route(
                "/zones/zone1/dns_records",
                post(move |body: axum::Json<Value>| {
                    let log = log.clone();
                    async move {
                        log.lock().unwrap().push(body.0["content"].to_string());
                        axum::Json(json!({"success": true, "result": {"id": "rec1"}}))
                    }
                }),
            )
            .route(
                "/zones/zone1/dns_records/rec1",
                delete(|| async { axum::Json(json!({"success": true, "result": {"id": "rec1"}})) }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let provider = Provider::Cloudflare {
            token: "secret".into(),
            base: format!("http://{address}"),
        };
        let values = vec!["abc".to_string()];
        let published = provider
            .present("example.com", "_acme-challenge.example.com", &values)
            .await
            .unwrap();
        assert_eq!(published.record_ids, ["zone1/rec1"]);
        assert_eq!(seen.lock().unwrap().as_slice(), ["\"\\\"abc\\\"\""]);
        provider
            .cleanup(
                "example.com",
                "_acme-challenge.example.com",
                &values,
                &published,
            )
            .await
            .unwrap();
    }
}
