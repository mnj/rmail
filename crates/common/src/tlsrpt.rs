//! SMTP TLS reporting (RFC 8460): outbound TLS outcomes are counted per
//! (UTC day, policy domain, policy type, MX host, result) and sent once a day
//! as a gzipped JSON report to the domain's `_smtp._tls` rua address.
//!
//! Counting happens in memory and is flushed to SQLite on an interval, so
//! deliveries never write to disk individually.

use anyhow::Result;
use base64::Engine;
use chrono::{NaiveDate, TimeZone, Utc};
use flate2::{Compression, write::GzEncoder};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::sync::{LazyLock, Mutex};

/// One aggregated counter, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterRow {
    pub day: String,
    pub domain: String,
    pub policy_type: String,
    pub mx_host: String,
    /// RFC 8460 `result-type`, or empty for successful sessions.
    pub result: String,
    pub count: u64,
    /// A representative diagnostic for failures.
    pub info: String,
}

type Key = (String, String, String, String, String);

static PENDING: LazyLock<Mutex<HashMap<Key, (u64, String)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn today() -> String {
    Utc::now().format("%Y-%m-%d").to_string()
}

fn add(day: String, domain: &str, policy_type: &str, mx_host: &str, result: &str, info: &str) {
    let key = (
        day,
        domain.to_ascii_lowercase(),
        policy_type.to_string(),
        mx_host.trim_end_matches('.').to_ascii_lowercase(),
        result.to_string(),
    );
    let mut pending = PENDING.lock().unwrap();
    let entry = pending.entry(key).or_insert((0, String::new()));
    entry.0 += 1;
    if !info.is_empty() {
        entry.1 = info.chars().take(500).collect();
    }
}

/// A session that met the domain's policy. `policy_type` is "sts" or "tlsa".
pub fn record_success(domain: &str, policy_type: &str, mx_host: &str) {
    add(today(), domain, policy_type, mx_host, "", "");
}

/// A session that failed the domain's policy.
pub fn record_failure(domain: &str, policy_type: &str, mx_host: &str, diagnostic: &str) {
    add(
        today(),
        domain,
        policy_type,
        mx_host,
        classify_failure(diagnostic),
        diagnostic,
    );
}

/// Map a delivery diagnostic to an RFC 8460 section 4.3 result type.
pub fn classify_failure(diagnostic: &str) -> &'static str {
    let d = diagnostic.to_ascii_lowercase();
    if d.contains("does not offer starttls") {
        "starttls-not-supported"
    } else if d.contains("expired") {
        "certificate-expired"
    } else if d.contains("hostname mismatch")
        || d.contains("host name mismatch")
        || d.contains("not valid for")
    {
        "certificate-host-mismatch"
    } else if d.contains("certificate") {
        "certificate-not-trusted"
    } else if d.contains("tlsa") && d.contains("dnssec") {
        "dnssec-invalid"
    } else if d.contains("tlsa") {
        "tlsa-invalid"
    } else {
        "validation-failure"
    }
}

/// Move pending counts into SQLite. Returns the number of counters written.
pub fn flush(db_path: &Path) -> Result<usize> {
    let drained: Vec<CounterRow> = {
        let mut pending = PENDING.lock().unwrap();
        pending
            .drain()
            .map(
                |((day, domain, policy_type, mx_host, result), (count, info))| CounterRow {
                    day,
                    domain,
                    policy_type,
                    mx_host,
                    result,
                    count,
                    info,
                },
            )
            .collect()
    };
    if drained.is_empty() {
        return Ok(0);
    }
    if let Err(error) = crate::db::add_tlsrpt_counts(db_path, &drained) {
        // Put the counts back so the next flush retries them.
        for row in drained {
            let key = (
                row.day,
                row.domain,
                row.policy_type,
                row.mx_host,
                row.result,
            );
            let mut pending = PENDING.lock().unwrap();
            let entry = pending.entry(key).or_insert((0, String::new()));
            entry.0 += row.count;
            if entry.1.is_empty() {
                entry.1 = row.info;
            }
        }
        return Err(error);
    }
    Ok(drained.len())
}

fn day_bounds(day: &str) -> Option<(String, String)> {
    let date = NaiveDate::parse_from_str(day, "%Y-%m-%d").ok()?;
    let start = Utc.from_utc_datetime(&date.and_hms_opt(0, 0, 0)?);
    let end = Utc.from_utc_datetime(&date.and_hms_opt(23, 59, 59)?);
    Some((
        start.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        end.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    ))
}

/// RFC 8460 section 4.4 JSON for one policy domain and day. `rows` are that
/// domain's counters. Returns `(report_id, json)`.
pub fn build_report(
    organization: &str,
    contact: &str,
    day: &str,
    domain: &str,
    rows: &[CounterRow],
) -> Option<(String, Vec<u8>)> {
    let (start, end) = day_bounds(day)?;
    let report_id = format!("{day}T00:00:00Z_{domain}");

    // One policy entry per policy type; failures are listed per MX and result.
    let mut types: Vec<&str> = rows.iter().map(|r| r.policy_type.as_str()).collect();
    types.sort_unstable();
    types.dedup();
    let policies: Vec<serde_json::Value> = types
        .into_iter()
        .map(|policy_type| {
            let of_type: Vec<&CounterRow> =
                rows.iter().filter(|r| r.policy_type == policy_type).collect();
            let success: u64 = of_type.iter().filter(|r| r.result.is_empty()).map(|r| r.count).sum();
            let failure: u64 = of_type.iter().filter(|r| !r.result.is_empty()).map(|r| r.count).sum();
            let mut mx_hosts: Vec<&str> = of_type
                .iter()
                .filter(|r| !r.mx_host.is_empty())
                .map(|r| r.mx_host.as_str())
                .collect();
            mx_hosts.sort_unstable();
            mx_hosts.dedup();
            let details: Vec<serde_json::Value> = of_type
                .iter()
                .filter(|r| !r.result.is_empty())
                .map(|r| {
                    let mut detail = serde_json::json!({
                        "result-type": r.result,
                        "receiving-mx-hostname": if r.mx_host.is_empty() { domain } else { r.mx_host.as_str() },
                        "failed-session-count": r.count,
                    });
                    if !r.info.is_empty() {
                        detail["additional-information"] = serde_json::Value::String(r.info.clone());
                    }
                    detail
                })
                .collect();
            let mut policy = serde_json::json!({
                "policy": {
                    "policy-type": policy_type,
                    "policy-string": [],
                    "policy-domain": domain,
                    "mx-host": mx_hosts,
                },
                "summary": {
                    "total-successful-session-count": success,
                    "total-failure-session-count": failure,
                },
            });
            if !details.is_empty() {
                policy["failure-details"] = serde_json::Value::Array(details);
            }
            policy
        })
        .collect();

    let report = serde_json::json!({
        "organization-name": organization,
        "date-range": { "start-datetime": start, "end-datetime": end },
        "contact-info": contact,
        "report-id": report_id,
        "policies": policies,
    });
    Some((report_id, serde_json::to_vec(&report).ok()?))
}

pub fn gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

/// The report email (RFC 8460 section 5.3): a short text part plus the
/// gzipped JSON as `application/tlsrpt+gzip`.
pub fn build_message(
    from: &str,
    to: &str,
    submitter: &str,
    domain: &str,
    report_id: &str,
    day: &str,
    gz: &[u8],
) -> Vec<u8> {
    let compact_day = day.replace('-', "");
    let filename = format!(
        "{submitter}!{domain}!{compact_day}T000000Z!{compact_day}T235959Z!{report_id}.json.gz"
    );
    let boundary = format!("=_tlsrpt_{}", report_id.len() * 7919 + gz.len());
    let encoded = base64::engine::general_purpose::STANDARD.encode(gz);
    let wrapped = encoded
        .as_bytes()
        .chunks(76)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\r\n");
    format!(
        "From: <{from}>\r\nTo: <{to}>\r\nSubject: Report Domain: {domain} Submitter: {submitter} Report-ID: <{report_id}>\r\nTLS-Report-Domain: {domain}\r\nTLS-Report-Submitter: {submitter}\r\nAuto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\nContent-Type: multipart/report; report-type=\"tlsrpt\"; boundary=\"{boundary}\"\r\n\r\n--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThis is an aggregate TLS report from {submitter}.\r\n\r\n--{boundary}\r\nContent-Type: application/tlsrpt+gzip\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"{filename}\"\r\n\r\n{wrapped}\r\n--{boundary}--\r\n"
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(policy: &str, mx: &str, result: &str, count: u64) -> CounterRow {
        CounterRow {
            day: "2026-10-03".into(),
            domain: "example.com".into(),
            policy_type: policy.into(),
            mx_host: mx.into(),
            result: result.into(),
            count,
            info: if result.is_empty() {
                String::new()
            } else {
                "boom".into()
            },
        }
    }

    #[test]
    fn classifies_failures_into_rfc_result_types() {
        assert_eq!(
            classify_failure("remote host x does not offer STARTTLS required by MTA-STS"),
            "starttls-not-supported"
        );
        assert_eq!(
            classify_failure("TLS connect failed: certificate has expired"),
            "certificate-expired"
        );
        assert_eq!(
            classify_failure("TLS connect failed: certificate is not valid for mx.x"),
            "certificate-host-mismatch"
        );
        assert_eq!(
            classify_failure("TLS connect failed: self signed certificate"),
            "certificate-not-trusted"
        );
        assert_eq!(classify_failure("no TLSA record matched"), "tlsa-invalid");
        assert_eq!(
            classify_failure("no recipient MX matches policy"),
            "validation-failure"
        );
    }

    #[test]
    fn report_json_totals_and_details() {
        let rows = vec![
            row("sts", "mx1.example.com", "", 8),
            row("sts", "mx1.example.com", "certificate-expired", 2),
            row("sts", "mx2.example.com", "starttls-not-supported", 1),
            row("tlsa", "mx1.example.com", "", 5),
        ];
        let (id, json) = build_report(
            "rMail",
            "postmaster@mail.test",
            "2026-10-03",
            "example.com",
            &rows,
        )
        .unwrap();
        assert_eq!(id, "2026-10-03T00:00:00Z_example.com");
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["date-range"]["start-datetime"], "2026-10-03T00:00:00Z");
        assert_eq!(v["date-range"]["end-datetime"], "2026-10-03T23:59:59Z");
        let policies = v["policies"].as_array().unwrap();
        assert_eq!(policies.len(), 2);
        let sts = policies
            .iter()
            .find(|p| p["policy"]["policy-type"] == "sts")
            .unwrap();
        assert_eq!(sts["summary"]["total-successful-session-count"], 8);
        assert_eq!(sts["summary"]["total-failure-session-count"], 3);
        assert_eq!(
            sts["policy"]["mx-host"],
            serde_json::json!(["mx1.example.com", "mx2.example.com"])
        );
        assert_eq!(sts["failure-details"].as_array().unwrap().len(), 2);
        let tlsa = policies
            .iter()
            .find(|p| p["policy"]["policy-type"] == "tlsa")
            .unwrap();
        assert!(tlsa.get("failure-details").is_none());
        assert_eq!(tlsa["summary"]["total-successful-session-count"], 5);
    }

    #[test]
    fn gzip_roundtrips_and_message_carries_attachment() {
        use std::io::Read;
        let gz = gzip(b"{\"a\":1}").unwrap();
        let mut out = String::new();
        flate2::read::GzDecoder::new(&gz[..])
            .read_to_string(&mut out)
            .unwrap();
        assert_eq!(out, "{\"a\":1}");
        let msg = String::from_utf8(build_message(
            "tlsrpt@mail.test",
            "rua@example.com",
            "mail.test",
            "example.com",
            "rid",
            "2026-10-03",
            &gz,
        ))
        .unwrap();
        assert!(msg.contains("Content-Type: multipart/report; report-type=\"tlsrpt\""));
        assert!(msg.contains("Content-Type: application/tlsrpt+gzip"));
        assert!(
            msg.contains(
                "Subject: Report Domain: example.com Submitter: mail.test Report-ID: <rid>"
            )
        );
        assert!(msg.lines().all(|l| l.len() <= 998));
    }

    #[test]
    fn counters_flush_aggregate_and_clear_per_day() {
        let td = tempfile::tempdir().unwrap();
        let db = td.path().join("t.db");
        crate::db::init_db(&db).unwrap();
        let domain = "flush-test.example";
        record_success(domain, "sts", "mx.flush-test.example");
        record_success(domain, "sts", "mx.flush-test.example.");
        record_failure(
            domain,
            "sts",
            "mx.flush-test.example",
            "certificate has expired",
        );
        assert!(flush(&db).unwrap() >= 2);
        // Second flush has nothing for these counters.
        record_success(domain, "sts", "mx.flush-test.example");
        flush(&db).unwrap();

        let rows = crate::db::tlsrpt_rows(&db, &today(), domain).unwrap();
        let ok = rows.iter().find(|r| r.result.is_empty()).unwrap();
        assert_eq!(
            ok.count, 3,
            "upsert adds across flushes; trailing dot is normalized"
        );
        let bad = rows
            .iter()
            .find(|r| r.result == "certificate-expired")
            .unwrap();
        assert_eq!(bad.count, 1);
        assert_eq!(bad.info, "certificate has expired");

        // Only past days are due.
        assert!(
            crate::db::tlsrpt_due(&db, &today())
                .unwrap()
                .iter()
                .all(|(_, d)| d != domain)
        );
        let tomorrow = (Utc::now() + chrono::Duration::days(1))
            .format("%Y-%m-%d")
            .to_string();
        assert!(
            crate::db::tlsrpt_due(&db, &tomorrow)
                .unwrap()
                .contains(&(today(), domain.to_string()))
        );

        crate::db::tlsrpt_delete(&db, &today(), domain).unwrap();
        assert!(
            crate::db::tlsrpt_rows(&db, &today(), domain)
                .unwrap()
                .is_empty()
        );
    }
}
