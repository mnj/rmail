//! DMARC aggregate reports received from other mail systems (RFC 7489
//! section 7.2): what they say about how mail claiming to be from a hosted
//! domain fared at the reporter.
//!
//! A domain's `rua=` address receives one report a day from each large
//! receiver. They are the only way to know whether it is safe to move a
//! policy from `p=none` to `quarantine`, so the totals are kept and shown;
//! the reports themselves are delivered like any other mail.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use anyhow::Result;
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::mime;

/// Larger messages are not looked at; real reports are a few kilobytes.
pub const MAX_MESSAGE_BYTES: usize = 10 * 1024 * 1024;
/// A compressed report may not expand past this (zip bombs).
const MAX_XML_BYTES: u64 = 32 * 1024 * 1024;
/// Rows read from one report.
const MAX_RECORDS: usize = 50_000;
/// Failing sources kept per report, largest first.
const MAX_FAILING: usize = 20;
const MAX_TEXT_CHARS: usize = 200;
/// MIME parts looked at in one message.
const MAX_PARTS: usize = 16;
/// How long totals are kept.
pub const RETENTION_SECS: i64 = 180 * 24 * 3600;
/// The longest period one report may cover. Reports are daily; a few
/// senders batch a week.
const MAX_PERIOD_SECS: i64 = 8 * 24 * 3600;

/// A source address whose mail failed DMARC at the reporter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailingSource {
    pub source_ip: String,
    pub messages: u64,
    /// The reporter's DKIM and SPF alignment results (`pass`/`fail`).
    pub dkim: String,
    pub spf: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateReport {
    /// Who sent the report (`org_name`).
    pub reporter: String,
    pub report_id: String,
    /// The domain the report is about (`policy_published/domain`).
    pub domain: String,
    /// The period covered, as Unix timestamps.
    pub begin: i64,
    pub end: i64,
    /// The policy the reporter saw published.
    pub policy: Option<String>,
    pub messages: u64,
    /// Messages that passed DMARC: aligned DKIM or aligned SPF.
    pub passed: u64,
    pub failing: Vec<FailingSource>,
}

/// Header fields in order, names lower-cased and folded lines joined.
fn header_fields(head: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(head);
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in text.lines().take(512) {
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = fields.last_mut()
                && value.len() < 4096
            {
                value.push(' ');
                value.push_str(line.trim());
            }
        } else if let Some((name, value)) = line.split_once(':') {
            fields.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    fields
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(field, _)| field == name)
        .map(|(_, value)| value.as_str())
}

/// The decoded bodies of a message's leaf parts, one level of nesting deep,
/// which is as deep as reporters go (the report is the body or an
/// attachment).
fn leaf_bodies(head: &[u8], body: &[u8], depth: usize, out: &mut Vec<Vec<u8>>) {
    let headers = header_fields(head);
    let content_type = field(&headers, "content-type").unwrap_or("text/plain");
    let kind = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if kind.starts_with("multipart/") {
        let params = mime::header_params(content_type);
        let Some(boundary) = params.get("boundary").filter(|value| !value.is_empty()) else {
            return;
        };
        if depth >= 2 {
            return;
        }
        for part in mime::split_multipart(body, boundary.as_bytes()) {
            if out.len() >= MAX_PARTS {
                return;
            }
            let (part_head, part_body) = mime::split_head(part);
            leaf_bodies(part_head, part_body, depth + 1, out);
        }
        return;
    }
    let encoding = field(&headers, "content-transfer-encoding")
        .unwrap_or_default()
        .to_ascii_lowercase();
    out.push(mime::decode_transfer_bytes(body, &encoding));
}

/// Read at most [`MAX_XML_BYTES`]; `None` when there is more or the stream
/// is corrupt.
fn read_capped(reader: impl Read) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    reader.take(MAX_XML_BYTES + 1).read_to_end(&mut out).ok()?;
    (out.len() as u64 <= MAX_XML_BYTES).then_some(out)
}

/// The first file of a zip archive. Reporters put exactly one XML file in
/// theirs, so the central directory is not needed.
fn unzip_first(data: &[u8]) -> Option<Vec<u8>> {
    let word = |at: usize| Some(u16::from_le_bytes(data.get(at..at + 2)?.try_into().ok()?));
    let method = word(8)?;
    let stored_size = u32::from_le_bytes(data.get(18..22)?.try_into().ok()?) as usize;
    let start = 30usize
        .checked_add(usize::from(word(26)?))?
        .checked_add(usize::from(word(28)?))?;
    let body = data.get(start..)?;
    match method {
        0 => read_capped(body.get(..stored_size)?),
        // Deflate ends itself, so a size left to the trailing descriptor
        // (written as 0 here) does not matter.
        8 => read_capped(flate2::read::DeflateDecoder::new(body)),
        _ => None,
    }
}

/// The XML inside an attachment, whatever it is wrapped in. Decided by the
/// leading bytes: declared media types vary too much between reporters.
fn unwrap_xml(data: &[u8]) -> Option<Vec<u8>> {
    if data.starts_with(&[0x1f, 0x8b]) {
        read_capped(flate2::read::GzDecoder::new(data))
    } else if data.starts_with(b"PK\x03\x04") {
        unzip_first(data)
    } else if data.trim_ascii_start().starts_with(b"<") {
        (data.len() as u64 <= MAX_XML_BYTES).then(|| data.to_vec())
    } else {
        None
    }
}

fn child<'a>(node: roxmltree::Node<'a, 'a>, name: &str) -> Option<roxmltree::Node<'a, 'a>> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == name)
}

fn text(node: roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    let value = child(node, name)?.text()?.trim();
    (!value.is_empty()).then(|| {
        value
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_TEXT_CHARS)
            .collect()
    })
}

fn parse_xml(xml: &[u8]) -> Option<AggregateReport> {
    let xml = String::from_utf8_lossy(xml);
    // Document type declarations are refused by default, which rules out
    // entity expansion.
    let document = roxmltree::Document::parse(&xml).ok()?;
    let root = document.root_element();
    if root.tag_name().name() != "feedback" {
        return None;
    }
    let metadata = child(root, "report_metadata")?;
    let published = child(root, "policy_published")?;
    let range = child(metadata, "date_range")?;
    let domain = crate::domain::canonicalize_domain(&text(published, "domain")?).ok()?;

    let mut messages = 0u64;
    let mut passed = 0u64;
    let mut failing: BTreeMap<String, FailingSource> = BTreeMap::new();
    let records = root
        .children()
        .filter(|node| node.is_element() && node.tag_name().name() == "record")
        .take(MAX_RECORDS);
    for record in records {
        let Some(row) = child(record, "row") else {
            continue;
        };
        let count = text(row, "count")
            .and_then(|count| count.parse::<u64>().ok())
            .unwrap_or(0)
            .min(1_000_000_000);
        let evaluated = child(row, "policy_evaluated");
        let result = |name: &str| {
            evaluated
                .and_then(|node| text(node, name))
                .unwrap_or_default()
                .to_ascii_lowercase()
        };
        let (dkim, spf) = (result("dkim"), result("spf"));
        messages = messages.saturating_add(count);
        if dkim == "pass" || spf == "pass" {
            passed = passed.saturating_add(count);
            continue;
        }
        let source_ip = text(row, "source_ip").unwrap_or_else(|| "unknown".to_string());
        // Bound the map as well as the stored list: a hostile report could
        // name a different source in every row.
        if failing.len() >= MAX_FAILING * 50 && !failing.contains_key(&source_ip) {
            continue;
        }
        failing
            .entry(source_ip.clone())
            .or_insert(FailingSource {
                source_ip,
                messages: 0,
                dkim,
                spf,
            })
            .messages += count;
    }
    let mut failing = failing.into_values().collect::<Vec<_>>();
    failing.sort_by(|a, b| {
        b.messages
            .cmp(&a.messages)
            .then(a.source_ip.cmp(&b.source_ip))
    });
    failing.truncate(MAX_FAILING);

    let begin: i64 = text(range, "begin")?.parse().ok()?;
    let end: i64 = text(range, "end")?.parse().ok()?;
    // A report claiming months of mail could outweigh every real one.
    if end <= begin || end - begin > MAX_PERIOD_SECS {
        return None;
    }
    Some(AggregateReport {
        reporter: text(metadata, "org_name")?,
        report_id: text(metadata, "report_id")?,
        domain,
        begin,
        end,
        policy: text(published, "p").map(|policy| policy.to_ascii_lowercase()),
        messages,
        passed,
        failing,
    })
}

/// Parse `message` as a DMARC aggregate report. `None` when it is not one.
///
/// Only messages with the subject the RFC prescribes (`Report Domain: ...`)
/// are opened, so ordinary mail with attachments costs a header scan.
pub fn parse(message: &[u8]) -> Option<AggregateReport> {
    if message.len() > MAX_MESSAGE_BYTES {
        return None;
    }
    let (head, body) = mime::split_head(message);
    let subject = field(&header_fields(head), "subject")?.to_ascii_lowercase();
    if !subject.contains("report domain:") {
        return None;
    }
    let mut bodies = Vec::new();
    leaf_bodies(head, body, 0, &mut bodies);
    bodies
        .iter()
        .filter_map(|body| unwrap_xml(body))
        .find_map(|xml| parse_xml(&xml))
}

/// Store a report's totals. Returns `false` when the same report (reporter,
/// id and domain) was stored before, or when it claims to cover the future.
///
/// `sender` is the domain the message carrying the report was authenticated
/// as (DMARC pass), if it was. Only such reports count in [`summary`], and
/// they are filed under that domain rather than under the name the report
/// gives itself, which anyone can write: a forger can then neither pose as
/// a well-known reporter nor count as more than the domains they control.
/// Totals past [`RETENTION_SECS`] are pruned.
pub fn record(
    db_path: &Path,
    report: &AggregateReport,
    sender: Option<&str>,
    now: i64,
) -> Result<bool> {
    if report.end > now + 86400 {
        return Ok(false);
    }
    let authenticated = sender.is_some();
    let conn = crate::sqlite_pool::connection(db_path)?;
    conn.execute(
        "DELETE FROM dmarc_received_reports WHERE received_at < ?1",
        params![now - RETENTION_SECS],
    )?;
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO dmarc_received_reports (received_at, reporter, report_id, domain, \
         begin_at, end_at, policy, messages, passed, failing, authenticated) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            now,
            sender.unwrap_or(&report.reporter).to_ascii_lowercase(),
            report.report_id,
            report.domain,
            report.begin,
            report.end,
            report.policy,
            report.messages.min(i64::MAX as u64) as i64,
            report.passed.min(i64::MAX as u64) as i64,
            serde_json::to_string(&report.failing)?,
            authenticated,
        ],
    )?;
    Ok(inserted > 0)
}

/// What the authenticated reports of a period add up to for one domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainSummary {
    pub domain: String,
    pub reports: u64,
    /// The authenticated domains the reports came from.
    pub reporters: Vec<String>,
    pub messages: u64,
    pub passed: u64,
    /// The span the reports cover.
    pub begin: i64,
    pub end: i64,
    /// The sources that failed most, across all reports.
    pub failing: Vec<FailingSource>,
}

/// Per-domain totals of the authenticated reports whose period lies at or
/// after `since`, sorted by domain.
pub fn summary(db_path: &Path, since: i64) -> Result<Vec<DomainSummary>> {
    let conn = crate::sqlite_pool::connection(db_path)?;
    let mut statement = conn.prepare(
        "SELECT domain, reporter, begin_at, end_at, messages, passed, failing \
         FROM dmarc_received_reports WHERE authenticated = 1 AND begin_at >= ?1 \
         ORDER BY domain, reporter",
    )?;
    let rows = statement.query_map(params![since], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, String>(6)?,
        ))
    })?;
    let mut domains: BTreeMap<
        String,
        (DomainSummary, Vec<String>, BTreeMap<String, FailingSource>),
    > = BTreeMap::new();
    for row in rows {
        let (domain, reporter, begin, end, messages, passed, failing) = row?;
        let (summary, reporters, sources) = domains.entry(domain.clone()).or_insert_with(|| {
            (
                DomainSummary {
                    domain,
                    reports: 0,
                    reporters: Vec::new(),
                    messages: 0,
                    passed: 0,
                    begin,
                    end,
                    failing: Vec::new(),
                },
                Vec::new(),
                BTreeMap::new(),
            )
        });
        summary.reports += 1;
        summary.messages = summary.messages.saturating_add(messages.max(0) as u64);
        summary.passed = summary.passed.saturating_add(passed.max(0) as u64);
        summary.begin = summary.begin.min(begin);
        summary.end = summary.end.max(end);
        if !reporters.contains(&reporter) {
            reporters.push(reporter);
        }
        for source in serde_json::from_str::<Vec<FailingSource>>(&failing).unwrap_or_default() {
            sources
                .entry(source.source_ip.clone())
                .and_modify(|known| known.messages = known.messages.saturating_add(source.messages))
                .or_insert(source);
        }
    }
    Ok(domains
        .into_values()
        .map(|(mut summary, reporters, sources)| {
            summary.reporters = reporters;
            summary.failing = sources.into_values().collect();
            summary.failing.sort_by(|a, b| {
                b.messages
                    .cmp(&a.messages)
                    .then(a.source_ip.cmp(&b.source_ip))
            });
            summary.failing.truncate(5);
            summary
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::io::Write;

    const XML: &str = r#"<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>1234567890</report_id>
    <date_range><begin>1790000000</begin><end>1790086399</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>Example.COM</domain><adkim>r</adkim><aspf>r</aspf><p>none</p><pct>100</pct>
  </policy_published>
  <record>
    <row><source_ip>203.0.113.5</source_ip><count>40</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
  </record>
  <record>
    <row><source_ip>203.0.113.5</source_ip><count>2</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>pass</spf></policy_evaluated></row>
  </record>
  <record>
    <row><source_ip>198.51.100.9</source_ip><count>3</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
  </record>
  <record>
    <row><source_ip>198.51.100.9</source_ip><count>4</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
  </record>
</feedback>"#;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// A one-file zip as reporters write them: deflated, with the sizes
    /// left to a trailing data descriptor.
    fn zip(data: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        let deflated = encoder.finish().unwrap();
        let name = b"google.com!example.com!1790000000!1790086399.xml";
        let mut out = b"PK\x03\x04".to_vec();
        out.extend_from_slice(&[20, 0, 8, 0, 8, 0]); // version, flags (descriptor), deflate
        out.extend_from_slice(&[0; 16]); // time, date, crc and both sizes
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(name);
        out.extend_from_slice(&deflated);
        out.extend_from_slice(b"PK\x07\x08trailing descriptor and directory");
        out
    }

    fn attached(media_type: &str, data: &[u8]) -> Vec<u8> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(data);
        format!(
            "From: noreply-dmarc-support@google.com\r\n\
             Subject: Report domain: example.com Submitter: google.com Report-ID: 1234567890\r\n\
             Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n\
             --b\r\nContent-Type: text/plain\r\n\r\nThis is an aggregate report.\r\n\
             --b\r\nContent-Type: {media_type}; name=\"report\"\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n--b--\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn reports_are_read_from_gzip_zip_and_plain_xml() {
        for message in [
            attached("application/gzip", &gzip(XML.as_bytes())),
            attached("application/zip", &zip(XML.as_bytes())),
            attached("text/xml", XML.as_bytes()),
            // Declared types are not trusted either way.
            attached("application/octet-stream", &gzip(XML.as_bytes())),
        ] {
            let report = parse(&message).expect("a report");
            assert_eq!(report.reporter, "google.com");
            assert_eq!(report.report_id, "1234567890");
            assert_eq!(report.domain, "example.com");
            assert_eq!((report.begin, report.end), (1790000000, 1790086399));
            assert_eq!(report.policy.as_deref(), Some("none"));
            // Aligned SPF alone is a DMARC pass.
            assert_eq!((report.messages, report.passed), (49, 42));
            assert_eq!(
                report.failing,
                [FailingSource {
                    source_ip: "198.51.100.9".into(),
                    messages: 7,
                    dkim: "fail".into(),
                    spf: "fail".into()
                }]
            );
        }
        // Microsoft sends the archive as the whole body.
        let encoded = base64::engine::general_purpose::STANDARD.encode(gzip(XML.as_bytes()));
        let single = format!(
            "Subject: Report Domain: example.com\r\nContent-Type: application/gzip\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n"
        );
        assert!(parse(single.as_bytes()).is_some());
    }

    #[test]
    fn other_mail_and_hostile_reports_are_refused() {
        // The right attachment under an ordinary subject is not opened.
        let ordinary = String::from_utf8(attached("application/gzip", &gzip(XML.as_bytes())))
            .unwrap()
            .replace("Report domain:", "Quarterly numbers");
        assert!(parse(ordinary.as_bytes()).is_none());
        for body in [
            &b"not xml at all"[..],
            b"<html><body>hello</body></html>",
            b"<feedback><report_metadata/></feedback>",
            // Entity expansion needs a DTD, which is refused.
            b"<!DOCTYPE f [<!ENTITY a \"aaaa\">]><feedback>&a;</feedback>",
            b"PK\x03\x04",
            b"PK\x03\x04\x14\x00\x00\x00\x63\x00 unknown compression method ........",
            &[0x1f, 0x8b, 0xff, 0xff, 0xff][..],
        ] {
            assert!(
                parse(&attached("application/zip", body)).is_none(),
                "{body:?}"
            );
        }
        // A domain that is not one, and counts that are not numbers.
        let bad_domain = XML.replace("Example.COM", "not a domain");
        assert!(parse(&attached("text/xml", bad_domain.as_bytes())).is_none());
        let bad_count = XML.replace("<count>40</count>", "<count>lots</count>");
        let report = parse(&attached("text/xml", bad_count.as_bytes())).unwrap();
        assert_eq!((report.messages, report.passed), (9, 2));
        // A period of months, or one that ends before it begins.
        for end in ["1795000000", "1789999999"] {
            let long = XML.replace("<end>1790086399</end>", &format!("<end>{end}</end>"));
            assert!(
                parse(&attached("text/xml", long.as_bytes())).is_none(),
                "{end}"
            );
        }
        let oversized = vec![b'a'; MAX_MESSAGE_BYTES + 1];
        assert!(parse(&oversized).is_none());
    }

    #[test]
    fn a_bomb_is_not_inflated_past_the_limit() {
        let zeros = vec![b' '; (MAX_XML_BYTES + 1024) as usize];
        assert!(unwrap_xml(&gzip(&zeros)).is_none());
        assert!(unwrap_xml(&zip(&zeros)).is_none());
    }

    #[test]
    fn totals_are_stored_once_and_summed_per_domain() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("rmail.db");
        crate::db::init_db(&db).unwrap();
        // A database from before received reports were kept gains the table.
        crate::sqlite_pool::connection(&db)
            .unwrap()
            .execute_batch("DROP TABLE dmarc_received_reports;")
            .unwrap();
        crate::db::init_db(&db).unwrap();
        let report = parse(&attached("text/xml", XML.as_bytes())).unwrap();
        let now = 1790100000;
        assert!(record(&db, &report, Some("google.com"), now).unwrap());
        // Sent again after a temporary failure.
        assert!(!record(&db, &report, Some("Google.com"), now).unwrap());

        let mut second = report.clone();
        second.reporter = "Outlook.com".into();
        second.report_id = "abc".into();
        second.begin += 86400;
        second.end += 86400;
        second.messages = 10;
        second.passed = 10;
        second.failing = vec![FailingSource {
            source_ip: "192.0.2.77".into(),
            messages: 1,
            dkim: "fail".into(),
            spf: "fail".into(),
        }];
        assert!(record(&db, &second, Some("outlook.com"), now + 86400).unwrap());
        // Anyone can mail a forged report; unauthenticated, it is kept but
        // does not count, and cannot take the place of the real one.
        let mut forged = report.clone();
        forged.messages = 1_000_000;
        assert!(record(&db, &forged, None, now).unwrap());
        // Authenticated as some other domain, it counts as that domain's
        // word, whatever name the report gives itself.
        let mut posing = report.clone();
        posing.report_id = "posing".into();
        posing.messages = 5;
        posing.passed = 5;
        posing.failing.clear();
        assert!(record(&db, &posing, Some("attacker.example"), now).unwrap());
        // A report from the future is refused.
        let mut early = report.clone();
        early.report_id = "early".into();
        early.end = now + 2 * 86400;
        assert!(!record(&db, &early, Some("google.com"), now).unwrap());
        let mut other = report.clone();
        other.domain = "example.org".into();
        assert!(record(&db, &other, Some("google.com"), now).unwrap());

        let summaries = summary(&db, 0).unwrap();
        assert_eq!(summaries.len(), 2);
        let first = &summaries[0];
        assert_eq!(first.domain, "example.com");
        assert_eq!(first.reports, 3);
        assert_eq!(
            first.reporters,
            ["attacker.example", "google.com", "outlook.com"]
        );
        assert_eq!((first.messages, first.passed), (64, 57));
        assert_eq!((first.begin, first.end), (1790000000, 1790086399 + 86400));
        assert_eq!(
            first
                .failing
                .iter()
                .map(|source| (source.source_ip.as_str(), source.messages))
                .collect::<Vec<_>>(),
            [("198.51.100.9", 7), ("192.0.2.77", 1)]
        );
        // Only reports whose whole period lies in the window count.
        let recent = summary(&db, 1790000000 + 1).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].reports, 1);
        assert_eq!(recent[0].reporters, ["outlook.com"]);

        // Totals saturate instead of wrapping.
        let mut huge = report.clone();
        for id in ["huge-1", "huge-2", "huge-3"] {
            huge.report_id = id.into();
            huge.messages = u64::MAX;
            huge.passed = u64::MAX;
            assert!(record(&db, &huge, Some("google.com"), now).unwrap());
        }
        assert_eq!(summary(&db, 0).unwrap()[0].messages, u64::MAX);

        // Old totals go when a new report arrives.
        let mut later = report.clone();
        later.report_id = "later".into();
        later.begin += RETENTION_SECS;
        later.end += RETENTION_SECS;
        assert!(
            record(
                &db,
                &later,
                Some("google.com"),
                now + RETENTION_SECS + 86400 + 1
            )
            .unwrap()
        );
        assert_eq!(summary(&db, 0).unwrap()[0].reports, 1);
    }
}
