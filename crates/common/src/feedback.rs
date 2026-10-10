//! Abuse feedback reports (ARF, RFC 5965) from mailbox providers' feedback
//! loops (RFC 6650), including authentication failure reports (RFC 6591).
//!
//! Providers send one report per complaint ("this is spam") to an address
//! the operator registered with them. Mail to the addresses listed in
//! `security.feedback_addresses` is delivered like any other message; when
//! it is an ARF report it is also parsed, tied to the local account or
//! domain that sent the original message, and stored in the
//! `feedback_reports` table, so a compromised account or a sender that
//! draws complaints shows up in the admin console, `rmail_ctl feedback` and
//! the log.
//!
//! Reports come from the Internet, so parsing is bounded: the message size,
//! the number of header fields and each value's length are capped, and
//! anything malformed is simply not a report.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use rusqlite::params;
use serde::Serialize;

use crate::mime;

/// Larger messages are delivered but not parsed. Reports are small: the
/// original message is usually truncated or reduced to its headers.
pub const MAX_REPORT_BYTES: usize = 4 * 1024 * 1024;
/// Header fields read from any one header block.
const MAX_FIELDS: usize = 256;
/// Characters kept of a field value.
const MAX_VALUE_CHARS: usize = 1000;
/// Values kept of a repeatable field (Original-Rcpt-To, Reported-Domain).
const MAX_REPEATED: usize = 20;
/// Reports are kept this long; older ones are pruned as new ones arrive.
pub const RETENTION_SECS: i64 = 180 * 24 * 3600;
/// The window the per-account complaint threshold counts over.
pub const THRESHOLD_WINDOW_SECS: i64 = 24 * 3600;

/// Feedback types counted in metrics: RFC 5965 section 7.3 plus RFC 6591's
/// `auth-failure`. Anything else is counted as "unknown".
pub const FEEDBACK_TYPES: &[&str] = &[
    "abuse",
    "fraud",
    "virus",
    "other",
    "not-spam",
    "auth-failure",
];
static RECEIVED: [AtomicU64; 7] = [const { AtomicU64::new(0) }; 7];

/// Count one stored report in the process's metrics.
pub fn count_received(feedback_type: &str) {
    let index = FEEDBACK_TYPES
        .iter()
        .position(|known| *known == feedback_type)
        .unwrap_or(FEEDBACK_TYPES.len());
    RECEIVED[index].fetch_add(1, Ordering::Relaxed);
}

/// Prometheus text for the received-report counters.
pub(crate) fn render_metrics(out: &mut String) {
    out.push_str(
        "# HELP rmail_feedback_reports_total Abuse feedback (ARF) reports received, by feedback type\n",
    );
    out.push_str("# TYPE rmail_feedback_reports_total counter\n");
    for (index, name) in FEEDBACK_TYPES.iter().chain(["unknown"].iter()).enumerate() {
        out.push_str(&format!(
            "rmail_feedback_reports_total{{type=\"{name}\"}} {}\n",
            RECEIVED[index].load(Ordering::Relaxed)
        ));
    }
}

/// True for feedback types that are a recipient's complaint about the mail
/// (as opposed to `not-spam` or an authentication failure report).
pub fn is_complaint(feedback_type: &str) -> bool {
    matches!(feedback_type, "abuse" | "fraud" | "virus" | "other")
}

/// The parts of an ARF report this server uses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeedbackReport {
    /// Lower-cased `Feedback-Type`, e.g. "abuse".
    pub feedback_type: String,
    pub user_agent: Option<String>,
    /// The report message's own From address: who complained.
    pub reporter: Option<String>,
    /// The report message's Message-ID, used to store each report once.
    pub report_message_id: Option<String>,
    /// Envelope sender of the reported message, as the provider saw it.
    pub original_mail_from: Option<String>,
    pub original_rcpt_to: Vec<String>,
    pub arrival_date: Option<String>,
    pub source_ip: Option<String>,
    pub reported_domain: Vec<String>,
    /// How many incidents the report stands for (RFC 5965 `Incidents`).
    pub incidents: u64,
    /// RFC 6591 `Auth-Failure` (dkim, spf, dmarc, ...).
    pub auth_failure: Option<String>,
    pub original: OriginalMessage,
}

/// Headers of the reported message (the report's third part).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OriginalMessage {
    pub return_path: Option<String>,
    pub from: Option<String>,
    pub sender: Option<String>,
    pub subject: Option<String>,
    pub message_id: Option<String>,
    /// (d=, i=) of each DKIM-Signature, lower-cased.
    pub dkim: Vec<(String, Option<String>)>,
}

/// Parse `message` as an ARF report. `None` when it is not one: it is not
/// `multipart/report; report-type=feedback-report`, has no
/// `message/feedback-report` part, or that part has no `Feedback-Type`.
pub fn parse(message: &[u8]) -> Option<FeedbackReport> {
    if message.len() > MAX_REPORT_BYTES {
        return None;
    }
    let (head, body) = mime::split_head(message);
    let headers = header_fields(head);
    let content_type = field(&headers, "content-type")?;
    if media_type(content_type) != "multipart/report" {
        return None;
    }
    let params = mime::header_params(content_type);
    if !params
        .get("report-type")
        .is_some_and(|kind| kind.eq_ignore_ascii_case("feedback-report"))
    {
        return None;
    }
    let boundary = params.get("boundary").filter(|value| !value.is_empty())?;

    let mut report_part = None;
    let mut original_part = None;
    for part in mime::split_multipart(body, boundary.as_bytes()) {
        let (part_head, part_body) = mime::split_head(part);
        let part_headers = header_fields(part_head);
        let kind = field(&part_headers, "content-type")
            .map(media_type)
            .unwrap_or_default();
        let encoding = field(&part_headers, "content-transfer-encoding")
            .unwrap_or_default()
            .to_ascii_lowercase();
        match kind.as_str() {
            "message/feedback-report" if report_part.is_none() => {
                report_part = Some(mime::decode_transfer_bytes(part_body, &encoding));
            }
            "message/rfc822" | "text/rfc822-headers" | "message/rfc822-headers"
                if original_part.is_none() =>
            {
                original_part = Some(mime::decode_transfer_bytes(part_body, &encoding));
            }
            _ => {}
        }
    }

    let report_part = report_part?;
    let fields = header_fields(mime::split_head(&report_part).0);
    let feedback_type = field(&fields, "feedback-type")?
        .split(|c: char| c.is_whitespace() || c == ';')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if feedback_type.is_empty() {
        return None;
    }
    let repeated = |name: &str| -> Vec<String> {
        fields
            .iter()
            .filter(|(field, _)| field == name)
            .map(|(_, value)| value.clone())
            .take(MAX_REPEATED)
            .collect()
    };
    Some(FeedbackReport {
        feedback_type,
        user_agent: field(&fields, "user-agent").map(str::to_string),
        reporter: field(&headers, "from").and_then(address),
        report_message_id: field(&headers, "message-id").map(message_id),
        original_mail_from: field(&fields, "original-mail-from").and_then(address),
        original_rcpt_to: repeated("original-rcpt-to")
            .iter()
            .filter_map(|value| address(value))
            .collect(),
        arrival_date: field(&fields, "arrival-date")
            .or_else(|| field(&fields, "received-date"))
            .map(str::to_string),
        source_ip: field(&fields, "source-ip").map(str::to_string),
        reported_domain: repeated("reported-domain")
            .into_iter()
            .map(|domain| domain.to_ascii_lowercase())
            .collect(),
        incidents: field(&fields, "incidents")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(1)
            .clamp(1, 1_000_000),
        auth_failure: field(&fields, "auth-failure").map(|value| value.to_ascii_lowercase()),
        original: original_part
            .map(|original| parse_original(&original))
            .unwrap_or_default(),
    })
}

fn parse_original(message: &[u8]) -> OriginalMessage {
    let headers = header_fields(mime::split_head(message).0);
    OriginalMessage {
        return_path: field(&headers, "return-path").and_then(address),
        from: field(&headers, "from").and_then(address),
        sender: field(&headers, "sender").and_then(address),
        subject: field(&headers, "subject").map(mime::decode_rfc2047_words),
        message_id: field(&headers, "message-id").map(message_id),
        dkim: headers
            .iter()
            .filter(|(name, _)| name == "dkim-signature")
            .filter_map(|(_, value)| dkim_identity(value))
            .take(MAX_REPEATED)
            .collect(),
    }
}

/// Header fields in order, names lower-cased, folded lines joined, values
/// trimmed, stripped of control characters and capped in length.
fn header_fields(head: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(head);
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = fields.last_mut()
                && value.len() < MAX_VALUE_CHARS * 4
            {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        if fields.len() >= MAX_FIELDS {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() || name.contains(char::is_whitespace) {
            continue;
        }
        fields.push((name.to_ascii_lowercase(), value.trim().to_string()));
    }
    for (_, value) in &mut fields {
        *value = value
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_VALUE_CHARS)
            .collect::<String>()
            .trim()
            .to_string();
    }
    fields
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(field, _)| field == name)
        .map(|(_, value)| value.as_str())
        .filter(|value| !value.is_empty())
}

/// Lower-cased `type/subtype` of a Content-Type value.
fn media_type(value: &str) -> String {
    value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

/// The address in `Name <local@domain>`, `<local@domain>` or a bare
/// `local@domain`, with the domain canonicalized. `None` for `<>` and
/// anything without a valid domain.
fn address(value: &str) -> Option<String> {
    let inner = match (value.rfind('<'), value.rfind('>')) {
        (Some(open), Some(close)) if open < close => &value[open + 1..close],
        _ => value
            .split(|c: char| c.is_whitespace() || c == ',')
            .find(|token| token.contains('@'))?,
    };
    let inner = inner.trim().trim_matches('"');
    crate::domain::canonicalize_mailbox_address(inner)
        .ok()
        .map(|canonical| canonical.to_lowercase())
}

/// A Message-ID without its angle brackets.
fn message_id(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim()
        .to_string()
}

/// `d=` and `i=` of a DKIM-Signature value.
fn dkim_identity(value: &str) -> Option<(String, Option<String>)> {
    let mut domain = None;
    let mut identity = None;
    for tag in value.split(';') {
        let Some((name, tag_value)) = tag.split_once('=') else {
            continue;
        };
        let tag_value: String = tag_value.chars().filter(|c| !c.is_whitespace()).collect();
        match name.trim() {
            "d" => domain = crate::domain::canonicalize_domain(&tag_value).ok(),
            "i" => identity = Some(tag_value.to_lowercase()),
            _ => {}
        }
    }
    Some((domain?, identity))
}

/// Which local account or domain a report is about, and how that was found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Attribution {
    /// A local mailbox that sent the reported message.
    pub account: Option<String>,
    /// The hosted domain it came from.
    pub domain: Option<String>,
    /// The field the answer came from, e.g. "original-mail-from".
    pub method: Option<String>,
}

/// Tie a report to the local sender. Candidates are tried in order of how
/// hard they are to forge from outside: the envelope sender the provider
/// saw (Original-Mail-From, then the original Return-Path), the Sender and
/// From headers, and the DKIM `i=` identity. The first one that is a local
/// mailbox names the account; failing that, the first in a hosted domain
/// (an alias, say) names the domain, and last a DKIM `d=` in a hosted
/// domain.
pub fn attribute(
    report: &FeedbackReport,
    is_account: impl Fn(&str) -> bool,
    is_local_domain: impl Fn(&str) -> bool,
) -> Attribution {
    let original = &report.original;
    let dkim_identities = original
        .dkim
        .iter()
        .filter_map(|(_, identity)| identity.as_deref())
        .filter(|identity| !identity.starts_with('@'));
    let candidates: Vec<(&str, &str)> = [
        ("original-mail-from", report.original_mail_from.as_deref()),
        ("return-path", original.return_path.as_deref()),
        ("sender", original.sender.as_deref()),
        ("from", original.from.as_deref()),
    ]
    .into_iter()
    .filter_map(|(method, address)| address.map(|address| (method, address)))
    .chain(dkim_identities.map(|identity| ("dkim-identity", identity)))
    .collect();
    let domain_of = |address: &str| {
        address
            .rsplit_once('@')
            .map(|(_, domain)| domain.to_string())
    };
    if let Some((method, address)) = candidates.iter().find(|(_, address)| is_account(address)) {
        return Attribution {
            account: Some(address.to_string()),
            domain: domain_of(address),
            method: Some(method.to_string()),
        };
    }
    if let Some((method, domain)) = candidates
        .iter()
        .filter_map(|(method, address)| domain_of(address).map(|domain| (method, domain)))
        .find(|(_, domain)| is_local_domain(domain))
    {
        return Attribution {
            account: None,
            domain: Some(domain),
            method: Some(method.to_string()),
        };
    }
    if let Some((domain, _)) = original
        .dkim
        .iter()
        .find(|(domain, _)| is_local_domain(domain))
    {
        return Attribution {
            account: None,
            domain: Some(domain.clone()),
            method: Some("dkim-domain".to_string()),
        };
    }
    Attribution::default()
}

/// Whether `address` is one of the configured feedback addresses. An entry
/// with an `@` matches that address; a bare local part (e.g. `fbl`) matches
/// it in any domain, which for inbound mail means any hosted domain.
pub fn is_feedback_address(address: &str, configured: &[String]) -> bool {
    let address = address.to_lowercase();
    let local = address
        .rsplit_once('@')
        .map_or(address.as_str(), |(local, _)| local);
    configured.iter().any(|entry| {
        let entry = entry.trim().to_lowercase();
        !entry.is_empty()
            && if entry.contains('@') {
                entry == address
            } else {
                entry == local
            }
    })
}

/// One stored report, as shown in the admin console and `rmail_ctl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoredReport {
    pub id: i64,
    pub received_at: i64,
    pub recipient: String,
    pub reporter: Option<String>,
    pub feedback_type: String,
    pub user_agent: Option<String>,
    pub incidents: i64,
    pub source_ip: Option<String>,
    pub arrival_date: Option<String>,
    pub original_mail_from: Option<String>,
    pub original_rcpt_to: Option<String>,
    pub reported_domain: Option<String>,
    pub auth_failure: Option<String>,
    pub original_from: Option<String>,
    pub original_subject: Option<String>,
    pub original_message_id: Option<String>,
    pub account: Option<String>,
    pub domain: Option<String>,
    pub attributed_by: Option<String>,
    /// The report itself passed DMARC, so it really came from the reporter.
    pub authenticated: bool,
}

/// Store a report. Returns `None` when the same report (by its Message-ID)
/// was stored before, e.g. because it was sent again after a temporary
/// failure. Reports older than [`RETENTION_SECS`] are pruned.
pub fn record(
    db_path: &Path,
    recipient: &str,
    report: &FeedbackReport,
    attribution: &Attribution,
    authenticated: bool,
    now: i64,
) -> Result<Option<i64>> {
    let conn = crate::sqlite_pool::connection(db_path)?;
    conn.execute(
        "DELETE FROM feedback_reports WHERE received_at < ?1",
        params![now - RETENTION_SECS],
    )?;
    let joined = |values: &[String]| (!values.is_empty()).then(|| values.join(", "));
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO feedback_reports (received_at, recipient, reporter, feedback_type, \
         user_agent, incidents, source_ip, arrival_date, original_mail_from, original_rcpt_to, \
         reported_domain, auth_failure, original_from, original_subject, original_message_id, \
         account, domain, attributed_by, authenticated, report_message_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
        params![
            now,
            recipient,
            report.reporter,
            report.feedback_type,
            report.user_agent,
            report.incidents as i64,
            report.source_ip,
            report.arrival_date,
            report.original_mail_from,
            joined(&report.original_rcpt_to),
            joined(&report.reported_domain),
            report.auth_failure,
            report.original.from,
            report.original.subject,
            report.original.message_id,
            attribution.account,
            attribution.domain,
            attribution.method,
            authenticated,
            report.report_message_id,
        ],
    )?;
    Ok((inserted > 0).then(|| conn.last_insert_rowid()))
}

/// Authenticated complaints (see [`is_complaint`]) about `account` since
/// `since`, counting each report's incidents.
pub fn account_complaints(db_path: &Path, account: &str, since: i64) -> Result<u64> {
    let conn = crate::sqlite_pool::connection(db_path)?;
    let count: i64 = conn.query_row(
        "SELECT COALESCE(SUM(incidents), 0) FROM feedback_reports WHERE account = ?1 \
         AND received_at >= ?2 AND authenticated = 1 \
         AND feedback_type IN ('abuse', 'fraud', 'virus', 'other')",
        params![account, since],
        |row| row.get(0),
    )?;
    Ok(count.max(0) as u64)
}

/// The newest reports, optionally only those about `account` (or, for an
/// entry without `@`, a domain).
pub fn list(db_path: &Path, filter: Option<&str>, limit: usize) -> Result<Vec<StoredReport>> {
    let conn = crate::sqlite_pool::connection(db_path)?;
    let filter = filter.map(|value| value.trim().to_lowercase());
    let mut statement = conn.prepare(
        "SELECT id, received_at, recipient, reporter, feedback_type, user_agent, incidents, \
         source_ip, arrival_date, original_mail_from, original_rcpt_to, reported_domain, \
         auth_failure, original_from, original_subject, original_message_id, account, domain, \
         attributed_by, authenticated FROM feedback_reports \
         WHERE ?1 IS NULL OR account = ?1 OR domain = ?1 \
         ORDER BY received_at DESC, id DESC LIMIT ?2",
    )?;
    let rows = statement.query_map(params![filter, limit as i64], |row| {
        Ok(StoredReport {
            id: row.get(0)?,
            received_at: row.get(1)?,
            recipient: row.get(2)?,
            reporter: row.get(3)?,
            feedback_type: row.get(4)?,
            user_agent: row.get(5)?,
            incidents: row.get(6)?,
            source_ip: row.get(7)?,
            arrival_date: row.get(8)?,
            original_mail_from: row.get(9)?,
            original_rcpt_to: row.get(10)?,
            reported_domain: row.get(11)?,
            auth_failure: row.get(12)?,
            original_from: row.get(13)?,
            original_subject: row.get(14)?,
            original_message_id: row.get(15)?,
            account: row.get(16)?,
            domain: row.get(17)?,
            attributed_by: row.get(18)?,
            authenticated: row.get(19)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Complaint totals per sender since `since`: who draws the most complaints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SenderSummary {
    /// The account, or the domain when no account was found, or "" for
    /// reports not tied to anything local.
    pub sender: String,
    pub complaints: i64,
    /// Complaints from reports that failed DMARC (possibly forged).
    pub unverified: i64,
    pub last_received_at: i64,
}

pub fn summary(db_path: &Path, since: i64) -> Result<Vec<SenderSummary>> {
    let conn = crate::sqlite_pool::connection(db_path)?;
    let mut statement = conn.prepare(
        "SELECT COALESCE(account, domain, '') AS sender, \
         SUM(CASE WHEN authenticated = 1 THEN incidents ELSE 0 END), \
         SUM(CASE WHEN authenticated = 1 THEN 0 ELSE incidents END), MAX(received_at) \
         FROM feedback_reports WHERE received_at >= ?1 \
         AND feedback_type IN ('abuse', 'fraud', 'virus', 'other') \
         GROUP BY sender ORDER BY 2 DESC, 3 DESC, sender LIMIT 100",
    )?;
    let rows = statement.query_map(params![since], |row| {
        Ok(SenderSummary {
            sender: row.get(0)?,
            complaints: row.get(1)?,
            unverified: row.get(2)?,
            last_received_at: row.get(3)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Delete one report; true when it existed.
pub fn delete(db_path: &Path, id: i64) -> Result<bool> {
    let conn = crate::sqlite_pool::connection(db_path)?;
    Ok(conn.execute("DELETE FROM feedback_reports WHERE id = ?1", params![id])? > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The abuse report example of RFC 5965 appendix B.2, with the given
    /// feedback part fields and third part.
    fn arf(fields: &str, third_part: &str) -> Vec<u8> {
        format!(
            "From: <abusedesk@example.com>\r\n\
             Date: Thu, 8 Mar 2005 17:40:36 EDT\r\n\
             Subject: FW: Earn money\r\n\
             To: <abuse@example.net>\r\n\
             Message-ID: <report-1@example.com>\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/report; report-type=feedback-report;\r\n     \
             boundary=\"part1_13d.2e68ed54_boundary\"\r\n\
             \r\n\
             --part1_13d.2e68ed54_boundary\r\n\
             Content-Type: text/plain; charset=\"US-ASCII\"\r\n\
             Content-Transfer-Encoding: 7bit\r\n\
             \r\n\
             This is an email abuse report for an email message received from IP\r\n\
             192.0.2.1 on Thu, 8 Mar 2005 14:00:00 EDT.\r\n\
             \r\n\
             --part1_13d.2e68ed54_boundary\r\n\
             Content-Type: message/feedback-report\r\n\
             \r\n\
             {fields}\
             \r\n\
             --part1_13d.2e68ed54_boundary\r\n\
             {third_part}\
             --part1_13d.2e68ed54_boundary--\r\n"
        )
        .into_bytes()
    }

    const RFC5965_FIELDS: &str = "Feedback-Type: abuse\r\n\
        User-Agent: SomeGenerator/1.0\r\n\
        Version: 1\r\n\
        Original-Mail-From: <somespammer@example.net>\r\n\
        Original-Rcpt-To: <user@example.com>\r\n\
        Arrival-Date: Thu, 8 Mar 2005 14:00:00 EDT\r\n\
        Reporting-MTA: dns; mail.example.com\r\n\
        Source-IP: 192.0.2.1\r\n\
        Authentication-Results: mail.example.com;\r\n               \
        spf=fail smtp.mail=somespammer@example.com\r\n\
        Reported-Domain: example.net\r\n\
        Reported-Uri: http://example.net/earn_money.html\r\n\
        Reported-Uri: mailto:user@example.com\r\n\
        Removal-Recipient: user@example.com\r\n";

    const RFC5965_ORIGINAL: &str = "Content-Type: message/rfc822\r\n\
        Content-Disposition: inline\r\n\
        \r\n\
        From: <somespammer@example.net>\r\n\
        Received: from mailserver.example.net (mailserver.example.net\r\n        \
        [192.0.2.1]) by example.com with ESMTP id M63d4137594e46;\r\n        \
        Thu, 08 Mar 2005 14:00:00 -0400\r\n\
        To: <Undisclosed Recipients>\r\n\
        Subject: Earn money\r\n\
        MIME-Version: 1.0\r\n\
        Content-type: text/plain\r\n\
        Message-ID: 8787KJKJ3K4J3K4J3K4J3.mail@example.net\r\n\
        Date: Thu, 02 Sep 2004 12:31:03 -0500\r\n\
        \r\n\
        Spam Spam Spam\r\n";

    /// A provider's complaint about mail one of our users sent, with only
    /// the original headers (text/rfc822-headers), as many loops send.
    fn complaint_about(mail_from: &str, from: &str, dkim: &str) -> Vec<u8> {
        arf(
            &format!(
                "Feedback-Type: abuse\r\nUser-Agent: Yahoo!-Mail-Feedback/2.0\r\nVersion: 1\r\n\
                 Original-Mail-From: <{mail_from}>\r\nArrival-Date: Mon, 5 Oct 2026 10:00:00 +0000\r\n\
                 Source-IP: 198.51.100.7\r\nReported-Domain: example.org\r\n"
            ),
            &format!(
                "Content-Type: text/rfc822-headers\r\n\r\n\
                 Return-Path: <{mail_from}>\r\n\
                 DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; {dkim}\r\n \
                 s=rmail; h=from:to:subject; bh=abc=; b=def=\r\n\
                 From: Newsletter <{from}>\r\n\
                 To: redacted@yahoo.example\r\n\
                 Subject: =?utf-8?q?Big_sale?=\r\n\
                 Message-ID: <abc123@mail.example.org>\r\n\r\n"
            ),
        )
    }

    #[test]
    fn parses_the_rfc_5965_example() {
        let report = parse(&arf(RFC5965_FIELDS, RFC5965_ORIGINAL)).expect("an ARF report");
        assert_eq!(report.feedback_type, "abuse");
        assert_eq!(report.user_agent.as_deref(), Some("SomeGenerator/1.0"));
        assert_eq!(report.reporter.as_deref(), Some("abusedesk@example.com"));
        assert_eq!(
            report.report_message_id.as_deref(),
            Some("report-1@example.com")
        );
        assert_eq!(
            report.original_mail_from.as_deref(),
            Some("somespammer@example.net")
        );
        assert_eq!(report.original_rcpt_to, ["user@example.com"]);
        assert_eq!(report.source_ip.as_deref(), Some("192.0.2.1"));
        assert_eq!(
            report.arrival_date.as_deref(),
            Some("Thu, 8 Mar 2005 14:00:00 EDT")
        );
        assert_eq!(report.reported_domain, ["example.net"]);
        assert_eq!(report.incidents, 1);
        assert_eq!(report.original.subject.as_deref(), Some("Earn money"));
        assert_eq!(
            report.original.message_id.as_deref(),
            Some("8787KJKJ3K4J3K4J3K4J3.mail@example.net")
        );
        assert_eq!(
            report.original.from.as_deref(),
            Some("somespammer@example.net")
        );
    }

    #[test]
    fn parses_an_auth_failure_report() {
        // RFC 6591 appendix B, shortened.
        let fields = "Feedback-Type: auth-failure\r\n\
            User-Agent: SomeDKIMFilter/1.0\r\n\
            Version: 1\r\n\
            Original-Mail-From: <randomuser@example.net>\r\n\
            Arrival-Date: Thu, 8 Mar 2005 14:00:00 EDT\r\n\
            Source-IP: 192.0.2.1\r\n\
            Authentication-Results: mail.example.com; dkim=fail header.d=example.net\r\n\
            Reported-Domain: example.net\r\n\
            DKIM-Domain: example.net\r\n\
            Auth-Failure: bodyhash\r\n";
        let report = parse(&arf(fields, RFC5965_ORIGINAL)).expect("an ARF report");
        assert_eq!(report.feedback_type, "auth-failure");
        assert_eq!(report.auth_failure.as_deref(), Some("bodyhash"));
        assert!(!is_complaint(&report.feedback_type));
    }

    #[test]
    fn decodes_encoded_parts_and_reads_header_only_originals() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(RFC5965_FIELDS.replace("abuse", "fraud"));
        let message = String::from_utf8(arf("", RFC5965_ORIGINAL)).unwrap().replace(
            "Content-Type: message/feedback-report\r\n\r\n",
            &format!(
                "Content-Type: message/feedback-report\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n"
            ),
        );
        let report = parse(message.as_bytes()).expect("an ARF report");
        assert_eq!(report.feedback_type, "fraud");
        assert_eq!(report.source_ip.as_deref(), Some("192.0.2.1"));

        let report = parse(&complaint_about(
            "news@example.org",
            "news@example.org",
            "d=Example.ORG; i=news@example.org;",
        ))
        .expect("an ARF report");
        assert_eq!(report.original.subject.as_deref(), Some("Big sale"));
        assert_eq!(
            report.original.return_path.as_deref(),
            Some("news@example.org")
        );
        assert_eq!(
            report.original.dkim,
            [(
                "example.org".to_string(),
                Some("news@example.org".to_string())
            )]
        );
    }

    #[test]
    fn other_messages_are_not_reports() {
        assert!(parse(b"From: a@example.com\r\nSubject: hi\r\n\r\nhello\r\n").is_none());
        let dsn = String::from_utf8(arf(RFC5965_FIELDS, RFC5965_ORIGINAL))
            .unwrap()
            .replace("report-type=feedback-report", "report-type=delivery-status");
        assert!(parse(dsn.as_bytes()).is_none());
        // No Feedback-Type: not a valid report.
        let fields = RFC5965_FIELDS.replace("Feedback-Type: abuse\r\n", "");
        assert!(parse(&arf(&fields, RFC5965_ORIGINAL)).is_none());
        // No boundary.
        assert!(
            parse(b"Content-Type: multipart/report; report-type=feedback-report\r\n\r\nx")
                .is_none()
        );
    }

    #[test]
    fn hostile_input_is_bounded() {
        let sample = arf(RFC5965_FIELDS, RFC5965_ORIGINAL);
        // Every truncation parses or not, but never panics.
        for end in 0..sample.len() {
            let _ = parse(&sample[..end]);
        }
        // Invalid UTF-8 and NULs.
        let mut garbage = sample.clone();
        for (index, byte) in garbage.iter_mut().enumerate() {
            if index % 7 == 0 {
                *byte = 0xff;
            } else if index % 11 == 0 {
                *byte = 0;
            }
        }
        let _ = parse(&garbage);
        // Oversized messages are not parsed at all.
        let mut large = sample.clone();
        large.resize(MAX_REPORT_BYTES + 1, b'a');
        assert!(parse(&large).is_none());
        // Many fields are capped.
        let mut fields = String::from("Feedback-Type: abuse\r\n");
        for index in 0..5000 {
            fields.push_str(&format!("Original-Rcpt-To: <u{index}@example.com>\r\n"));
        }
        fields.push_str("User-Agent: late\r\n");
        let report = parse(&arf(&fields, RFC5965_ORIGINAL)).expect("an ARF report");
        assert_eq!(report.original_rcpt_to.len(), MAX_REPEATED);
        assert!(
            report.user_agent.is_none(),
            "fields past the cap are dropped"
        );
        // So are long values, folded or not.
        let long = format!(
            "Feedback-Type: abuse\r\nUser-Agent: {}\r\nVersion: 1\r\n{}",
            "y".repeat(100_000),
            " folded\r\n".repeat(100_000)
        );
        let report = parse(&arf(&long, RFC5965_ORIGINAL)).expect("an ARF report");
        assert_eq!(report.user_agent.unwrap().chars().count(), MAX_VALUE_CHARS);
        // Control characters never reach the database or logs.
        let report = parse(&arf(
            "Feedback-Type: abuse\r\nSource-IP: 192.0.2.1\u{1b}[31m\r\n",
            RFC5965_ORIGINAL,
        ))
        .unwrap();
        assert_eq!(report.source_ip.as_deref(), Some("192.0.2.1[31m"));
    }

    #[test]
    fn attributes_reports_to_the_local_sender() {
        let accounts = ["alice@example.org"];
        let domains = ["example.org"];
        let is_account = |address: &str| accounts.contains(&address);
        let is_local = |domain: &str| domains.contains(&domain);

        // The envelope sender is a local account.
        let report = parse(&complaint_about(
            "alice@example.org",
            "alice@example.org",
            "d=example.org;",
        ))
        .unwrap();
        let found = attribute(&report, is_account, is_local);
        assert_eq!(found.account.as_deref(), Some("alice@example.org"));
        assert_eq!(found.domain.as_deref(), Some("example.org"));
        assert_eq!(found.method.as_deref(), Some("original-mail-from"));

        // A bounce address elsewhere, but From is the account.
        let report = parse(&complaint_about(
            "bounces@esp.example.net",
            "Alice@Example.org",
            "d=esp.example.net;",
        ))
        .unwrap();
        let found = attribute(&report, is_account, is_local);
        assert_eq!(found.account.as_deref(), Some("alice@example.org"));
        assert_eq!(found.method.as_deref(), Some("from"));

        // An alias in a hosted domain names only the domain.
        let report = parse(&complaint_about(
            "sales@example.org",
            "sales@example.org",
            "d=example.org;",
        ))
        .unwrap();
        let found = attribute(&report, is_account, is_local);
        assert_eq!(found.account, None);
        assert_eq!(found.domain.as_deref(), Some("example.org"));
        assert_eq!(found.method.as_deref(), Some("original-mail-from"));

        // Only our DKIM signature ties it to us.
        let report = parse(&complaint_about(
            "x@other.example",
            "y@other.example",
            "d=example.org; i=@example.org;",
        ))
        .unwrap();
        let found = attribute(&report, is_account, is_local);
        assert_eq!(found.domain.as_deref(), Some("example.org"));
        assert_eq!(found.method.as_deref(), Some("dkim-domain"));

        // Nothing local.
        let report = parse(&arf(RFC5965_FIELDS, RFC5965_ORIGINAL)).unwrap();
        assert_eq!(
            attribute(&report, is_account, is_local),
            Attribution::default()
        );
    }

    #[test]
    fn matches_configured_feedback_addresses() {
        let configured = vec!["FBL@example.org".to_string(), " abuse ".to_string()];
        assert!(is_feedback_address("fbl@example.org", &configured));
        assert!(is_feedback_address("Abuse@example.org", &configured));
        assert!(is_feedback_address("abuse@example.net", &configured));
        assert!(!is_feedback_address("fbl@example.net", &configured));
        assert!(!is_feedback_address("postmaster@example.org", &configured));
        assert!(!is_feedback_address("abuse@example.org", &[]));
    }

    #[test]
    fn stores_reports_once_and_counts_complaints() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("rmail.db");
        crate::db::init_db(&db).unwrap();
        let report = parse(&complaint_about(
            "alice@example.org",
            "alice@example.org",
            "d=example.org;",
        ))
        .unwrap();
        let attribution = Attribution {
            account: Some("alice@example.org".into()),
            domain: Some("example.org".into()),
            method: Some("original-mail-from".into()),
        };
        let now = 1_800_000_000;
        let first = record(&db, "fbl@example.org", &report, &attribution, true, now).unwrap();
        assert!(first.is_some());
        // The same report again (same Message-ID) is ignored.
        assert_eq!(
            record(&db, "fbl@example.org", &report, &attribution, true, now).unwrap(),
            None
        );
        let mut second = report.clone();
        second.report_message_id = Some("report-2@example.com".into());
        second.incidents = 3;
        record(&db, "fbl@example.org", &second, &attribution, true, now).unwrap();
        // Unauthenticated reports and not-spam reports do not count.
        let mut forged = report.clone();
        forged.report_message_id = Some("report-3@example.com".into());
        record(&db, "fbl@example.org", &forged, &attribution, false, now).unwrap();
        let mut not_spam = report.clone();
        not_spam.report_message_id = Some("report-4@example.com".into());
        not_spam.feedback_type = "not-spam".into();
        record(&db, "fbl@example.org", &not_spam, &attribution, true, now).unwrap();

        assert_eq!(
            account_complaints(&db, "alice@example.org", now - 60).unwrap(),
            4
        );
        assert_eq!(
            account_complaints(&db, "alice@example.org", now + 1).unwrap(),
            0
        );
        let senders = summary(&db, now - 60).unwrap();
        assert_eq!(
            senders,
            [SenderSummary {
                sender: "alice@example.org".into(),
                complaints: 4,
                unverified: 1,
                last_received_at: now,
            }]
        );
        let stored = list(&db, Some("Alice@example.org"), 10).unwrap();
        assert_eq!(stored.len(), 4);
        assert_eq!(stored[0].original_subject.as_deref(), Some("Big sale"));
        assert_eq!(list(&db, Some("example.org"), 10).unwrap().len(), 4);
        assert!(list(&db, Some("bob@example.org"), 10).unwrap().is_empty());
        assert!(delete(&db, stored[0].id).unwrap());
        assert!(!delete(&db, stored[0].id).unwrap());

        // Old reports are pruned when new ones arrive.
        let mut late = report.clone();
        late.report_message_id = Some("report-5@example.com".into());
        record(
            &db,
            "fbl@example.org",
            &late,
            &attribution,
            true,
            now + RETENTION_SECS + 1,
        )
        .unwrap();
        assert_eq!(list(&db, None, 10).unwrap().len(), 1);
    }

    #[test]
    fn the_table_is_added_to_existing_databases() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("rmail.db");
        crate::db::init_db(&db).unwrap();
        // A database from before feedback reports existed.
        crate::sqlite_pool::connection(&db)
            .unwrap()
            .execute_batch("DROP TABLE feedback_reports;")
            .unwrap();
        crate::db::init_db(&db).unwrap();
        crate::db::init_db(&db).unwrap();
        assert!(list(&db, None, 10).unwrap().is_empty());
    }

    #[test]
    fn metrics_count_each_type() {
        count_received("abuse");
        count_received("something-new");
        let mut out = String::new();
        render_metrics(&mut out);
        assert!(out.contains("rmail_feedback_reports_total{type=\"abuse\"}"));
        assert!(out.contains("rmail_feedback_reports_total{type=\"unknown\"}"));
    }
}
