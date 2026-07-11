use anyhow::{Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::AsyncStream;
use tokio::io::{AsyncWriteExt, BufReader};

#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct SelectedMailbox {
    pub(crate) domain: String,
    pub(crate) local: String,
    pub(crate) mailbox: String,
    pub(crate) uidvalidity: u64,
    pub(crate) uidnext: u64,
    pub(crate) highest_modseq: u64,
    pub(crate) read_only: bool,
    pub(crate) msgs: Vec<(u64, PathBuf, Vec<String>, u64)>,
    pub(crate) internal_dates: HashMap<u64, (i64, i32)>,
    pub(crate) save_dates: HashMap<u64, i64>,
    pub(crate) sizes: HashMap<u64, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MailboxSyncEvent {
    Exists(usize),
    Expunge {
        seq: usize,
        uid: u64,
    },
    FetchFlags {
        seq: usize,
        uid: u64,
        flags: Vec<String>,
    },
}

impl MailboxSyncEvent {
    pub(crate) fn response_line(&self, qresync_enabled: bool) -> String {
        match self {
            MailboxSyncEvent::Exists(count) => format!("* {} EXISTS\r\n", count),
            MailboxSyncEvent::Expunge { seq, uid } => {
                if qresync_enabled {
                    format!("* VANISHED {}\r\n", uid)
                } else {
                    format!("* {} EXPUNGE\r\n", seq)
                }
            }
            MailboxSyncEvent::FetchFlags { seq, uid, flags } => {
                format!(
                    "* {} FETCH (FLAGS ({}) UID {})\r\n",
                    seq,
                    flags.join(" "),
                    uid
                )
            }
        }
    }
}

pub(crate) async fn load_selected_mailbox(
    mail_root: &str,
    address: &str,
    mailbox: &str,
) -> Result<SelectedMailbox> {
    let at = address
        .find('@')
        .ok_or_else(|| anyhow!("invalid mailbox address"))?;
    let local = address[..at].to_string();
    let domain = address[at + 1..].to_string();
    let mail_root = mail_root.to_string();
    let domain_c = domain.clone();
    let local_c = local.clone();
    let mailbox = rmail_common::maildir::normalize_mailbox_name(mailbox)?;
    match tokio::task::spawn_blocking(move || {
        let (folder, state_msgs) = rmail_common::imap_state::load_folder(
            Path::new(&mail_root),
            &domain_c,
            &local_c,
            &mailbox,
        )?;
        let internal_dates = state_msgs
            .iter()
            .map(|message| (message.uid, (message.internaldate, message.internaldate_tz)))
            .collect();
        let save_dates = state_msgs
            .iter()
            .map(|message| (message.uid, message.save_date))
            .collect();
        let sizes = state_msgs
            .iter()
            .map(|message| (message.uid, message.size))
            .collect();
        let msgs = state_msgs
            .into_iter()
            .map(|message| (message.uid, message.path, message.flags, message.modseq))
            .collect();
        Ok(SelectedMailbox {
            domain: domain_c,
            local: local_c,
            mailbox,
            uidvalidity: folder.uidvalidity,
            uidnext: folder.uidnext,
            highest_modseq: folder.highest_modseq,
            read_only: false,
            msgs,
            internal_dates,
            save_dates,
            sizes,
        })
    })
    .await
    {
        Ok(Ok(sel)) => Ok(sel),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(anyhow!("task join error: {}", e)),
    }
}

pub(crate) async fn expunge_deleted(
    mail_root: &str,
    selected: &SelectedMailbox,
) -> Result<Vec<(usize, u64)>> {
    let mut deleted: Vec<(usize, u64)> = selected
        .msgs
        .iter()
        .enumerate()
        .filter_map(|(idx, (uid, _, flags, _))| {
            flags
                .iter()
                .any(|f| f.eq_ignore_ascii_case("\\Deleted"))
                .then_some((idx + 1, *uid))
        })
        .collect();
    deleted.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, uid) in &deleted {
        let mail_root = mail_root.to_string();
        let domain = selected.domain.clone();
        let local = selected.local.clone();
        let mailbox = selected.mailbox.clone();
        let uid = *uid;
        tokio::task::spawn_blocking(move || {
            rmail_common::maildir::delete_message_by_uid_for_mailbox(
                Path::new(&mail_root),
                &domain,
                &local,
                &mailbox,
                uid,
            )
        })
        .await??;
    }
    Ok(deleted)
}

pub(crate) async fn refresh_selected_mailbox(
    mail_root: &str,
    selected: &SelectedMailbox,
) -> Result<(SelectedMailbox, Vec<MailboxSyncEvent>)> {
    let address = format!("{}@{}", selected.local, selected.domain);
    let mut refreshed = load_selected_mailbox(mail_root, &address, &selected.mailbox).await?;
    refreshed.read_only = selected.read_only;
    let old_by_uid = selected
        .msgs
        .iter()
        .enumerate()
        .map(|(idx, (uid, _, flags, _))| (*uid, (idx + 1, flags.clone())))
        .collect::<HashMap<_, _>>();
    let new_by_uid = refreshed
        .msgs
        .iter()
        .enumerate()
        .map(|(idx, (uid, _, flags, _))| (*uid, (idx + 1, flags.clone())))
        .collect::<HashMap<_, _>>();

    let mut events = selected
        .msgs
        .iter()
        .enumerate()
        .filter_map(|(idx, (uid, _, _, _))| {
            (!new_by_uid.contains_key(uid)).then_some(MailboxSyncEvent::Expunge {
                seq: idx + 1,
                uid: *uid,
            })
        })
        .collect::<Vec<_>>();
    events.sort_by(|a, b| match (a, b) {
        (
            MailboxSyncEvent::Expunge { seq: left, .. },
            MailboxSyncEvent::Expunge { seq: right, .. },
        ) => right.cmp(left),
        _ => std::cmp::Ordering::Equal,
    });

    if refreshed.msgs.len() != selected.msgs.len() {
        events.push(MailboxSyncEvent::Exists(refreshed.msgs.len()));
    }

    for (uid, (new_seq, new_flags)) in &new_by_uid {
        if let Some((_old_seq, old_flags)) = old_by_uid.get(uid) {
            if old_flags != new_flags {
                events.push(MailboxSyncEvent::FetchFlags {
                    seq: *new_seq,
                    uid: *uid,
                    flags: new_flags.clone(),
                });
            }
        }
    }

    Ok((refreshed, events))
}

pub(crate) fn address_parts(address: &str) -> Result<(String, String)> {
    let at = address
        .find('@')
        .ok_or_else(|| anyhow!("invalid mailbox address"))?;
    Ok((address[..at].to_string(), address[at + 1..].to_string()))
}

pub(crate) fn selected_mailbox_name(selected: &Option<SelectedMailbox>) -> &str {
    selected
        .as_ref()
        .map(|s| s.mailbox.as_str())
        .unwrap_or("INBOX")
}

pub(crate) fn selected_mailbox_for_log(selected: &Option<SelectedMailbox>) -> &str {
    selected.as_ref().map(|s| s.mailbox.as_str()).unwrap_or("-")
}

pub(crate) fn next_uid(sel: &SelectedMailbox) -> u64 {
    sel.uidnext
}

pub(crate) fn first_unseen(sel: &SelectedMailbox) -> u64 {
    sel.msgs
        .iter()
        .enumerate()
        .find(|(_, (_, _, flags, _))| !flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen")))
        .map(|(idx, _)| idx as u64 + 1)
        .unwrap_or(0)
}

pub(crate) fn unseen_count(sel: &SelectedMailbox) -> usize {
    sel.msgs
        .iter()
        .filter(|(_, _, flags, _)| !flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen")))
        .count()
}

pub(crate) fn format_internal_date(timestamp: i64, timezone_offset_minutes: i32) -> String {
    use chrono::TimeZone;

    let offset_seconds = timezone_offset_minutes.saturating_mul(60);
    let offset = chrono::FixedOffset::east_opt(offset_seconds)
        .unwrap_or_else(|| chrono::FixedOffset::east_opt(0).expect("zero offset"));
    offset
        .timestamp_opt(timestamp, 0)
        .single()
        .unwrap_or_else(|| offset.timestamp_opt(0, 0).single().expect("Unix epoch"))
        .format("%d-%b-%Y %H:%M:%S %z")
        .to_string()
}

pub(crate) fn copy_uid_pairs(
    source_set: &[u64],
    destination_uids: &[u64],
    uidvalidity: u64,
) -> Option<String> {
    if source_set.is_empty() || destination_uids.is_empty() {
        None
    } else {
        let source = source_set
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let dest = destination_uids
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        Some(format!("[COPYUID {} {} {}] ", uidvalidity, source, dest))
    }
}

pub(crate) fn fetch_inner_spec(spec: &str) -> &str {
    let trimmed = spec.trim();
    trimmed
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(trimmed)
}

fn header_section_response_name(spec: &str) -> Option<String> {
    let inner = fetch_inner_spec(spec);
    let upper = inner.to_uppercase();
    let start = upper
        .find("BODY.PEEK[HEADER")
        .or_else(|| upper.find("BODY[HEADER"))?;
    let candidate = inner[start..].trim();
    let end = candidate.rfind(']')?;
    let mut section = candidate[..=end].to_string();
    if section.to_uppercase().starts_with("BODY.PEEK[") {
        section = format!("BODY[{}", &section["BODY.PEEK[".len()..]);
    }
    Some(section)
}

fn body_section_response_name(spec: &str) -> Option<String> {
    let inner = fetch_inner_spec(spec);
    let upper = inner.to_uppercase();
    let start = upper.find("BODY.PEEK[").or_else(|| upper.find("BODY["))?;
    if upper[start..].starts_with("BODY.PEEK[HEADER") || upper[start..].starts_with("BODY[HEADER") {
        return None;
    }
    let candidate = inner[start..].trim();
    let end = candidate.find(']')?;
    let section = &candidate[..=end];
    let mut name = if section.to_uppercase().starts_with("BODY.PEEK[") {
        format!("BODY[{}", &section["BODY.PEEK[".len()..])
    } else {
        section.to_string()
    };
    if let Some((offset, _count)) = partial_fetch_range(candidate) {
        name.push_str(&format!("<{}>", offset));
    }
    Some(name)
}

fn binary_section_response_name(spec: &str) -> Option<String> {
    let upper = spec.to_ascii_uppercase();
    let start = if upper.starts_with("BINARY.PEEK[") {
        "BINARY.PEEK[".len()
    } else if upper.starts_with("BINARY[") {
        "BINARY[".len()
    } else {
        return None;
    };
    let end = spec[start..].find(']')? + start;
    let mut name = format!("BINARY[{}]", &spec[start..end]);
    if let Some((offset, _)) = partial_fetch_range(spec) {
        name.push_str(&format!("<{}>", offset));
    }
    Some(name)
}

fn partial_fetch_range(section: &str) -> Option<(usize, usize)> {
    let start = section.find('<')?;
    let end = section[start + 1..].find('>')? + start + 1;
    let mut parts = section[start + 1..end].splitn(2, '.');
    let offset = parts.next()?.parse::<usize>().ok()?;
    let count = parts.next()?.parse::<usize>().ok()?;
    Some((offset, count))
}

pub(crate) fn body_after_header(data: &[u8]) -> &[u8] {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| &data[pos + 4..])
        .or_else(|| {
            data.windows(2)
                .position(|w| w == b"\n\n")
                .map(|pos| &data[pos + 2..])
        })
        .unwrap_or(data)
}

fn apply_partial_range(data: &[u8], range: Option<(usize, usize)>) -> Vec<u8> {
    let Some((offset, count)) = range else {
        return data.to_vec();
    };
    if offset >= data.len() {
        return Vec::new();
    }
    let end = offset.saturating_add(count).min(data.len());
    data[offset..end].to_vec()
}

fn requested_header_fields(spec: &str) -> Option<(Vec<String>, bool)> {
    let upper = spec.to_uppercase();
    let (marker, exclude) = if upper.contains("HEADER.FIELDS.NOT (") {
        ("HEADER.FIELDS.NOT (", true)
    } else {
        ("HEADER.FIELDS (", false)
    };
    let start = upper.find(marker)?;
    let after = &spec[start + marker.len()..];
    let end = after.find(')')?;
    let fields = after[..end]
        .split_whitespace()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    Some((fields, exclude))
}

fn extract_header_literal(data: &[u8], requested_fields: Option<(&[String], bool)>) -> Vec<u8> {
    let header_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
        .unwrap_or(data.len());
    let header = &data[..header_end];
    let Some((fields, exclude)) = requested_fields else {
        return header.to_vec();
    };
    if fields.is_empty() {
        return b"\r\n".to_vec();
    }

    let header_str = String::from_utf8_lossy(header);
    let mut out = String::new();
    let mut include_current = false;
    for line in header_str.split_inclusive("\r\n") {
        if line == "\r\n" {
            break;
        }
        let first = line.as_bytes().first().copied().unwrap_or_default();
        if first == b' ' || first == b'\t' {
            if include_current {
                out.push_str(line);
            }
            continue;
        }
        if let Some((name, _)) = line.split_once(':') {
            let matched = fields.iter().any(|f| f.eq_ignore_ascii_case(name.trim()));
            include_current = if exclude { !matched } else { matched };
            if include_current {
                out.push_str(line);
            }
        } else {
            include_current = false;
        }
    }
    out.push_str("\r\n");
    out.into_bytes()
}

fn read_message_header(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
        if let Some(pos) = out.windows(4).position(|w| w == b"\r\n\r\n") {
            out.truncate(pos + 4);
            break;
        }
        if out.len() > 256 * 1024 {
            break;
        }
    }
    Ok(out)
}

pub(crate) fn header_value(data: &[u8], field: &str) -> Option<String> {
    let header_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(data.len());
    let header = String::from_utf8_lossy(&data[..header_end]);
    for line in header.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case(field) {
            return Some(value.trim().replace(['\\', '"'], ""));
        }
    }
    None
}

fn nstring(value: Option<&str>) -> String {
    match value {
        Some(value) if !value.is_empty() => {
            format!("\"{}\"", value.replace(['\\', '"'], ""))
        }
        _ => "NIL".to_string(),
    }
}

fn parse_address(value: &str) -> Option<(Option<String>, String, String)> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (name, addr) = if let Some(start) = trimmed.rfind('<') {
        let end = trimmed[start + 1..]
            .find('>')
            .map(|pos| start + 1 + pos)
            .unwrap_or(trimmed.len());
        let display = trimmed[..start].trim().trim_matches('"').trim();
        let name = (!display.is_empty()).then(|| display.to_string());
        (name, trimmed[start + 1..end].trim())
    } else {
        (None, trimmed.trim_matches('"'))
    };
    let (mailbox, host) = addr.rsplit_once('@')?;
    if mailbox.is_empty() || host.is_empty() {
        return None;
    }
    Some((name, mailbox.to_string(), host.to_string()))
}

fn envelope_address_list(value: Option<String>) -> String {
    let Some(value) = value else {
        return "NIL".to_string();
    };
    let addresses = value
        .split(',')
        .filter_map(parse_address)
        .map(|(name, mailbox, host)| {
            format!(
                "({} NIL \"{}\" \"{}\")",
                nstring(name.as_deref()),
                mailbox.replace(['\\', '"'], ""),
                host.replace(['\\', '"'], "")
            )
        })
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        "NIL".to_string()
    } else {
        format!("({})", addresses.join(" "))
    }
}

fn envelope_response(data: &[u8]) -> String {
    let date = header_value(data, "Date").unwrap_or_default();
    let subject = header_value(data, "Subject").unwrap_or_default();
    let from = header_value(data, "From");
    let sender = header_value(data, "Sender").or_else(|| from.clone());
    let reply_to = header_value(data, "Reply-To").or_else(|| from.clone());
    let to = header_value(data, "To");
    let cc = header_value(data, "Cc");
    let bcc = header_value(data, "Bcc");
    let in_reply_to = header_value(data, "In-Reply-To");
    let message_id = header_value(data, "Message-ID");
    format!(
        "({} {} {} {} {} {} {} {} {} {})",
        nstring(Some(&date)),
        nstring(Some(&subject)),
        envelope_address_list(from),
        envelope_address_list(sender),
        envelope_address_list(reply_to),
        envelope_address_list(to),
        envelope_address_list(cc),
        envelope_address_list(bcc),
        nstring(in_reply_to.as_deref()),
        nstring(message_id.as_deref())
    )
}

fn parse_header_params(value: &str) -> (String, Vec<(String, String)>) {
    let mut parts = value.split(';');
    let main = parts
        .next()
        .unwrap_or("text/plain")
        .trim()
        .to_ascii_lowercase();
    let params = parts
        .filter_map(|part| {
            let (name, value) = part.split_once('=')?;
            let value = value.trim().trim_matches('"').to_string();
            Some((name.trim().to_ascii_uppercase(), value))
        })
        .collect();
    (main, params)
}

fn imap_param_list(params: &[(String, String)]) -> String {
    if params.is_empty() {
        "NIL".to_string()
    } else {
        let values = params
            .iter()
            .map(|(name, value)| format!("\"{}\" {}", name, nstring(Some(value))))
            .collect::<Vec<_>>();
        format!("({})", values.join(" "))
    }
}

fn content_type_parts(data: &[u8]) -> (String, String, Vec<(String, String)>) {
    let raw = header_value(data, "Content-Type").unwrap_or_else(|| "text/plain".to_string());
    let (main, params) = parse_header_params(&raw);
    let (typ, subtype) = main
        .split_once('/')
        .map(|(typ, subtype)| (typ.to_ascii_uppercase(), subtype.to_ascii_uppercase()))
        .unwrap_or_else(|| ("TEXT".to_string(), "PLAIN".to_string()));
    (typ, subtype, params)
}

fn content_disposition(data: &[u8]) -> String {
    let Some(raw) = header_value(data, "Content-Disposition") else {
        return "NIL".to_string();
    };
    let (disposition, params) = parse_header_params(&raw);
    format!(
        "({} {})",
        nstring(Some(&disposition.to_ascii_uppercase())),
        imap_param_list(&params)
    )
}

fn body_line_count(body: &[u8]) -> usize {
    if body.is_empty() {
        0
    } else {
        bytecount_newlines(body).max(1)
    }
}

fn bytecount_newlines(data: &[u8]) -> usize {
    data.iter().filter(|b| **b == b'\n').count()
}

fn multipart_boundary(params: &[(String, String)]) -> Option<String> {
    params
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("BOUNDARY"))
        .map(|(_, value)| value.clone())
}

fn split_multipart_parts(body: &[u8], boundary: &str) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(body);
    let marker = format!("--{}", boundary);
    let closing = format!("--{}--", boundary);
    let mut parts = Vec::new();
    let mut current = Vec::new();
    let mut in_part = false;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed == marker {
            if in_part && !current.is_empty() {
                parts.push(current.join("").into_bytes());
                current.clear();
            }
            in_part = true;
        } else if trimmed == closing {
            if in_part && !current.is_empty() {
                parts.push(current.join("").into_bytes());
            }
            break;
        } else if in_part {
            current.push(line);
        }
    }
    parts
}

#[derive(Debug, Clone)]
struct MimeNode {
    header: Vec<u8>,
    body: Vec<u8>,
    children: Vec<MimeNode>,
    embedded: Option<Box<MimeNode>>,
}

fn split_header_body(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        (data[..pos + 4].to_vec(), data[pos + 4..].to_vec())
    } else if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        (data[..pos + 2].to_vec(), data[pos + 2..].to_vec())
    } else {
        (data.to_vec(), Vec::new())
    }
}

fn parse_mime_tree(data: &[u8]) -> MimeNode {
    let (header, body) = split_header_body(data);
    let (typ, subtype, params) = content_type_parts(data);
    let children = if typ == "MULTIPART" {
        multipart_boundary(&params)
            .as_ref()
            .map(|boundary| {
                split_multipart_parts(&body, boundary)
                    .into_iter()
                    .map(|part| parse_mime_tree(&part))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let embedded =
        (typ == "MESSAGE" && subtype == "RFC822").then(|| Box::new(parse_mime_tree(&body)));
    MimeNode {
        header,
        body,
        children,
        embedded,
    }
}

fn parse_body_section(section_name: &str) -> Option<String> {
    let start = section_name.find('[')?;
    let end = section_name[start + 1..].find(']')? + start + 1;
    Some(section_name[start + 1..end].trim().to_ascii_uppercase())
}

fn locate_mime_part<'a>(root: &'a MimeNode, path: &[usize]) -> Option<&'a MimeNode> {
    let mut current = root;
    for (position, idx) in path.iter().enumerate() {
        if *idx == 0 {
            return None;
        }
        if current.children.is_empty() {
            if position == 0 && *idx == 1 {
                continue;
            }
            current = current.embedded.as_deref()?;
            if current.children.is_empty() {
                if *idx != 1 {
                    return None;
                }
            } else {
                current = current.children.get(idx - 1)?;
            }
        } else {
            current = current.children.get(idx - 1)?;
        }
    }
    Some(current)
}

fn extract_mime_section(data: &[u8], literal_name: &str) -> Vec<u8> {
    let Some(section) = parse_body_section(literal_name) else {
        return data.to_vec();
    };
    if section.is_empty() {
        return data.to_vec();
    }
    let root = parse_mime_tree(data);
    if section == "TEXT" {
        return root.body;
    }
    if section == "HEADER" || section == "MIME" {
        return root.header;
    }

    let mut path = Vec::new();
    let mut suffix = None;
    for segment in section.split('.') {
        if let Ok(idx) = segment.parse::<usize>() {
            path.push(idx);
        } else {
            suffix = Some(segment);
            break;
        }
    }
    let Some(part) = locate_mime_part(&root, &path) else {
        return Vec::new();
    };
    match suffix {
        Some("MIME") => part.header.clone(),
        Some("HEADER") => part
            .embedded
            .as_deref()
            .map(|embedded| embedded.header.clone())
            .unwrap_or_else(|| part.header.clone()),
        Some("TEXT") => part
            .embedded
            .as_deref()
            .map(|embedded| embedded.body.clone())
            .unwrap_or_else(|| part.body.clone()),
        Some(_) => Vec::new(),
        None => part.body.clone(),
    }
}

fn decode_quoted_printable(input: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] != b'=' {
            output.push(input[index]);
            index += 1;
            continue;
        }
        if input.get(index + 1..index + 3) == Some(b"\r\n") {
            index += 3;
            continue;
        }
        if input.get(index + 1) == Some(&b'\n') {
            index += 2;
            continue;
        }
        let hex = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        output.push((hex(*input.get(index + 1)?)? << 4) | hex(*input.get(index + 2)?)?);
        index += 3;
    }
    Some(output)
}

fn decode_transfer_encoding(part: &MimeNode) -> Option<Vec<u8>> {
    let encoding = header_value(&part.header, "Content-Transfer-Encoding")
        .unwrap_or_else(|| "7BIT".to_string())
        .to_ascii_uppercase();
    match encoding.as_str() {
        "7BIT" | "8BIT" | "BINARY" => Some(part.body.clone()),
        "BASE64" => {
            let compact = part
                .body
                .iter()
                .copied()
                .filter(|byte| !byte.is_ascii_whitespace())
                .collect::<Vec<_>>();
            BASE64_ENGINE.decode(compact).ok()
        }
        "QUOTED-PRINTABLE" => decode_quoted_printable(&part.body),
        _ => None,
    }
}

fn extract_binary_section(data: &[u8], item: &str) -> Option<Vec<u8>> {
    let section = parse_body_section(item)?;
    let root = parse_mime_tree(data);
    let path = if section.is_empty() {
        Vec::new()
    } else {
        section
            .split('.')
            .map(|segment| segment.parse::<usize>().ok())
            .collect::<Option<Vec<_>>>()?
    };
    decode_transfer_encoding(locate_mime_part(&root, &path)?)
}

fn bodystructure_response(data: &[u8]) -> String {
    let (typ, subtype, params) = content_type_parts(data);
    let body = body_after_header(data);
    if typ == "MULTIPART" {
        let boundary = multipart_boundary(&params);
        let parts = boundary
            .as_ref()
            .map(|boundary| split_multipart_parts(body, boundary))
            .unwrap_or_default();
        if parts.is_empty() {
            return format!("(\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" {} 0)", body.len());
        }
        let children = parts
            .iter()
            .map(|part| bodystructure_response(part))
            .collect::<Vec<_>>()
            .join(" ");
        return format!(
            "({} \"{}\" {} NIL NIL)",
            children,
            subtype,
            imap_param_list(&params)
        );
    }

    let encoding = header_value(data, "Content-Transfer-Encoding")
        .unwrap_or_else(|| "7BIT".to_string())
        .to_ascii_uppercase();
    let content_id = header_value(data, "Content-ID");
    let description = header_value(data, "Content-Description");
    let disposition = content_disposition(data);
    if typ == "MESSAGE" && subtype == "RFC822" {
        return format!(
            "(\"MESSAGE\" \"RFC822\" {} {} {} {} {} {} {} {} NIL {} NIL)",
            imap_param_list(&params),
            nstring(content_id.as_deref()),
            nstring(description.as_deref()),
            nstring(Some(&encoding)),
            body.len(),
            envelope_response(body),
            bodystructure_response(body),
            body_line_count(body),
            disposition
        );
    }
    if typ == "TEXT" {
        format!(
            "(\"TEXT\" \"{}\" {} {} {} {} {} {} NIL {} NIL)",
            subtype,
            imap_param_list(&params),
            nstring(content_id.as_deref()),
            nstring(description.as_deref()),
            nstring(Some(&encoding)),
            body.len(),
            body_line_count(body),
            disposition
        )
    } else {
        format!(
            "(\"{}\" \"{}\" {} {} {} {} {} NIL {} NIL)",
            typ,
            subtype,
            imap_param_list(&params),
            nstring(content_id.as_deref()),
            nstring(description.as_deref()),
            nstring(Some(&encoding)),
            body.len(),
            disposition
        )
    }
}

pub(crate) async fn write_fetch_response(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    seq: usize,
    uid: u64,
    flags: &[String],
    modseq: u64,
    internal_date: (i64, i32),
    save_date: i64,
    path: PathBuf,
    requested: &[String],
    _raw_spec: &str,
    force_uid: bool,
) -> Result<()> {
    let include_uid = force_uid || requested.iter().any(|i| i == "UID");
    let include_flags = requested.iter().any(|i| i == "FLAGS");
    let include_modseq = requested.iter().any(|i| i == "MODSEQ");
    let include_size = requested.iter().any(|i| i == "RFC822.SIZE");
    let include_internaldate = requested.iter().any(|i| i == "INTERNALDATE");
    let include_savedate = requested.iter().any(|i| i == "SAVEDATE");
    let literal_items = requested
        .iter()
        .filter(|item| {
            matches!(item.as_str(), "RFC822" | "RFC822.HEADER" | "RFC822.TEXT")
                || item.starts_with("BODY[")
                || item.starts_with("BODY.PEEK[")
                || item.starts_with("BINARY[")
                || item.starts_with("BINARY.PEEK[")
        })
        .collect::<Vec<_>>();
    let binary_size_items = requested
        .iter()
        .filter(|item| item.starts_with("BINARY.SIZE["))
        .collect::<Vec<_>>();
    let include_envelope = requested.iter().any(|i| i == "ENVELOPE");
    let include_bodystructure = requested
        .iter()
        .any(|i| i == "BODYSTRUCTURE" || i == "BODY");
    let need_data = include_size
        || !literal_items.is_empty()
        || !binary_size_items.is_empty()
        || include_envelope
        || include_bodystructure;
    let internal_date =
        include_internaldate.then(|| format_internal_date(internal_date.0, internal_date.1));
    let metadata_len = if include_size || include_bodystructure {
        Some(
            tokio::task::spawn_blocking({
                let path = path.clone();
                move || std::fs::metadata(path).map(|m| m.len() as usize)
            })
            .await??,
        )
    } else {
        None
    };
    let data =
        if !literal_items.is_empty() || !binary_size_items.is_empty() || include_bodystructure {
            Some(tokio::task::spawn_blocking(move || std::fs::read(path)).await??)
        } else if include_envelope {
            Some(tokio::task::spawn_blocking(move || read_message_header(&path)).await??)
        } else if need_data {
            Some(Vec::new())
        } else {
            None
        };

    let mut attrs: Vec<String> = Vec::new();
    if include_flags {
        attrs.push(format!("FLAGS ({})", flags.join(" ")));
    }
    if include_uid {
        attrs.push(format!("UID {}", uid));
    }
    if include_modseq {
        attrs.push(format!("MODSEQ ({})", modseq));
    }
    if include_size {
        let len = metadata_len
            .or_else(|| data.as_ref().map(|d| d.len()))
            .unwrap_or(0);
        attrs.push(format!("RFC822.SIZE {}", len));
    }
    if include_internaldate {
        attrs.push(format!(
            "INTERNALDATE \"{}\"",
            internal_date.unwrap_or_default()
        ));
    }
    if include_savedate {
        attrs.push(format!(
            "SAVEDATE \"{}\"",
            format_internal_date(save_date, 0)
        ));
    }
    for item in binary_size_items {
        match extract_binary_section(data.as_deref().unwrap_or_default(), item) {
            Some(decoded) => attrs.push(format!("{} {}", item, decoded.len())),
            None => attrs.push(format!("{} NIL", item)),
        }
    }
    if include_envelope {
        attrs.push(format!(
            "ENVELOPE {}",
            envelope_response(data.as_deref().unwrap_or_default())
        ));
    }
    if include_bodystructure {
        attrs.push(format!(
            "BODYSTRUCTURE {}",
            bodystructure_response(data.as_deref().unwrap_or_default())
        ));
    }

    let w = reader.get_mut();
    if literal_items.is_empty() {
        w.write_all(format!("* {} FETCH ({})\r\n", seq, attrs.join(" ")).as_bytes())
            .await?;
        w.flush().await?;
        return Ok(());
    }

    let mut prefix = format!("* {} FETCH (", seq);
    if !attrs.is_empty() {
        prefix.push_str(&attrs.join(" "));
        prefix.push(' ');
    }
    let data = data.unwrap_or_default();
    w.write_all(prefix.as_bytes()).await?;
    for (index, item) in literal_items.iter().enumerate() {
        if index != 0 {
            w.write_all(b" ").await?;
        }
        let response_name = if item.starts_with("BINARY.PEEK[") {
            binary_section_response_name(item).unwrap_or_else(|| (*item).clone())
        } else if item.starts_with("BINARY[") {
            binary_section_response_name(item).unwrap_or_else(|| (*item).clone())
        } else if item.starts_with("BODY[HEADER") || item.starts_with("BODY.PEEK[HEADER") {
            header_section_response_name(item).unwrap_or_else(|| (*item).clone())
        } else if item.starts_with("BODY[") || item.starts_with("BODY.PEEK[") {
            body_section_response_name(item).unwrap_or_else(|| (*item).clone())
        } else {
            (*item).clone()
        };
        let partial = partial_fetch_range(fetch_inner_spec(item));
        let literal = if item.starts_with("BINARY[") || item.starts_with("BINARY.PEEK[") {
            extract_binary_section(&data, item)
                .map(|decoded| apply_partial_range(&decoded, partial))
        } else if *item == "RFC822.HEADER" {
            Some(extract_header_literal(&data, None))
        } else if *item == "RFC822.TEXT" {
            Some(body_after_header(&data).to_vec())
        } else if *item == "RFC822" {
            Some(data.clone())
        } else if item.starts_with("BODY[HEADER") || item.starts_with("BODY.PEEK[HEADER") {
            let fields = requested_header_fields(item);
            Some(extract_header_literal(
                &data,
                fields
                    .as_ref()
                    .map(|(fields, exclude)| (fields.as_slice(), *exclude)),
            ))
        } else {
            Some(apply_partial_range(
                &extract_mime_section(&data, &response_name),
                partial,
            ))
        };
        let Some(literal) = literal else {
            w.write_all(format!("{} NIL", response_name).as_bytes())
                .await?;
            continue;
        };
        let marker = if item.starts_with("BINARY[") || item.starts_with("BINARY.PEEK[") {
            "~"
        } else {
            ""
        };
        w.write_all(format!("{} {}{{{}}}\r\n", response_name, marker, literal.len()).as_bytes())
            .await?;
        w.write_all(&literal).await?;
    }
    w.write_all(b"\r\n)\r\n").await?;
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{bodystructure_response, extract_binary_section, extract_mime_section};

    const EMBEDDED_MESSAGE: &[u8] = b"From: outer@example.test\r\n\
Content-Type: multipart/mixed; boundary=outer\r\n\r\n\
--outer\r\nContent-Type: text/plain\r\n\r\nfirst\r\n\
--outer\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment; filename=forwarded.eml\r\n\r\n\
From: inner@example.test\r\nTo: recipient@example.test\r\nSubject: forwarded\r\n\
Content-Type: multipart/alternative; boundary=inner\r\n\r\n\
--inner\r\nContent-Type: text/plain\r\n\r\ninner plain\r\n\
--inner\r\nContent-Type: text/html\r\n\r\n<p>inner html</p>\r\n\
--inner--\r\n--outer--\r\n";

    #[test]
    fn message_rfc822_sections_distinguish_outer_mime_and_embedded_message() {
        let mime = extract_mime_section(EMBEDDED_MESSAGE, "BODY[2.MIME]");
        assert!(String::from_utf8_lossy(&mime).contains("Content-Type: message/rfc822"));
        assert!(!String::from_utf8_lossy(&mime).contains("Subject: forwarded"));

        let header = extract_mime_section(EMBEDDED_MESSAGE, "BODY[2.HEADER]");
        assert!(String::from_utf8_lossy(&header).contains("Subject: forwarded"));
        assert!(!String::from_utf8_lossy(&header).contains("inner plain"));

        let text = extract_mime_section(EMBEDDED_MESSAGE, "BODY[2.TEXT]");
        assert!(String::from_utf8_lossy(&text).contains("--inner"));
        assert!(!String::from_utf8_lossy(&text).contains("Subject: forwarded"));

        assert_eq!(
            extract_mime_section(EMBEDDED_MESSAGE, "BODY[2.1]"),
            b"inner plain\r\n"
        );
        assert_eq!(
            extract_mime_section(EMBEDDED_MESSAGE, "BODY[2.2]"),
            b"<p>inner html</p>\r\n"
        );
    }

    #[test]
    fn message_rfc822_bodystructure_contains_envelope_child_and_line_count() {
        let structure = bodystructure_response(EMBEDDED_MESSAGE);
        assert!(structure.contains("\"MESSAGE\" \"RFC822\""));
        assert!(structure.contains("\"forwarded\""));
        assert!(structure.contains("\"ALTERNATIVE\""));
        assert!(structure.contains("\"ATTACHMENT\" (\"FILENAME\" \"forwarded.eml\")"));
    }

    #[test]
    fn binary_sections_decode_transfer_encodings_and_reject_malformed_data() {
        let message = b"Content-Type: multipart/mixed; boundary=x\r\n\r\n\
--x\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8Ad29ybGQ=\r\n\
--x\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nline=20one=0Asoft=\r\nbreak\r\n\
--x\r\nContent-Transfer-Encoding: base64\r\n\r\n%%%\r\n--x--\r\n";
        assert_eq!(
            extract_binary_section(message, "BINARY[1]"),
            Some(b"hello\0world".to_vec())
        );
        assert_eq!(
            extract_binary_section(message, "BINARY.SIZE[1]").map(|decoded| decoded.len()),
            Some(11)
        );
        assert_eq!(
            extract_binary_section(message, "BINARY[2]"),
            Some(b"line one\nsoftbreak\r\n".to_vec())
        );
        assert_eq!(extract_binary_section(message, "BINARY[3]"), None);
        assert_eq!(extract_binary_section(message, "BINARY[0]"), None);
    }
}
