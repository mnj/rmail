//! Parsing stored messages: headers (RFC 2047), MIME multipart bodies,
//! transfer encodings, inline images, and sanitizing HTML for the webmail
//! reader. Shared by webmail and the mail classifier.

use std::collections::{BTreeMap, HashMap};

use base64::Engine;
use serde::Serialize;

/// Nested multipart levels followed; deeper parts are ignored.
const MAX_DEPTH: usize = 12;

#[derive(Default)]
pub struct ParsedMessage {
    pub from: String,
    pub to: String,
    pub cc: String,
    pub reply_to: String,
    pub subject: String,
    pub date: String,
    pub list_id: String,
    pub message_id: String,
    pub in_reply_to: String,
    pub references: String,
    pub text_body: String,
    pub html_body: Option<String>,
    pub inline_images: HashMap<String, String>,
    pub attachments: Vec<Attachment>,
}

/// A part of the message offered for download.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Attachment {
    /// Position among the message's leaf parts; stable for a given message.
    pub index: usize,
    pub filename: String,
    /// Lower-case `type/subtype`.
    pub content_type: String,
    /// Decoded size in bytes.
    pub size: usize,
    /// `Content-Disposition: inline` (shown in the body by some clients).
    pub inline: bool,
}

/// A non-multipart part: its headers and still-encoded body.
struct Leaf<'a> {
    headers: HashMap<String, String>,
    body: &'a [u8],
}

impl Leaf<'_> {
    fn content_type(&self) -> String {
        self.headers
            .get("content-type")
            .and_then(|value| value.split(';').next())
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| value.contains('/'))
            .unwrap_or_else(|| "text/plain".to_string())
    }

    fn param(&self, header: &str, name: &str) -> Option<String> {
        self.headers
            .get(header)
            .and_then(|value| header_params(value).remove(name))
    }

    fn disposition(&self) -> String {
        self.headers
            .get("content-disposition")
            .and_then(|value| value.split(';').next())
            .map(|value| value.trim().to_ascii_lowercase())
            .unwrap_or_default()
    }

    fn filename(&self) -> Option<String> {
        self.param("content-disposition", "filename")
            .or_else(|| self.param("content-type", "name"))
            .map(|name| sanitize_filename(&name))
            .filter(|name| !name.is_empty())
    }

    fn decoded(&self) -> Vec<u8> {
        let encoding = self
            .headers
            .get("content-transfer-encoding")
            .map(|value| value.trim().to_ascii_lowercase())
            .unwrap_or_default();
        decode_transfer_bytes(self.body, &encoding)
    }

    fn text(&self) -> String {
        decode_charset(
            &self.decoded(),
            self.param("content-type", "charset").as_deref(),
        )
    }
}

pub fn parse_message(bytes: &[u8]) -> ParsedMessage {
    let (head, body) = split_head(bytes);
    let headers = parse_headers(head);
    let mut parsed = ParsedMessage::default();
    let get = |name: &str| headers.get(name).cloned().unwrap_or_default();
    parsed.from = get("from");
    parsed.to = get("to");
    parsed.cc = get("cc");
    parsed.reply_to = get("reply-to");
    parsed.subject = get("subject");
    parsed.date = get("date");
    parsed.list_id = get("list-id");
    parsed.message_id = get("message-id");
    parsed.in_reply_to = get("in-reply-to");
    parsed.references = get("references");

    let mut parts = Vec::new();
    collect_leaves(headers, body, 0, &mut parts);
    let mut text = None;
    let mut html = None;
    for (index, part) in parts.iter().enumerate() {
        let content_type = part.content_type();
        let disposition = part.disposition();
        let filename = part.filename();
        let body_candidate = disposition != "attachment" && filename.is_none();
        if body_candidate && content_type == "text/plain" && text.is_none() {
            text = Some(part.text());
        } else if body_candidate && content_type == "text/html" && html.is_none() {
            html = Some(part.text());
        } else if content_type.starts_with("image/")
            && disposition != "attachment"
            && let Some(cid) = part.headers.get("content-id")
        {
            let cid = cid.trim().trim_matches(['<', '>']).to_string();
            parsed.inline_images.insert(
                cid,
                format!(
                    "data:{content_type};base64,{}",
                    base64::engine::general_purpose::STANDARD.encode(part.decoded())
                ),
            );
        } else {
            let decoded_len = part.decoded().len();
            if decoded_len == 0 && filename.is_none() {
                continue;
            }
            parsed.attachments.push(Attachment {
                index,
                filename: filename.unwrap_or_else(|| default_filename(&content_type, index)),
                content_type,
                size: decoded_len,
                inline: disposition == "inline",
            });
        }
    }
    parsed.text_body = text
        .unwrap_or_else(|| html.as_deref().map(strip_html).unwrap_or_default())
        .trim()
        .to_string();
    parsed.html_body = html.map(|html| apply_inline_images(html.trim(), &parsed.inline_images));
    parsed
}

/// The decoded bytes of attachment `index` (see [`Attachment::index`]).
pub fn attachment_data(bytes: &[u8], index: usize) -> Option<(Attachment, Vec<u8>)> {
    parse_message(bytes)
        .attachments
        .into_iter()
        .find(|attachment| attachment.index == index)
        .and_then(|attachment| {
            let (head, body) = split_head(bytes);
            let mut parts = Vec::new();
            collect_leaves(parse_headers(head), body, 0, &mut parts);
            parts.get(index).map(|part| (attachment, part.decoded()))
        })
}

/// A file name safe to offer for download: no directories or control
/// characters, at most 200 characters.
fn sanitize_filename(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    base.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .trim_start_matches('.')
        .chars()
        .take(200)
        .collect()
}

fn default_filename(content_type: &str, index: usize) -> String {
    let extension = match content_type {
        "message/rfc822" => "eml",
        "text/calendar" => "ics",
        "application/pdf" => "pdf",
        "text/plain" => "txt",
        "text/html" => "html",
        other => other.rsplit('/').next().unwrap_or("bin"),
    };
    format!("attachment-{}.{extension}", index + 1)
}

/// Split at the first empty line (CRLF or LF).
fn split_head(bytes: &[u8]) -> (&[u8], &[u8]) {
    let crlf = find(bytes, b"\r\n\r\n").map(|i| (i, 4));
    let lf = find(bytes, b"\n\n").map(|i| (i, 2));
    match (crlf, lf) {
        (Some(a), Some(b)) => {
            let (i, n) = if a.0 <= b.0 { a } else { b };
            (&bytes[..i], &bytes[i + n..])
        }
        (Some((i, n)), None) | (None, Some((i, n))) => (&bytes[..i], &bytes[i + n..]),
        (None, None) => (bytes, &[]),
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn collect_leaves<'a>(
    headers: HashMap<String, String>,
    body: &'a [u8],
    depth: usize,
    out: &mut Vec<Leaf<'a>>,
) {
    let content_type = headers.get("content-type").cloned().unwrap_or_default();
    if content_type
        .trim()
        .to_ascii_lowercase()
        .starts_with("multipart/")
        && depth < MAX_DEPTH
        && let Some(boundary) = header_params(&content_type).remove("boundary")
    {
        for part in split_multipart(body, boundary.as_bytes()) {
            let (head, body) = split_head(part);
            collect_leaves(parse_headers(head), body, depth + 1, out);
        }
        return;
    }
    out.push(Leaf { headers, body });
}

/// The parts between `--boundary` delimiter lines, up to `--boundary--`.
fn split_multipart<'a>(body: &'a [u8], boundary: &[u8]) -> Vec<&'a [u8]> {
    let mut delimiter = b"--".to_vec();
    delimiter.extend_from_slice(boundary);
    let mut parts = Vec::new();
    let mut part_start: Option<usize> = None;
    let mut line_start = 0;
    while line_start < body.len() {
        let line_end = body[line_start..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(body.len(), |i| line_start + i + 1);
        let line = &body[line_start..line_end];
        if line.starts_with(&delimiter) {
            if let Some(start) = part_start {
                let mut end = line_start;
                if end > start && body[end - 1] == b'\n' {
                    end -= 1;
                }
                if end > start && body[end - 1] == b'\r' {
                    end -= 1;
                }
                parts.push(&body[start..end.max(start)]);
            }
            if line[delimiter.len()..].starts_with(b"--") {
                return parts;
            }
            part_start = Some(line_end);
        }
        line_start = line_end;
    }
    // A missing closing delimiter still yields the last part.
    if let Some(start) = part_start
        && start < body.len()
    {
        parts.push(&body[start..]);
    }
    parts
}

fn parse_headers(head: &[u8]) -> HashMap<String, String> {
    let text = String::from_utf8_lossy(head);
    let mut out = HashMap::new();
    let mut current_name: Option<String> = None;
    let mut current_value = String::new();
    for line in text.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if !current_value.is_empty() {
                current_value.push(' ');
            }
            current_value.push_str(line.trim());
            continue;
        }
        if let Some(name) = current_name.take() {
            out.entry(name)
                .or_insert_with(|| decode_rfc2047_words(current_value.trim()));
            current_value.clear();
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        current_name = Some(name.trim().to_ascii_lowercase());
        current_value.push_str(value.trim());
    }
    if let Some(name) = current_name {
        out.entry(name)
            .or_insert_with(|| decode_rfc2047_words(current_value.trim()));
    }
    out
}

/// Parameters of a structured header (`type/sub; a=1; b="x;y"`), with names
/// lower-cased, quotes removed, and RFC 2231 extended and continued values
/// (`name*=utf-8''..`, `name*0*=..`) decoded.
fn header_params(value: &str) -> HashMap<String, String> {
    let mut raw: Vec<(String, String)> = Vec::new();
    let mut rest = match value.find(';') {
        Some(i) => &value[i + 1..],
        None => return HashMap::new(),
    };
    while !rest.trim().is_empty() {
        let Some(eq) = rest.find('=') else {
            break;
        };
        let name = rest[..eq]
            .trim()
            .trim_start_matches(';')
            .trim()
            .to_ascii_lowercase();
        let after = rest[eq + 1..].trim_start();
        let (val, next) = if let Some(quoted) = after.strip_prefix('"') {
            let mut out = String::new();
            let mut chars = quoted.char_indices();
            let mut end = quoted.len();
            while let Some((i, c)) = chars.next() {
                match c {
                    '\\' => {
                        if let Some((_, escaped)) = chars.next() {
                            out.push(escaped);
                        }
                    }
                    '"' => {
                        end = i + 1;
                        break;
                    }
                    _ => out.push(c),
                }
            }
            let remainder = &quoted[end.min(quoted.len())..];
            (out, remainder.find(';').map_or("", |i| &remainder[i + 1..]))
        } else {
            match after.find(';') {
                Some(i) => (after[..i].trim().to_string(), &after[i + 1..]),
                None => (after.trim().to_string(), ""),
            }
        };
        if !name.is_empty() {
            raw.push((name, val));
        }
        rest = next;
    }

    let mut params = HashMap::new();
    let mut continued: BTreeMap<String, BTreeMap<u32, (bool, String)>> = BTreeMap::new();
    for (name, value) in raw {
        let (base, extended) = match name.strip_suffix('*') {
            Some(base) => (base.to_string(), true),
            None => (name.clone(), false),
        };
        if let Some((stem, n)) = base.rsplit_once('*')
            && let Ok(n) = n.parse::<u32>()
        {
            continued
                .entry(stem.to_string())
                .or_default()
                .insert(n, (extended, value));
            continue;
        }
        let value = if extended {
            decode_rfc2231(&value, None)
        } else {
            value
        };
        params.insert(base, value);
    }
    for (name, pieces) in continued {
        // The charset is given on the first extended piece only.
        let mut charset = None;
        let mut bytes = Vec::new();
        for (n, (extended, value)) in pieces {
            if extended {
                let encoded = if n == 0 {
                    let mut fields = value.splitn(3, '\'');
                    match (fields.next(), fields.next(), fields.next()) {
                        (Some(cs), Some(_), Some(text)) => {
                            charset = Some(cs.to_string());
                            text.to_string()
                        }
                        _ => value,
                    }
                } else {
                    value
                };
                bytes.extend(percent_decode(&encoded));
            } else {
                bytes.extend(value.into_bytes());
            }
        }
        params
            .entry(name)
            .or_insert_with(|| decode_charset(&bytes, charset.as_deref()));
    }
    params
}

/// `charset'lang'percent-encoded` (RFC 2231).
fn decode_rfc2231(value: &str, charset: Option<&str>) -> String {
    let mut fields = value.splitn(3, '\'');
    match (fields.next(), fields.next(), fields.next()) {
        (Some(cs), Some(_), Some(text)) => decode_charset(&percent_decode(text), Some(cs)),
        _ => decode_charset(&percent_decode(value), charset),
    }
}

fn percent_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len() + 1
            && let (Some(hi), Some(lo)) = (
                bytes.get(i + 1).and_then(|b| hex_val(*b)),
                bytes.get(i + 2).and_then(|b| hex_val(*b)),
            )
        {
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

/// Text in `charset` (any label encoding_rs knows; UTF-8 when absent or
/// unknown), with malformed sequences replaced.
fn decode_charset(bytes: &[u8], charset: Option<&str>) -> String {
    let encoding = charset
        .and_then(|label| encoding_rs::Encoding::for_label(label.trim().as_bytes()))
        .unwrap_or(encoding_rs::UTF_8);
    encoding.decode(bytes).0.into_owned()
}

fn decode_transfer_bytes(input: &[u8], encoding: &str) -> Vec<u8> {
    if encoding.contains("quoted-printable") {
        decode_quoted_printable(input)
    } else if encoding.contains("base64") {
        let compact: Vec<u8> = input
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(&compact)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&compact))
            .unwrap_or_else(|_| input.to_vec())
    } else {
        input.to_vec()
    }
}

fn apply_inline_images(html: &str, inline_images: &HashMap<String, String>) -> String {
    let mut out = html.to_string();
    for (cid, data_url) in inline_images {
        out = out.replace(&format!("cid:{cid}"), data_url);
        out = out.replace(&format!("cid:<{cid}>"), data_url);
    }
    out
}

fn decode_quoted_printable(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'=' {
            if input.get(i + 1) == Some(&b'\r') && input.get(i + 2) == Some(&b'\n') {
                i += 3;
                continue;
            }
            if input.get(i + 1) == Some(&b'\n') {
                i += 2;
                continue;
            }
            if i + 2 < input.len()
                && let (Some(hi), Some(lo)) = (hex_val(input[i + 1]), hex_val(input[i + 2]))
            {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// RFC 2047 encoded words in any charset. Whitespace between adjacent
/// encoded words is dropped, as the RFC requires.
fn decode_rfc2047_words(input: &str) -> String {
    let mut out = String::new();
    let mut rest = input;
    let mut last_was_word = false;
    while let Some(start) = rest.find("=?") {
        let gap = &rest[..start];
        if !(last_was_word && gap.trim().is_empty()) {
            out.push_str(gap);
        }
        let after_start = &rest[start + 2..];
        let Some(charset_end) = after_start.find('?') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let charset = after_start[..charset_end]
            .split('*')
            .next()
            .unwrap_or_default();
        let after_charset = &after_start[charset_end + 1..];
        let Some(enc_end) = after_charset.find('?') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let encoding = &after_charset[..enc_end];
        let after_encoding = &after_charset[enc_end + 1..];
        let Some(data_end) = after_encoding.find("?=") else {
            out.push_str(&rest[start..]);
            return out;
        };
        let data = &after_encoding[..data_end];
        let bytes = if encoding.eq_ignore_ascii_case("q") {
            Some(decode_quoted_printable(data.replace('_', " ").as_bytes()))
        } else if encoding.eq_ignore_ascii_case("b") {
            base64::engine::general_purpose::STANDARD.decode(data).ok()
        } else {
            None
        };
        match bytes {
            Some(bytes) => out.push_str(&decode_charset(&bytes, Some(charset))),
            None => out.push_str(data),
        }
        last_was_word = true;
        rest = &after_encoding[data_end + 2..];
    }
    out.push_str(rest);
    out
}

fn strip_html(input: &str) -> String {
    let input = remove_html_block(input, "head");
    let input = remove_html_block(&input, "style");
    let input = remove_html_block(&input, "script");
    let input = remove_html_block(&input, "noscript");
    let input = remove_html_comments(&input);
    let mut out = String::new();
    let mut in_tag = false;
    let mut last_was_space = false;
    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                if !last_was_space {
                    out.push(' ');
                    last_was_space = true;
                }
            }
            _ if !in_tag => {
                if ch.is_whitespace() {
                    if !last_was_space {
                        out.push(' ');
                        last_was_space = true;
                    }
                } else {
                    out.push(ch);
                    last_was_space = false;
                }
            }
            _ => {}
        }
    }
    html_unescape(&out).trim().to_string()
}

fn remove_html_block(input: &str, tag: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    loop {
        let lower = rest.to_ascii_lowercase();
        let Some(start) = lower.find(&open) else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..start]);
        let after_open = &rest[start..];
        let lower_after = &lower[start..];
        if let Some(end) = lower_after.find(&close) {
            rest = &after_open[end + close.len()..];
        } else {
            break;
        }
    }
    out
}

fn remove_html_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    loop {
        let Some(start) = rest.find("<!--") else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..start]);
        let after = &rest[start + 4..];
        if let Some(end) = after.find("-->") {
            rest = &after[end + 3..];
        } else {
            break;
        }
    }
    out
}

pub fn has_remote_content(html: &str) -> bool {
    let lower = html.to_ascii_lowercase();
    [
        "src=\"http",
        "src='http",
        "src=http",
        "src=\"//",
        "src='//",
        "url(http",
        "url('http",
        "url(\"http",
        "url(//",
        "background=\"http",
        "srcset=\"http",
        "@import",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// Content policy for a rendered message. Remote images, fonts and styles are
/// blocked by default so opening a message cannot be tracked.
fn message_csp(allow_remote_content: bool) -> &'static str {
    if allow_remote_content {
        "default-src 'none'; img-src data: cid: https: http:; style-src 'unsafe-inline' https: http:; font-src data: https: http:"
    } else {
        "default-src 'none'; img-src data: cid:; style-src 'unsafe-inline'; font-src data:"
    }
}

pub fn sanitize_email_html(input: &str, allow_remote_content: bool) -> String {
    let input = remove_html_block(input, "script");
    let input = remove_html_block(&input, "iframe");
    let input = remove_html_block(&input, "object");
    let input = remove_html_block(&input, "embed");
    let input = remove_html_comments(&input);
    let mut out = String::with_capacity(input.len() + 128);
    let mut rest = input.as_str();
    while let Some(start) = rest.find('<') {
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        let Some(end) = after.find('>') else {
            break;
        };
        let tag = &after[..=end];
        out.push_str(&sanitize_html_tag(tag));
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    format!(
        r#"<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="{}"><base target="_blank"><style>html,body{{margin:0;padding:0;background:#fff;color:#222831;font:14px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;overflow-wrap:anywhere}}img{{max-width:100%;height:auto}}table{{max-width:100%;border-collapse:collapse}}a{{color:#276ef1}}</style></head><body>{}</body></html>"#,
        message_csp(allow_remote_content),
        out
    )
}

fn sanitize_html_tag(tag: &str) -> String {
    let lower = tag.to_ascii_lowercase();
    if lower.starts_with("<script")
        || lower.starts_with("</script")
        || lower.starts_with("<iframe")
        || lower.starts_with("</iframe")
        || lower.starts_with("<object")
        || lower.starts_with("</object")
        || lower.starts_with("<embed")
        || lower.starts_with("</embed")
        || lower.starts_with("<meta")
        || lower.starts_with("<link")
    {
        return String::new();
    }

    let mut cleaned = String::with_capacity(tag.len());
    let bytes = tag.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            let attr_start = i;
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            let name_start = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'-' || bytes[i] == b':')
            {
                i += 1;
            }
            let name = tag[name_start..i].to_ascii_lowercase();
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'=' {
                i += 1;
                while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                    let quote = bytes[i];
                    i += 1;
                    while i < bytes.len() && bytes[i] != quote {
                        i += 1;
                    }
                    if i < bytes.len() {
                        i += 1;
                    }
                } else {
                    while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
                        i += 1;
                    }
                }
            }
            if name.starts_with("on") || name == "srcdoc" {
                continue;
            }
            cleaned.push_str(&tag[attr_start..i]);
        } else {
            cleaned.push(bytes[i] as char);
            i += 1;
        }
    }
    cleaned
}

pub fn snippet(input: &str) -> String {
    let compact = input.split_whitespace().collect::<Vec<_>>().join(" ");
    compact.chars().take(160).collect()
}

fn html_unescape(input: &str) -> String {
    input
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_message_decodes_quoted_printable_html() {
        let parsed = parse_message(
            b"From: =?UTF-8?Q?Glassdoor_Jobs?= <noreply@example.test>\r\nSubject: =?UTF-8?Q?Apply_Now_=E2=80=93_Aarhus?=\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n<p>Vestas Wind Systems =E2=80=93 apply now.</p>",
        );

        assert_eq!(parsed.from, "Glassdoor Jobs <noreply@example.test>");
        assert_eq!(parsed.subject, "Apply Now – Aarhus");
        assert_eq!(parsed.text_body, "Vestas Wind Systems – apply now.");
    }

    #[test]
    fn parse_message_drops_html_styles_from_visible_text() {
        let parsed = parse_message(
            b"From: jobs@example.test\r\nSubject: styled\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n<html><head><style>@font-face { font-family: 'Glassdoor Sans'; src: url(font.woff2); } body { color: red; }</style></head><body><h1>Apply Now</h1><p>Vestas Wind Systems =E2=80=93 Aarhus</p></body></html>",
        );

        assert_eq!(parsed.text_body, "Apply Now Vestas Wind Systems – Aarhus");
        assert!(!parsed.text_body.contains("@font-face"));
        assert!(!parsed.text_body.contains("font-family"));
    }

    #[test]
    fn parse_message_prefers_plain_part_from_multipart() {
        let parsed = parse_message(
            b"From: a@example.test\r\nSubject: multipart\r\nContent-Type: multipart/alternative; boundary=\"b1\"\r\n\r\n--b1\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nPlain =E2=80=93 text\r\n--b1\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n<p>HTML =E2=80=93 text</p>\r\n--b1--\r\n",
        );

        assert_eq!(parsed.text_body, "Plain – text");
        assert_eq!(parsed.html_body.as_deref(), Some("<p>HTML – text</p>"));
    }

    #[test]
    fn parse_message_rewrites_inline_cid_images() {
        let parsed = parse_message(
            b"From: a@example.test\r\nSubject: image\r\nContent-Type: multipart/related; boundary=\"rel\"\r\n\r\n--rel\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<p>Logo <img src=\"cid:logo@example.test\"></p>\r\n--rel\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\nContent-ID: <logo@example.test>\r\n\r\naGVsbG8=\r\n--rel--\r\n",
        );

        let html = parsed.html_body.unwrap();
        assert!(html.contains("Logo"));
        assert!(html.contains("src=\"data:image/png;base64,aGVsbG8=\""));
    }

    fn mixed_message() -> Vec<u8> {
        let mut raw = b"From: =?ISO-8859-1?Q?S=F8ren?= <soren@example.test>\r\n\
To: a@example.test\r\nCc: b@example.test, c@example.test\r\n\
Subject: =?UTF-8?B?UmVwb3J0?= =?UTF-8?B?IOKAkyBRMw==?=\r\n\
Message-ID: <m1@example.test>\r\nReferences: <m0@example.test>\r\n\
Content-Type: multipart/mixed; boundary=\"outer\"\r\n\r\n\
preamble\r\n--outer\r\n\
Content-Type: multipart/alternative; boundary=\"alt\"\r\n\r\n\
--alt\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n\
Hej, se vedh=E6ftet rapport.\r\n--alt\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Hej</p>\r\n--alt--\r\n\
--outer\r\nContent-Type: application/pdf; name=\"ignored.pdf\"\r\n\
Content-Disposition: attachment; filename*=UTF-8''Q3%20rapport%20%E2%80%93%20final.pdf\r\n\
Content-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n\
--outer\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"../../etc/passwd\"\r\n\r\n"
            .to_vec();
        // An unencoded binary part (8bit): bytes must survive untouched.
        raw.extend_from_slice(&[0x00, 0xff, 0xfe, 0x80, b'\r', b'\n']);
        raw.extend_from_slice(b"--outer\r\nContent-Type: message/rfc822\r\n\r\nSubject: inner\r\n\r\nhi\r\n--outer--\r\n");
        raw
    }

    #[test]
    fn attachments_charsets_and_headers_are_parsed() {
        let raw = mixed_message();
        let parsed = parse_message(&raw);
        assert_eq!(parsed.from, "Søren <soren@example.test>");
        assert_eq!(parsed.subject, "Report – Q3", "adjacent encoded words join");
        assert_eq!(parsed.cc, "b@example.test, c@example.test");
        assert_eq!(parsed.message_id, "<m1@example.test>");
        assert_eq!(parsed.references, "<m0@example.test>");
        assert_eq!(parsed.text_body, "Hej, se vedhæftet rapport.");
        assert_eq!(parsed.html_body.as_deref(), Some("<p>Hej</p>"));

        let names: Vec<&str> = parsed
            .attachments
            .iter()
            .map(|a| a.filename.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["Q3 rapport – final.pdf", "passwd", "attachment-5.eml"]
        );
        let pdf = &parsed.attachments[0];
        assert_eq!(
            (pdf.content_type.as_str(), pdf.size),
            ("application/pdf", 9)
        );

        let (_, bytes) = attachment_data(&raw, pdf.index).unwrap();
        assert_eq!(bytes, b"%PDF-1.4\n");
        let (_, binary) = attachment_data(&raw, parsed.attachments[1].index).unwrap();
        assert_eq!(binary, [0x00, 0xff, 0xfe, 0x80]);
        assert!(attachment_data(&raw, 99).is_none());
        assert!(
            attachment_data(&raw, 0).is_none(),
            "the text body is not an attachment"
        );
    }

    #[test]
    fn rfc2231_continuations_and_quoted_params() {
        let params = header_params(
            "attachment; filename*0*=utf-8''%C3%85rs; filename*1=\"rapport.pdf\"; note=\"a;b\"",
        );
        assert_eq!(params["filename"], "Årsrapport.pdf");
        assert_eq!(params["note"], "a;b");
        assert!(header_params("text/plain").is_empty());
        assert_eq!(sanitize_filename("..\\..\\boot.ini"), "boot.ini");
        assert_eq!(sanitize_filename(".hidden"), "hidden");
    }

    #[test]
    fn remote_content_is_blocked_unless_requested() {
        let html = r#"<p>Hi</p><img src="https://tracker.example/pixel.gif">"#;
        assert!(has_remote_content(html));
        assert!(!has_remote_content(
            "<p>plain</p><img src=\"data:image/png;base64,AA\">"
        ));
        let blocked = sanitize_email_html(html, false);
        assert!(blocked.contains("img-src data: cid:;"), "{blocked}");
        let allowed = sanitize_email_html(html, true);
        assert!(
            allowed.contains("img-src data: cid: https: http:"),
            "{allowed}"
        );
    }
}
