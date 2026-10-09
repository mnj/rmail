//! MIME structure as JMAP sees it (RFC 8621 section 4.1.4): a tree of
//! `EmailBodyPart`s, the `textBody`/`htmlBody`/`attachments` lists picked
//! from it, and the header parsed forms of section 4.1.2.
//!
//! Leaf parts are numbered depth first ("1", "2", ...); a part's blob is the
//! message's blob plus that number, so it can be found again by re-parsing
//! the stored message.

use std::collections::HashMap;
use std::ops::Range;

use base64::Engine;
use serde_json::{Value, json};

use crate::jmap::address;
use crate::mime::{
    decode_charset, decode_rfc2047_words, decode_transfer_bytes, header_params, split_head,
    split_multipart,
};

const MAX_DEPTH: usize = 20;

/// One header field: its name as written and its raw value (everything
/// after the colon, folding included, without the final line break).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct BodyPart {
    /// `None` for multipart parts.
    pub part_id: Option<String>,
    pub headers: Vec<Header>,
    /// Lower-cased `type/subtype`.
    pub content_type: String,
    pub charset: Option<String>,
    pub disposition: Option<String>,
    pub name: Option<String>,
    pub cid: Option<String>,
    pub language: Option<Vec<String>>,
    pub location: Option<String>,
    /// Octets after transfer decoding (0 for multipart parts).
    pub size: u64,
    /// Where the still-encoded body sits in the message.
    pub body: Range<usize>,
    pub encoding: String,
    pub sub_parts: Vec<BodyPart>,
}

impl BodyPart {
    pub fn is_multipart(&self) -> bool {
        self.content_type.starts_with("multipart/")
    }

    /// The decoded body octets.
    pub fn decoded(&self, message: &[u8]) -> Vec<u8> {
        decode_transfer_bytes(&message[self.body.clone()], &self.encoding)
    }

    /// The body as text, with CRLF line ends normalized to LF.
    pub fn text(&self, message: &[u8]) -> String {
        decode_charset(&self.decoded(message), self.charset.as_deref()).replace("\r\n", "\n")
    }

    /// Every leaf in depth-first order.
    pub fn leaves(&self) -> Vec<&BodyPart> {
        let mut out = Vec::new();
        fn walk<'a>(part: &'a BodyPart, out: &mut Vec<&'a BodyPart>) {
            if part.is_multipart() {
                for child in &part.sub_parts {
                    walk(child, out);
                }
            } else {
                out.push(part);
            }
        }
        walk(self, &mut out);
        out
    }

    pub fn find(&self, part_id: &str) -> Option<&BodyPart> {
        self.leaves()
            .into_iter()
            .find(|part| part.part_id.as_deref() == Some(part_id))
    }
}

/// Header fields of a header block, in order.
pub fn parse_header_fields(head: &[u8]) -> Vec<Header> {
    let text = String::from_utf8_lossy(head);
    let mut headers: Vec<Header> = Vec::new();
    for line in text.split_inclusive('\n') {
        if line.starts_with([' ', '\t']) {
            if let Some(last) = headers.last_mut() {
                last.value.push_str(line);
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim_end();
            if name.is_empty() || name.contains(' ') {
                continue;
            }
            headers.push(Header {
                name: name.to_string(),
                value: value.to_string(),
            });
        }
    }
    for header in &mut headers {
        let trimmed = header.value.trim_end_matches(['\r', '\n']).len();
        header.value.truncate(trimmed);
    }
    headers
}

fn header<'a>(headers: &'a [Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .rev()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

/// Parse a whole message into its part tree.
pub fn parse(message: &[u8]) -> BodyPart {
    let mut next_id = 1;
    parse_part(message, message, "text/plain", 0, &mut next_id)
}

fn offset_of(base: &[u8], slice: &[u8]) -> usize {
    (slice.as_ptr() as usize).saturating_sub(base.as_ptr() as usize)
}

fn parse_part(
    base: &[u8],
    bytes: &[u8],
    default_type: &str,
    depth: usize,
    next_id: &mut usize,
) -> BodyPart {
    let (head, body) = split_head(bytes);
    // The body is always the tail of `bytes`, which lies inside `base`; a
    // part without a blank line has an empty body that is not a slice of
    // `base` at all, so its position comes from `bytes`, never from it.
    let body_start = offset_of(base, bytes) + (bytes.len() - body.len());
    let headers = parse_header_fields(head);
    let content_type_header = header(&headers, "Content-Type").map(unfold);
    let content_type = content_type_header
        .as_deref()
        .and_then(|value| value.split(';').next())
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| value.contains('/'))
        .unwrap_or_else(|| default_type.to_string());
    let type_params = content_type_header
        .as_deref()
        .map(header_params)
        .unwrap_or_default();
    let disposition_header = header(&headers, "Content-Disposition").map(unfold);
    let disposition = disposition_header
        .as_deref()
        .and_then(|value| value.split(';').next())
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    let disposition_params = disposition_header
        .as_deref()
        .map(header_params)
        .unwrap_or_default();
    let name = disposition_params
        .get("filename")
        .or_else(|| type_params.get("name"))
        .map(|name| decode_rfc2047_words(name.trim()))
        .filter(|name| !name.is_empty());
    let charset = type_params
        .get("charset")
        .map(|charset| charset.to_ascii_lowercase())
        .or_else(|| {
            content_type
                .starts_with("text/")
                .then(|| "us-ascii".to_string())
        });
    let cid = header(&headers, "Content-ID")
        .map(|value| unfold(value).trim().to_string())
        .filter(|value| !value.is_empty());
    let language = header(&headers, "Content-Language").map(|value| {
        unfold(value)
            .split(',')
            .map(|tag| tag.trim().to_string())
            .filter(|tag| !tag.is_empty())
            .collect()
    });
    let location =
        header(&headers, "Content-Location").map(|value| unfold(value).trim().to_string());
    let encoding = header(&headers, "Content-Transfer-Encoding")
        .map(|value| unfold(value).trim().to_ascii_lowercase())
        .unwrap_or_default();
    let mut part = BodyPart {
        part_id: None,
        headers,
        content_type: content_type.clone(),
        charset,
        disposition,
        name,
        cid,
        language,
        location,
        size: 0,
        body: body_start..body_start + body.len(),
        encoding,
        sub_parts: Vec::new(),
    };
    if content_type.starts_with("multipart/") && depth < MAX_DEPTH {
        if let Some(boundary) = type_params.get("boundary") {
            let child_default = if content_type == "multipart/digest" {
                "message/rfc822"
            } else {
                "text/plain"
            };
            for child in split_multipart(body, boundary.as_bytes()) {
                part.sub_parts
                    .push(parse_part(base, child, child_default, depth + 1, next_id));
            }
            part.charset = None;
            return part;
        }
        // A multipart without a boundary is shown as plain text.
        part.content_type = "text/plain".to_string();
        part.charset = Some("us-ascii".to_string());
    }
    part.part_id = Some(next_id.to_string());
    *next_id += 1;
    part.size = part.decoded(base).len() as u64;
    part
}

/// The `textBody`, `htmlBody` and `attachments` lists (RFC 8621 section
/// 4.1.4), as part ids.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BodyLists {
    pub text: Vec<String>,
    pub html: Vec<String>,
    pub attachments: Vec<String>,
}

fn is_inline_media(content_type: &str) -> bool {
    ["image/", "audio/", "video/"]
        .iter()
        .any(|prefix| content_type.starts_with(prefix))
}

pub fn body_lists(root: &BodyPart) -> BodyLists {
    let mut text = Vec::new();
    let mut html = Vec::new();
    let mut attachments = Vec::new();
    parse_structure(
        std::slice::from_ref(root),
        "mixed",
        false,
        Some(&mut html),
        Some(&mut text),
        &mut attachments,
    );
    let id = |part: &&BodyPart| part.part_id.clone().unwrap_or_default();
    BodyLists {
        text: text.iter().map(id).collect(),
        html: html.iter().map(id).collect(),
        attachments: attachments.iter().map(id).collect(),
    }
}

/// The algorithm of RFC 8621 section 4.1.4, transcribed.
fn parse_structure<'a>(
    parts: &'a [BodyPart],
    multipart_type: &str,
    in_alternative: bool,
    mut html_body: Option<&mut Vec<&'a BodyPart>>,
    mut text_body: Option<&mut Vec<&'a BodyPart>>,
    attachments: &mut Vec<&'a BodyPart>,
) {
    let text_length = text_body.as_ref().map(|body| body.len());
    let html_length = html_body.as_ref().map(|body| body.len());
    for (index, part) in parts.iter().enumerate() {
        let is_inline = part.disposition.as_deref() != Some("attachment")
            && (part.content_type == "text/plain"
                || part.content_type == "text/html"
                || is_inline_media(&part.content_type))
            && (index == 0
                || (multipart_type != "related"
                    && (is_inline_media(&part.content_type) || part.name.is_none())));
        if part.is_multipart() {
            let sub_type = part.content_type.split('/').nth(1).unwrap_or("mixed");
            parse_structure(
                &part.sub_parts,
                sub_type,
                in_alternative || sub_type == "alternative",
                html_body.as_deref_mut(),
                text_body.as_deref_mut(),
                attachments,
            );
        } else if is_inline {
            if multipart_type == "alternative" {
                match part.content_type.as_str() {
                    "text/plain" => {
                        if let Some(body) = text_body.as_deref_mut() {
                            body.push(part);
                        }
                    }
                    "text/html" => {
                        if let Some(body) = html_body.as_deref_mut() {
                            body.push(part);
                        }
                    }
                    _ => attachments.push(part),
                }
                continue;
            } else if in_alternative {
                if part.content_type == "text/plain" {
                    html_body = None;
                }
                if part.content_type == "text/html" {
                    text_body = None;
                }
            }
            let missing_one = text_body.is_none() || html_body.is_none();
            if let Some(body) = text_body.as_deref_mut() {
                body.push(part);
            }
            if let Some(body) = html_body.as_deref_mut() {
                body.push(part);
            }
            if missing_one && is_inline_media(&part.content_type) {
                attachments.push(part);
            }
        } else {
            attachments.push(part);
        }
    }
    if multipart_type == "alternative"
        && let (Some(text), Some(html)) = (text_body, html_body)
    {
        if text_length == Some(text.len()) && html_length != Some(html.len()) {
            let start = html_length.unwrap_or(0);
            text.extend(html[start..].iter().copied());
        }
        if html_length == Some(html.len()) && text_length != Some(text.len()) {
            let start = text_length.unwrap_or(0);
            html.extend(text[start..].iter().copied());
        }
    }
}

/// Text for previews and snippets: the first text body part, or the first
/// HTML one with its markup removed, whitespace collapsed.
pub fn preview(message: &[u8], root: &BodyPart, lists: &BodyLists, max_chars: usize) -> String {
    let pick = |ids: &[String], html: bool| {
        ids.iter()
            .filter_map(|id| root.find(id))
            .find(|part| part.content_type == if html { "text/html" } else { "text/plain" })
            .map(|part| {
                let text = part.text(message);
                if html {
                    crate::mime::strip_html(&text)
                } else {
                    text
                }
            })
    };
    let text = pick(&lists.text, false)
        .or_else(|| pick(&lists.html, true))
        .unwrap_or_default();
    let mut out = String::new();
    for word in text.split_whitespace() {
        if out.chars().count() >= max_chars {
            break;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    out.chars().take(max_chars).collect()
}

/// Whether the message has attachments a user would call attachments:
/// anything in `attachments` except inline images the HTML refers to.
pub fn has_attachment(root: &BodyPart, lists: &BodyLists) -> bool {
    lists.attachments.iter().any(|id| {
        root.find(id).is_some_and(|part| {
            !(part.cid.is_some()
                && part.disposition.as_deref() != Some("attachment")
                && is_inline_media(&part.content_type))
        })
    })
}

// ---------------------------------------------------------------------------
// Header parsed forms (RFC 8621 section 4.1.2)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderForm {
    Raw,
    Text,
    Addresses,
    GroupedAddresses,
    MessageIds,
    Date,
    Urls,
}

impl HeaderForm {
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "asRaw" => Self::Raw,
            "asText" => Self::Text,
            "asAddresses" => Self::Addresses,
            "asGroupedAddresses" => Self::GroupedAddresses,
            "asMessageIds" => Self::MessageIds,
            "asDate" => Self::Date,
            "asURLs" => Self::Urls,
            _ => return None,
        })
    }

    /// Whether the form may be used for `header` (section 4.1.2.1 to
    /// 4.1.2.7 name the fields each form applies to).
    pub fn allowed_for(self, header: &str) -> bool {
        let header = header.to_ascii_lowercase();
        let address_fields = [
            "from",
            "sender",
            "reply-to",
            "to",
            "cc",
            "bcc",
            "resent-from",
            "resent-sender",
            "resent-reply-to",
            "resent-to",
            "resent-cc",
            "resent-bcc",
        ];
        match self {
            Self::Raw => true,
            Self::Text => {
                !address_fields.contains(&header.as_str())
                    && ![
                        "message-id",
                        "in-reply-to",
                        "references",
                        "date",
                        "resent-date",
                    ]
                    .contains(&header.as_str())
            }
            Self::Addresses | Self::GroupedAddresses => {
                address_fields.contains(&header.as_str()) || !is_known_field(&header)
            }
            Self::MessageIds => {
                [
                    "message-id",
                    "in-reply-to",
                    "references",
                    "resent-message-id",
                ]
                .contains(&header.as_str())
                    || !is_known_field(&header)
            }
            Self::Date => {
                ["date", "resent-date"].contains(&header.as_str()) || !is_known_field(&header)
            }
            Self::Urls => header.starts_with("list-") || !is_known_field(&header),
        }
    }
}

fn is_known_field(header: &str) -> bool {
    [
        "from",
        "sender",
        "reply-to",
        "to",
        "cc",
        "bcc",
        "subject",
        "comments",
        "keywords",
        "date",
        "message-id",
        "in-reply-to",
        "references",
        "resent-date",
        "resent-from",
        "resent-sender",
        "resent-to",
        "resent-cc",
        "resent-bcc",
        "resent-message-id",
        "list-help",
        "list-unsubscribe",
        "list-subscribe",
        "list-post",
        "list-owner",
        "list-archive",
    ]
    .contains(&header)
}

/// Remove folding: a line break followed by whitespace.
pub fn unfold(value: &str) -> String {
    value.replace("\r\n", "").replace('\n', "")
}

/// The Text form: unfolded, encoded words decoded, trimmed.
pub fn as_text(value: &str) -> String {
    decode_rfc2047_words(unfold(value).trim())
        .trim()
        .to_string()
}

pub fn as_message_ids(value: &str) -> Option<Vec<String>> {
    let value = unfold(value);
    let mut ids = Vec::new();
    let mut rest = value.as_str();
    while let Some(start) = rest.find('<') {
        let Some(end) = rest[start..].find('>') else {
            break;
        };
        let id = rest[start + 1..start + end].trim();
        if !id.is_empty() {
            ids.push(id.to_string());
        }
        rest = &rest[start + end + 1..];
    }
    if ids.is_empty() {
        // Some mailers omit the brackets.
        ids = value
            .split_whitespace()
            .filter(|word| word.contains('@'))
            .map(str::to_string)
            .collect();
    }
    (!ids.is_empty()).then_some(ids)
}

/// The Date form as an RFC 3339 date-time with the header's offset.
pub fn as_date(value: &str) -> Option<String> {
    parse_date(value).map(|date| date.to_rfc3339_opts(chrono::SecondsFormat::Secs, false))
}

pub fn parse_date(value: &str) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    let value = unfold(value);
    // Drop a trailing comment such as "(UTC)", which the parser rejects.
    let value = match value.find('(') {
        Some(index) => value[..index].trim().to_string(),
        None => value.trim().to_string(),
    };
    chrono::DateTime::parse_from_rfc2822(&value).ok()
}

pub fn as_urls(value: &str) -> Option<Vec<String>> {
    let value = unfold(value);
    let urls = value
        .split(',')
        .filter_map(|item| {
            let item = item.trim();
            let start = item.find('<')?;
            let end = item[start..].find('>')?;
            Some(item[start + 1..start + end].trim().to_string())
        })
        .collect::<Vec<_>>();
    (!urls.is_empty()).then_some(urls)
}

/// One header value in `form` as JSON (null when it does not parse).
pub fn header_value(value: &str, form: HeaderForm) -> Value {
    match form {
        HeaderForm::Raw => json!(value),
        HeaderForm::Text => json!(as_text(value)),
        HeaderForm::Addresses => json!(address::parse(&unfold(value))),
        HeaderForm::GroupedAddresses => json!(address::parse_grouped(&unfold(value))),
        HeaderForm::MessageIds => json!(as_message_ids(value)),
        HeaderForm::Date => json!(as_date(value)),
        HeaderForm::Urls => json!(as_urls(value)),
    }
}

/// `header:{name}:{form}[:all]` over a header block: the last instance, or
/// every instance with `all` (RFC 8621 section 4.1.3).
pub fn header_property(headers: &[Header], name: &str, form: HeaderForm, all: bool) -> Value {
    let mut values = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header_value(&header.value, form));
    if all {
        Value::Array(values.collect())
    } else {
        values.next_back().unwrap_or(Value::Null)
    }
}

/// A parsed `header:` property name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderProperty {
    pub name: String,
    pub form: HeaderForm,
    pub all: bool,
}

impl HeaderProperty {
    pub fn parse(property: &str) -> Option<Self> {
        let rest = property.strip_prefix("header:")?;
        let mut pieces = rest.split(':');
        let name = pieces.next().filter(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b':')
        })?;
        let mut form = HeaderForm::Raw;
        let mut all = false;
        let mut rest = pieces.collect::<Vec<_>>();
        if rest.last() == Some(&"all") {
            all = true;
            rest.pop();
        }
        match rest.as_slice() {
            [] => {}
            [form_name] => form = HeaderForm::parse(form_name)?,
            _ => return None,
        }
        if !form.allowed_for(name) {
            return None;
        }
        Some(Self {
            name: name.to_string(),
            form,
            all,
        })
    }
}

/// RFC 2047 encoded word(s) for a non-ASCII phrase or text (base64, UTF-8,
/// split so no word exceeds 75 characters).
pub fn encode_word(text: &str) -> String {
    let mut words = Vec::new();
    let mut chunk = String::new();
    for c in text.chars() {
        if (chunk.len() + c.len_utf8()).div_ceil(3) * 4 > 45 {
            words.push(std::mem::take(&mut chunk));
        }
        chunk.push(c);
    }
    if !chunk.is_empty() {
        words.push(chunk);
    }
    words
        .iter()
        .map(|word| {
            format!(
                "=?UTF-8?B?{}?=",
                base64::engine::general_purpose::STANDARD.encode(word)
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Encode a header's unstructured text (Subject and the like).
pub fn encode_text(text: &str) -> String {
    if text.is_ascii() {
        text.replace(['\r', '\n'], " ")
    } else {
        encode_word(&text.replace(['\r', '\n'], " "))
    }
}

/// Header fields as JSON `EmailHeader` objects.
pub fn headers_json(headers: &[Header]) -> Value {
    Value::Array(
        headers
            .iter()
            .map(|header| json!({"name": header.name, "value": header.value}))
            .collect(),
    )
}

/// Every header field value, by lower-cased name, last instance winning.
pub fn header_map(headers: &[Header]) -> HashMap<String, String> {
    headers
        .iter()
        .map(|header| (header.name.to_ascii_lowercase(), header.value.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] = b"From: A <a@x.test>\r\n\
Subject: =?UTF-8?Q?Hej_J=C3=B8rgen?=\r\n\
Date: Thu, 30 Oct 2014 14:12:00 +0800\r\n\
Message-ID: <one@x.test>\r\n\
References: <zero@x.test>\r\n  <minus@x.test>\r\n\
Content-Type: multipart/mixed; boundary=\"outer\"\r\n\
\r\n\
--outer\r\n\
Content-Type: multipart/alternative; boundary=\"alt\"\r\n\
\r\n\
--alt\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Hello  there\r\n\
--alt\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<p>Hello <b>there</b></p>\r\n\
--alt--\r\n\
--outer\r\n\
Content-Type: application/pdf; name=\"report.pdf\"\r\n\
Content-Disposition: attachment; filename=\"report.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
JVBERi0x\r\n\
--outer--\r\n";

    #[test]
    fn parses_the_tree_and_picks_bodies() {
        let root = parse(MESSAGE);
        assert_eq!(root.content_type, "multipart/mixed");
        assert_eq!(root.part_id, None);
        let leaves = root.leaves();
        assert_eq!(leaves.len(), 3);
        assert_eq!(leaves[0].part_id.as_deref(), Some("1"));
        assert_eq!(leaves[0].text(MESSAGE), "Hello  there");
        assert_eq!(leaves[2].name.as_deref(), Some("report.pdf"));
        assert_eq!(leaves[2].decoded(MESSAGE), b"%PDF-1");
        assert_eq!(leaves[2].size, 6);
        let lists = body_lists(&root);
        assert_eq!(lists.text, ["1"]);
        assert_eq!(lists.html, ["2"]);
        assert_eq!(lists.attachments, ["3"]);
        assert!(has_attachment(&root, &lists));
        assert_eq!(preview(MESSAGE, &root, &lists, 256), "Hello there");
    }

    #[test]
    fn parts_without_a_body_do_not_panic() {
        // Header-only message, and a multipart child without a blank line.
        let header_only = b"Subject: x\r\nFrom: a@x.test";
        let root = parse(header_only);
        assert_eq!(root.body, header_only.len()..header_only.len());
        assert!(root.decoded(header_only).is_empty());
        let message = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n--b--\r\n";
        let root = parse(message);
        for leaf in root.leaves() {
            assert!(leaf.body.end <= message.len());
            let _ = leaf.text(message);
        }
        let _ = crate::jmap::store::summarize(message);
    }

    #[test]
    fn a_single_part_message_is_both_text_and_html_body() {
        let message = b"Subject: x\r\n\r\nJust text\r\n";
        let root = parse(message);
        let lists = body_lists(&root);
        assert_eq!(lists.text, ["1"]);
        assert_eq!(lists.html, ["1"]);
        assert!(lists.attachments.is_empty());
        assert_eq!(root.charset.as_deref(), Some("us-ascii"));
    }

    #[test]
    fn header_forms() {
        let (head, _) = split_head(MESSAGE);
        let headers = parse_header_fields(head);
        assert_eq!(
            header_property(&headers, "subject", HeaderForm::Text, false),
            json!("Hej Jørgen")
        );
        assert_eq!(
            header_property(&headers, "References", HeaderForm::MessageIds, false),
            json!(["zero@x.test", "minus@x.test"])
        );
        assert_eq!(
            header_property(&headers, "Date", HeaderForm::Date, false),
            json!("2014-10-30T14:12:00+08:00")
        );
        assert_eq!(
            header_property(&headers, "From", HeaderForm::Addresses, true),
            json!([[{"name": "A", "email": "a@x.test"}]])
        );
        assert_eq!(
            header_property(&headers, "References", HeaderForm::Raw, false),
            json!(" <zero@x.test>\r\n  <minus@x.test>")
        );
        assert!(HeaderProperty::parse("header:From:asAddresses:all").is_some());
        assert!(HeaderProperty::parse("header:Subject:asAddresses").is_none());
        assert!(HeaderProperty::parse("header:X-Custom:asDate").is_some());
        assert!(HeaderProperty::parse("header:From:asBogus").is_none());
    }

    #[test]
    fn encoded_words_round_trip() {
        let encoded = encode_word("Hej Jørgen, sådan går det");
        assert!(encoded.split(' ').all(|word| word.len() <= 75));
        assert_eq!(decode_rfc2047_words(&encoded), "Hej Jørgen, sådan går det");
    }
}
