//! Parsing stored messages for display: headers (RFC 2047), MIME
//! multipart bodies, transfer encodings, inline images, and sanitizing HTML
//! for the sandboxed reader.

use std::collections::HashMap;

use base64::Engine;

#[derive(Default)]
pub(crate) struct ParsedMessage {
    pub(crate) from: String,
    pub(crate) to: String,
    pub(crate) subject: String,
    pub(crate) date: String,
    pub(crate) text_body: String,
    pub(crate) html_body: Option<String>,
    pub(crate) inline_images: HashMap<String, String>,
}

#[derive(Default)]
struct MultipartParsed {
    text_body: Option<String>,
    html_body: Option<String>,
    inline_images: HashMap<String, String>,
}

pub(crate) fn parse_message(bytes: &[u8]) -> ParsedMessage {
    let text = String::from_utf8_lossy(bytes).replace("\r\n", "\n");
    let (headers, body) = text.split_once("\n\n").unwrap_or(("", &text));
    parse_message_parts(headers, body)
}

fn parse_message_parts(headers: &str, body: &str) -> ParsedMessage {
    let mut parsed = ParsedMessage::default();
    let header_map = parse_headers(headers);
    parsed.from = header_map.get("from").cloned().unwrap_or_default();
    parsed.to = header_map.get("to").cloned().unwrap_or_default();
    parsed.subject = header_map.get("subject").cloned().unwrap_or_default();
    parsed.date = header_map.get("date").cloned().unwrap_or_default();

    let content_type_raw = header_map
        .get("content-type")
        .cloned()
        .unwrap_or_else(|| "text/plain".to_string());
    let content_type = content_type_raw.to_ascii_lowercase();
    let transfer_encoding = header_map
        .get("content-transfer-encoding")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    let (text_body, html_body, inline_images) = if content_type.starts_with("multipart/") {
        if let Some(boundary) = header_param(&content_type_raw, "boundary") {
            let multipart = parse_multipart_body(body, &boundary);
            (
                multipart.text_body.unwrap_or_else(|| {
                    multipart
                        .html_body
                        .as_deref()
                        .map(strip_html)
                        .unwrap_or_default()
                }),
                multipart.html_body,
                multipart.inline_images,
            )
        } else {
            (
                decode_transfer_text(body, &transfer_encoding),
                None,
                HashMap::new(),
            )
        }
    } else {
        let decoded = decode_transfer_text(body, &transfer_encoding);
        if content_type.contains("text/html") {
            (strip_html(decoded.trim()), Some(decoded), HashMap::new())
        } else {
            (decoded, None, HashMap::new())
        }
    };

    parsed.text_body = text_body.trim().to_string();
    parsed.inline_images = inline_images;
    parsed.html_body =
        html_body.map(|html| apply_inline_images(html.trim(), &parsed.inline_images));
    parsed
}

fn parse_headers(headers: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut current_name: Option<String> = None;
    let mut current_value = String::new();
    for line in headers.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if !current_value.is_empty() {
                current_value.push(' ');
            }
            current_value.push_str(line.trim());
            continue;
        }
        if let Some(name) = current_name.take() {
            out.insert(name, decode_rfc2047_words(current_value.trim()));
            current_value.clear();
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        current_name = Some(name.trim().to_ascii_lowercase());
        current_value.push_str(value.trim());
    }
    if let Some(name) = current_name {
        out.insert(name, decode_rfc2047_words(current_value.trim()));
    }
    out
}

fn header_param(content_type: &str, name: &str) -> Option<String> {
    for part in content_type.split(';').skip(1) {
        let (k, v) = part.trim().split_once('=')?;
        if k.trim().eq_ignore_ascii_case(name) {
            return Some(v.trim().trim_matches('"').to_string());
        }
    }
    None
}

fn parse_multipart_body(body: &str, boundary: &str) -> MultipartParsed {
    let marker = format!("--{boundary}");
    let mut parsed = MultipartParsed::default();
    for raw_part in body.split(&marker).skip(1) {
        let part = raw_part.trim_start_matches('\n').trim_end();
        if part.starts_with("--") {
            break;
        }
        let Some((part_headers, part_body)) = part.split_once("\n\n") else {
            continue;
        };
        let headers = parse_headers(part_headers);
        let content_type_raw = headers
            .get("content-type")
            .cloned()
            .unwrap_or_else(|| "text/plain".to_string());
        let content_type = content_type_raw.to_ascii_lowercase();
        let transfer_encoding = headers
            .get("content-transfer-encoding")
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        if content_type.starts_with("multipart/") {
            if let Some(boundary) = header_param(&content_type_raw, "boundary") {
                let nested = parse_multipart_body(part_body, &boundary);
                if parsed.text_body.is_none() {
                    parsed.text_body = nested.text_body;
                }
                if parsed.html_body.is_none() {
                    parsed.html_body = nested.html_body;
                }
                parsed.inline_images.extend(nested.inline_images);
            }
            continue;
        }

        let decoded = decode_transfer_text(part_body, &transfer_encoding);
        if content_type.starts_with("image/") {
            if let Some(cid) = headers
                .get("content-id")
                .map(|v| v.trim().trim_matches('<').trim_matches('>').to_string())
            {
                let bytes = decode_transfer_bytes(part_body, &transfer_encoding);
                parsed.inline_images.insert(
                    cid,
                    format!(
                        "data:{};base64,{}",
                        content_type_raw
                            .split(';')
                            .next()
                            .unwrap_or("application/octet-stream"),
                        base64::engine::general_purpose::STANDARD.encode(bytes)
                    ),
                );
            }
        } else if content_type.contains("text/plain") && parsed.text_body.is_none() {
            parsed.text_body = Some(decoded);
        } else if content_type.contains("text/html") && parsed.html_body.is_none() {
            parsed.html_body = Some(decoded);
        }
    }
    parsed
}

fn decode_transfer_text(input: &str, encoding: &str) -> String {
    String::from_utf8_lossy(&decode_transfer_bytes(input, encoding)).to_string()
}

fn decode_transfer_bytes(input: &str, encoding: &str) -> Vec<u8> {
    if encoding.contains("quoted-printable") {
        decode_quoted_printable(input.as_bytes())
    } else if encoding.contains("base64") {
        let compact = input.split_whitespace().collect::<String>();
        base64::engine::general_purpose::STANDARD
            .decode(compact)
            .unwrap_or_else(|_| input.as_bytes().to_vec())
    } else {
        input.as_bytes().to_vec()
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

fn decode_rfc2047_words(input: &str) -> String {
    let mut out = String::new();
    let mut rest = input;
    while let Some(start) = rest.find("=?") {
        out.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let Some(charset_end) = after_start.find('?') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let charset = &after_start[..charset_end];
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
        if charset.eq_ignore_ascii_case("utf-8") || charset.eq_ignore_ascii_case("us-ascii") {
            if encoding.eq_ignore_ascii_case("q") {
                let qp = data.replace('_', " ");
                out.push_str(&String::from_utf8_lossy(&decode_quoted_printable(
                    qp.as_bytes(),
                )));
            } else if encoding.eq_ignore_ascii_case("b") {
                match base64::engine::general_purpose::STANDARD.decode(data) {
                    Ok(bytes) => out.push_str(&String::from_utf8_lossy(&bytes)),
                    Err(_) => out.push_str(data),
                }
            } else {
                out.push_str(data);
            }
        } else {
            out.push_str(data);
        }
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

pub(crate) fn has_remote_content(html: &str) -> bool {
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

pub(crate) fn sanitize_email_html(input: &str, allow_remote_content: bool) -> String {
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

pub(crate) fn snippet(input: &str) -> String {
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
