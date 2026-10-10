//! Building outgoing messages (RFC 5322 + MIME) for webmail: encoded
//! headers, a quoted-printable text body (with an optional HTML
//! alternative and its inline images) and base64 attachments.

use anyhow::{Result, bail};
use base64::Engine;

use crate::compose_html::{self, DataImages, InlineImage};

/// Longest header line before folding, and body line length.
const LINE: usize = 76;

#[derive(Default)]
pub struct Outgoing {
    /// The sender's own address or one of their identities (never taken
    /// from user input unchecked).
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub text: String,
    /// A cleaned HTML body fragment (see [`Outgoing::set_html`]), sent as
    /// an alternative to `text`.
    pub html: Option<String>,
    /// Images the HTML refers to as `cid:`, sent as `multipart/related`.
    pub inline_images: Vec<InlineImage>,
    pub in_reply_to: Option<String>,
    pub references: Option<String>,
    pub attachments: Vec<OutgoingAttachment>,
    /// A calendar invitation, reply or cancellation (iMIP, RFC 6047), sent
    /// as a `text/calendar` alternative to the text.
    pub calendar: Option<CalendarPart>,
}

pub struct CalendarPart {
    /// The iTIP method (`REQUEST`, `REPLY`, `CANCEL`).
    pub method: String,
    pub data: String,
}

pub struct OutgoingAttachment {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

pub struct Built {
    pub bytes: Vec<u8>,
    pub message_id: String,
}

impl Outgoing {
    /// Use HTML the user wrote as the body: cleaned (see
    /// [`compose_html`]), pasted or dropped `data:` images moved into
    /// inline parts, and the plain-text alternative generated from it.
    pub fn set_html(&mut self, raw: &str) {
        let cleaned = compose_html::clean(
            raw,
            compose_html::Options {
                remote_images: true,
                data_images: DataImages::Extract,
            },
        );
        self.text = compose_html::to_text(&cleaned.html);
        self.html = Some(cleaned.html);
        self.inline_images = cleaned.images;
    }

    /// Every recipient's bare address, in order, without duplicates.
    pub fn envelope_recipients(&self) -> Result<Vec<String>> {
        let mut out: Vec<String> = Vec::new();
        for value in self.to.iter().chain(&self.cc).chain(&self.bcc) {
            let address = bare_address(value)?;
            if !out.iter().any(|known| known.eq_ignore_ascii_case(&address)) {
                out.push(address);
            }
        }
        Ok(out)
    }
}

/// `Name <user@example>` or `user@example` -> `user@example`, rejecting
/// anything that is not a single plausible address.
pub fn bare_address(value: &str) -> Result<String> {
    let value = value.trim();
    if value.chars().any(char::is_control) {
        bail!("not an email address: {}", value.escape_debug());
    }
    let address = match (value.rfind('<'), value.rfind('>')) {
        (Some(start), Some(end)) if start < end => value[start + 1..end].trim(),
        _ => value,
    };
    let valid = address.contains('@')
        && !address.starts_with('@')
        && !address.ends_with('@')
        && address.len() <= 320
        && !address
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "<>,;\"()[]\\".contains(c));
    if !valid {
        bail!("not an email address: {value}");
    }
    Ok(address.to_string())
}

/// Build the message. With `include_bcc` the Bcc header is kept (for the
/// Sent and Drafts copies); the copy handed to SMTP never carries it.
pub fn build(message: &Outgoing, include_bcc: bool, message_id: Option<&str>) -> Result<Built> {
    for value in message
        .to
        .iter()
        .chain(&message.cc)
        .chain(&message.bcc)
        .chain(std::iter::once(&message.from))
    {
        bare_address(value)?;
    }
    let domain = bare_address(&message.from)?
        .rsplit('@')
        .next()
        .unwrap_or("localhost")
        .to_string();
    let message_id = message_id.map(str::to_string).unwrap_or_else(|| {
        let random: String = (0..16)
            .map(|_| format!("{:02x}", rand::random::<u8>()))
            .collect();
        format!("<{random}@{domain}>")
    });

    let mut out = String::new();
    header(&mut out, "Date", &chrono::Utc::now().to_rfc2822());
    header(&mut out, "From", &encode_address(&message.from));
    if !message.to.is_empty() {
        header(&mut out, "To", &encode_address_list(&message.to));
    }
    if !message.cc.is_empty() {
        header(&mut out, "Cc", &encode_address_list(&message.cc));
    }
    if include_bcc && !message.bcc.is_empty() {
        header(&mut out, "Bcc", &encode_address_list(&message.bcc));
    }
    header(&mut out, "Subject", &encode_words(&message.subject));
    header(&mut out, "Message-ID", &message_id);
    if let Some(value) = message.in_reply_to.as_deref().filter(|v| is_header_safe(v)) {
        header(&mut out, "In-Reply-To", value);
    }
    if let Some(value) = message.references.as_deref().filter(|v| is_header_safe(v)) {
        header(&mut out, "References", value);
    }
    header(&mut out, "MIME-Version", "1.0");
    header(&mut out, "User-Agent", "rMail Webmail");

    let text_part = format!(
        "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n{}",
        quoted_printable(&message.text)
    );
    let mut alternatives = vec![text_part];
    if let Some(html) = &message.html {
        let html_part = format!(
            "Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n{}",
            quoted_printable(&compose_html::document(html))
        );
        if message.inline_images.is_empty() {
            alternatives.push(html_part);
        } else {
            let mut parts = vec![html_part];
            for (index, image) in message.inline_images.iter().enumerate() {
                parts.push(inline_image_part(index, image));
            }
            alternatives.push(multipart("related; type=\"text/html\"", &parts));
        }
    }
    if let Some(calendar) = &message.calendar {
        let method = if calendar.method.bytes().all(|b| b.is_ascii_alphabetic()) {
            calendar.method.to_ascii_uppercase()
        } else {
            "PUBLISH".to_string()
        };
        let mut part = format!(
            "Content-Type: text/calendar; charset=utf-8; method={method}\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n"
        );
        base64_lines(&mut part, calendar.data.as_bytes());
        alternatives.push(part);
    }
    let text_part = if alternatives.len() == 1 {
        alternatives.remove(0)
    } else {
        multipart("alternative", &alternatives)
    };
    if message.attachments.is_empty() {
        out.push_str(&text_part);
    } else {
        let boundary = boundary();
        out.push_str(&format!(
            "Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\nThis is a multi-part message in MIME format.\r\n"
        ));
        out.push_str(&format!("--{boundary}\r\n{text_part}\r\n"));
        for attachment in &message.attachments {
            let content_type = if is_mime_type(&attachment.content_type) {
                attachment.content_type.to_ascii_lowercase()
            } else {
                "application/octet-stream".to_string()
            };
            let name = attachment
                .filename
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or("attachment")
                .chars()
                .filter(|c| !c.is_control())
                .collect::<String>();
            let ascii: String = name
                .chars()
                .map(|c| {
                    if c.is_ascii() && c != '"' && c != '\\' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            out.push_str(&format!(
                "--{boundary}\r\nContent-Type: {content_type};\r\n name=\"{ascii}\"\r\nContent-Disposition: attachment; filename=\"{ascii}\";\r\n filename*=UTF-8''{}\r\nContent-Transfer-Encoding: base64\r\n\r\n",
                percent_encode(&name)
            ));
            base64_lines(&mut out, &attachment.data);
        }
        out.push_str(&format!("--{boundary}--\r\n"));
    }
    Ok(Built {
        bytes: out.into_bytes(),
        message_id,
    })
}

/// A `multipart/<subtype>` entity (headers and body) of `parts`, each
/// starting with its own headers.
fn multipart(subtype: &str, parts: &[String]) -> String {
    let boundary = boundary();
    let mut out = format!("Content-Type: multipart/{subtype};\r\n boundary=\"{boundary}\"\r\n\r\n");
    for part in parts {
        out.push_str(&format!("--{boundary}\r\n{part}"));
        if !part.ends_with("\r\n") {
            out.push_str("\r\n");
        }
    }
    out.push_str(&format!("--{boundary}--\r\n"));
    out
}

fn inline_image_part(index: usize, image: &InlineImage) -> String {
    let content_type = if is_mime_type(&image.content_type) {
        image.content_type.to_ascii_lowercase()
    } else {
        "application/octet-stream".to_string()
    };
    let extension = content_type.rsplit('/').next().unwrap_or("bin");
    let name = format!("image{}.{extension}", index + 1);
    let content_id: String = image
        .content_id
        .chars()
        .filter(|c| c.is_ascii_graphic() && !"<>\"".contains(*c))
        .collect();
    let mut part = format!(
        "Content-Type: {content_type}; name=\"{name}\"\r\nContent-Transfer-Encoding: base64\r\nContent-ID: <{content_id}>\r\nContent-Disposition: inline; filename=\"{name}\"\r\n\r\n"
    );
    base64_lines(&mut part, &image.data);
    part
}

fn boundary() -> String {
    format!(
        "=_rmail_{}",
        (0..12)
            .map(|_| format!("{:02x}", rand::random::<u8>()))
            .collect::<String>()
    )
}

fn base64_lines(out: &mut String, data: &[u8]) {
    let encoded = base64::engine::general_purpose::STANDARD.encode(data);
    for chunk in encoded.as_bytes().chunks(LINE) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push_str("\r\n");
    }
}

fn is_header_safe(value: &str) -> bool {
    !value.contains(['\r', '\n']) && value.len() <= 4000
}

fn is_mime_type(value: &str) -> bool {
    let mut parts = value.splitn(2, '/');
    let token = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "!#$&-^_.+".contains(c))
    };
    matches!((parts.next(), parts.next()), (Some(a), Some(b)) if token(a) && token(b))
}

/// Append `Name: value`, folding long values at spaces (RFC 5322 2.2.3).
fn header(out: &mut String, name: &str, value: &str) {
    let mut line = format!("{name}: ");
    let mut first = true;
    for word in value.split(' ') {
        if !first && line.len() + word.len() + 1 > LINE {
            out.push_str(&line);
            out.push_str("\r\n");
            line = String::from(" ");
        } else if !first {
            line.push(' ');
        }
        line.push_str(word);
        first = false;
    }
    out.push_str(&line);
    out.push_str("\r\n");
}

/// RFC 2047 B-encoding for non-ASCII text, in words short enough to fold.
fn encode_words(text: &str) -> String {
    let text = text.replace(['\r', '\n'], " ");
    if text.is_ascii() {
        return text;
    }
    let mut words = Vec::new();
    let mut chunk = String::new();
    for c in text.chars() {
        if chunk.len() + c.len_utf8() > 45 {
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
                base64::engine::general_purpose::STANDARD.encode(word.as_bytes())
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// `Name <addr>` with the name encoded when it is not ASCII.
fn encode_address(value: &str) -> String {
    let value = value.trim();
    match (value.rfind('<'), value.rfind('>')) {
        (Some(start), Some(end)) if start < end => {
            let name = value[..start].trim().trim_matches('"').trim();
            let address = value[start + 1..end].trim();
            if name.is_empty() {
                format!("<{address}>")
            } else if name.is_ascii() {
                format!("\"{}\" <{address}>", name.replace(['"', '\\'], ""))
            } else {
                format!("{} <{address}>", encode_words(name))
            }
        }
        _ => value.to_string(),
    }
}

fn encode_address_list(values: &[String]) -> String {
    values
        .iter()
        .map(|value| encode_address(value))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Quoted-printable (RFC 2045) with CRLF line ends and soft breaks.
pub fn quoted_printable(text: &str) -> String {
    let text = text.replace("\r\n", "\n");
    let mut out = String::new();
    for (index, line) in text.split('\n').enumerate() {
        if index > 0 {
            out.push_str("\r\n");
        }
        let mut current = 0;
        let bytes = line.as_bytes();
        for (position, &byte) in bytes.iter().enumerate() {
            let last = position + 1 == bytes.len();
            let encoded = if (byte == b' ' || byte == b'\t') && last {
                format!("={byte:02X}")
            } else if (33..=126).contains(&byte) && byte != b'=' || byte == b' ' || byte == b'\t' {
                (byte as char).to_string()
            } else {
                format!("={byte:02X}")
            };
            if current + encoded.len() > LINE - 1 {
                out.push_str("=\r\n");
                current = 0;
            }
            out.push_str(&encoded);
            current += encoded.len();
        }
    }
    out.push_str("\r\n");
    out
}

fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mime::{attachment_data, parse_message};

    fn outgoing() -> Outgoing {
        Outgoing {
            from: "alice@example.test".into(),
            to: vec!["Søren Holm <soren@example.test>".into()],
            cc: vec!["bob@example.test".into()],
            bcc: vec!["secret@example.test".into()],
            subject: "Re: Q3 rapport – final".into(),
            text: format!(
                "Hej Søren,\n\nTak!\n{}\n> quoted = line \n",
                "x".repeat(200)
            ),
            in_reply_to: Some("<m1@example.test>".into()),
            references: Some("<m0@example.test> <m1@example.test>".into()),
            attachments: vec![OutgoingAttachment {
                filename: "../Årsrapport.pdf".into(),
                content_type: "application/pdf".into(),
                data: b"%PDF-1.4\n\x00\xff".to_vec(),
            }],
            calendar: None,
            ..Default::default()
        }
    }

    #[test]
    fn html_messages_carry_a_text_alternative_and_inline_images() {
        let png = base64::engine::general_purpose::STANDARD.encode(b"\x89PNG\r\n\x1a\nimage");
        let mut message = outgoing();
        message.set_html(&format!(
            "<div>Hej <b>Søren</b> – se <a href=\"https://example.test/r\">rapporten</a></div>\
             <div><img src=\"data:image/png;base64,{png}\" alt=\"graf\"></div>\
             <blockquote><div>{}</div></blockquote><script>alert(1)</script>\
             <p onclick=\"x()\">=end</p>",
            "lang linje ".repeat(40)
        ));
        assert!(message.text.starts_with(
            "Hej Søren – se rapporten <https://example.test/r>\n[graf]\n\n> lang linje"
        ));
        let built = build(&message, false, None).unwrap();
        let raw = String::from_utf8(built.bytes.clone()).unwrap();
        assert!(raw.is_ascii(), "7-bit clean");
        let long: Vec<&str> = raw.lines().filter(|line| line.len() > 78).collect();
        assert!(long.is_empty(), "{long:?}");
        assert!(raw.contains("Content-Type: multipart/mixed"));
        assert!(raw.contains("Content-Type: multipart/alternative"));
        assert!(raw.contains("Content-Type: multipart/related; type=\"text/html\""));
        assert!(!raw.contains("alert(1)") && !raw.contains("onclick"));

        let parsed = parse_message(&built.bytes);
        assert!(parsed.text_body.starts_with("Hej Søren – se rapporten"));
        let html = parsed.html_body.unwrap();
        assert!(html.contains("<b>Søren</b>"));
        assert!(html.contains("<a href=\"https://example.test/r\">rapporten</a>"));
        assert!(
            html.contains(&"lang linje ".repeat(40)),
            "soft breaks rejoin"
        );
        assert!(html.contains("<p>=end</p>"));
        // The image is inline (shown in the body), not an attachment.
        assert!(html.contains(&format!("src=\"data:image/png;base64,{png}\"")));
        assert_eq!(parsed.attachments.len(), 1);
        assert_eq!(parsed.attachments[0].filename, "Årsrapport.pdf");
        let (_, data) = attachment_data(&built.bytes, parsed.attachments[0].index).unwrap();
        assert_eq!(data, b"%PDF-1.4\n\x00\xff");

        // Without attachments or images: just the alternative.
        message.attachments.clear();
        message.set_html("<p>Hi</p>");
        let raw = String::from_utf8(build(&message, false, None).unwrap().bytes).unwrap();
        assert!(!raw.contains("multipart/mixed") && !raw.contains("multipart/related"));
        assert!(raw.contains("Content-Type: multipart/alternative"));
        let parsed = parse_message(raw.as_bytes());
        assert_eq!(parsed.text_body, "Hi");
        assert!(parsed.html_body.unwrap().contains("<p>Hi</p>"));
    }

    #[test]
    fn html_invitations_keep_the_calendar_part() {
        let mut message = outgoing();
        message.attachments.clear();
        message.set_html("<p>Invitation</p>");
        message.calendar = Some(CalendarPart {
            method: "REQUEST".into(),
            data: "BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nEND:VCALENDAR\r\n".into(),
        });
        let built = build(&message, false, None).unwrap();
        let root = crate::jmap::mime::parse(&built.bytes);
        let types: Vec<String> = root
            .leaves()
            .into_iter()
            .map(|part| part.content_type.clone())
            .collect();
        assert_eq!(types.len(), 3, "{types:?}");
        assert!(types[0].starts_with("text/plain"));
        assert!(types[1].starts_with("text/html"));
        assert!(types[2].starts_with("text/calendar"));
    }

    #[test]
    fn invitations_carry_the_calendar_as_an_alternative() {
        let mut message = outgoing();
        message.attachments.clear();
        message.calendar = Some(CalendarPart {
            method: "request".into(),
            data: "BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nEND:VCALENDAR\r\n".into(),
        });
        let built = build(&message, false, None).unwrap();
        let raw = String::from_utf8(built.bytes.clone()).unwrap();
        assert!(raw.contains("multipart/alternative"));
        assert!(raw.contains("Content-Type: text/calendar; charset=utf-8; method=REQUEST"));
        let parsed = parse_message(&built.bytes);
        assert!(parsed.text_body.starts_with("Hej Søren"));
        let root = crate::jmap::mime::parse(&built.bytes);
        let calendar = root
            .leaves()
            .into_iter()
            .find(|part| part.content_type.starts_with("text/calendar"))
            .unwrap();
        assert!(calendar.text(&built.bytes).contains("METHOD:REQUEST"));
    }

    #[test]
    fn built_messages_round_trip_through_the_parser() {
        let message = outgoing();
        let built = build(&message, false, None).unwrap();
        let raw = String::from_utf8(built.bytes.clone()).unwrap();
        assert!(raw.is_ascii(), "7-bit clean");
        assert!(raw.lines().all(|line| line.len() <= 998));
        assert!(!raw.contains("secret@example.test"), "no Bcc on the wire");
        assert!(raw.contains(&format!("Message-ID: {}", built.message_id)));
        assert!(built.message_id.ends_with("@example.test>"));

        let parsed = parse_message(&built.bytes);
        assert_eq!(parsed.subject, "Re: Q3 rapport – final");
        assert_eq!(parsed.to, "Søren Holm <soren@example.test>");
        assert_eq!(parsed.cc, "bob@example.test");
        assert_eq!(parsed.in_reply_to, "<m1@example.test>");
        assert!(parsed.text_body.starts_with("Hej Søren,\n\nTak!"));
        assert!(
            parsed.text_body.contains(&"x".repeat(200)),
            "soft breaks rejoin"
        );
        assert!(parsed.text_body.contains("> quoted = line"));
        assert_eq!(parsed.attachments.len(), 1);
        assert_eq!(parsed.attachments[0].filename, "Årsrapport.pdf");
        let (_, data) = attachment_data(&built.bytes, parsed.attachments[0].index).unwrap();
        assert_eq!(data, b"%PDF-1.4\n\x00\xff");

        let copy = build(&message, true, Some(&built.message_id)).unwrap();
        assert!(
            String::from_utf8(copy.bytes)
                .unwrap()
                .contains("Bcc: secret@example.test")
        );
    }

    #[test]
    fn recipients_are_validated_and_deduplicated() {
        let message = outgoing();
        assert_eq!(
            message.envelope_recipients().unwrap(),
            vec![
                "soren@example.test",
                "bob@example.test",
                "secret@example.test"
            ]
        );
        assert!(bare_address("not an address").is_err());
        assert!(bare_address("a@b\r\nRCPT TO:<x@y>").is_err());
        let mut bad = outgoing();
        bad.subject = "Hi\r\nBcc: injected@example.test".into();
        let raw = String::from_utf8(build(&bad, false, None).unwrap().bytes).unwrap();
        assert!(
            !raw.contains("\r\nBcc: injected"),
            "header injection is neutralised"
        );
    }
}
