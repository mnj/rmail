//! Building outgoing messages (RFC 5322 + MIME) for webmail: encoded
//! headers, a quoted-printable text body and base64 attachments.

use anyhow::{Result, bail};
use base64::Engine;

/// Longest header line before folding, and body line length.
const LINE: usize = 76;

pub struct Outgoing {
    /// The sender's own address (never taken from user input).
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub text: String,
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

    let mut text_part = format!(
        "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n{}",
        quoted_printable(&message.text)
    );
    if let Some(calendar) = &message.calendar {
        let method = if calendar.method.bytes().all(|b| b.is_ascii_alphabetic()) {
            calendar.method.to_ascii_uppercase()
        } else {
            "PUBLISH".to_string()
        };
        let boundary = boundary();
        let mut alternative = format!(
            "Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n--{boundary}\r\n{text_part}\r\n--{boundary}\r\n\
             Content-Type: text/calendar; charset=utf-8; method={method}\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n"
        );
        base64_lines(&mut alternative, calendar.data.as_bytes());
        alternative.push_str(&format!("--{boundary}--\r\n"));
        text_part = alternative;
    }
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
                "--{boundary}\r\nContent-Type: {content_type}; name=\"{ascii}\"\r\nContent-Disposition: attachment; filename=\"{ascii}\"; filename*=UTF-8''{}\r\nContent-Transfer-Encoding: base64\r\n\r\n",
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
        }
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
