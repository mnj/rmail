use std::cmp::Ordering;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use unicode_normalization::UnicodeNormalization;

use crate::parser::{SortCriterion, SortKey};

#[derive(Debug)]
pub(crate) struct SortRecord {
    pub(crate) seq: u64,
    pub(crate) uid: u64,
    arrival: i64,
    date: i64,
    size: usize,
    cc: String,
    from: String,
    subject: String,
    to: String,
}

impl SortRecord {
    pub(crate) fn from_message(seq: u64, uid: u64, internal_date: i64, data: &[u8]) -> Self {
        let headers = parse_headers(data);
        let date = first_header(&headers, "date")
            .and_then(|value| chrono::DateTime::parse_from_rfc2822(value).ok())
            .map(|date| date.timestamp())
            .unwrap_or(internal_date);
        Self {
            seq,
            uid,
            arrival: internal_date,
            date,
            size: data.len(),
            cc: normalized_mailbox(first_header(&headers, "cc")),
            from: normalized_mailbox(first_header(&headers, "from")),
            subject: normalized_string(&base_subject(
                &first_header(&headers, "subject")
                    .map(decode_rfc2047)
                    .unwrap_or_default(),
            )),
            to: normalized_mailbox(first_header(&headers, "to")),
        }
    }
}

pub(crate) fn compare_records(
    left: &SortRecord,
    right: &SortRecord,
    criteria: &[SortCriterion],
) -> Ordering {
    for criterion in criteria {
        let ordering = match criterion.key {
            SortKey::Arrival => left.arrival.cmp(&right.arrival),
            SortKey::Cc => left.cc.cmp(&right.cc),
            SortKey::Date => left.date.cmp(&right.date),
            SortKey::From => left.from.cmp(&right.from),
            SortKey::Size => left.size.cmp(&right.size),
            SortKey::Subject => left.subject.cmp(&right.subject),
            SortKey::To => left.to.cmp(&right.to),
        };
        if ordering != Ordering::Equal {
            return if criterion.reverse {
                ordering.reverse()
            } else {
                ordering
            };
        }
    }
    left.seq.cmp(&right.seq)
}

pub(crate) fn parse_headers(data: &[u8]) -> Vec<(String, String)> {
    let end = data
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .or_else(|| data.windows(2).position(|window| window == b"\n\n"))
        .unwrap_or(data.len());
    let text = String::from_utf8_lossy(&data[..end]);
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, value)) = headers.last_mut() {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    headers
}

pub(crate) fn first_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header == name)
        .map(|(_, value)| value.as_str())
}

pub(crate) fn normalized_string(value: &str) -> String {
    value.nfkd().flat_map(char::to_lowercase).collect()
}

fn normalized_mailbox(value: Option<&str>) -> String {
    let value = value.map(decode_rfc2047).unwrap_or_default();
    let first = value.split(',').next().unwrap_or("").trim();
    let address = if let Some(start) = first.rfind('<') {
        let tail = &first[start + 1..];
        &tail[..tail.find('>').unwrap_or(tail.len())]
    } else {
        first
    };
    let mailbox = address
        .trim()
        .trim_matches('"')
        .split('@')
        .next()
        .unwrap_or("");
    normalized_string(mailbox)
}

pub(crate) fn decode_rfc2047(value: &str) -> String {
    let mut output = String::new();
    let mut rest = value;
    while let Some(start) = rest.find("=?") {
        output.push_str(&rest[..start]);
        let encoded = &rest[start + 2..];
        let Some(charset_end) = encoded.find('?') else {
            output.push_str(&rest[start..]);
            return output;
        };
        let charset = &encoded[..charset_end];
        let encoded = &encoded[charset_end + 1..];
        let Some(encoding_end) = encoded.find('?') else {
            output.push_str(&rest[start..]);
            return output;
        };
        let encoding = &encoded[..encoding_end];
        let payload = &encoded[encoding_end + 1..];
        let Some(payload_end) = payload.find("?=") else {
            output.push_str(&rest[start..]);
            return output;
        };
        let payload_text = &payload[..payload_end];
        let bytes = if encoding.eq_ignore_ascii_case("B") {
            BASE64_ENGINE.decode(payload_text).ok()
        } else if encoding.eq_ignore_ascii_case("Q") {
            decode_q_word(payload_text)
        } else {
            None
        };
        let Some(bytes) = bytes else {
            output.push_str(
                &rest[start..start + 2 + charset_end + 1 + encoding_end + 1 + payload_end + 2],
            );
            rest = &payload[payload_end + 2..];
            continue;
        };
        output.push_str(&decode_charset(&bytes, charset));
        rest = &payload[payload_end + 2..];
        if rest.starts_with(char::is_whitespace) && rest.trim_start().starts_with("=?") {
            rest = rest.trim_start();
        }
    }
    output.push_str(rest);
    output
}

fn decode_q_word(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'_' => decoded.push(b' '),
            b'=' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok()?;
                decoded.push(u8::from_str_radix(hex, 16).ok()?);
                index += 2;
            }
            b'=' => return None,
            byte => decoded.push(byte),
        }
        index += 1;
    }
    Some(decoded)
}

fn decode_charset(bytes: &[u8], charset: &str) -> String {
    if charset.eq_ignore_ascii_case("UTF-8") || charset.eq_ignore_ascii_case("US-ASCII") {
        String::from_utf8_lossy(bytes).into_owned()
    } else if charset.eq_ignore_ascii_case("ISO-8859-1") || charset.eq_ignore_ascii_case("LATIN1") {
        bytes.iter().map(|byte| char::from(*byte)).collect()
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

pub(crate) fn base_subject(subject: &str) -> String {
    let mut value = subject.trim().to_string();
    loop {
        let previous = value.clone();
        value = value.trim().to_string();
        while value.to_ascii_lowercase().ends_with("(fwd)") {
            value.truncate(value.len().saturating_sub(5));
            value = value.trim_end().to_string();
        }
        if value.len() >= 6 && value[..5].eq_ignore_ascii_case("[fwd:") && value.ends_with(']') {
            value = value[5..value.len() - 1].trim().to_string();
            continue;
        }
        value = strip_subject_prefixes(&value);
        if value == previous {
            break;
        }
    }
    value
}

fn strip_subject_prefixes(subject: &str) -> String {
    let mut value = subject.trim_start();
    loop {
        let before = value;
        if value.starts_with('[') {
            if let Some(end) = value.find(']') {
                value = value[end + 1..].trim_start();
            }
        }
        let lower = value.to_ascii_lowercase();
        let mut stripped = false;
        for leader in ["re", "fw", "fwd"] {
            if let Some(tail) = lower.strip_prefix(leader) {
                let offset = value.len() - tail.len();
                let tail = value[offset..].trim_start();
                if let Some(tail) = tail.strip_prefix(':') {
                    value = tail.trim_start();
                    stripped = true;
                    break;
                }
            }
        }
        if !stripped && value == before {
            break;
        }
    }
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_encoded_words_and_normalizes_base_subjects() {
        assert_eq!(decode_rfc2047("=?UTF-8?Q?J=C3=B8rgen?="), "Jørgen");
        assert_eq!(decode_rfc2047("=?UTF-8?B?SsO4cmdlbg==?="), "Jørgen");
        assert_eq!(base_subject(" Re: [list] Fwd: topic (fwd) "), "topic");
    }

    #[test]
    fn compares_multiple_keys_and_uses_sequence_as_final_tie_breaker() {
        let first = SortRecord::from_message(
            2,
            20,
            200,
            b"Date: Tue, 2 Jan 2024 00:00:00 +0000\r\nSubject: Re: Zebra\r\n\r\n",
        );
        let second = SortRecord::from_message(
            1,
            10,
            100,
            b"Date: Mon, 1 Jan 2024 00:00:00 +0000\r\nSubject: zebra\r\n\r\n",
        );
        let criteria = [SortCriterion {
            key: SortKey::Subject,
            reverse: false,
        }];
        assert_eq!(
            compare_records(&first, &second, &criteria),
            Ordering::Greater
        );
    }
}
