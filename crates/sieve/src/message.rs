//! The message a script runs against: parsed headers, body and envelope.

/// A message plus its SMTP envelope. Header values are unfolded but not
/// RFC 2047-decoded.
pub struct Message<'a> {
    raw: &'a [u8],
    headers: Vec<(String, String)>,
    body: &'a [u8],
    pub envelope_from: String,
    pub envelope_to: String,
}

impl<'a> Message<'a> {
    /// `envelope_from` is empty for the null sender.
    pub fn new(raw: &'a [u8], envelope_from: &str, envelope_to: &str) -> Self {
        let split = find_header_end(raw);
        let (head, body) = match split {
            Some((end, body_start)) => (&raw[..end], &raw[body_start..]),
            None => (raw, &raw[raw.len()..]),
        };
        let mut headers: Vec<(String, String)> = Vec::new();
        for line in String::from_utf8_lossy(head).lines() {
            if line.starts_with([' ', '\t']) {
                if let Some((_, value)) = headers.last_mut() {
                    value.push(' ');
                    value.push_str(line.trim());
                }
            } else if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }
        Self {
            raw,
            headers,
            body,
            envelope_from: envelope_from.to_string(),
            envelope_to: envelope_to.to_string(),
        }
    }

    pub fn size(&self) -> u64 {
        self.raw.len() as u64
    }

    /// Values of every header called `name` (case-insensitive), in order.
    pub fn header_values(&self, name: &str) -> Vec<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn has_header(&self, name: &str) -> bool {
        !self.header_values(name).is_empty()
    }

    pub fn first_header(&self, name: &str) -> Option<&str> {
        self.header_values(name).into_iter().next()
    }

    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(self.body).into_owned()
    }
}

/// Offsets of the end of the header block and the start of the body.
fn find_header_end(raw: &[u8]) -> Option<(usize, usize)> {
    if raw.starts_with(b"\r\n") {
        return Some((0, 2));
    }
    if raw.starts_with(b"\n") {
        return Some((0, 1));
    }
    (0..raw.len()).find_map(|i| {
        if raw[i..].starts_with(b"\r\n\r\n") {
            Some((i + 2, i + 4))
        } else if raw[i..].starts_with(b"\n\n") {
            Some((i + 1, i + 2))
        } else {
            None
        }
    })
}

/// The addr-spec of each address in an address-list header value.
pub fn parse_addresses(value: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let (mut current, mut quoted, mut angle, mut comment) = (String::new(), false, false, 0u32);
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' if quoted => {
                current.push(c);
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            '"' if comment == 0 => {
                quoted = !quoted;
                current.push(c);
            }
            '(' if !quoted => comment += 1,
            ')' if !quoted && comment > 0 => comment -= 1,
            _ if comment > 0 => {}
            '<' if !quoted => {
                angle = true;
                current.push(c);
            }
            '>' if !quoted => {
                angle = false;
                current.push(c);
            }
            ',' if !quoted && !angle => parts.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    parts.push(current);
    parts
        .into_iter()
        .filter_map(|part| {
            let part = part.trim();
            let addr = match (part.rfind('<'), part.rfind('>')) {
                (Some(open), Some(close)) if open < close => part[open + 1..close].trim(),
                _ => part,
            };
            let addr = addr.trim_matches('"');
            (!addr.is_empty()).then(|| addr.to_string())
        })
        .collect()
}

/// `local@domain` split at the last `@`; no `@` means all local part.
pub fn split_address(address: &str) -> (&str, &str) {
    address.rsplit_once('@').unwrap_or((address, ""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_headers_with_folding_and_body() {
        let raw = b"Subject: hello\r\n world\r\nTo: a@x.test\r\nTO: b@x.test\r\n\r\nbody text\r\n";
        let m = Message::new(raw, "s@y.test", "a@x.test");
        assert_eq!(m.first_header("subject"), Some("hello world"));
        assert_eq!(m.header_values("To"), vec!["a@x.test", "b@x.test"]);
        assert_eq!(m.body_text(), "body text\r\n");
        assert!(!m.has_header("cc"));
        assert_eq!(m.size(), raw.len() as u64);
    }

    #[test]
    fn handles_lf_only_and_headerless_messages() {
        let m = Message::new(b"A: 1\n\nbody", "", "x@y.test");
        assert_eq!(m.first_header("a"), Some("1"));
        assert_eq!(m.body_text(), "body");
        let m = Message::new(b"\nbody only", "", "x@y.test");
        assert_eq!(m.body_text(), "body only");
        let m = Message::new(b"A: 1", "", "x@y.test");
        assert_eq!(m.first_header("a"), Some("1"));
        assert_eq!(m.body_text(), "");
    }

    #[test]
    fn extracts_addr_specs_from_lists() {
        assert_eq!(
            parse_addresses("\"Doe, John\" <john@x.test>, plain@y.test, Bob (boss) <bob@z.test>"),
            vec!["john@x.test", "plain@y.test", "bob@z.test"]
        );
        assert_eq!(parse_addresses(""), Vec::<String>::new());
        assert_eq!(split_address("a@b@c.test"), ("a@b", "c.test"));
        assert_eq!(split_address("local"), ("local", ""));
    }
}
