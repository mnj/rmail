//! The MIME part tree of a message and IMAP body sections (RFC 3501
//! section 6.4.5, RFC 9051 section 6.4.5): `1.2`, `HEADER`, `TEXT`,
//! `1.MIME`, `2.HEADER`, ... IMAP FETCH and CATENATE use it, and so does
//! URLAUTH resolution, which the submission server shares for BURL.

pub fn header_value(data: &[u8], field: &str) -> Option<String> {
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

pub fn parse_header_params(value: &str) -> (String, Vec<(String, String)>) {
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

pub fn content_type_parts(data: &[u8]) -> (String, String, Vec<(String, String)>) {
    let raw = header_value(data, "Content-Type").unwrap_or_else(|| "text/plain".to_string());
    let (main, params) = parse_header_params(&raw);
    let (typ, subtype) = main
        .split_once('/')
        .map(|(typ, subtype)| (typ.to_ascii_uppercase(), subtype.to_ascii_uppercase()))
        .unwrap_or_else(|| ("TEXT".to_string(), "PLAIN".to_string()));
    (typ, subtype, params)
}

pub fn multipart_boundary(params: &[(String, String)]) -> Option<String> {
    params
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("BOUNDARY"))
        .map(|(_, value)| value.clone())
}

pub fn split_multipart_parts(body: &[u8], boundary: &str) -> Vec<Vec<u8>> {
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
pub struct MimeNode {
    pub header: Vec<u8>,
    pub body: Vec<u8>,
    pub children: Vec<MimeNode>,
    pub embedded: Option<Box<MimeNode>>,
}

pub fn split_header_body(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        (data[..pos + 4].to_vec(), data[pos + 4..].to_vec())
    } else if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        (data[..pos + 2].to_vec(), data[pos + 2..].to_vec())
    } else {
        (data.to_vec(), Vec::new())
    }
}

pub fn parse_mime_tree(data: &[u8]) -> MimeNode {
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

pub fn locate_mime_part<'a>(root: &'a MimeNode, path: &[usize]) -> Option<&'a MimeNode> {
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

/// The bytes of body `section` (an IMAP section without the brackets, empty
/// for the whole message), or `None` when the message has no such part.
pub fn extract_section(data: &[u8], section: &str) -> Option<Vec<u8>> {
    let section = section.trim().to_ascii_uppercase();
    if section.is_empty() {
        return Some(data.to_vec());
    }
    let root = parse_mime_tree(data);
    if section == "TEXT" {
        return Some(root.body);
    }
    if section == "HEADER" || section == "MIME" {
        return Some(root.header);
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
    let part = locate_mime_part(&root, &path)?;
    match suffix {
        Some("MIME") => Some(part.header.clone()),
        Some("HEADER") => Some(
            part.embedded
                .as_deref()
                .map(|embedded| embedded.header.clone())
                .unwrap_or_else(|| part.header.clone()),
        ),
        Some("TEXT") => Some(
            part.embedded
                .as_deref()
                .map(|embedded| embedded.body.clone())
                .unwrap_or_else(|| part.body.clone()),
        ),
        Some(_) => None,
        None => Some(part.body.clone()),
    }
}
