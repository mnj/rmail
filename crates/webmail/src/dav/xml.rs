//! WebDAV XML: reading request bodies (with namespaces) and writing
//! `multistatus` responses (RFC 4918 section 13).

use std::collections::BTreeMap;

pub(crate) const DAV: &str = "DAV:";
pub(crate) const CALDAV: &str = "urn:ietf:params:xml:ns:caldav";
pub(crate) const CARDDAV: &str = "urn:ietf:params:xml:ns:carddav";
pub(crate) const CALSERVER: &str = "http://calendarserver.org/ns/";
pub(crate) const APPLE: &str = "http://apple.com/ns/ical/";

/// A property name: namespace and local name.
pub(crate) type Name = (String, String);

pub(crate) fn name(ns: &str, local: &str) -> Name {
    (ns.to_string(), local.to_string())
}

/// Parse a request body; `None` for an empty one, an error for bad XML
/// (DTDs are refused, so entity expansion cannot be abused).
pub(crate) fn parse(body: &[u8]) -> Result<Option<roxmltree::Document<'_>>, ()> {
    let text = std::str::from_utf8(body).map_err(|_| ())?;
    if text.trim().is_empty() {
        return Ok(None);
    }
    roxmltree::Document::parse(text).map(Some).map_err(|_| ())
}

pub(crate) fn is(node: roxmltree::Node<'_, '_>, ns: &str, local: &str) -> bool {
    node.is_element() && node.tag_name().name() == local && node.tag_name().namespace() == Some(ns)
}

pub(crate) fn child<'a, 'input>(
    node: roxmltree::Node<'a, 'input>,
    ns: &str,
    local: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    node.children().find(|child| is(*child, ns, local))
}

pub(crate) fn children<'a, 'input: 'a>(
    node: roxmltree::Node<'a, 'input>,
    ns: &'a str,
    local: &'a str,
) -> impl Iterator<Item = roxmltree::Node<'a, 'input>> + 'a {
    node.children().filter(move |child| is(*child, ns, local))
}

/// The names of the elements directly inside `node` (a `prop` element).
pub(crate) fn names(node: roxmltree::Node<'_, '_>) -> Vec<Name> {
    node.children()
        .filter(|child| child.is_element())
        .map(|child| {
            name(
                child.tag_name().namespace().unwrap_or_default(),
                child.tag_name().name(),
            )
        })
        .collect()
}

pub(crate) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            // Characters XML 1.0 cannot carry.
            c if (c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r') => {}
            c => out.push(c),
        }
    }
    out
}

/// The prefix used for a namespace in responses.
fn prefix(ns: &str) -> Option<&'static str> {
    Some(match ns {
        DAV => "d",
        CALDAV => "c",
        CARDDAV => "card",
        CALSERVER => "cs",
        APPLE => "ical",
        _ => return None,
    })
}

pub(crate) const ROOT_NAMESPACES: &str = "xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:caldav\" \
xmlns:card=\"urn:ietf:params:xml:ns:carddav\" xmlns:cs=\"http://calendarserver.org/ns/\" \
xmlns:ical=\"http://apple.com/ns/ical/\"";

/// An element for property `name` with `inner` XML content (or empty).
pub(crate) fn element(name: &Name, inner: Option<&str>) -> String {
    let (ns, local) = name;
    let (tag, declaration) = match prefix(ns) {
        Some(prefix) => (format!("{prefix}:{local}"), String::new()),
        None if ns.is_empty() => (local.clone(), String::new()),
        None => (format!("x:{local}"), format!(" xmlns:x=\"{}\"", escape(ns))),
    };
    match inner {
        Some(inner) if !inner.is_empty() => format!("<{tag}{declaration}>{inner}</{tag}>"),
        _ => format!("<{tag}{declaration}/>"),
    }
}

pub(crate) fn href(path: &str) -> String {
    format!("<d:href>{}</d:href>", escape(path))
}

/// One `response` of a multistatus: an href and properties by status.
#[derive(Default)]
pub(crate) struct Response {
    pub href: String,
    /// Status (e.g. 200, 404) -> property elements.
    pub props: BTreeMap<u16, Vec<String>>,
    /// A status for the resource itself (deleted in a sync, say).
    pub status: Option<u16>,
}

fn status_line(status: u16) -> String {
    let reason = match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        424 => "Failed Dependency",
        507 => "Insufficient Storage",
        _ => "Unknown",
    };
    format!("<d:status>HTTP/1.1 {status} {reason}</d:status>")
}

impl Response {
    pub fn new(href: &str) -> Self {
        Self {
            href: href.to_string(),
            ..Default::default()
        }
    }

    pub fn add(&mut self, status: u16, element: String) {
        self.props.entry(status).or_default().push(element);
    }

    fn render(&self) -> String {
        let mut out = format!("<d:response>{}", href(&self.href));
        if let Some(status) = self.status {
            out.push_str(&status_line(status));
        }
        for (status, props) in &self.props {
            out.push_str("<d:propstat><d:prop>");
            for prop in props {
                out.push_str(prop);
            }
            out.push_str("</d:prop>");
            out.push_str(&status_line(*status));
            out.push_str("</d:propstat>");
        }
        out.push_str("</d:response>");
        out
    }
}

/// A `multistatus` document, with an optional sync token.
pub(crate) fn multistatus(responses: &[Response], sync_token: Option<&str>) -> String {
    let mut out =
        format!("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<d:multistatus {ROOT_NAMESPACES}>");
    for response in responses {
        out.push_str(&response.render());
    }
    if let Some(token) = sync_token {
        out.push_str(&format!("<d:sync-token>{}</d:sync-token>", escape(token)));
    }
    out.push_str("</d:multistatus>");
    out
}

/// A `DAV:error` body naming a failed precondition (RFC 4918 16).
pub(crate) fn error(condition: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<d:error {ROOT_NAMESPACES}>{condition}</d:error>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_namespaced_elements_and_multistatus() {
        assert_eq!(
            element(&name(DAV, "displayname"), Some("Work &amp; play")),
            "<d:displayname>Work &amp; play</d:displayname>"
        );
        assert_eq!(
            element(&name("urn:x", "odd"), None),
            "<x:odd xmlns:x=\"urn:x\"/>"
        );
        let mut response = Response::new("/dav/a b/");
        response.add(200, element(&name(DAV, "getetag"), Some("\"1\"")));
        response.add(404, element(&name(CALDAV, "calendar-data"), None));
        let xml = multistatus(&[response], Some("https://rmail.invalid/sync/3"));
        let document = roxmltree::Document::parse(&xml).unwrap();
        assert!(
            document
                .descendants()
                .any(|node| is(node, DAV, "sync-token"))
        );
        assert!(xml.contains("<d:href>/dav/a b/</d:href>"));
        assert!(xml.contains("HTTP/1.1 404 Not Found"));
        assert!(parse(b"<!DOCTYPE x [<!ENTITY a \"b\">]><x>&a;</x>").is_err());
        assert!(matches!(parse(b"  "), Ok(None)));
    }
}
