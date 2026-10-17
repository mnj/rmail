//! Notes: messages in the account's `Notes` folder, in the form Apple
//! Notes uses over IMAP (`X-Uniform-Type-Identifier: com.apple.mail-note`,
//! an HTML body whose first line is the title). iPhone and Mac Notes sync
//! them as an IMAP account's notes; webmail and ActiveSync phones show the
//! same notes.
//!
//! - A note keeps its `X-Universally-Unique-Identifier` across edits, while
//!   each edit replaces the message (a new UID), as Apple Notes does. Notes
//!   from elsewhere without one are known by their UID.
//! - Webmail and phones edit notes as plain text; formatting a note had
//!   (bold, lists, checklists) does not survive an edit there.

use std::path::Path;

use anyhow::Result;
use rmail_common::{imap_state, mime};
use serde::Serialize;

/// The folder notes live in (Apple Notes' name for it).
pub(crate) const FOLDER: &str = "Notes";
/// The longest note accepted, in characters.
pub(crate) const MAX_TEXT: usize = 100_000;

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct Note {
    /// Stable across edits.
    pub id: String,
    pub title: String,
    pub text: String,
    /// Unix seconds.
    pub created: i64,
    pub modified: i64,
    /// The message's UID now (changes with every edit).
    #[serde(skip)]
    pub uid: u64,
}

/// Whether `name` is the notes folder (shown as notes, not mail).
pub(crate) fn is_notes_folder(name: &str) -> bool {
    name.eq_ignore_ascii_case(FOLDER)
}

fn header(raw: &[u8], name: &str) -> Option<String> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n"))
        .unwrap_or(raw.len());
    let head = String::from_utf8_lossy(&raw[..end]).replace("\r\n", "\n");
    let unfolded = head.replace("\n ", " ").replace("\n\t", " ");
    let prefix = format!("{}:", name.to_ascii_lowercase());
    unfolded.lines().find_map(|line| {
        line.get(..prefix.len())
            .filter(|start| start.eq_ignore_ascii_case(&prefix))
            .map(|_| line[prefix.len()..].trim().to_string())
    })
}

/// A note's HTML as text: blocks and breaks become lines.
fn html_text(html: &str) -> String {
    let mut out = String::new();
    let mut tag = String::new();
    let mut in_tag = false;
    let lower = html.to_ascii_lowercase();
    let body = lower
        .find("<body")
        .and_then(|at| html[at..].find('>').map(|end| at + end + 1))
        .map_or(html, |start| &html[start..]);
    for ch in body.chars() {
        match ch {
            '<' => {
                in_tag = true;
                tag.clear();
            }
            '>' if in_tag => {
                in_tag = false;
                let name = tag
                    .trim_start_matches('/')
                    .split(|c: char| c.is_whitespace() || c == '/')
                    .next()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                let closing = tag.starts_with('/');
                match name.as_str() {
                    "br" => out.push('\n'),
                    "div" | "p" | "li" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "tr"
                        if closing && !out.ends_with('\n') =>
                    {
                        out.push('\n');
                    }
                    _ => {}
                }
            }
            _ if in_tag => tag.push(ch),
            _ => out.push(ch),
        }
    }
    let decoded = out
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&");
    decoded
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The first non-empty line, as Apple Notes titles a note.
pub(crate) fn title_of(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or_default()
        .chars()
        .take(200)
        .collect()
}

fn date_of(text: Option<String>) -> Option<i64> {
    chrono::DateTime::parse_from_rfc2822(text?.trim())
        .ok()
        .map(|d| d.timestamp())
}

/// A note from its message.
fn read(message: &imap_state::Message) -> Option<Note> {
    let raw = std::fs::read(&message.path).ok()?;
    let parsed = mime::parse_message(&raw);
    let text = match &parsed.html_body {
        Some(html) => html_text(html),
        None => parsed.text_body.trim().to_string(),
    };
    let created = date_of(header(&raw, "X-Mail-Created-Date")).unwrap_or(message.internaldate);
    let modified = date_of(header(&raw, "Date")).unwrap_or(message.internaldate);
    let id = header(&raw, "X-Universally-Unique-Identifier")
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 64
                && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        .unwrap_or_else(|| format!("m{}", message.uid));
    let title = if parsed.subject.trim().is_empty() {
        title_of(&text)
    } else {
        parsed.subject.trim().to_string()
    };
    Some(Note {
        id,
        title,
        text,
        created,
        modified,
        uid: message.uid,
    })
}

fn has_folder(root: &Path, domain: &str, local: &str) -> Result<bool> {
    Ok(imap_state::list_folders(root, domain, local)?
        .iter()
        .any(|f| is_notes_folder(&f.name)))
}

/// The account's notes, most recently changed first.
pub(crate) fn list(root: &Path, domain: &str, local: &str) -> Result<Vec<Note>> {
    if !has_folder(root, domain, local)? {
        return Ok(Vec::new());
    }
    let (_, messages) = imap_state::load_folder(root, domain, local, FOLDER)?;
    let mut notes: Vec<Note> = messages
        .iter()
        .filter(|m| !m.flags.iter().any(|f| f.eq_ignore_ascii_case("\\Deleted")))
        .filter_map(read)
        .collect();
    notes.sort_by(|a, b| b.modified.cmp(&a.modified).then(b.uid.cmp(&a.uid)));
    Ok(notes)
}

fn new_id() -> String {
    let bytes: [u8; 16] = rand::random();
    let hex: String = bytes.iter().map(|b| format!("{b:02X}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// The message a note is stored as.
fn message(address: &str, id: &str, text: &str, created: i64) -> Vec<u8> {
    let now = chrono::Utc::now();
    let created = chrono::DateTime::from_timestamp(created, 0).unwrap_or(now);
    let title = title_of(text).replace(['\r', '\n'], " ");
    let body: String = text
        .lines()
        .map(|line| {
            if line.trim().is_empty() {
                "<div><br></div>".to_string()
            } else {
                format!("<div>{}</div>", escape_html(line))
            }
        })
        .collect();
    let domain = address.rsplit_once('@').map_or("localhost", |(_, d)| d);
    format!(
        "From: {address}\r\nDate: {date}\r\nSubject: {subject}\r\n\
         X-Uniform-Type-Identifier: com.apple.mail-note\r\n\
         X-Universally-Unique-Identifier: {id}\r\nX-Mail-Created-Date: {created}\r\n\
         Message-Id: <{id}.{stamp}@{domain}>\r\nMIME-Version: 1.0\r\n\
         Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n\
         <html><head></head><body>{body}</body></html>\r\n",
        date = now.to_rfc2822(),
        subject = mime_subject(&title),
        created = created.to_rfc2822(),
        stamp = now.timestamp_millis(),
    )
    .into_bytes()
}

/// A Subject header value: as it is when ASCII, else RFC 2047 encoded.
fn mime_subject(title: &str) -> String {
    use base64::Engine;
    if title.is_ascii() {
        title.to_string()
    } else {
        format!(
            "=?utf-8?B?{}?=",
            base64::engine::general_purpose::STANDARD.encode(title.as_bytes())
        )
    }
}

/// Store `text` as note `id` (replacing its message), or as a new note.
pub(crate) fn save(
    root: &Path,
    address: &str,
    domain: &str,
    local: &str,
    id: Option<&str>,
    text: &str,
) -> Result<Note> {
    if !has_folder(root, domain, local)? {
        imap_state::create_folder(root, domain, local, FOLDER)?;
    }
    let existing = match id {
        Some(id) => list(root, domain, local)?.into_iter().find(|n| n.id == id),
        None => None,
    };
    // A note from elsewhere without an identifier gets one now.
    let note_id = match (&existing, id) {
        (Some(note), _) if !note.id.starts_with('m') => note.id.clone(),
        (_, Some(id)) if !id.starts_with('m') => id.to_string(),
        _ => new_id(),
    };
    let created = existing
        .as_ref()
        .map_or_else(|| chrono::Utc::now().timestamp(), |n| n.created);
    let data = message(address, &note_id, text.trim_end(), created);
    imap_state::append_message(
        root,
        domain,
        local,
        FOLDER,
        &data,
        vec!["\\Seen".to_string()],
    )?;
    if let Some(previous) = &existing {
        imap_state::delete_message_by_uid(root, domain, local, FOLDER, previous.uid)?;
    }
    list(root, domain, local)?
        .into_iter()
        .find(|n| n.id == note_id)
        .ok_or_else(|| anyhow::anyhow!("the note was not stored"))
}

/// Delete note `id`; false when there is none.
pub(crate) fn delete(root: &Path, domain: &str, local: &str, id: &str) -> Result<bool> {
    let Some(note) = list(root, domain, local)?.into_iter().find(|n| n.id == id) else {
        return Ok(false);
    };
    imap_state::delete_message_by_uid(root, domain, local, FOLDER, note.uid)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notes_are_stored_as_apple_notes_and_edited_in_place() {
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        imap_state::init_account(root, "example.test", "user").unwrap();
        assert!(list(root, "example.test", "user").unwrap().is_empty());
        let first = save(
            root,
            "user@example.test",
            "example.test",
            "user",
            None,
            "Groceries\nMilk & eggs\n\n<bread>",
        )
        .unwrap();
        assert_eq!(first.title, "Groceries");
        assert_eq!(first.text, "Groceries\nMilk & eggs\n\n<bread>");
        let (_, messages) = imap_state::load_folder(root, "example.test", "user", FOLDER).unwrap();
        let raw = std::fs::read(&messages[0].path).unwrap();
        assert_eq!(
            header(&raw, "X-Uniform-Type-Identifier").as_deref(),
            Some("com.apple.mail-note")
        );
        assert!(String::from_utf8_lossy(&raw).contains("<div>Milk &amp; eggs</div>"));

        let edited = save(
            root,
            "user@example.test",
            "example.test",
            "user",
            Some(&first.id),
            "Groceries\nMilk",
        )
        .unwrap();
        assert_eq!(edited.id, first.id, "the same note");
        assert_ne!(edited.uid, first.uid, "in a new message");
        assert_eq!(edited.created, first.created);
        let notes = list(root, "example.test", "user").unwrap();
        assert_eq!(notes.len(), 1, "the old message is gone");
        assert!(delete(root, "example.test", "user", &first.id).unwrap());
        assert!(list(root, "example.test", "user").unwrap().is_empty());
    }

    #[test]
    fn apple_html_reads_as_lines() {
        let html = "<html><head><style>x{}</style></head><body><div><b>Trip</b></div><div>Pack &amp; go<br></div><ul><li>Passport</li><li>Tickets</li></ul></body></html>";
        assert_eq!(html_text(html), "Trip\nPack & go\nPassport\nTickets");
    }
}
