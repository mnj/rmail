//! What webmail keeps per account for composing, in the account's state
//! database: compose preferences and the addresses the user recently sent
//! to. Address suggestions combine those with the account's CardDAV
//! address books.

use std::path::Path;

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::dav::text;

/// Recent recipients kept; the least recently used go first.
const MAX_RECENT: i64 = 500;

pub(crate) fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS compose_prefs(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS recent_recipients(
            address TEXT PRIMARY KEY COLLATE NOCASE,
            name TEXT NOT NULL,
            uses INTEGER NOT NULL,
            last_used INTEGER NOT NULL
        );
        ",
    )?;
    Ok(())
}

fn open(
    mail_root: &Path,
    domain: &str,
    localpart: &str,
) -> Result<crate::sqlite_pool::SqliteConnection> {
    crate::imap_state::open_account(mail_root, domain, localpart)
}

/// Compose preferences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// `html` or `text`: how new messages start.
    pub format: String,
    /// BCP 47 tag for the editor's `lang` (spellchecking); empty follows
    /// the browser.
    pub language: String,
    /// Seconds a sent message waits so it can be undone (0 sends at once).
    pub undo_seconds: u32,
    /// AI writing suggestions while composing. Off until the user turns it
    /// on, and only offered when the server has them enabled
    /// (`compose_ai.*` settings): the draft around the cursor then goes to
    /// the provider the admin configured.
    pub ai_suggestions: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            format: "html".to_string(),
            language: String::new(),
            undo_seconds: 0,
            ai_suggestions: false,
        }
    }
}

/// The longest undo window offered.
pub const MAX_UNDO_SECONDS: u32 = 60;

impl Prefs {
    /// Values in range: an unknown format is HTML, a malformed language is
    /// dropped, the undo window is capped.
    pub fn normalized(mut self) -> Self {
        if self.format != "text" {
            self.format = "html".to_string();
        }
        let valid_language = self.language.len() <= 35
            && self.language.split('-').all(|part| {
                !part.is_empty()
                    && part.len() <= 8
                    && part.bytes().all(|b| b.is_ascii_alphanumeric())
            });
        if !valid_language {
            self.language.clear();
        }
        self.undo_seconds = self.undo_seconds.min(MAX_UNDO_SECONDS);
        self
    }
}

pub fn prefs(mail_root: &Path, domain: &str, localpart: &str) -> Result<Prefs> {
    let conn = open(mail_root, domain, localpart)?;
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM compose_prefs WHERE key = 'prefs'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(value
        .and_then(|value| serde_json::from_str::<Prefs>(&value).ok())
        .unwrap_or_default()
        .normalized())
}

pub fn set_prefs(mail_root: &Path, domain: &str, localpart: &str, prefs: Prefs) -> Result<Prefs> {
    let prefs = prefs.normalized();
    let conn = open(mail_root, domain, localpart)?;
    conn.execute(
        "INSERT INTO compose_prefs(key, value) VALUES('prefs', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![serde_json::to_string(&prefs)?],
    )?;
    Ok(prefs)
}

/// `Name <a@b>` or `a@b` -> (name, address); `None` without an `@`.
fn split(value: &str) -> Option<(String, String)> {
    let value = value.trim();
    let (name, address) = match (value.rfind('<'), value.rfind('>')) {
        (Some(start), Some(end)) if start < end => (
            value[..start].trim().trim_matches('"').trim(),
            value[start + 1..end].trim(),
        ),
        _ => ("", value),
    };
    (address.contains('@') && !address.chars().any(char::is_whitespace))
        .then(|| (name.chars().take(200).collect(), address.to_string()))
}

/// Remember the people a message went to.
pub fn record_recipients(
    mail_root: &Path,
    domain: &str,
    localpart: &str,
    recipients: &[String],
) -> Result<()> {
    let mut conn = open(mail_root, domain, localpart)?;
    let now = chrono::Utc::now().timestamp();
    let tx = conn.transaction()?;
    for (name, address) in recipients.iter().filter_map(|value| split(value)) {
        tx.execute(
            "INSERT INTO recent_recipients(address, name, uses, last_used) VALUES(?1, ?2, 1, ?3)
             ON CONFLICT(address) DO UPDATE SET uses = uses + 1, last_used = excluded.last_used,
                 name = CASE WHEN excluded.name != '' THEN excluded.name ELSE name END",
            params![address, name, now],
        )?;
    }
    tx.execute(
        "DELETE FROM recent_recipients WHERE address NOT IN
             (SELECT address FROM recent_recipients ORDER BY last_used DESC LIMIT ?1)",
        params![MAX_RECENT],
    )?;
    tx.commit()?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Contact {
    pub name: String,
    pub email: String,
    /// `contacts` (an address book) or `recent`.
    pub source: &'static str,
}

/// vCard text value unescaping (RFC 6350 3.4).
fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n' | 'N') => out.push(' '),
                Some(other) => out.push(other),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The name and addresses on a vCard.
fn card_addresses(data: &str) -> Vec<(String, String)> {
    let Ok(card) = text::parse(data) else {
        return Vec::new();
    };
    let name = card
        .property("FN")
        .map(|fn_| unescape(&fn_.value))
        .filter(|name| !name.trim().is_empty())
        .or_else(|| {
            card.property("N").map(|n| {
                let parts: Vec<String> = n.value.split(';').map(unescape).collect();
                [parts.get(1), parts.first()]
                    .into_iter()
                    .flatten()
                    .filter(|part| !part.is_empty())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ")
            })
        })
        .unwrap_or_default();
    card.properties_named("EMAIL")
        .map(|email| {
            let address = unescape(&email.value);
            address.trim().trim_start_matches("mailto:").to_string()
        })
        .filter(|address| address.contains('@') && !address.chars().any(char::is_whitespace))
        .map(|address| (name.trim().to_string(), address))
        .collect()
}

/// Up to `limit` people matching `query` (by name or address, any case):
/// address-book contacts first, then recent recipients not among them,
/// most used first.
pub fn suggestions(
    mail_root: &Path,
    domain: &str,
    localpart: &str,
    query: &str,
    limit: usize,
) -> Result<Vec<Contact>> {
    let conn = open(mail_root, domain, localpart)?;
    let needle = query.trim().to_lowercase();
    let matches = |name: &str, email: &str| {
        needle.is_empty()
            || email.to_lowercase().contains(&needle)
            || name
                .to_lowercase()
                .split_whitespace()
                .any(|word| word.starts_with(&needle))
            || name.to_lowercase().starts_with(&needle)
    };
    let mut out: Vec<Contact> = Vec::new();
    let known =
        |out: &[Contact], email: &str| out.iter().any(|c| c.email.eq_ignore_ascii_case(email));
    // A LIKE prefilter keeps large address books cheap; vCards are matched
    // properly after parsing.
    let like = format!("%{}%", needle.replace(['%', '_', '\\'], ""));
    let mut statement = conn.prepare(
        "SELECT o.data FROM dav_objects o JOIN dav_collections c ON c.id = o.collection_id
         WHERE c.kind = 'addressbook' AND o.deleted = 0 AND o.data LIKE ?1
         ORDER BY o.name LIMIT 2000",
    )?;
    let cards = statement
        .query_map(params![like], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut from_cards: Vec<Contact> = Vec::new();
    for data in cards {
        for (name, email) in card_addresses(&data) {
            if matches(&name, &email) && !known(&from_cards, &email) {
                from_cards.push(Contact {
                    name,
                    email,
                    source: "contacts",
                });
            }
        }
    }
    from_cards.sort_by_key(|card| card.name.to_lowercase());
    out.extend(from_cards);
    let mut statement = conn.prepare(
        "SELECT name, address FROM recent_recipients ORDER BY uses DESC, last_used DESC LIMIT ?1",
    )?;
    let recent = statement
        .query_map(params![MAX_RECENT], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (name, email) in recent {
        if matches(&name, &email) && !known(&out, &email) {
            out.push(Contact {
                name,
                email,
                source: "recent",
            });
        }
    }
    out.truncate(limit);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefs_are_kept_and_normalized() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        assert_eq!(
            prefs(root, "example.test", "ann").unwrap(),
            Prefs::default()
        );
        let saved = set_prefs(
            root,
            "example.test",
            "ann",
            Prefs {
                format: "rtf".into(),
                language: "da-DK".into(),
                undo_seconds: 600,
                ai_suggestions: true,
            },
        )
        .unwrap();
        assert_eq!(saved.format, "html");
        assert_eq!(saved.undo_seconds, MAX_UNDO_SECONDS);
        assert!(saved.ai_suggestions);
        assert_eq!(prefs(root, "example.test", "ann").unwrap(), saved);
        let cleared = set_prefs(
            root,
            "example.test",
            "ann",
            Prefs {
                format: "text".into(),
                language: "\"><script>".into(),
                undo_seconds: 10,
                ai_suggestions: false,
            },
        )
        .unwrap();
        assert_eq!(cleared.language, "");
        assert_eq!(cleared.format, "text");
    }

    #[test]
    fn suggestions_come_from_contacts_and_recent_recipients() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let (d, l) = ("example.test", "ann");
        {
            let conn = open(root, d, l).unwrap();
            let book = crate::dav::store::collections(&conn, crate::dav::store::Kind::AddressBook)
                .unwrap()
                .remove(0);
            crate::dav::store::put(
                &conn,
                &book,
                "a.vcf",
                "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:a\r\nFN:Søren Holm\r\nEMAIL;TYPE=work:soren@example.test\r\nEMAIL:holm@home.test\r\nEND:VCARD\r\n",
                &|_| true,
            )
            .unwrap()
            .unwrap();
            crate::dav::store::put(
                &conn,
                &book,
                "b.vcf",
                "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:b\r\nN:Berg;Jonas;;;\r\nEMAIL:jonas@example.test\r\nEND:VCARD\r\n",
                &|_| true,
            )
            .unwrap()
            .unwrap();
        }
        record_recipients(
            root,
            d,
            l,
            &[
                "\"Søren H.\" <soren@example.test>".into(),
                "Sofie <sofie@other.test>".into(),
                "not an address".into(),
            ],
        )
        .unwrap();
        record_recipients(root, d, l, &["sofie@other.test".into()]).unwrap();

        let found = suggestions(root, d, l, "so", 10).unwrap();
        let emails: Vec<&str> = found.iter().map(|c| c.email.as_str()).collect();
        assert_eq!(emails, ["soren@example.test", "sofie@other.test"]);
        assert_eq!(found[0].name, "Søren Holm");
        assert_eq!(found[0].source, "contacts");
        assert_eq!(found[1].name, "Sofie", "an empty name keeps the known one");
        assert_eq!(found[1].source, "recent");

        let jonas = suggestions(root, d, l, "jonas", 10).unwrap();
        assert_eq!(jonas[0].name, "Jonas Berg");
        assert!(suggestions(root, d, l, "zzz", 10).unwrap().is_empty());
        assert_eq!(suggestions(root, d, l, "", 2).unwrap().len(), 2);
    }
}
