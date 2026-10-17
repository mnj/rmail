//! Journaling: a copy of every message a domain sends or receives, kept
//! in an archive mailbox for compliance. smtpd stores the copy when it
//! accepts a message (mail sent from webmail and phones passes through it
//! too), with headers recording the direction, the envelope sender and
//! every envelope recipient, Bcc included, above the original message.
//!
//! The archive mailbox is an ordinary local mailbox; put it on legal hold
//! (`imap_state::set_legal_hold`) so nothing in it can be deleted.

use std::path::Path;

use anyhow::{Result, bail};
use rusqlite::{OptionalExtension, params};

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS journal_policies (
        domain TEXT PRIMARY KEY,
        archive TEXT NOT NULL
    );
";

fn open(db: &Path) -> Result<crate::sqlite_pool::SqliteConnection> {
    let conn = crate::sqlite_pool::connection(db)?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

fn clean_domain(domain: &str) -> Result<String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || domain.contains(['/', '\\', '@']) {
        bail!("invalid domain");
    }
    Ok(domain)
}

/// Journal `domain`'s mail to `archive` (a local mailbox), or with `None`
/// stop.
pub fn set(db: &Path, domain: &str, archive: Option<&str>) -> Result<()> {
    let domain = clean_domain(domain)?;
    let conn = open(db)?;
    match archive {
        Some(archive) => {
            let archive =
                crate::domain::canonicalize_mailbox_address(archive)?.to_ascii_lowercase();
            if !crate::db::mailbox_exists(db, &archive)? {
                bail!("no mailbox {archive}");
            }
            conn.execute(
                "INSERT INTO journal_policies (domain, archive) VALUES (?1, ?2)
                 ON CONFLICT(domain) DO UPDATE SET archive = excluded.archive",
                params![domain, archive],
            )?;
        }
        None => {
            conn.execute(
                "DELETE FROM journal_policies WHERE domain = ?1",
                params![domain],
            )?;
        }
    }
    Ok(())
}

/// Where `domain`'s mail is journaled, if it is.
pub fn archive_of(db: &Path, domain: &str) -> Result<Option<String>> {
    Ok(open(db)?
        .query_row(
            "SELECT archive FROM journal_policies WHERE domain = ?1",
            params![domain.trim().to_ascii_lowercase()],
            |row| row.get(0),
        )
        .optional()?)
}

/// Every journaled domain and its archive mailbox.
pub fn list(db: &Path) -> Result<Vec<(String, String)>> {
    let conn = open(db)?;
    let mut stmt = conn.prepare("SELECT domain, archive FROM journal_policies ORDER BY domain")?;
    let rows = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Which way a journaled message went, for its domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Sent by one of the domain's people.
    Outbound,
    /// Received by one of them.
    Inbound,
    /// Both: sent from the domain to someone in it.
    Internal,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Direction::Outbound => "outbound",
            Direction::Inbound => "inbound",
            Direction::Internal => "internal",
        }
    }
}

/// Header-safe text: no line breaks, and not absurdly long.
fn header_text(text: &str) -> String {
    text.chars()
        .filter(|c| !matches!(c, '\r' | '\n'))
        .take(998)
        .collect()
}

/// The journal copy: the journal headers, then the message as it came.
pub fn journal_copy(
    message: &[u8],
    direction: Direction,
    domain: &str,
    sender: &str,
    recipients: &[String],
) -> Vec<u8> {
    let mut out = format!(
        "X-Rmail-Journal: {}; domain={}\r\nX-Rmail-Journal-Sender: <{}>\r\n",
        direction.as_str(),
        header_text(domain),
        header_text(sender),
    );
    // One recipient per header line, so long lists stay within limits.
    for recipient in recipients {
        out.push_str(&format!(
            "X-Rmail-Journal-Recipient: <{}>\r\n",
            header_text(recipient)
        ));
    }
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(message);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_journal_to_a_local_mailbox() {
        let td = tempfile::tempdir().unwrap();
        let db = td.path().join("accounts.sqlite");
        crate::db::init_db(&db).unwrap();
        crate::db::add_mailbox(&db, "archive@example.test", None, None, None).unwrap();
        assert!(set(&db, "example.test", Some("nobody@example.test")).is_err());
        set(&db, "Example.test", Some("Archive@example.test")).unwrap();
        assert_eq!(
            archive_of(&db, "example.test").unwrap().as_deref(),
            Some("archive@example.test")
        );
        assert_eq!(list(&db).unwrap().len(), 1);
        set(&db, "example.test", None).unwrap();
        assert_eq!(archive_of(&db, "example.test").unwrap(), None);

        let copy = journal_copy(
            b"Subject: hi\r\n\r\nbody",
            Direction::Inbound,
            "example.test",
            "a@b.test",
            &[
                "x@example.test".into(),
                "bcc\r\nX-Evil: 1@example.test".into(),
            ],
        );
        let text = String::from_utf8(copy).unwrap();
        assert!(text.starts_with("X-Rmail-Journal: inbound; domain=example.test\r\n"));
        assert!(
            text.contains("X-Rmail-Journal-Recipient: <bccX-Evil: 1@example.test>\r\n"),
            "no header injection"
        );
        assert!(text.ends_with("Subject: hi\r\n\r\nbody"));
    }
}
