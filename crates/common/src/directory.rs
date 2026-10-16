//! The global address list: everyone (and every group address) in a
//! domain, for the people in it.
//!
//! - Off unless an administrator turns it on for a domain, since not every
//!   server's users belong together.
//! - Each user of an enabled domain gets a read-only address book named
//!   [`DIRECTORY_NAME`] in their own store, kept in step by webmail's
//!   background task. CardDAV clients therefore see it like any other
//!   address book, and compose suggestions (which read every address book)
//!   offer its entries without anything else.
//! - Entries are the domain's mailboxes, named after their JMAP identity
//!   (the name the user signs mail with) when they set one, and its aliases
//!   with targets (a group when there are several).

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};

use crate::dav::store::{self, DIRECTORY_NAME, Kind};

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS directory_domains (
        domain TEXT PRIMARY KEY
    );
";

fn open(db: &Path) -> Result<crate::sqlite_pool::SqliteConnection> {
    let conn = crate::sqlite_pool::connection(db)?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

/// Turn the directory on or off for a domain.
pub fn set_enabled(db: &Path, domain: &str, enabled: bool) -> Result<()> {
    let domain = crate::domain::canonicalize_domain(domain.trim())?;
    let conn = open(db)?;
    if enabled {
        conn.execute(
            "INSERT OR IGNORE INTO directory_domains (domain) VALUES (?1)",
            params![domain],
        )?;
    } else {
        conn.execute(
            "DELETE FROM directory_domains WHERE domain = ?1",
            params![domain],
        )?;
    }
    Ok(())
}

pub fn enabled_domains(db: &Path) -> Result<Vec<String>> {
    let conn = open(db)?;
    let mut stmt = conn.prepare("SELECT domain FROM directory_domains ORDER BY domain")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub address: String,
    pub name: String,
    /// The vCard `KIND` (RFC 6350 6.1.4, RFC 6869): `individual`, `group`
    /// (an alias reaching several people), `location` (a room) or `device`
    /// (equipment).
    pub kind: &'static str,
}

/// The name an account signs its mail with, if it set one.
fn identity_name(mail_root: &Path, address: &str) -> Option<String> {
    let (local, domain) = address.split_once('@')?;
    let path = crate::imap_state::account_maildir(mail_root, domain, local);
    if !path.exists() {
        return None;
    }
    let conn = crate::jmap::store::open(mail_root, domain, local).ok()?;
    conn.query_row(
        "SELECT name FROM jmap_identities WHERE lower(email) = lower(?1) AND name != '' ORDER BY id LIMIT 1",
        params![address],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .ok()
    .flatten()
}

/// Everyone in `domain`, by address.
pub fn entries(db: &Path, mail_root: &Path, domain: &str) -> Result<Vec<Entry>> {
    let domain = domain.to_ascii_lowercase();
    let in_domain = |address: &str| {
        address
            .rsplit_once('@')
            .is_some_and(|(_, d)| d.eq_ignore_ascii_case(&domain))
    };
    let resources: BTreeMap<String, crate::resources::ResourceKind> =
        crate::resources::list(db, Some(&domain))?
            .into_iter()
            .collect();
    let mut found: BTreeMap<String, Entry> = BTreeMap::new();
    for mailbox in crate::db::list_mailboxes(db)? {
        let address = mailbox.address.to_ascii_lowercase();
        if !in_domain(&address) {
            continue;
        }
        let name = identity_name(mail_root, &address).unwrap_or_default();
        found.insert(
            address.clone(),
            Entry {
                kind: match resources.get(&address) {
                    Some(crate::resources::ResourceKind::Room) => "location",
                    Some(crate::resources::ResourceKind::Equipment) => "device",
                    None => "individual",
                },
                address,
                name,
            },
        );
    }
    for (alias, targets) in crate::db::list_aliases(db)? {
        let address = alias.to_ascii_lowercase();
        if !in_domain(&address) || targets.is_empty() || found.contains_key(&address) {
            continue;
        }
        found.insert(
            address.clone(),
            Entry {
                address,
                name: String::new(),
                kind: if targets.len() > 1 {
                    "group"
                } else {
                    "individual"
                },
            },
        );
    }
    Ok(found.into_values().collect())
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace(',', "\\,")
        .replace(';', "\\;")
        .replace(['\r', '\n'], " ")
}

/// The vCard for an entry (vCard 4: groups are `KIND:group`).
fn card(entry: &Entry) -> String {
    let shown = if entry.name.trim().is_empty() {
        entry
            .address
            .split('@')
            .next()
            .unwrap_or(&entry.address)
            .to_string()
    } else {
        entry.name.trim().to_string()
    };
    let mut lines = vec![
        "BEGIN:VCARD".to_string(),
        "VERSION:4.0".to_string(),
        format!("UID:urn:rmail:directory:{}", entry.address),
        format!("FN:{}", escape(&shown)),
        format!("EMAIL;TYPE=work:{}", entry.address),
    ];
    if entry.kind != "individual" {
        lines.push(format!("KIND:{}", entry.kind));
    }
    lines.push("END:VCARD".to_string());
    lines.join("\r\n") + "\r\n"
}

fn resource_name(address: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(address.as_bytes());
    format!(
        "{}.vcf",
        digest[..12]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

/// Bring one account's directory book in step with `entries` (or remove
/// it with `None`, when its domain does not share one). Unchanged cards
/// are left alone, and so is an address book of the user's own that has
/// the name.
pub fn sync(conn: &Connection, entries: Option<&[Entry]>) -> Result<(usize, usize)> {
    let existing = store::collection(conn, Kind::AddressBook, DIRECTORY_NAME)?;
    if existing
        .as_ref()
        .is_some_and(|collection| !collection.managed)
    {
        return Ok((0, 0));
    }
    let Some(entries) = entries else {
        if let Some(collection) = existing {
            store::delete_collection(conn, &collection)?;
        }
        return Ok((0, 0));
    };
    let collection = match existing {
        Some(collection) => collection,
        None => store::create_managed(
            conn,
            Kind::AddressBook,
            DIRECTORY_NAME,
            Some("Directory"),
            &[],
        )?,
    };
    let wanted: BTreeMap<String, String> = entries
        .iter()
        .map(|entry| (resource_name(&entry.address), card(entry)))
        .collect();
    let current = store::objects(conn, &collection)?;
    let mut removed = 0;
    for object in &current {
        if !wanted.contains_key(&object.name)
            && matches!(
                store::delete(conn, &collection, &object.name, &|_| true)?,
                store::Deleted::Deleted(_)
            )
        {
            removed += 1;
        }
    }
    let mut stored = 0;
    for (name, data) in &wanted {
        if current
            .iter()
            .any(|object| &object.name == name && &object.data == data)
        {
            continue;
        }
        if store::put(conn, &collection, name, data, &|_| true)?.is_ok() {
            stored += 1;
        }
    }
    Ok((stored, removed))
}

/// Sync every account's directory book: the domain's entries where it is
/// on, none where it is off. Returns the accounts that could not be synced
/// (with why), which keep their book as it was.
pub fn sync_all(db: &Path, mail_root: &Path) -> Result<Vec<String>> {
    let enabled = enabled_domains(db)?;
    let mut by_domain: BTreeMap<String, Vec<Entry>> = BTreeMap::new();
    for domain in &enabled {
        by_domain.insert(domain.clone(), entries(db, mail_root, domain)?);
    }
    let mut failed = Vec::new();
    for (domain, localpart, _) in crate::imap_state::list_accounts(mail_root)? {
        let entries = by_domain
            .get(&domain.to_ascii_lowercase())
            .map(Vec::as_slice);
        let synced = crate::jmap::store::open(mail_root, &domain, &localpart)
            .and_then(|conn| sync(&conn, entries));
        if let Err(error) = synced {
            failed.push(format!("{localpart}@{domain}: {error:#}"));
        }
    }
    Ok(failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_directory_lists_a_domain_for_its_people_only_when_on() {
        let td = tempfile::tempdir().unwrap();
        let db = td.path().join("accounts.sqlite");
        let root = td.path().join("mail");
        crate::db::init_db(&db).unwrap();
        for address in ["ann@example.test", "bob@example.test", "eve@other.test"] {
            crate::db::add_mailbox(&db, address, None, None, None).unwrap();
            let (local, domain) = address.split_once('@').unwrap();
            crate::imap_state::init_account(&root, domain, local).unwrap();
        }
        crate::db::add_alias(
            &db,
            "team@example.test",
            &["ann@example.test", "bob@example.test"],
        )
        .unwrap();
        crate::db::add_alias(&db, "sales@example.test", &["ann@example.test"]).unwrap();
        let ann = crate::jmap::store::open(&root, "example.test", "ann").unwrap();
        ann.execute(
            "INSERT INTO jmap_identities(id, name, email, text_signature, html_signature) VALUES ('1', 'Ann Lee', 'ann@example.test', '', '')",
            [],
        )
        .unwrap();

        let list = entries(&db, &root, "example.test").unwrap();
        assert_eq!(
            list.iter().map(|e| e.address.as_str()).collect::<Vec<_>>(),
            [
                "ann@example.test",
                "bob@example.test",
                "sales@example.test",
                "team@example.test"
            ]
        );
        assert_eq!(list[0].name, "Ann Lee");
        assert_eq!((list[3].kind, list[2].kind), ("group", "individual"));
        crate::db::add_mailbox(&db, "room1@example.test", None, None, None).unwrap();
        crate::resources::set(
            &db,
            "room1@example.test",
            Some(crate::resources::ResourceKind::Room),
        )
        .unwrap();
        let room = entries(&db, &root, "example.test")
            .unwrap()
            .into_iter()
            .find(|e| e.address == "room1@example.test")
            .unwrap();
        assert_eq!(room.kind, "location");
        crate::db::remove_mailbox(&db, "room1@example.test").unwrap();

        // Off by default: nobody gets a directory book.
        sync_all(&db, &root).unwrap();
        assert!(
            store::collection(&ann, Kind::AddressBook, DIRECTORY_NAME)
                .unwrap()
                .is_none()
        );
        set_enabled(&db, "Example.TEST", true).unwrap();
        sync_all(&db, &root).unwrap();
        let book = store::collection(&ann, Kind::AddressBook, DIRECTORY_NAME)
            .unwrap()
            .unwrap();
        let cards = store::objects(&ann, &book).unwrap();
        assert_eq!(cards.len(), 4);
        assert!(cards.iter().any(|c| c.data.contains("FN:Ann Lee")));
        assert!(cards.iter().any(|c| c.data.contains("KIND:group")));
        let eve = crate::jmap::store::open(&root, "other.test", "eve").unwrap();
        assert!(
            store::collection(&eve, Kind::AddressBook, DIRECTORY_NAME)
                .unwrap()
                .is_none(),
            "other domains do not see it"
        );
        // Compose suggestions see the directory.
        let suggested =
            crate::compose_store::suggestions(&root, "example.test", "bob", "ann", 5).unwrap();
        assert!(
            suggested
                .iter()
                .any(|c| c.email == "ann@example.test" && c.name == "Ann Lee")
        );

        // Changes follow; turning it off removes the book.
        crate::db::remove_alias(&db, "sales@example.test").unwrap();
        let (_, removed) = sync(&ann, Some(&entries(&db, &root, "example.test").unwrap())).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(
            sync(&ann, Some(&entries(&db, &root, "example.test").unwrap())).unwrap(),
            (0, 0)
        );
        set_enabled(&db, "example.test", false).unwrap();
        assert!(sync_all(&db, &root).unwrap().is_empty());
        assert!(
            store::collection(&ann, Kind::AddressBook, DIRECTORY_NAME)
                .unwrap()
                .is_none()
        );

        // An address book of the user's own by that name stays theirs.
        let own = store::create(&ann, Kind::AddressBook, DIRECTORY_NAME, None, &[]).unwrap();
        store::put(
            &ann,
            &own,
            "mine.vcf",
            "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:mine\r\nFN:Mine\r\nEND:VCARD\r\n",
            &|_| true,
        )
        .unwrap()
        .unwrap();
        sync_all(&db, &root).unwrap();
        set_enabled(&db, "example.test", true).unwrap();
        sync_all(&db, &root).unwrap();
        let kept = store::collection(&ann, Kind::AddressBook, DIRECTORY_NAME)
            .unwrap()
            .unwrap();
        assert!(!kept.managed);
        assert_eq!(store::objects(&ann, &kept).unwrap().len(), 1);
    }
}
