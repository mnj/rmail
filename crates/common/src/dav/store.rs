//! Calendars and address books in each account's state database.
//!
//! - `dav_collections`: one row per calendar or address book. `sync_seq`
//!   counts the collection's changes; it is the CalDAV `getctag` and the
//!   number in its RFC 6578 sync token.
//! - `dav_objects`: one row per calendar object or vCard, stored as sent so
//!   its ETag stays stable. A deleted object stays as a tombstone so
//!   `sync-collection` can report it; tombstones older than 90 days are
//!   forgotten and older sync tokens then answer `valid-sync-token`.

use anyhow::{Result, bail};
use rusqlite::{Connection, OptionalExtension, params};

use super::text;

const TOMBSTONE_SECONDS: i64 = 90 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Calendar,
    AddressBook,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Calendar => "calendar",
            Kind::AddressBook => "addressbook",
        }
    }
}

pub(crate) fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS dav_collections(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            name TEXT NOT NULL,
            displayname TEXT,
            description TEXT,
            color TEXT,
            sort_order TEXT,
            timezone TEXT,
            components TEXT,
            sync_seq INTEGER NOT NULL DEFAULT 1,
            min_seq INTEGER NOT NULL DEFAULT 0,
            UNIQUE(kind, name)
        );
        CREATE TABLE IF NOT EXISTS dav_objects(
            collection_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            uid TEXT,
            etag TEXT NOT NULL,
            data TEXT NOT NULL,
            component TEXT,
            start_at INTEGER,
            end_at INTEGER,
            modseq INTEGER NOT NULL,
            modified INTEGER NOT NULL,
            deleted INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(collection_id, name),
            FOREIGN KEY(collection_id) REFERENCES dav_collections(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_dav_objects_uid ON dav_objects(collection_id, uid);
        CREATE INDEX IF NOT EXISTS idx_dav_objects_modseq ON dav_objects(collection_id, modseq);
        ",
    )?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collection {
    pub id: i64,
    pub kind: Kind,
    pub name: String,
    pub displayname: Option<String>,
    pub description: Option<String>,
    pub color: Option<String>,
    pub sort_order: Option<String>,
    pub timezone: Option<String>,
    /// Calendar component types (`VEVENT`, `VTODO`, ...); empty for address
    /// books.
    pub components: Vec<String>,
    pub sync_seq: i64,
    pub min_seq: i64,
}

impl Collection {
    /// The RFC 6578 sync token (a URI). It names the collection too: ids
    /// are never reused, so a token from a deleted collection at the same
    /// URL is refused instead of hiding the difference.
    pub fn sync_token(&self) -> String {
        format!("https://rmail.invalid/sync/{}/{}", self.id, self.sync_seq)
    }
}

/// The sequence number a sync token names, if it is `collection`'s.
pub fn parse_sync_token(collection: &Collection, token: &str) -> Option<i64> {
    let (id, seq) = token
        .strip_prefix("https://rmail.invalid/sync/")?
        .split_once('/')?;
    if id.parse::<i64>().ok()? != collection.id {
        return None;
    }
    seq.parse().ok()
}

/// A write transaction that takes the database lock at once, so checks
/// made inside it (UID conflicts, existence) still hold at commit.
fn write_transaction(conn: &Connection) -> Result<rusqlite::Transaction<'_>> {
    Ok(rusqlite::Transaction::new_unchecked(
        conn,
        rusqlite::TransactionBehavior::Immediate,
    )?)
}

fn row_to_collection(row: &rusqlite::Row<'_>) -> rusqlite::Result<Collection> {
    let kind: String = row.get(1)?;
    let components: Option<String> = row.get(8)?;
    Ok(Collection {
        id: row.get(0)?,
        kind: if kind == "calendar" {
            Kind::Calendar
        } else {
            Kind::AddressBook
        },
        name: row.get(2)?,
        displayname: row.get(3)?,
        description: row.get(4)?,
        color: row.get(5)?,
        sort_order: row.get(6)?,
        timezone: row.get(7)?,
        components: components
            .unwrap_or_default()
            .split(',')
            .filter(|c| !c.is_empty())
            .map(str::to_string)
            .collect(),
        sync_seq: row.get(9)?,
        min_seq: row.get(10)?,
    })
}

const COLLECTION_COLUMNS: &str = "id, kind, name, displayname, description, color, sort_order, timezone, components, sync_seq, min_seq";

/// The account's collections of `kind`, creating a default one the first
/// time the account has none.
pub fn collections(conn: &Connection, kind: Kind) -> Result<Vec<Collection>> {
    let list = || -> Result<Vec<Collection>> {
        let mut statement = conn.prepare(&format!(
            "SELECT {COLLECTION_COLUMNS} FROM dav_collections WHERE kind = ?1 ORDER BY name"
        ))?;
        Ok(statement
            .query_map(params![kind.as_str()], row_to_collection)?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    };
    let found = list()?;
    if !found.is_empty() {
        return Ok(found);
    }
    let marker = format!("dav_defaults_{}", kind.as_str());
    let created_before: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM server_metadata WHERE entry = ?1)",
            params![format!("/private/vendor/rmail/{marker}")],
            |row| row.get(0),
        )
        .unwrap_or(false);
    // Defaults are made once; a user who deletes them keeps it that way.
    if !created_before {
        match kind {
            Kind::Calendar => create(
                conn,
                kind,
                "default",
                Some("Calendar"),
                &["VEVENT", "VTODO"],
            )?,
            Kind::AddressBook => create(conn, kind, "default", Some("Contacts"), &[])?,
        };
        conn.execute(
            "INSERT OR REPLACE INTO server_metadata(entry, value) VALUES(?1, '1')",
            params![format!("/private/vendor/rmail/{marker}")],
        )?;
    }
    list()
}

pub fn collection(conn: &Connection, kind: Kind, name: &str) -> Result<Option<Collection>> {
    collections(conn, kind)?;
    Ok(conn
        .query_row(
            &format!(
                "SELECT {COLLECTION_COLUMNS} FROM dav_collections WHERE kind = ?1 AND name = ?2"
            ),
            params![kind.as_str(), name],
            row_to_collection,
        )
        .optional()?)
}

/// Whether `name` can be a collection or object URL segment.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|c| c.is_control() || c == '/' || c == '\\')
}

pub fn create(
    conn: &Connection,
    kind: Kind,
    name: &str,
    displayname: Option<&str>,
    components: &[&str],
) -> Result<Collection> {
    if !valid_name(name) {
        bail!("invalid collection name");
    }
    conn.execute(
        "INSERT INTO dav_collections(kind, name, displayname, components) VALUES(?1, ?2, ?3, ?4)",
        params![kind.as_str(), name, displayname, components.join(",")],
    )?;
    let id = conn.last_insert_rowid();
    Ok(conn.query_row(
        &format!("SELECT {COLLECTION_COLUMNS} FROM dav_collections WHERE id = ?1"),
        params![id],
        row_to_collection,
    )?)
}

/// A collection property PROPPATCH can change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setting {
    DisplayName,
    Description,
    Color,
    SortOrder,
    Timezone,
}

pub fn set_property(
    conn: &Connection,
    collection: &Collection,
    setting: Setting,
    value: Option<&str>,
) -> Result<()> {
    let column = match setting {
        Setting::DisplayName => "displayname",
        Setting::Description => "description",
        Setting::Color => "color",
        Setting::SortOrder => "sort_order",
        Setting::Timezone => "timezone",
    };
    conn.execute(
        &format!("UPDATE dav_collections SET {column} = ?2, sync_seq = sync_seq + 1 WHERE id = ?1"),
        params![collection.id, value],
    )?;
    Ok(())
}

pub fn delete_collection(conn: &Connection, collection: &Collection) -> Result<()> {
    conn.execute(
        "DELETE FROM dav_collections WHERE id = ?1",
        params![collection.id],
    )?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    pub name: String,
    pub uid: Option<String>,
    pub etag: String,
    pub data: String,
    pub component: Option<String>,
    pub start: Option<i64>,
    pub end: Option<i64>,
    pub modseq: i64,
    pub modified: i64,
}

const OBJECT_COLUMNS: &str = "name, uid, etag, data, component, start_at, end_at, modseq, modified";

fn row_to_object(row: &rusqlite::Row<'_>) -> rusqlite::Result<Object> {
    Ok(Object {
        name: row.get(0)?,
        uid: row.get(1)?,
        etag: row.get(2)?,
        data: row.get(3)?,
        component: row.get(4)?,
        start: row.get(5)?,
        end: row.get(6)?,
        modseq: row.get(7)?,
        modified: row.get(8)?,
    })
}

pub fn objects(conn: &Connection, collection: &Collection) -> Result<Vec<Object>> {
    let mut statement = conn.prepare(&format!(
        "SELECT {OBJECT_COLUMNS} FROM dav_objects WHERE collection_id = ?1 AND deleted = 0
         ORDER BY name"
    ))?;
    Ok(statement
        .query_map(params![collection.id], row_to_object)?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn object(conn: &Connection, collection: &Collection, name: &str) -> Result<Option<Object>> {
    Ok(conn
        .query_row(
            &format!(
                "SELECT {OBJECT_COLUMNS} FROM dav_objects
                 WHERE collection_id = ?1 AND name = ?2 AND deleted = 0"
            ),
            params![collection.id, name],
            row_to_object,
        )
        .optional()?)
}

/// Why a PUT was refused (the RFC 4791/6352 preconditions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutError {
    /// Not iCalendar/vCard, or not one object as the collection needs.
    InvalidData(String),
    /// The component type is not one the calendar accepts.
    UnsupportedComponent,
    /// Another object in the collection has this UID (its name).
    UidConflict(String),
}

/// What a valid object says about itself.
struct Parsed {
    uid: String,
    component: Option<String>,
    start: Option<i64>,
    end: Option<i64>,
}

fn validate(collection: &Collection, data: &str) -> std::result::Result<Parsed, PutError> {
    let root = text::parse(data).map_err(|error| PutError::InvalidData(error.to_string()))?;
    match collection.kind {
        Kind::Calendar => {
            if root.name != "VCALENDAR" {
                return Err(PutError::InvalidData("not a VCALENDAR".to_string()));
            }
            // RFC 4791 4.1: one component type and one UID per resource,
            // besides time zones.
            let parts = root
                .components
                .iter()
                .filter(|component| component.name != "VTIMEZONE")
                .collect::<Vec<_>>();
            let Some(first) = parts.first() else {
                return Err(PutError::InvalidData("no calendar component".to_string()));
            };
            if parts.iter().any(|part| part.name != first.name) {
                return Err(PutError::InvalidData("mixed component types".to_string()));
            }
            let uid = first
                .property("UID")
                .map(|uid| uid.value.trim().to_string())
                .filter(|uid| !uid.is_empty())
                .ok_or_else(|| PutError::InvalidData("missing UID".to_string()))?;
            if parts
                .iter()
                .any(|part| part.property("UID").map(|p| p.value.trim()) != Some(uid.as_str()))
            {
                return Err(PutError::InvalidData(
                    "components with different UIDs".to_string(),
                ));
            }
            if !collection.components.is_empty()
                && !collection.components.iter().any(|kind| kind == &first.name)
            {
                return Err(PutError::UnsupportedComponent);
            }
            let (start, end) = text::time_bounds(&root);
            Ok(Parsed {
                uid,
                component: Some(first.name.clone()),
                start,
                end,
            })
        }
        Kind::AddressBook => {
            if root.name != "VCARD" {
                return Err(PutError::InvalidData("not a VCARD".to_string()));
            }
            let uid = root
                .property("UID")
                .map(|uid| uid.value.trim().to_string())
                .filter(|uid| !uid.is_empty())
                .ok_or_else(|| PutError::InvalidData("missing UID".to_string()))?;
            Ok(Parsed {
                uid,
                component: None,
                start: None,
                end: None,
            })
        }
    }
}

/// A strong ETag for stored content.
fn etag(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data.as_bytes());
    format!(
        "\"{}\"",
        digest[..12]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

/// Store an object; returns its new ETag and whether it was created.
pub fn put(
    conn: &Connection,
    collection: &Collection,
    name: &str,
    data: &str,
) -> Result<std::result::Result<(String, bool), PutError>> {
    if !valid_name(name) {
        return Ok(Err(PutError::InvalidData(
            "invalid resource name".to_string(),
        )));
    }
    let parsed = match validate(collection, data) {
        Ok(parsed) => parsed,
        Err(error) => return Ok(Err(error)),
    };
    let tx = write_transaction(conn)?;
    let conflict: Option<String> = tx
        .query_row(
            "SELECT name FROM dav_objects
             WHERE collection_id = ?1 AND uid = ?2 AND name != ?3 AND deleted = 0",
            params![collection.id, parsed.uid, name],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(other) = conflict {
        return Ok(Err(PutError::UidConflict(other)));
    }
    let existed = object(&tx, collection, name)?.is_some();
    let seq = bump(&tx, collection)?;
    let tag = etag(data);
    tx.execute(
        "INSERT INTO dav_objects(collection_id, name, uid, etag, data, component, start_at, end_at,
             modseq, modified, deleted)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, strftime('%s','now'), 0)
         ON CONFLICT(collection_id, name) DO UPDATE SET uid = excluded.uid, etag = excluded.etag,
             data = excluded.data, component = excluded.component, start_at = excluded.start_at,
             end_at = excluded.end_at, modseq = excluded.modseq, modified = excluded.modified,
             deleted = 0",
        params![
            collection.id,
            name,
            parsed.uid,
            tag,
            data,
            parsed.component,
            parsed.start,
            parsed.end,
            seq
        ],
    )?;
    tx.commit()?;
    Ok(Ok((tag, !existed)))
}

fn bump(conn: &Connection, collection: &Collection) -> Result<i64> {
    conn.execute(
        "UPDATE dav_collections SET sync_seq = sync_seq + 1 WHERE id = ?1",
        params![collection.id],
    )?;
    Ok(conn.query_row(
        "SELECT sync_seq FROM dav_collections WHERE id = ?1",
        params![collection.id],
        |row| row.get(0),
    )?)
}

/// Delete an object, leaving a tombstone for sync; false when absent.
pub fn delete(conn: &Connection, collection: &Collection, name: &str) -> Result<bool> {
    let tx = write_transaction(conn)?;
    if object(&tx, collection, name)?.is_none() {
        return Ok(false);
    }
    let seq = bump(&tx, collection)?;
    tx.execute(
        "UPDATE dav_objects SET deleted = 1, data = '', uid = NULL, modseq = ?3,
             modified = strftime('%s','now')
         WHERE collection_id = ?1 AND name = ?2",
        params![collection.id, name, seq],
    )?;
    // Forget old tombstones; tokens from before them can no longer sync.
    let cutoff = chrono::Utc::now().timestamp() - TOMBSTONE_SECONDS;
    let forgotten: Option<i64> = tx.query_row(
        "SELECT MAX(modseq) FROM dav_objects WHERE collection_id = ?1 AND deleted = 1 AND modified < ?2",
        params![collection.id, cutoff],
        |row| row.get(0),
    )?;
    if let Some(forgotten) = forgotten {
        tx.execute(
            "DELETE FROM dav_objects WHERE collection_id = ?1 AND deleted = 1 AND modseq <= ?2",
            params![collection.id, forgotten],
        )?;
        tx.execute(
            "UPDATE dav_collections SET min_seq = MAX(min_seq, ?2) WHERE id = ?1",
            params![collection.id, forgotten],
        )?;
    }
    tx.commit()?;
    Ok(true)
}

/// A change for `sync-collection`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Changed(Object),
    Deleted(String),
}

/// Changes since `since` (0 for the initial sync, which lists only live
/// objects), or `None` when the token is too old or from the future.
pub fn changes_since(
    conn: &Connection,
    collection: &Collection,
    since: i64,
) -> Result<Option<Vec<Change>>> {
    if since != 0 && (since < collection.min_seq || since > collection.sync_seq) {
        return Ok(None);
    }
    let mut statement = conn.prepare(&format!(
        "SELECT {OBJECT_COLUMNS}, deleted FROM dav_objects
         WHERE collection_id = ?1 AND modseq > ?2 ORDER BY modseq"
    ))?;
    let rows = statement
        .query_map(params![collection.id, since], |row| {
            Ok((row_to_object(row)?, row.get::<_, i64>(9)? != 0))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Some(
        rows.into_iter()
            .filter(|(_, deleted)| since != 0 || !deleted)
            .map(|(object, deleted)| {
                if deleted {
                    Change::Deleted(object.name)
                } else {
                    Change::Changed(object)
                }
            })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> (tempfile::TempDir, crate::sqlite_pool::SqliteConnection) {
        let dir = tempfile::tempdir().unwrap();
        crate::imap_state::init_account(dir.path(), "example.test", "user").unwrap();
        let conn = crate::imap_state::open_account(dir.path(), "example.test", "user").unwrap();
        (dir, conn)
    }

    fn event(uid: &str, summary: &str) -> String {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:{uid}\r\nDTSTART:20261012T090000Z\r\nSUMMARY:{summary}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        )
    }

    #[test]
    fn defaults_are_made_once_and_objects_sync() {
        let (_dir, conn) = conn();
        let calendars = collections(&conn, Kind::Calendar).unwrap();
        assert_eq!(calendars.len(), 1);
        assert_eq!(calendars[0].displayname.as_deref(), Some("Calendar"));
        assert_eq!(collections(&conn, Kind::AddressBook).unwrap().len(), 1);
        let calendar = calendars[0].clone();
        let start = calendar.sync_seq;

        let (tag, created) = put(&conn, &calendar, "a.ics", &event("a", "One"))
            .unwrap()
            .unwrap();
        assert!(created && tag.starts_with('"'));
        let (_, created) = put(&conn, &calendar, "a.ics", &event("a", "Two"))
            .unwrap()
            .unwrap();
        assert!(!created);
        assert_eq!(
            put(&conn, &calendar, "b.ics", &event("a", "Dup")).unwrap(),
            Err(PutError::UidConflict("a.ics".to_string()))
        );
        assert!(matches!(
            put(
                &conn,
                &calendar,
                "c.ics",
                "BEGIN:VCARD\r\nUID:x\r\nEND:VCARD\r\n"
            )
            .unwrap(),
            Err(PutError::InvalidData(_))
        ));
        let calendar = collection(&conn, Kind::Calendar, "default")
            .unwrap()
            .unwrap();
        let since = changes_since(&conn, &calendar, start).unwrap().unwrap();
        assert_eq!(since.len(), 1);
        let middle = calendar.sync_seq;
        assert!(delete(&conn, &calendar, "a.ics").unwrap());
        assert!(!delete(&conn, &calendar, "a.ics").unwrap());
        let calendar = collection(&conn, Kind::Calendar, "default")
            .unwrap()
            .unwrap();
        assert_eq!(
            changes_since(&conn, &calendar, middle).unwrap().unwrap(),
            vec![Change::Deleted("a.ics".to_string())]
        );
        assert!(
            changes_since(&conn, &calendar, 0)
                .unwrap()
                .unwrap()
                .is_empty()
        );
        assert!(
            changes_since(&conn, &calendar, calendar.sync_seq + 5)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            parse_sync_token(&calendar, &calendar.sync_token()),
            Some(calendar.sync_seq)
        );

        // Deleting the defaults does not bring them back.
        delete_collection(&conn, &calendar).unwrap();
        assert!(collections(&conn, Kind::Calendar).unwrap().is_empty());
        // A new collection at the same URL refuses the old one's tokens.
        let old_token = calendar.sync_token();
        let again = create(&conn, Kind::Calendar, "default", None, &["VEVENT"]).unwrap();
        assert_ne!(again.id, calendar.id);
        assert_eq!(parse_sync_token(&again, &old_token), None);
    }
}
