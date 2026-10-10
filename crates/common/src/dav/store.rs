//! Calendars and address books in each account's state database.
//!
//! - `dav_collections`: one row per calendar or address book. `sync_seq`
//!   counts the collection's changes; it is the CalDAV `getctag` and the
//!   number in its RFC 6578 sync token.
//! - `dav_objects`: one row per calendar object or vCard, stored as sent so
//!   its ETag stays stable. A deleted object stays as a tombstone so
//!   `sync-collection` can report it; tombstones older than 90 days are
//!   forgotten and older sync tokens then answer `valid-sync-token`.
//! - Scheduling (RFC 6638): objects the account organizes or attends carry
//!   a schedule tag; the schedule inbox is a hidden collection of kind
//!   `schedule-inbox` holding the scheduling messages delivered to the
//!   account, which may share UIDs.

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
            schedule_tag TEXT,
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
    /// The schedule inbox (RFC 6638 2.2), not a calendar of the user's.
    pub inbox: bool,
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
        kind: if kind == "addressbook" {
            Kind::AddressBook
        } else {
            Kind::Calendar
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
        inbox: kind == INBOX_KIND,
    })
}

/// The `kind` of the schedule inbox row; `collections` never lists it.
const INBOX_KIND: &str = "schedule-inbox";

/// The most scheduling messages kept in the inbox; older ones go first.
const MAX_INBOX: i64 = 500;

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

/// The account's schedule inbox, created on first use.
pub fn inbox(conn: &Connection) -> Result<Collection> {
    conn.execute(
        "INSERT OR IGNORE INTO dav_collections(kind, name, displayname, components)
         VALUES(?1, 'inbox', 'Inbox', 'VEVENT,VTODO')",
        params![INBOX_KIND],
    )?;
    Ok(conn.query_row(
        &format!("SELECT {COLLECTION_COLUMNS} FROM dav_collections WHERE kind = ?1"),
        params![INBOX_KIND],
        row_to_collection,
    )?)
}

/// Deliver a scheduling message to the inbox; returns its name.
pub fn inbox_add(conn: &Connection, data: &str) -> Result<String> {
    let inbox = inbox(conn)?;
    let root = text::parse(data)?;
    let component = root
        .components
        .iter()
        .find(|component| component.name != "VTIMEZONE")
        .map(|component| component.name.clone());
    let (start, end) = text::time_bounds(&root);
    let name = format!("{}.ics", random_token());
    let tx = write_transaction(conn)?;
    let seq = bump(&tx, &inbox)?;
    tx.execute(
        "INSERT INTO dav_objects(collection_id, name, uid, etag, data, component, start_at, end_at,
             modseq, modified, deleted)
         VALUES(?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, ?8, strftime('%s','now'), 0)",
        params![inbox.id, name, etag(data), data, component, start, end, seq],
    )?;
    // Keep the newest messages only; the dropped ones become tombstones.
    tx.execute(
        "UPDATE dav_objects SET deleted = 1, data = '', modseq = ?2
         WHERE collection_id = ?1 AND deleted = 0 AND name IN (
             SELECT name FROM dav_objects WHERE collection_id = ?1 AND deleted = 0
             ORDER BY modseq DESC LIMIT -1 OFFSET ?3)",
        params![inbox.id, seq, MAX_INBOX],
    )?;
    tx.commit()?;
    Ok(name)
}

/// The calendar object with this UID in any of the account's calendars.
pub fn find_by_uid(conn: &Connection, uid: &str) -> Result<Option<(Collection, Object)>> {
    for collection in collections(conn, Kind::Calendar)? {
        let found = conn
            .query_row(
                &format!(
                    "SELECT {OBJECT_COLUMNS} FROM dav_objects
                     WHERE collection_id = ?1 AND uid = ?2 AND deleted = 0"
                ),
                params![collection.id, uid],
                row_to_object,
            )
            .optional()?;
        if let Some(object) = found {
            return Ok(Some((collection, object)));
        }
    }
    Ok(None)
}

/// Where scheduling messages for the account land when it has no copy of
/// the event yet (RFC 6638 9.2): the default calendar, else the first that
/// takes events. Recreated if the account deleted every calendar.
pub fn default_calendar(conn: &Connection) -> Result<Collection> {
    let calendars = collections(conn, Kind::Calendar)?;
    let takes_events = |collection: &&Collection| {
        collection.components.is_empty() || collection.components.iter().any(|c| c == "VEVENT")
    };
    if let Some(found) = calendars
        .iter()
        .filter(takes_events)
        .find(|collection| collection.name == "default")
        .or_else(|| calendars.iter().find(takes_events))
    {
        return Ok(found.clone());
    }
    let name = if calendars.iter().any(|c| c.name == "default") {
        format!("calendar-{}", random_token())
    } else {
        "default".to_string()
    };
    create(
        conn,
        Kind::Calendar,
        &name,
        Some("Calendar"),
        &["VEVENT", "VTODO"],
    )
}

fn random_token() -> String {
    (0..12)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect()
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
    /// The RFC 6638 schedule tag of a scheduling object.
    pub schedule_tag: Option<String>,
}

const OBJECT_COLUMNS: &str =
    "name, uid, etag, data, component, start_at, end_at, modseq, modified, schedule_tag";

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
        schedule_tag: row.get(9)?,
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
    /// The request's If-Match/If-None-Match does not hold for the object as
    /// it is now.
    PreconditionFailed,
}

/// A request precondition, checked against the object as it is (`None`
/// when it does not exist) inside the write transaction, so a concurrent
/// change between reading and writing cannot slip past it.
pub type Precondition<'a> = &'a dyn Fn(Option<&Object>) -> bool;

/// What a conditional delete did; a deletion returns what was deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deleted {
    Deleted(Box<Object>),
    NotFound,
    PreconditionFailed,
}

/// What becomes of an object's schedule tag on a write (RFC 6638 3.2.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleTag {
    /// Not a scheduling object: no tag.
    None,
    /// The server merged a reply into it: the tag stays.
    Keep,
    /// The organizer or attendee changed it: a new tag.
    New,
}

/// The data a write stores, made from the object as it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    pub data: String,
    pub schedule_tag: ScheduleTag,
}

/// A stored object: its ETag and schedule tag, whether it was created, and
/// the version it replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub etag: String,
    pub schedule_tag: Option<String>,
    pub created: bool,
    pub previous: Option<Object>,
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

/// Store an object as sent; returns its new ETag and whether it was
/// created.
pub fn put(
    conn: &Connection,
    collection: &Collection,
    name: &str,
    data: &str,
    precondition: Precondition<'_>,
) -> Result<std::result::Result<(String, bool), PutError>> {
    Ok(put_with(conn, collection, name, &mut |current| {
        if !precondition(current) {
            return Err(PutError::PreconditionFailed);
        }
        Ok(Prepared {
            data: data.to_string(),
            schedule_tag: ScheduleTag::Keep,
        })
    })?
    .map(|stored| (stored.etag, stored.created)))
}

/// Store an object whose data `prepare` makes from the current version,
/// inside the write transaction: preconditions and scheduling changes see
/// exactly the version they replace.
pub fn put_with(
    conn: &Connection,
    collection: &Collection,
    name: &str,
    prepare: &mut dyn FnMut(Option<&Object>) -> std::result::Result<Prepared, PutError>,
) -> Result<std::result::Result<Stored, PutError>> {
    if !valid_name(name) {
        return Ok(Err(PutError::InvalidData(
            "invalid resource name".to_string(),
        )));
    }
    let tx = write_transaction(conn)?;
    let current = object(&tx, collection, name)?;
    let prepared = match prepare(current.as_ref()) {
        Ok(prepared) => prepared,
        Err(error) => return Ok(Err(error)),
    };
    let parsed = match validate(collection, &prepared.data) {
        Ok(parsed) => parsed,
        Err(error) => return Ok(Err(error)),
    };
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
    let schedule_tag = match prepared.schedule_tag {
        ScheduleTag::None => None,
        ScheduleTag::Keep => current
            .as_ref()
            .and_then(|object| object.schedule_tag.clone()),
        ScheduleTag::New => Some(format!("\"{}\"", random_token())),
    };
    let seq = bump(&tx, collection)?;
    let tag = etag(&prepared.data);
    tx.execute(
        "INSERT INTO dav_objects(collection_id, name, uid, etag, data, component, start_at, end_at,
             modseq, modified, deleted, schedule_tag)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, strftime('%s','now'), 0, ?10)
         ON CONFLICT(collection_id, name) DO UPDATE SET uid = excluded.uid, etag = excluded.etag,
             data = excluded.data, component = excluded.component, start_at = excluded.start_at,
             end_at = excluded.end_at, modseq = excluded.modseq, modified = excluded.modified,
             deleted = 0, schedule_tag = excluded.schedule_tag",
        params![
            collection.id,
            name,
            parsed.uid,
            tag,
            prepared.data,
            parsed.component,
            parsed.start,
            parsed.end,
            seq,
            schedule_tag
        ],
    )?;
    tx.commit()?;
    Ok(Ok(Stored {
        etag: tag,
        schedule_tag,
        created: current.is_none(),
        previous: current,
    }))
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

/// Delete an object, leaving a tombstone for sync.
pub fn delete(
    conn: &Connection,
    collection: &Collection,
    name: &str,
    precondition: Precondition<'_>,
) -> Result<Deleted> {
    let tx = write_transaction(conn)?;
    let Some(current) = object(&tx, collection, name)? else {
        return Ok(Deleted::NotFound);
    };
    if !precondition(Some(&current)) {
        return Ok(Deleted::PreconditionFailed);
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
    Ok(Deleted::Deleted(Box::new(current)))
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
            Ok((row_to_object(row)?, row.get::<_, i64>(10)? != 0))
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
    fn concurrent_conditional_writes_cannot_both_win() {
        let dir = tempfile::tempdir().unwrap();
        crate::imap_state::init_account(dir.path(), "example.test", "user").unwrap();
        let conn = crate::imap_state::open_account(dir.path(), "example.test", "user").unwrap();
        let calendar = collections(&conn, Kind::Calendar).unwrap().remove(0);
        let (tag, _) = put(&conn, &calendar, "a.ics", &event("a", "Base"), &|_| true)
            .unwrap()
            .unwrap();
        drop(conn);
        // Two clients edit the version they both read.
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles = ["One", "Two"].map(|summary| {
            let root = dir.path().to_path_buf();
            let calendar = calendar.clone();
            let tag = tag.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let conn = crate::imap_state::open_account(&root, "example.test", "user").unwrap();
                barrier.wait();
                put(
                    &conn,
                    &calendar,
                    "a.ics",
                    &event("a", summary),
                    &|current| current.map(|o| o.etag.as_str()) == Some(tag.as_str()),
                )
                .unwrap()
            })
        });
        let outcomes = handles.map(|handle| handle.join().unwrap());
        let wins = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
        assert_eq!(wins, 1, "{outcomes:?}");
        assert!(outcomes.contains(&Err(PutError::PreconditionFailed)));
    }

    #[test]
    fn schedule_tags_and_the_inbox() {
        let (_dir, conn) = conn();
        let calendar = collections(&conn, Kind::Calendar).unwrap().remove(0);
        let write = |data: String, schedule_tag| {
            put_with(&conn, &calendar, "m.ics", &mut |_| {
                Ok(Prepared {
                    data: data.clone(),
                    schedule_tag,
                })
            })
            .unwrap()
            .unwrap()
        };
        let first = write(event("m", "One"), ScheduleTag::New);
        let tag = first.schedule_tag.clone().unwrap();
        assert!(first.created && first.previous.is_none());
        // A merged reply keeps the tag; the user's own change replaces it.
        let kept = write(event("m", "Two"), ScheduleTag::Keep);
        assert_eq!(kept.schedule_tag.as_deref(), Some(tag.as_str()));
        assert!(kept.previous.unwrap().data.contains("SUMMARY:One"));
        let renewed = write(event("m", "Three"), ScheduleTag::New);
        assert_ne!(renewed.schedule_tag.as_deref(), Some(tag.as_str()));
        assert_eq!(
            write(event("m", "Plain"), ScheduleTag::None).schedule_tag,
            None
        );
        let (found, object) = find_by_uid(&conn, "m").unwrap().unwrap();
        assert_eq!((found.id, object.name.as_str()), (calendar.id, "m.ics"));
        assert!(find_by_uid(&conn, "nope").unwrap().is_none());

        // The inbox takes messages with the same UID and is not a calendar.
        let inbox = inbox(&conn).unwrap();
        assert!(inbox.inbox);
        inbox_add(&conn, &event("m", "Invite")).unwrap();
        inbox_add(&conn, &event("m", "Update")).unwrap();
        assert_eq!(objects(&conn, &inbox).unwrap().len(), 2);
        assert!(
            collections(&conn, Kind::Calendar)
                .unwrap()
                .iter()
                .all(|c| !c.inbox)
        );
        assert_eq!(default_calendar(&conn).unwrap().id, calendar.id);
        delete_collection(&conn, &calendar).unwrap();
        let recreated = default_calendar(&conn).unwrap();
        assert!(!recreated.inbox && recreated.id != calendar.id);
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

        let any = |_: Option<&Object>| true;
        let (tag, created) = put(&conn, &calendar, "a.ics", &event("a", "One"), &any)
            .unwrap()
            .unwrap();
        assert!(created && tag.starts_with('"'));
        // A precondition naming an older version is checked under the lock.
        let stale = |current: Option<&Object>| current.is_some_and(|o| o.etag == "\"old\"");
        assert_eq!(
            put(&conn, &calendar, "a.ics", &event("a", "Lost"), &stale).unwrap(),
            Err(PutError::PreconditionFailed)
        );
        let matching = |current: Option<&Object>| current.is_some_and(|o| o.etag == tag);
        let (_, created) = put(&conn, &calendar, "a.ics", &event("a", "Two"), &matching)
            .unwrap()
            .unwrap();
        assert!(!created);
        assert_eq!(
            put(&conn, &calendar, "b.ics", &event("a", "Dup"), &any).unwrap(),
            Err(PutError::UidConflict("a.ics".to_string()))
        );
        assert!(matches!(
            put(
                &conn,
                &calendar,
                "c.ics",
                "BEGIN:VCARD\r\nUID:x\r\nEND:VCARD\r\n",
                &any
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
        assert_eq!(
            delete(&conn, &calendar, "a.ics", &stale).unwrap(),
            Deleted::PreconditionFailed
        );
        assert!(matches!(
            delete(&conn, &calendar, "a.ics", &any).unwrap(),
            Deleted::Deleted(old) if old.data.contains("SUMMARY:Two")
        ));
        assert_eq!(
            delete(&conn, &calendar, "a.ics", &any).unwrap(),
            Deleted::NotFound
        );
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
