//! What each device has been sent, per account (`rmail-eas.sqlite` in the
//! account directory): stable folder ids, the folder list and, per folder,
//! the messages and flags last sent under each sync key. A sync key moves
//! on with every response; the previous one is kept, so a device that lost
//! a response can ask again.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};

/// What a device was sent of one folder: UID -> flags it was told
/// (`S` read, `F` flagged).
pub type Snapshot = BTreeMap<u64, String>;

/// A device's folder list: id -> (parent id, name, type).
pub type FolderList = BTreeMap<String, (String, String, u8)>;

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS folder_ids (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE
    );
    CREATE TABLE IF NOT EXISTS devices (
        device_id TEXT PRIMARY KEY,
        device_type TEXT NOT NULL DEFAULT '',
        policy_key TEXT NOT NULL DEFAULT '',
        folder_key INTEGER NOT NULL DEFAULT 0,
        folders TEXT NOT NULL DEFAULT '{}',
        last_sync BLOB,
        ping_folders TEXT NOT NULL DEFAULT '[]',
        ping_interval INTEGER NOT NULL DEFAULT 0,
        last_seen INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS sync_state (
        device_id TEXT NOT NULL,
        collection TEXT NOT NULL,
        sync_key INTEGER NOT NULL,
        snapshot TEXT NOT NULL,
        prev_key INTEGER NOT NULL DEFAULT -1,
        prev_snapshot TEXT NOT NULL DEFAULT '{}',
        filter INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (device_id, collection)
    );
";

pub fn open(account_dir: &Path) -> Result<Connection> {
    std::fs::create_dir_all(account_dir)?;
    let conn = Connection::open(account_dir.join("rmail-eas.sqlite"))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

/// The id a folder is known by to devices (kept across restarts).
pub fn folder_id(conn: &Connection, name: &str) -> Result<String> {
    conn.execute(
        "INSERT OR IGNORE INTO folder_ids (name) VALUES (?1)",
        params![name],
    )?;
    let id: i64 = conn.query_row(
        "SELECT id FROM folder_ids WHERE name = ?1",
        params![name],
        |row| row.get(0),
    )?;
    Ok(id.to_string())
}

pub fn folder_name(conn: &Connection, id: &str) -> Result<Option<String>> {
    let Ok(id) = id.parse::<i64>() else {
        return Ok(None);
    };
    Ok(conn
        .query_row(
            "SELECT name FROM folder_ids WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )
        .optional()?)
}

/// After a rename the new name takes the old id, so devices keep it.
pub fn rename_folder(conn: &Connection, from: &str, to: &str) -> Result<()> {
    // Subfolders move with their parent and keep their ids too.
    conn.execute(
        "UPDATE folder_ids SET name = ?2 || substr(name, length(?1) + 1)
         WHERE name = ?1 OR substr(name, 1, length(?1) + 1) = ?1 || '/'",
        params![from, to],
    )?;
    Ok(())
}

pub fn touch_device(conn: &Connection, device: &str, device_type: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO devices (device_id, device_type, last_seen) VALUES (?1, ?2, strftime('%s','now'))
         ON CONFLICT(device_id) DO UPDATE SET device_type = excluded.device_type, last_seen = excluded.last_seen",
        params![device, device_type],
    )?;
    Ok(())
}

/// The folder list a device holds: (key, id -> [parent, name, type]).
pub fn folders(conn: &Connection, device: &str) -> Result<(i64, FolderList)> {
    let (key, folders): (i64, String) = conn.query_row(
        "SELECT folder_key, folders FROM devices WHERE device_id = ?1",
        params![device],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((key, serde_json::from_str(&folders).unwrap_or_default()))
}

pub fn set_folders(conn: &Connection, device: &str, key: i64, folders: &FolderList) -> Result<()> {
    conn.execute(
        "UPDATE devices SET folder_key = ?2, folders = ?3 WHERE device_id = ?1",
        params![device, key, serde_json::to_string(folders)?],
    )?;
    Ok(())
}

pub fn set_policy_key(conn: &Connection, device: &str, key: &str) -> Result<()> {
    conn.execute(
        "UPDATE devices SET policy_key = ?2 WHERE device_id = ?1",
        params![device, key],
    )?;
    Ok(())
}

/// The last full Sync request, for a device that sends an empty one.
pub fn last_sync(conn: &Connection, device: &str) -> Result<Option<Vec<u8>>> {
    Ok(conn
        .query_row(
            "SELECT last_sync FROM devices WHERE device_id = ?1",
            params![device],
            |row| row.get(0),
        )
        .optional()?
        .flatten())
}

pub fn set_last_sync(conn: &Connection, device: &str, request: &[u8]) -> Result<()> {
    conn.execute(
        "UPDATE devices SET last_sync = ?2 WHERE device_id = ?1",
        params![device, request],
    )?;
    Ok(())
}

pub fn ping(conn: &Connection, device: &str) -> Result<(Vec<String>, u64)> {
    let (folders, interval): (String, i64) = conn.query_row(
        "SELECT ping_folders, ping_interval FROM devices WHERE device_id = ?1",
        params![device],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((
        serde_json::from_str(&folders).unwrap_or_default(),
        interval.max(0) as u64,
    ))
}

pub fn set_ping(conn: &Connection, device: &str, folders: &[String], interval: u64) -> Result<()> {
    conn.execute(
        "UPDATE devices SET ping_folders = ?2, ping_interval = ?3 WHERE device_id = ?1",
        params![device, serde_json::to_string(folders)?, interval as i64],
    )?;
    Ok(())
}

/// A collection's sync state: (key, snapshot, previous key, its snapshot, filter).
pub struct SyncState {
    pub key: i64,
    pub snapshot: Snapshot,
    pub prev_key: i64,
    pub prev_snapshot: Snapshot,
    pub filter: i64,
}

pub fn sync_state(conn: &Connection, device: &str, collection: &str) -> Result<Option<SyncState>> {
    Ok(conn
        .query_row(
            "SELECT sync_key, snapshot, prev_key, prev_snapshot, filter FROM sync_state
             WHERE device_id = ?1 AND collection = ?2",
            params![device, collection],
            |row| {
                Ok(SyncState {
                    key: row.get(0)?,
                    snapshot: serde_json::from_str(&row.get::<_, String>(1)?).unwrap_or_default(),
                    prev_key: row.get(2)?,
                    prev_snapshot: serde_json::from_str(&row.get::<_, String>(3)?)
                        .unwrap_or_default(),
                    filter: row.get(4)?,
                })
            },
        )
        .optional()?)
}

/// Move a collection on to `key` with `snapshot`, keeping `prev` (the key
/// the device just used, with what it then had) for a repeat.
pub fn save_sync(
    conn: &Connection,
    device: &str,
    collection: &str,
    key: i64,
    snapshot: &Snapshot,
    prev: Option<(i64, &Snapshot)>,
    filter: i64,
) -> Result<()> {
    let (prev_key, prev_snapshot) = prev.map_or((-1, String::from("{}")), |(k, s)| {
        (k, serde_json::to_string(s).unwrap_or_default())
    });
    conn.execute(
        "INSERT INTO sync_state (device_id, collection, sync_key, snapshot, prev_key, prev_snapshot, filter)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(device_id, collection) DO UPDATE SET sync_key = excluded.sync_key, snapshot = excluded.snapshot,
             prev_key = excluded.prev_key, prev_snapshot = excluded.prev_snapshot, filter = excluded.filter",
        params![device, collection, key, serde_json::to_string(snapshot)?, prev_key, prev_snapshot, filter],
    )?;
    Ok(())
}

/// Forget a device's state for collections it no longer has.
pub fn forget_collection(conn: &Connection, device: &str, collection: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM sync_state WHERE device_id = ?1 AND collection = ?2",
        params![device, collection],
    )?;
    Ok(())
}

/// A contacts or calendar collection's state: (key, items, previous key,
/// its items), items being ServerId -> ETag.
pub type ItemsState = (i64, Items, i64, Items);
pub type Items = BTreeMap<String, String>;

pub fn items_state(
    conn: &Connection,
    device: &str,
    collection: &str,
) -> Result<Option<ItemsState>> {
    Ok(conn
        .query_row(
            "SELECT sync_key, snapshot, prev_key, prev_snapshot FROM sync_state
             WHERE device_id = ?1 AND collection = ?2",
            params![device, collection],
            |row| {
                Ok((
                    row.get(0)?,
                    serde_json::from_str(&row.get::<_, String>(1)?).unwrap_or_default(),
                    row.get(2)?,
                    serde_json::from_str(&row.get::<_, String>(3)?).unwrap_or_default(),
                ))
            },
        )
        .optional()?)
}

pub fn save_items(
    conn: &Connection,
    device: &str,
    collection: &str,
    key: i64,
    items: &Items,
    prev: Option<(i64, &Items)>,
) -> Result<()> {
    let (prev_key, prev_items) = prev.map_or((-1, String::from("{}")), |(k, s)| {
        (k, serde_json::to_string(s).unwrap_or_default())
    });
    conn.execute(
        "INSERT INTO sync_state (device_id, collection, sync_key, snapshot, prev_key, prev_snapshot, filter)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)
         ON CONFLICT(device_id, collection) DO UPDATE SET sync_key = excluded.sync_key, snapshot = excluded.snapshot,
             prev_key = excluded.prev_key, prev_snapshot = excluded.prev_snapshot",
        params![device, collection, key, serde_json::to_string(items)?, prev_key, prev_items],
    )?;
    Ok(())
}
