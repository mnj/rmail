pub use crate::maildir::account_maildir;
use crate::maildir::{
    STANDARD_FOLDERS, ensure_maildir, mailbox_dir, message_path, normalize_mailbox_name,
};
use crate::sqlite_pool::SqliteConnection;
use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const STATE_DB_FILENAME: &str = ".rmail-state.sqlite";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    pub name: String,
    pub path: String,
    pub special_use: Option<String>,
    pub subscribed: bool,
    pub uidvalidity: u64,
    pub uidnext: u64,
    pub highest_modseq: u64,
    /// RFC 8474 MAILBOXID: assigned at creation, kept across RENAME, never
    /// reused.
    pub mailbox_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub uid: u64,
    pub path: PathBuf,
    pub flags: Vec<String>,
    pub size: u64,
    pub internaldate: i64,
    pub internaldate_tz: i32,
    pub save_date: i64,
    pub modseq: u64,
    /// RFC 8474 EMAILID: kept across COPY and MOVE, never reused.
    pub email_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderSummary {
    pub folder: Folder,
    pub messages: usize,
    pub unseen: usize,
    /// Messages with the \Deleted flag (IMAP4rev2 STATUS DELETED).
    pub deleted: usize,
    /// Octets in messages with the \Deleted flag (RFC 9208 DELETED-STORAGE).
    pub deleted_size: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QresyncChanges {
    pub vanished_uids: Vec<u64>,
    pub changed_messages: Vec<Message>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageQuotaExceeded {
    pub used: u64,
    pub limit: u64,
    pub requested: u64,
}

impl std::fmt::Display for StorageQuotaExceeded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "storage quota exceeded: {} used + {} requested > {} limit",
            self.used, self.requested, self.limit
        )
    }
}

impl std::error::Error for StorageQuotaExceeded {}

pub fn state_db_path(maildir_root: &Path, domain: &str, localpart: &str) -> PathBuf {
    account_maildir(maildir_root, domain, localpart).join(STATE_DB_FILENAME)
}

pub fn init_account(maildir_root: &Path, domain: &str, localpart: &str) -> Result<()> {
    let root = account_maildir(maildir_root, domain, localpart);
    ensure_maildir(&root)?;
    let conn = open_account(maildir_root, domain, localpart)?;
    ensure_schema(&conn)?;
    ensure_standard_folders(&conn, maildir_root, domain, localpart)?;
    Ok(())
}

pub(crate) fn open_account(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
) -> Result<SqliteConnection> {
    let root = account_maildir(maildir_root, domain, localpart);
    fs::create_dir_all(&root)?;
    let conn = crate::sqlite_pool::connection(&root.join(STATE_DB_FILENAME))?;
    ensure_schema(&conn)?;
    ensure_standard_folders(&conn, maildir_root, domain, localpart)?;
    Ok(conn)
}

fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
        INSERT INTO schema_version(version)
            SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version);
        CREATE TABLE IF NOT EXISTS folders(
            id INTEGER PRIMARY KEY,
            name TEXT UNIQUE,
            path TEXT NOT NULL,
            special_use TEXT,
            subscribed INTEGER NOT NULL,
            uidvalidity INTEGER NOT NULL,
            uidnext INTEGER NOT NULL,
            highest_modseq INTEGER NOT NULL DEFAULT 1,
            new_generation INTEGER NOT NULL DEFAULT 0,
            cur_generation INTEGER NOT NULL DEFAULT 0,
            reconcile_count INTEGER NOT NULL DEFAULT 0,
            mailbox_id TEXT
        );
        CREATE TABLE IF NOT EXISTS messages(
            id INTEGER PRIMARY KEY,
            folder_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            subdir TEXT NOT NULL,
            uid INTEGER NOT NULL,
            flags TEXT NOT NULL,
            size INTEGER NOT NULL,
            internaldate INTEGER NOT NULL,
            internaldate_tz INTEGER NOT NULL DEFAULT 0,
            save_date INTEGER NOT NULL DEFAULT 0,
            modseq INTEGER NOT NULL DEFAULT 1,
            recent INTEGER NOT NULL DEFAULT 0,
            email_id TEXT,
            FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE CASCADE
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_folder_filename
            ON messages(folder_id, filename);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_folder_uid
            ON messages(folder_id, uid);
        CREATE TABLE IF NOT EXISTS expunges(
            folder_id INTEGER NOT NULL,
            uid INTEGER NOT NULL,
            modseq INTEGER NOT NULL,
            PRIMARY KEY(folder_id, uid),
            FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_expunges_folder_modseq
            ON expunges(folder_id, modseq);
        CREATE TABLE IF NOT EXISTS subscriptions(
            name TEXT PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS account_settings(
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            quota_bytes INTEGER
        );
        INSERT OR IGNORE INTO account_settings(singleton, quota_bytes) VALUES(1, NULL);
        CREATE TABLE IF NOT EXISTS server_metadata(
            entry TEXT PRIMARY KEY COLLATE NOCASE,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS mailbox_metadata(
            folder_id INTEGER NOT NULL,
            entry TEXT NOT NULL COLLATE NOCASE,
            value TEXT NOT NULL,
            PRIMARY KEY(folder_id, entry),
            FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE CASCADE
        );
        INSERT OR IGNORE INTO subscriptions(name)
            SELECT name FROM folders WHERE subscribed != 0;
        ",
    )?;
    add_column_if_missing(
        conn,
        "folders",
        "highest_modseq",
        "INTEGER NOT NULL DEFAULT 1",
    )?;
    add_column_if_missing(
        conn,
        "folders",
        "new_generation",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    add_column_if_missing(
        conn,
        "folders",
        "cur_generation",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    add_column_if_missing(
        conn,
        "folders",
        "reconcile_count",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    add_column_if_missing(conn, "messages", "save_date", "INTEGER NOT NULL DEFAULT 0")?;
    conn.execute(
        "UPDATE messages SET save_date = internaldate WHERE save_date = 0",
        [],
    )?;
    add_column_if_missing(conn, "messages", "modseq", "INTEGER NOT NULL DEFAULT 1")?;
    add_column_if_missing(conn, "messages", "recent", "INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_missing(
        conn,
        "messages",
        "internaldate_tz",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_object_ids(conn)?;
    crate::jmap::store::ensure_schema(conn)?;
    let invalid_uidvalidity_ids = {
        let mut statement = conn
            .prepare("SELECT id FROM folders WHERE uidvalidity <= 0 OR uidvalidity > 4294967295")?;
        statement
            .query_map([], |row| row.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for folder_id in invalid_uidvalidity_ids {
        conn.execute(
            "UPDATE folders SET uidvalidity = ?1 WHERE id = ?2",
            params![new_uidvalidity() as i64, folder_id],
        )?;
    }
    Ok(())
}

/// Prefix of generated MAILBOXID values. Object IDs start with a letter so
/// they are never mistaken for numbers or `NIL` (RFC 8474 §3).
const MAILBOX_ID_PREFIX: &str = "F";
/// Prefix of generated EMAILID values.
const EMAIL_ID_PREFIX: &str = "M";

/// Give every folder and message a permanent RFC 8474 object ID.
///
/// Row ids are not usable for this: SQLite reuses the largest rowid after a
/// delete, and a copied message gets a new row. The IDs are 96 random bits,
/// so they are never reused. Rows inserted without an ID get one from the
/// triggers; COPY and MOVE insert the source message's EMAILID explicitly.
fn ensure_object_ids(conn: &Connection) -> Result<()> {
    const OBJECT_ID_SCHEMA_VERSION: i64 = 2;
    let current_version = |conn: &Connection| -> Result<i64> {
        Ok(
            conn.query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })?,
        )
    };
    if current_version(conn)? >= OBJECT_ID_SCHEMA_VERSION {
        return Ok(());
    }
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let migrated = (|| -> Result<()> {
        // Another process may have migrated while this one waited.
        if current_version(conn)? >= OBJECT_ID_SCHEMA_VERSION {
            return Ok(());
        }
        add_column_if_missing(conn, "folders", "mailbox_id", "TEXT")?;
        add_column_if_missing(conn, "messages", "email_id", "TEXT")?;
        conn.execute_batch(&format!(
            "
            UPDATE folders SET mailbox_id = '{MAILBOX_ID_PREFIX}' || lower(hex(randomblob(12)))
                WHERE mailbox_id IS NULL;
            UPDATE messages SET email_id = '{EMAIL_ID_PREFIX}' || lower(hex(randomblob(12)))
                WHERE email_id IS NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS idx_folders_mailbox_id ON folders(mailbox_id);
            CREATE TRIGGER IF NOT EXISTS folders_assign_mailbox_id
                AFTER INSERT ON folders WHEN NEW.mailbox_id IS NULL
            BEGIN
                UPDATE folders SET mailbox_id = '{MAILBOX_ID_PREFIX}' || lower(hex(randomblob(12)))
                    WHERE id = NEW.id;
            END;
            CREATE TRIGGER IF NOT EXISTS messages_assign_email_id
                AFTER INSERT ON messages WHEN NEW.email_id IS NULL
            BEGIN
                UPDATE messages SET email_id = '{EMAIL_ID_PREFIX}' || lower(hex(randomblob(12)))
                    WHERE id = NEW.id;
            END;
            UPDATE schema_version SET version = {OBJECT_ID_SCHEMA_VERSION};
            "
        ))?;
        Ok(())
    })();
    match migrated {
        Ok(()) => conn.execute_batch("COMMIT")?,
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(error);
        }
    }
    Ok(())
}

/// Synchronize the configured storage limit into the account-local state DB.
pub fn set_storage_quota(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    quota_bytes: Option<u64>,
) -> Result<()> {
    let quota_bytes = quota_bytes.map(i64::try_from).transpose()?;
    let conn = open_account(maildir_root, domain, localpart)?;
    conn.execute(
        "UPDATE account_settings SET quota_bytes = ?1 WHERE singleton = 1",
        params![quota_bytes],
    )?;
    Ok(())
}

/// Return indexed storage use and the configured limit for one account.
pub fn storage_quota(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
) -> Result<(u64, Option<u64>)> {
    let conn = open_account(maildir_root, domain, localpart)?;
    let used: i64 = conn.query_row("SELECT COALESCE(SUM(size), 0) FROM messages", [], |row| {
        row.get(0)
    })?;
    let limit: Option<i64> = conn.query_row(
        "SELECT quota_bytes FROM account_settings WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    Ok((u64::try_from(used)?, limit.map(u64::try_from).transpose()?))
}

fn enforce_storage_quota(conn: &Connection, requested: u64) -> Result<()> {
    let limit: Option<i64> = conn.query_row(
        "SELECT quota_bytes FROM account_settings WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let Some(limit) = limit.map(u64::try_from).transpose()? else {
        return Ok(());
    };
    let used = u64::try_from(conn.query_row(
        "SELECT COALESCE(SUM(size), 0) FROM messages",
        [],
        |row| row.get::<_, i64>(0),
    )?)?;
    if used
        .checked_add(requested)
        .is_none_or(|total| total > limit)
    {
        return Err(StorageQuotaExceeded {
            used,
            limit,
            requested,
        }
        .into());
    }
    Ok(())
}

fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", table))?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !columns.iter().any(|name| name == column) {
        conn.execute(
            &format!("ALTER TABLE {} ADD COLUMN {} {}", table, column, definition),
            [],
        )?;
    }
    Ok(())
}

fn ensure_standard_folders(
    conn: &Connection,
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
) -> Result<()> {
    for (name, special) in STANDARD_FOLDERS {
        let dir = mailbox_dir(maildir_root, domain, localpart, name)?;
        ensure_maildir(&dir)?;
        insert_folder(conn, name, &folder_path(name)?, special_use(special), true)?;
    }
    Ok(())
}

fn insert_folder(
    conn: &Connection,
    name: &str,
    path: &str,
    special_use: Option<&str>,
    subscribed: bool,
) -> Result<()> {
    let uidvalidity = new_uidvalidity();
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO folders(name, path, special_use, subscribed, uidvalidity, uidnext, highest_modseq)
         VALUES(?1, ?2, ?3, ?4, ?5, 1, 1)",
        params![
            name,
            path,
            special_use,
            i64::from(subscribed),
            uidvalidity as i64
        ],
    )?;
    conn.execute(
        "UPDATE folders SET path = ?2, special_use = ?3 WHERE name = ?1",
        params![name, path, special_use],
    )?;
    if subscribed && inserted > 0 {
        conn.execute(
            "INSERT OR IGNORE INTO subscriptions(name) VALUES(?1)",
            params![name],
        )?;
    }
    Ok(())
}

fn folder_path(name: &str) -> Result<String> {
    let normalized = normalize_mailbox_name(name)?;
    if normalized.eq_ignore_ascii_case("INBOX") {
        Ok(String::new())
    } else {
        Ok(format!(".{}", normalized))
    }
}

fn special_use(special: &str) -> Option<&str> {
    (!special.is_empty()).then_some(special)
}

fn new_uidvalidity() -> u64 {
    u64::from(rand::random::<u32>().max(1))
}

fn allocatable_uid(value: i64) -> Result<u64> {
    if !(1..i64::from(u32::MAX)).contains(&value) {
        anyhow::bail!("mailbox UID space is exhausted or invalid");
    }
    Ok(value as u64)
}

pub fn list_folders(maildir_root: &Path, domain: &str, localpart: &str) -> Result<Vec<Folder>> {
    let conn = open_account(maildir_root, domain, localpart)?;
    let mut stmt = conn.prepare(
        "SELECT name, path, special_use, subscribed, uidvalidity, uidnext, highest_modseq, mailbox_id
         FROM folders ORDER BY CASE WHEN name = 'INBOX' THEN 0 ELSE 1 END, name COLLATE NOCASE",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(Folder {
            name: row.get(0)?,
            path: row.get(1)?,
            special_use: row.get(2)?,
            subscribed: row.get::<_, i64>(3)? != 0,
            uidvalidity: row.get::<_, i64>(4)? as u64,
            uidnext: row.get::<_, i64>(5)? as u64,
            highest_modseq: row.get::<_, i64>(6)? as u64,
            mailbox_id: row.get(7)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

pub fn list_subscribed_folders(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
) -> Result<Vec<Folder>> {
    Ok(list_folders(maildir_root, domain, localpart)?
        .into_iter()
        .filter(|f| f.subscribed)
        .collect())
}

pub fn list_subscriptions(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
) -> Result<Vec<String>> {
    let conn = open_account(maildir_root, domain, localpart)?;
    let mut statement =
        conn.prepare("SELECT name FROM subscriptions ORDER BY name COLLATE NOCASE")?;
    statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

pub fn create_folder(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
) -> Result<()> {
    create_folder_with_special_use(maildir_root, domain, localpart, mailbox, None)
}

/// Special-use attributes a created mailbox may carry (RFC 6154 §3,
/// CREATE-SPECIAL-USE). \All and \Flagged are virtual views and are not
/// supported for real folders.
pub const CREATABLE_SPECIAL_USES: &[&str] =
    &["\\Archive", "\\Drafts", "\\Junk", "\\Sent", "\\Trash"];

/// Create a mailbox, optionally with a special-use attribute from
/// [`CREATABLE_SPECIAL_USES`] (matched case-insensitively).
pub fn create_folder_with_special_use(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    special_use: Option<&str>,
) -> Result<()> {
    let special_use = match special_use {
        Some(requested) => Some(
            *CREATABLE_SPECIAL_USES
                .iter()
                .find(|known| known.eq_ignore_ascii_case(requested))
                .ok_or_else(|| anyhow::anyhow!("unsupported special-use attribute {requested}"))?,
        ),
        None => None,
    };
    let name = normalize_mailbox_name(mailbox)?;
    let mut conn = open_account(maildir_root, domain, localpart)?;
    if folder_id(&conn, &name)?.is_some() {
        anyhow::bail!("mailbox already exists");
    }
    let directory = mailbox_dir(maildir_root, domain, localpart, &name)?;
    if directory.exists() {
        anyhow::bail!("mailbox directory already exists");
    }
    ensure_maildir(&directory)?;
    let guard = FileMutationGuard::created_directory(directory);
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "INSERT INTO folders(name, path, special_use, subscribed, uidvalidity, uidnext, highest_modseq)
         VALUES(?1, ?2, ?3, 1, ?4, 1, 1)",
        params![
            name,
            folder_path(&name)?,
            special_use,
            new_uidvalidity() as i64
        ],
    )?;
    tx.execute(
        "INSERT OR IGNORE INTO subscriptions(name) VALUES(?1)",
        params![name],
    )?;
    tx.commit()?;
    guard.commit();
    Ok(())
}

pub fn delete_folder(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
) -> Result<()> {
    let name = normalize_mailbox_name(mailbox)?;
    if name.eq_ignore_ascii_case("INBOX") {
        anyhow::bail!("cannot delete INBOX");
    }
    let mut conn = open_account(maildir_root, domain, localpart)?;
    let id = folder_id(&conn, &name)?.context("mailbox does not exist")?;
    let child_prefix = format!("{name}/");
    let has_children = conn
        .query_row(
            "SELECT 1 FROM folders WHERE substr(name, 1, ?1) = ?2 LIMIT 1",
            params![child_prefix.len() as i64, child_prefix],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some();
    if has_children {
        anyhow::bail!("mailbox has children, delete them first");
    }
    let dir = mailbox_dir(maildir_root, domain, localpart, &name)?;
    let tombstone = account_maildir(maildir_root, domain, localpart)
        .join("tmp")
        .join(format!(
            ".mailbox-delete.{}.{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
            rand::random::<u64>()
        ));
    let guard = if dir.exists() {
        fs::rename(&dir, &tombstone)
            .with_context(|| format!("staging mailbox {name} for deletion"))?;
        Some(FileMutationGuard::moved(dir, tombstone.clone()))
    } else {
        None
    };
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute("DELETE FROM folders WHERE id = ?1", params![id])?;
    tx.execute("DELETE FROM subscriptions WHERE name = ?1", params![name])?;
    tx.commit()?;
    if let Some(guard) = guard {
        guard.commit();
        if let Err(error) = fs::remove_dir_all(&tombstone) {
            crate::structured_log!("warn", "storage", "tombstone_cleanup_failed", { "path": tombstone.display().to_string(), "error": error.to_string() });
        }
    }
    Ok(())
}

pub fn rename_folder(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    source_mailbox: &str,
    destination_mailbox: &str,
) -> Result<()> {
    let source = normalize_mailbox_name(source_mailbox)?;
    let destination = normalize_mailbox_name(destination_mailbox)?;
    if source.eq_ignore_ascii_case("INBOX") {
        anyhow::bail!("cannot rename INBOX");
    }
    if source.eq_ignore_ascii_case(&destination) {
        return Ok(());
    }

    let mut conn = open_account(maildir_root, domain, localpart)?;
    let Some(_) = folder_id(&conn, &source)? else {
        anyhow::bail!("source mailbox does not exist");
    };
    let prefix = format!("{source}/");
    let mut mappings = list_folders(maildir_root, domain, localpart)?
        .into_iter()
        .filter_map(|folder| {
            if folder.name.eq_ignore_ascii_case(&source) {
                Some((folder.name, destination.clone()))
            } else if folder.name.starts_with(&prefix) {
                Some((
                    folder.name.clone(),
                    format!("{destination}/{}", &folder.name[prefix.len()..]),
                ))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    mappings.sort_by_key(|left| left.0.len());
    for (_, new_name) in &mappings {
        if let Some(existing_id) = folder_id(&conn, new_name)? {
            let replacing_source = mappings.iter().any(|(old_name, _)| {
                folder_id(&conn, old_name).ok().flatten() == Some(existing_id)
            });
            if !replacing_source {
                anyhow::bail!("destination mailbox already exists");
            }
        }
    }

    let source_dir = mailbox_dir(maildir_root, domain, localpart, &source)?;
    let destination_dir = mailbox_dir(maildir_root, domain, localpart, &destination)?;
    if !source_dir.is_dir() {
        anyhow::bail!("source mailbox directory does not exist");
    }
    if destination_dir.exists() {
        anyhow::bail!("destination mailbox directory already exists");
    }
    fs::rename(&source_dir, &destination_dir)
        .with_context(|| format!("renaming mailbox {source} to {destination}"))?;
    let guard = FileMutationGuard::moved(source_dir, destination_dir);
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for (old_name, new_name) in &mappings {
        tx.execute(
            "DELETE FROM subscriptions WHERE name = ?1 AND EXISTS (
                 SELECT 1 FROM subscriptions WHERE name = ?2
             )",
            params![new_name, old_name],
        )?;
        tx.execute(
            "UPDATE folders SET name = ?1, path = ?2 WHERE name = ?3",
            params![new_name, folder_path(new_name)?, old_name],
        )?;
        tx.execute(
            "UPDATE subscriptions SET name = ?1 WHERE name = ?2",
            params![new_name, old_name],
        )?;
    }
    tx.commit()?;
    guard.commit();
    Ok(())
}

pub fn set_subscription(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    subscribed: bool,
) -> Result<()> {
    let name = normalize_mailbox_name(mailbox)?;
    let conn = open_account(maildir_root, domain, localpart)?;
    if subscribed {
        conn.execute(
            "INSERT OR IGNORE INTO subscriptions(name) VALUES(?1)",
            params![name],
        )?;
    } else {
        conn.execute("DELETE FROM subscriptions WHERE name = ?1", params![name])?;
    }
    conn.execute(
        "UPDATE folders SET subscribed = ?1 WHERE name = ?2",
        params![i64::from(subscribed), name],
    )?;
    Ok(())
}

pub fn folder_exists(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
) -> Result<bool> {
    let name = normalize_mailbox_name(mailbox)?;
    let conn = open_account(maildir_root, domain, localpart)?;
    Ok(folder_id(&conn, &name)?.is_some()
        && mailbox_dir(maildir_root, domain, localpart, &name)?.is_dir())
}

/// The folder named `mailbox`, if it exists.
pub fn find_folder(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
) -> Result<Option<Folder>> {
    let name = normalize_mailbox_name(mailbox)?;
    let conn = open_account(maildir_root, domain, localpart)?;
    if !mailbox_dir(maildir_root, domain, localpart, &name)?.is_dir() {
        return Ok(None);
    }
    get_folder(&conn, &name)
}

/// A SETMETADATA request that would take the account past its entry limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataTooMany {
    pub limit: usize,
}

impl std::fmt::Display for MetadataTooMany {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "too many metadata entries (limit {})",
            self.limit
        )
    }
}

impl std::error::Error for MetadataTooMany {}

/// RFC 5464 annotations of one mailbox, or of the server when `mailbox` is
/// `None`, as `(entry, value)` pairs sorted by entry. Returns `None` when the
/// mailbox does not exist.
pub fn get_metadata(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: Option<&str>,
) -> Result<Option<Vec<(String, String)>>> {
    let conn = open_account(maildir_root, domain, localpart)?;
    let entries = match mailbox {
        None => {
            let mut statement =
                conn.prepare("SELECT entry, value FROM server_metadata ORDER BY entry")?;
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        }
        Some(mailbox) => {
            let name = normalize_mailbox_name(mailbox)?;
            let Some(id) = folder_id(&conn, &name)? else {
                return Ok(None);
            };
            let mut statement = conn.prepare(
                "SELECT entry, value FROM mailbox_metadata WHERE folder_id = ?1 ORDER BY entry",
            )?;
            statement
                .query_map(params![id], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        }
    };
    Ok(Some(entries))
}

/// Apply one SETMETADATA request atomically: `Some(value)` sets an entry and
/// `None` removes it. Entry names compare case-insensitively. Fails with
/// [`MetadataTooMany`] when the account would hold more than `max_entries`
/// entries. Returns `false` when the mailbox does not exist.
pub fn set_metadata(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: Option<&str>,
    changes: &[(String, Option<String>)],
    max_entries: usize,
) -> Result<bool> {
    let mut conn = open_account(maildir_root, domain, localpart)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let folder = match mailbox {
        None => None,
        Some(mailbox) => {
            let name = normalize_mailbox_name(mailbox)?;
            let Some(id) = folder_id(&tx, &name)? else {
                return Ok(false);
            };
            Some(id)
        }
    };
    for (entry, value) in changes {
        match (folder, value) {
            (None, Some(value)) => tx.execute(
                "INSERT INTO server_metadata(entry, value) VALUES(?1, ?2)
                 ON CONFLICT(entry) DO UPDATE SET entry = excluded.entry, value = excluded.value",
                params![entry, value],
            )?,
            (None, None) => tx.execute(
                "DELETE FROM server_metadata WHERE entry = ?1",
                params![entry],
            )?,
            (Some(id), Some(value)) => tx.execute(
                "INSERT INTO mailbox_metadata(folder_id, entry, value) VALUES(?1, ?2, ?3)
                 ON CONFLICT(folder_id, entry)
                 DO UPDATE SET entry = excluded.entry, value = excluded.value",
                params![id, entry, value],
            )?,
            (Some(id), None) => tx.execute(
                "DELETE FROM mailbox_metadata WHERE folder_id = ?1 AND entry = ?2",
                params![id, entry],
            )?,
        };
    }
    let total: i64 = tx.query_row(
        "SELECT (SELECT COUNT(*) FROM server_metadata) + (SELECT COUNT(*) FROM mailbox_metadata)",
        [],
        |row| row.get(0),
    )?;
    let adds_entries = changes.iter().any(|(_, value)| value.is_some());
    if adds_entries && usize::try_from(total).unwrap_or(usize::MAX) > max_entries {
        // Dropping the transaction rolls every change back.
        return Err(MetadataTooMany { limit: max_entries }.into());
    }
    tx.commit()?;
    Ok(true)
}

pub fn claim_recent_uids(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
) -> Result<Vec<u64>> {
    let name = normalize_mailbox_name(mailbox)?;
    let mut conn = open_account(maildir_root, domain, localpart)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    reconcile_folder(&tx, maildir_root, domain, localpart, &name)?;
    let folder_id = folder_id(&tx, &name)?.context("missing folder")?;
    let uids = {
        let mut statement = tx.prepare(
            "SELECT uid FROM messages WHERE folder_id = ?1 AND recent != 0 ORDER BY uid",
        )?;
        statement
            .query_map(params![folder_id], |row| row.get::<_, i64>(0))?
            .map(|uid| uid.map(|uid| uid as u64))
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    tx.execute(
        "UPDATE messages SET recent = 0 WHERE folder_id = ?1 AND recent != 0",
        params![folder_id],
    )?;
    tx.commit()?;
    Ok(uids)
}

pub fn recent_count(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
) -> Result<usize> {
    let name = normalize_mailbox_name(mailbox)?;
    let conn = open_account(maildir_root, domain, localpart)?;
    reconcile_folder(&conn, maildir_root, domain, localpart, &name)?;
    let folder_id = folder_id(&conn, &name)?.context("missing folder")?;
    let count = conn.query_row(
        "SELECT COUNT(*) FROM messages WHERE folder_id = ?1 AND recent != 0",
        params![folder_id],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(count as usize)
}

pub fn load_folder(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
) -> Result<(Folder, Vec<Message>)> {
    let name = normalize_mailbox_name(mailbox)?;
    let conn = open_account(maildir_root, domain, localpart)?;
    ensure_folder(&conn, maildir_root, domain, localpart, &name)?;
    reconcile_folder(&conn, maildir_root, domain, localpart, &name)?;
    let folder = get_folder(&conn, &name)?.context("missing folder after reconcile")?;
    let messages = list_messages_for_folder(&conn, maildir_root, domain, localpart, &folder)?;
    Ok((folder, messages))
}

pub fn set_uid_flags(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    uid: u64,
    flags: Vec<String>,
) -> Result<u64> {
    Ok(
        set_uid_flags_batch(maildir_root, domain, localpart, mailbox, &[(uid, flags)])?
            .into_iter()
            .next()
            .map(|(_, modseq)| modseq)
            .unwrap_or(0),
    )
}

pub fn set_uid_flags_batch(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    updates: &[(u64, Vec<String>)],
) -> Result<Vec<(u64, u64)>> {
    let name = normalize_mailbox_name(mailbox)?;
    let mut conn = open_account(maildir_root, domain, localpart)?;
    ensure_folder(&conn, maildir_root, domain, localpart, &name)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let folder_id = folder_id(&tx, &name)?.context("missing folder")?;
    let mut results = Vec::new();
    let mut seen = HashSet::new();
    for (uid, flags) in updates {
        if !seen.insert(*uid) {
            anyhow::bail!("duplicate UID {uid} in flag update batch");
        }
        let message_exists = tx
            .query_row(
                "SELECT 1 FROM messages WHERE folder_id = ?1 AND uid = ?2",
                params![folder_id, *uid as i64],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        if !message_exists {
            continue;
        }
        let modseq = next_modseq(&tx, folder_id)?;
        tx.execute(
            "UPDATE messages
             SET flags = ?1, modseq = ?2
             WHERE folder_id = ?3 AND uid = ?4",
            params![flags_to_text(flags)?, modseq as i64, folder_id, *uid as i64],
        )?;
        results.push((*uid, modseq));
    }
    tx.commit()?;
    Ok(results)
}

pub fn delete_message_by_uid(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    uid: u64,
) -> Result<()> {
    delete_messages_by_uid(maildir_root, domain, localpart, mailbox, &[uid]).map(|_| ())
}

pub fn delete_messages_by_uid(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    uids: &[u64],
) -> Result<Vec<u64>> {
    let name = normalize_mailbox_name(mailbox)?;
    let mut requested = uids.to_vec();
    requested.sort_unstable();
    requested.dedup();
    if requested.is_empty() {
        return Ok(Vec::new());
    }
    let mut conn = open_account(maildir_root, domain, localpart)?;
    ensure_folder(&conn, maildir_root, domain, localpart, &name)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (deleted, staged) =
        expunge_uids_in_tx(&tx, maildir_root, domain, localpart, &name, &requested)?;
    tx.commit()?;
    finish_expunge(staged);
    Ok(deleted)
}

type ExpungeTombstones = Vec<(FileMutationGuard, PathBuf)>;

/// Expunge messages inside `tx`: each file is moved to a tombstone whose
/// guard restores it unless [`finish_expunge`] runs after the commit.
/// `uids` must be sorted and deduplicated; missing UIDs are skipped.
fn expunge_uids_in_tx(
    tx: &Connection,
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    name: &str,
    uids: &[u64],
) -> Result<(Vec<u64>, ExpungeTombstones)> {
    let dir = mailbox_dir(maildir_root, domain, localpart, name)?;
    let folder_id = folder_id(tx, name)?.context("missing folder")?;
    let mut staged = Vec::new();
    let mut deleted = Vec::new();
    for &uid in uids {
        let Some((filename, subdir)) = tx
            .query_row(
                "SELECT filename, subdir FROM messages WHERE folder_id = ?1 AND uid = ?2",
                params![folder_id, uid as i64],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        else {
            continue;
        };
        let path = message_path(&dir, &subdir, &filename)?;
        if path.exists() {
            let tombstone = dir.join("tmp").join(format!(
                "{}.expunge.{}.{}",
                filename,
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
                rand::random::<u64>()
            ));
            fs::rename(&path, &tombstone)
                .with_context(|| format!("staging message UID {uid} for expunge"))?;
            staged.push((FileMutationGuard::moved(path, tombstone.clone()), tombstone));
        }
        let modseq = next_modseq(tx, folder_id)?;
        record_expunge(tx, folder_id, uid, modseq)?;
        tx.execute(
            "DELETE FROM messages WHERE folder_id = ?1 AND uid = ?2",
            params![folder_id, uid as i64],
        )?;
        deleted.push(uid);
    }
    Ok((deleted, staged))
}

/// Remove the tombstones of a committed expunge.
fn finish_expunge(staged: ExpungeTombstones) {
    for (guard, tombstone) in staged {
        guard.commit();
        if let Err(error) = fs::remove_file(&tombstone) {
            crate::structured_log!("warn", "storage", "tombstone_cleanup_failed", { "path": tombstone.display().to_string(), "error": error.to_string() });
        }
    }
}

enum FileMutationRollback {
    Move {
        source: PathBuf,
        destination: PathBuf,
    },
    Copy {
        destination: PathBuf,
    },
    CreatedDirectory {
        path: PathBuf,
    },
}

struct FileMutationGuard {
    rollback: Option<FileMutationRollback>,
}

impl FileMutationGuard {
    fn moved(source: PathBuf, destination: PathBuf) -> Self {
        Self {
            rollback: Some(FileMutationRollback::Move {
                source,
                destination,
            }),
        }
    }

    fn copied(destination: PathBuf) -> Self {
        Self {
            rollback: Some(FileMutationRollback::Copy { destination }),
        }
    }

    fn created_directory(path: PathBuf) -> Self {
        Self {
            rollback: Some(FileMutationRollback::CreatedDirectory { path }),
        }
    }

    fn commit(mut self) {
        self.rollback = None;
    }
}

impl Drop for FileMutationGuard {
    fn drop(&mut self) {
        match self.rollback.take() {
            Some(FileMutationRollback::Move {
                source,
                destination,
            }) => {
                let _ = fs::rename(destination, source);
            }
            Some(FileMutationRollback::Copy { destination }) => {
                let _ = fs::remove_file(destination);
            }
            Some(FileMutationRollback::CreatedDirectory { path }) => {
                let _ = fs::remove_dir_all(path);
            }
            None => {}
        }
    }
}

/// One mailbox of one account.
#[derive(Debug, Clone, Copy)]
pub struct MailboxRef<'a> {
    pub domain: &'a str,
    pub localpart: &'a str,
    pub mailbox: &'a str,
}

/// COPY or MOVE between two accounts (a shared mailbox and one of the
/// user's own). The messages are copied into the destination as one atomic
/// APPEND batch with their INTERNALDATE and the flags `keep_flag` accepts;
/// MOVE then expunges them from the source. Returns (source UID,
/// destination UID) pairs; UIDs that no longer exist are skipped.
pub fn transfer_messages_between_accounts(
    maildir_root: &Path,
    source: MailboxRef<'_>,
    uids: &[u64],
    destination: MailboxRef<'_>,
    move_messages: bool,
    keep_flag: impl Fn(&str) -> bool,
) -> Result<Vec<(u64, u64)>> {
    let (_, messages) = load_folder(
        maildir_root,
        source.domain,
        source.localpart,
        source.mailbox,
    )?;
    let by_uid = messages
        .iter()
        .map(|message| (message.uid, message))
        .collect::<HashMap<_, _>>();
    let mut requested = uids.to_vec();
    requested.sort_unstable();
    requested.dedup();
    requested.retain(|uid| by_uid.contains_key(uid));
    if requested.is_empty() {
        return Ok(Vec::new());
    }
    let mut staged = Vec::with_capacity(requested.len());
    let stage = |staged: &mut Vec<StagedAppend>, message: &Message| -> Result<()> {
        let path = append_staging_path(maildir_root, destination.domain, destination.localpart)?;
        fs::copy(&message.path, &path).context("copying message to the destination account")?;
        staged.push(StagedAppend {
            path,
            flags: message
                .flags
                .iter()
                .filter(|flag| !flag.eq_ignore_ascii_case("\\Recent") && keep_flag(flag))
                .cloned()
                .collect(),
            internal_date: Some((message.internaldate, message.internaldate_tz)),
        });
        Ok(())
    };
    let mut result = requested
        .iter()
        .try_for_each(|uid| stage(&mut staged, by_uid[uid]));
    let paths = staged
        .iter()
        .map(|item| item.path.clone())
        .collect::<Vec<_>>();
    let published = match result {
        Ok(()) => publish_staged_appends(
            maildir_root,
            destination.domain,
            destination.localpart,
            destination.mailbox,
            staged,
        ),
        Err(error) => Err(error),
    };
    let destination_uids = match published {
        Ok((_, destination_uids)) => destination_uids,
        Err(error) => {
            for path in paths {
                let _ = fs::remove_file(path);
            }
            return Err(error);
        }
    };
    if move_messages {
        result = delete_messages_by_uid(
            maildir_root,
            source.domain,
            source.localpart,
            source.mailbox,
            &requested,
        )
        .map(|_| ());
        result.context("removing moved messages from the source mailbox")?;
    }
    Ok(requested.into_iter().zip(destination_uids).collect())
}

pub fn transfer_messages_by_uid(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    source_mailbox: &str,
    uids: &[u64],
    destination_mailbox: &str,
    move_messages: bool,
) -> Result<Vec<(u64, u64)>> {
    let source = normalize_mailbox_name(source_mailbox)?;
    let destination = normalize_mailbox_name(destination_mailbox)?;
    let mut requested = uids.to_vec();
    requested.sort_unstable();
    requested.dedup();
    if requested.is_empty() {
        return Ok(Vec::new());
    }

    let mut conn = open_account(maildir_root, domain, localpart)?;
    ensure_folder(&conn, maildir_root, domain, localpart, &source)?;
    if folder_id(&conn, &destination)?.is_none() {
        anyhow::bail!("destination mailbox does not exist");
    }
    reconcile_folder(&conn, maildir_root, domain, localpart, &source)?;
    if !source.eq_ignore_ascii_case(&destination) {
        reconcile_folder(&conn, maildir_root, domain, localpart, &destination)?;
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let source_id = folder_id(&tx, &source)?.context("missing source folder")?;
    let destination_id = folder_id(&tx, &destination)?.context("missing destination folder")?;
    if move_messages && source_id == destination_id {
        let mut existing = Vec::new();
        for uid in requested {
            if tx
                .query_row(
                    "SELECT 1 FROM messages WHERE folder_id = ?1 AND uid = ?2",
                    params![source_id, uid as i64],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .is_some()
            {
                existing.push((uid, uid));
            }
        }
        tx.commit()?;
        return Ok(existing);
    }
    if !move_messages {
        let mut requested_bytes = 0u64;
        for uid in &requested {
            let size = tx
                .query_row(
                    "SELECT size FROM messages WHERE folder_id = ?1 AND uid = ?2",
                    params![source_id, *uid as i64],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            if let Some(size) = size {
                requested_bytes = requested_bytes
                    .checked_add(u64::try_from(size)?)
                    .context("COPY size overflow")?;
            }
        }
        enforce_storage_quota(&tx, requested_bytes)?;
    }

    let source_dir = mailbox_dir(maildir_root, domain, localpart, &source)?;
    let destination_dir = mailbox_dir(maildir_root, domain, localpart, &destination)?;
    ensure_maildir(&destination_dir)?;
    let mut destination_uid: i64 = tx.query_row(
        "SELECT uidnext FROM folders WHERE id = ?1",
        params![destination_id],
        |row| row.get(0),
    )?;
    allocatable_uid(destination_uid)?;
    let mut guards = Vec::new();
    let mut mappings = Vec::new();
    for uid in requested {
        let Some((filename, subdir, flags, size, internaldate, internaldate_tz, email_id)) = tx
            .query_row(
                "SELECT filename, subdir, flags, size, internaldate, internaldate_tz, email_id
                 FROM messages WHERE folder_id = ?1 AND uid = ?2",
                params![source_id, uid as i64],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i32>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .optional()?
        else {
            continue;
        };
        let source_path = message_path(&source_dir, &subdir, &filename)?;
        let operation = if move_messages { "moved" } else { "copy" };
        let destination_filename = format!(
            "{}.{}.{}.{}",
            filename,
            operation,
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
            rand::random::<u64>()
        );
        let destination_path = message_path(&destination_dir, &subdir, &destination_filename)?;
        if move_messages {
            fs::rename(&source_path, &destination_path).with_context(|| {
                format!("moving message {uid} from {source_mailbox} to {destination_mailbox}")
            })?;
            guards.push(FileMutationGuard::moved(source_path, destination_path));
        } else {
            fs::copy(&source_path, &destination_path).with_context(|| {
                format!("copying message {uid} from {source_mailbox} to {destination_mailbox}")
            })?;
            guards.push(FileMutationGuard::copied(destination_path));
        }
        let destination_modseq = next_modseq(&tx, destination_id)?;
        allocatable_uid(destination_uid)?;
        tx.execute(
            "INSERT INTO messages(folder_id, filename, subdir, uid, flags, size, internaldate, internaldate_tz, save_date, modseq, email_id)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                destination_id,
                destination_filename,
                subdir,
                destination_uid,
                flags,
                size,
                internaldate,
                internaldate_tz,
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64,
                destination_modseq as i64,
                email_id
            ],
        )?;
        // The source row goes after the destination row exists, so the
        // email never has zero copies: JMAP sees a move, not a deletion
        // and a new email.
        if move_messages {
            let source_modseq = next_modseq(&tx, source_id)?;
            record_expunge(&tx, source_id, uid, source_modseq)?;
            tx.execute(
                "DELETE FROM messages WHERE folder_id = ?1 AND uid = ?2",
                params![source_id, uid as i64],
            )?;
        }
        mappings.push((uid, destination_uid as u64));
        destination_uid = destination_uid.saturating_add(1);
    }
    tx.execute(
        "UPDATE folders SET uidnext = ?1 WHERE id = ?2",
        params![destination_uid, destination_id],
    )?;
    tx.commit()?;
    for guard in guards {
        guard.commit();
    }
    Ok(mappings)
}

pub fn move_message_by_uid(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    source_mailbox: &str,
    uid: u64,
    destination_mailbox: &str,
) -> Result<Option<u64>> {
    let source = normalize_mailbox_name(source_mailbox)?;
    let destination = normalize_mailbox_name(destination_mailbox)?;
    if source.eq_ignore_ascii_case(&destination) {
        return Ok(Some(uid));
    }

    let mut conn = open_account(maildir_root, domain, localpart)?;
    ensure_folder(&conn, maildir_root, domain, localpart, &source)?;
    if folder_id(&conn, &destination)?.is_none() {
        anyhow::bail!("destination mailbox does not exist");
    }
    reconcile_folder(&conn, maildir_root, domain, localpart, &source)?;
    reconcile_folder(&conn, maildir_root, domain, localpart, &destination)?;

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let source_id = folder_id(&tx, &source)?.context("missing source folder")?;
    let destination_id = folder_id(&tx, &destination)?.context("missing destination folder")?;
    let Some((filename, subdir, flags, size, internaldate, internaldate_tz, email_id)) = tx
        .query_row(
            "SELECT filename, subdir, flags, size, internaldate, internaldate_tz, email_id
             FROM messages WHERE folder_id = ?1 AND uid = ?2",
            params![source_id, uid as i64],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i32>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?
    else {
        return Ok(None);
    };

    let source_dir = mailbox_dir(maildir_root, domain, localpart, &source)?;
    let destination_dir = mailbox_dir(maildir_root, domain, localpart, &destination)?;
    ensure_maildir(&destination_dir)?;
    let source_path = message_path(&source_dir, &subdir, &filename)?;
    let mut destination_filename = filename.clone();
    let mut destination_path = message_path(&destination_dir, &subdir, &destination_filename)?;
    if destination_path.exists() {
        destination_filename = format!(
            "{}.moved.{}.{}",
            filename,
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
            rand::random::<u64>()
        );
        destination_path = message_path(&destination_dir, &subdir, &destination_filename)?;
    }
    fs::rename(&source_path, &destination_path).with_context(|| {
        format!(
            "moving message {} from {} to {}",
            uid, source_mailbox, destination_mailbox
        )
    })?;
    let file_guard = FileMutationGuard::moved(source_path, destination_path);

    let source_modseq = next_modseq(&tx, source_id)?;
    record_expunge(&tx, source_id, uid, source_modseq)?;
    tx.execute(
        "DELETE FROM messages WHERE folder_id = ?1 AND uid = ?2",
        params![source_id, uid as i64],
    )?;
    let uidnext: i64 = tx.query_row(
        "SELECT uidnext FROM folders WHERE id = ?1",
        params![destination_id],
        |row| row.get(0),
    )?;
    allocatable_uid(uidnext)?;
    let destination_modseq = next_modseq(&tx, destination_id)?;
    tx.execute(
        "INSERT INTO messages(folder_id, filename, subdir, uid, flags, size, internaldate, internaldate_tz, save_date, modseq, email_id)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            destination_id,
            destination_filename,
            subdir,
            uidnext,
            flags,
            size,
            internaldate,
            internaldate_tz,
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64,
            destination_modseq as i64,
            email_id
        ],
    )?;
    tx.execute(
        "UPDATE folders SET uidnext = ?1 WHERE id = ?2",
        params![uidnext.saturating_add(1), destination_id],
    )?;
    tx.commit()?;
    file_guard.commit();
    Ok(Some(uidnext as u64))
}

pub fn copy_message_by_uid(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    source_mailbox: &str,
    uid: u64,
    destination_mailbox: &str,
) -> Result<Option<u64>> {
    let source = normalize_mailbox_name(source_mailbox)?;
    let destination = normalize_mailbox_name(destination_mailbox)?;

    let mut conn = open_account(maildir_root, domain, localpart)?;
    ensure_folder(&conn, maildir_root, domain, localpart, &source)?;
    if folder_id(&conn, &destination)?.is_none() {
        anyhow::bail!("destination mailbox does not exist");
    }
    reconcile_folder(&conn, maildir_root, domain, localpart, &source)?;
    reconcile_folder(&conn, maildir_root, domain, localpart, &destination)?;

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let source_id = folder_id(&tx, &source)?.context("missing source folder")?;
    let destination_id = folder_id(&tx, &destination)?.context("missing destination folder")?;
    let Some((filename, subdir, flags, size, internaldate, internaldate_tz, email_id)) = tx
        .query_row(
            "SELECT filename, subdir, flags, size, internaldate, internaldate_tz, email_id
             FROM messages WHERE folder_id = ?1 AND uid = ?2",
            params![source_id, uid as i64],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i32>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?
    else {
        return Ok(None);
    };
    enforce_storage_quota(&tx, u64::try_from(size)?)?;

    let source_dir = mailbox_dir(maildir_root, domain, localpart, &source)?;
    let destination_dir = mailbox_dir(maildir_root, domain, localpart, &destination)?;
    ensure_maildir(&destination_dir)?;
    let source_path = message_path(&source_dir, &subdir, &filename)?;
    let uidnext: i64 = tx.query_row(
        "SELECT uidnext FROM folders WHERE id = ?1",
        params![destination_id],
        |row| row.get(0),
    )?;
    allocatable_uid(uidnext)?;
    let destination_filename = format!(
        "{}.copy.{}.{}",
        filename,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
        rand::random::<u64>()
    );
    let destination_path = message_path(&destination_dir, &subdir, &destination_filename)?;
    fs::copy(&source_path, &destination_path).with_context(|| {
        format!(
            "copying message {} from {} to {}",
            uid, source_mailbox, destination_mailbox
        )
    })?;
    let file_guard = FileMutationGuard::copied(destination_path);

    let destination_modseq = next_modseq(&tx, destination_id)?;
    tx.execute(
        "INSERT INTO messages(folder_id, filename, subdir, uid, flags, size, internaldate, internaldate_tz, save_date, modseq, email_id)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            destination_id,
            destination_filename,
            subdir,
            uidnext,
            flags,
            size,
            internaldate,
            internaldate_tz,
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64,
            destination_modseq as i64,
            email_id
        ],
    )?;
    tx.execute(
        "UPDATE folders SET uidnext = ?1 WHERE id = ?2",
        params![uidnext.saturating_add(1), destination_id],
    )?;
    tx.commit()?;
    file_guard.commit();
    Ok(Some(uidnext as u64))
}

pub fn delete_or_trash_message_by_uid(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    uid: u64,
) -> Result<()> {
    let name = normalize_mailbox_name(mailbox)?;
    if name.eq_ignore_ascii_case("Trash") {
        delete_message_by_uid(maildir_root, domain, localpart, &name, uid)
    } else {
        move_message_by_uid(maildir_root, domain, localpart, &name, uid, "Trash").map(|_| ())
    }
}

pub fn uid_to_path(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    uid: u64,
) -> Result<Option<PathBuf>> {
    let (_folder, messages) = load_folder(maildir_root, domain, localpart, mailbox)?;
    Ok(messages.into_iter().find(|m| m.uid == uid).map(|m| m.path))
}

pub fn list_accounts(maildir_root: &Path) -> Result<Vec<(String, String, PathBuf)>> {
    let mut out = Vec::new();
    if !maildir_root.is_dir() {
        return Ok(out);
    }
    for domain in fs::read_dir(maildir_root)? {
        let domain = domain?;
        if !domain.file_type()?.is_dir() {
            continue;
        }
        let domain_name = domain.file_name().to_string_lossy().to_string();
        for local in fs::read_dir(domain.path())? {
            let local = local?;
            if !local.file_type()?.is_dir() {
                continue;
            }
            let maildir = local.path().join("Maildir");
            if maildir.is_dir() {
                out.push((
                    domain_name.clone(),
                    local.file_name().to_string_lossy().to_string(),
                    maildir,
                ));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    Ok(out)
}

pub fn list_folder_summaries(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
) -> Result<Vec<FolderSummary>> {
    let mut summaries = Vec::new();
    for folder in list_folders(maildir_root, domain, localpart)? {
        let (folder, messages) = load_folder(maildir_root, domain, localpart, &folder.name)?;
        let unseen = messages
            .iter()
            .filter(|m| !m.flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen")))
            .count();
        summaries.push(FolderSummary {
            folder,
            messages: messages.len(),
            unseen,
            deleted: count_deleted(&messages),
            deleted_size: deleted_size(&messages),
            size: messages.iter().map(|message| message.size).sum(),
        });
    }
    Ok(summaries)
}

pub fn folder_summary(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
) -> Result<Option<FolderSummary>> {
    let name = normalize_mailbox_name(mailbox)?;
    let conn = open_account(maildir_root, domain, localpart)?;
    if folder_id(&conn, &name)?.is_none()
        || !mailbox_dir(maildir_root, domain, localpart, &name)?.is_dir()
    {
        return Ok(None);
    }
    reconcile_folder(&conn, maildir_root, domain, localpart, &name)?;
    let Some(folder) = get_folder(&conn, &name)? else {
        return Ok(None);
    };
    let messages = list_messages_for_folder(&conn, maildir_root, domain, localpart, &folder)?;
    Ok(Some(FolderSummary {
        unseen: messages
            .iter()
            .filter(|message| {
                !message
                    .flags
                    .iter()
                    .any(|flag| flag.eq_ignore_ascii_case("\\Seen"))
            })
            .count(),
        deleted: count_deleted(&messages),
        deleted_size: deleted_size(&messages),
        size: messages.iter().map(|message| message.size).sum(),
        messages: messages.len(),
        folder,
    }))
}

fn is_deleted(message: &Message) -> bool {
    message
        .flags
        .iter()
        .any(|flag| flag.eq_ignore_ascii_case("\\Deleted"))
}

fn count_deleted(messages: &[Message]) -> usize {
    messages
        .iter()
        .filter(|message| is_deleted(message))
        .count()
}

fn deleted_size(messages: &[Message]) -> u64 {
    messages
        .iter()
        .filter(|message| is_deleted(message))
        .map(|message| message.size)
        .sum()
}

pub fn list_message_metadata(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
) -> Result<Vec<Message>> {
    Ok(load_folder(maildir_root, domain, localpart, mailbox)?.1)
}

pub fn qresync_changes(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    since_modseq: u64,
    known_uids: Option<&[u64]>,
) -> Result<QresyncChanges> {
    let name = normalize_mailbox_name(mailbox)?;
    let conn = open_account(maildir_root, domain, localpart)?;
    ensure_folder(&conn, maildir_root, domain, localpart, &name)?;
    reconcile_folder(&conn, maildir_root, domain, localpart, &name)?;
    let folder = get_folder(&conn, &name)?.context("missing folder")?;
    let folder_id = folder_id(&conn, &name)?.context("missing folder")?;
    let known = known_uids.map(|uids| uids.iter().copied().collect::<HashSet<_>>());
    let mut stmt =
        conn.prepare("SELECT uid FROM expunges WHERE folder_id = ?1 AND modseq > ?2 ORDER BY uid")?;
    let vanished_uids = stmt
        .query_map(params![folder_id, since_modseq as i64], |row| {
            Ok(row.get::<_, i64>(0)? as u64)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .filter(|uid| known.as_ref().is_none_or(|known| known.contains(uid)))
        .collect();
    let changed_messages =
        list_messages_for_folder(&conn, maildir_root, domain, localpart, &folder)?
            .into_iter()
            .filter(|message| {
                message.modseq > since_modseq
                    && known
                        .as_ref()
                        .is_none_or(|known| known.contains(&message.uid))
            })
            .collect();
    Ok(QresyncChanges {
        vanished_uids,
        changed_messages,
    })
}

pub fn append_message(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    data: &[u8],
    flags: Vec<String>,
) -> Result<(u64, u64)> {
    append_message_with_internal_date(maildir_root, domain, localpart, mailbox, data, flags, None)
}

/// Appends a message with an optional RFC INTERNALDATE `(Unix timestamp, UTC offset minutes)`.
pub fn append_message_with_internal_date(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    data: &[u8],
    flags: Vec<String>,
    internal_date: Option<(i64, i32)>,
) -> Result<(u64, u64)> {
    append_message_internal(
        maildir_root,
        domain,
        localpart,
        mailbox,
        data,
        flags,
        internal_date,
        false,
    )
}

/// Deliver an externally received message and make it eligible for one
/// session's `\Recent` claim while enforcing the account storage quota.
pub fn deliver_message(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    data: &[u8],
) -> Result<(u64, u64)> {
    append_message_internal(
        maildir_root,
        domain,
        localpart,
        "INBOX",
        data,
        Vec::new(),
        None,
        true,
    )
}

/// Deliver an externally received message to `mailbox` with `flags`, as
/// [`deliver_message`] does for INBOX (Sieve `fileinto`).
pub fn deliver_message_to(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    data: &[u8],
    flags: Vec<String>,
) -> Result<(u64, u64)> {
    append_message_internal(
        maildir_root,
        domain,
        localpart,
        mailbox,
        data,
        flags,
        None,
        true,
    )
}

fn append_message_internal(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    data: &[u8],
    flags: Vec<String>,
    internal_date: Option<(i64, i32)>,
    recent: bool,
) -> Result<(u64, u64)> {
    let name = normalize_mailbox_name(mailbox)?;
    let mut conn = open_account(maildir_root, domain, localpart)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if folder_id(&tx, &name)?.is_none() {
        anyhow::bail!("destination mailbox does not exist");
    }
    reconcile_folder(&tx, maildir_root, domain, localpart, &name)?;
    enforce_storage_quota(&tx, data.len() as u64)?;

    let dir = mailbox_dir(maildir_root, domain, localpart, &name)?;
    ensure_maildir(&dir)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let (internaldate, internaldate_tz) = internal_date.unwrap_or((now.as_secs() as i64, 0));
    let filename = format!(
        "{}.{}.{}.append",
        now.as_nanos(),
        std::process::id(),
        rand::random::<u64>()
    );
    let tmp_path = dir.join("tmp").join(&filename);
    let new_path = dir.join("new").join(&filename);
    let mut file = fs::File::create(&tmp_path)?;
    let tmp_guard = FileMutationGuard::copied(tmp_path.clone());
    file.write_all(data)?;
    file.sync_all()?;
    set_file_mtime(&tmp_path, internaldate)?;
    fs::rename(&tmp_path, &new_path)?;
    tmp_guard.commit();
    let new_guard = FileMutationGuard::copied(new_path);

    let folder = get_folder(&tx, &name)?.context("missing destination folder")?;
    let folder_id = folder_id(&tx, &name)?.context("missing destination folder")?;
    let uid = allocatable_uid(i64::try_from(folder.uidnext).unwrap_or(i64::MAX))?;
    let modseq = next_modseq(&tx, folder_id)?;
    tx.execute(
        "INSERT INTO messages(folder_id, filename, subdir, uid, flags, size, internaldate, internaldate_tz, save_date, modseq, recent)
         VALUES(?1, ?2, 'new', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            folder_id,
            filename,
            uid as i64,
            flags_to_text(&flags)?,
            data.len() as i64,
            internaldate,
            internaldate_tz,
            now.as_secs() as i64,
            modseq as i64,
            i64::from(recent)
        ],
    )?;
    tx.execute(
        "UPDATE folders SET uidnext = ?1 WHERE id = ?2",
        params![uid.saturating_add(1) as i64, folder_id],
    )?;
    tx.commit()?;
    new_guard.commit();
    Ok((folder.uidvalidity, uid))
}

/// Allocate a unique path for streaming an IMAP APPEND literal without holding
/// the complete message in memory. The path is inside the account Maildir tmp
/// directory and is not visible as a delivered message.
pub fn append_staging_path(maildir_root: &Path, domain: &str, localpart: &str) -> Result<PathBuf> {
    let directory = account_maildir(maildir_root, domain, localpart).join("tmp");
    fs::create_dir_all(&directory)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(directory.join(format!(
        ".append-stage.{}.{}.{}",
        now,
        std::process::id(),
        rand::random::<u64>()
    )))
}

/// Atomically publish a fully written APPEND staging file and index it in the
/// destination mailbox. The staging file must have been allocated by
/// [`append_staging_path`] for the same account.
pub fn publish_staged_append(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    staged_path: &Path,
    flags: Vec<String>,
    internal_date: Option<(i64, i32)>,
) -> Result<(u64, u64)> {
    let (uidvalidity, mut uids) = publish_staged_appends(
        maildir_root,
        domain,
        localpart,
        mailbox,
        vec![StagedAppend {
            path: staged_path.to_path_buf(),
            flags,
            internal_date,
        }],
    )?;
    Ok((uidvalidity, uids.remove(0)))
}

#[derive(Debug)]
pub struct StagedAppend {
    pub path: PathBuf,
    pub flags: Vec<String>,
    pub internal_date: Option<(i64, i32)>,
}

/// Publish a batch of staged APPEND messages atomically. Database changes are
/// committed together and filesystem publication is rolled back if any item
/// fails, as required by IMAP MULTIAPPEND.
pub fn publish_staged_appends(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    staged: Vec<StagedAppend>,
) -> Result<(u64, Vec<u64>)> {
    let metadata = validate_staged_appends(maildir_root, domain, localpart, &staged)?;
    let name = normalize_mailbox_name(mailbox)?;
    let mut conn = open_account(maildir_root, domain, localpart)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (uidvalidity, uids, guards) = publish_staged_in_tx(
        &tx,
        maildir_root,
        domain,
        localpart,
        &name,
        staged,
        &metadata,
    )?;
    tx.commit()?;
    for guard in guards {
        guard.commit();
    }
    Ok((uidvalidity, uids))
}

fn validate_staged_appends(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    staged: &[StagedAppend],
) -> Result<Vec<fs::Metadata>> {
    if staged.is_empty() {
        anyhow::bail!("APPEND batch is empty");
    }
    let expected_parent = account_maildir(maildir_root, domain, localpart).join("tmp");
    let mut metadata = Vec::with_capacity(staged.len());
    for item in staged {
        let valid_stage = item.path.parent() == Some(expected_parent.as_path())
            && item
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".append-stage."));
        if !valid_stage {
            anyhow::bail!("invalid APPEND staging path");
        }
        let item_metadata =
            fs::symlink_metadata(&item.path).context("reading APPEND staging file")?;
        if !item_metadata.is_file() {
            anyhow::bail!("APPEND staging path is not a regular file");
        }
        metadata.push(item_metadata);
    }
    if staged.len() > 1 && metadata.iter().any(|item| item.len() == 0) {
        anyhow::bail!("zero-length MULTIAPPEND message");
    }

    Ok(metadata)
}

/// Move staged files into `name` and index them inside `tx`. The returned
/// guards remove the published files unless committed after `tx` commits.
fn publish_staged_in_tx(
    tx: &Connection,
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    name: &str,
    staged: Vec<StagedAppend>,
    metadata: &[fs::Metadata],
) -> Result<(u64, Vec<u64>, Vec<FileMutationGuard>)> {
    if folder_id(tx, name)?.is_none() {
        anyhow::bail!("destination mailbox does not exist");
    }
    reconcile_folder(tx, maildir_root, domain, localpart, name)?;
    let total_size = metadata.iter().try_fold(0_u64, |total, item| {
        total
            .checked_add(item.len())
            .context("APPEND batch too large")
    })?;
    enforce_storage_quota(tx, total_size)?;

    let directory = mailbox_dir(maildir_root, domain, localpart, name)?;
    ensure_maildir(&directory)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let folder = get_folder(tx, name)?.context("missing destination folder")?;
    let folder_id = folder_id(tx, name)?.context("missing destination folder")?;
    let mut uid = folder.uidnext;
    let mut uids = Vec::with_capacity(staged.len());
    let mut guards = Vec::with_capacity(staged.len());
    for (index, item) in staged.into_iter().enumerate() {
        uid = allocatable_uid(i64::try_from(uid).unwrap_or(i64::MAX))?;
        let (internaldate, internaldate_tz) =
            item.internal_date.unwrap_or((now.as_secs() as i64, 0));
        let filename = format!(
            "{}.{}.{}.{}.append",
            now.as_nanos(),
            std::process::id(),
            index,
            rand::random::<u64>()
        );
        set_file_mtime(&item.path, internaldate)?;
        let new_path = directory.join("new").join(&filename);
        fs::rename(&item.path, &new_path)?;
        guards.push(FileMutationGuard::copied(new_path));
        let modseq = next_modseq(tx, folder_id)?;
        tx.execute(
            "INSERT INTO messages(folder_id, filename, subdir, uid, flags, size, internaldate, internaldate_tz, save_date, modseq)
             VALUES(?1, ?2, 'new', ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                folder_id,
                filename,
                uid as i64,
                flags_to_text(&item.flags)?,
                metadata[index].len() as i64,
                internaldate,
                internaldate_tz,
                now.as_secs() as i64,
                modseq as i64
            ],
        )?;
        uids.push(uid);
        uid = uid.saturating_add(1);
    }
    tx.execute(
        "UPDATE folders SET uidnext = ?1 WHERE id = ?2",
        params![uid as i64, folder_id],
    )?;
    Ok((folder.uidvalidity, uids, guards))
}

/// Outcome of [`replace_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplaceOutcome {
    pub uidvalidity: u64,
    pub uid: u64,
    /// Whether the replaced message was still present and was expunged.
    pub expunged: bool,
}

/// RFC 8508 REPLACE: publish a staged message in `destination` and expunge
/// `source_uid` from `source_mailbox` in one index transaction. The old
/// message is expunged first so that the quota check counts its space as
/// freed; if publishing fails, the expunge is rolled back.
pub fn replace_message(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    source_mailbox: &str,
    source_uid: u64,
    destination: &str,
    staged: StagedAppend,
) -> Result<ReplaceOutcome> {
    let staged = vec![staged];
    let metadata = validate_staged_appends(maildir_root, domain, localpart, &staged)?;
    let source = normalize_mailbox_name(source_mailbox)?;
    let destination = normalize_mailbox_name(destination)?;
    let mut conn = open_account(maildir_root, domain, localpart)?;
    ensure_folder(&conn, maildir_root, domain, localpart, &source)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (expunged, tombstones) =
        expunge_uids_in_tx(&tx, maildir_root, domain, localpart, &source, &[source_uid])?;
    let (uidvalidity, uids, guards) = publish_staged_in_tx(
        &tx,
        maildir_root,
        domain,
        localpart,
        &destination,
        staged,
        &metadata,
    )?;
    tx.commit()?;
    for guard in guards {
        guard.commit();
    }
    finish_expunge(tombstones);
    Ok(ReplaceOutcome {
        uidvalidity,
        uid: uids[0],
        expunged: !expunged.is_empty(),
    })
}

#[cfg(unix)]
fn set_file_mtime(path: &Path, timestamp: i64) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: timestamp,
            tv_nsec: 0,
        },
    ];
    let result = unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), 0) };
    if result == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mtime(_path: &Path, _timestamp: i64) -> Result<()> {
    Ok(())
}

fn ensure_folder(
    conn: &Connection,
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    name: &str,
) -> Result<()> {
    if folder_id(conn, name)?.is_none() {
        ensure_maildir(&mailbox_dir(maildir_root, domain, localpart, name)?)?;
        let special = STANDARD_FOLDERS
            .iter()
            .find(|(folder_name, _)| folder_name.eq_ignore_ascii_case(name))
            .and_then(|(_, special)| special_use(special));
        insert_folder(conn, name, &folder_path(name)?, special, true)?;
    }
    Ok(())
}

pub(crate) fn folder_id(conn: &Connection, name: &str) -> Result<Option<i64>> {
    conn.query_row(
        "SELECT id FROM folders WHERE name = ?1",
        params![name],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

pub(crate) fn get_folder(conn: &Connection, name: &str) -> Result<Option<Folder>> {
    conn.query_row(
        "SELECT name, path, special_use, subscribed, uidvalidity, uidnext, highest_modseq, mailbox_id
         FROM folders WHERE name = ?1",
        params![name],
        |row| {
            Ok(Folder {
                name: row.get(0)?,
                path: row.get(1)?,
                special_use: row.get(2)?,
                subscribed: row.get::<_, i64>(3)? != 0,
                uidvalidity: row.get::<_, i64>(4)? as u64,
                uidnext: row.get::<_, i64>(5)? as u64,
                highest_modseq: row.get::<_, i64>(6)? as u64,
                mailbox_id: row.get(7)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

fn next_modseq(conn: &Connection, folder_id: i64) -> Result<u64> {
    let current: i64 = conn.query_row(
        "SELECT highest_modseq FROM folders WHERE id = ?1",
        params![folder_id],
        |row| row.get(0),
    )?;
    let next = current.saturating_add(1).max(2);
    conn.execute(
        "UPDATE folders SET highest_modseq = ?1 WHERE id = ?2",
        params![next, folder_id],
    )?;
    Ok(next as u64)
}

fn record_expunge(conn: &Connection, folder_id: i64, uid: u64, modseq: u64) -> Result<()> {
    conn.execute(
        "INSERT INTO expunges(folder_id, uid, modseq) VALUES(?1, ?2, ?3)
         ON CONFLICT(folder_id, uid) DO UPDATE SET modseq = excluded.modseq",
        params![folder_id, uid as i64, modseq as i64],
    )?;
    Ok(())
}

pub(crate) fn reconcile_folder(
    conn: &Connection,
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    name: &str,
) -> Result<()> {
    let folder_id = folder_id(conn, name)?.context("missing folder")?;
    let dir = mailbox_dir(maildir_root, domain, localpart, name)?;
    ensure_maildir(&dir)?;
    let new_generation = directory_generation(&dir.join("new"))?;
    let cur_generation = directory_generation(&dir.join("cur"))?;
    let stored_generations = conn.query_row(
        "SELECT new_generation, cur_generation FROM folders WHERE id = ?1",
        params![folder_id],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    if stored_generations == (new_generation, cur_generation) {
        return Ok(());
    }
    let mut disk = Vec::new();
    for subdir in ["new", "cur"] {
        let subpath = dir.join(subdir);
        for entry in fs::read_dir(&subpath)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let filename = entry.file_name().to_string_lossy().to_string();
            let metadata = entry.metadata()?;
            let internaldate = metadata
                .modified()
                .ok()
                .and_then(|mtime| mtime.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            disk.push((
                filename,
                subdir.to_string(),
                metadata.len() as i64,
                internaldate,
            ));
        }
    }
    disk.sort_by(|a, b| a.0.cmp(&b.0));

    let mut existing = HashMap::new();
    let mut stmt = conn.prepare("SELECT filename, uid FROM messages WHERE folder_id = ?1")?;
    for row in stmt.query_map(params![folder_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
    })? {
        let (filename, uid) = row?;
        existing.insert(filename, uid);
    }
    drop(stmt);
    let disk_names = disk
        .iter()
        .map(|(name, _, _, _)| name.clone())
        .collect::<HashSet<_>>();

    for filename in existing.keys() {
        if !disk_names.contains(filename) {
            let modseq = next_modseq(conn, folder_id)?;
            record_expunge(conn, folder_id, existing[filename], modseq)?;
            conn.execute(
                "DELETE FROM messages WHERE folder_id = ?1 AND filename = ?2",
                params![folder_id, filename],
            )?;
        }
    }

    for (filename, subdir, size, internaldate) in disk {
        let updated = conn.execute(
            "UPDATE messages
             SET subdir = ?1, size = ?2
             WHERE folder_id = ?3 AND filename = ?4",
            params![subdir, size, folder_id, filename],
        )?;
        if updated == 0 {
            let uidnext: i64 = conn.query_row(
                "SELECT uidnext FROM folders WHERE id = ?1",
                params![folder_id],
                |row| row.get(0),
            )?;
            allocatable_uid(uidnext)?;
            let modseq = next_modseq(conn, folder_id)?;
            conn.execute(
                "INSERT INTO messages(folder_id, filename, subdir, uid, flags, size, internaldate, save_date, modseq, recent)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    folder_id,
                    filename,
                    subdir,
                    uidnext,
                    "[]",
                    size,
                    internaldate,
                    internaldate,
                    modseq as i64
                    ,i64::from(subdir == "new")
                ],
            )?;
            conn.execute(
                "UPDATE folders SET uidnext = ?1 WHERE id = ?2",
                params![uidnext.saturating_add(1), folder_id],
            )?;
        }
    }
    let new_generation = directory_generation(&dir.join("new"))?;
    let cur_generation = directory_generation(&dir.join("cur"))?;
    conn.execute(
        "UPDATE folders
         SET new_generation = ?1, cur_generation = ?2, reconcile_count = reconcile_count + 1
         WHERE id = ?3",
        params![new_generation, cur_generation, folder_id],
    )?;
    Ok(())
}

fn directory_generation(path: &Path) -> Result<i64> {
    use std::hash::{Hash, Hasher};

    let metadata = fs::metadata(path)?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    metadata.len().hash(&mut hasher);
    metadata.modified()?.hash(&mut hasher);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.mtime().hash(&mut hasher);
        metadata.mtime_nsec().hash(&mut hasher);
        metadata.ctime().hash(&mut hasher);
        metadata.ctime_nsec().hash(&mut hasher);
    }
    Ok(hasher.finish() as i64)
}

fn list_messages_for_folder(
    conn: &Connection,
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    folder: &Folder,
) -> Result<Vec<Message>> {
    let dir = mailbox_dir(maildir_root, domain, localpart, &folder.name)?;
    let folder_id = folder_id(conn, &folder.name)?.context("missing folder")?;
    let mut stmt = conn.prepare(
        "SELECT uid, filename, subdir, flags, size, internaldate, internaldate_tz, save_date, modseq,
                email_id
         FROM messages WHERE folder_id = ?1 ORDER BY filename",
    )?;
    let rows = stmt.query_map(params![folder_id], |row| {
        let flags_text: String = row.get(3)?;
        Ok((
            row.get::<_, i64>(0)? as u64,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            flags_text,
            row.get::<_, i64>(4)? as u64,
            row.get::<_, i64>(5)?,
            row.get::<_, i32>(6)?,
            row.get::<_, i64>(7)?,
            row.get::<_, i64>(8)? as u64,
            row.get::<_, String>(9)?,
        ))
    })?;

    let mut messages = Vec::new();
    for row in rows {
        let (
            uid,
            filename,
            subdir,
            flags_text,
            size,
            internaldate,
            internaldate_tz,
            save_date,
            modseq,
            email_id,
        ) = row?;
        messages.push(Message {
            uid,
            path: message_path(&dir, &subdir, &filename)?,
            flags: flags_from_text(&flags_text)?,
            size,
            internaldate,
            internaldate_tz,
            save_date,
            modseq,
            email_id,
        });
    }
    Ok(messages)
}

pub(crate) fn flags_to_text(flags: &[String]) -> Result<String> {
    Ok(serde_json::to_string(flags)?)
}

pub(crate) fn flags_from_text(text: &str) -> Result<Vec<String>> {
    Ok(serde_json::from_str(text).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_msg(path: &Path, name: &str, body: &[u8]) -> PathBuf {
        ensure_maildir(path).unwrap();
        let p = path.join("new").join(name);
        fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn initializes_schema_and_standard_folders() {
        let td = tempfile::tempdir().unwrap();
        init_account(td.path(), "example.test", "user").unwrap();
        let folders = list_folders(td.path(), "example.test", "user").unwrap();
        assert_eq!(folders.len(), STANDARD_FOLDERS.len());
        assert!(folders.iter().any(|f| f.name == "INBOX"));
        assert!(state_db_path(td.path(), "example.test", "user").is_file());
    }

    #[test]
    fn unchanged_maildirs_are_served_without_reconciliation_scans() {
        let td = tempfile::tempdir().unwrap();
        init_account(td.path(), "example.test", "user").unwrap();
        let scan_count = || {
            let connection =
                Connection::open(state_db_path(td.path(), "example.test", "user")).unwrap();
            connection
                .query_row(
                    "SELECT reconcile_count FROM folders WHERE name = 'INBOX'",
                    [],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap()
        };

        load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        assert_eq!(scan_count(), 1);
        load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        folder_summary(td.path(), "example.test", "user", "INBOX").unwrap();
        assert_eq!(scan_count(), 1);

        let inbox = mailbox_dir(td.path(), "example.test", "user", "INBOX").unwrap();
        let external = write_msg(&inbox, "external", b"Subject: new\r\n\r\nbody");
        assert_eq!(
            load_folder(td.path(), "example.test", "user", "INBOX")
                .unwrap()
                .1
                .len(),
            1
        );
        assert_eq!(scan_count(), 2);
        fs::remove_file(external).unwrap();
        assert!(
            load_folder(td.path(), "example.test", "user", "INBOX")
                .unwrap()
                .1
                .is_empty()
        );
        assert_eq!(scan_count(), 3);
    }

    #[test]
    fn recent_uids_are_external_delivery_only_and_claimed_once() {
        let td = tempfile::tempdir().unwrap();
        init_account(td.path(), "example.test", "user").unwrap();
        let (_, appended_uid) = append_message(
            td.path(),
            "example.test",
            "user",
            "INBOX",
            b"Subject: appended\r\n\r\nbody",
            vec![],
        )
        .unwrap();
        assert_eq!(
            recent_count(td.path(), "example.test", "user", "INBOX").unwrap(),
            0
        );

        let inbox = mailbox_dir(td.path(), "example.test", "user", "INBOX").unwrap();
        write_msg(
            &inbox,
            "external-delivery",
            b"Subject: delivered\r\n\r\nbody",
        );
        assert_eq!(
            recent_count(td.path(), "example.test", "user", "INBOX").unwrap(),
            1
        );

        let claimed = claim_recent_uids(td.path(), "example.test", "user", "INBOX").unwrap();
        assert_eq!(claimed.len(), 1);
        assert!(!claimed.contains(&appended_uid));
        assert!(
            claim_recent_uids(td.path(), "example.test", "user", "INBOX")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            recent_count(td.path(), "example.test", "user", "INBOX").unwrap(),
            0
        );
    }

    #[test]
    fn migrates_uidvalidity_into_the_imap_32_bit_range() {
        let td = tempfile::tempdir().unwrap();
        init_account(td.path(), "example.test", "user").unwrap();
        let db = state_db_path(td.path(), "example.test", "user");
        let conn = Connection::open(&db).unwrap();
        conn.execute(
            "UPDATE folders SET uidvalidity = ?1 WHERE name = 'INBOX'",
            params![1_i64 << 40],
        )
        .unwrap();
        drop(conn);

        let (folder, _) = load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        assert!((1..=u64::from(u32::MAX)).contains(&folder.uidvalidity));
        assert_ne!(folder.uidvalidity, 1_u64 << 40);
    }

    #[test]
    fn migration_backfills_object_ids_for_existing_rows() {
        let td = tempfile::tempdir().unwrap();
        let inbox = account_maildir(td.path(), "example.test", "user");
        write_msg(&inbox, "a", b"Subject: a\r\n\r\n");
        write_msg(&inbox, "b", b"Subject: b\r\n\r\n");
        load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        // Roll the database back to the pre-OBJECTID schema.
        let conn = Connection::open(state_db_path(td.path(), "example.test", "user")).unwrap();
        // The JMAP triggers came later and use the ID columns.
        let jmap_triggers = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'jmap_%'")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        for trigger in jmap_triggers {
            conn.execute_batch(&format!("DROP TRIGGER {trigger}"))
                .unwrap();
        }
        conn.execute_batch(
            "DROP TRIGGER folders_assign_mailbox_id;
             DROP TRIGGER messages_assign_email_id;
             DROP INDEX idx_folders_mailbox_id;
             DROP INDEX idx_messages_email_id;
             ALTER TABLE folders DROP COLUMN mailbox_id;
             ALTER TABLE messages DROP COLUMN email_id;
             UPDATE schema_version SET version = 1;",
        )
        .unwrap();
        drop(conn);

        let (folder, messages) = load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        assert!(folder.mailbox_id.starts_with(MAILBOX_ID_PREFIX));
        assert_eq!(folder.mailbox_id.len(), 25);
        assert_eq!(messages.len(), 2);
        assert!(
            messages
                .iter()
                .all(|message| message.email_id.starts_with(EMAIL_ID_PREFIX))
        );
        assert_ne!(messages[0].email_id, messages[1].email_id);
        let mailbox_ids = list_folders(td.path(), "example.test", "user")
            .unwrap()
            .into_iter()
            .map(|folder| folder.mailbox_id)
            .collect::<HashSet<_>>();
        assert_eq!(mailbox_ids.len(), STANDARD_FOLDERS.len());

        // Reopening keeps the assigned IDs.
        let (again, messages_again) =
            load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        assert_eq!(again.mailbox_id, folder.mailbox_id);
        assert_eq!(messages_again, messages);
    }

    #[test]
    fn object_ids_survive_rename_copy_and_move_but_not_recreation() {
        let td = tempfile::tempdir().unwrap();
        let (root, domain, user) = (td.path(), "example.test", "user");
        create_folder(root, domain, user, "Projects").unwrap();
        let (projects, _) = load_folder(root, domain, user, "Projects").unwrap();
        rename_folder(root, domain, user, "Projects", "Renamed").unwrap();
        let (renamed, _) = load_folder(root, domain, user, "Renamed").unwrap();
        assert_eq!(renamed.mailbox_id, projects.mailbox_id);
        delete_folder(root, domain, user, "Renamed").unwrap();
        create_folder(root, domain, user, "Renamed").unwrap();
        let (recreated, _) = load_folder(root, domain, user, "Renamed").unwrap();
        assert_ne!(recreated.mailbox_id, projects.mailbox_id);

        let (_, first) =
            append_message(root, domain, user, "INBOX", b"Subject: 1\r\n\r\n", vec![]).unwrap();
        let (_, second) =
            append_message(root, domain, user, "INBOX", b"Subject: 2\r\n\r\n", vec![]).unwrap();
        let (_, inbox) = load_folder(root, domain, user, "INBOX").unwrap();
        let email_id = |messages: &[Message], uid| {
            messages
                .iter()
                .find(|message| message.uid == uid)
                .unwrap()
                .email_id
                .clone()
        };
        let first_id = email_id(&inbox, first);
        let second_id = email_id(&inbox, second);
        assert_ne!(first_id, second_id);

        let copied = copy_message_by_uid(root, domain, user, "INBOX", first, "Renamed")
            .unwrap()
            .unwrap();
        let moved = move_message_by_uid(root, domain, user, "INBOX", second, "Renamed")
            .unwrap()
            .unwrap();
        let (_, destination) = load_folder(root, domain, user, "Renamed").unwrap();
        assert_eq!(email_id(&destination, copied), first_id);
        assert_eq!(email_id(&destination, moved), second_id);

        let transferred = transfer_messages_by_uid(
            root,
            domain,
            user,
            "Renamed",
            &[copied, moved],
            "Archive",
            true,
        )
        .unwrap();
        let (_, archive) = load_folder(root, domain, user, "Archive").unwrap();
        assert_eq!(email_id(&archive, transferred[0].1), first_id);
        assert_eq!(email_id(&archive, transferred[1].1), second_id);

        // A new message never reuses an expunged message's ID.
        delete_message_by_uid(root, domain, user, "INBOX", first).unwrap();
        let (_, third) =
            append_message(root, domain, user, "INBOX", b"Subject: 3\r\n\r\n", vec![]).unwrap();
        let (_, inbox) = load_folder(root, domain, user, "INBOX").unwrap();
        let third_id = email_id(&inbox, third);
        assert_ne!(third_id, first_id);
        assert_ne!(third_id, second_id);
    }

    #[test]
    fn reconcile_allocates_uids_and_persists_flags() {
        let td = tempfile::tempdir().unwrap();
        let inbox = account_maildir(td.path(), "example.test", "user");
        write_msg(&inbox, "a", b"Subject: a\r\n\r\n");
        let (folder, messages) = load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        assert_eq!(folder.uidnext, 2);
        assert_eq!(messages[0].uid, 1);
        set_uid_flags(
            td.path(),
            "example.test",
            "user",
            "INBOX",
            1,
            vec!["\\Seen".to_string()],
        )
        .unwrap();
        let (_, messages) = load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        assert_eq!(messages[0].flags, vec!["\\Seen"]);
    }

    #[test]
    fn message_mutations_advance_modseqs() {
        let td = tempfile::tempdir().unwrap();
        let (_uidvalidity, uid) = append_message(
            td.path(),
            "example.test",
            "user",
            "INBOX",
            b"Subject: a\r\n\r\n",
            vec![],
        )
        .unwrap();
        let (folder, messages) = load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        assert_eq!(messages[0].uid, uid);
        assert!(folder.highest_modseq >= messages[0].modseq);
        let original_modseq = messages[0].modseq;

        let updated_modseq = set_uid_flags(
            td.path(),
            "example.test",
            "user",
            "INBOX",
            uid,
            vec!["\\Seen".to_string()],
        )
        .unwrap();
        let (folder, messages) = load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        assert!(updated_modseq > original_modseq);
        assert_eq!(messages[0].modseq, updated_modseq);
        assert_eq!(folder.highest_modseq, updated_modseq);

        delete_message_by_uid(td.path(), "example.test", "user", "INBOX", uid).unwrap();
        let (folder, messages) = load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        assert!(messages.is_empty());
        assert!(folder.highest_modseq > updated_modseq);
    }

    #[test]
    fn qresync_journals_flag_changes_expunges_moves_and_external_deletions() {
        let td = tempfile::tempdir().unwrap();
        init_account(td.path(), "example.test", "user").unwrap();
        let mut uids = Vec::new();
        for subject in ["one", "two", "three"] {
            let (_, uid) = append_message(
                td.path(),
                "example.test",
                "user",
                "INBOX",
                format!("Subject: {}\r\n\r\n", subject).as_bytes(),
                Vec::new(),
            )
            .unwrap();
            uids.push(uid);
        }
        let baseline = load_folder(td.path(), "example.test", "user", "INBOX")
            .unwrap()
            .0
            .highest_modseq;
        set_uid_flags(
            td.path(),
            "example.test",
            "user",
            "INBOX",
            uids[0],
            vec!["\\Seen".to_string()],
        )
        .unwrap();
        delete_message_by_uid(td.path(), "example.test", "user", "INBOX", uids[1]).unwrap();
        move_message_by_uid(
            td.path(),
            "example.test",
            "user",
            "INBOX",
            uids[2],
            "Archive",
        )
        .unwrap();
        let changes = qresync_changes(
            td.path(),
            "example.test",
            "user",
            "INBOX",
            baseline,
            Some(&uids),
        )
        .unwrap();
        assert_eq!(changes.vanished_uids, vec![uids[1], uids[2]]);
        assert_eq!(changes.changed_messages.len(), 1);
        assert_eq!(changes.changed_messages[0].uid, uids[0]);
        assert_eq!(changes.changed_messages[0].flags, vec!["\\Seen"]);

        let (_, external_uid) = append_message(
            td.path(),
            "example.test",
            "user",
            "INBOX",
            b"Subject: external\r\n\r\n",
            Vec::new(),
        )
        .unwrap();
        let (_, messages) = load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        let external = messages
            .iter()
            .find(|message| message.uid == external_uid)
            .unwrap();
        let baseline = messages.iter().map(|message| message.modseq).max().unwrap();
        fs::remove_file(&external.path).unwrap();
        let changes =
            qresync_changes(td.path(), "example.test", "user", "INBOX", baseline, None).unwrap();
        assert_eq!(changes.vanished_uids, vec![external_uid]);
    }

    #[test]
    fn file_move_keeps_uid_and_deleted_file_removes_row() {
        let td = tempfile::tempdir().unwrap();
        let inbox = account_maildir(td.path(), "example.test", "user");
        let new_path = write_msg(&inbox, "a", b"Subject: a\r\n\r\n");
        let (_, messages) = load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        assert_eq!(messages[0].uid, 1);
        let cur_path = inbox.join("cur").join("a");
        fs::rename(new_path, &cur_path).unwrap();
        let (_, messages) = load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        assert_eq!(messages[0].uid, 1);
        assert!(messages[0].path.ends_with("cur/a"));
        fs::remove_file(cur_path).unwrap();
        let (_, messages) = load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        assert!(messages.is_empty());
    }

    #[test]
    fn uidnext_is_monotonic_after_expunge() {
        let td = tempfile::tempdir().unwrap();
        let inbox = account_maildir(td.path(), "example.test", "user");
        write_msg(&inbox, "a", b"a");
        let (_, messages) = load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        delete_message_by_uid(td.path(), "example.test", "user", "INBOX", messages[0].uid).unwrap();
        write_msg(&inbox, "b", b"b");
        let (folder, messages) = load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        assert_eq!(messages[0].uid, 2);
        assert_eq!(folder.uidnext, 3);
    }

    #[test]
    fn move_message_assigns_destination_uid_and_removes_source() {
        let td = tempfile::tempdir().unwrap();
        let inbox = account_maildir(td.path(), "example.test", "user");
        write_msg(&inbox, "a", b"Subject: a\r\n\r\nbody");
        let (_, messages) = load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        let dest_uid = move_message_by_uid(
            td.path(),
            "example.test",
            "user",
            "INBOX",
            messages[0].uid,
            "Archive",
        )
        .unwrap()
        .unwrap();
        assert!(
            load_folder(td.path(), "example.test", "user", "INBOX")
                .unwrap()
                .1
                .is_empty()
        );
        let (_, archived) = load_folder(td.path(), "example.test", "user", "Archive").unwrap();
        assert_eq!(archived.len(), 1);
        assert_eq!(archived[0].uid, dest_uid);
        assert_eq!(
            fs::read(&archived[0].path).unwrap(),
            b"Subject: a\r\n\r\nbody"
        );
    }

    #[test]
    fn copy_message_assigns_destination_uid_and_keeps_source() {
        let td = tempfile::tempdir().unwrap();
        let inbox = account_maildir(td.path(), "example.test", "user");
        write_msg(&inbox, "a", b"Subject: a\r\n\r\nbody");
        let (_, messages) = load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        let dest_uid = copy_message_by_uid(
            td.path(),
            "example.test",
            "user",
            "INBOX",
            messages[0].uid,
            "Archive",
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            load_folder(td.path(), "example.test", "user", "INBOX")
                .unwrap()
                .1
                .len(),
            1
        );
        let (_, archived) = load_folder(td.path(), "example.test", "user", "Archive").unwrap();
        assert_eq!(archived.len(), 1);
        assert_eq!(archived[0].uid, dest_uid);
        assert_eq!(
            fs::read(&archived[0].path).unwrap(),
            b"Subject: a\r\n\r\nbody"
        );
    }

    #[test]
    fn copy_consumes_quota_but_move_does_not() {
        let td = tempfile::tempdir().unwrap();
        init_account(td.path(), "example.test", "user").unwrap();
        let data = b"123456";
        let (_, uid) =
            append_message(td.path(), "example.test", "user", "INBOX", data, Vec::new()).unwrap();
        set_storage_quota(td.path(), "example.test", "user", Some(10)).unwrap();
        let error = copy_message_by_uid(td.path(), "example.test", "user", "INBOX", uid, "Archive")
            .unwrap_err();
        assert!(error.downcast_ref::<StorageQuotaExceeded>().is_some());
        assert_eq!(
            storage_quota(td.path(), "example.test", "user").unwrap().0,
            6
        );
        assert!(
            move_message_by_uid(td.path(), "example.test", "user", "INBOX", uid, "Archive",)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            storage_quota(td.path(), "example.test", "user").unwrap().0,
            6
        );
    }

    #[test]
    fn copy_and_move_roll_back_maildir_when_database_commit_fails() {
        for move_message in [false, true] {
            let td = tempfile::tempdir().unwrap();
            init_account(td.path(), "example.test", "user").unwrap();
            let (_, uid) = append_message(
                td.path(),
                "example.test",
                "user",
                "INBOX",
                b"Subject: rollback\r\n\r\nbody\r\n",
                Vec::new(),
            )
            .unwrap();
            let (_, source_before) =
                load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
            let source_path = source_before[0].path.clone();
            let conn = Connection::open(state_db_path(td.path(), "example.test", "user")).unwrap();
            conn.execute_batch(
                "CREATE TRIGGER reject_archive_insert
                 BEFORE INSERT ON messages
                 WHEN NEW.folder_id = (SELECT id FROM folders WHERE name = 'Archive')
                 BEGIN SELECT RAISE(FAIL, 'injected destination failure'); END;",
            )
            .unwrap();
            drop(conn);

            let result = if move_message {
                move_message_by_uid(td.path(), "example.test", "user", "INBOX", uid, "Archive")
            } else {
                copy_message_by_uid(td.path(), "example.test", "user", "INBOX", uid, "Archive")
            };
            assert!(result.is_err());
            assert!(
                source_path.is_file(),
                "source was not restored after failure"
            );
            let (_, source_after) =
                load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
            let (_, destination_after) =
                load_folder(td.path(), "example.test", "user", "Archive").unwrap();
            assert_eq!(source_after.len(), 1);
            assert!(destination_after.is_empty());
            let archive_dir = mailbox_dir(td.path(), "example.test", "user", "Archive").unwrap();
            assert_eq!(fs::read_dir(archive_dir.join("new")).unwrap().count(), 0);
            assert_eq!(fs::read_dir(archive_dir.join("cur")).unwrap().count(), 0);
        }
    }

    #[test]
    fn batch_copy_and_move_are_atomic_when_a_later_message_fails() {
        for move_messages in [false, true] {
            let td = tempfile::tempdir().unwrap();
            init_account(td.path(), "example.test", "user").unwrap();
            let (_, first) = append_message(
                td.path(),
                "example.test",
                "user",
                "INBOX",
                b"Subject: first\r\n\r\n",
                Vec::new(),
            )
            .unwrap();
            let (_, second) = append_message(
                td.path(),
                "example.test",
                "user",
                "INBOX",
                b"Subject: second\r\n\r\n",
                Vec::new(),
            )
            .unwrap();
            let (_, source_before) =
                load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
            let source_paths = source_before
                .iter()
                .map(|message| message.path.clone())
                .collect::<Vec<_>>();
            let (destination_before, _) =
                load_folder(td.path(), "example.test", "user", "Archive").unwrap();
            let conn = Connection::open(state_db_path(td.path(), "example.test", "user")).unwrap();
            conn.execute_batch(
                "CREATE TRIGGER reject_second_archive_insert
                 BEFORE INSERT ON messages
                 WHEN NEW.folder_id = (SELECT id FROM folders WHERE name = 'Archive')
                      AND NEW.uid = 2
                 BEGIN SELECT RAISE(FAIL, 'injected second-message failure'); END;",
            )
            .unwrap();
            drop(conn);

            assert!(
                transfer_messages_by_uid(
                    td.path(),
                    "example.test",
                    "user",
                    "INBOX",
                    &[first, second],
                    "Archive",
                    move_messages,
                )
                .is_err()
            );
            assert!(source_paths.iter().all(|path| path.is_file()));
            let (_, source_after) =
                load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
            let (destination_after, messages_after) =
                load_folder(td.path(), "example.test", "user", "Archive").unwrap();
            assert_eq!(source_after.len(), 2);
            assert!(messages_after.is_empty());
            assert_eq!(destination_after.uidnext, destination_before.uidnext);
        }
    }

    #[test]
    fn append_and_expunge_roll_back_maildir_when_database_changes_fail() {
        let append_td = tempfile::tempdir().unwrap();
        init_account(append_td.path(), "example.test", "user").unwrap();
        let (before, _) = load_folder(append_td.path(), "example.test", "user", "INBOX").unwrap();
        let conn =
            Connection::open(state_db_path(append_td.path(), "example.test", "user")).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER reject_append_insert
             BEFORE INSERT ON messages
             WHEN NEW.folder_id = (SELECT id FROM folders WHERE name = 'INBOX')
             BEGIN SELECT RAISE(FAIL, 'injected append failure'); END;",
        )
        .unwrap();
        drop(conn);

        assert!(
            append_message(
                append_td.path(),
                "example.test",
                "user",
                "INBOX",
                b"Subject: rejected\r\n\r\nbody",
                Vec::new(),
            )
            .is_err()
        );
        let (after, messages) =
            load_folder(append_td.path(), "example.test", "user", "INBOX").unwrap();
        assert!(messages.is_empty());
        assert_eq!(after.uidnext, before.uidnext);
        let inbox = account_maildir(append_td.path(), "example.test", "user");
        assert_eq!(fs::read_dir(inbox.join("new")).unwrap().count(), 0);
        assert_eq!(fs::read_dir(inbox.join("tmp")).unwrap().count(), 0);

        let expunge_td = tempfile::tempdir().unwrap();
        let (_, uid) = append_message(
            expunge_td.path(),
            "example.test",
            "user",
            "INBOX",
            b"Subject: retained\r\n\r\nbody",
            Vec::new(),
        )
        .unwrap();
        let (_, messages) =
            load_folder(expunge_td.path(), "example.test", "user", "INBOX").unwrap();
        let original_path = messages[0].path.clone();
        let conn =
            Connection::open(state_db_path(expunge_td.path(), "example.test", "user")).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER reject_expunge_journal
             BEFORE INSERT ON expunges
             BEGIN SELECT RAISE(FAIL, 'injected expunge failure'); END;",
        )
        .unwrap();
        drop(conn);

        assert!(
            delete_message_by_uid(expunge_td.path(), "example.test", "user", "INBOX", uid,)
                .is_err()
        );
        assert!(original_path.is_file());
        let (_, messages) =
            load_folder(expunge_td.path(), "example.test", "user", "INBOX").unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].uid, uid);
        assert_eq!(
            fs::read_dir(account_maildir(expunge_td.path(), "example.test", "user").join("tmp"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn flag_update_batch_is_atomic_when_a_later_message_fails() {
        let td = tempfile::tempdir().unwrap();
        let (_, first) = append_message(
            td.path(),
            "example.test",
            "user",
            "INBOX",
            b"Subject: first\r\n\r\n",
            Vec::new(),
        )
        .unwrap();
        let (_, second) = append_message(
            td.path(),
            "example.test",
            "user",
            "INBOX",
            b"Subject: second\r\n\r\n",
            Vec::new(),
        )
        .unwrap();
        let (before, messages_before) =
            load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        let conn = Connection::open(state_db_path(td.path(), "example.test", "user")).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER reject_second_flag_update
             BEFORE UPDATE OF flags ON messages
             WHEN OLD.uid = 2
             BEGIN SELECT RAISE(FAIL, 'injected flag update failure'); END;",
        )
        .unwrap();
        drop(conn);

        assert!(
            set_uid_flags_batch(
                td.path(),
                "example.test",
                "user",
                "INBOX",
                &[
                    (first, vec!["\\Seen".to_string()]),
                    (second, vec!["\\Flagged".to_string()]),
                ],
            )
            .is_err()
        );
        let (after, messages_after) =
            load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        assert_eq!(after.highest_modseq, before.highest_modseq);
        assert_eq!(messages_after.len(), messages_before.len());
        for message in messages_after {
            let original = messages_before
                .iter()
                .find(|candidate| candidate.uid == message.uid)
                .unwrap();
            assert_eq!(message.flags, original.flags);
            assert_eq!(message.modseq, original.modseq);
        }
    }

    #[test]
    fn expunge_batch_is_atomic_when_a_later_message_fails() {
        let td = tempfile::tempdir().unwrap();
        let (_, first) = append_message(
            td.path(),
            "example.test",
            "user",
            "INBOX",
            b"Subject: first\r\n\r\n",
            Vec::new(),
        )
        .unwrap();
        let (_, second) = append_message(
            td.path(),
            "example.test",
            "user",
            "INBOX",
            b"Subject: second\r\n\r\n",
            Vec::new(),
        )
        .unwrap();
        let (before, messages_before) =
            load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        let paths = messages_before
            .iter()
            .map(|message| message.path.clone())
            .collect::<Vec<_>>();
        let conn = Connection::open(state_db_path(td.path(), "example.test", "user")).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER reject_second_expunge
             BEFORE INSERT ON expunges
             WHEN NEW.uid = 2
             BEGIN SELECT RAISE(FAIL, 'injected second expunge failure'); END;",
        )
        .unwrap();
        drop(conn);

        assert!(
            delete_messages_by_uid(td.path(), "example.test", "user", "INBOX", &[first, second],)
                .is_err()
        );
        assert!(paths.iter().all(|path| path.is_file()));
        let (after, messages_after) =
            load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        assert_eq!(after.highest_modseq, before.highest_modseq);
        assert_eq!(messages_after.len(), 2);
        let conn = Connection::open(state_db_path(td.path(), "example.test", "user")).unwrap();
        let expunges: i64 = conn
            .query_row("SELECT COUNT(*) FROM expunges", [], |row| row.get(0))
            .unwrap();
        assert_eq!(expunges, 0);
        assert_eq!(
            fs::read_dir(account_maildir(td.path(), "example.test", "user").join("tmp"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn append_message_preserves_bytes_flags_and_requires_existing_folder() {
        let td = tempfile::tempdir().unwrap();
        init_account(td.path(), "example.test", "user").unwrap();
        let raw = b"Subject: appended\r\nX-Raw: \xff\r\n\r\nbody\x00bytes\r\n";
        let (uidvalidity, uid) = append_message(
            td.path(),
            "example.test",
            "user",
            "Drafts",
            raw,
            vec!["\\Seen".to_string(), "\\Draft".to_string()],
        )
        .unwrap();
        let (folder, messages) = load_folder(td.path(), "example.test", "user", "Drafts").unwrap();
        assert_eq!(folder.uidvalidity, uidvalidity);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].uid, uid);
        assert_eq!(messages[0].flags, vec!["\\Seen", "\\Draft"]);
        assert_eq!(fs::read(&messages[0].path).unwrap(), raw);

        assert!(
            append_message(
                td.path(),
                "example.test",
                "user",
                "Missing",
                raw,
                Vec::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn storage_quota_is_enforced_inside_append_transaction() {
        let td = tempfile::tempdir().unwrap();
        init_account(td.path(), "example.test", "user").unwrap();
        set_storage_quota(td.path(), "example.test", "user", Some(10)).unwrap();
        append_message(
            td.path(),
            "example.test",
            "user",
            "INBOX",
            b"123456",
            Vec::new(),
        )
        .unwrap();
        let error = append_message(
            td.path(),
            "example.test",
            "user",
            "INBOX",
            b"abcde",
            Vec::new(),
        )
        .unwrap_err();
        let quota = error.downcast_ref::<StorageQuotaExceeded>().unwrap();
        assert_eq!(
            *quota,
            StorageQuotaExceeded {
                used: 6,
                limit: 10,
                requested: 5,
            }
        );
        assert_eq!(
            storage_quota(td.path(), "example.test", "user").unwrap(),
            (6, Some(10))
        );
        assert_eq!(
            load_folder(td.path(), "example.test", "user", "INBOX")
                .unwrap()
                .1
                .len(),
            1
        );
    }

    #[test]
    fn append_internal_date_survives_reconciliation_and_copy() {
        let td = tempfile::tempdir().unwrap();
        init_account(td.path(), "example.test", "user").unwrap();
        let timestamp = 837_596_665;
        let timezone_offset = -7 * 60;
        let before_append = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let (_, uid) = append_message_with_internal_date(
            td.path(),
            "example.test",
            "user",
            "Sent",
            b"Subject: dated\r\n\r\nbody\r\n",
            vec!["\\Seen".to_string()],
            Some((timestamp, timezone_offset)),
        )
        .unwrap();

        let (_, sent) = load_folder(td.path(), "example.test", "user", "Sent").unwrap();
        assert_eq!(sent[0].internaldate, timestamp);
        assert_eq!(sent[0].internaldate_tz, timezone_offset);
        assert!(sent[0].save_date >= before_append);
        assert_ne!(sent[0].save_date, sent[0].internaldate);
        let mtime = fs::metadata(&sent[0].path)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert_eq!(mtime, timestamp);

        let copied_uid =
            copy_message_by_uid(td.path(), "example.test", "user", "Sent", uid, "Archive")
                .unwrap()
                .unwrap();
        let (_, archived) = load_folder(td.path(), "example.test", "user", "Archive").unwrap();
        let copied = archived
            .iter()
            .find(|message| message.uid == copied_uid)
            .unwrap();
        assert_eq!(copied.internaldate, timestamp);
        assert_eq!(copied.internaldate_tz, timezone_offset);
        assert!(copied.save_date >= sent[0].save_date);
    }

    #[test]
    fn delete_moves_to_trash_then_removes_from_trash() {
        let td = tempfile::tempdir().unwrap();
        let inbox = account_maildir(td.path(), "example.test", "user");
        write_msg(&inbox, "a", b"Subject: a\r\n\r\nbody");
        let (_, messages) = load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        delete_or_trash_message_by_uid(td.path(), "example.test", "user", "INBOX", messages[0].uid)
            .unwrap();
        assert!(
            load_folder(td.path(), "example.test", "user", "INBOX")
                .unwrap()
                .1
                .is_empty()
        );
        let (_, trash) = load_folder(td.path(), "example.test", "user", "Trash").unwrap();
        assert_eq!(trash.len(), 1);
        let trash_path = trash[0].path.clone();
        delete_or_trash_message_by_uid(td.path(), "example.test", "user", "Trash", trash[0].uid)
            .unwrap();
        assert!(!trash_path.exists());
        assert!(
            load_folder(td.path(), "example.test", "user", "Trash")
                .unwrap()
                .1
                .is_empty()
        );
    }

    #[test]
    fn folder_create_delete_and_subscribe() {
        let td = tempfile::tempdir().unwrap();
        create_folder(td.path(), "example.test", "user", "Projects").unwrap();
        create_folder(td.path(), "example.test", "user", "Projects/Child").unwrap();
        assert!(folder_exists(td.path(), "example.test", "user", "Projects").unwrap());
        set_subscription(td.path(), "example.test", "user", "Projects", false).unwrap();
        let subscribed = list_subscribed_folders(td.path(), "example.test", "user").unwrap();
        assert!(!subscribed.iter().any(|f| f.name == "Projects"));
        assert!(delete_folder(td.path(), "example.test", "user", "Projects").is_err());
        assert!(folder_exists(td.path(), "example.test", "user", "Projects/Child").unwrap());
        delete_folder(td.path(), "example.test", "user", "Projects/Child").unwrap();
        delete_folder(td.path(), "example.test", "user", "Projects").unwrap();
        assert!(!folder_exists(td.path(), "example.test", "user", "Projects").unwrap());
    }

    #[test]
    fn nonexistent_subscriptions_do_not_create_mailboxes() {
        let td = tempfile::tempdir().unwrap();
        set_subscription(td.path(), "example.test", "user", "Ghost", true).unwrap();
        assert!(!folder_exists(td.path(), "example.test", "user", "Ghost").unwrap());
        assert!(
            list_subscriptions(td.path(), "example.test", "user")
                .unwrap()
                .iter()
                .any(|name| name == "Ghost")
        );

        set_subscription(td.path(), "example.test", "user", "INBOX", false).unwrap();
        assert!(
            !list_subscriptions(td.path(), "example.test", "user")
                .unwrap()
                .iter()
                .any(|name| name == "INBOX")
        );
        assert!(
            !load_folder(td.path(), "example.test", "user", "INBOX")
                .unwrap()
                .0
                .subscribed
        );

        set_subscription(td.path(), "example.test", "user", "Ghost", false).unwrap();
        assert!(
            !list_subscriptions(td.path(), "example.test", "user")
                .unwrap()
                .iter()
                .any(|name| name == "Ghost")
        );
    }

    #[test]
    fn folder_summary_does_not_create_missing_mailboxes() {
        let td = tempfile::tempdir().unwrap();
        assert!(
            folder_summary(td.path(), "example.test", "user", "Missing")
                .unwrap()
                .is_none()
        );
        assert!(!folder_exists(td.path(), "example.test", "user", "Missing").unwrap());

        let inbox = folder_summary(td.path(), "example.test", "user", "inbox")
            .unwrap()
            .unwrap();
        assert_eq!(inbox.folder.name, "INBOX");
        assert_eq!(inbox.messages, 0);
    }

    #[test]
    fn rename_folder_preserves_messages_flags_and_subscription() {
        let td = tempfile::tempdir().unwrap();
        create_folder(td.path(), "example.test", "user", "Projects").unwrap();
        create_folder(td.path(), "example.test", "user", "Projects/Child").unwrap();
        let projects = mailbox_dir(td.path(), "example.test", "user", "Projects").unwrap();
        let child = mailbox_dir(td.path(), "example.test", "user", "Projects/Child").unwrap();
        write_msg(&projects, "a", b"Subject: a\r\n\r\nbody");
        write_msg(&child, "b", b"Subject: b\r\n\r\nchild");
        let (_, messages) = load_folder(td.path(), "example.test", "user", "Projects").unwrap();
        let (_, child_messages) =
            load_folder(td.path(), "example.test", "user", "Projects/Child").unwrap();
        set_uid_flags(
            td.path(),
            "example.test",
            "user",
            "Projects",
            messages[0].uid,
            vec!["\\Seen".to_string()],
        )
        .unwrap();
        set_subscription(td.path(), "example.test", "user", "Projects", false).unwrap();

        rename_folder(td.path(), "example.test", "user", "Projects", "Renamed").unwrap();
        assert!(!folder_exists(td.path(), "example.test", "user", "Projects").unwrap());
        assert!(!folder_exists(td.path(), "example.test", "user", "Projects/Child").unwrap());
        assert!(folder_exists(td.path(), "example.test", "user", "Renamed").unwrap());
        assert!(folder_exists(td.path(), "example.test", "user", "Renamed/Child").unwrap());
        let (folder, renamed) = load_folder(td.path(), "example.test", "user", "Renamed").unwrap();
        assert_eq!(renamed.len(), 1);
        assert_eq!(renamed[0].uid, messages[0].uid);
        assert_eq!(renamed[0].flags, vec!["\\Seen"]);
        assert!(!folder.subscribed);
        assert_eq!(
            fs::read(&renamed[0].path).unwrap(),
            b"Subject: a\r\n\r\nbody"
        );
        let (_, renamed_child) =
            load_folder(td.path(), "example.test", "user", "Renamed/Child").unwrap();
        assert_eq!(renamed_child[0].uid, child_messages[0].uid);
        assert_eq!(
            fs::read(&renamed_child[0].path).unwrap(),
            b"Subject: b\r\n\r\nchild"
        );

        assert!(rename_folder(td.path(), "example.test", "user", "INBOX", "Nope").is_err());
    }

    #[test]
    fn hierarchy_rename_rolls_back_filesystem_and_database_together() {
        let td = tempfile::tempdir().unwrap();
        create_folder(td.path(), "example.test", "user", "Projects").unwrap();
        create_folder(td.path(), "example.test", "user", "Projects/Child").unwrap();
        let parent_dir = mailbox_dir(td.path(), "example.test", "user", "Projects").unwrap();
        let child_dir = mailbox_dir(td.path(), "example.test", "user", "Projects/Child").unwrap();
        let conn = Connection::open(state_db_path(td.path(), "example.test", "user")).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER reject_child_rename
             BEFORE UPDATE OF name ON folders
             WHEN OLD.name = 'Projects/Child'
             BEGIN SELECT RAISE(FAIL, 'injected child rename failure'); END;",
        )
        .unwrap();
        drop(conn);

        assert!(rename_folder(td.path(), "example.test", "user", "Projects", "Renamed").is_err());
        assert!(parent_dir.is_dir());
        assert!(child_dir.is_dir());
        assert!(folder_exists(td.path(), "example.test", "user", "Projects").unwrap());
        assert!(folder_exists(td.path(), "example.test", "user", "Projects/Child").unwrap());
        assert!(!folder_exists(td.path(), "example.test", "user", "Renamed").unwrap());
        assert!(!folder_exists(td.path(), "example.test", "user", "Renamed/Child").unwrap());
    }

    #[test]
    fn mailbox_delete_rolls_back_filesystem_when_database_delete_fails() {
        let td = tempfile::tempdir().unwrap();
        create_folder(td.path(), "example.test", "user", "Projects").unwrap();
        let projects = mailbox_dir(td.path(), "example.test", "user", "Projects").unwrap();
        write_msg(&projects, "a", b"Subject: retained\r\n\r\nbody");
        load_folder(td.path(), "example.test", "user", "Projects").unwrap();
        let conn = Connection::open(state_db_path(td.path(), "example.test", "user")).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER reject_mailbox_delete
             BEFORE DELETE ON folders
             WHEN OLD.name = 'Projects'
             BEGIN SELECT RAISE(FAIL, 'injected mailbox delete failure'); END;",
        )
        .unwrap();
        drop(conn);

        assert!(delete_folder(td.path(), "example.test", "user", "Projects").is_err());
        assert!(projects.is_dir());
        assert!(folder_exists(td.path(), "example.test", "user", "Projects").unwrap());
        let (_, messages) = load_folder(td.path(), "example.test", "user", "Projects").unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(
            fs::read(&messages[0].path).unwrap(),
            b"Subject: retained\r\n\r\nbody"
        );
    }

    #[test]
    fn mailbox_create_rolls_back_directory_when_database_insert_fails() {
        let td = tempfile::tempdir().unwrap();
        init_account(td.path(), "example.test", "user").unwrap();
        let conn = Connection::open(state_db_path(td.path(), "example.test", "user")).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER reject_mailbox_create
             BEFORE INSERT ON folders
             WHEN NEW.name = 'Projects'
             BEGIN SELECT RAISE(FAIL, 'injected mailbox create failure'); END;",
        )
        .unwrap();
        drop(conn);

        assert!(create_folder(td.path(), "example.test", "user", "Projects").is_err());
        assert!(
            !mailbox_dir(td.path(), "example.test", "user", "Projects")
                .unwrap()
                .exists()
        );
        assert!(!folder_exists(td.path(), "example.test", "user", "Projects").unwrap());
    }

    #[test]
    fn staged_append_is_published_without_rewriting_message_bytes() {
        let td = tempfile::tempdir().unwrap();
        init_account(td.path(), "example.test", "user").unwrap();
        let staged = append_staging_path(td.path(), "example.test", "user").unwrap();
        let message = b"Subject: staged\r\n\r\n\0binary\xffbody";
        fs::write(&staged, message).unwrap();

        let (uidvalidity, uid) = publish_staged_append(
            td.path(),
            "example.test",
            "user",
            "INBOX",
            &staged,
            vec!["\\Seen".to_string()],
            Some((1_700_000_000, 60)),
        )
        .unwrap();

        assert!(!staged.exists());
        let (folder, messages) = load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        assert_eq!(uidvalidity, folder.uidvalidity);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].uid, uid);
        assert_eq!(messages[0].size, message.len() as u64);
        assert_eq!(messages[0].flags, vec!["\\Seen"]);
        assert_eq!(fs::read(&messages[0].path).unwrap(), message);
    }

    #[test]
    fn staged_multiappend_publishes_ordered_uids_atomically() {
        let td = tempfile::tempdir().unwrap();
        init_account(td.path(), "example.test", "user").unwrap();
        let first = append_staging_path(td.path(), "example.test", "user").unwrap();
        let second = append_staging_path(td.path(), "example.test", "user").unwrap();
        fs::write(&first, b"Subject: first\r\n\r\none").unwrap();
        fs::write(&second, b"Subject: second\r\n\r\ntwo").unwrap();

        let (uidvalidity, uids) = publish_staged_appends(
            td.path(),
            "example.test",
            "user",
            "INBOX",
            vec![
                StagedAppend {
                    path: first,
                    flags: vec!["\\Seen".to_string()],
                    internal_date: None,
                },
                StagedAppend {
                    path: second,
                    flags: Vec::new(),
                    internal_date: None,
                },
            ],
        )
        .unwrap();
        let (folder, messages) = load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        assert_eq!(uidvalidity, folder.uidvalidity);
        assert_eq!(uids.len(), 2);
        assert_eq!(uids[1], uids[0] + 1);
        assert_eq!(
            messages
                .iter()
                .map(|message| message.uid)
                .collect::<Vec<_>>(),
            uids
        );
    }

    #[test]
    fn staged_multiappend_rolls_back_every_message_on_publish_failure() {
        let td = tempfile::tempdir().unwrap();
        init_account(td.path(), "example.test", "user").unwrap();
        let first = append_staging_path(td.path(), "example.test", "user").unwrap();
        let second = append_staging_path(td.path(), "example.test", "user").unwrap();
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        let conn = Connection::open(state_db_path(td.path(), "example.test", "user")).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER reject_second_multiappend
             BEFORE INSERT ON messages WHEN NEW.flags != '[]'
             BEGIN SELECT RAISE(FAIL, 'injected MULTIAPPEND failure'); END;",
        )
        .unwrap();
        drop(conn);

        assert!(
            publish_staged_appends(
                td.path(),
                "example.test",
                "user",
                "INBOX",
                vec![
                    StagedAppend {
                        path: first,
                        flags: Vec::new(),
                        internal_date: None
                    },
                    StagedAppend {
                        path: second,
                        flags: vec!["\\Flagged".to_string()],
                        internal_date: None,
                    },
                ],
            )
            .is_err()
        );
        let (_, messages) = load_folder(td.path(), "example.test", "user", "INBOX").unwrap();
        assert!(messages.is_empty());
    }

    fn staged_message(root: &Path, body: &[u8]) -> StagedAppend {
        let path = append_staging_path(root, "example.test", "user").unwrap();
        fs::write(&path, body).unwrap();
        StagedAppend {
            path,
            flags: vec!["\\Seen".to_string()],
            internal_date: None,
        }
    }

    #[test]
    fn replace_message_expunges_and_publishes_together() {
        let td = tempfile::tempdir().unwrap();
        let (root, domain, user) = (td.path(), "example.test", "user");
        let (_, old_uid) =
            append_message(root, domain, user, "INBOX", b"Subject: old\r\n\r\n", vec![]).unwrap();

        // A failed publish rolls the expunge back.
        let failed = staged_message(root, b"Subject: new\r\n\r\n");
        let failed_path = failed.path.clone();
        assert!(replace_message(root, domain, user, "INBOX", old_uid, "Missing", failed).is_err());
        let _ = fs::remove_file(failed_path);
        let (_, inbox) = load_folder(root, domain, user, "INBOX").unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].uid, old_uid);
        assert_eq!(fs::read(&inbox[0].path).unwrap(), b"Subject: old\r\n\r\n");

        // The old message's space counts as freed for the quota check.
        set_storage_quota(root, domain, user, Some(20)).unwrap();
        let outcome = replace_message(
            root,
            domain,
            user,
            "INBOX",
            old_uid,
            "Drafts",
            staged_message(root, b"Subject: new\r\n\r\n"),
        )
        .unwrap();
        assert!(outcome.expunged);
        assert!(
            load_folder(root, domain, user, "INBOX")
                .unwrap()
                .1
                .is_empty()
        );
        let (drafts_folder, drafts) = load_folder(root, domain, user, "Drafts").unwrap();
        assert_eq!(outcome.uidvalidity, drafts_folder.uidvalidity);
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].uid, outcome.uid);
        assert_eq!(drafts[0].flags, vec!["\\Seen"]);
        assert_eq!(fs::read(&drafts[0].path).unwrap(), b"Subject: new\r\n\r\n");

        // A message that is already gone is not an error; only the append
        // happens.
        set_storage_quota(root, domain, user, None).unwrap();
        let outcome = replace_message(
            root,
            domain,
            user,
            "INBOX",
            old_uid,
            "INBOX",
            staged_message(root, b"Subject: newer\r\n\r\n"),
        )
        .unwrap();
        assert!(!outcome.expunged);
        assert_eq!(load_folder(root, domain, user, "INBOX").unwrap().1.len(), 1);
    }

    fn set_entries(
        root: &Path,
        mailbox: Option<&str>,
        changes: &[(&str, Option<&str>)],
        limit: usize,
    ) -> Result<bool> {
        let changes = changes
            .iter()
            .map(|(entry, value)| (entry.to_string(), value.map(str::to_string)))
            .collect::<Vec<_>>();
        set_metadata(root, "example.test", "user", mailbox, &changes, limit)
    }

    fn entries(root: &Path, mailbox: Option<&str>) -> Option<Vec<(String, String)>> {
        get_metadata(root, "example.test", "user", mailbox).unwrap()
    }

    #[test]
    fn metadata_follows_rename_and_is_dropped_with_the_mailbox() {
        let td = tempfile::tempdir().unwrap();
        create_folder(td.path(), "example.test", "user", "Projects").unwrap();
        create_folder(td.path(), "example.test", "user", "Projects/Child").unwrap();
        assert!(
            set_entries(
                td.path(),
                Some("Projects/Child"),
                &[("/private/comment", Some("child"))],
                10
            )
            .unwrap()
        );
        rename_folder(td.path(), "example.test", "user", "Projects", "Work").unwrap();
        assert_eq!(
            entries(td.path(), Some("Work/Child")).unwrap(),
            vec![("/private/comment".to_string(), "child".to_string())]
        );
        assert_eq!(entries(td.path(), Some("Projects/Child")), None);

        delete_folder(td.path(), "example.test", "user", "Work/Child").unwrap();
        create_folder(td.path(), "example.test", "user", "Work/Child").unwrap();
        assert_eq!(entries(td.path(), Some("Work/Child")).unwrap(), Vec::new());
    }

    #[test]
    fn metadata_entries_are_case_insensitive_and_server_entries_are_separate() {
        let td = tempfile::tempdir().unwrap();
        set_entries(td.path(), None, &[("/shared/comment", Some("server"))], 10).unwrap();
        set_entries(
            td.path(),
            Some("inbox"),
            &[("/Private/Comment", Some("first"))],
            10,
        )
        .unwrap();
        set_entries(
            td.path(),
            Some("INBOX"),
            &[("/private/comment", Some("second"))],
            10,
        )
        .unwrap();
        assert_eq!(
            entries(td.path(), Some("INBOX")).unwrap(),
            vec![("/private/comment".to_string(), "second".to_string())]
        );
        assert_eq!(
            entries(td.path(), None).unwrap(),
            vec![("/shared/comment".to_string(), "server".to_string())]
        );
        set_entries(td.path(), Some("INBOX"), &[("/PRIVATE/COMMENT", None)], 10).unwrap();
        assert_eq!(entries(td.path(), Some("INBOX")).unwrap(), Vec::new());
    }

    #[test]
    fn metadata_entry_limit_rolls_back_the_whole_request() {
        let td = tempfile::tempdir().unwrap();
        set_entries(td.path(), None, &[("/shared/a", Some("1"))], 2).unwrap();
        let error = set_entries(
            td.path(),
            Some("INBOX"),
            &[("/private/b", Some("2")), ("/private/c", Some("3"))],
            2,
        )
        .unwrap_err();
        assert!(error.downcast_ref::<MetadataTooMany>().is_some());
        assert_eq!(entries(td.path(), Some("INBOX")).unwrap(), Vec::new());
        // Removing entries is always allowed, even at the limit.
        set_entries(td.path(), None, &[("/shared/a", None)], 0).unwrap();
        assert!(!set_entries(td.path(), Some("Missing"), &[("/private/x", Some("1"))], 2).unwrap());
    }
}
