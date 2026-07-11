use crate::maildir::{STANDARD_FOLDERS, ensure_maildir, mailbox_dir, normalize_mailbox_name};
use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderSummary {
    pub folder: Folder,
    pub messages: usize,
    pub unseen: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QresyncChanges {
    pub vanished_uids: Vec<u64>,
    pub changed_messages: Vec<Message>,
}

pub fn account_maildir(maildir_root: &Path, domain: &str, localpart: &str) -> PathBuf {
    maildir_root.join(domain).join(localpart).join("Maildir")
}

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

fn open_account(maildir_root: &Path, domain: &str, localpart: &str) -> Result<Connection> {
    let root = account_maildir(maildir_root, domain, localpart);
    fs::create_dir_all(&root)?;
    let conn = Connection::open(root.join(STATE_DB_FILENAME))?;
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
            highest_modseq INTEGER NOT NULL DEFAULT 1
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
        ",
    )?;
    add_column_if_missing(
        conn,
        "folders",
        "highest_modseq",
        "INTEGER NOT NULL DEFAULT 1",
    )?;
    add_column_if_missing(conn, "messages", "save_date", "INTEGER NOT NULL DEFAULT 0")?;
    conn.execute(
        "UPDATE messages SET save_date = internaldate WHERE save_date = 0",
        [],
    )?;
    add_column_if_missing(conn, "messages", "modseq", "INTEGER NOT NULL DEFAULT 1")?;
    add_column_if_missing(
        conn,
        "messages",
        "internaldate_tz",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
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
    conn.execute(
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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1);
    (now ^ rand::random::<u64>()).max(1)
}

pub fn list_folders(maildir_root: &Path, domain: &str, localpart: &str) -> Result<Vec<Folder>> {
    let conn = open_account(maildir_root, domain, localpart)?;
    let mut stmt = conn.prepare(
        "SELECT name, path, special_use, subscribed, uidvalidity, uidnext, highest_modseq
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

pub fn create_folder(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
) -> Result<()> {
    let name = normalize_mailbox_name(mailbox)?;
    let conn = open_account(maildir_root, domain, localpart)?;
    ensure_maildir(&mailbox_dir(maildir_root, domain, localpart, &name)?)?;
    insert_folder(&conn, &name, &folder_path(&name)?, None, true)
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
    let conn = open_account(maildir_root, domain, localpart)?;
    if let Some(id) = folder_id(&conn, &name)? {
        conn.execute("DELETE FROM folders WHERE id = ?1", params![id])?;
    }
    let dir = mailbox_dir(maildir_root, domain, localpart, &name)?;
    if dir.exists() {
        fs::remove_dir_all(dir)?;
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

    let conn = open_account(maildir_root, domain, localpart)?;
    let Some(source_id) = folder_id(&conn, &source)? else {
        anyhow::bail!("source mailbox does not exist");
    };
    if folder_id(&conn, &destination)?.is_some() {
        anyhow::bail!("destination mailbox already exists");
    }

    let source_dir = mailbox_dir(maildir_root, domain, localpart, &source)?;
    let destination_dir = mailbox_dir(maildir_root, domain, localpart, &destination)?;
    if !source_dir.is_dir() {
        anyhow::bail!("source mailbox directory does not exist");
    }
    if destination_dir.exists() {
        anyhow::bail!("destination mailbox directory already exists");
    }
    fs::rename(&source_dir, &destination_dir).with_context(|| {
        format!(
            "renaming mailbox {} to {}",
            source_mailbox, destination_mailbox
        )
    })?;
    conn.execute(
        "UPDATE folders SET name = ?1, path = ?2 WHERE id = ?3",
        params![destination, folder_path(&destination)?, source_id],
    )?;
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
    ensure_folder(&conn, maildir_root, domain, localpart, &name)?;
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
    let name = normalize_mailbox_name(mailbox)?;
    let mut conn = open_account(maildir_root, domain, localpart)?;
    ensure_folder(&conn, maildir_root, domain, localpart, &name)?;
    let tx = conn.transaction()?;
    let folder_id = folder_id(&tx, &name)?.context("missing folder")?;
    let message_exists = tx
        .query_row(
            "SELECT 1 FROM messages WHERE folder_id = ?1 AND uid = ?2",
            params![folder_id, uid as i64],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some();
    if !message_exists {
        tx.commit()?;
        return Ok(0);
    }
    let modseq = next_modseq(&tx, folder_id)?;
    tx.execute(
        "UPDATE messages
         SET flags = ?1, modseq = ?2
         WHERE folder_id = ?3 AND uid = ?4",
        params![flags_to_text(&flags)?, modseq as i64, folder_id, uid as i64],
    )?;
    tx.commit()?;
    Ok(modseq)
}

pub fn delete_message_by_uid(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    uid: u64,
) -> Result<()> {
    let name = normalize_mailbox_name(mailbox)?;
    let mut conn = open_account(maildir_root, domain, localpart)?;
    ensure_folder(&conn, maildir_root, domain, localpart, &name)?;
    let tx = conn.transaction()?;
    let Some((folder_id, filename, subdir)) = tx
        .query_row(
            "SELECT folder_id, filename, subdir
             FROM messages
             WHERE folder_id = (SELECT id FROM folders WHERE name = ?1) AND uid = ?2",
            params![name, uid as i64],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?
    else {
        return Ok(());
    };

    let dir = mailbox_dir(maildir_root, domain, localpart, &name)?;
    let path = dir.join(&subdir).join(&filename);
    if path.exists() {
        let _ = fs::remove_file(&path);
    }
    let modseq = next_modseq(&tx, folder_id)?;
    record_expunge(&tx, folder_id, uid, modseq)?;
    tx.execute(
        "DELETE FROM messages WHERE folder_id = ?1 AND uid = ?2",
        params![folder_id, uid as i64],
    )?;
    tx.commit()?;
    Ok(())
}

enum FileMutationRollback {
    Move {
        source: PathBuf,
        destination: PathBuf,
    },
    Copy {
        destination: PathBuf,
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
            None => {}
        }
    }
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

    let tx = conn.transaction()?;
    let source_id = folder_id(&tx, &source)?.context("missing source folder")?;
    let destination_id = folder_id(&tx, &destination)?.context("missing destination folder")?;
    let Some((filename, subdir, flags, size, internaldate, internaldate_tz)) = tx
        .query_row(
            "SELECT filename, subdir, flags, size, internaldate, internaldate_tz
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
    let source_path = source_dir.join(&subdir).join(&filename);
    let mut destination_filename = filename.clone();
    let mut destination_path = destination_dir.join(&subdir).join(&destination_filename);
    if destination_path.exists() {
        destination_filename = format!(
            "{}.moved.{}.{}",
            filename,
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
            rand::random::<u64>()
        );
        destination_path = destination_dir.join(&subdir).join(&destination_filename);
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
    let destination_modseq = next_modseq(&tx, destination_id)?;
    tx.execute(
        "INSERT INTO messages(folder_id, filename, subdir, uid, flags, size, internaldate, internaldate_tz, save_date, modseq)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
            destination_modseq as i64
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

    let tx = conn.transaction()?;
    let source_id = folder_id(&tx, &source)?.context("missing source folder")?;
    let destination_id = folder_id(&tx, &destination)?.context("missing destination folder")?;
    let Some((filename, subdir, flags, size, internaldate, internaldate_tz)) = tx
        .query_row(
            "SELECT filename, subdir, flags, size, internaldate, internaldate_tz
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
    let source_path = source_dir.join(&subdir).join(&filename);
    let uidnext: i64 = tx.query_row(
        "SELECT uidnext FROM folders WHERE id = ?1",
        params![destination_id],
        |row| row.get(0),
    )?;
    let destination_filename = format!(
        "{}.copy.{}.{}",
        filename,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
        rand::random::<u64>()
    );
    let destination_path = destination_dir.join(&subdir).join(&destination_filename);
    fs::copy(&source_path, &destination_path).with_context(|| {
        format!(
            "copying message {} from {} to {}",
            uid, source_mailbox, destination_mailbox
        )
    })?;
    let file_guard = FileMutationGuard::copied(destination_path);

    let destination_modseq = next_modseq(&tx, destination_id)?;
    tx.execute(
        "INSERT INTO messages(folder_id, filename, subdir, uid, flags, size, internaldate, internaldate_tz, save_date, modseq)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
            destination_modseq as i64
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
        });
    }
    Ok(summaries)
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
    let name = normalize_mailbox_name(mailbox)?;
    let mut conn = open_account(maildir_root, domain, localpart)?;
    if folder_id(&conn, &name)?.is_none() {
        anyhow::bail!("destination mailbox does not exist");
    }
    reconcile_folder(&conn, maildir_root, domain, localpart, &name)?;

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
    file.write_all(data)?;
    file.sync_all()?;
    set_file_mtime(&tmp_path, internaldate)?;
    fs::rename(&tmp_path, &new_path)?;

    let tx = conn.transaction()?;
    let folder = get_folder(&tx, &name)?.context("missing destination folder")?;
    let folder_id = folder_id(&tx, &name)?.context("missing destination folder")?;
    let uid = folder.uidnext;
    let modseq = next_modseq(&tx, folder_id)?;
    tx.execute(
        "INSERT INTO messages(folder_id, filename, subdir, uid, flags, size, internaldate, internaldate_tz, save_date, modseq)
         VALUES(?1, ?2, 'new', ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            folder_id,
            filename,
            uid as i64,
            flags_to_text(&flags)?,
            data.len() as i64,
            internaldate,
            internaldate_tz,
            now.as_secs() as i64,
            modseq as i64
        ],
    )?;
    tx.execute(
        "UPDATE folders SET uidnext = ?1 WHERE id = ?2",
        params![uid.saturating_add(1) as i64, folder_id],
    )?;
    tx.commit()?;
    Ok((folder.uidvalidity, uid))
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

fn folder_id(conn: &Connection, name: &str) -> Result<Option<i64>> {
    conn.query_row(
        "SELECT id FROM folders WHERE name = ?1",
        params![name],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

fn get_folder(conn: &Connection, name: &str) -> Result<Option<Folder>> {
    conn.query_row(
        "SELECT name, path, special_use, subscribed, uidvalidity, uidnext, highest_modseq
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

fn reconcile_folder(
    conn: &Connection,
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    name: &str,
) -> Result<()> {
    let folder_id = folder_id(conn, name)?.context("missing folder")?;
    let dir = mailbox_dir(maildir_root, domain, localpart, name)?;
    ensure_maildir(&dir)?;
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
            let modseq = next_modseq(conn, folder_id)?;
            conn.execute(
                "INSERT INTO messages(folder_id, filename, subdir, uid, flags, size, internaldate, save_date, modseq)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
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
                ],
            )?;
            conn.execute(
                "UPDATE folders SET uidnext = ?1 WHERE id = ?2",
                params![uidnext.saturating_add(1), folder_id],
            )?;
        }
    }
    Ok(())
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
        "SELECT uid, filename, subdir, flags, size, internaldate, internaldate_tz, save_date, modseq
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
        ) = row?;
        messages.push(Message {
            uid,
            path: dir.join(subdir).join(filename),
            flags: flags_from_text(&flags_text)?,
            size,
            internaldate,
            internaldate_tz,
            save_date,
            modseq,
        });
    }
    Ok(messages)
}

fn flags_to_text(flags: &[String]) -> Result<String> {
    Ok(serde_json::to_string(flags)?)
}

fn flags_from_text(text: &str) -> Result<Vec<String>> {
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
        assert!(folder_exists(td.path(), "example.test", "user", "Projects").unwrap());
        set_subscription(td.path(), "example.test", "user", "Projects", false).unwrap();
        let subscribed = list_subscribed_folders(td.path(), "example.test", "user").unwrap();
        assert!(!subscribed.iter().any(|f| f.name == "Projects"));
        delete_folder(td.path(), "example.test", "user", "Projects").unwrap();
        assert!(!folder_exists(td.path(), "example.test", "user", "Projects").unwrap());
    }

    #[test]
    fn rename_folder_preserves_messages_flags_and_subscription() {
        let td = tempfile::tempdir().unwrap();
        create_folder(td.path(), "example.test", "user", "Projects").unwrap();
        let projects = mailbox_dir(td.path(), "example.test", "user", "Projects").unwrap();
        write_msg(&projects, "a", b"Subject: a\r\n\r\nbody");
        let (_, messages) = load_folder(td.path(), "example.test", "user", "Projects").unwrap();
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
        assert!(folder_exists(td.path(), "example.test", "user", "Renamed").unwrap());
        let (folder, renamed) = load_folder(td.path(), "example.test", "user", "Renamed").unwrap();
        assert_eq!(renamed.len(), 1);
        assert_eq!(renamed[0].uid, messages[0].uid);
        assert_eq!(renamed[0].flags, vec!["\\Seen"]);
        assert!(!folder.subscribed);
        assert_eq!(
            fs::read(&renamed[0].path).unwrap(),
            b"Subject: a\r\n\r\nbody"
        );

        assert!(rename_folder(td.path(), "example.test", "user", "INBOX", "Nope").is_err());
    }
}
