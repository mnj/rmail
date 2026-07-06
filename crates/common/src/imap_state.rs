use crate::maildir::{STANDARD_FOLDERS, ensure_maildir, mailbox_dir, normalize_mailbox_name};
use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{HashMap, HashSet};
use std::fs;
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub uid: u64,
    pub path: PathBuf,
    pub flags: Vec<String>,
    pub size: u64,
    pub internaldate: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderSummary {
    pub folder: Folder,
    pub messages: usize,
    pub unseen: usize,
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
            uidnext INTEGER NOT NULL
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
            FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE CASCADE
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_folder_filename
            ON messages(folder_id, filename);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_folder_uid
            ON messages(folder_id, uid);
        ",
    )?;
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
        "INSERT OR IGNORE INTO folders(name, path, special_use, subscribed, uidvalidity, uidnext)
         VALUES(?1, ?2, ?3, ?4, ?5, 1)",
        params![
            name,
            path,
            special_use,
            i64::from(subscribed),
            uidvalidity as i64
        ],
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
        "SELECT name, path, special_use, subscribed, uidvalidity, uidnext
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
) -> Result<()> {
    let name = normalize_mailbox_name(mailbox)?;
    let conn = open_account(maildir_root, domain, localpart)?;
    ensure_folder(&conn, maildir_root, domain, localpart, &name)?;
    conn.execute(
        "UPDATE messages
         SET flags = ?1
         WHERE folder_id = (SELECT id FROM folders WHERE name = ?2) AND uid = ?3",
        params![flags_to_text(&flags)?, name, uid as i64],
    )?;
    Ok(())
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
    tx.execute(
        "DELETE FROM messages WHERE folder_id = ?1 AND uid = ?2",
        params![folder_id, uid as i64],
    )?;
    tx.commit()?;
    Ok(())
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
    let Some((filename, subdir, flags, size, internaldate)) = tx
        .query_row(
            "SELECT filename, subdir, flags, size, internaldate
             FROM messages WHERE folder_id = ?1 AND uid = ?2",
            params![source_id, uid as i64],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
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

    tx.execute(
        "DELETE FROM messages WHERE folder_id = ?1 AND uid = ?2",
        params![source_id, uid as i64],
    )?;
    let uidnext: i64 = tx.query_row(
        "SELECT uidnext FROM folders WHERE id = ?1",
        params![destination_id],
        |row| row.get(0),
    )?;
    tx.execute(
        "INSERT INTO messages(folder_id, filename, subdir, uid, flags, size, internaldate)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            destination_id,
            destination_filename,
            subdir,
            uidnext,
            flags,
            size,
            internaldate
        ],
    )?;
    tx.execute(
        "UPDATE folders SET uidnext = ?1 WHERE id = ?2",
        params![uidnext.saturating_add(1), destination_id],
    )?;
    tx.commit()?;
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
    let Some((filename, subdir, flags, size, internaldate)) = tx
        .query_row(
            "SELECT filename, subdir, flags, size, internaldate
             FROM messages WHERE folder_id = ?1 AND uid = ?2",
            params![source_id, uid as i64],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
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

    tx.execute(
        "INSERT INTO messages(folder_id, filename, subdir, uid, flags, size, internaldate)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            destination_id,
            destination_filename,
            subdir,
            uidnext,
            flags,
            size,
            internaldate
        ],
    )?;
    tx.execute(
        "UPDATE folders SET uidnext = ?1 WHERE id = ?2",
        params![uidnext.saturating_add(1), destination_id],
    )?;
    tx.commit()?;
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
        "SELECT name, path, special_use, subscribed, uidvalidity, uidnext
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
            })
        },
    )
    .optional()
    .map_err(Into::into)
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
    let mut stmt = conn.prepare("SELECT filename FROM messages WHERE folder_id = ?1")?;
    for row in stmt.query_map(params![folder_id], |row| row.get::<_, String>(0))? {
        existing.insert(row?, ());
    }
    let disk_names = disk
        .iter()
        .map(|(name, _, _, _)| name.clone())
        .collect::<HashSet<_>>();

    for filename in existing.keys() {
        if !disk_names.contains(filename) {
            conn.execute(
                "DELETE FROM messages WHERE folder_id = ?1 AND filename = ?2",
                params![folder_id, filename],
            )?;
        }
    }

    for (filename, subdir, size, internaldate) in disk {
        let updated = conn.execute(
            "UPDATE messages
             SET subdir = ?1, size = ?2, internaldate = ?3
             WHERE folder_id = ?4 AND filename = ?5",
            params![subdir, size, internaldate, folder_id, filename],
        )?;
        if updated == 0 {
            let uidnext: i64 = conn.query_row(
                "SELECT uidnext FROM folders WHERE id = ?1",
                params![folder_id],
                |row| row.get(0),
            )?;
            conn.execute(
                "INSERT INTO messages(folder_id, filename, subdir, uid, flags, size, internaldate)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    folder_id,
                    filename,
                    subdir,
                    uidnext,
                    "[]",
                    size,
                    internaldate
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
        "SELECT uid, filename, subdir, flags, size, internaldate
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
        ))
    })?;

    let mut messages = Vec::new();
    for row in rows {
        let (uid, filename, subdir, flags_text, size, internaldate) = row?;
        messages.push(Message {
            uid,
            path: dir.join(subdir).join(filename),
            flags: flags_from_text(&flags_text)?,
            size,
            internaldate,
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
}
