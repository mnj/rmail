use anyhow::Result;
use rusqlite::{params, Connection};
use std::path::Path;
use crate::config::Mailbox;
use std::time::{SystemTime, UNIX_EPOCH};
use serde_json;

/// Initialize SQLite DB schema if not present
pub fn init_db<P: AsRef<Path>>(path: P) -> Result<()> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", &"WAL")?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS mailboxes (
            address TEXT PRIMARY KEY,
            password_hash TEXT,
            maildir TEXT,
            created_at INTEGER,
            uidvalidity INTEGER
        );
        CREATE TABLE IF NOT EXISTS catchalls (
            domain TEXT PRIMARY KEY,
            target TEXT
        );
        CREATE TABLE IF NOT EXISTS uid_sequences (
            address TEXT PRIMARY KEY,
            last_uid INTEGER
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT NOT NULL,
            domain TEXT NOT NULL,
            localpart TEXT NOT NULL,
            filename TEXT NOT NULL,
            uid INTEGER NOT NULL,
            flags TEXT,
            created_at INTEGER,
            size INTEGER,
            dkim TEXT,
            spf TEXT,
            dmarc TEXT,
            FOREIGN KEY(address) REFERENCES mailboxes(address)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS messages_address_uid ON messages(address, uid);
        "#,
    )?;
    Ok(())
}

/// Add or replace mailbox
pub fn add_mailbox<P: AsRef<Path>>(path: P, address: &str, password_hash: Option<&str>, maildir: Option<&str>) -> Result<()> {
    let conn = Connection::open(path)?;
    conn.execute(
        "INSERT OR REPLACE INTO mailboxes (address, password_hash, maildir, created_at) VALUES (?1, ?2, ?3, strftime('%s','now'))",
        params![address, password_hash, maildir],
    )?;
    Ok(())
}

/// Get mailbox by exact address
pub fn get_mailbox<P: AsRef<Path>>(path: P, address: &str) -> Result<Option<Mailbox>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare("SELECT address, password_hash, maildir FROM mailboxes WHERE address = ?1")?;
    let mut rows = stmt.query(params![address])?;
    if let Some(row) = rows.next()? {
        let address: String = row.get(0)?;
        let password_hash: Option<String> = row.get(1)?;
        let maildir: Option<String> = row.get(2)?;
        Ok(Some(Mailbox { address, password_hash, maildir }))
    } else {
        Ok(None)
    }
}

/// Find unique mailbox by localpart (address like local@*) — returns None if ambiguous
pub fn find_mailbox_by_localpart<P: AsRef<Path>>(path: P, local: &str) -> Result<Option<Mailbox>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare("SELECT address, password_hash, maildir FROM mailboxes WHERE address LIKE ?1")?;
    let like = format!("{}@%", local);
    let mut rows = stmt.query(params![like])?;
    let mut found: Option<Mailbox> = None;
    while let Some(row) = rows.next()? {
        if found.is_some() { return Ok(None); } // ambiguous
        let address: String = row.get(0)?;
        let password_hash: Option<String> = row.get(1)?;
        let maildir: Option<String> = row.get(2)?;
        found = Some(Mailbox { address, password_hash, maildir });
    }
    Ok(found)
}

/// Check if mailbox exists
pub fn mailbox_exists<P: AsRef<Path>>(path: P, address: &str) -> Result<bool> {
    Ok(get_mailbox(path, address)?.is_some())
}

/// List all mailboxes
pub fn list_mailboxes<P: AsRef<Path>>(path: P) -> Result<Vec<Mailbox>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare("SELECT address, password_hash, maildir FROM mailboxes ORDER BY address")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let address: String = row.get(0)?;
        let password_hash: Option<String> = row.get(1)?;
        let maildir: Option<String> = row.get(2)?;
        out.push(Mailbox { address, password_hash, maildir });
    }
    Ok(out)
}

/// Get catchall target for a domain
pub fn get_catchall<P: AsRef<Path>>(path: P, domain: &str) -> Result<Option<String>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare("SELECT target FROM catchalls WHERE domain = ?1")?;
    let mut rows = stmt.query(params![domain])?;
    if let Some(row) = rows.next()? {
        let target: String = row.get(0)?;
        Ok(Some(target))
    } else {
        Ok(None)
    }
}

/// Set a catchall mapping
pub fn set_catchall<P: AsRef<Path>>(path: P, domain: &str, target: &str) -> Result<()> {
    let conn = Connection::open(path)?;
    conn.execute("INSERT OR REPLACE INTO catchalls (domain, target) VALUES (?1, ?2)", params![domain, target])?;
    Ok(())
}

/// Allocate the next UID for a mailbox (atomic within a transaction)
fn allocate_uid<P: AsRef<Path>>(path: P, address: &str) -> Result<u64> {
    let conn = Connection::open(path)?;
    let tx = conn.transaction()?;
    tx.execute("INSERT OR IGNORE INTO uid_sequences (address, last_uid) VALUES (?1, 0)", params![address])?;
    let last: i64 = tx.query_row("SELECT last_uid FROM uid_sequences WHERE address = ?1", params![address], |r| r.get(0))?;
    let next = last + 1;
    tx.execute("UPDATE uid_sequences SET last_uid = ?1 WHERE address = ?2", params![next, address])?;
    tx.commit()?;
    Ok(next as u64)
}

/// Add a message record after writing the file to Maildir. Returns assigned UID.
pub fn add_message<P: AsRef<Path>>(path: P, domain: &str, local: &str, filename: &str, size: i64, dkim: Option<&str>, spf: Option<&str>, dmarc: Option<&str>) -> Result<u64> {
    let conn = Connection::open(&path)?;
    let address = format!("{}@{}", local, domain);
    // Ensure mailbox exists in case it wasn't created via ctl
    conn.execute("INSERT OR IGNORE INTO mailboxes (address, created_at) VALUES (?1, strftime('%s','now'))", params![&address])?;
    // Allocate UID
    let uid = allocate_uid(&path, &address)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    conn.execute(
        "INSERT INTO messages (address, domain, localpart, filename, uid, flags, created_at, size, dkim, spf, dmarc) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![&address, domain, local, filename, uid as i64, Option::<String>::None, now, size, dkim, spf, dmarc],
    )?;
    Ok(uid)
}

/// List messages for a mailbox ordered by filename (stable ordering)
pub fn list_messages<P: AsRef<Path>>(path: P, domain: &str, local: &str) -> Result<Vec<(u64, String, Vec<String>)>> {
    let conn = Connection::open(path)?;
    let address = format!("{}@{}", local, domain);
    let mut stmt = conn.prepare("SELECT uid, filename, flags FROM messages WHERE address = ?1 ORDER BY filename")?;
    let mut rows = stmt.query(params![address])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let uid: i64 = row.get(0)?;
        let filename: String = row.get(1)?;
        let flags_json: Option<String> = row.get(2)?;
        let flags: Vec<String> = if let Some(s) = flags_json { serde_json::from_str(&s).unwrap_or_default() } else { Vec::new() };
        out.push((uid as u64, filename, flags));
    }
    Ok(out)
}

/// Count messages for a mailbox
pub fn count_messages<P: AsRef<Path>>(path: P, address: &str) -> Result<i64> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare("SELECT COUNT(*) FROM messages WHERE address = ?1")?;
    let v: i64 = stmt.query_row(params![address], |r| r.get(0))?;
    Ok(v)
}

/// Get or create UIDVALIDITY for a mailbox
pub fn get_mailbox_uidvalidity<P: AsRef<Path>>(path: P, address: &str) -> Result<u64> {
    let conn = Connection::open(path)?;
    let res: Result<Option<i64>, rusqlite::Error> = conn.query_row("SELECT uidvalidity FROM mailboxes WHERE address = ?1", params![address], |r| r.get(0)).map(|v: Option<i64>| v);
    match res {
        Ok(Some(v)) => Ok(v as u64),
        Ok(None) => {
            let v = (SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64) ^ (rand::random::<u64>());
            conn.execute("UPDATE mailboxes SET uidvalidity = ?1 WHERE address = ?2", params![v as i64, address])?;
            Ok(v)
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            let v = (SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64) ^ (rand::random::<u64>());
            conn.execute("INSERT INTO mailboxes (address, created_at, uidvalidity) VALUES (?1, strftime('%s','now'), ?2)", params![address, v as i64])?;
            Ok(v)
        }
        Err(e) => Err(e.into()),
    }
}

/// Set flags for a UID
pub fn set_message_flags<P: AsRef<Path>>(path: P, domain: &str, local: &str, uid: u64, flags: Vec<String>) -> Result<()> {
    let conn = Connection::open(path)?;
    let address = format!("{}@{}", local, domain);
    let flags_json = serde_json::to_string(&flags)?;
    conn.execute("UPDATE messages SET flags = ?1 WHERE address = ?2 AND uid = ?3", params![flags_json, address, uid as i64])?;
    Ok(())
}

/// Remove message record by UID (DB-only). Caller may also delete the file on disk.
pub fn delete_message_record<P: AsRef<Path>>(path: P, domain: &str, local: &str, uid: u64) -> Result<()> {
    let conn = Connection::open(path)?;
    let address = format!("{}@{}", local, domain);
    conn.execute("DELETE FROM messages WHERE address = ?1 AND uid = ?2", params![address, uid as i64])?;
    Ok(())
}
