use anyhow::Result;
use rusqlite::{params, Connection};
use std::path::Path;
use crate::config::Mailbox;

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
            created_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS catchalls (
            domain TEXT PRIMARY KEY,
            target TEXT
        );
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
