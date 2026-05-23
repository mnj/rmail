use anyhow::Result;
use rusqlite::{params, Connection};
use std::path::Path;
// Mailbox representation used by DB APIs
#[derive(Debug, Clone)]
pub struct Mailbox {
    pub address: String,
    pub password_hash: Option<String>,
    pub maildir: Option<String>,
    pub scram: Option<String>,
}

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
            uidvalidity INTEGER,
            scram TEXT
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

        -- outbound_queue stores messages that need to be delivered to remote MX hosts. The
        -- queue is authoritative in SQLite so multiple worker processes can coordinate work
        -- by claiming rows in a transaction. Data is stored as a BLOB; in production this
        -- may be replaced with a file reference for very large messages.
        CREATE TABLE IF NOT EXISTS outbound_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT NOT NULL,
            envelope_from TEXT,
            data BLOB NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            next_try INTEGER DEFAULT 0,
            created_at INTEGER
        );

        -- dmarc_events stores individual DMARC evaluation events which are later aggregated
        -- into periodic DMARC aggregate reports (rua). Events are marked reported after being
        -- included in an aggregate report.
        CREATE TABLE IF NOT EXISTS dmarc_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            header_from TEXT,
            envelope_from TEXT,
            source_ip TEXT,
            dkim_result TEXT,
            spf_result TEXT,
            dmarc_result TEXT,
            headers TEXT,
            created_at INTEGER,
            reported INTEGER DEFAULT 0
        );
        "#,
    )?;
    Ok(())
}

/// Add or replace mailbox
pub fn add_mailbox<P: AsRef<Path>>(path: P, address: &str, password_hash: Option<&str>, maildir: Option<&str>, scram: Option<&str>) -> Result<()> {
    let conn = Connection::open(path)?;
    conn.execute(
        "INSERT OR REPLACE INTO mailboxes (address, password_hash, maildir, created_at, scram) VALUES (?1, ?2, ?3, strftime('%s','now'), ?4)",
        params![address, password_hash, maildir, scram],
    )?;
    Ok(())
}

/// Get mailbox by exact address
pub fn get_mailbox<P: AsRef<Path>>(path: P, address: &str) -> Result<Option<Mailbox>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare("SELECT address, password_hash, maildir, scram FROM mailboxes WHERE address = ?1")?;
    let mut rows = stmt.query(params![address])?;
    if let Some(row) = rows.next()? {
        let address: String = row.get(0)?;
        let password_hash: Option<String> = row.get(1)?;
        let maildir: Option<String> = row.get(2)?;
        let scram: Option<String> = row.get(3)?;
        Ok(Some(Mailbox { address, password_hash, maildir, scram }))
    } else {
        Ok(None)
    }
}

/// Find unique mailbox by localpart (address like local@*) — returns None if ambiguous
pub fn find_mailbox_by_localpart<P: AsRef<Path>>(path: P, local: &str) -> Result<Option<Mailbox>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare("SELECT address, password_hash, maildir, scram FROM mailboxes WHERE address LIKE ?1")?;
    let like = format!("{}@%", local);
    let mut rows = stmt.query(params![like])?;
    let mut found: Option<Mailbox> = None;
    while let Some(row) = rows.next()? {
        if found.is_some() { return Ok(None); } // ambiguous
        let address: String = row.get(0)?;
        let password_hash: Option<String> = row.get(1)?;
        let maildir: Option<String> = row.get(2)?;
        let scram: Option<String> = row.get(3)?;
        found = Some(Mailbox { address, password_hash, maildir, scram });
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
    let mut stmt = conn.prepare("SELECT address, password_hash, maildir, scram FROM mailboxes ORDER BY address")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let address: String = row.get(0)?;
        let password_hash: Option<String> = row.get(1)?;
        let maildir: Option<String> = row.get(2)?;
        let scram: Option<String> = row.get(3)?;
        out.push(Mailbox { address, password_hash, maildir, scram });
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
    let mut conn = Connection::open(path)?;
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

/// Enqueue an outbound delivery into the SQLite queue. Returns the inserted row id.
pub fn enqueue_outbound<P: AsRef<Path>>(path: P, recipient: &str, envelope_from: Option<&str>, data: &[u8]) -> Result<i64> {
    let conn = Connection::open(path)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    conn.execute(
        "INSERT INTO outbound_queue (recipient, envelope_from, data, status, attempts, next_try, created_at) VALUES (?1, ?2, ?3, 'queued', 0, 0, ?4)",
        params![recipient, envelope_from, data, now],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Claim the next outbound item for processing. This atomically marks the row as inflight
/// and increments the attempts counter. Returns (id, recipient, envelope_from, data, attempts).
pub fn claim_outbound<P: AsRef<Path>>(path: P) -> Result<Option<(i64, String, Option<String>, Vec<u8>, i64)>> {
    let mut conn = Connection::open(path)?;
    let tx = conn.transaction()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    // Select one queued row eligible for delivery ordered by priority then next_try then created_at
    let mut stmt = tx.prepare("SELECT id, recipient, envelope_from, data, attempts FROM outbound_queue WHERE status = 'queued' AND (next_try IS NULL OR next_try <= ?1) ORDER BY priority DESC, next_try ASC, created_at ASC LIMIT 1")?;
    let mut rows = stmt.query(params![now])?;
    if let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let recipient: String = row.get(1)?;
        let envelope_from: Option<String> = row.get(2)?;
        let data: Vec<u8> = row.get(3)?;
        let attempts: i64 = row.get(4)?;
        // Drop query handles before committing the transaction to avoid borrow issues
        drop(rows);
        drop(stmt);
        tx.execute("UPDATE outbound_queue SET status = 'inflight', attempts = attempts + 1 WHERE id = ?1", params![id])?;
        tx.commit()?;
        return Ok(Some((id, recipient, envelope_from, data, attempts + 1)));
    }
    Ok(None)
}

/// Mark an outbound item as successfully delivered.
pub fn mark_outbound_sent<P: AsRef<Path>>(path: P, id: i64) -> Result<()> {
    let conn = Connection::open(path)?;
    conn.execute("UPDATE outbound_queue SET status = 'sent' WHERE id = ?1", params![id])?;
    Ok(())
}

/// Mark an outbound item as failed and schedule a retry after `retry_after_seconds` if provided.
pub fn mark_outbound_failed<P: AsRef<Path>>(path: P, id: i64, last_error: Option<&str>, retry_after_seconds: Option<i64>) -> Result<()> {
    let conn = Connection::open(path)?;
    // Fetch current attempts and configured max_attempts (default 5)
    let mut stmt = conn.prepare("SELECT attempts, max_attempts FROM outbound_queue WHERE id = ?1")?;
    let mut rows = stmt.query(params![id])?;
    let (attempts, max_attempts) = if let Some(row) = rows.next()? {
        let a: i64 = row.get(0)?;
        let m: Option<i64> = row.get(1)?;
        (a, m.unwrap_or(5))
    } else {
        (0, 5)
    };

    if attempts >= max_attempts {
        // Move to dead-letter state
        conn.execute("UPDATE outbound_queue SET status = 'dead', last_error = ?1 WHERE id = ?2", params![last_error, id])?;
    } else {
        let next_try = if let Some(s) = retry_after_seconds { (SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64) + s } else { 0 };
        conn.execute("UPDATE outbound_queue SET status = 'queued', last_error = ?1, next_try = ?2 WHERE id = ?3", params![last_error, next_try, id])?;
    }
    Ok(())
}

/// Return the number of pending outbound items (not yet marked as 'sent'). This is a simple
/// helper for metrics and web UI to show queue depth.
pub fn count_outbound_pending<P: AsRef<Path>>(path: P) -> Result<i64> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare("SELECT COUNT(*) FROM outbound_queue WHERE status != 'sent'")?;
    let v: i64 = stmt.query_row([], |r| r.get(0))?;
    Ok(v)
}

/// Record a DMARC evaluation event for later aggregation into rua reports. Returns inserted id.
pub fn add_dmarc_event<P: AsRef<Path>>(path: P, domain: &str, header_from: Option<&str>, envelope_from: Option<&str>, source_ip: Option<&str>, dkim: Option<&str>, spf: Option<&str>, dmarc: Option<&str>, headers: Option<&str>) -> Result<i64> {
    let conn = Connection::open(path)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    conn.execute(
        "INSERT INTO dmarc_events (domain, header_from, envelope_from, source_ip, dkim_result, spf_result, dmarc_result, headers, created_at, reported) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)",
        params![domain, header_from, envelope_from, source_ip, dkim, spf, dmarc, headers, now],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Return domains which have unreported DMARC events (reported = 0)
pub fn get_unreported_dmarc_domains<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare("SELECT DISTINCT domain FROM dmarc_events WHERE reported = 0")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let domain: String = row.get(0)?;
        out.push(domain);
    }
    Ok(out)
}

/// Fetch unreported DMARC events for a specific domain
pub fn fetch_unreported_dmarc_events_for_domain<P: AsRef<Path>>(path: P, domain: &str) -> Result<Vec<(i64, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, i64)>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare("SELECT id, header_from, envelope_from, source_ip, dkim_result, spf_result, dmarc_result, created_at FROM dmarc_events WHERE domain = ?1 AND reported = 0 ORDER BY created_at")?;
    let mut rows = stmt.query(params![domain])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let header_from: Option<String> = row.get(1)?;
        let envelope_from: Option<String> = row.get(2)?;
        let source_ip: Option<String> = row.get(3)?;
        let dkim: Option<String> = row.get(4)?;
        let spf: Option<String> = row.get(5)?;
        let dmarc: Option<String> = row.get(6)?;
        let created_at: i64 = row.get(7)?;
        out.push((id, header_from, envelope_from, source_ip, dkim, spf, dmarc, created_at));
    }
    Ok(out)
}

/// Mark a list of DMARC event ids as reported
pub fn mark_dmarc_events_reported<P: AsRef<Path>>(path: P, ids: &[i64]) -> Result<()> {
    let mut conn = Connection::open(path)?;
    let tx = conn.transaction()?;
    for id in ids {
        tx.execute("UPDATE dmarc_events SET reported = 1 WHERE id = ?1", params![id])?;
    }
    tx.commit()?;
    Ok(())
}

/// Ensure outbound_queue has the columns required by the queue manager (priority, max_attempts).
pub fn ensure_outbound_columns<P: AsRef<Path>>(path: P) -> Result<()> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare("PRAGMA table_info(outbound_queue)")?;
    let mut rows = stmt.query([])?;
    let mut has_priority = false;
    let mut has_max_attempts = false;
    while let Some(r) = rows.next()? {
        let col: String = r.get(1)?;
        if col == "priority" { has_priority = true; }
        if col == "max_attempts" { has_max_attempts = true; }
    }
    if !has_priority {
        let _ = conn.execute("ALTER TABLE outbound_queue ADD COLUMN priority INTEGER DEFAULT 0", []);
    }
    if !has_max_attempts {
        let _ = conn.execute("ALTER TABLE outbound_queue ADD COLUMN max_attempts INTEGER DEFAULT 5", []);
    }
    Ok(())
}
