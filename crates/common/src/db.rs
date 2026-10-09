use crate::sqlite_pool::SqliteConnection;
use anyhow::Result;
use rusqlite::params;
use std::path::Path;

struct Connection;

impl Connection {
    fn open(path: impl AsRef<Path>) -> Result<SqliteConnection> {
        crate::sqlite_pool::connection(path.as_ref())
    }
}
// Mailbox representation used by DB APIs
#[derive(Debug, Clone)]
pub struct Mailbox {
    pub address: String,
    pub password_hash: Option<String>,
    pub maildir: Option<String>,
    pub scram: Option<String>,
    /// Maximum stored message bytes for this account. `None` means unlimited.
    pub quota_bytes: Option<u64>,
}

use serde_json;
use std::time::{SystemTime, UNIX_EPOCH};

/// Make the database readable by its owner only: it holds password hashes,
/// DKIM private keys and relay passwords. SQLite gives the `-wal` and `-shm`
/// files it creates the database's mode, and existing ones are fixed here.
pub fn restrict_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use anyhow::Context;
        use std::os::unix::fs::PermissionsExt;
        for suffix in ["", "-wal", "-shm"] {
            let mut file = path.as_os_str().to_owned();
            file.push(suffix);
            let file = std::path::PathBuf::from(file);
            let mode = match std::fs::metadata(&file) {
                Ok(metadata) => metadata.permissions().mode(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error).with_context(|| format!("reading {}", file.display()));
                }
            };
            if mode & 0o077 != 0 {
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode & 0o7700))
                    .with_context(|| format!("restricting permissions of {}", file.display()))?;
            }
        }
    }
    Ok(())
}

/// Initialize SQLite DB schema if not present
pub fn init_db<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    let conn = Connection::open(path)?;
    restrict_permissions(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS mailboxes (
            address TEXT PRIMARY KEY,
            password_hash TEXT,
            maildir TEXT,
            created_at INTEGER,
            uidvalidity INTEGER,
            scram TEXT,
            quota_bytes INTEGER
        );
        CREATE TABLE IF NOT EXISTS catchalls (
            domain TEXT PRIMARY KEY,
            target TEXT
        );
        CREATE TABLE IF NOT EXISTS aliases (
            address TEXT PRIMARY KEY,
            targets TEXT NOT NULL,
            created_at INTEGER
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
            priority INTEGER DEFAULT 0,
            max_attempts INTEGER DEFAULT 5,
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

        -- Sieve scripts per account (full lowercase address); at most one is active.
        CREATE TABLE IF NOT EXISTS sieve_scripts (
            account TEXT NOT NULL,
            name TEXT NOT NULL,
            content TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (account, name)
        ) WITHOUT ROWID;

        -- Last vacation reply per (account, sender, reply key), to send one per period.
        CREATE TABLE IF NOT EXISTS sieve_vacation (
            account TEXT NOT NULL,
            sender TEXT NOT NULL,
            reply_key TEXT NOT NULL,
            sent_at INTEGER NOT NULL,
            PRIMARY KEY (account, sender, reply_key)
        ) WITHOUT ROWID;

        -- tlsrpt_counts aggregates outbound TLS outcomes per UTC day (see tlsrpt.rs).
        CREATE TABLE IF NOT EXISTS tlsrpt_counts (
            day TEXT NOT NULL,
            domain TEXT NOT NULL,
            policy_type TEXT NOT NULL,
            mx_host TEXT NOT NULL,
            result TEXT NOT NULL,
            count INTEGER NOT NULL,
            info TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (day, domain, policy_type, mx_host, result)
        ) WITHOUT ROWID;

        -- DKIM keys (see dkim.rs): every key for a domain signs its mail; the
        -- one with arc = 1 seals forwarded mail.
        CREATE TABLE IF NOT EXISTS dkim_keys (
            domain TEXT NOT NULL,
            selector TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            private_key TEXT NOT NULL,
            arc INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (domain, selector)
        ) WITHOUT ROWID;

        -- Delivery routes (see transport.rs); domain '*' is the default route.
        CREATE TABLE IF NOT EXISTS transport_routes (
            domain TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            host TEXT,
            port INTEGER,
            implicit_tls INTEGER NOT NULL DEFAULT 0,
            username TEXT,
            password TEXT,
            reply TEXT,
            updated_at INTEGER NOT NULL
        ) WITHOUT ROWID;

        -- greylist is a periodic snapshot of the in-memory greylist (see greylist.rs).
        CREATE TABLE IF NOT EXISTS greylist (
            key TEXT PRIMARY KEY,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL
        ) WITHOUT ROWID;
        "#,
    )?;
    ensure_outbound_columns(path)?;
    add_column_if_missing(path, "mailboxes", "quota_bytes", "INTEGER")?;
    Ok(())
}

/// Replace the persisted greylist with `records` in one transaction.
pub fn save_greylist<P: AsRef<Path>>(
    path: P,
    records: &[crate::greylist::GreylistRecord],
) -> Result<()> {
    let mut conn = Connection::open(path)?;
    // Wait out a concurrent save (e.g. the shutdown flush overlapping a
    // periodic one) instead of failing with SQLITE_BUSY.
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    let tx = conn.transaction()?;
    tx.execute("DELETE FROM greylist", [])?;
    {
        let mut stmt =
            tx.prepare("INSERT INTO greylist (key, first_seen, last_seen) VALUES (?1, ?2, ?3)")?;
        for record in records {
            stmt.execute(params![
                record.key,
                record.first_seen as i64,
                record.last_seen as i64
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

pub fn load_greylist<P: AsRef<Path>>(path: P) -> Result<Vec<crate::greylist::GreylistRecord>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare("SELECT key, first_seen, last_seen FROM greylist")?;
    let rows = stmt.query_map([], |row| {
        Ok(crate::greylist::GreylistRecord {
            key: row.get(0)?,
            first_seen: row.get::<_, i64>(1)? as u64,
            last_seen: row.get::<_, i64>(2)? as u64,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Add or replace mailbox
pub fn add_mailbox<P: AsRef<Path>>(
    path: P,
    address: &str,
    password_hash: Option<&str>,
    maildir: Option<&str>,
    scram: Option<&str>,
) -> Result<()> {
    let address = crate::domain::canonicalize_mailbox_address(address)?;
    let conn = Connection::open(path)?;
    conn.execute(
        "INSERT INTO mailboxes (address, password_hash, maildir, created_at, scram)
         VALUES (?1, ?2, ?3, strftime('%s','now'), ?4)
         ON CONFLICT(address) DO UPDATE SET
             password_hash = excluded.password_hash,
             maildir = excluded.maildir,
             scram = excluded.scram",
        params![address, password_hash, maildir, scram],
    )?;
    Ok(())
}

/// Remove a mailbox from the account database.
pub fn remove_mailbox<P: AsRef<Path>>(path: P, address: &str) -> Result<()> {
    let address = crate::domain::canonicalize_mailbox_address(address)?;
    let conn = Connection::open(path)?;
    conn.execute("DELETE FROM mailboxes WHERE address = ?1", params![address])?;
    Ok(())
}

/// Get mailbox by exact address
pub fn get_mailbox<P: AsRef<Path>>(path: P, address: &str) -> Result<Option<Mailbox>> {
    let address = crate::domain::canonicalize_mailbox_address(address)?;
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare(
        "SELECT address, password_hash, maildir, scram, quota_bytes FROM mailboxes WHERE address = ?1",
    )?;
    let mut rows = stmt.query(params![address])?;
    if let Some(row) = rows.next()? {
        let address: String = row.get(0)?;
        let password_hash: Option<String> = row.get(1)?;
        let maildir: Option<String> = row.get(2)?;
        let scram: Option<String> = row.get(3)?;
        let quota_bytes = row
            .get::<_, Option<i64>>(4)?
            .map(u64::try_from)
            .transpose()?;
        Ok(Some(Mailbox {
            address,
            password_hash,
            maildir,
            scram,
            quota_bytes,
        }))
    } else {
        Ok(None)
    }
}

/// Find unique mailbox by localpart (address like local@*) — returns None if ambiguous
pub fn find_mailbox_by_localpart<P: AsRef<Path>>(path: P, local: &str) -> Result<Option<Mailbox>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare(
        "SELECT address, password_hash, maildir, scram, quota_bytes FROM mailboxes WHERE address LIKE ?1",
    )?;
    let like = format!("{}@%", local);
    let mut rows = stmt.query(params![like])?;
    let mut found: Option<Mailbox> = None;
    while let Some(row) = rows.next()? {
        if found.is_some() {
            return Ok(None);
        } // ambiguous
        let address: String = row.get(0)?;
        let password_hash: Option<String> = row.get(1)?;
        let maildir: Option<String> = row.get(2)?;
        let scram: Option<String> = row.get(3)?;
        let quota_bytes = row
            .get::<_, Option<i64>>(4)?
            .map(u64::try_from)
            .transpose()?;
        found = Some(Mailbox {
            address,
            password_hash,
            maildir,
            scram,
            quota_bytes,
        });
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
    let mut stmt = conn
        .prepare("SELECT address, password_hash, maildir, scram, quota_bytes FROM mailboxes ORDER BY address")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let address: String = row.get(0)?;
        let password_hash: Option<String> = row.get(1)?;
        let maildir: Option<String> = row.get(2)?;
        let scram: Option<String> = row.get(3)?;
        let quota_bytes = row
            .get::<_, Option<i64>>(4)?
            .map(u64::try_from)
            .transpose()?;
        out.push(Mailbox {
            address,
            password_hash,
            maildir,
            scram,
            quota_bytes,
        });
    }
    Ok(out)
}

/// Set the maximum stored message bytes for an account. `None` removes the limit.
pub fn set_mailbox_quota<P: AsRef<Path>>(
    path: P,
    address: &str,
    quota_bytes: Option<u64>,
) -> Result<()> {
    let address = crate::domain::canonicalize_mailbox_address(address)?;
    let quota_bytes = quota_bytes.map(i64::try_from).transpose()?;
    let conn = Connection::open(path)?;
    let changed = conn.execute(
        "UPDATE mailboxes SET quota_bytes = ?1 WHERE address = ?2",
        params![quota_bytes, address],
    )?;
    if changed == 0 {
        anyhow::bail!("mailbox does not exist");
    }
    Ok(())
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Store (create or replace) a script. Replacing keeps its active flag.
pub fn put_sieve_script<P: AsRef<Path>>(
    path: P,
    account: &str,
    name: &str,
    content: &str,
) -> Result<()> {
    let conn = Connection::open(path)?;
    conn.execute(
        "INSERT INTO sieve_scripts (account, name, content, active, updated_at) VALUES (?1, ?2, ?3, 0, ?4)
         ON CONFLICT(account, name) DO UPDATE SET content = excluded.content, updated_at = excluded.updated_at",
        params![account.to_ascii_lowercase(), name, content, unix_now()],
    )?;
    Ok(())
}

pub fn get_sieve_script<P: AsRef<Path>>(
    path: P,
    account: &str,
    name: &str,
) -> Result<Option<String>> {
    let conn = Connection::open(path)?;
    let mut stmt =
        conn.prepare("SELECT content FROM sieve_scripts WHERE account = ?1 AND name = ?2")?;
    let mut rows = stmt.query(params![account.to_ascii_lowercase(), name])?;
    Ok(rows.next()?.map(|row| row.get(0)).transpose()?)
}

/// `(name, active)` for each script, by name.
pub fn list_sieve_scripts<P: AsRef<Path>>(path: P, account: &str) -> Result<Vec<(String, bool)>> {
    let conn = Connection::open(path)?;
    let mut stmt =
        conn.prepare("SELECT name, active FROM sieve_scripts WHERE account = ?1 ORDER BY name")?;
    let rows = stmt.query_map(params![account.to_ascii_lowercase()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? != 0))
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn get_active_sieve_script<P: AsRef<Path>>(path: P, account: &str) -> Result<Option<String>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn
        .prepare("SELECT content FROM sieve_scripts WHERE account = ?1 AND active = 1 LIMIT 1")?;
    let mut rows = stmt.query(params![account.to_ascii_lowercase()])?;
    Ok(rows.next()?.map(|row| row.get(0)).transpose()?)
}

/// Make `name` the only active script, or deactivate all with `None`.
/// Returns false when `name` does not exist.
pub fn set_active_sieve_script<P: AsRef<Path>>(
    path: P,
    account: &str,
    name: Option<&str>,
) -> Result<bool> {
    let mut conn = Connection::open(path)?;
    let tx = conn.transaction()?;
    let account = account.to_ascii_lowercase();
    if let Some(name) = name {
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sieve_scripts WHERE account = ?1 AND name = ?2)",
            params![account, name],
            |row| row.get(0),
        )?;
        if !exists {
            return Ok(false);
        }
    }
    tx.execute(
        "UPDATE sieve_scripts SET active = 0 WHERE account = ?1",
        params![account],
    )?;
    if let Some(name) = name {
        tx.execute(
            "UPDATE sieve_scripts SET active = 1 WHERE account = ?1 AND name = ?2",
            params![account, name],
        )?;
    }
    tx.commit()?;
    Ok(true)
}

/// Rename a script, keeping its active flag. Returns false when `from` does
/// not exist; fails when `to` already does.
pub fn rename_sieve_script<P: AsRef<Path>>(
    path: P,
    account: &str,
    from: &str,
    to: &str,
) -> Result<bool> {
    let conn = Connection::open(path)?;
    let changed = conn.execute(
        "UPDATE sieve_scripts SET name = ?3, updated_at = ?4 WHERE account = ?1 AND name = ?2",
        params![account.to_ascii_lowercase(), from, to, unix_now()],
    )?;
    Ok(changed == 1)
}

/// Delete an inactive script. Returns false when it does not exist or is active.
pub fn delete_sieve_script<P: AsRef<Path>>(path: P, account: &str, name: &str) -> Result<bool> {
    let conn = Connection::open(path)?;
    let changed = conn.execute(
        "DELETE FROM sieve_scripts WHERE account = ?1 AND name = ?2 AND active = 0",
        params![account.to_ascii_lowercase(), name],
    )?;
    Ok(changed == 1)
}

/// True when a vacation reply may be sent now: records the send atomically,
/// so two concurrent deliveries cannot both reply within `days`.
pub fn vacation_claim_reply<P: AsRef<Path>>(
    path: P,
    account: &str,
    sender: &str,
    reply_key: &str,
    days: u32,
) -> Result<bool> {
    let conn = Connection::open(path)?;
    let now = unix_now();
    let changed = conn.execute(
        "INSERT INTO sieve_vacation (account, sender, reply_key, sent_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(account, sender, reply_key) DO UPDATE SET sent_at = excluded.sent_at
         WHERE sieve_vacation.sent_at <= ?5",
        params![
            account.to_ascii_lowercase(),
            sender.to_ascii_lowercase(),
            reply_key,
            now,
            now - i64::from(days) * 86_400
        ],
    )?;
    Ok(changed == 1)
}

/// Add `rows` to the persisted TLS-RPT counters in one transaction.
pub fn add_tlsrpt_counts<P: AsRef<Path>>(
    path: P,
    rows: &[crate::tlsrpt::CounterRow],
) -> Result<()> {
    let mut conn = Connection::open(path)?;
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO tlsrpt_counts (day, domain, policy_type, mx_host, result, count, info)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(day, domain, policy_type, mx_host, result)
             DO UPDATE SET count = count + excluded.count,
                           info = CASE WHEN excluded.info = '' THEN info ELSE excluded.info END",
        )?;
        for row in rows {
            stmt.execute(params![
                row.day,
                row.domain,
                row.policy_type,
                row.mx_host,
                row.result,
                row.count as i64,
                row.info
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Counters for one day and policy domain.
pub fn tlsrpt_rows<P: AsRef<Path>>(
    path: P,
    day: &str,
    domain: &str,
) -> Result<Vec<crate::tlsrpt::CounterRow>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare(
        "SELECT day, domain, policy_type, mx_host, result, count, info FROM tlsrpt_counts
         WHERE day = ?1 AND domain = ?2 ORDER BY policy_type, mx_host, result",
    )?;
    let rows = stmt.query_map(params![day, domain], |row| {
        Ok(crate::tlsrpt::CounterRow {
            day: row.get(0)?,
            domain: row.get(1)?,
            policy_type: row.get(2)?,
            mx_host: row.get(3)?,
            result: row.get(4)?,
            count: row.get::<_, i64>(5)? as u64,
            info: row.get(6)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// (day, domain) pairs from days before `today` that still need a report.
pub fn tlsrpt_due<P: AsRef<Path>>(path: P, today: &str) -> Result<Vec<(String, String)>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare(
        "SELECT DISTINCT day, domain FROM tlsrpt_counts WHERE day < ?1 ORDER BY day, domain",
    )?;
    let rows = stmt.query_map(params![today], |row| Ok((row.get(0)?, row.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn tlsrpt_delete<P: AsRef<Path>>(path: P, day: &str, domain: &str) -> Result<()> {
    let conn = Connection::open(path)?;
    conn.execute(
        "DELETE FROM tlsrpt_counts WHERE day = ?1 AND domain = ?2",
        params![day, domain],
    )?;
    Ok(())
}

/// True when `domain` has a mailbox, an alias with targets or a catchall on
/// this server.
pub fn is_local_domain<P: AsRef<Path>>(path: P, domain: &str) -> Result<bool> {
    let conn = Connection::open(path)?;
    let domain = domain.to_ascii_lowercase();
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM mailboxes WHERE lower(substr(address, instr(address, '@') + 1)) = ?1)
             OR EXISTS(SELECT 1 FROM aliases WHERE targets != '[]' AND lower(substr(address, instr(address, '@') + 1)) = ?1)
             OR EXISTS(SELECT 1 FROM catchalls WHERE lower(domain) = ?1)",
        params![domain],
        |row| row.get(0),
    )?;
    Ok(exists)
}

/// Every domain with a mailbox, an alias with targets or a catchall, sorted.
pub fn local_domains<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare(
        "SELECT lower(substr(address, instr(address, '@') + 1)) AS d FROM mailboxes WHERE instr(address, '@') > 0
         UNION SELECT lower(substr(address, instr(address, '@') + 1)) FROM aliases WHERE instr(address, '@') > 0 AND targets != '[]'
         UNION SELECT lower(domain) FROM catchalls ORDER BY 1",
    )?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Get catchall target for a domain
pub fn get_catchall<P: AsRef<Path>>(path: P, domain: &str) -> Result<Option<String>> {
    let domain = crate::domain::canonicalize_domain(domain)?;
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
    let domain = crate::domain::canonicalize_domain(domain)?;
    let target = crate::domain::canonicalize_mailbox_address(target)?;
    let conn = Connection::open(path)?;
    conn.execute(
        "INSERT OR REPLACE INTO catchalls (domain, target) VALUES (?1, ?2)",
        params![domain, target],
    )?;
    Ok(())
}

/// Remove a catchall mapping.
pub fn remove_catchall<P: AsRef<Path>>(path: P, domain: &str) -> Result<()> {
    let domain = crate::domain::canonicalize_domain(domain)?;
    let conn = Connection::open(path)?;
    conn.execute("DELETE FROM catchalls WHERE domain = ?1", params![domain])?;
    Ok(())
}

/// List catchall mappings.
pub fn list_catchalls<P: AsRef<Path>>(path: P) -> Result<Vec<(String, String)>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare("SELECT domain, target FROM catchalls ORDER BY domain")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push((row.get(0)?, row.get(1)?));
    }
    Ok(out)
}

/// Add or update an alias mapping. Targets is a JSON array of address strings (may include remote addresses).
pub fn add_alias<P: AsRef<Path>>(path: P, address: &str, targets: &[&str]) -> Result<()> {
    let address = crate::domain::canonicalize_mailbox_address(address)?;
    let targets = targets
        .iter()
        .map(|target| crate::domain::canonicalize_mailbox_address(target))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let conn = Connection::open(path)?;
    let targets_json = serde_json::to_string(&targets)?;
    conn.execute("INSERT OR REPLACE INTO aliases (address, targets, created_at) VALUES (?1, ?2, strftime('%s','now'))", params![address, targets_json])?;
    Ok(())
}

/// Get alias targets for an exact address, or None if no alias exists.
pub fn get_alias_targets<P: AsRef<Path>>(path: P, address: &str) -> Result<Option<Vec<String>>> {
    let address = crate::domain::canonicalize_mailbox_address(address)?;
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare("SELECT targets FROM aliases WHERE address = ?1")?;
    let mut rows = stmt.query(params![address])?;
    if let Some(row) = rows.next()? {
        let targets_json: String = row.get(0)?;
        let v: Vec<String> = serde_json::from_str(&targets_json).unwrap_or_default();
        Ok(Some(v))
    } else {
        Ok(None)
    }
}

/// Remove an alias mapping
pub fn remove_alias<P: AsRef<Path>>(path: P, address: &str) -> Result<()> {
    let address = crate::domain::canonicalize_mailbox_address(address)?;
    let conn = Connection::open(path)?;
    conn.execute("DELETE FROM aliases WHERE address = ?1", params![address])?;
    Ok(())
}

/// List aliases
pub fn list_aliases<P: AsRef<Path>>(path: P) -> Result<Vec<(String, Vec<String>)>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare("SELECT address, targets FROM aliases ORDER BY address")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let addr: String = row.get(0)?;
        let targets_json: String = row.get(1)?;
        let targets: Vec<String> = serde_json::from_str(&targets_json).unwrap_or_default();
        out.push((addr, targets));
    }
    Ok(out)
}

/// Allocate the next UID for a mailbox (atomic within a transaction)
fn allocate_uid<P: AsRef<Path>>(path: P, address: &str) -> Result<u64> {
    let mut conn = Connection::open(path)?;
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT OR IGNORE INTO uid_sequences (address, last_uid) VALUES (?1, 0)",
        params![address],
    )?;
    let last: i64 = tx.query_row(
        "SELECT last_uid FROM uid_sequences WHERE address = ?1",
        params![address],
        |r| r.get(0),
    )?;
    let next = last + 1;
    tx.execute(
        "UPDATE uid_sequences SET last_uid = ?1 WHERE address = ?2",
        params![next, address],
    )?;
    tx.commit()?;
    Ok(next as u64)
}

/// Add a message record after writing the file to Maildir. Returns assigned UID.
pub fn add_message<P: AsRef<Path>>(
    path: P,
    domain: &str,
    local: &str,
    filename: &str,
    size: i64,
    dkim: Option<&str>,
    spf: Option<&str>,
    dmarc: Option<&str>,
) -> Result<u64> {
    let conn = Connection::open(&path)?;
    let address = format!("{}@{}", local, domain);
    // Ensure mailbox exists in case it wasn't created via ctl
    conn.execute(
        "INSERT OR IGNORE INTO mailboxes (address, created_at) VALUES (?1, strftime('%s','now'))",
        params![&address],
    )?;
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
pub fn list_messages<P: AsRef<Path>>(
    path: P,
    domain: &str,
    local: &str,
) -> Result<Vec<(u64, String, Vec<String>)>> {
    let conn = Connection::open(path)?;
    let address = format!("{}@{}", local, domain);
    let mut stmt = conn.prepare(
        "SELECT uid, filename, flags FROM messages WHERE address = ?1 ORDER BY filename",
    )?;
    let mut rows = stmt.query(params![address])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let uid: i64 = row.get(0)?;
        let filename: String = row.get(1)?;
        let flags_json: Option<String> = row.get(2)?;
        let flags: Vec<String> = if let Some(s) = flags_json {
            serde_json::from_str(&s).unwrap_or_default()
        } else {
            Vec::new()
        };
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
    let res: Result<Option<i64>, rusqlite::Error> = conn
        .query_row(
            "SELECT uidvalidity FROM mailboxes WHERE address = ?1",
            params![address],
            |r| r.get(0),
        )
        .map(|v: Option<i64>| v);
    match res {
        Ok(Some(v)) => Ok(v as u64),
        Ok(None) => {
            let v = (SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64)
                ^ (rand::random::<u64>());
            conn.execute(
                "UPDATE mailboxes SET uidvalidity = ?1 WHERE address = ?2",
                params![v as i64, address],
            )?;
            Ok(v)
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            let v = (SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64)
                ^ (rand::random::<u64>());
            conn.execute("INSERT INTO mailboxes (address, created_at, uidvalidity) VALUES (?1, strftime('%s','now'), ?2)", params![address, v as i64])?;
            Ok(v)
        }
        Err(e) => Err(e.into()),
    }
}

/// Set flags for a UID
pub fn set_message_flags<P: AsRef<Path>>(
    path: P,
    domain: &str,
    local: &str,
    uid: u64,
    flags: Vec<String>,
) -> Result<()> {
    let conn = Connection::open(path)?;
    let address = format!("{}@{}", local, domain);
    let flags_json = serde_json::to_string(&flags)?;
    conn.execute(
        "UPDATE messages SET flags = ?1 WHERE address = ?2 AND uid = ?3",
        params![flags_json, address, uid as i64],
    )?;
    Ok(())
}

/// Remove message record by UID (DB-only). Caller may also delete the file on disk.
pub fn delete_message_record<P: AsRef<Path>>(
    path: P,
    domain: &str,
    local: &str,
    uid: u64,
) -> Result<()> {
    let conn = Connection::open(path)?;
    let address = format!("{}@{}", local, domain);
    conn.execute(
        "DELETE FROM messages WHERE address = ?1 AND uid = ?2",
        params![address, uid as i64],
    )?;
    Ok(())
}

/// Enqueue an outbound delivery into the SQLite queue. Returns the inserted row id.
pub fn enqueue_outbound<P: AsRef<Path>>(
    path: P,
    recipient: &str,
    envelope_from: Option<&str>,
    data: &[u8],
) -> Result<i64> {
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
pub fn claim_outbound<P: AsRef<Path>>(
    path: P,
) -> Result<Option<(i64, String, Option<String>, Vec<u8>, i64)>> {
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
        tx.execute(
            "UPDATE outbound_queue SET status = 'inflight', attempts = attempts + 1 WHERE id = ?1",
            params![id],
        )?;
        tx.commit()?;
        return Ok(Some((id, recipient, envelope_from, data, attempts + 1)));
    }
    Ok(None)
}

/// Mark an outbound item as successfully delivered.
pub fn mark_outbound_sent<P: AsRef<Path>>(path: P, id: i64) -> Result<()> {
    let conn = Connection::open(path)?;
    conn.execute(
        "UPDATE outbound_queue SET status = 'sent' WHERE id = ?1",
        params![id],
    )?;
    Ok(())
}

/// Mark an outbound item as failed and schedule a retry after `retry_after_seconds` if provided.
pub fn mark_outbound_failed<P: AsRef<Path>>(
    path: P,
    id: i64,
    last_error: Option<&str>,
    retry_after_seconds: Option<i64>,
) -> Result<()> {
    let conn = Connection::open(path)?;
    // Fetch current attempts and configured max_attempts (default 5)
    let mut stmt =
        conn.prepare("SELECT attempts, max_attempts FROM outbound_queue WHERE id = ?1")?;
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
        conn.execute(
            "UPDATE outbound_queue SET status = 'dead', last_error = ?1 WHERE id = ?2",
            params![last_error, id],
        )?;
    } else {
        let next_try = if let Some(s) = retry_after_seconds {
            (SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64) + s
        } else {
            0
        };
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
pub fn add_dmarc_event<P: AsRef<Path>>(
    path: P,
    domain: &str,
    header_from: Option<&str>,
    envelope_from: Option<&str>,
    source_ip: Option<&str>,
    dkim: Option<&str>,
    spf: Option<&str>,
    dmarc: Option<&str>,
    headers: Option<&str>,
) -> Result<i64> {
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
pub fn fetch_unreported_dmarc_events_for_domain<P: AsRef<Path>>(
    path: P,
    domain: &str,
) -> Result<
    Vec<(
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        i64,
    )>,
> {
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
        out.push((
            id,
            header_from,
            envelope_from,
            source_ip,
            dkim,
            spf,
            dmarc,
            created_at,
        ));
    }
    Ok(out)
}

/// Mark a list of DMARC event ids as reported
pub fn mark_dmarc_events_reported<P: AsRef<Path>>(path: P, ids: &[i64]) -> Result<()> {
    let mut conn = Connection::open(path)?;
    let tx = conn.transaction()?;
    for id in ids {
        tx.execute(
            "UPDATE dmarc_events SET reported = 1 WHERE id = ?1",
            params![id],
        )?;
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
        if col == "priority" {
            has_priority = true;
        }
        if col == "max_attempts" {
            has_max_attempts = true;
        }
    }
    if !has_priority {
        let _ = conn.execute(
            "ALTER TABLE outbound_queue ADD COLUMN priority INTEGER DEFAULT 0",
            [],
        );
    }
    if !has_max_attempts {
        let _ = conn.execute(
            "ALTER TABLE outbound_queue ADD COLUMN max_attempts INTEGER DEFAULT 5",
            [],
        );
    }
    Ok(())
}

fn add_column_if_missing(path: &Path, table: &str, column: &str, definition: &str) -> Result<()> {
    let conn = Connection::open(path)?;
    let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !columns.iter().any(|name| name == column) {
        conn.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
            [],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        add_alias, add_mailbox, get_alias_targets, get_catchall, get_mailbox, init_db,
        set_catchall, set_mailbox_quota,
    };
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[cfg(unix)]
    #[test]
    fn database_files_are_readable_by_their_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let td = tempdir().expect("tempdir");
        let db = td.path().join("rmail.db");
        std::fs::write(&db, b"").unwrap();
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
        init_db(&db).expect("init db");
        crate::settings::open(&db).unwrap();
        for suffix in ["", "-wal", "-shm"] {
            let path = td.path().join(format!("rmail.db{suffix}"));
            if let Ok(metadata) = std::fs::metadata(&path) {
                assert_eq!(metadata.permissions().mode() & 0o777, 0o600, "{suffix}");
            }
        }
    }

    #[test]
    fn sieve_scripts_have_one_active_and_cannot_delete_it() {
        let td = tempdir().expect("tempdir");
        let db = td.path().join("sieve.db");
        init_db(&db).expect("init db");
        let acct = "Bob@Example.com";
        super::put_sieve_script(&db, acct, "a", "keep;").unwrap();
        super::put_sieve_script(&db, acct, "b", "discard;").unwrap();
        assert_eq!(super::get_active_sieve_script(&db, acct).unwrap(), None);
        assert!(super::set_active_sieve_script(&db, acct, Some("a")).unwrap());
        assert!(super::set_active_sieve_script(&db, acct, Some("b")).unwrap());
        assert_eq!(
            super::get_active_sieve_script(&db, "bob@example.com")
                .unwrap()
                .as_deref(),
            Some("discard;")
        );
        assert_eq!(
            super::list_sieve_scripts(&db, acct).unwrap(),
            vec![("a".to_string(), false), ("b".to_string(), true)]
        );
        assert!(!super::set_active_sieve_script(&db, acct, Some("nope")).unwrap());
        assert!(
            !super::delete_sieve_script(&db, acct, "b").unwrap(),
            "active scripts stay"
        );
        assert!(super::delete_sieve_script(&db, acct, "a").unwrap());
        // Replacing content keeps the active flag.
        super::put_sieve_script(&db, acct, "b", "keep;").unwrap();
        assert_eq!(
            super::get_active_sieve_script(&db, acct)
                .unwrap()
                .as_deref(),
            Some("keep;")
        );
        assert!(super::set_active_sieve_script(&db, acct, None).unwrap());
        assert_eq!(super::get_active_sieve_script(&db, acct).unwrap(), None);
        assert_eq!(
            super::get_sieve_script(&db, acct, "b").unwrap().as_deref(),
            Some("keep;")
        );
    }

    #[test]
    fn vacation_reply_is_claimed_once_per_period() {
        let td = tempdir().expect("tempdir");
        let db = td.path().join("vac.db");
        init_db(&db).expect("init db");
        assert!(super::vacation_claim_reply(&db, "bob@x.test", "A@y.test", "k", 7).unwrap());
        assert!(!super::vacation_claim_reply(&db, "bob@x.test", "a@y.test", "k", 7).unwrap());
        // Another sender, key or account is independent.
        assert!(super::vacation_claim_reply(&db, "bob@x.test", "c@y.test", "k", 7).unwrap());
        assert!(super::vacation_claim_reply(&db, "bob@x.test", "a@y.test", "k2", 7).unwrap());
        assert!(super::vacation_claim_reply(&db, "eve@x.test", "a@y.test", "k", 7).unwrap());
        // Backdate the record: after the period it can be claimed again.
        let conn = Connection::open(&db).unwrap();
        conn.execute(
            "UPDATE sieve_vacation SET sent_at = sent_at - 8 * 86400",
            [],
        )
        .unwrap();
        assert!(super::vacation_claim_reply(&db, "bob@x.test", "a@y.test", "k", 7).unwrap());
    }

    #[test]
    fn local_domains_come_from_mailboxes_aliases_and_catchalls() {
        let td = tempdir().expect("tempdir");
        let db_path = td.path().join("domains.db");
        init_db(&db_path).expect("init db");
        add_mailbox(&db_path, "Alice@Example.COM", None, None, None).expect("mailbox");
        set_catchall(&db_path, "other.test", "alice@example.com").expect("catchall");
        add_alias(&db_path, "info@Forward.test", &["alice@example.com"]).expect("alias");
        add_alias(&db_path, "empty@dead.test", &[]).expect("empty alias");

        assert!(super::is_local_domain(&db_path, "forward.test").unwrap());
        assert!(!super::is_local_domain(&db_path, "dead.test").unwrap());
        assert!(super::is_local_domain(&db_path, "example.com").unwrap());
        assert!(super::is_local_domain(&db_path, "EXAMPLE.com").unwrap());
        assert!(super::is_local_domain(&db_path, "other.test").unwrap());
        assert!(!super::is_local_domain(&db_path, "nope.test").unwrap());
        assert!(!super::is_local_domain(&db_path, "xample.com").unwrap());
        assert_eq!(
            super::local_domains(&db_path).unwrap(),
            vec![
                "example.com".to_string(),
                "forward.test".to_string(),
                "other.test".to_string()
            ]
        );
    }

    #[test]
    fn init_db_provisions_outbound_queue_columns() {
        let td = tempdir().expect("tempdir");
        let db_path = td.path().join("test.db");
        init_db(&db_path).expect("init db");

        let conn = Connection::open(&db_path).expect("open db");
        let mut stmt = conn
            .prepare("PRAGMA table_info(outbound_queue)")
            .expect("pragma");
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query");
        let columns: Vec<String> = rows.map(|r| r.expect("column")).collect();

        assert!(columns.iter().any(|c| c == "priority"));
        assert!(columns.iter().any(|c| c == "max_attempts"));
    }

    #[test]
    fn mailbox_quota_migrates_and_survives_credential_updates() {
        let td = tempdir().expect("tempdir");
        let db_path = td.path().join("legacy.db");
        let conn = Connection::open(&db_path).expect("open legacy db");
        conn.execute_batch(
            "CREATE TABLE mailboxes(
                address TEXT PRIMARY KEY,
                password_hash TEXT,
                maildir TEXT,
                created_at INTEGER,
                uidvalidity INTEGER,
                scram TEXT
            );",
        )
        .expect("legacy schema");
        drop(conn);

        init_db(&db_path).expect("migrate schema");
        add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:first"),
            None,
            None,
        )
        .expect("add mailbox");
        set_mailbox_quota(&db_path, "user@example.test", Some(1_048_576)).expect("set quota");
        add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:second"),
            None,
            None,
        )
        .expect("update credentials");

        let mailbox = get_mailbox(&db_path, "user@example.test")
            .expect("lookup")
            .expect("mailbox");
        assert_eq!(mailbox.password_hash.as_deref(), Some("plain:second"));
        assert_eq!(mailbox.quota_bytes, Some(1_048_576));
        set_mailbox_quota(&db_path, "user@example.test", None).expect("clear quota");
        assert_eq!(
            get_mailbox(&db_path, "user@example.test")
                .unwrap()
                .unwrap()
                .quota_bytes,
            None
        );
    }

    #[test]
    fn identity_boundaries_canonicalize_idn_domains() {
        let td = tempdir().expect("tempdir");
        let db_path = td.path().join("test.db");
        init_db(&db_path).unwrap();
        add_mailbox(&db_path, "User@BÜCHER.example", None, None, None).unwrap();
        assert_eq!(
            get_mailbox(&db_path, "User@xn--bcher-kva.example")
                .unwrap()
                .unwrap()
                .address,
            "User@xn--bcher-kva.example"
        );
        add_alias(&db_path, "team@BÜCHER.example", &["User@BÜCHER.example"]).unwrap();
        assert_eq!(
            get_alias_targets(&db_path, "team@xn--bcher-kva.example")
                .unwrap()
                .unwrap(),
            ["User@xn--bcher-kva.example"]
        );
        set_catchall(&db_path, "BÜCHER.example", "User@BÜCHER.example").unwrap();
        assert_eq!(
            get_catchall(&db_path, "xn--bcher-kva.example")
                .unwrap()
                .as_deref(),
            Some("User@xn--bcher-kva.example")
        );
    }
}
