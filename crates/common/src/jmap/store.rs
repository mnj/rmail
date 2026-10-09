//! JMAP state in each account's state database.
//!
//! - `jmap_changes` has one row per object that ever changed: its kind
//!   (`Email`, `Mailbox`, `Thread`, ...), the account-wide sequence number of
//!   its last change, of its creation, and of its last change other than its
//!   counts (Mailbox only), and whether it is destroyed. Triggers on the
//!   message and folder tables keep it current whatever changed the mailbox
//!   (IMAP, delivery, webmail, Sieve, Maildir reconciliation), so `/changes`
//!   needs no cooperation from those paths. The sequence number is the JMAP
//!   state string.
//! - `jmap_emails` indexes what JMAP needs about each email but IMAP does
//!   not store: its thread and the header fields queries filter and sort
//!   on. Emails are indexed lazily, at the start of each JMAP request.
//! - `jmap_thread_refs` maps every Message-ID seen to its thread.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

use crate::imap_state;
use crate::jmap::{address, mime};
use crate::maildir::{mailbox_dir, message_path};

/// Destroyed objects are remembered this long; older states cannot be
/// brought up to date and the client resynchronizes.
const TOMBSTONE_SECONDS: i64 = 60 * 24 * 60 * 60;
/// Characters of preview text kept per email (RFC 8621 allows up to 256).
pub const PREVIEW_CHARS: usize = 256;

/// SQL logging a change of `kind` for the object `id_expr` (an SQL
/// expression), as one statement pair. `created` and `destroyed` are SQL
/// boolean expressions; `counts_only` marks Mailbox changes that only
/// changed its counts.
fn log_sql(kind: &str, id_expr: &str, created: &str, destroyed: &str, counts_only: bool) -> String {
    format!(
        "UPDATE jmap_state SET seq = seq + 1 WHERE singleton = 1;
         INSERT INTO jmap_changes(kind, object_id, seq, created_seq, props_seq, destroyed, changed_at)
         SELECT '{kind}', {id_expr}, s.seq,
                CASE WHEN {created} THEN s.seq ELSE 0 END,
                CASE WHEN {counts_only} THEN 0 ELSE s.seq END,
                CASE WHEN {destroyed} THEN 1 ELSE 0 END,
                strftime('%s','now')
         FROM jmap_state s WHERE s.singleton = 1 AND {id_expr} IS NOT NULL
         ON CONFLICT(kind, object_id) DO UPDATE SET
             seq = excluded.seq,
             created_seq = CASE
                 WHEN excluded.created_seq != 0 AND jmap_changes.destroyed = 1
                     THEN excluded.created_seq
                 ELSE jmap_changes.created_seq END,
             props_seq = CASE WHEN {counts_only} THEN jmap_changes.props_seq
                 ELSE excluded.props_seq END,
             destroyed = excluded.destroyed,
             changed_at = excluded.changed_at;",
        counts_only = if counts_only { "1" } else { "0" },
    )
}

/// The MAILBOXID of a folder row id, as an SQL expression.
fn mailbox_of(folder_expr: &str) -> String {
    format!("(SELECT mailbox_id FROM folders WHERE id = {folder_expr})")
}

pub(crate) fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS jmap_state(
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            seq INTEGER NOT NULL,
            min_seq INTEGER NOT NULL
        );
        INSERT OR IGNORE INTO jmap_state(singleton, seq, min_seq) VALUES(1, 0, 0);
        CREATE TABLE IF NOT EXISTS jmap_changes(
            kind TEXT NOT NULL,
            object_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            created_seq INTEGER NOT NULL,
            props_seq INTEGER NOT NULL,
            destroyed INTEGER NOT NULL,
            changed_at INTEGER NOT NULL,
            PRIMARY KEY(kind, object_id)
        );
        CREATE INDEX IF NOT EXISTS idx_jmap_changes_seq ON jmap_changes(kind, seq);
        CREATE INDEX IF NOT EXISTS idx_messages_email_id ON messages(email_id);
        CREATE TABLE IF NOT EXISTS jmap_emails(
            email_id TEXT PRIMARY KEY,
            thread_id TEXT NOT NULL,
            received_at INTEGER NOT NULL,
            sent_at INTEGER,
            size INTEGER NOT NULL,
            subject TEXT NOT NULL,
            from_text TEXT NOT NULL,
            to_text TEXT NOT NULL,
            cc_text TEXT NOT NULL,
            bcc_text TEXT NOT NULL,
            preview TEXT NOT NULL,
            has_attachment INTEGER NOT NULL,
            message_id TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_jmap_emails_thread ON jmap_emails(thread_id);
        CREATE TABLE IF NOT EXISTS jmap_thread_refs(
            message_id TEXT PRIMARY KEY,
            thread_id TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS jmap_identities(
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            reply_to TEXT,
            bcc TEXT,
            text_signature TEXT NOT NULL,
            html_signature TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS jmap_submissions(
            id TEXT PRIMARY KEY,
            identity_id TEXT NOT NULL,
            email_id TEXT NOT NULL,
            thread_id TEXT NOT NULL,
            envelope TEXT NOT NULL,
            send_at INTEGER NOT NULL,
            delivery_status TEXT NOT NULL,
            undo_status TEXT NOT NULL DEFAULT 'final',
            hold_id TEXT
        );
        ",
    )?;
    // Scheduled sending (pending submissions) came after the table.
    imap_state::add_column_if_missing(
        conn,
        "jmap_submissions",
        "undo_status",
        "TEXT NOT NULL DEFAULT 'final'",
    )?;
    imap_state::add_column_if_missing(conn, "jmap_submissions", "hold_id", "TEXT")?;
    let email_created = |row: &str| {
        format!(
            "NOT EXISTS (SELECT 1 FROM messages o WHERE o.email_id = {row}.email_id AND o.id != {row}.id)"
        )
    };
    let triggers = [
        (
            "jmap_message_inserted",
            "AFTER INSERT ON messages WHEN NEW.email_id IS NOT NULL",
            format!(
                "{}{}",
                log_sql("Email", "NEW.email_id", &email_created("NEW"), "0", false),
                log_sql("Mailbox", &mailbox_of("NEW.folder_id"), "0", "0", true)
            ),
        ),
        (
            // Rows inserted without an EMAILID get one right after.
            "jmap_message_id_assigned",
            "AFTER UPDATE OF email_id ON messages
             WHEN OLD.email_id IS NULL AND NEW.email_id IS NOT NULL",
            format!(
                "{}{}",
                log_sql("Email", "NEW.email_id", &email_created("NEW"), "0", false),
                log_sql("Mailbox", &mailbox_of("NEW.folder_id"), "0", "0", true)
            ),
        ),
        (
            "jmap_message_changed",
            "AFTER UPDATE OF flags, folder_id ON messages
             WHEN OLD.email_id IS NOT NULL
              AND (OLD.flags IS NOT NEW.flags OR OLD.folder_id != NEW.folder_id)",
            format!(
                "{}{}{}",
                log_sql("Email", "NEW.email_id", "0", "0", false),
                log_sql("Mailbox", &mailbox_of("NEW.folder_id"), "0", "0", true),
                log_sql("Mailbox", &mailbox_of("OLD.folder_id"), "0", "0", true)
            ),
        ),
        (
            "jmap_message_deleted",
            "AFTER DELETE ON messages WHEN OLD.email_id IS NOT NULL",
            format!(
                "{}{}
                 DELETE FROM jmap_emails WHERE email_id = OLD.email_id
                   AND NOT EXISTS (SELECT 1 FROM messages WHERE email_id = OLD.email_id);",
                log_sql(
                    "Email",
                    "OLD.email_id",
                    "0",
                    "NOT EXISTS (SELECT 1 FROM messages WHERE email_id = OLD.email_id)",
                    false
                ),
                log_sql("Mailbox", &mailbox_of("OLD.folder_id"), "0", "0", true)
            ),
        ),
        (
            "jmap_folder_inserted",
            "AFTER INSERT ON folders WHEN NEW.mailbox_id IS NOT NULL",
            log_sql("Mailbox", "NEW.mailbox_id", "1", "0", false),
        ),
        (
            "jmap_folder_id_assigned",
            "AFTER UPDATE OF mailbox_id ON folders
             WHEN OLD.mailbox_id IS NULL AND NEW.mailbox_id IS NOT NULL",
            log_sql("Mailbox", "NEW.mailbox_id", "1", "0", false),
        ),
        (
            "jmap_folder_changed",
            "AFTER UPDATE OF name, special_use ON folders
             WHEN OLD.name IS NOT NEW.name OR OLD.special_use IS NOT NEW.special_use",
            log_sql("Mailbox", "NEW.mailbox_id", "0", "0", false),
        ),
        (
            "jmap_folder_deleted",
            "AFTER DELETE ON folders WHEN OLD.mailbox_id IS NOT NULL",
            log_sql("Mailbox", "OLD.mailbox_id", "0", "1", false),
        ),
        (
            "jmap_subscribed",
            "AFTER INSERT ON subscriptions",
            log_sql(
                "Mailbox",
                "(SELECT mailbox_id FROM folders WHERE name = NEW.name)",
                "0",
                "0",
                false,
            ),
        ),
        (
            "jmap_unsubscribed",
            "AFTER DELETE ON subscriptions",
            log_sql(
                "Mailbox",
                "(SELECT mailbox_id FROM folders WHERE name = OLD.name)",
                "0",
                "0",
                false,
            ),
        ),
        (
            "jmap_thread_member_added",
            "AFTER INSERT ON jmap_emails",
            log_sql(
                "Thread",
                "NEW.thread_id",
                "NOT EXISTS (SELECT 1 FROM jmap_emails WHERE thread_id = NEW.thread_id
                             AND email_id != NEW.email_id)",
                "0",
                false,
            ),
        ),
        (
            "jmap_thread_member_removed",
            "AFTER DELETE ON jmap_emails",
            log_sql(
                "Thread",
                "OLD.thread_id",
                "0",
                "NOT EXISTS (SELECT 1 FROM jmap_emails WHERE thread_id = OLD.thread_id)",
                false,
            ),
        ),
    ];
    for (name, when, body) in triggers {
        conn.execute_batch(&format!(
            "CREATE TRIGGER IF NOT EXISTS {name} {when} BEGIN {body} END;"
        ))?;
    }
    Ok(())
}

/// Record a change made by JMAP itself (identities, submissions).
pub fn log_change(
    conn: &Connection,
    kind: &str,
    id: &str,
    created: bool,
    destroyed: bool,
) -> Result<()> {
    let sql = log_sql(
        kind,
        "?1",
        if created { "1" } else { "0" },
        if destroyed { "1" } else { "0" },
        false,
    );
    // One savepoint, so the row gets the sequence number this call took
    // even when another writer bumps it meanwhile.
    conn.execute_batch("SAVEPOINT jmap_log_change")?;
    let logged = (|| -> Result<()> {
        for statement in sql.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            if statement.contains("?1") {
                conn.execute(statement, params![id])?;
            } else {
                conn.execute(statement, [])?;
            }
        }
        Ok(())
    })();
    match logged {
        Ok(()) => conn.execute_batch("RELEASE jmap_log_change")?,
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK TO jmap_log_change; RELEASE jmap_log_change");
            return Err(error);
        }
    }
    Ok(())
}

/// The current state (sequence number).
pub fn state(conn: &Connection) -> Result<u64> {
    Ok(conn.query_row(
        "SELECT seq FROM jmap_state WHERE singleton = 1",
        [],
        |row| row.get::<_, i64>(0),
    )? as u64)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Changes {
    pub created: Vec<String>,
    pub updated: Vec<String>,
    pub destroyed: Vec<String>,
    /// Whether every updated object changed only its counts (Mailbox).
    pub counts_only: bool,
    /// The state the lists bring the client to.
    pub new_state: u64,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangesError {
    /// The state is from before the oldest change still remembered, or
    /// from the future.
    CannotCalculate,
}

/// What changed for `kind` since `since`, at most `max` objects (the oldest
/// changes first, so `has_more` can continue from `new_state`).
pub fn changes(
    conn: &Connection,
    kind: &str,
    since: u64,
    max: Option<usize>,
) -> Result<std::result::Result<Changes, ChangesError>> {
    let (current, min_seq): (i64, i64) = conn.query_row(
        "SELECT seq, min_seq FROM jmap_state WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if since as i64 > current || (since as i64) < min_seq {
        return Ok(Err(ChangesError::CannotCalculate));
    }
    let mut statement = conn.prepare(
        "SELECT object_id, seq, created_seq, props_seq, destroyed FROM jmap_changes
         WHERE kind = ?1 AND seq > ?2 ORDER BY seq",
    )?;
    let rows = statement
        .query_map(params![kind, since as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)? != 0,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut out = Changes {
        counts_only: true,
        new_state: current as u64,
        ..Default::default()
    };
    let limit = max.unwrap_or(usize::MAX);
    let mut taken = 0;
    for (index, (id, seq, created_seq, props_seq, destroyed)) in rows.iter().enumerate() {
        let existed_before = *created_seq <= since as i64;
        if taken == limit {
            out.has_more = true;
            out.new_state = rows[index - 1].1 as u64;
            break;
        }
        // Objects that changed several times in a row share one sequence
        // number per change, so a cut never splits one object's changes.
        let _ = seq;
        match (existed_before, *destroyed) {
            (true, true) => out.destroyed.push(id.clone()),
            (false, true) => continue,
            (false, false) => out.created.push(id.clone()),
            (true, false) => {
                if *props_seq > since as i64 {
                    out.counts_only = false;
                }
                out.updated.push(id.clone());
            }
        }
        taken += 1;
    }
    if out.updated.is_empty() {
        out.counts_only = false;
    }
    Ok(Ok(out))
}

/// Forget destroyed objects older than the tombstone period. States from
/// before the newest forgotten change can no longer be updated.
pub fn prune(conn: &Connection) -> Result<()> {
    let cutoff = chrono::Utc::now().timestamp() - TOMBSTONE_SECONDS;
    let newest_forgotten: Option<i64> = conn.query_row(
        "SELECT MAX(seq) FROM jmap_changes WHERE destroyed = 1 AND changed_at < ?1",
        params![cutoff],
        |row| row.get(0),
    )?;
    if let Some(seq) = newest_forgotten {
        conn.execute(
            "DELETE FROM jmap_changes WHERE destroyed = 1 AND seq <= ?1",
            params![seq],
        )?;
        conn.execute(
            "UPDATE jmap_state SET min_seq = MAX(min_seq, ?1) WHERE singleton = 1",
            params![seq],
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Synchronizing and indexing

/// Bring the account's database up to date for a JMAP request: reconcile
/// every folder with its Maildir and index new emails.
pub fn sync_account(maildir_root: &Path, domain: &str, localpart: &str) -> Result<()> {
    let conn = imap_state::open_account(maildir_root, domain, localpart)?;
    let names = {
        let mut statement = conn.prepare("SELECT name FROM folders")?;
        statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for name in names {
        imap_state::reconcile_folder(&conn, maildir_root, domain, localpart, &name)?;
    }
    index_new_emails(&conn, maildir_root, domain, localpart)?;
    Ok(())
}

/// What indexing learns from a message.
#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub sent_at: Option<i64>,
    pub subject: String,
    pub from: String,
    pub to: String,
    pub cc: String,
    pub bcc: String,
    pub preview: String,
    pub has_attachment: bool,
    pub message_id: Option<String>,
    /// Message-IDs this message refers to (In-Reply-To, then References).
    pub refs: Vec<String>,
}

fn address_text(value: Option<&String>) -> String {
    value
        .map(|value| {
            address::parse(&mime::unfold(value))
                .iter()
                .map(|address| match &address.name {
                    Some(name) => format!("{name} <{}>", address.email),
                    None => address.email.clone(),
                })
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

pub fn summarize(message: &[u8]) -> Summary {
    let root = mime::parse(message);
    let headers = mime::header_map(&root.headers);
    let lists = mime::body_lists(&root);
    let mut refs = Vec::new();
    for name in ["in-reply-to", "references"] {
        if let Some(ids) = headers
            .get(name)
            .and_then(|value| mime::as_message_ids(value))
        {
            for id in ids {
                if !refs.contains(&id) {
                    refs.push(id);
                }
            }
        }
    }
    Summary {
        sent_at: headers
            .get("date")
            .and_then(|value| mime::parse_date(value))
            .map(|date| date.timestamp()),
        subject: headers
            .get("subject")
            .map(|value| mime::as_text(value))
            .unwrap_or_default(),
        from: address_text(headers.get("from")),
        to: address_text(headers.get("to")),
        cc: address_text(headers.get("cc")),
        bcc: address_text(headers.get("bcc")),
        preview: mime::preview(message, &root, &lists, PREVIEW_CHARS),
        has_attachment: mime::has_attachment(&root, &lists),
        message_id: headers
            .get("message-id")
            .and_then(|value| mime::as_message_ids(value))
            .and_then(|ids| ids.into_iter().next()),
        refs,
    }
}

fn new_thread_id() -> String {
    format!("T{:024x}", rand::random::<u128>() >> 32)
}

/// Index every email without an index row, assigning threads: an email
/// joins the thread of any message it refers to or that refers to it.
fn index_new_emails(
    conn: &Connection,
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
) -> Result<()> {
    let pending = {
        let mut statement = conn.prepare(
            "SELECT m.email_id, f.name, m.subdir, m.filename, MIN(m.internaldate), m.size
             FROM messages m JOIN folders f ON f.id = m.folder_id
             WHERE m.email_id IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM jmap_emails e WHERE e.email_id = m.email_id)
             GROUP BY m.email_id",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for chunk in pending.chunks(200) {
        let summaries = chunk
            .iter()
            .map(|(_, folder, subdir, filename, _, _)| {
                mailbox_dir(maildir_root, domain, localpart, folder)
                    .and_then(|dir| message_path(&dir, subdir, filename))
                    .ok()
                    .and_then(|path| std::fs::read(path).ok())
                    .map(|data| summarize(&data))
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>();
        let tx = conn.unchecked_transaction()?;
        for ((email_id, _, _, _, received_at, size), summary) in chunk.iter().zip(summaries) {
            let mut ids = summary.refs.clone();
            if let Some(id) = &summary.message_id {
                ids.insert(0, id.clone());
            }
            let mut thread_id = None;
            for id in &ids {
                thread_id = tx
                    .query_row(
                        "SELECT thread_id FROM jmap_thread_refs WHERE message_id = ?1",
                        params![id],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?;
                if thread_id.is_some() {
                    break;
                }
            }
            let thread_id = thread_id.unwrap_or_else(new_thread_id);
            for id in &ids {
                tx.execute(
                    "INSERT OR IGNORE INTO jmap_thread_refs(message_id, thread_id) VALUES(?1, ?2)",
                    params![id, thread_id],
                )?;
            }
            tx.execute(
                "INSERT OR IGNORE INTO jmap_emails(email_id, thread_id, received_at, sent_at, size,
                     subject, from_text, to_text, cc_text, bcc_text, preview, has_attachment,
                     message_id)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    email_id,
                    thread_id,
                    received_at,
                    summary.sent_at,
                    size,
                    summary.subject,
                    summary.from,
                    summary.to,
                    summary.cc,
                    summary.bcc,
                    summary.preview,
                    summary.has_attachment,
                    summary.message_id,
                ],
            )?;
        }
        tx.commit()?;
    }
    prune(conn)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Reading

/// A mailbox as JMAP needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxRow {
    pub mailbox_id: String,
    /// The full IMAP name, `/`-separated.
    pub name: String,
    pub special_use: Option<String>,
    pub subscribed: bool,
    pub total_emails: u64,
    pub unread_emails: u64,
    pub total_threads: u64,
    pub unread_threads: u64,
}

pub fn mailboxes(conn: &Connection) -> Result<Vec<MailboxRow>> {
    let subscribed = {
        let mut statement = conn.prepare("SELECT name FROM subscriptions")?;
        statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<HashSet<_>>>()?
    };
    let mut statement = conn.prepare(
        "SELECT f.id, f.name, f.special_use, f.mailbox_id FROM folders f
         WHERE f.mailbox_id IS NOT NULL ORDER BY f.name",
    )?;
    let folders = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    // Per folder: (email, thread, seen) for counting emails and threads.
    let mut members: HashMap<i64, Vec<(String, Option<String>, bool)>> = HashMap::new();
    let mut statement = conn.prepare(
        "SELECT m.folder_id, m.email_id, e.thread_id, m.flags FROM messages m
         LEFT JOIN jmap_emails e ON e.email_id = m.email_id
         WHERE m.email_id IS NOT NULL",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    for row in rows {
        let (folder_id, email_id, thread_id, flags) = row?;
        let flags = imap_state::flags_from_text(&flags)?;
        let seen = flags.iter().any(|flag| flag.eq_ignore_ascii_case("\\Seen"));
        members
            .entry(folder_id)
            .or_default()
            .push((email_id, thread_id, seen));
    }
    Ok(folders
        .into_iter()
        .map(|(id, name, special_use, mailbox_id)| {
            let rows = members.remove(&id).unwrap_or_default();
            let emails = rows.iter().map(|row| &row.0).collect::<HashSet<_>>();
            let unread = rows
                .iter()
                .filter(|row| !row.2)
                .map(|row| &row.0)
                .collect::<HashSet<_>>();
            let threads = rows
                .iter()
                .map(|row| row.1.as_ref().unwrap_or(&row.0))
                .collect::<HashSet<_>>();
            let unread_threads = rows
                .iter()
                .filter(|row| !row.2)
                .map(|row| row.1.as_ref().unwrap_or(&row.0))
                .collect::<HashSet<_>>();
            MailboxRow {
                mailbox_id,
                subscribed: subscribed.contains(&name),
                name,
                special_use,
                total_emails: emails.len() as u64,
                unread_emails: unread.len() as u64,
                total_threads: threads.len() as u64,
                unread_threads: unread_threads.len() as u64,
            }
        })
        .collect())
}

/// One stored copy of an email.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Copy {
    pub mailbox_id: String,
    pub folder: String,
    pub uid: u64,
    pub flags: Vec<String>,
    pub path: PathBuf,
}

/// An email: its copies and its index row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailRow {
    pub email_id: String,
    pub thread_id: String,
    pub received_at: i64,
    pub sent_at: Option<i64>,
    pub size: u64,
    pub subject: String,
    pub from: String,
    pub to: String,
    pub cc: String,
    pub bcc: String,
    pub preview: String,
    pub has_attachment: bool,
    pub copies: Vec<Copy>,
}

impl EmailRow {
    /// The union of the copies' flags (a keyword set on any copy counts).
    pub fn flags(&self) -> Vec<String> {
        let mut flags: Vec<String> = Vec::new();
        for copy in &self.copies {
            for flag in &copy.flags {
                if !flags.iter().any(|known| known.eq_ignore_ascii_case(flag)) {
                    flags.push(flag.clone());
                }
            }
        }
        flags
    }

    pub fn has_flag(&self, flag: &str) -> bool {
        self.copies.iter().any(|copy| {
            copy.flags
                .iter()
                .any(|known| known.eq_ignore_ascii_case(flag))
        })
    }
}

/// Every indexed email, or only `ids` when given.
pub fn emails(
    conn: &Connection,
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    ids: Option<&[String]>,
) -> Result<Vec<EmailRow>> {
    let wanted: Option<HashSet<&str>> = ids.map(|ids| ids.iter().map(String::as_str).collect());
    let mut statement = conn.prepare(
        "SELECT e.email_id, e.thread_id, e.received_at, e.sent_at, e.size, e.subject, e.from_text,
                e.to_text, e.cc_text, e.bcc_text, e.preview, e.has_attachment,
                f.mailbox_id, f.name, m.uid, m.flags, m.subdir, m.filename
         FROM jmap_emails e
         JOIN messages m ON m.email_id = e.email_id
         JOIN folders f ON f.id = m.folder_id
         ORDER BY e.email_id, f.name",
    )?;
    let mut rows = statement.query([])?;
    let mut out: Vec<EmailRow> = Vec::new();
    let mut dirs: HashMap<String, PathBuf> = HashMap::new();
    while let Some(row) = rows.next()? {
        let email_id: String = row.get(0)?;
        if let Some(wanted) = &wanted
            && !wanted.contains(email_id.as_str())
        {
            continue;
        }
        let folder: String = row.get(13)?;
        let dir = match dirs.get(&folder) {
            Some(dir) => dir.clone(),
            None => {
                let dir = mailbox_dir(maildir_root, domain, localpart, &folder)?;
                dirs.insert(folder.clone(), dir.clone());
                dir
            }
        };
        let copy = Copy {
            mailbox_id: row.get(12)?,
            uid: row.get::<_, i64>(14)? as u64,
            flags: imap_state::flags_from_text(&row.get::<_, String>(15)?)?,
            path: message_path(&dir, &row.get::<_, String>(16)?, &row.get::<_, String>(17)?)?,
            folder,
        };
        match out.last_mut() {
            Some(last) if last.email_id == email_id => last.copies.push(copy),
            _ => out.push(EmailRow {
                email_id,
                thread_id: row.get(1)?,
                received_at: row.get(2)?,
                sent_at: row.get(3)?,
                size: row.get::<_, i64>(4)? as u64,
                subject: row.get(5)?,
                from: row.get(6)?,
                to: row.get(7)?,
                cc: row.get(8)?,
                bcc: row.get(9)?,
                preview: row.get(10)?,
                has_attachment: row.get::<_, i64>(11)? != 0,
                copies: vec![copy],
            }),
        }
    }
    Ok(out)
}

/// The email ids of each requested thread, oldest first.
pub fn threads(conn: &Connection, ids: &[String]) -> Result<HashMap<String, Vec<String>>> {
    let mut statement = conn.prepare(
        "SELECT email_id FROM jmap_emails WHERE thread_id = ?1
           AND EXISTS (SELECT 1 FROM messages m WHERE m.email_id = jmap_emails.email_id)
         ORDER BY received_at, email_id",
    )?;
    let mut out = HashMap::new();
    for id in ids {
        let emails = statement
            .query_map(params![id], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if !emails.is_empty() {
            out.insert(id.clone(), emails);
        }
    }
    Ok(out)
}

/// The EMAILID of the message `uid` in `folder`.
pub fn email_id_at(conn: &Connection, folder: &str, uid: u64) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT m.email_id FROM messages m JOIN folders f ON f.id = m.folder_id
             WHERE f.name = ?1 AND m.uid = ?2",
            params![folder, uid as i64],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten())
}

/// The JMAP thread of each of `email_ids`, indexing new emails first.
/// IMAP reports these as THREADID (RFC 8474).
pub fn thread_ids(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    email_ids: &[String],
) -> Result<HashMap<String, String>> {
    let conn = open(maildir_root, domain, localpart)?;
    index_new_emails(&conn, maildir_root, domain, localpart)?;
    let mut statement = conn.prepare("SELECT thread_id FROM jmap_emails WHERE email_id = ?1")?;
    let mut out = HashMap::new();
    for id in email_ids {
        if let Some(thread) = statement
            .query_row(params![id], |row| row.get::<_, String>(0))
            .optional()?
        {
            out.insert(id.clone(), thread);
        }
    }
    Ok(out)
}

/// The EMAILIDs in thread `thread_id`, indexing new emails first.
pub fn thread_members(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
    thread_id: &str,
) -> Result<Vec<String>> {
    let conn = open(maildir_root, domain, localpart)?;
    index_new_emails(&conn, maildir_root, domain, localpart)?;
    Ok(threads(&conn, &[thread_id.to_string()])?
        .remove(thread_id)
        .unwrap_or_default())
}

/// Open the account's state database (creating the account if needed).
pub fn open(
    maildir_root: &Path,
    domain: &str,
    localpart: &str,
) -> Result<crate::sqlite_pool::SqliteConnection> {
    imap_state::open_account(maildir_root, domain, localpart)
        .with_context(|| format!("opening the mail state of {localpart}@{domain}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        imap_state::init_account(&root, "example.test", "user").unwrap();
        (dir, root)
    }

    fn message(id: &str, refs: &str, subject: &str) -> Vec<u8> {
        format!(
            "From: A <a@x.test>\r\nTo: b@x.test\r\nSubject: {subject}\r\nMessage-ID: <{id}>\r\n{refs}\
             Date: Thu, 30 Oct 2014 14:12:00 +0000\r\n\r\nBody of {subject}\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn changes_follow_every_write_path() {
        let (_dir, root) = account();
        let conn = open(&root, "example.test", "user").unwrap();
        sync_account(&root, "example.test", "user").unwrap();
        let start = state(&conn).unwrap();

        imap_state::append_message(
            &root,
            "example.test",
            "user",
            "INBOX",
            &message("1@x", "", "one"),
            vec![],
        )
        .unwrap();
        sync_account(&root, "example.test", "user").unwrap();
        let after_append = state(&conn).unwrap();
        let emails_changed = changes(&conn, "Email", start, None).unwrap().unwrap();
        assert_eq!(emails_changed.created.len(), 1);
        let email_id = emails_changed.created[0].clone();
        let mailboxes_changed = changes(&conn, "Mailbox", start, None).unwrap().unwrap();
        assert_eq!(mailboxes_changed.updated.len(), 1);
        assert!(mailboxes_changed.counts_only);
        let threads_changed = changes(&conn, "Thread", start, None).unwrap().unwrap();
        assert_eq!(threads_changed.created.len(), 1);

        // A flag change updates the email; a copy keeps it one email.
        imap_state::set_uid_flags(
            &root,
            "example.test",
            "user",
            "INBOX",
            1,
            vec!["\\Seen".into()],
        )
        .unwrap();
        imap_state::copy_message_by_uid(&root, "example.test", "user", "INBOX", 1, "Archive")
            .unwrap();
        let since_append = changes(&conn, "Email", after_append, None)
            .unwrap()
            .unwrap();
        assert_eq!(since_append.updated, vec![email_id.clone()]);
        assert!(since_append.created.is_empty());
        let rows = emails(&conn, &root, "example.test", "user", None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].copies.len(), 2);
        assert!(rows[0].has_flag("\\seen"));

        // Moving keeps the email and its thread: an update, not a deletion
        // and a new email (both the single and the batch move).
        let before_move = state(&conn).unwrap();
        let thread_before = rows[0].thread_id.clone();
        for folder in ["Moved", "Later"] {
            imap_state::create_folder(&root, "example.test", "user", folder).unwrap();
        }
        let moved =
            imap_state::move_message_by_uid(&root, "example.test", "user", "Archive", 1, "Moved")
                .unwrap()
                .unwrap();
        let later = imap_state::transfer_messages_by_uid(
            &root,
            "example.test",
            "user",
            "INBOX",
            &[1],
            "Later",
            true,
        )
        .unwrap()[0]
            .1;
        sync_account(&root, "example.test", "user").unwrap();
        let after_move = changes(&conn, "Email", before_move, None).unwrap().unwrap();
        assert_eq!(after_move.updated, vec![email_id.clone()]);
        assert!(after_move.created.is_empty() && after_move.destroyed.is_empty());
        let threads_moved = changes(&conn, "Thread", before_move, None)
            .unwrap()
            .unwrap();
        assert!(threads_moved.created.is_empty() && threads_moved.destroyed.is_empty());
        assert_eq!(
            emails(&conn, &root, "example.test", "user", None).unwrap()[0].thread_id,
            thread_before
        );

        // Removing every copy destroys the email and its thread.
        let before_delete = state(&conn).unwrap();
        imap_state::delete_messages_by_uid(&root, "example.test", "user", "Moved", &[moved])
            .unwrap();
        imap_state::delete_messages_by_uid(&root, "example.test", "user", "Later", &[later])
            .unwrap();
        let deleted = changes(&conn, "Email", before_delete, None)
            .unwrap()
            .unwrap();
        assert_eq!(deleted.destroyed, vec![email_id]);
        let threads_deleted = changes(&conn, "Thread", before_delete, None)
            .unwrap()
            .unwrap();
        assert_eq!(threads_deleted.destroyed.len(), 1);
        // An email created and destroyed since the state is not reported.
        let whole = changes(&conn, "Email", start, None).unwrap().unwrap();
        assert!(whole.created.is_empty() && whole.destroyed.is_empty());

        // Mailbox create, rename and delete.
        let before_folders = state(&conn).unwrap();
        imap_state::create_folder(&root, "example.test", "user", "Projects").unwrap();
        let created = changes(&conn, "Mailbox", before_folders, None)
            .unwrap()
            .unwrap();
        assert_eq!(created.created.len(), 1);
        let after_create = state(&conn).unwrap();
        imap_state::rename_folder(&root, "example.test", "user", "Projects", "Plans").unwrap();
        let renamed = changes(&conn, "Mailbox", after_create, None)
            .unwrap()
            .unwrap();
        assert_eq!(renamed.updated, created.created);
        assert!(!renamed.counts_only);
        imap_state::delete_folder(&root, "example.test", "user", "Plans").unwrap();
        let destroyed = changes(&conn, "Mailbox", after_create, None)
            .unwrap()
            .unwrap();
        assert_eq!(destroyed.destroyed, created.created);

        assert_eq!(
            changes(&conn, "Email", state(&conn).unwrap() + 1, None).unwrap(),
            Err(ChangesError::CannotCalculate)
        );
    }

    #[test]
    fn replies_join_their_thread_and_counts_follow() {
        let (_dir, root) = account();
        for (id, refs) in [
            ("1@x", ""),
            ("2@x", "In-Reply-To: <1@x>\r\n"),
            ("3@x", "References: <1@x> <2@x>\r\n"),
            ("4@x", ""),
        ] {
            imap_state::append_message(
                &root,
                "example.test",
                "user",
                "INBOX",
                &message(id, refs, id),
                vec![],
            )
            .unwrap();
        }
        sync_account(&root, "example.test", "user").unwrap();
        let conn = open(&root, "example.test", "user").unwrap();
        let rows = emails(&conn, &root, "example.test", "user", None).unwrap();
        let thread_of = |subject: &str| {
            rows.iter()
                .find(|row| row.subject == subject)
                .unwrap()
                .thread_id
                .clone()
        };
        assert_eq!(thread_of("1@x"), thread_of("2@x"));
        assert_eq!(thread_of("1@x"), thread_of("3@x"));
        assert_ne!(thread_of("1@x"), thread_of("4@x"));
        let thread = threads(&conn, &[thread_of("1@x")]).unwrap();
        assert_eq!(thread[&thread_of("1@x")].len(), 3);
        let inbox = mailboxes(&conn)
            .unwrap()
            .into_iter()
            .find(|mailbox| mailbox.name == "INBOX")
            .unwrap();
        assert_eq!(inbox.total_emails, 4);
        assert_eq!(inbox.unread_emails, 4);
        assert_eq!(inbox.total_threads, 2);
        let row = rows.iter().find(|row| row.subject == "1@x").unwrap();
        assert_eq!(row.from, "A <a@x.test>");
        assert_eq!(row.preview, "Body of 1@x");
        assert_eq!(row.sent_at, Some(1_414_678_320));
    }
}
