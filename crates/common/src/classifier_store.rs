//! Per-account state for the mail classifier.
//!
//! Each account that opts in gets `classifier.sqlite` next to its IMAP state
//! database. The file's absence means the account has not opted in, so the
//! daemon can skip idle accounts with a single `stat`. Webmail writes the
//! preferences and resolves suggestions; the `rmail_classifier` daemon writes
//! everything else.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::imap_state;
use crate::sqlite_pool::{self, SqliteConnection};

pub const STORE_FILENAME: &str = "classifier.sqlite";

/// IMAP keyword set on INBOX messages that have a pending suggestion.
pub const SUGGESTED_KEYWORD: &str = "$Suggested";

pub fn store_path(mail_root: &Path, domain: &str, localpart: &str) -> PathBuf {
    imap_state::account_maildir(mail_root, domain, localpart).join(STORE_FILENAME)
}

/// Open the account's store, or `None` when the account never opted in.
pub fn open_existing(
    mail_root: &Path,
    domain: &str,
    localpart: &str,
) -> Result<Option<SqliteConnection>> {
    let path = store_path(mail_root, domain, localpart);
    if !path.is_file() {
        return Ok(None);
    }
    open_path(&path).map(Some)
}

/// Open the account's store, creating it when needed.
pub fn open_or_create(mail_root: &Path, domain: &str, localpart: &str) -> Result<SqliteConnection> {
    let path = store_path(mail_root, domain, localpart);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    open_path(&path)
}

fn open_path(path: &Path) -> Result<SqliteConnection> {
    let conn =
        sqlite_pool::connection(path).with_context(|| format!("opening {}", path.display()))?;
    ensure_schema(&conn)?;
    Ok(conn)
}

fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS prefs(
            id INTEGER PRIMARY KEY CHECK (id = 1),
            enabled INTEGER NOT NULL DEFAULT 0,
            excluded_folders TEXT NOT NULL DEFAULT '[]',
            autofile_folders TEXT NOT NULL DEFAULT '[]',
            updated_at INTEGER NOT NULL DEFAULT 0
        );
        INSERT OR IGNORE INTO prefs(id) VALUES (1);
        CREATE TABLE IF NOT EXISTS watermarks(
            folder TEXT PRIMARY KEY,
            uidvalidity INTEGER NOT NULL,
            last_uid INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS vectors(
            folder TEXT NOT NULL,
            uid INTEGER NOT NULL,
            sender TEXT NOT NULL,
            list_id TEXT NOT NULL,
            subject TEXT NOT NULL,
            model_id TEXT NOT NULL,
            embedding BLOB NOT NULL,
            source TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (folder, uid)
        );
        CREATE TABLE IF NOT EXISTS suggestions(
            uidvalidity INTEGER NOT NULL,
            uid INTEGER NOT NULL,
            folder TEXT NOT NULL,
            score REAL NOT NULL,
            method TEXT NOT NULL,
            state TEXT NOT NULL,
            sender TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            resolved_at INTEGER,
            PRIMARY KEY (uidvalidity, uid)
        );
        CREATE INDEX IF NOT EXISTS suggestions_state ON suggestions(state);
        CREATE TABLE IF NOT EXISTS feedback(
            sender TEXT NOT NULL,
            folder TEXT NOT NULL,
            verdict TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (sender, folder)
        );
        CREATE TABLE IF NOT EXISTS labels(
            name TEXT PRIMARY KEY,
            keyword TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT '',
            position INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS label_marks(
            id INTEGER PRIMARY KEY CHECK (id = 1),
            uidvalidity INTEGER NOT NULL,
            last_uid INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS labeled(
            uidvalidity INTEGER NOT NULL,
            uid INTEGER NOT NULL,
            label TEXT NOT NULL,
            score REAL NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (uidvalidity, uid, label)
        );
        ",
    )?;
    // Added after the first release: stores opted in before them start with
    // no cloud consent and labeling off.
    add_column(conn, "prefs", "cloud_consent", "TEXT NOT NULL DEFAULT '[]'")?;
    add_column(
        conn,
        "prefs",
        "labels_enabled",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    Ok(())
}

fn add_column(conn: &Connection, table: &str, column: &str, definition: &str) -> Result<()> {
    let exists = conn
        .prepare(&format!(
            "SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1"
        ))?
        .exists([column])?;
    if !exists {
        conn.execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN {column} {definition}"
        ))?;
    }
    Ok(())
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Preferences

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prefs {
    pub enabled: bool,
    /// Folders never suggested or learned from.
    pub excluded_folders: Vec<String>,
    /// Folders the user trusts enough for automatic moves.
    pub autofile_folders: Vec<String>,
    /// Cloud providers the user agreed may receive their mail's text.
    #[serde(default)]
    pub cloud_consent: Vec<String>,
    /// Label new INBOX mail with the user's labels. Independent of folder
    /// suggestions (`enabled`).
    #[serde(default)]
    pub labels_enabled: bool,
}

impl Prefs {
    /// Whether the daemon has anything to do for this account.
    pub fn any_enabled(&self) -> bool {
        self.enabled || self.labels_enabled
    }

    /// Whether the user agreed to every provider in `providers`.
    pub fn allows_cloud(&self, providers: &[&str]) -> bool {
        providers
            .iter()
            .all(|provider| self.cloud_consent.iter().any(|agreed| agreed == provider))
    }
}

pub fn prefs(conn: &Connection) -> Result<Prefs> {
    let (enabled, excluded, autofile, consent, labels_enabled) = conn.query_row(
        "SELECT enabled, excluded_folders, autofile_folders, cloud_consent, labels_enabled
         FROM prefs WHERE id = 1",
        [],
        |row| {
            Ok((
                row.get::<_, bool>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, bool>(4)?,
            ))
        },
    )?;
    Ok(Prefs {
        enabled,
        excluded_folders: serde_json::from_str(&excluded).unwrap_or_default(),
        autofile_folders: serde_json::from_str(&autofile).unwrap_or_default(),
        cloud_consent: serde_json::from_str(&consent).unwrap_or_default(),
        labels_enabled,
    })
}

pub fn set_prefs(conn: &Connection, prefs: &Prefs) -> Result<()> {
    conn.execute(
        "UPDATE prefs SET enabled = ?1, excluded_folders = ?2, autofile_folders = ?3,
             cloud_consent = ?4, labels_enabled = ?5, updated_at = ?6 WHERE id = 1",
        params![
            prefs.enabled,
            serde_json::to_string(&prefs.excluded_folders)?,
            serde_json::to_string(&prefs.autofile_folders)?,
            serde_json::to_string(&prefs.cloud_consent)?,
            prefs.labels_enabled,
            now()
        ],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Labels

/// Most labels one account may define; each costs a question per message.
pub const MAX_LABELS: usize = 30;
pub const MAX_LABEL_NAME: usize = 40;
pub const MAX_LABEL_DESCRIPTION: usize = 300;

/// A user-defined label, applied to messages as an IMAP keyword.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Label {
    pub name: String,
    /// The IMAP keyword (RFC 3501 flag-keyword atom) clients see.
    pub keyword: String,
    pub description: String,
}

/// An IMAP keyword for a label name: atom characters only, spaces become
/// `_`, and never a system flag (`\`) or a reserved `$` keyword.
pub fn keyword_for(name: &str) -> String {
    // Atom characters (RFC 3501): printable ASCII except atom-specials.
    let atom = |c: char| c.is_ascii_graphic() && !"(){%*\"\\]".contains(c);
    let mut keyword: String = name
        .trim()
        .chars()
        .map(|c| if atom(c) { c } else { '_' })
        .collect();
    let trimmed = keyword.trim_start_matches(['$', '\\']).to_string();
    keyword = trimmed;
    if keyword.trim_matches('_').is_empty() {
        keyword = "label".to_string();
    }
    keyword
}

pub fn labels(conn: &Connection) -> Result<Vec<Label>> {
    let mut statement =
        conn.prepare("SELECT name, keyword, description FROM labels ORDER BY position, name")?;
    let rows = statement.query_map([], |row| {
        Ok(Label {
            name: row.get(0)?,
            keyword: row.get(1)?,
            description: row.get(2)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Replace the account's labels with `wanted` (name, description) pairs.
/// Existing labels keep their keyword so messages already labeled stay
/// labeled; new ones get a keyword unique within the account.
pub fn set_labels(conn: &Connection, wanted: &[(String, String)]) -> Result<Vec<Label>> {
    if wanted.len() > MAX_LABELS {
        bail!("at most {MAX_LABELS} labels");
    }
    let existing: BTreeMap<String, String> = labels(conn)?
        .into_iter()
        .map(|label| (label.name.to_lowercase(), label.keyword))
        .collect();
    let mut seen = std::collections::BTreeSet::new();
    let mut keywords = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for (name, description) in wanted {
        let name = name.trim().to_string();
        let description = description.trim().to_string();
        if name.is_empty() || name.chars().count() > MAX_LABEL_NAME {
            bail!("label names must be 1-{MAX_LABEL_NAME} characters");
        }
        if description.chars().count() > MAX_LABEL_DESCRIPTION {
            bail!("label descriptions must be at most {MAX_LABEL_DESCRIPTION} characters");
        }
        if !seen.insert(name.to_lowercase()) {
            bail!("duplicate label {name}");
        }
        let mut keyword = existing
            .get(&name.to_lowercase())
            .cloned()
            .unwrap_or_else(|| keyword_for(&name));
        let base = keyword.clone();
        let mut n = 2;
        while !keywords.insert(keyword.to_lowercase()) {
            keyword = format!("{base}_{n}");
            n += 1;
        }
        out.push(Label {
            name,
            keyword,
            description,
        });
    }
    let tx = conn.unchecked_transaction()?;
    tx.execute("DELETE FROM labels", [])?;
    for (position, label) in out.iter().enumerate() {
        tx.execute(
            "INSERT INTO labels(name, keyword, description, position) VALUES (?1, ?2, ?3, ?4)",
            params![
                label.name,
                label.keyword,
                label.description,
                position as i64
            ],
        )?;
    }
    tx.commit()?;
    Ok(out)
}

pub fn label_mark(conn: &Connection) -> Result<Option<Watermark>> {
    Ok(conn
        .query_row(
            "SELECT uidvalidity, last_uid FROM label_marks WHERE id = 1",
            [],
            |row| {
                Ok(Watermark {
                    uidvalidity: row.get::<_, i64>(0)? as u64,
                    last_uid: row.get::<_, i64>(1)? as u64,
                })
            },
        )
        .optional()?)
}

pub fn set_label_mark(conn: &Connection, mark: Watermark) -> Result<()> {
    conn.execute(
        "INSERT INTO label_marks(id, uidvalidity, last_uid) VALUES (1, ?1, ?2)
         ON CONFLICT(id) DO UPDATE SET uidvalidity = ?1, last_uid = ?2",
        params![mark.uidvalidity as i64, mark.last_uid as i64],
    )?;
    Ok(())
}

pub fn record_labels(
    conn: &Connection,
    uidvalidity: u64,
    uid: u64,
    labels: &[(String, f64)],
) -> Result<()> {
    for (label, score) in labels {
        conn.execute(
            "INSERT OR REPLACE INTO labeled(uidvalidity, uid, label, score, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![uidvalidity as i64, uid as i64, label, score, now()],
        )?;
    }
    Ok(())
}

/// Messages labeled per label name, ever.
pub fn label_counts(conn: &Connection) -> Result<BTreeMap<String, u64>> {
    let mut statement = conn.prepare("SELECT label, COUNT(*) FROM labeled GROUP BY label")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

// ---------------------------------------------------------------------------
// Watermarks

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Watermark {
    pub uidvalidity: u64,
    pub last_uid: u64,
}

pub fn watermarks(conn: &Connection) -> Result<BTreeMap<String, Watermark>> {
    let mut stmt = conn.prepare("SELECT folder, uidvalidity, last_uid FROM watermarks")?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                Watermark {
                    uidvalidity: row.get::<_, i64>(1)? as u64,
                    last_uid: row.get::<_, i64>(2)? as u64,
                },
            ))
        })?
        .collect::<rusqlite::Result<BTreeMap<_, _>>>()?;
    Ok(rows)
}

pub fn set_watermark(conn: &Connection, folder: &str, mark: Watermark) -> Result<()> {
    conn.execute(
        "INSERT INTO watermarks(folder, uidvalidity, last_uid) VALUES (?1, ?2, ?3)
         ON CONFLICT(folder) DO UPDATE SET uidvalidity = excluded.uidvalidity,
             last_uid = excluded.last_uid",
        params![folder, mark.uidvalidity as i64, mark.last_uid as i64],
    )?;
    Ok(())
}

pub fn remove_watermark(conn: &Connection, folder: &str) -> Result<()> {
    conn.execute("DELETE FROM watermarks WHERE folder = ?1", params![folder])?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Learned examples

#[derive(Debug, Clone, PartialEq)]
pub struct Example {
    pub folder: String,
    pub uid: u64,
    pub sender: String,
    pub list_id: String,
    pub subject: String,
    pub embedding: Vec<f32>,
}

pub fn insert_example(
    conn: &Connection,
    example: &Example,
    model_id: &str,
    source: &str,
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO vectors(folder, uid, sender, list_id, subject, model_id,
             embedding, source, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            example.folder,
            example.uid as i64,
            example.sender,
            example.list_id,
            example.subject,
            model_id,
            encode_embedding(&example.embedding),
            source,
            now()
        ],
    )?;
    Ok(())
}

/// Every example embedded with `model_id`. Examples from other models are
/// not comparable and are ignored until re-embedded.
pub fn examples(conn: &Connection, model_id: &str) -> Result<Vec<Example>> {
    let mut stmt = conn.prepare(
        "SELECT folder, uid, sender, list_id, subject, embedding FROM vectors WHERE model_id = ?1",
    )?;
    let rows = stmt
        .query_map(params![model_id], |row| {
            Ok(Example {
                folder: row.get(0)?,
                uid: row.get::<_, i64>(1)? as u64,
                sender: row.get(2)?,
                list_id: row.get(3)?,
                subject: row.get(4)?,
                embedding: decode_embedding(&row.get::<_, Vec<u8>>(5)?),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// True when the store holds examples from a model other than `model_id`.
pub fn has_stale_examples(conn: &Connection, model_id: &str) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM vectors WHERE model_id != ?1 LIMIT 1",
            params![model_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Forget every example and watermark so all folders are learned again.
pub fn reset_learning(conn: &Connection) -> Result<()> {
    conn.execute_batch("DELETE FROM vectors; DELETE FROM watermarks;")?;
    Ok(())
}

pub fn remove_folder_examples(conn: &Connection, folder: &str) -> Result<()> {
    conn.execute("DELETE FROM vectors WHERE folder = ?1", params![folder])?;
    Ok(())
}

pub fn example_counts(conn: &Connection) -> Result<BTreeMap<String, u64>> {
    let mut stmt = conn.prepare("SELECT folder, COUNT(*) FROM vectors GROUP BY folder")?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        })?
        .collect::<rusqlite::Result<BTreeMap<_, _>>>()?;
    Ok(rows)
}

fn encode_embedding(values: &[f32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

fn decode_embedding(bytes: &[u8]) -> Vec<f32> {
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|chunk| f32::from_le_bytes(*chunk))
        .collect()
}

// ---------------------------------------------------------------------------
// Suggestions

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Suggestion {
    pub uidvalidity: u64,
    pub uid: u64,
    pub folder: String,
    /// Confidence between 0 and 1.
    pub score: f64,
    /// `sender`, `knn` or `llm`.
    pub method: String,
    /// `pending`, `moved` (automatic), `accepted`, `dismissed` or `gone`.
    pub state: String,
    pub sender: String,
    pub created_at: i64,
}

pub fn record_suggestion(conn: &Connection, suggestion: &Suggestion) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO suggestions(uidvalidity, uid, folder, score, method, state,
             sender, created_at, resolved_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
             CASE WHEN ?6 = 'pending' THEN NULL ELSE ?8 END)",
        params![
            suggestion.uidvalidity as i64,
            suggestion.uid as i64,
            suggestion.folder,
            suggestion.score,
            suggestion.method,
            suggestion.state,
            suggestion.sender,
            suggestion.created_at
        ],
    )?;
    Ok(())
}

pub fn pending_suggestions(conn: &Connection, uidvalidity: u64) -> Result<Vec<Suggestion>> {
    let mut stmt = conn.prepare(
        "SELECT uidvalidity, uid, folder, score, method, state, sender, created_at
         FROM suggestions WHERE state = 'pending' AND uidvalidity = ?1 ORDER BY uid",
    )?;
    let rows = stmt
        .query_map(params![uidvalidity as i64], suggestion_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn suggestion(conn: &Connection, uidvalidity: u64, uid: u64) -> Result<Option<Suggestion>> {
    Ok(conn
        .query_row(
            "SELECT uidvalidity, uid, folder, score, method, state, sender, created_at
             FROM suggestions WHERE uidvalidity = ?1 AND uid = ?2",
            params![uidvalidity as i64, uid as i64],
            suggestion_row,
        )
        .optional()?)
}

fn suggestion_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Suggestion> {
    Ok(Suggestion {
        uidvalidity: row.get::<_, i64>(0)? as u64,
        uid: row.get::<_, i64>(1)? as u64,
        folder: row.get(2)?,
        score: row.get(3)?,
        method: row.get(4)?,
        state: row.get(5)?,
        sender: row.get(6)?,
        created_at: row.get(7)?,
    })
}

pub fn set_suggestion_state(
    conn: &Connection,
    uidvalidity: u64,
    uid: u64,
    state: &str,
) -> Result<()> {
    conn.execute(
        "UPDATE suggestions SET state = ?3, resolved_at = ?4 WHERE uidvalidity = ?1 AND uid = ?2",
        params![uidvalidity as i64, uid as i64, state, now()],
    )?;
    Ok(())
}

/// Accepted and dismissed suggestion counts per folder over the last 30 days.
pub fn recent_outcomes(conn: &Connection) -> Result<BTreeMap<String, (u64, u64)>> {
    let mut stmt = conn.prepare(
        "SELECT folder,
             SUM(CASE WHEN state IN ('accepted', 'moved') THEN 1 ELSE 0 END),
             SUM(CASE WHEN state = 'dismissed' THEN 1 ELSE 0 END)
         FROM suggestions WHERE created_at >= ?1 GROUP BY folder",
    )?;
    let rows = stmt
        .query_map(params![now() - 30 * 86_400], |row| {
            Ok((
                row.get::<_, String>(0)?,
                (row.get::<_, i64>(1)? as u64, row.get::<_, i64>(2)? as u64),
            ))
        })?
        .collect::<rusqlite::Result<BTreeMap<_, _>>>()?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Feedback

pub fn record_dismissal(conn: &Connection, sender: &str, folder: &str) -> Result<()> {
    if sender.is_empty() {
        return Ok(());
    }
    conn.execute(
        "INSERT OR REPLACE INTO feedback(sender, folder, verdict, created_at)
         VALUES (?1, ?2, 'dismissed', ?3)",
        params![sender, folder, now()],
    )?;
    Ok(())
}

/// Senders mapped to the folders their mail should no longer be suggested for.
pub fn dismissals(conn: &Connection) -> Result<BTreeMap<String, Vec<String>>> {
    let mut stmt =
        conn.prepare("SELECT sender, folder FROM feedback WHERE verdict = 'dismissed'")?;
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })? {
        let (sender, folder) = row?;
        out.entry(sender).or_default().push(folder);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Mailbox operations shared by the daemon and webmail

/// Folders the classifier may suggest and learn from: user folders, not INBOX
/// or special-use folders such as Sent, Trash, Junk and Archive.
pub fn is_user_folder(folder: &imap_state::Folder) -> bool {
    !folder.name.eq_ignore_ascii_case("INBOX")
        && folder.special_use.as_deref().is_none_or(str::is_empty)
}

/// Add or remove an IMAP keyword on one message without touching its other
/// flags.
pub fn set_keyword(
    mail_root: &Path,
    domain: &str,
    localpart: &str,
    mailbox: &str,
    uid: u64,
    keyword: &str,
    present: bool,
) -> Result<()> {
    let (_folder, messages) = imap_state::load_folder(mail_root, domain, localpart, mailbox)?;
    let Some(message) = messages.into_iter().find(|message| message.uid == uid) else {
        return Ok(());
    };
    let has = message
        .flags
        .iter()
        .any(|flag| flag.eq_ignore_ascii_case(keyword));
    if has == present {
        return Ok(());
    }
    let mut flags: Vec<String> = message
        .flags
        .into_iter()
        .filter(|flag| {
            !flag.eq_ignore_ascii_case(keyword) && !flag.eq_ignore_ascii_case("\\Recent")
        })
        .collect();
    if present {
        flags.push(keyword.to_string());
    }
    imap_state::set_uid_flags(mail_root, domain, localpart, mailbox, uid, flags)?;
    Ok(())
}

/// Accept a pending INBOX suggestion: move the message and remember it.
/// Returns the folder the message went to.
pub fn accept(mail_root: &Path, domain: &str, localpart: &str, uid: u64) -> Result<String> {
    let conn =
        open_existing(mail_root, domain, localpart)?.context("organization is not enabled")?;
    let (inbox, _) = imap_state::load_folder(mail_root, domain, localpart, "INBOX")?;
    let Some(found) = suggestion(&conn, inbox.uidvalidity, uid)? else {
        bail!("no suggestion for this message");
    };
    if found.state != "pending" {
        bail!("suggestion already {}", found.state);
    }
    set_keyword(
        mail_root,
        domain,
        localpart,
        "INBOX",
        uid,
        SUGGESTED_KEYWORD,
        false,
    )?;
    imap_state::move_message_by_uid(mail_root, domain, localpart, "INBOX", uid, &found.folder)?;
    set_suggestion_state(&conn, inbox.uidvalidity, uid, "accepted")?;
    Ok(found.folder)
}

/// Dismiss a pending INBOX suggestion and stop suggesting that folder for the
/// same sender.
pub fn dismiss(mail_root: &Path, domain: &str, localpart: &str, uid: u64) -> Result<()> {
    let conn =
        open_existing(mail_root, domain, localpart)?.context("organization is not enabled")?;
    let (inbox, _) = imap_state::load_folder(mail_root, domain, localpart, "INBOX")?;
    let Some(found) = suggestion(&conn, inbox.uidvalidity, uid)? else {
        bail!("no suggestion for this message");
    };
    set_keyword(
        mail_root,
        domain,
        localpart,
        "INBOX",
        uid,
        SUGGESTED_KEYWORD,
        false,
    )?;
    set_suggestion_state(&conn, inbox.uidvalidity, uid, "dismissed")?;
    record_dismissal(&conn, &found.sender, &found.folder)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_keywords_are_imap_atoms_and_stay_stable() {
        assert_eq!(keyword_for("To do"), "To_do");
        assert_eq!(keyword_for("$Junk"), "Junk");
        assert_eq!(keyword_for("\\Seen"), "_Seen");
        assert_eq!(keyword_for("a(b)*\"c\""), "a_b___c_");
        assert_eq!(keyword_for("Økonomi"), "_konomi");
        assert_eq!(keyword_for("   "), "label");

        let dir = tempfile::tempdir().unwrap();
        let conn = open_or_create(dir.path(), "example.test", "alice").unwrap();
        let pair = |name: &str, description: &str| (name.to_string(), description.to_string());
        let first = set_labels(&conn, &[pair("To do", "Needs action"), pair("To_do", "")]).unwrap();
        assert_eq!(first[0].keyword, "To_do");
        assert_eq!(
            first[1].keyword, "To_do_2",
            "keywords are unique per account"
        );
        assert_eq!(labels(&conn).unwrap(), first);

        // Renaming one label keeps the other's keyword, so labeled mail stays labeled.
        let second = set_labels(&conn, &[pair("Invoices", ""), pair("To_do", "x")]).unwrap();
        assert_eq!(second[1].keyword, "To_do_2");
        assert!(set_labels(&conn, &[pair("A", ""), pair("a", "")]).is_err());
        assert!(set_labels(&conn, &[pair("", "")]).is_err());

        assert_eq!(label_mark(&conn).unwrap(), None);
        set_label_mark(
            &conn,
            Watermark {
                uidvalidity: 3,
                last_uid: 9,
            },
        )
        .unwrap();
        assert_eq!(label_mark(&conn).unwrap().unwrap().last_uid, 9);
        record_labels(&conn, 3, 9, &[("Invoices".into(), 0.9)]).unwrap();
        record_labels(&conn, 3, 10, &[("Invoices".into(), 0.8)]).unwrap();
        assert_eq!(label_counts(&conn).unwrap()["Invoices"], 2);
    }

    #[test]
    fn stores_from_before_cloud_consent_are_migrated_without_consent() {
        let dir = tempfile::tempdir().unwrap();
        let path = store_path(dir.path(), "example.test", "bob");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        {
            let old = Connection::open(&path).unwrap();
            old.execute_batch(
                "CREATE TABLE prefs(id INTEGER PRIMARY KEY CHECK (id = 1),
                     enabled INTEGER NOT NULL DEFAULT 0,
                     excluded_folders TEXT NOT NULL DEFAULT '[]',
                     autofile_folders TEXT NOT NULL DEFAULT '[]',
                     updated_at INTEGER NOT NULL DEFAULT 0);
                 INSERT INTO prefs(id, enabled) VALUES (1, 1);",
            )
            .unwrap();
        }
        let conn = open_existing(dir.path(), "example.test", "bob")
            .unwrap()
            .unwrap();
        let migrated = prefs(&conn).unwrap();
        assert!(migrated.enabled);
        assert!(!migrated.labels_enabled);
        assert!(migrated.cloud_consent.is_empty());
        assert!(!migrated.allows_cloud(&["openrouter"]));
    }

    #[test]
    fn store_round_trips_prefs_examples_and_suggestions() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        assert!(
            open_existing(root, "example.test", "alice")
                .unwrap()
                .is_none()
        );
        let conn = open_or_create(root, "example.test", "alice").unwrap();

        assert_eq!(prefs(&conn).unwrap(), Prefs::default());
        let wanted = Prefs {
            enabled: true,
            excluded_folders: vec!["Private".into()],
            autofile_folders: vec!["Receipts".into()],
            cloud_consent: vec!["openrouter".into()],
            labels_enabled: true,
        };
        set_prefs(&conn, &wanted).unwrap();
        assert_eq!(prefs(&conn).unwrap(), wanted);
        assert!(wanted.allows_cloud(&[]));
        assert!(wanted.allows_cloud(&["openrouter"]));
        assert!(!wanted.allows_cloud(&["openrouter", "typesafe"]));

        let example = Example {
            folder: "Receipts".into(),
            uid: 7,
            sender: "shop@example.net".into(),
            list_id: String::new(),
            subject: "Your order".into(),
            embedding: vec![0.25, -1.5, 3.0],
        };
        insert_example(&conn, &example, "m1", "filed").unwrap();
        assert_eq!(examples(&conn, "m1").unwrap(), vec![example]);
        assert!(examples(&conn, "m2").unwrap().is_empty());
        assert!(has_stale_examples(&conn, "m2").unwrap());
        assert_eq!(example_counts(&conn).unwrap()["Receipts"], 1);

        let suggestion = Suggestion {
            uidvalidity: 1,
            uid: 3,
            folder: "Receipts".into(),
            score: 0.9,
            method: "knn".into(),
            state: "pending".into(),
            sender: "shop@example.net".into(),
            created_at: now(),
        };
        record_suggestion(&conn, &suggestion).unwrap();
        assert_eq!(pending_suggestions(&conn, 1).unwrap(), vec![suggestion]);
        set_suggestion_state(&conn, 1, 3, "dismissed").unwrap();
        assert!(pending_suggestions(&conn, 1).unwrap().is_empty());
        assert_eq!(recent_outcomes(&conn).unwrap()["Receipts"], (0, 1));

        record_dismissal(&conn, "shop@example.net", "Receipts").unwrap();
        assert_eq!(
            dismissals(&conn).unwrap()["shop@example.net"],
            vec!["Receipts".to_string()]
        );

        set_watermark(
            &conn,
            "INBOX",
            Watermark {
                uidvalidity: 1,
                last_uid: 9,
            },
        )
        .unwrap();
        assert_eq!(watermarks(&conn).unwrap()["INBOX"].last_uid, 9);
        reset_learning(&conn).unwrap();
        assert!(watermarks(&conn).unwrap().is_empty());
    }
}
