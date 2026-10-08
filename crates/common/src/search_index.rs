//! Per-account full-text index for `SEARCH BODY/TEXT` and webmail search.
//!
//! The index is an SQLite FTS5 table using the `trigram` tokenizer, which
//! answers *substring* queries of three or more characters. It lives in its
//! own file (`<account Maildir>/search-index.db`), is filled lazily by
//! searches, and can be deleted at any time: it is only a cache.
//!
//! Results are identical to the scans they replace. Text is stored already
//! folded the way the scans fold it (IMAP: NFKD then lowercase; webmail:
//! lowercase) and SQLite's own case folding is switched off, so a trigram
//! match is exactly `fold(text).contains(fold(needle))`. A message counts as
//! *covered* only when it was indexed completely; callers answer covered
//! messages from [`Hits`] and scan the rest, so results never depend on how
//! much has been indexed yet.

use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization;

use crate::sqlite_pool::{self, SqliteConnection};

pub const MIN_NEEDLE_CHARS: usize = 3;
const INDEX_FILENAME: &str = "search-index.db";
/// Raw body text indexed per message; larger messages are left to the scan.
const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_DECODED_BYTES: usize = 256 * 1024;
const INDEX_BATCH: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// Raw text after the header block (IMAP `BODY`).
    Body,
    /// Raw headers and body (IMAP `TEXT`).
    Text,
    /// Decoded From/To/Cc/Subject and text body (webmail search).
    Decoded,
}

/// Answers for one needle in one folder.
#[derive(Debug, Default)]
pub struct Hits {
    /// UIDs indexed completely: for these `hits` is authoritative.
    pub covered: HashSet<u64>,
    pub hits: HashSet<u64>,
}

impl Hits {
    /// `Some(matches)` for covered messages, `None` when the caller must scan.
    pub fn lookup(&self, uid: u64) -> Option<bool> {
        self.covered
            .contains(&uid)
            .then(|| self.hits.contains(&uid))
    }
}

/// How IMAP `SEARCH` compares strings: NFKD, then lowercase.
pub fn fold_imap(text: &str) -> String {
    text.nfkd().flat_map(char::to_lowercase).collect()
}

fn fold(field: Field, text: &str) -> String {
    match field {
        Field::Body | Field::Text => fold_imap(text),
        Field::Decoded => text.to_lowercase(),
    }
}

/// Needles the trigram index answers exactly: at least three characters once
/// folded, and no newlines (a needle spanning the header/body boundary would
/// not be found in the separately indexed columns).
pub fn usable_needle(field: Field, needle: &str) -> bool {
    !needle.contains(['\0', '\r', '\n']) && fold(field, needle).chars().count() >= MIN_NEEDLE_CHARS
}

pub fn index_path(maildir_root: &Path, domain: &str, localpart: &str) -> PathBuf {
    crate::maildir::account_maildir(maildir_root, domain, localpart).join(INDEX_FILENAME)
}

/// Delete an account's index so the next search rebuilds it.
pub fn remove_index(maildir_root: &Path, domain: &str, localpart: &str) -> Result<bool> {
    let path = index_path(maildir_root, domain, localpart);
    let mut removed = false;
    for suffix in ["", "-wal", "-shm"] {
        let file = PathBuf::from(format!("{}{suffix}", path.display()));
        match std::fs::remove_file(&file) {
            Ok(()) => removed = true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(removed)
}

pub struct SearchIndex {
    conn: SqliteConnection,
}

impl SearchIndex {
    pub fn open(maildir_root: &Path, domain: &str, localpart: &str) -> Result<Self> {
        let path = index_path(maildir_root, domain, localpart);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = sqlite_pool::connection(&path)?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            CREATE TABLE IF NOT EXISTS docs(
                id INTEGER PRIMARY KEY,
                folder TEXT NOT NULL,
                uidvalidity INTEGER NOT NULL,
                uid INTEGER NOT NULL,
                complete INTEGER NOT NULL,
                UNIQUE(folder, uidvalidity, uid)
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS msgtext USING fts5(
                hdr, body, dec, tokenize = 'trigram case_sensitive 1'
            );
            ",
        )?;
        Ok(Self { conn })
    }

    /// Bring the index of `folder` up to date with `messages` (`(uid, path)`):
    /// drop entries for vanished messages and for other UIDVALIDITY epochs, and
    /// index up to `budget` messages that are missing. Returns how many
    /// messages are still unindexed.
    pub fn sync(
        &self,
        folder: &str,
        uidvalidity: u64,
        messages: &[(u64, PathBuf)],
        budget: usize,
    ) -> Result<usize> {
        let current: HashSet<u64> = messages.iter().map(|(uid, _)| *uid).collect();
        let tx = self.conn.unchecked_transaction()?;
        // Rows from another UIDVALIDITY of this folder are meaningless now.
        let stale: Vec<i64> = {
            let mut stmt = tx.prepare("SELECT id, uid, uidvalidity FROM docs WHERE folder = ?1")?;
            let rows = stmt.query_map([folder], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?;
            let mut ids = Vec::new();
            for row in rows {
                let (id, uid, validity) = row?;
                if validity as u64 != uidvalidity || !current.contains(&(uid as u64)) {
                    ids.push(id);
                }
            }
            ids
        };
        for id in &stale {
            tx.execute("DELETE FROM msgtext WHERE rowid = ?1", [id])?;
            tx.execute("DELETE FROM docs WHERE id = ?1", [id])?;
        }
        let indexed: HashSet<u64> = {
            let mut stmt =
                tx.prepare("SELECT uid FROM docs WHERE folder = ?1 AND uidvalidity = ?2")?;
            let rows = stmt.query_map(rusqlite::params![folder, uidvalidity as i64], |row| {
                row.get::<_, i64>(0)
            })?;
            rows.map(|row| row.map(|uid| uid as u64))
                .collect::<rusqlite::Result<_>>()?
        };
        tx.commit()?;

        let missing: Vec<&(u64, PathBuf)> = messages
            .iter()
            .filter(|(uid, _)| !indexed.contains(uid))
            .collect();
        let mut remaining = missing.len();
        for chunk in missing
            .iter()
            .take(budget)
            .collect::<Vec<_>>()
            .chunks(INDEX_BATCH)
        {
            // Read outside the write transaction; unreadable files are skipped
            // (they stay uncovered, so the scan decides, and reports errors).
            let extracted: Vec<(u64, Extracted)> = chunk
                .iter()
                .filter_map(|(uid, path)| std::fs::read(path).ok().map(|raw| (*uid, extract(&raw))))
                .collect();
            let tx = self.conn.unchecked_transaction()?;
            for (uid, text) in &extracted {
                let inserted = tx.execute(
                    "INSERT OR IGNORE INTO docs(folder, uidvalidity, uid, complete) VALUES(?1, ?2, ?3, ?4)",
                    rusqlite::params![folder, uidvalidity as i64, *uid as i64, text.complete],
                )?;
                if inserted == 1 {
                    tx.execute(
                        "INSERT INTO msgtext(rowid, hdr, body, dec) VALUES(?1, ?2, ?3, ?4)",
                        rusqlite::params![tx.last_insert_rowid(), text.hdr, text.body, text.dec],
                    )?;
                }
            }
            tx.commit()?;
            remaining = remaining.saturating_sub(extracted.len());
        }
        Ok(remaining)
    }

    /// Indexed answers for `needle`, or `None` when the needle cannot use the
    /// index (non-ASCII or shorter than three characters).
    pub fn query(
        &self,
        folder: &str,
        uidvalidity: u64,
        field: Field,
        needle: &str,
    ) -> Result<Option<Hits>> {
        if !usable_needle(field, needle) {
            return Ok(None);
        }
        let phrase = format!("\"{}\"", fold(field, needle).replace('"', "\"\""));
        let expression = match field {
            Field::Body => format!("body : {phrase}"),
            Field::Text => format!("{{hdr body}} : {phrase}"),
            Field::Decoded => format!("dec : {phrase}"),
        };
        let validity = uidvalidity as i64;
        let mut hits = Hits::default();
        {
            let mut stmt = self.conn.prepare(
                "SELECT uid FROM docs WHERE folder = ?1 AND uidvalidity = ?2 AND complete = 1",
            )?;
            let rows = stmt.query_map(rusqlite::params![folder, validity], |row| {
                row.get::<_, i64>(0)
            })?;
            for uid in rows {
                hits.covered.insert(uid? as u64);
            }
        }
        {
            let mut stmt = self.conn.prepare(
                "SELECT d.uid FROM msgtext JOIN docs d ON d.id = msgtext.rowid
                 WHERE msgtext MATCH ?3 AND d.folder = ?1 AND d.uidvalidity = ?2 AND d.complete = 1",
            )?;
            let rows = stmt.query_map(rusqlite::params![folder, validity, expression], |row| {
                row.get::<_, i64>(0)
            })?;
            for uid in rows {
                hits.hits.insert(uid? as u64);
            }
        }
        Ok(Some(hits))
    }

    /// Number of messages indexed per folder (for diagnostics).
    pub fn counts(&self) -> Result<HashMap<String, usize>> {
        let mut stmt = self
            .conn
            .prepare("SELECT folder, COUNT(*) FROM docs GROUP BY folder")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut out = HashMap::new();
        for row in rows {
            let (folder, count) = row?;
            out.insert(folder, count as usize);
        }
        Ok(out)
    }
}

struct Extracted {
    hdr: String,
    body: String,
    dec: String,
    /// Nothing was cut off, so every field is authoritative.
    complete: bool,
}

/// Where the scan (`mailbox::body_after_header`) puts the body: after the
/// first CRLF CRLF, else after the first LF LF, else the whole message.
/// Returns `(end of headers, start of body)`.
fn header_end(raw: &[u8]) -> (usize, usize) {
    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        return (pos, pos + 4);
    }
    if let Some(pos) = raw.windows(2).position(|w| w == b"\n\n") {
        return (pos, pos + 2);
    }
    (raw.len(), 0)
}

fn capped(bytes: &[u8], max: usize, complete: &mut bool) -> String {
    if bytes.len() > max {
        *complete = false;
        String::from_utf8_lossy(&bytes[..max]).into_owned()
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

fn extract(raw: &[u8]) -> Extracted {
    let (head_end, body_start) = header_end(raw);
    let mut complete = true;
    let hdr = fold_imap(&capped(&raw[..head_end], MAX_HEADER_BYTES, &mut complete));
    let body = fold_imap(&capped(&raw[body_start..], MAX_BODY_BYTES, &mut complete));
    let parsed = crate::mime::parse_message(raw);
    let decoded = format!(
        "{} {} {} {} {}",
        parsed.from, parsed.to, parsed.cc, parsed.subject, parsed.text_body
    );
    let dec = capped(decoded.as_bytes(), MAX_DECODED_BYTES, &mut complete).to_lowercase();
    Extracted {
        hdr,
        body,
        dec,
        complete,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> (tempfile::TempDir, PathBuf) {
        let td = tempfile::tempdir().unwrap();
        (td, PathBuf::from("mail"))
    }

    fn write(dir: &Path, name: &str, data: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, data).unwrap();
        path
    }

    fn open(td: &tempfile::TempDir) -> SearchIndex {
        SearchIndex::open(&td.path().join("mail"), "example.test", "user").unwrap()
    }

    const A: &[u8] = b"From: Alice <alice@example.org>\r\nSubject: Quarterly REPORT\r\n\r\nThe numbers inside.\r\n";
    const B: &[u8] = b"From: bob@example.org\r\nSubject: lunch\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nCaf=C3=A9 menu and numbers\r\n";

    fn files(td: &tempfile::TempDir) -> Vec<(u64, PathBuf)> {
        vec![(1, write(td.path(), "a", A)), (2, write(td.path(), "b", B))]
    }

    #[test]
    fn needle_rules() {
        for field in [Field::Body, Field::Text, Field::Decoded] {
            assert!(usable_needle(field, "abc"));
            assert!(usable_needle(field, "a b\"c"));
            assert!(usable_needle(field, "héllo"));
            assert!(!usable_needle(field, "ab"));
            assert!(!usable_needle(field, ""));
            assert!(!usable_needle(field, "ab\0c"));
            assert!(!usable_needle(field, "a\r\nb"));
        }
        // Folded length counts: NFKD splits é into e + a combining accent, so
        // "éa" is three characters for IMAP search but two for webmail.
        assert!(!usable_needle(Field::Body, "é"));
        assert!(usable_needle(Field::Body, "éa"));
        assert!(!usable_needle(Field::Decoded, "éa"));
    }

    #[test]
    fn substring_semantics_per_field() {
        let (td, _) = account();
        let index = open(&td);
        assert_eq!(index.sync("INBOX", 7, &files(&td), 100).unwrap(), 0);
        let q = |field, needle: &str| {
            let hits = index.query("INBOX", 7, field, needle).unwrap().unwrap();
            assert_eq!(hits.covered, HashSet::from([1, 2]));
            let mut v: Vec<u64> = hits.hits.into_iter().collect();
            v.sort();
            v
        };
        // Case-insensitive substring, mid-word.
        assert_eq!(q(Field::Body, "UMBER"), vec![1, 2]);
        // Headers are not in BODY but are in TEXT.
        assert_eq!(q(Field::Body, "quarterly"), Vec::<u64>::new());
        assert_eq!(q(Field::Text, "quarterly"), vec![1]);
        assert_eq!(q(Field::Text, "alice@example"), vec![1]);
        // BODY is the raw text; DECODED sees through quoted-printable.
        assert_eq!(q(Field::Body, "caf=c3"), vec![2]);
        assert_eq!(q(Field::Decoded, "menu and"), vec![2]);
        assert_eq!(q(Field::Decoded, "bob@example"), vec![2]);
        assert_eq!(q(Field::Decoded, "report inside"), Vec::<u64>::new());
        // Quotes in a needle cannot break the query.
        assert_eq!(q(Field::Text, "a\"b\"c"), Vec::<u64>::new());
        // Unusable needles are refused so the caller scans.
        assert!(
            index
                .query("INBOX", 7, Field::Body, "ab")
                .unwrap()
                .is_none()
        );
        assert!(
            index
                .query(
                    "INBOX",
                    7,
                    Field::Body,
                    "a
b"
                )
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn sync_is_incremental_and_follows_the_mailbox() {
        let (td, _) = account();
        let index = open(&td);
        let mut messages = files(&td);
        // A small budget indexes progressively; unindexed mail is not covered.
        assert_eq!(index.sync("INBOX", 7, &messages, 1).unwrap(), 1);
        let partial = index
            .query("INBOX", 7, Field::Body, "numbers")
            .unwrap()
            .unwrap();
        assert_eq!(partial.covered.len(), 1);
        assert_eq!(partial.lookup(1), Some(true));
        assert_eq!(partial.lookup(2), None);
        assert_eq!(index.sync("INBOX", 7, &messages, 10).unwrap(), 0);

        // A new message is picked up; an expunged one disappears.
        messages.push((
            3,
            write(td.path(), "c", b"Subject: x\r\n\r\nfresh numbers\r\n"),
        ));
        messages.remove(0);
        assert_eq!(index.sync("INBOX", 7, &messages, 10).unwrap(), 0);
        let hits = index
            .query("INBOX", 7, Field::Body, "numbers")
            .unwrap()
            .unwrap();
        assert_eq!(hits.covered, HashSet::from([2, 3]));
        assert_eq!(hits.hits, HashSet::from([2, 3]));
        assert_eq!(index.counts().unwrap()["INBOX"], 2);

        // A new UIDVALIDITY discards the old epoch and starts over.
        assert_eq!(index.sync("INBOX", 8, &messages, 10).unwrap(), 0);
        assert!(
            index
                .query("INBOX", 7, Field::Body, "numbers")
                .unwrap()
                .unwrap()
                .covered
                .is_empty()
        );
        assert_eq!(
            index
                .query("INBOX", 8, Field::Body, "numbers")
                .unwrap()
                .unwrap()
                .covered
                .len(),
            2
        );
        // Folders are independent.
        assert!(
            index
                .query("Archive", 8, Field::Body, "numbers")
                .unwrap()
                .unwrap()
                .covered
                .is_empty()
        );
    }

    #[test]
    fn oversized_and_unreadable_messages_stay_uncovered() {
        let (td, _) = account();
        let index = open(&td);
        let mut big = b"Subject: big\r\n\r\n".to_vec();
        big.extend(std::iter::repeat_n(b'x', MAX_BODY_BYTES + 10));
        big.extend_from_slice(b"needleatend");
        let messages = vec![
            (1, write(td.path(), "a", A)),
            (2, write(td.path(), "big", &big)),
            (3, td.path().join("missing")),
        ];
        assert_eq!(
            index.sync("INBOX", 1, &messages, 10).unwrap(),
            1,
            "the unreadable file is retried later"
        );
        let hits = index
            .query("INBOX", 1, Field::Body, "needleatend")
            .unwrap()
            .unwrap();
        // The truncated message is not covered, so the caller scans it and
        // finds the text past the cut-off.
        assert_eq!(hits.covered, HashSet::from([1]));
        assert_eq!(hits.lookup(1), Some(false));
        assert_eq!(hits.lookup(2), None);
        assert_eq!(hits.lookup(3), None);
    }

    #[test]
    fn removing_the_index_resets_it() {
        let (td, _) = account();
        {
            let index = open(&td);
            index.sync("INBOX", 1, &files(&td), 10).unwrap();
        }
        let root = td.path().join("mail");
        assert!(index_path(&root, "example.test", "user").exists());
        assert!(remove_index(&root, "example.test", "user").unwrap());
        assert!(!index_path(&root, "example.test", "user").exists());
        assert!(!remove_index(&root, "example.test", "user").unwrap());
    }

    /// The scans this index replaces, for comparison.
    fn scan(raw: &[u8], field: Field, needle: &str) -> bool {
        match field {
            Field::Body => fold_imap(&String::from_utf8_lossy(&raw[header_end_for_scan(raw)..]))
                .contains(&fold_imap(needle)),
            Field::Text => fold_imap(&String::from_utf8_lossy(raw)).contains(&fold_imap(needle)),
            Field::Decoded => {
                let p = crate::mime::parse_message(raw);
                format!("{} {} {} {} {}", p.from, p.to, p.cc, p.subject, p.text_body)
                    .to_lowercase()
                    .contains(&needle.to_lowercase())
            }
        }
    }

    /// `mailbox::body_after_header` as implemented in the IMAP daemon.
    fn header_end_for_scan(data: &[u8]) -> usize {
        data.windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|pos| pos + 4)
            .or_else(|| {
                data.windows(2)
                    .position(|w| w == b"\n\n")
                    .map(|pos| pos + 2)
            })
            .unwrap_or(0)
    }

    #[test]
    fn results_match_the_scans_they_replace() {
        let corpus: Vec<(&str, Vec<u8>)> = vec![
            ("plain", A.to_vec()),
            ("qp", B.to_vec()),
            (
                "accents",
                "Subject: Café\r\n\r\nUn café très crème brûlée\r\n"
                    .as_bytes()
                    .to_vec(),
            ),
            (
                "ligature",
                "Subject: x\r\n\r\nthe ﬁnal oﬃce ﬂow\r\n"
                    .as_bytes()
                    .to_vec(),
            ),
            (
                "fullwidth",
                "Subject: x\r\n\r\nＨＥＬＬＯ ｗｏｒｌｄ\r\n"
                    .as_bytes()
                    .to_vec(),
            ),
            (
                "greek",
                "Subject: x\r\n\r\nΟΔΥΣΣΕΑΣ ὀδυσσεύς\r\n"
                    .as_bytes()
                    .to_vec(),
            ),
            (
                "kelvin",
                "Subject: x\r\n\r\n\u{212A}elvin and ß and İstanbul\r\n"
                    .as_bytes()
                    .to_vec(),
            ),
            ("lf only", b"Subject: lf\n\nbody with lf\n".to_vec()),
            (
                "no separator",
                b"Subject: only headers and needlehere".to_vec(),
            ),
            ("empty body", b"Subject: nothing\r\n\r\n".to_vec()),
            (
                "mixed endings",
                b"Subject: m\nX: y\r\n\r\nafter crlf\n\nafter lf\r\n".to_vec(),
            ),
            (
                "invalid utf8",
                b"Subject: bin\r\n\r\nbad \xff\xfe bytes here\r\n".to_vec(),
            ),
            ("empty", Vec::new()),
        ];
        let needles = [
            "cafe",
            "café",
            "CAFÉ",
            "creme",
            "brulee",
            "final",
            "office",
            "flow",
            "hello",
            "WORLD",
            "ΣΕΑ",
            "σσε",
            "odysseus",
            "kelvin",
            "ß",
            "ss ",
            "istanbul",
            "numbers",
            "needlehere",
            "lf\nb",
            "body",
            "after",
            "subject",
            "bad ",
            "x: y",
            "nothing",
            "\u{FFFD}",
            "quarterly",
            "menu and",
            "alice@",
            "bob@",
            "nomatchatall",
        ];
        let (td, _) = account();
        let index = open(&td);
        let messages: Vec<(u64, PathBuf)> = corpus
            .iter()
            .enumerate()
            .map(|(i, (name, raw))| (i as u64 + 1, write(td.path(), name, raw)))
            .collect();
        assert_eq!(index.sync("INBOX", 1, &messages, 100).unwrap(), 0);
        let mut checked = 0;
        for field in [Field::Body, Field::Text, Field::Decoded] {
            for needle in needles {
                let Some(hits) = index.query("INBOX", 1, field, needle).unwrap() else {
                    continue;
                };
                for (i, (name, raw)) in corpus.iter().enumerate() {
                    let uid = i as u64 + 1;
                    let covered = hits.lookup(uid);
                    assert_eq!(
                        covered,
                        Some(scan(raw, field, needle)),
                        "{field:?} {needle:?} in {name}"
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked > 300, "{checked}");
    }
}
