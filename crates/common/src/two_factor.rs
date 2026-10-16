//! Two-factor sign-in and app passwords.
//!
//! - **TOTP** (RFC 6238: HMAC-SHA1, 30-second steps, 6 digits), the codes
//!   authenticator apps show. A code is accepted one step either side of
//!   now, and never twice (the last step used is stored).
//! - **Recovery codes**: ten one-time codes made when 2FA is turned on,
//!   stored as SHA-256 digests.
//! - **App passwords**: random per-device passwords for mail apps (IMAP,
//!   SMTP, POP3, ManageSieve, CalDAV/CardDAV, JMAP). They carry about 80
//!   bits of entropy, so a SHA-256 digest is stored and looked up directly;
//!   a slow password hash would have to be run once per app password on
//!   every login.
//!
//! With 2FA on, the account's main password is accepted only by webmail
//! (with a code); mail apps must use an app password, and SCRAM, whose
//! verifier comes from the main password, is not offered for the account
//! (see `db::get_mailbox`).
//!
//! The tables live in the accounts database next to `mailboxes`.

use std::path::Path;

use anyhow::{Result, bail};
use hmac::{Hmac, Mac};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

pub const STEP_SECONDS: i64 = 30;
pub const RECOVERY_CODES: usize = 10;
const SECRET_BYTES: usize = 20;
/// At most this many app passwords per account.
pub const MAX_APP_PASSWORDS: usize = 50;

pub(crate) const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS two_factor (
        account TEXT PRIMARY KEY,
        secret TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 0,
        last_step INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS recovery_codes (
        account TEXT NOT NULL,
        digest TEXT NOT NULL,
        used_at INTEGER,
        PRIMARY KEY (account, digest)
    );
    CREATE TABLE IF NOT EXISTS app_passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account TEXT NOT NULL,
        name TEXT NOT NULL,
        digest TEXT NOT NULL UNIQUE,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS app_passwords_account ON app_passwords(account);
";

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// The accounts database (owner-only, pooled like every other opener).
fn open(path: &Path) -> Result<crate::sqlite_pool::SqliteConnection> {
    let conn = crate::sqlite_pool::connection(path)?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

fn account_key(account: &str) -> Result<String> {
    Ok(crate::domain::canonicalize_mailbox_address(account)?.to_ascii_lowercase())
}

fn digest(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ---------------------------------------------------------------------------
// TOTP

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding, as authenticator apps take secrets.
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            out.push(BASE32[((buffer >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for c in text.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let value = BASE32
            .iter()
            .position(|&b| b as char == c.to_ascii_uppercase())? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            out.push((buffer >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    Some(out)
}

/// The code for one time step (RFC 4226 dynamic truncation, 6 digits).
pub fn code_at(secret: &[u8], step: i64) -> u32 {
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(secret).expect("any key length");
    mac.update(&step.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = (hash[19] & 0x0f) as usize;
    let value = (u32::from(hash[offset] & 0x7f) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]);
    value % 1_000_000
}

/// The step a code matches, one step either side of `at` (clock drift).
fn matching_step(secret: &[u8], code: &str, at: i64) -> Option<i64> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let wanted: u32 = code.parse().ok()?;
    let current = at.div_euclid(STEP_SECONDS);
    (current - 1..=current + 1).find(|&step| {
        // Compared in constant time, like every secret here.
        let expected = format!("{:06}", code_at(secret, step));
        constant_eq(expected.as_bytes(), format!("{wanted:06}").as_bytes())
    })
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The `otpauth://` URI authenticator apps scan.
pub fn provisioning_uri(account: &str, secret: &str, issuer: &str) -> String {
    let enc = |text: &str| {
        text.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'@' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect::<String>()
    };
    format!(
        "otpauth://totp/{}:{}?secret={secret}&issuer={}&algorithm=SHA1&digits=6&period=30",
        enc(issuer),
        enc(account),
        enc(issuer)
    )
}

// ---------------------------------------------------------------------------
// Enrolment and checks

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub enabled: bool,
    pub since: Option<i64>,
    /// Recovery codes not used yet.
    pub recovery_left: usize,
}

pub fn status(db: &Path, account: &str) -> Result<Status> {
    let account = account_key(account)?;
    let conn = open(db)?;
    let row: Option<(bool, i64)> = conn
        .query_row(
            "SELECT enabled, created_at FROM two_factor WHERE account = ?1",
            params![account],
            |row| Ok((row.get::<_, i64>(0)? != 0, row.get(1)?)),
        )
        .optional()?;
    let left: i64 = conn.query_row(
        "SELECT COUNT(*) FROM recovery_codes WHERE account = ?1 AND used_at IS NULL",
        params![account],
        |row| row.get(0),
    )?;
    Ok(Status {
        enabled: row.is_some_and(|(enabled, _)| enabled),
        since: row.filter(|(enabled, _)| *enabled).map(|(_, at)| at),
        recovery_left: left as usize,
    })
}

/// The enabled TOTP secret (base32), if 2FA is on.
pub fn enabled_secret(conn: &Connection, account: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT secret FROM two_factor WHERE account = ?1 AND enabled = 1",
            params![account.to_ascii_lowercase()],
            |row| row.get(0),
        )
        .optional()?)
}

/// Start turning 2FA on: a new secret (base32) that is not enabled until a
/// code from it is confirmed. Refused while 2FA is on.
pub fn begin(db: &Path, account: &str) -> Result<String> {
    let account = account_key(account)?;
    let conn = open(db)?;
    if enabled_secret(&conn, &account)?.is_some() {
        bail!("two-factor sign-in is already on");
    }
    let secret = base32_encode(&rand::random::<[u8; SECRET_BYTES]>());
    conn.execute(
        "INSERT INTO two_factor (account, secret, enabled, last_step, created_at) VALUES (?1, ?2, 0, 0, ?3)
         ON CONFLICT(account) DO UPDATE SET secret = excluded.secret, enabled = 0, last_step = 0,
             created_at = excluded.created_at",
        params![account, secret, now()],
    )?;
    Ok(secret)
}

/// Turn 2FA on with a code from the pending secret; the new recovery codes
/// (shown once), or `None` when the code is wrong.
pub fn confirm(db: &Path, account: &str, code: &str) -> Result<Option<Vec<String>>> {
    let account = account_key(account)?;
    let mut conn = open(db)?;
    let tx = conn.transaction()?;
    let Some(secret): Option<String> = tx
        .query_row(
            "SELECT secret FROM two_factor WHERE account = ?1 AND enabled = 0",
            params![account],
            |row| row.get(0),
        )
        .optional()?
    else {
        return Ok(None);
    };
    let Some(step) = base32_decode(&secret).and_then(|key| matching_step(&key, code, now())) else {
        return Ok(None);
    };
    tx.execute(
        "UPDATE two_factor SET enabled = 1, last_step = ?2, created_at = ?3 WHERE account = ?1",
        params![account, step, now()],
    )?;
    let codes = replace_recovery_codes(&tx, &account)?;
    tx.commit()?;
    Ok(Some(codes))
}

fn new_recovery_code() -> String {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let pick = |_| ALPHABET[rand::random::<usize>() % ALPHABET.len()] as char;
    let first: String = (0..5).map(pick).collect();
    let second: String = (0..5).map(pick).collect();
    format!("{first}-{second}")
}

fn replace_recovery_codes(conn: &Connection, account: &str) -> Result<Vec<String>> {
    conn.execute(
        "DELETE FROM recovery_codes WHERE account = ?1",
        params![account],
    )?;
    let codes: Vec<String> = (0..RECOVERY_CODES).map(|_| new_recovery_code()).collect();
    for code in &codes {
        conn.execute(
            "INSERT INTO recovery_codes (account, digest) VALUES (?1, ?2)",
            params![account, digest(code)],
        )?;
    }
    Ok(codes)
}

/// Whether `code` (from the app, or an unused recovery code) passes for an
/// account with 2FA on; a passing code cannot be used again.
pub fn verify(db: &Path, account: &str, code: &str) -> Result<bool> {
    let account = account_key(account)?;
    let mut conn = open(db)?;
    let tx = conn.transaction()?;
    let row: Option<(String, i64)> = tx
        .query_row(
            "SELECT secret, last_step FROM two_factor WHERE account = ?1 AND enabled = 1",
            params![account],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((secret, last_step)) = row else {
        return Ok(false);
    };
    if let Some(step) = base32_decode(&secret).and_then(|key| matching_step(&key, code, now())) {
        if step <= last_step {
            return Ok(false);
        }
        tx.execute(
            "UPDATE two_factor SET last_step = ?2 WHERE account = ?1",
            params![account, step],
        )?;
        tx.commit()?;
        return Ok(true);
    }
    let normalized = code.trim().to_ascii_lowercase();
    let used = tx.execute(
        "UPDATE recovery_codes SET used_at = ?3 WHERE account = ?1 AND digest = ?2 AND used_at IS NULL",
        params![account, digest(&normalized), now()],
    )?;
    tx.commit()?;
    Ok(used == 1)
}

/// New recovery codes, the old ones no longer valid.
pub fn regenerate_recovery_codes(db: &Path, account: &str) -> Result<Vec<String>> {
    let account = account_key(account)?;
    let mut conn = open(db)?;
    let tx = conn.transaction()?;
    let codes = replace_recovery_codes(&tx, &account)?;
    tx.commit()?;
    Ok(codes)
}

/// Turn 2FA off (the user, after a code and their password, or an admin).
pub fn disable(db: &Path, account: &str) -> Result<bool> {
    let account = account_key(account)?;
    let conn = open(db)?;
    let removed = conn.execute(
        "DELETE FROM two_factor WHERE account = ?1",
        params![account],
    )?;
    conn.execute(
        "DELETE FROM recovery_codes WHERE account = ?1",
        params![account],
    )?;
    Ok(removed > 0)
}

// ---------------------------------------------------------------------------
// App passwords

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AppPassword {
    pub id: i64,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

/// A new app password: four groups of four lowercase letters (about 75
/// bits), easy to type on a phone.
fn new_app_password() -> String {
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    (0..4)
        .map(|_| {
            (0..4)
                .map(|_| LETTERS[rand::random::<usize>() % LETTERS.len()] as char)
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// What a typed app password is compared as: lowercase, without spaces or
/// dashes (clients and users add either).
fn normalize_app_password(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

/// Make an app password called `name`; the password, shown once.
pub fn create_app_password(db: &Path, account: &str, name: &str) -> Result<(AppPassword, String)> {
    let account = account_key(account)?;
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 100 || name.contains(['\r', '\n']) {
        bail!("give the app password a short name");
    }
    let conn = open(db)?;
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM app_passwords WHERE account = ?1",
        params![account],
        |row| row.get(0),
    )?;
    if count as usize >= MAX_APP_PASSWORDS {
        bail!("at most {MAX_APP_PASSWORDS} app passwords");
    }
    let password = new_app_password();
    let created = now();
    conn.execute(
        "INSERT INTO app_passwords (account, name, digest, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![
            account,
            name,
            digest(&normalize_app_password(&password)),
            created
        ],
    )?;
    Ok((
        AppPassword {
            id: conn.last_insert_rowid(),
            name: name.to_string(),
            created_at: created,
            last_used_at: None,
        },
        password,
    ))
}

pub fn app_passwords(db: &Path, account: &str) -> Result<Vec<AppPassword>> {
    let account = account_key(account)?;
    let conn = open(db)?;
    let mut stmt = conn.prepare(
        "SELECT id, name, created_at, last_used_at FROM app_passwords WHERE account = ?1 ORDER BY created_at, id",
    )?;
    let rows = stmt.query_map(params![account], |row| {
        Ok(AppPassword {
            id: row.get(0)?,
            name: row.get(1)?,
            created_at: row.get(2)?,
            last_used_at: row.get(3)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn revoke_app_password(db: &Path, account: &str, id: i64) -> Result<bool> {
    let account = account_key(account)?;
    let conn = open(db)?;
    Ok(conn.execute(
        "DELETE FROM app_passwords WHERE account = ?1 AND id = ?2",
        params![account, id],
    )? == 1)
}

/// Whether `password` is one of the account's app passwords (and note its
/// use). The digest is looked up, so this costs one query however many
/// app passwords there are.
pub fn check_app_password(db: &Path, account: &str, password: &str) -> Result<bool> {
    let normalized = normalize_app_password(password);
    // App passwords are 16 letters; anything else is not one.
    if normalized.len() != 16 || !normalized.bytes().all(|b| b.is_ascii_lowercase()) {
        return Ok(false);
    }
    let account = account_key(account)?;
    let conn = open(db)?;
    Ok(conn.execute(
        "UPDATE app_passwords SET last_used_at = ?3 WHERE account = ?1 AND digest = ?2",
        params![account, digest(&normalized), now()],
    )? == 1)
}

/// How a mail app's password for `account` fares, before any main-password
/// check: an app password signs in; with 2FA on nothing else does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolPassword {
    AppPassword,
    /// 2FA is on and this is not an app password: refuse.
    Refused,
    /// No app password matched and 2FA is off: check the main password.
    CheckMain,
}

pub fn protocol_password(db: &Path, account: &str, password: &str) -> Result<ProtocolPassword> {
    if check_app_password(db, account, password)? {
        return Ok(ProtocolPassword::AppPassword);
    }
    let conn = open(db)?;
    Ok(
        if enabled_secret(&conn, &account_key(account)?)?.is_some() {
            ProtocolPassword::Refused
        } else {
            ProtocolPassword::CheckMain
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_matches_rfc_6238() {
        // RFC 6238 appendix B, SHA-1 key; the 8-digit values end in these 6.
        let key = b"12345678901234567890";
        for (time, expected) in [
            (59, 287_082),
            (1_111_111_109, 81_804),
            (1_234_567_890, 5_924),
            (2_000_000_000, 279_037),
        ] {
            assert_eq!(code_at(key, time / STEP_SECONDS), expected, "{time}");
        }
        assert_eq!(base32_decode(&base32_encode(key)).unwrap(), key);
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(matching_step(key, "287082", 59), Some(1));
        assert_eq!(
            matching_step(key, "287 082", 59 + 30),
            Some(1),
            "a step late"
        );
        assert_eq!(matching_step(key, "287082", 59 + 90), None, "too late");
        assert_eq!(matching_step(key, "28708", 59), None);
    }

    #[test]
    fn enrolment_codes_and_app_passwords() {
        let td = tempfile::tempdir().unwrap();
        let db = td.path().join("accounts.sqlite");
        let me = "User@Example.test";
        assert!(!status(&db, me).unwrap().enabled);
        assert_eq!(
            protocol_password(&db, me, "main").unwrap(),
            ProtocolPassword::CheckMain
        );

        let secret = begin(&db, me).unwrap();
        let key = base32_decode(&secret).unwrap();
        assert_eq!(confirm(&db, me, "000000").unwrap(), None, "wrong code");
        assert!(!status(&db, me).unwrap().enabled);
        let code = format!("{:06}", code_at(&key, now() / STEP_SECONDS));
        let recovery = confirm(&db, me, &code).unwrap().unwrap();
        assert_eq!(recovery.len(), RECOVERY_CODES);
        assert!(status(&db, me).unwrap().enabled);
        assert!(begin(&db, me).is_err(), "already on");

        // The confirming code is spent; a recovery code works once.
        assert!(!verify(&db, me, &code).unwrap());
        assert!(verify(&db, me, &recovery[0].to_uppercase()).unwrap());
        assert!(!verify(&db, me, &recovery[0]).unwrap());
        assert_eq!(status(&db, me).unwrap().recovery_left, RECOVERY_CODES - 1);
        let fresh = regenerate_recovery_codes(&db, me).unwrap();
        assert!(
            !verify(&db, me, &recovery[1]).unwrap(),
            "old codes are gone"
        );
        assert!(verify(&db, me, &fresh[0]).unwrap());

        // With 2FA on, only app passwords sign mail apps in.
        assert_eq!(
            protocol_password(&db, me, "main").unwrap(),
            ProtocolPassword::Refused
        );
        let (made, password) = create_app_password(&db, me, "Phone").unwrap();
        assert_eq!(password.len(), 19);
        let typed = password.to_uppercase().replace('-', " ");
        assert_eq!(
            protocol_password(&db, me, &typed).unwrap(),
            ProtocolPassword::AppPassword
        );
        assert!(app_passwords(&db, me).unwrap()[0].last_used_at.is_some());
        assert!(!check_app_password(&db, "other@example.test", &password).unwrap());
        assert!(revoke_app_password(&db, me, made.id).unwrap());
        assert_eq!(
            protocol_password(&db, me, &password).unwrap(),
            ProtocolPassword::Refused
        );
        assert!(create_app_password(&db, me, " ").is_err());

        assert!(disable(&db, me).unwrap());
        assert_eq!(
            protocol_password(&db, me, "main").unwrap(),
            ProtocolPassword::CheckMain
        );
        assert!(provisioning_uri("a b@x.test", "ABC", "rMail mail.x.test").starts_with(
            "otpauth://totp/rMail%20mail.x.test:a%20b@x.test?secret=ABC&issuer=rMail%20mail.x.test"
        ));
    }
}
