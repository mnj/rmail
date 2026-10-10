//! IMAP URLAUTH (RFC 4467): IMAP URLs (RFC 5092) that carry their own
//! authorization, so a client can let the submission server fetch a saved
//! message (BURL, RFC 4468) instead of uploading it a second time.
//!
//! GENURLAUTH signs a URL "rump", the URL up to and including
//! `;URLAUTH=<access>`, with HMAC-SHA256 (the `INTERNAL` mechanism) under a
//! random access key and appends `:INTERNAL:<token>`. A key belongs to one
//! user and one mailbox and lives in that user's account state database
//! (`urlauth_keys`), keyed by MAILBOXID: it follows a RENAME and is never
//! inherited by a later mailbox of the same name. RESETKEY deletes keys,
//! which revokes every URL signed with them.
//!
//! A URL alone grants nothing: [`fetch`] resolves it as the user named in
//! the URL, with that user's current rights, and only for the requester the
//! access identifier names. imapd uses this module for GENURLAUTH, URLFETCH
//! and RESETKEY, and smtpd for BURL, reading the store directly since both
//! run on the same host over the same data.

use std::fmt;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::Result;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::Sha256;

use crate::acl::{self, Rights};
use crate::imap_state::{self, Folder};

/// The only authorization mechanism (RFC 4467 section 2.4.1).
pub const MECHANISM: &str = "INTERNAL";

const KEY_BYTES: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// Who may use a URL (RFC 4467 section 3, the access identifier).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    /// `submit+<user>`: the submission server, sending for `<user>`.
    Submit(String),
    /// `user+<user>`: an IMAP session authenticated as `<user>`.
    User(String),
    /// `authuser`: any authenticated user.
    AuthUser,
    /// `anonymous`: anyone. rMail never honors it.
    Anonymous,
}

/// A parsed URLAUTH rump that names one message or one part of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImapUrl {
    /// The user whose mailbox namespace (and access key) the URL uses.
    pub user: String,
    /// The server, lower-cased, without the port.
    pub host: String,
    /// The mailbox name, percent-decoded (UTF-8, RFC 5092 section 3.2).
    pub mailbox: String,
    pub uidvalidity: Option<u32>,
    pub uid: u32,
    /// The IMAP body section, upper-cased.
    pub section: Option<String>,
    /// `;PARTIAL=offset[.length]`.
    pub partial: Option<(u64, Option<u64>)>,
    /// `;EXPIRE=`, as Unix time.
    pub expire: Option<i64>,
    pub access: Access,
}

/// The party resolving a URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requester<'a> {
    /// An IMAP session authenticated as this user (URLFETCH).
    Imap(&'a str),
    /// The submission server, for a client authenticated as this user (BURL).
    Submit(&'a str),
}

/// Why a URL was refused. The variants that depend on stored state are
/// folded into [`Refusal::Unresolved`], so a requester cannot tell a wrong
/// token from a missing mailbox or a revoked key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Not a URLAUTH-authorized IMAP URL naming a message.
    Invalid,
    /// Resolving the URL would need a trust relationship rMail does not
    /// have: it names another server, or it is a plain IMAP URL without
    /// URLAUTH (RFC 4468 section 5).
    Untrusted,
    /// The access identifier does not admit the requester.
    NotAuthorized,
    /// Wrong token, expired, revoked, or the mailbox, message or read right
    /// is gone.
    Unresolved,
    /// The content is larger than the caller accepts.
    TooLarge,
    /// The store could not be read.
    Unavailable,
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Refusal::Invalid => "invalid URLAUTH URL",
            Refusal::Untrusted => "URL resolution requires a trust relationship",
            Refusal::NotAuthorized => "access identifier does not admit the requester",
            Refusal::Unresolved => "URL could not be resolved",
            Refusal::TooLarge => "URL content is too large",
            Refusal::Unavailable => "mail store unavailable",
        })
    }
}

impl std::error::Error for Refusal {}

// ---------------------------------------------------------------------------
// Server names

static SERVER_NAMES: OnceLock<Vec<String>> = OnceLock::new();

/// Set the host names URLs may name (once, at service start). Until then
/// only the system hostname is accepted.
pub fn set_server_names(names: Vec<String>) {
    let _ = SERVER_NAMES.set(
        names
            .into_iter()
            .map(|name| name.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|name| !name.is_empty())
            .collect(),
    );
}

/// The names clients reach this server by: `global.hostname` (or the system
/// hostname), the ACME certificate names and the DNS names on the
/// configured certificate.
pub fn server_names_from_config(config: &crate::config::Config) -> Vec<String> {
    let mut names = vec![config.global.server_hostname()];
    names.extend(config.acme.domains.iter().cloned());
    if let Some(cert) = config.global.tls_cert.as_deref()
        && let Ok(info) = crate::acme::cert::inspect_file(cert)
    {
        names.extend(info.names);
    }
    names
}

/// Whether `host` (lower-case) is this server. A `*.example.com` name
/// covers one label, as on a certificate.
fn is_server_host(host: &str) -> bool {
    host_matches(
        SERVER_NAMES.get_or_init(|| vec![crate::config::system_hostname()]),
        host,
    )
}

fn host_matches(names: &[String], host: &str) -> bool {
    names.iter().any(|name| match name.strip_prefix("*.") {
        Some(base) => host
            .split_once('.')
            .is_some_and(|(label, rest)| !label.is_empty() && rest == base),
        None => name == host,
    })
}

// ---------------------------------------------------------------------------
// Parsing

/// Parse a URL rump: an absolute IMAP URL naming one message (or part)
/// that ends with `[;EXPIRE=<date-time>];URLAUTH=<access>` (RFC 4467
/// section 9). The user is mandatory.
pub fn parse_rump(rump: &str) -> Result<ImapUrl, Refusal> {
    if rump.bytes().any(|byte| !byte.is_ascii_graphic()) {
        return Err(Refusal::Invalid);
    }
    let rest = strip_prefix_ignore_case(rump, "imap://").ok_or(Refusal::Invalid)?;
    let (authority, path) = rest.split_once('/').ok_or(Refusal::Invalid)?;
    let (userinfo, hostport) = authority.rsplit_once('@').ok_or(Refusal::Invalid)?;
    // `;AUTH=<type>` selects how a client logs in; it is signed with the
    // rest of the rump but does not change how the URL resolves.
    let user = match userinfo.split_once(';') {
        Some((user, auth)) => {
            strip_prefix_ignore_case(auth, "AUTH=")
                .filter(|kind| !kind.is_empty())
                .ok_or(Refusal::Invalid)?;
            user
        }
        None => userinfo,
    };
    let user = decode_userid(user)?;
    let host = parse_host(hostport)?;

    let at = rfind_ignore_case(path, ";URLAUTH=").ok_or(Refusal::Invalid)?;
    let access = parse_access(&path[at + ";URLAUTH=".len()..])?;
    let mut message = &path[..at];
    let mut expire = None;
    if let Some(at) = rfind_ignore_case(message, ";EXPIRE=") {
        let value = percent_decode(&message[at + ";EXPIRE=".len()..])?;
        expire = Some(
            chrono::DateTime::parse_from_rfc3339(&value)
                .map_err(|_| Refusal::Invalid)?
                .timestamp(),
        );
        message = &message[..at];
    }

    let mut segments = message.split("/;");
    let first = segments.next().unwrap_or_default();
    let (mailbox, uidvalidity) = match first.split_once(';') {
        Some((mailbox, parameter)) => {
            let value = parameter_value(parameter, "UIDVALIDITY")?;
            (mailbox, Some(nz_number(value)?))
        }
        None => (first, None),
    };
    let mailbox = percent_decode(mailbox)?;
    if mailbox.is_empty() {
        return Err(Refusal::Invalid);
    }
    let uid = nz_number(parameter_value(
        segments.next().ok_or(Refusal::Invalid)?,
        "UID",
    )?)?;
    let mut section = None;
    let mut partial = None;
    for segment in segments {
        if section.is_none()
            && partial.is_none()
            && let Ok(value) = parameter_value(segment, "SECTION")
        {
            let value = percent_decode(value)?.to_ascii_uppercase();
            if !valid_section(&value) {
                return Err(Refusal::Invalid);
            }
            section = Some(value);
        } else if partial.is_none()
            && let Ok(value) = parameter_value(segment, "PARTIAL")
        {
            partial = Some(parse_partial(value)?);
        } else {
            return Err(Refusal::Invalid);
        }
    }
    Ok(ImapUrl {
        user,
        host,
        mailbox,
        uidvalidity,
        uid,
        section,
        partial,
        expire,
        access,
    })
}

/// Split an authorized URL into its rump, mechanism and token. Removing
/// `:<mechanism>:<token>` is the only operation applied to get the rump
/// (RFC 4467 section 6): no decoding or case folding.
pub fn split_authorized(url: &str) -> Result<(&str, &str, &str), Refusal> {
    let (head, token) = url.rsplit_once(':').ok_or(Refusal::Invalid)?;
    let (rump, mechanism) = head.rsplit_once(':').ok_or(Refusal::Invalid)?;
    let valid_mechanism = !mechanism.is_empty()
        && mechanism
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'));
    if !valid_mechanism || token.len() < 32 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Refusal::Invalid);
    }
    Ok((rump, mechanism, token))
}

fn strip_prefix_ignore_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|_| &value[prefix.len()..])
}

fn rfind_ignore_case(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .to_ascii_uppercase()
        .rfind(&needle.to_ascii_uppercase())
}

fn parameter_value<'a>(parameter: &'a str, name: &str) -> Result<&'a str, Refusal> {
    let (key, value) = parameter.split_once('=').ok_or(Refusal::Invalid)?;
    if key.eq_ignore_ascii_case(name) {
        Ok(value)
    } else {
        Err(Refusal::Invalid)
    }
}

/// An RFC 5092 `nz-number`: no sign, no leading zero, 32 bits.
fn nz_number(value: &str) -> Result<u32, Refusal> {
    if value.is_empty() || value.starts_with('0') || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Refusal::Invalid);
    }
    value.parse().map_err(|_| Refusal::Invalid)
}

fn parse_partial(value: &str) -> Result<(u64, Option<u64>), Refusal> {
    let (offset, length) = match value.split_once('.') {
        Some((offset, length)) => (offset, Some(u64::from(nz_number(length)?))),
        None => (value, None),
    };
    if offset.is_empty() || !offset.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Refusal::Invalid);
    }
    Ok((offset.parse().map_err(|_| Refusal::Invalid)?, length))
}

/// Body sections that [`crate::mime_section::extract_section`] serves:
/// `HEADER`, `TEXT`, or part numbers with an optional `.HEADER`, `.TEXT` or
/// `.MIME`. `HEADER.FIELDS` is not supported in URLs.
fn valid_section(section: &str) -> bool {
    if matches!(section, "HEADER" | "TEXT") {
        return true;
    }
    let mut parts = section.split('.').peekable();
    let mut numbers = 0;
    while let Some(part) = parts.next() {
        if nz_number(part).is_ok() {
            numbers += 1;
        } else {
            return numbers > 0
                && parts.peek().is_none()
                && matches!(part, "HEADER" | "TEXT" | "MIME");
        }
    }
    numbers > 0
}

fn parse_host(hostport: &str) -> Result<String, Refusal> {
    let host = if let Some(literal) = hostport.strip_prefix('[') {
        let (address, port) = literal.split_once(']').ok_or(Refusal::Invalid)?;
        if !port.is_empty() {
            valid_port(port.strip_prefix(':').ok_or(Refusal::Invalid)?)?;
        }
        address
    } else {
        match hostport.split_once(':') {
            Some((host, port)) => {
                valid_port(port)?;
                host
            }
            None => hostport,
        }
    };
    let host = percent_decode(host)?;
    if host.is_empty() {
        return Err(Refusal::Invalid);
    }
    Ok(host.trim_end_matches('.').to_ascii_lowercase())
}

fn valid_port(port: &str) -> Result<(), Refusal> {
    if port.is_empty() || port.parse::<u16>().is_err() {
        return Err(Refusal::Invalid);
    }
    Ok(())
}

fn decode_userid(encoded: &str) -> Result<String, Refusal> {
    let user = percent_decode(encoded)?;
    crate::domain::canonicalize_mailbox_address(&user).map_err(|_| Refusal::Invalid)
}

fn parse_access(access: &str) -> Result<Access, Refusal> {
    if access.eq_ignore_ascii_case("authuser") {
        Ok(Access::AuthUser)
    } else if access.eq_ignore_ascii_case("anonymous") {
        Ok(Access::Anonymous)
    } else if let Some(user) = strip_prefix_ignore_case(access, "submit+") {
        Ok(Access::Submit(decode_userid(user)?))
    } else if let Some(user) = strip_prefix_ignore_case(access, "user+") {
        Ok(Access::User(decode_userid(user)?))
    } else {
        Err(Refusal::Invalid)
    }
}

/// Decode `%XX` escapes. The result must be UTF-8 without control
/// characters.
fn percent_decode(value: &str) -> Result<String, Refusal> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes.get(index + 1..index + 3).ok_or(Refusal::Invalid)?;
            let hex = std::str::from_utf8(hex).map_err(|_| Refusal::Invalid)?;
            if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(Refusal::Invalid);
            }
            output.push(u8::from_str_radix(hex, 16).map_err(|_| Refusal::Invalid)?);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    let text = String::from_utf8(output).map_err(|_| Refusal::Invalid)?;
    if text.chars().any(char::is_control) {
        return Err(Refusal::Invalid);
    }
    Ok(text)
}

// ---------------------------------------------------------------------------
// Access keys

/// Create the key table in an account state database.
pub(crate) fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS urlauth_keys(
            mailbox_id TEXT PRIMARY KEY,
            access_key BLOB NOT NULL
        );",
    )?;
    Ok(())
}

fn split_address(address: &str) -> Result<(String, String)> {
    let (local, domain) = address
        .rsplit_once('@')
        .ok_or_else(|| anyhow::anyhow!("invalid account address"))?;
    Ok((local.to_string(), domain.to_string()))
}

/// The user's access key for a mailbox, created when `create` is set.
fn access_key(
    mail_root: &Path,
    user: &str,
    mailbox_id: &str,
    create: bool,
) -> Result<Option<Vec<u8>>> {
    let (local, domain) = split_address(user)?;
    let conn = imap_state::open_account(mail_root, &domain, &local)?;
    let read = |conn: &Connection| -> Result<Option<Vec<u8>>> {
        Ok(conn
            .query_row(
                "SELECT access_key FROM urlauth_keys WHERE mailbox_id = ?1",
                params![mailbox_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?)
    };
    if let Some(key) = read(&conn)? {
        return Ok(Some(key));
    }
    if !create {
        return Ok(None);
    }
    let mut key = vec![0_u8; KEY_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut key);
    // A concurrent GENURLAUTH may have created one first; keep that one.
    conn.execute(
        "INSERT OR IGNORE INTO urlauth_keys(mailbox_id, access_key) VALUES(?1, ?2)",
        params![mailbox_id, key],
    )?;
    read(&conn)
}

/// RESETKEY: revoke the user's URLs for one mailbox (by MAILBOXID), or for
/// every mailbox. GENURLAUTH creates a new key when it next needs one.
pub fn reset_keys(mail_root: &Path, user: &str, mailbox_id: Option<&str>) -> Result<()> {
    let (local, domain) = split_address(user)?;
    let conn = imap_state::open_account(mail_root, &domain, &local)?;
    match mailbox_id {
        Some(id) => conn.execute(
            "DELETE FROM urlauth_keys WHERE mailbox_id = ?1",
            params![id],
        )?,
        None => conn.execute("DELETE FROM urlauth_keys", [])?,
    };
    Ok(())
}

fn mac(key: &[u8], rump: &str) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(rump.as_bytes());
    mac
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(text.get(index..index + 2)?, 16).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Mailbox resolution

/// A mailbox as stored, in the owner's account.
pub struct Resolved {
    pub domain: String,
    pub local: String,
    pub folder: Folder,
}

/// The stored address of an account, or `None` when it does not exist.
/// Checked before touching storage, which would otherwise create an
/// account directory for any name in a URL.
fn existing_account(db_path: &Path, address: &str) -> Result<Option<String>> {
    Ok(crate::db::get_mailbox(db_path, address)?.map(|mailbox| mailbox.address))
}

/// Resolve `mailbox` in `user`'s namespace: one of the user's own
/// mailboxes, or `Other Users/<owner>/<name>` shared with the user with the
/// read right. `None` when it does not exist or may not be read.
pub fn resolve_mailbox(
    mail_root: &Path,
    db_path: &Path,
    user: &str,
    mailbox: &str,
) -> Result<Option<Resolved>> {
    if let Some((owner, rest)) = acl::split_shared_name(mailbox) {
        if rest.is_empty() {
            return Ok(None);
        }
        let Some(shared) = acl::find_shared(mail_root, db_path, user, owner, rest)? else {
            return Ok(None);
        };
        if !shared.rights.contains(Rights::READ) {
            return Ok(None);
        }
        return Ok(Some(Resolved {
            domain: shared.domain,
            local: shared.localpart,
            folder: shared.folder,
        }));
    }
    if crate::maildir::normalize_mailbox_name(mailbox).is_err() {
        return Ok(None);
    }
    let (local, domain) = split_address(user)?;
    Ok(
        imap_state::find_folder(mail_root, &domain, &local, mailbox)?.map(|folder| Resolved {
            domain,
            local,
            folder,
        }),
    )
}

// ---------------------------------------------------------------------------
// GENURLAUTH and URL resolution

/// GENURLAUTH for one rump: check it names a mailbox `user` may read on
/// this server and return the authorized URL. The key is created on first
/// use (RFC 4467 section 7).
pub fn generate(
    mail_root: &Path,
    db_path: Option<&Path>,
    user: &str,
    rump: &str,
    mechanism: &str,
) -> Result<String, Refusal> {
    if !mechanism.eq_ignore_ascii_case(MECHANISM) {
        return Err(Refusal::Invalid);
    }
    let url = parse_rump(rump)?;
    if !is_server_host(&url.host) {
        return Err(Refusal::Untrusted);
    }
    let db_path = db_path.ok_or(Refusal::Unavailable)?;
    let user = crate::domain::canonicalize_mailbox_address(user).map_err(|_| Refusal::Invalid)?;
    if url.user != user {
        return Err(Refusal::NotAuthorized);
    }
    match &url.access {
        Access::Anonymous => return Err(Refusal::NotAuthorized),
        Access::Submit(target) | Access::User(target) => {
            // The access identifier must name a valid userid.
            if existing_account(db_path, target)
                .map_err(|_| Refusal::Unavailable)?
                .is_none()
            {
                return Err(Refusal::Invalid);
            }
        }
        Access::AuthUser => {}
    }
    if url
        .expire
        .is_some_and(|expire| expire <= chrono::Utc::now().timestamp())
    {
        return Err(Refusal::Invalid);
    }
    let resolved = resolve_mailbox(mail_root, db_path, &user, &url.mailbox)
        .map_err(|_| Refusal::Unavailable)?
        .ok_or(Refusal::Unresolved)?;
    if url
        .uidvalidity
        .is_some_and(|expected| u64::from(expected) != resolved.folder.uidvalidity)
    {
        return Err(Refusal::Unresolved);
    }
    let key = access_key(mail_root, &user, &resolved.folder.mailbox_id, true)
        .map_err(|_| Refusal::Unavailable)?
        .ok_or(Refusal::Unavailable)?;
    let token = mac(&key, rump).finalize().into_bytes();
    Ok(format!("{rump}:{MECHANISM}:{}", hex(&token)))
}

/// Whether the access identifier admits the requester. The submission
/// server acts only for the user a `submit+` URL names (RFC 4468 section
/// 5); IMAP sessions are never the submission server.
fn admits(access: &Access, requester: Requester<'_>) -> bool {
    let same = |target: &str, user: &str| {
        crate::domain::canonicalize_mailbox_address(user).is_ok_and(|user| user == target)
    };
    match (access, requester) {
        (Access::Submit(target), Requester::Submit(user)) => same(target, user),
        (Access::User(target), Requester::Imap(user)) => same(target, user),
        (Access::AuthUser, _) => true,
        _ => false,
    }
}

/// Resolve an authorized URL for `requester` and return its content, at
/// most `max_bytes`. URLFETCH answers NIL and BURL fails on any refusal.
pub fn fetch(
    mail_root: &Path,
    db_path: Option<&Path>,
    authorized: &str,
    requester: Requester<'_>,
    max_bytes: u64,
) -> Result<Vec<u8>, Refusal> {
    if rfind_ignore_case(authorized, ";URLAUTH=").is_none() {
        return Err(Refusal::Untrusted);
    }
    let (rump, mechanism, token) = split_authorized(authorized)?;
    if !mechanism.eq_ignore_ascii_case(MECHANISM) {
        return Err(Refusal::Invalid);
    }
    let url = parse_rump(rump)?;
    if !is_server_host(&url.host) {
        return Err(Refusal::Untrusted);
    }
    if !admits(&url.access, requester) {
        return Err(Refusal::NotAuthorized);
    }
    let db_path = db_path.ok_or(Refusal::Unavailable)?;

    // Look up the key; a URL whose mailbox cannot be identified is still
    // checked against a throwaway key, so timing does not tell the cases
    // apart (RFC 4467 section 6).
    let resolved = existing_account(db_path, &url.user)
        .map_err(|_| Refusal::Unavailable)?
        .map(|user| -> Result<_, Refusal> {
            let Some(resolved) = resolve_mailbox(mail_root, db_path, &user, &url.mailbox)
                .map_err(|_| Refusal::Unavailable)?
            else {
                return Ok(None);
            };
            let key = access_key(mail_root, &user, &resolved.folder.mailbox_id, false)
                .map_err(|_| Refusal::Unavailable)?;
            Ok(key.map(|key| (resolved, key)))
        })
        .transpose()?
        .flatten();
    let mut throwaway = [0_u8; KEY_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut throwaway);
    let key = resolved
        .as_ref()
        .map_or(&throwaway[..], |(_, key)| key.as_slice());
    let token = unhex(token).ok_or(Refusal::Invalid)?;
    // Constant-time comparison.
    let verified = mac(key, rump).verify_slice(&token).is_ok();
    let Some((resolved, _)) = resolved.filter(|_| verified) else {
        return Err(Refusal::Unresolved);
    };
    if url
        .expire
        .is_some_and(|expire| expire <= chrono::Utc::now().timestamp())
    {
        return Err(Refusal::Unresolved);
    }
    if url
        .uidvalidity
        .is_some_and(|expected| u64::from(expected) != resolved.folder.uidvalidity)
    {
        return Err(Refusal::Unresolved);
    }
    read_part(mail_root, &resolved, &url, max_bytes)
}

fn read_part(
    mail_root: &Path,
    resolved: &Resolved,
    url: &ImapUrl,
    max_bytes: u64,
) -> Result<Vec<u8>, Refusal> {
    let (_, messages) = imap_state::load_folder(
        mail_root,
        &resolved.domain,
        &resolved.local,
        &resolved.folder.name,
    )
    .map_err(|_| Refusal::Unavailable)?;
    let message = messages
        .into_iter()
        .find(|message| message.uid == u64::from(url.uid))
        .ok_or(Refusal::Unresolved)?;
    if url.section.is_none() && url.partial.is_none() && message.size > max_bytes {
        return Err(Refusal::TooLarge);
    }
    let data = std::fs::read(&message.path).map_err(|_| Refusal::Unresolved)?;
    let mut data = match &url.section {
        Some(section) => {
            crate::mime_section::extract_section(&data, section).ok_or(Refusal::Unresolved)?
        }
        None => data,
    };
    if let Some((offset, length)) = url.partial {
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(data.len());
        let end = length
            .and_then(|length| usize::try_from(length).ok())
            .map_or(data.len(), |length| {
                start.saturating_add(length).min(data.len())
            });
        data = data[start..end].to_vec();
    }
    if data.len() as u64 > max_bytes {
        return Err(Refusal::TooLarge);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "mail.example.test";

    fn rump(path: &str) -> String {
        format!("imap://alice%40example.test@{HOST}/{path}")
    }

    #[test]
    fn rumps_parse_into_their_parts() {
        let url = parse_rump(&rump(
            "Other%20Users/bob%40example.test/Drafts;UIDVALIDITY=385759045/;UID=20/;SECTION=1.mime/;PARTIAL=0.1024;EXPIRE=2030-01-01T00:00:00Z;URLAUTH=submit+alice%40Example.TEST",
        ))
        .unwrap();
        assert_eq!(url.user, "alice@example.test");
        assert_eq!(url.host, HOST);
        assert_eq!(url.mailbox, "Other Users/bob@example.test/Drafts");
        assert_eq!(url.uidvalidity, Some(385759045));
        assert_eq!(url.uid, 20);
        assert_eq!(url.section.as_deref(), Some("1.MIME"));
        assert_eq!(url.partial, Some((0, Some(1024))));
        assert_eq!(url.expire, Some(1_893_456_000));
        assert_eq!(url.access, Access::Submit("alice@example.test".into()));

        let url = parse_rump(&format!(
            "IMAP://alice%40example.test;AUTH=*@{}:143/INBOX/;uid=1;urlauth=authuser",
            HOST.to_uppercase()
        ))
        .unwrap();
        assert_eq!(url.host, HOST);
        assert_eq!(url.mailbox, "INBOX");
        assert_eq!(url.access, Access::AuthUser);
    }

    #[test]
    fn malformed_rumps_are_refused() {
        for bad in [
            // No user, no URLAUTH, no UID, bad numbers and parameters.
            format!("imap://{HOST}/INBOX/;UID=1;URLAUTH=authuser"),
            rump("INBOX/;UID=1"),
            rump("INBOX;URLAUTH=authuser"),
            rump("INBOX/;UID=0;URLAUTH=authuser"),
            rump("INBOX/;UID=01;URLAUTH=authuser"),
            rump("INBOX;UIDVALIDITY=x/;UID=1;URLAUTH=authuser"),
            rump("INBOX/;UID=1/;UID=2;URLAUTH=authuser"),
            rump("INBOX/;UID=1/;PARTIAL=1/;SECTION=1;URLAUTH=authuser"),
            rump("INBOX/;UID=1/;SECTION=HEADER.FIELDS%20(To);URLAUTH=authuser"),
            rump("INBOX/;UID=1/;SECTION=0;URLAUTH=authuser"),
            rump("INBOX/;UID=1;EXPIRE=tomorrow;URLAUTH=authuser"),
            rump("INBOX/;UID=1;URLAUTH=someone"),
            rump("INBOX/;UID=1;URLAUTH=user+nobody"),
            rump("IN%0ABOX/;UID=1;URLAUTH=authuser"),
            rump("INBOX/;UID=1;URLAUTH=auth user"),
            rump("/;UID=1;URLAUTH=authuser"),
        ] {
            assert_eq!(parse_rump(&bad), Err(Refusal::Invalid), "{bad}");
        }
    }

    #[test]
    fn authorized_urls_split_at_the_last_two_colons_only() {
        let token = "a".repeat(64);
        let url = format!("{}:INTERNAL:{token}", rump("INBOX/;UID=1;URLAUTH=authuser"));
        let (rump_part, mechanism, found) = split_authorized(&url).unwrap();
        assert_eq!(rump_part, rump("INBOX/;UID=1;URLAUTH=authuser"));
        assert_eq!(mechanism, "INTERNAL");
        assert_eq!(found, token);
        assert!(split_authorized(&format!("{}:INTERNAL:abc", rump("x"))).is_err());
        assert!(split_authorized(&format!("{}:INTERNAL:{}", rump("x"), "g".repeat(32))).is_err());
    }

    #[test]
    fn access_identifiers_admit_only_their_requesters() {
        let alice = "alice@example.test";
        let submit = Access::Submit(alice.into());
        assert!(admits(&submit, Requester::Submit("alice@EXAMPLE.test")));
        assert!(!admits(&submit, Requester::Submit("bob@example.test")));
        assert!(!admits(&submit, Requester::Imap(alice)));
        let user = Access::User(alice.into());
        assert!(admits(&user, Requester::Imap(alice)));
        assert!(!admits(&user, Requester::Submit(alice)));
        assert!(admits(
            &Access::AuthUser,
            Requester::Imap("bob@example.test")
        ));
        assert!(!admits(&Access::Anonymous, Requester::Imap(alice)));
        assert!(!admits(&Access::Anonymous, Requester::Submit(alice)));
    }

    #[test]
    fn sections_follow_the_imap_grammar() {
        for good in [
            "HEADER", "TEXT", "1", "1.2.3", "2.MIME", "3.HEADER", "1.TEXT",
        ] {
            assert!(valid_section(good), "{good}");
        }
        for bad in [
            "",
            "MIME",
            "1.",
            ".1",
            "1.MIME.2",
            "HEADER.FIELDS (TO)",
            "1.X",
        ] {
            assert!(!valid_section(bad), "{bad}");
        }
    }

    struct Store {
        _dir: tempfile::TempDir,
        mail_root: std::path::PathBuf,
        db_path: std::path::PathBuf,
    }

    fn store() -> Store {
        let dir = tempfile::tempdir().unwrap();
        let mail_root = dir.path().join("mail");
        let db_path = dir.path().join("config.db");
        crate::db::init_db(&db_path).unwrap();
        crate::db::add_mailbox(&db_path, "alice@example.test", None, None, None).unwrap();
        imap_state::append_message(
            &mail_root,
            "example.test",
            "alice",
            "INBOX",
            b"Subject: hi\r\n\r\nbody\r\n",
            Vec::new(),
        )
        .unwrap();
        Store {
            _dir: dir,
            mail_root,
            db_path,
        }
    }

    fn local_rump(path: &str) -> String {
        format!(
            "imap://alice%40example.test@{}/{path}",
            crate::config::system_hostname()
        )
    }

    /// Sign `rump` with alice's INBOX key, as GENURLAUTH would but without
    /// its checks, to reach the checks `fetch` makes on its own.
    fn sign(store: &Store, rump: &str) -> String {
        let folder = imap_state::find_folder(&store.mail_root, "example.test", "alice", "INBOX")
            .unwrap()
            .unwrap();
        let key = access_key(
            &store.mail_root,
            "alice@example.test",
            &folder.mailbox_id,
            true,
        )
        .unwrap()
        .unwrap();
        format!(
            "{rump}:INTERNAL:{}",
            hex(&mac(&key, rump).finalize().into_bytes())
        )
    }

    #[test]
    fn fetch_refuses_expired_oversized_and_unknown_account_urls() {
        let store = store();
        let alice = Requester::Imap("alice@example.test");
        let fetch = |url: &str, max: u64| {
            super::fetch(&store.mail_root, Some(&store.db_path), url, alice, max)
        };
        let live = sign(
            &store,
            &local_rump("INBOX/;UID=1;EXPIRE=2999-01-01T00:00:00Z;URLAUTH=authuser"),
        );
        assert_eq!(fetch(&live, 1024).unwrap(), b"Subject: hi\r\n\r\nbody\r\n");
        assert_eq!(fetch(&live, 5), Err(Refusal::TooLarge));
        let expired = sign(
            &store,
            &local_rump("INBOX/;UID=1;EXPIRE=2001-01-01T00:00:00Z;URLAUTH=authuser"),
        );
        assert_eq!(fetch(&expired, 1024), Err(Refusal::Unresolved));
        // A token from one rump does not authorize another.
        let (_, _, token) = split_authorized(&live).unwrap();
        let other = format!(
            "{}:INTERNAL:{token}",
            local_rump("INBOX/;UID=1;EXPIRE=2999-01-01T00:00:01Z;URLAUTH=authuser")
        );
        assert_eq!(fetch(&other, 1024), Err(Refusal::Unresolved));
        // A URL for an account that does not exist fails like a bad token
        // and creates nothing on disk.
        let ghost = live.replace("alice%40", "ghost%40");
        assert_eq!(fetch(&ghost, 1024), Err(Refusal::Unresolved));
        assert!(!store.mail_root.join("example.test/ghost").exists());
        // Without the account database nothing resolves.
        assert_eq!(
            super::fetch(&store.mail_root, None, &live, alice, 1024),
            Err(Refusal::Unavailable)
        );
        assert!(reset_keys(&store.mail_root, "alice@example.test", None).is_ok());
        assert_eq!(fetch(&live, 1024), Err(Refusal::Unresolved));
    }

    #[test]
    fn wildcard_server_names_cover_one_label() {
        let names = ["mail.example.test".to_string(), "*.example.org".to_string()];
        let matches = |host: &str| host_matches(&names, host);
        assert!(matches("mail.example.test"));
        assert!(matches("imap.example.org"));
        assert!(!matches("a.b.example.org"));
        assert!(!matches("example.org"));
    }
}
