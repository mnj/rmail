//! DKIM and ARC signing keys, stored in the `dkim_keys` table.
//!
//! Every key for a sender domain signs its outbound mail, so a domain can
//! carry RSA and Ed25519 signatures side by side (RFC 8463 section 6). One
//! RSA key may also be the ARC key that seals forwarded mail.

use std::path::{Path, PathBuf};
use std::sync::RwLock;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    Rsa,
    Ed25519,
}

impl Algorithm {
    pub fn parse(text: &str) -> Result<Self> {
        match text.to_ascii_lowercase().as_str() {
            "rsa" => Ok(Self::Rsa),
            "ed25519" => Ok(Self::Ed25519),
            _ => bail!("unknown DKIM key algorithm {text:?} (use rsa or ed25519)"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rsa => "rsa",
            Self::Ed25519 => "ed25519",
        }
    }
}

#[derive(Clone, Serialize)]
pub struct DkimKey {
    pub domain: String,
    pub selector: String,
    pub algorithm: Algorithm,
    #[serde(skip)]
    pub private_key: String,
    /// Seals forwarded mail with ARC.
    pub arc: bool,
    pub created_at: i64,
    /// The TXT record to publish at `<selector>._domainkey.<domain>`.
    pub dns_record: String,
}

impl std::fmt::Debug for DkimKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DkimKey")
            .field("domain", &self.domain)
            .field("selector", &self.selector)
            .field("algorithm", &self.algorithm)
            .field("arc", &self.arc)
            .finish_non_exhaustive()
    }
}

impl DkimKey {
    /// The DNS name the public key goes under.
    pub fn dns_name(&self) -> String {
        format!("{}._domainkey.{}", self.selector, self.domain)
    }
}

/// Headers covered by DKIM signatures.
pub const SIGNED_HEADERS: &[&str] = &[
    "From",
    "To",
    "Subject",
    "Date",
    "Message-ID",
    "MIME-Version",
    "Content-Type",
];
/// Headers covered by ARC-Message-Signature: the DKIM set plus any
/// DKIM-Signature the forwarded message carries.
pub const ARC_SIGNED_HEADERS: &[&str] = &[
    "From",
    "To",
    "Subject",
    "Date",
    "Message-ID",
    "MIME-Version",
    "Content-Type",
    "DKIM-Signature",
];

static DATABASE: RwLock<Option<PathBuf>> = RwLock::new(None);

/// Sign and seal with the keys in `db_path`. Processes that never call this
/// leave mail unsigned.
pub fn use_database(db_path: impl Into<PathBuf>) {
    *DATABASE.write().unwrap() = Some(db_path.into());
}

pub(crate) fn database() -> Option<PathBuf> {
    DATABASE.read().unwrap().clone()
}

fn open(db_path: &Path) -> Result<Connection> {
    let conn = Connection::open(db_path)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(conn)
}

/// A new private key as PKCS#8 PEM.
pub fn generate(algorithm: Algorithm) -> Result<String> {
    match algorithm {
        Algorithm::Rsa => {
            use rsa::pkcs8::{EncodePrivateKey, LineEnding};
            let key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)
                .context("generating an RSA key")?;
            Ok(key.to_pkcs8_pem(LineEnding::LF)?.to_string())
        }
        Algorithm::Ed25519 => {
            let der = mail_auth::common::crypto::Ed25519Key::generate_pkcs8()
                .map_err(|error| anyhow!("generating an Ed25519 key: {error}"))?;
            Ok(pem("PRIVATE KEY", &der))
        }
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    let body = BASE64.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// A private key ready for signing.
pub(crate) enum SigningKey {
    Rsa(mail_auth::common::crypto::RsaKey<mail_auth::common::crypto::Sha256>),
    Ed25519(mail_auth::common::crypto::Ed25519Key),
}

/// Parse a PEM private key: Ed25519 (PKCS#8) or RSA (PKCS#1 or PKCS#8).
pub(crate) fn parse_key(pem: &str) -> Result<SigningKey> {
    use mail_auth::common::crypto::{Ed25519Key, RsaKey};
    use rustls_pki_types::pem::PemObject;
    let der = rustls_pki_types::PrivateKeyDer::from_pem_slice(pem.as_bytes())
        .context("parsing the private key PEM")?;
    if let rustls_pki_types::PrivateKeyDer::Pkcs8(pkcs8) = &der
        && let Ok(key) = Ed25519Key::from_pkcs8_der(pkcs8.secret_pkcs8_der())
    {
        return Ok(SigningKey::Ed25519(key));
    }
    RsaKey::from_key_der(der)
        .map(SigningKey::Rsa)
        .map_err(|error| anyhow!("not an RSA or Ed25519 private key ({error})"))
}

/// The `v=DKIM1` TXT record for a PEM private key.
pub fn dns_record(pem: &str) -> Result<String> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
    match parse_key(pem)? {
        SigningKey::Ed25519(key) => Ok(format!(
            "v=DKIM1; k=ed25519; p={}",
            BASE64.encode(key.public_key())
        )),
        SigningKey::Rsa(_) => {
            let key = rsa::RsaPrivateKey::from_pkcs8_pem(pem)
                .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(pem))
                .context("reading the RSA key")?;
            let spki = key.to_public_key().to_public_key_der()?;
            Ok(format!(
                "v=DKIM1; k=rsa; p={}",
                BASE64.encode(spki.as_bytes())
            ))
        }
    }
}

fn validate_selector(selector: &str) -> Result<()> {
    let valid = !selector.is_empty()
        && selector.len() <= 63
        && selector.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        });
    if !valid {
        bail!("invalid DKIM selector {selector:?}");
    }
    Ok(())
}

fn row_to_key(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<(String, String, String, String, bool, i64)> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

fn into_key(
    (domain, selector, algorithm, private_key, arc, created_at): (
        String,
        String,
        String,
        String,
        bool,
        i64,
    ),
) -> Result<DkimKey> {
    Ok(DkimKey {
        dns_record: dns_record(&private_key)
            .with_context(|| format!("DKIM key {selector}._domainkey.{domain}"))?,
        algorithm: Algorithm::parse(&algorithm)?,
        domain,
        selector,
        private_key,
        arc,
        created_at,
    })
}

const COLUMNS: &str = "domain, selector, algorithm, private_key, arc, created_at";

/// Store a key for `domain`/`selector`: `pem` when given, otherwise a newly
/// generated `algorithm` key.
pub fn add_key(
    db_path: &Path,
    domain: &str,
    selector: &str,
    algorithm: Algorithm,
    pem: Option<&str>,
) -> Result<DkimKey> {
    let domain = crate::domain::canonicalize_domain(domain.trim())?;
    let selector = selector.trim().to_ascii_lowercase();
    validate_selector(&selector)?;
    let pem = match pem {
        Some(pem) => pem.to_string(),
        None => generate(algorithm)?,
    };
    let algorithm = match parse_key(&pem)? {
        SigningKey::Rsa(_) => Algorithm::Rsa,
        SigningKey::Ed25519(_) => Algorithm::Ed25519,
    };
    let conn = open(db_path)?;
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO dkim_keys (domain, selector, algorithm, private_key, arc, created_at)
         VALUES (?1, ?2, ?3, ?4, 0, strftime('%s','now'))",
        params![domain, selector, algorithm.as_str(), pem],
    )?;
    if inserted == 0 {
        bail!("{selector}._domainkey.{domain} already has a key");
    }
    get_key(db_path, &domain, &selector)?.ok_or_else(|| anyhow!("stored key vanished"))
}

pub fn get_key(db_path: &Path, domain: &str, selector: &str) -> Result<Option<DkimKey>> {
    let conn = open(db_path)?;
    conn.query_row(
        &format!("SELECT {COLUMNS} FROM dkim_keys WHERE domain = ?1 AND selector = ?2"),
        params![domain, selector],
        row_to_key,
    )
    .optional()?
    .map(into_key)
    .transpose()
}

pub fn list_keys(db_path: &Path) -> Result<Vec<DkimKey>> {
    let conn = open(db_path)?;
    let mut statement = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM dkim_keys ORDER BY domain, selector"
    ))?;
    let rows = statement.query_map([], row_to_key)?;
    rows.map(|row| into_key(row?)).collect()
}

/// The keys that sign mail from `domain`.
pub fn keys_for_domain(db_path: &Path, domain: &str) -> Result<Vec<DkimKey>> {
    let domain = crate::domain::canonicalize_domain(domain)?;
    let conn = open(db_path)?;
    let mut statement = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM dkim_keys WHERE domain = ?1 ORDER BY selector"
    ))?;
    let rows = statement.query_map(params![domain], row_to_key)?;
    rows.map(|row| into_key(row?)).collect()
}

pub fn delete_key(db_path: &Path, domain: &str, selector: &str) -> Result<bool> {
    let conn = open(db_path)?;
    Ok(conn.execute(
        "DELETE FROM dkim_keys WHERE domain = ?1 AND selector = ?2",
        params![domain, selector],
    )? > 0)
}

/// Make `domain`/`selector` the ARC sealing key, or clear it with `None`.
/// ARC verifiers expect rsa-sha256 (RFC 8617 section 4.1.3).
pub fn set_arc_key(db_path: &Path, key: Option<(&str, &str)>) -> Result<()> {
    let mut conn = open(db_path)?;
    let tx = conn.transaction()?;
    tx.execute("UPDATE dkim_keys SET arc = 0 WHERE arc = 1", [])?;
    if let Some((domain, selector)) = key {
        let algorithm: Option<String> = tx
            .query_row(
                "SELECT algorithm FROM dkim_keys WHERE domain = ?1 AND selector = ?2",
                params![domain, selector],
                |row| row.get(0),
            )
            .optional()?;
        match algorithm.as_deref() {
            None => bail!("no key {selector}._domainkey.{domain}"),
            Some("rsa") => {}
            Some(_) => bail!("the ARC key must be RSA"),
        }
        tx.execute(
            "UPDATE dkim_keys SET arc = 1 WHERE domain = ?1 AND selector = ?2",
            params![domain, selector],
        )?;
    }
    tx.commit()?;
    Ok(())
}

pub fn arc_key(db_path: &Path) -> Result<Option<DkimKey>> {
    let conn = open(db_path)?;
    conn.query_row(
        &format!("SELECT {COLUMNS} FROM dkim_keys WHERE arc = 1"),
        [],
        row_to_key,
    )
    .optional()?
    .map(into_key)
    .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rmail.db");
        crate::db::init_db(&path).unwrap();
        (dir, path)
    }

    #[test]
    fn generated_keys_round_trip_with_dns_records() {
        let (_dir, path) = db();
        let rsa = add_key(&path, "Example.TEST", "rsa1", Algorithm::Rsa, None).unwrap();
        assert_eq!(rsa.domain, "example.test");
        assert_eq!(rsa.algorithm, Algorithm::Rsa);
        assert!(rsa.dns_record.starts_with("v=DKIM1; k=rsa; p=MII"));
        let ed = add_key(&path, "example.test", "ed1", Algorithm::Ed25519, None).unwrap();
        assert!(ed.dns_record.starts_with("v=DKIM1; k=ed25519; p="));
        // A raw 32-byte key is 44 base64 characters.
        assert_eq!(ed.dns_record.rsplit("p=").next().unwrap().len(), 44);
        assert_eq!(ed.dns_name(), "ed1._domainkey.example.test");
        assert_eq!(keys_for_domain(&path, "example.test").unwrap().len(), 2);
        assert!(add_key(&path, "example.test", "ed1", Algorithm::Ed25519, None).is_err());
        assert!(add_key(&path, "example.test", "bad selector", Algorithm::Rsa, None).is_err());
        assert!(delete_key(&path, "example.test", "ed1").unwrap());
        assert_eq!(list_keys(&path).unwrap().len(), 1);
    }

    #[test]
    fn imported_keys_take_their_algorithm_from_the_pem() {
        let (_dir, path) = db();
        let pem = generate(Algorithm::Ed25519).unwrap();
        let key = add_key(&path, "example.test", "s1", Algorithm::Rsa, Some(&pem)).unwrap();
        assert_eq!(key.algorithm, Algorithm::Ed25519);
        assert!(add_key(&path, "example.test", "s2", Algorithm::Rsa, Some("junk")).is_err());
    }

    #[test]
    fn arc_key_must_be_rsa_and_is_unique() {
        let (_dir, path) = db();
        add_key(&path, "example.test", "a", Algorithm::Rsa, None).unwrap();
        add_key(&path, "example.test", "b", Algorithm::Rsa, None).unwrap();
        add_key(&path, "example.test", "e", Algorithm::Ed25519, None).unwrap();
        assert!(set_arc_key(&path, Some(("example.test", "e"))).is_err());
        set_arc_key(&path, Some(("example.test", "a"))).unwrap();
        set_arc_key(&path, Some(("example.test", "b"))).unwrap();
        assert_eq!(arc_key(&path).unwrap().unwrap().selector, "b");
        set_arc_key(&path, None).unwrap();
        assert!(arc_key(&path).unwrap().is_none());
    }
}
