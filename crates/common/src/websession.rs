//! Signed, stateless session cookies for the admin console and webmail.
//!
//! A token is `base64(subject|expiry|binding).base64(hmac)`. The binding is a
//! short MAC over the account's current password hash, so changing the
//! password invalidates every existing session. Explicit logouts are recorded
//! in an in-memory [`RevocationList`] until the token would have expired.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn mac(key: &[u8], parts: &[&[u8]]) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    mac
}

/// Short, stable fingerprint of the credential a session is bound to.
pub fn credential_binding(key: &[u8], credential: &str) -> String {
    let tag = mac(key, &[b"binding\0", credential.as_bytes()])
        .finalize()
        .into_bytes();
    URL_SAFE_NO_PAD.encode(&tag[..12])
}

pub fn sign(key: &[u8], subject: &str, binding: &str, ttl_secs: u64) -> String {
    let payload = format!("{subject}|{}|{binding}", now_secs() + ttl_secs);
    let tag = mac(key, &[payload.as_bytes()]).finalize().into_bytes();
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(payload.as_bytes()),
        URL_SAFE_NO_PAD.encode(tag)
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSession {
    pub subject: String,
    pub binding: String,
    pub expires_at: u64,
}

/// Verify signature and expiry. The caller must still compare `binding`
/// against the account's current [`credential_binding`].
pub fn verify(key: &[u8], token: &str) -> Option<VerifiedSession> {
    let (payload64, tag64) = token.split_once('.')?;
    let payload = URL_SAFE_NO_PAD.decode(payload64).ok()?;
    let tag = URL_SAFE_NO_PAD.decode(tag64).ok()?;
    mac(key, &[&payload]).verify_slice(&tag).ok()?;
    let payload = String::from_utf8(payload).ok()?;
    let mut parts = payload.rsplitn(3, '|');
    let binding = parts.next()?.to_string();
    let expires_at = parts.next()?.parse::<u64>().ok()?;
    let subject = parts.next()?.to_string();
    (expires_at >= now_secs()).then_some(VerifiedSession {
        subject,
        binding,
        expires_at,
    })
}

/// Extract a cookie value from a `Cookie` header.
pub fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name).then_some(value)
    })
}

/// Logged-out tokens, remembered until they expire.
#[derive(Default)]
pub struct RevocationList {
    revoked: Mutex<HashMap<[u8; 32], u64>>,
}

impl RevocationList {
    pub fn revoke(&self, token: &str, expires_at: u64) {
        let now = now_secs();
        let mut revoked = self.revoked.lock().unwrap_or_else(|p| p.into_inner());
        revoked.retain(|_, expiry| *expiry >= now);
        revoked.insert(Sha256::digest(token.as_bytes()).into(), expires_at);
    }

    pub fn is_revoked(&self, token: &str) -> bool {
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        self.revoked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(&digest)
    }
}

/// Build a `Set-Cookie` value. `max_age` of zero clears the cookie.
pub fn set_cookie(name: &str, value: &str, max_age: u64, secure: bool, same_site: &str) -> String {
    format!(
        "{name}={value}; Path=/; HttpOnly; SameSite={same_site}; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tamper_detection() {
        let key = b"k".repeat(32);
        let binding = credential_binding(&key, "$argon2id$hash");
        let token = sign(&key, "user@example.test", &binding, 60);
        let session = verify(&key, &token).expect("valid");
        assert_eq!(session.subject, "user@example.test");
        assert_eq!(session.binding, binding);

        assert!(verify(b"other", &token).is_none());
        let (payload, tag) = token.split_once('.').unwrap();
        let forged = URL_SAFE_NO_PAD.encode(b"admin|99999999999|x");
        assert!(verify(&key, &format!("{forged}.{tag}")).is_none());
        assert!(verify(&key, payload).is_none());
    }

    #[test]
    fn subjects_may_contain_separators() {
        let key = b"key";
        let token = sign(key, "odd|name", "b", 60);
        assert_eq!(verify(key, &token).unwrap().subject, "odd|name");
    }

    #[test]
    fn expired_tokens_are_rejected() {
        let key = b"key";
        let payload = format!("user|{}|b", now_secs() - 1);
        let tag = mac(key, &[payload.as_bytes()]).finalize().into_bytes();
        let token = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(tag)
        );
        assert!(verify(key, &token).is_none());
    }

    #[test]
    fn binding_changes_with_credential() {
        assert_ne!(
            credential_binding(b"key", "hash-a"),
            credential_binding(b"key", "hash-b")
        );
    }

    #[test]
    fn revocation() {
        let list = RevocationList::default();
        list.revoke("t", now_secs() + 60);
        assert!(list.is_revoked("t"));
        assert!(!list.is_revoked("u"));
    }

    #[test]
    fn cookie_parsing() {
        assert_eq!(cookie_value("a=1; rmail=tok; b=2", "rmail"), Some("tok"));
        assert_eq!(cookie_value("a=1", "rmail"), None);
    }
}
