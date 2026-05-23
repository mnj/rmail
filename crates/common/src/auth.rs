//! rmail_common::auth — authentication helpers
//!
//! Provides password verification helpers used by SMTP and IMAP servers.
//!
//! Notes:
//! - Accepts PHC-style password hashes (e.g. argon2id strings produced by password-hash compatible libraries)
//! - For testing only: supports a "plain:..." prefix to store plaintext passwords (DO NOT USE IN PRODUCTION)

use anyhow::Context;
use argon2::{Argon2, PasswordVerifier};
use password_hash::PasswordHash;

/// Verify a password against a stored password hash.
///
/// Supported formats:
/// - PHC string (e.g. "$argon2id$v=19$m=...,t=...,p=...$...$...") — verified with argon2 crate
/// - "plain:secret" — direct comparison for testing only
///
/// Returns Ok(true) if the password matches, Ok(false) if it does not, or Err on malformed hashes.
pub fn verify_password(password: &str, password_hash: &str) -> anyhow::Result<bool> {
    // Shortcut for test-only plaintext hashes
    if let Some(rest) = password_hash.strip_prefix("plain:") {
        return Ok(password == rest);
    }

    // Parse PHC-format password hash and verify with Argon2
    let parsed = PasswordHash::new(password_hash).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let argon2 = Argon2::default();
    match argon2.verify_password(password.as_bytes(), &parsed) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}
