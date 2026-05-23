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

use pbkdf2::pbkdf2;
use hmac::Hmac;
use hmac::Mac;
use hmac::digest::KeyInit;
use sha2::{Sha256, Digest};
use base64;
use rand::rngs::OsRng;
use rand::RngCore;
use unicode_normalization::UnicodeNormalization;

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

type HmacSha256 = Hmac<Sha256>;

/// Create a SCRAM-SHA-256 verifier for a plaintext password.
/// Returns a JSON string containing base64(salt), iterations, base64(stored_key), base64(server_key).
pub fn create_scram_verifier(password: &str, iterations: u32) -> anyhow::Result<String> {
    // Generate a random salt
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    // Derive salted_password using PBKDF2-HMAC-SHA256
    let mut salted_password = [0u8; 32];
    pbkdf2::<HmacSha256>(password.as_bytes(), &salt, iterations, &mut salted_password);

    // client_key = HMAC(salted_password, "Client Key")
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&salted_password).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    mac.update(b"Client Key");
    let client_key = mac.finalize().into_bytes();

    // stored_key = H(client_key)
    let stored_key = Sha256::digest(&client_key);

    // server_key = HMAC(salted_password, "Server Key")
    let mut mac2 = <HmacSha256 as KeyInit>::new_from_slice(&salted_password).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    mac2.update(b"Server Key");
    let server_key = mac2.finalize().into_bytes();

    let obj = serde_json::json!({
        "salt": base64::encode(&salt),
        "iter": iterations,
        "stored_key": base64::encode(&stored_key),
        "server_key": base64::encode(&server_key)
    });
    Ok(serde_json::to_string(&obj)?)
}

/// Parse a stored SCRAM verifier JSON and return (salt_base64, iterations)
pub fn parse_scram_verifier(stored_verifier_json: &str) -> anyhow::Result<(String, u32)> {
    let v: serde_json::Value = serde_json::from_str(stored_verifier_json).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let salt = v.get("salt").and_then(|s| s.as_str()).ok_or_else(|| anyhow::anyhow!("missing salt"))?.to_string();
    let iter = v.get("iter").and_then(|i| i.as_u64()).ok_or_else(|| anyhow::anyhow!("missing iter"))? as u32;
    Ok((salt, iter))
}

/// Verify a SCRAM client proof using a stored verifier JSON and the computed auth message.
/// Returns server_signature bytes on success.
pub fn verify_scram_proof(stored_verifier_json: &str, auth_message: &str, client_proof_b64: &str) -> anyhow::Result<Vec<u8>> {
    let v: serde_json::Value = serde_json::from_str(stored_verifier_json).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let stored_key_b64 = v.get("stored_key").and_then(|s| s.as_str()).ok_or_else(|| anyhow::anyhow!("missing stored_key in verifier"))?;
    let server_key_b64 = v.get("server_key").and_then(|s| s.as_str()).ok_or_else(|| anyhow::anyhow!("missing server_key in verifier"))?;

    let stored_key = base64::decode(stored_key_b64).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let server_key = base64::decode(server_key_b64).map_err(|e| anyhow::anyhow!(e.to_string()))?;

    // client_signature = HMAC(stored_key, auth_message)
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&stored_key).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    mac.update(auth_message.as_bytes());
    let client_signature = mac.finalize().into_bytes();

    let client_proof = base64::decode(client_proof_b64).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    if client_proof.len() != client_signature.len() {
        return Err(anyhow::anyhow!("invalid client proof length"));
    }

    // client_key = client_proof XOR client_signature
    let client_key: Vec<u8> = client_proof.iter().zip(client_signature.iter()).map(|(a,b)| a ^ b).collect();

    // stored_key_check = H(client_key)
    let stored_key_check = Sha256::digest(&client_key);

    if stored_key_check.as_slice() != stored_key.as_slice() {
        return Err(anyhow::anyhow!("invalid SCRAM proof"));
    }

    // server_signature = HMAC(server_key, auth_message)
    let mut mac2 = <HmacSha256 as KeyInit>::new_from_slice(&server_key).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    mac2.update(auth_message.as_bytes());
    let server_signature = mac2.finalize().into_bytes();
    Ok(server_signature.to_vec())
}

/// Minimal SASLprep-like username normalization used for SCRAM username handling.
///
/// NOTE: This implementation applies Unicode NFKC normalization which covers the most
/// common interoperability cases. Full SASLprep (stringprep) requires handling mapping
/// tables and prohibited characters; consider using a dedicated crate for production.
pub fn saslprep(input: &str) -> String {
    input.nfkc().collect::<String>()
}

/// Verify the tls-server-end-point channel binding value sent by the client (c=).
/// The client sends base64(gs2_header || channel_binding_data). For tls-server-end-point
/// channel binding data is the certificate fingerprint (SHA-256 of the DER bytes). This
/// function returns Ok(()) if the provided c_b64 matches the expected value.
pub fn verify_tls_server_end_point_binding(gs2_header: &str, server_end_point: &[u8], c_b64: &str) -> anyhow::Result<()> {
    let decoded = base64::decode(c_b64).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let gh = gs2_header.as_bytes();
    if decoded.len() != gh.len() + server_end_point.len() {
        return Err(anyhow::anyhow!("channel-binding length mismatch"));
    }
    if &decoded[..gh.len()] != gh {
        return Err(anyhow::anyhow!("gs2 header mismatch in channel binding"));
    }
    if &decoded[gh.len()..] != server_end_point {
        return Err(anyhow::anyhow!("server_end_point mismatch in channel binding"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64;
    use pbkdf2::pbkdf2;
    use hmac::Hmac;
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    #[test]
    fn test_saslprep_basic() {
        // basic ASCII input should be unchanged
        assert_eq!(saslprep("simple"), "simple");
    }

    #[test]
    fn test_scram_roundtrip() {
        let password = "correct horse battery staple";
        let iterations = 4096u32;
        let verifier_json = create_scram_verifier(password, iterations).expect("create verifier");
        let (salt_b64, iter) = parse_scram_verifier(&verifier_json).expect("parse verifier");
        assert_eq!(iter, iterations);
        let salt = base64::decode(&salt_b64).expect("decode salt");

        // derive salted_password using PBKDF2-HMAC-SHA256 (must match create_scram_verifier)
        let mut salted_password = [0u8; 32];
        pbkdf2::<HmacSha256>(password.as_bytes(), &salt, iter, &mut salted_password);

        // client_key = HMAC(salted_password, "Client Key")
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&salted_password).unwrap();
        mac.update(b"Client Key");
        let client_key = mac.finalize().into_bytes();

        // stored_key = H(client_key)
        let stored_key = Sha256::digest(&client_key);

        // server_key = HMAC(salted_password, "Server Key")
        let mut mac2 = <HmacSha256 as KeyInit>::new_from_slice(&salted_password).unwrap();
        mac2.update(b"Server Key");
        let server_key = mac2.finalize().into_bytes();

        // Construct a sample auth_message (client-first-bare,server-first,client-final-without-proof)
        let auth_message = "n=user,r=clientnonce,server-first,n=client-final";

        // client_signature = HMAC(stored_key, auth_message)
        let mut mac3 = <HmacSha256 as KeyInit>::new_from_slice(&stored_key).unwrap();
        mac3.update(auth_message.as_bytes());
        let client_signature = mac3.finalize().into_bytes();

        // client_proof = client_key XOR client_signature
        let client_proof: Vec<u8> = client_key.iter().zip(client_signature.iter()).map(|(a,b)| a ^ b).collect();
        let client_proof_b64 = base64::encode(&client_proof);

        // Verify using the library call
        let server_sig = verify_scram_proof(&verifier_json, auth_message, &client_proof_b64).expect("verify");

        // Expected server_signature = HMAC(server_key, auth_message)
        let mut mac4 = <HmacSha256 as KeyInit>::new_from_slice(&server_key).unwrap();
        mac4.update(auth_message.as_bytes());
        let expected = mac4.finalize().into_bytes();
        assert_eq!(server_sig, expected.as_slice());
    }

    #[test]
    fn test_verify_tls_server_end_point_binding_ok() {
        let gs2 = "p=tls-server-end-point,,";
        let server_ep = vec![1u8,2u8,3u8,4u8,5u8];
        let mut combined = gs2.as_bytes().to_vec();
        combined.extend_from_slice(&server_ep);
        let c_b64 = base64::encode(&combined);
        assert!(verify_tls_server_end_point_binding(gs2, &server_ep, &c_b64).is_ok());
    }

    #[test]
    fn test_verify_tls_server_end_point_binding_fail() {
        let gs2 = "p=tls-server-end-point,,";
        let server_ep = vec![1u8,2u8,3u8,4u8,5u8];
        let mut combined = gs2.as_bytes().to_vec();
        combined.extend_from_slice(&[9u8,9u8,9u8]);
        let c_b64 = base64::encode(&combined);
        assert!(verify_tls_server_end_point_binding(gs2, &server_ep, &c_b64).is_err());
    }
}
