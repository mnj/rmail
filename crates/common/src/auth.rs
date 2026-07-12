//! rmail_common::auth — authentication helpers
//!
//! Provides password verification helpers used by SMTP and IMAP servers.
//!
//! Notes:
//! - Accepts PHC-style password hashes (e.g. argon2id strings produced by password-hash compatible libraries)
//! - For testing only: supports a "plain:..." prefix to store plaintext passwords (DO NOT USE IN PRODUCTION)

use argon2::{Argon2, PasswordVerifier};
use base64::Engine;
use password_hash::PasswordHash;

use crate::db::Mailbox;
use hmac::Hmac;
use hmac::Mac;
use hmac::digest::KeyInit;
use pbkdf2::pbkdf2;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
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

pub enum PasswordAuthResult {
    Success(Mailbox),
    Rejected,
    Unavailable {
        mailbox: Option<Mailbox>,
        message: String,
    },
}

pub async fn lookup_mailbox(
    db_path: Option<&String>,
    user: &str,
) -> Result<Option<Mailbox>, String> {
    let Some(db_path) = db_path else {
        return Err("authentication database is not configured".to_string());
    };
    let user = saslprep(user).to_ascii_lowercase();
    let db_path = db_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        if user.contains('@') {
            crate::db::get_mailbox(db_path, &user)
        } else {
            crate::db::find_mailbox_by_localpart(db_path, &user)
        }
    })
    .await;
    match result {
        Ok(Ok(mailbox)) => Ok(mailbox),
        Ok(Err(error)) => Err(error.to_string()),
        Err(error) => Err(error.to_string()),
    }
}

pub async fn authenticate_password(
    db_path: Option<&String>,
    user: &str,
    password: &str,
) -> PasswordAuthResult {
    let mailbox = match lookup_mailbox(db_path, user).await {
        Ok(Some(mailbox)) => mailbox,
        Ok(None) => return PasswordAuthResult::Rejected,
        Err(message) => {
            return PasswordAuthResult::Unavailable {
                mailbox: None,
                message,
            };
        }
    };
    let Some(hash) = mailbox.password_hash.as_ref() else {
        return PasswordAuthResult::Rejected;
    };
    match verify_password(password, hash) {
        Ok(true) => PasswordAuthResult::Success(mailbox),
        Ok(false) => PasswordAuthResult::Rejected,
        Err(error) => PasswordAuthResult::Unavailable {
            mailbox: Some(mailbox),
            message: error.to_string(),
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaslCredentials {
    pub authcid: String,
    pub authzid: Option<String>,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordSaslProgress {
    Challenge(&'static str),
    Credentials(SaslCredentials),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslExchangeError {
    InvalidResponse,
    UnexpectedResponse,
}

pub trait PasswordSaslExchange: Send {
    fn start(&mut self, initial: Option<&str>) -> Result<PasswordSaslProgress, SaslExchangeError>;
    fn receive(&mut self, response: &str) -> Result<PasswordSaslProgress, SaslExchangeError>;
}

fn decode_sasl_text(response: &str) -> Option<String> {
    if response == "=" {
        return Some(String::new());
    }
    String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(response)
            .ok()?,
    )
    .ok()
}

fn plain_credentials(response: &str) -> Option<SaslCredentials> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(response)
        .ok()?;
    let mut parts = decoded.split(|byte| *byte == 0);
    let authzid = parts.next()?;
    let authcid = parts.next()?;
    let password = parts.next()?;
    if parts.next().is_some() || authcid.is_empty() {
        return None;
    }
    Some(SaslCredentials {
        authcid: String::from_utf8(authcid.to_vec()).ok()?,
        authzid: if authzid.is_empty() {
            None
        } else {
            Some(String::from_utf8(authzid.to_vec()).ok()?)
        },
        password: String::from_utf8(password.to_vec()).ok()?,
    })
}

#[derive(Default)]
pub struct PlainExchange {
    waiting: bool,
}

impl PasswordSaslExchange for PlainExchange {
    fn start(&mut self, initial: Option<&str>) -> Result<PasswordSaslProgress, SaslExchangeError> {
        if self.waiting {
            return Err(SaslExchangeError::UnexpectedResponse);
        }
        match initial {
            Some(response) => plain_credentials(response)
                .map(PasswordSaslProgress::Credentials)
                .ok_or(SaslExchangeError::InvalidResponse),
            None => {
                self.waiting = true;
                Ok(PasswordSaslProgress::Challenge(""))
            }
        }
    }

    fn receive(&mut self, response: &str) -> Result<PasswordSaslProgress, SaslExchangeError> {
        if !self.waiting {
            return Err(SaslExchangeError::UnexpectedResponse);
        }
        self.waiting = false;
        plain_credentials(response)
            .map(PasswordSaslProgress::Credentials)
            .ok_or(SaslExchangeError::InvalidResponse)
    }
}

#[derive(Default)]
pub struct LoginExchange {
    state: LoginState,
    username: Option<String>,
}

#[derive(Default)]
enum LoginState {
    #[default]
    New,
    Username,
    Password,
    Complete,
}

impl PasswordSaslExchange for LoginExchange {
    fn start(&mut self, initial: Option<&str>) -> Result<PasswordSaslProgress, SaslExchangeError> {
        if !matches!(self.state, LoginState::New) {
            return Err(SaslExchangeError::UnexpectedResponse);
        }
        match initial {
            Some(response) => {
                self.username =
                    Some(decode_sasl_text(response).ok_or(SaslExchangeError::InvalidResponse)?);
                self.state = LoginState::Password;
                Ok(PasswordSaslProgress::Challenge("UGFzc3dvcmQ6"))
            }
            None => {
                self.state = LoginState::Username;
                Ok(PasswordSaslProgress::Challenge("VXNlcm5hbWU6"))
            }
        }
    }

    fn receive(&mut self, response: &str) -> Result<PasswordSaslProgress, SaslExchangeError> {
        match self.state {
            LoginState::Username => {
                self.username =
                    Some(decode_sasl_text(response).ok_or(SaslExchangeError::InvalidResponse)?);
                self.state = LoginState::Password;
                Ok(PasswordSaslProgress::Challenge("UGFzc3dvcmQ6"))
            }
            LoginState::Password => {
                let password =
                    decode_sasl_text(response).ok_or(SaslExchangeError::InvalidResponse)?;
                self.state = LoginState::Complete;
                Ok(PasswordSaslProgress::Credentials(SaslCredentials {
                    authcid: self
                        .username
                        .take()
                        .ok_or(SaslExchangeError::UnexpectedResponse)?,
                    authzid: None,
                    password,
                }))
            }
            LoginState::New | LoginState::Complete => Err(SaslExchangeError::UnexpectedResponse),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScramClientFirst {
    pub username: String,
    pub authzid: Option<String>,
    pub nonce: String,
    pub bare: String,
    pub gs2_header: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScramClientFinal {
    pub without_proof: String,
    pub proof: String,
    pub channel_binding: String,
    pub nonce: String,
}

fn decode_scram_name(value: &str) -> Option<String> {
    let mut decoded = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character != '=' {
            decoded.push(character);
            continue;
        }
        match (characters.next(), characters.next()) {
            (Some('2'), Some('C')) => decoded.push(','),
            (Some('3'), Some('D')) => decoded.push('='),
            _ => return None,
        }
    }
    Some(decoded)
}

fn parse_scram_attributes(message: &str) -> Option<Vec<(&str, &str)>> {
    let mut attributes = Vec::new();
    for part in message.split(',') {
        let (name, value) = part.split_once('=')?;
        if name.len() != 1 || name == "m" || attributes.iter().any(|(seen, _)| *seen == name) {
            return None;
        }
        attributes.push((name, value));
    }
    Some(attributes)
}

pub fn parse_scram_client_first(
    message: &str,
    channel_binding_required: bool,
) -> Option<ScramClientFirst> {
    let first_comma = message.find(',')?;
    let second_comma = message[first_comma + 1..].find(',')? + first_comma + 1;
    let channel_binding_flag = &message[..first_comma];
    if channel_binding_required {
        if channel_binding_flag != "p=tls-server-end-point" {
            return None;
        }
    } else if channel_binding_flag != "n" && channel_binding_flag != "y" {
        return None;
    }
    let authzid_field = &message[first_comma + 1..second_comma];
    let authzid = if authzid_field.is_empty() {
        None
    } else {
        Some(decode_scram_name(authzid_field.strip_prefix("a=")?)?)
    };
    let gs2_header = message[..=second_comma].to_string();
    let bare = message[second_comma + 1..].to_string();
    let attributes = parse_scram_attributes(&bare)?;
    let username = decode_scram_name(attributes.iter().find(|(name, _)| *name == "n")?.1)?;
    let nonce = attributes
        .iter()
        .find(|(name, _)| *name == "r")?
        .1
        .to_string();
    if username.is_empty()
        || nonce.is_empty()
        || !nonce
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte) && byte != b',')
    {
        return None;
    }
    Some(ScramClientFirst {
        username,
        authzid,
        nonce,
        bare,
        gs2_header,
    })
}

pub fn parse_scram_client_final(message: &str) -> Option<ScramClientFinal> {
    let attributes = parse_scram_attributes(message)?;
    if attributes.last().map(|(name, _)| *name) != Some("p") {
        return None;
    }
    let proof = attributes.iter().find(|(name, _)| *name == "p")?.1;
    let channel_binding = attributes.iter().find(|(name, _)| *name == "c")?.1;
    let nonce = attributes.iter().find(|(name, _)| *name == "r")?.1;
    if proof.is_empty() || channel_binding.is_empty() || nonce.is_empty() {
        return None;
    }
    let proof_marker = message.rfind(",p=")?;
    Some(ScramClientFinal {
        without_proof: message[..proof_marker].to_string(),
        proof: proof.to_string(),
        channel_binding: channel_binding.to_string(),
        nonce: nonce.to_string(),
    })
}

pub fn generate_scram_nonce() -> String {
    let mut bytes = [0u8; 18];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
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
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&salted_password)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    mac.update(b"Client Key");
    let client_key = mac.finalize().into_bytes();

    // stored_key = H(client_key)
    let stored_key = Sha256::digest(&client_key);

    // server_key = HMAC(salted_password, "Server Key")
    let mut mac2 = <HmacSha256 as KeyInit>::new_from_slice(&salted_password)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    mac2.update(b"Server Key");
    let server_key = mac2.finalize().into_bytes();

    let obj = serde_json::json!({
        "salt": base64::engine::general_purpose::STANDARD.encode(&salt),
        "iter": iterations,
        "stored_key": base64::engine::general_purpose::STANDARD.encode(&stored_key),
        "server_key": base64::engine::general_purpose::STANDARD.encode(&server_key)
    });
    Ok(serde_json::to_string(&obj)?)
}

/// Parse a stored SCRAM verifier JSON and return (salt_base64, iterations)
pub fn parse_scram_verifier(stored_verifier_json: &str) -> anyhow::Result<(String, u32)> {
    let v: serde_json::Value =
        serde_json::from_str(stored_verifier_json).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let salt = v
        .get("salt")
        .and_then(|s| s.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing salt"))?
        .to_string();
    let iter = v
        .get("iter")
        .and_then(|i| i.as_u64())
        .ok_or_else(|| anyhow::anyhow!("missing iter"))? as u32;
    Ok((salt, iter))
}

/// Verify a SCRAM client proof using a stored verifier JSON and the computed auth message.
/// Returns server_signature bytes on success.
pub fn verify_scram_proof(
    stored_verifier_json: &str,
    auth_message: &str,
    client_proof_b64: &str,
) -> anyhow::Result<Vec<u8>> {
    let v: serde_json::Value =
        serde_json::from_str(stored_verifier_json).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let stored_key_b64 = v
        .get("stored_key")
        .and_then(|s| s.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing stored_key in verifier"))?;
    let server_key_b64 = v
        .get("server_key")
        .and_then(|s| s.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing server_key in verifier"))?;

    let stored_key = base64::engine::general_purpose::STANDARD
        .decode(stored_key_b64)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let server_key = base64::engine::general_purpose::STANDARD
        .decode(server_key_b64)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    // client_signature = HMAC(stored_key, auth_message)
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&stored_key)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    mac.update(auth_message.as_bytes());
    let client_signature = mac.finalize().into_bytes();

    let client_proof = base64::engine::general_purpose::STANDARD
        .decode(client_proof_b64)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    if client_proof.len() != client_signature.len() {
        return Err(anyhow::anyhow!("invalid client proof length"));
    }

    // client_key = client_proof XOR client_signature
    let client_key: Vec<u8> = client_proof
        .iter()
        .zip(client_signature.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    // stored_key_check = H(client_key)
    let stored_key_check = Sha256::digest(&client_key);

    if stored_key_check.as_slice() != stored_key.as_slice() {
        return Err(anyhow::anyhow!("invalid SCRAM proof"));
    }

    // server_signature = HMAC(server_key, auth_message)
    let mut mac2 = <HmacSha256 as KeyInit>::new_from_slice(&server_key)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
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
pub fn verify_tls_server_end_point_binding(
    gs2_header: &str,
    server_end_point: &[u8],
    c_b64: &str,
) -> anyhow::Result<()> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(c_b64)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let gh = gs2_header.as_bytes();
    if decoded.len() != gh.len() + server_end_point.len() {
        return Err(anyhow::anyhow!("channel-binding length mismatch"));
    }
    if &decoded[..gh.len()] != gh {
        return Err(anyhow::anyhow!("gs2 header mismatch in channel binding"));
    }
    if &decoded[gh.len()..] != server_end_point {
        return Err(anyhow::anyhow!(
            "server_end_point mismatch in channel binding"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64;
    use hmac::Hmac;
    use pbkdf2::pbkdf2;
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    #[test]
    fn test_saslprep_basic() {
        // basic ASCII input should be unchanged
        assert_eq!(saslprep("simple"), "simple");
    }

    #[test]
    fn password_sasl_exchanges_enforce_strict_state_and_utf8() {
        let plain_wire =
            base64::engine::general_purpose::STANDARD.encode(b"\0user@example.test\0password");
        let mut plain = PlainExchange::default();
        assert_eq!(
            plain.start(Some(&plain_wire)).unwrap(),
            PasswordSaslProgress::Credentials(SaslCredentials {
                authcid: "user@example.test".to_string(),
                authzid: None,
                password: "password".to_string(),
            })
        );
        assert!(plain.receive(&plain_wire).is_err());

        let mut login = LoginExchange::default();
        assert_eq!(
            login.start(None).unwrap(),
            PasswordSaslProgress::Challenge("VXNlcm5hbWU6")
        );
        assert_eq!(
            login.receive("dXNlckBleGFtcGxlLnRlc3Q=").unwrap(),
            PasswordSaslProgress::Challenge("UGFzc3dvcmQ6")
        );
        assert!(matches!(
            login.receive("cGFzc3dvcmQ=").unwrap(),
            PasswordSaslProgress::Credentials(_)
        ));
        assert!(login.receive("cGFzc3dvcmQ=").is_err());
        assert!(LoginExchange::default().start(Some("/w==")).is_err());
    }

    #[test]
    fn scram_wire_parser_rejects_downgrade_duplicates_and_bad_proof_order() {
        let first = parse_scram_client_first("n,,n=user=2Cname,r=nonce", false).unwrap();
        assert_eq!(first.username, "user,name");
        assert_eq!(first.gs2_header, "n,,");
        assert!(parse_scram_client_first("p=tls-server-end-point,,n=user,r=n", false).is_none());
        assert!(parse_scram_client_first("n,,n=user,n=again,r=n", false).is_none());
        assert!(parse_scram_client_first("n,,m=reserved,n=user,r=n", false).is_none());

        let final_message = parse_scram_client_final("c=biws,r=nonce,p=cHJvb2Y=").unwrap();
        assert_eq!(final_message.without_proof, "c=biws,r=nonce");
        assert!(parse_scram_client_final("c=biws,r=n,p=x,x=late").is_none());
        assert!(parse_scram_client_final("c=biws,r=n,r=again,p=x").is_none());
    }

    #[test]
    fn test_scram_roundtrip() {
        let password = "correct horse battery staple";
        let iterations = 4096u32;
        let verifier_json = create_scram_verifier(password, iterations).expect("create verifier");
        let (salt_b64, iter) = parse_scram_verifier(&verifier_json).expect("parse verifier");
        assert_eq!(iter, iterations);
        let salt = base64::engine::general_purpose::STANDARD
            .decode(&salt_b64)
            .expect("decode salt");

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
        let client_proof: Vec<u8> = client_key
            .iter()
            .zip(client_signature.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        let client_proof_b64 = base64::engine::general_purpose::STANDARD.encode(&client_proof);

        // Verify using the library call
        let server_sig =
            verify_scram_proof(&verifier_json, auth_message, &client_proof_b64).expect("verify");

        // Expected server_signature = HMAC(server_key, auth_message)
        let mut mac4 = <HmacSha256 as KeyInit>::new_from_slice(&server_key).unwrap();
        mac4.update(auth_message.as_bytes());
        let expected = mac4.finalize().into_bytes();
        assert_eq!(server_sig, expected.as_slice());
    }

    #[test]
    fn test_verify_tls_server_end_point_binding_ok() {
        let gs2 = "p=tls-server-end-point,,";
        let server_ep = vec![1u8, 2u8, 3u8, 4u8, 5u8];
        let mut combined = gs2.as_bytes().to_vec();
        combined.extend_from_slice(&server_ep);
        let c_b64 = base64::engine::general_purpose::STANDARD.encode(&combined);
        assert!(verify_tls_server_end_point_binding(gs2, &server_ep, &c_b64).is_ok());
    }

    #[test]
    fn test_verify_tls_server_end_point_binding_fail() {
        let gs2 = "p=tls-server-end-point,,";
        let server_ep = vec![1u8, 2u8, 3u8, 4u8, 5u8];
        let mut combined = gs2.as_bytes().to_vec();
        combined.extend_from_slice(&[9u8, 9u8, 9u8]);
        let c_b64 = base64::engine::general_purpose::STANDARD.encode(&combined);
        assert!(verify_tls_server_end_point_binding(gs2, &server_ep, &c_b64).is_err());
    }
}
