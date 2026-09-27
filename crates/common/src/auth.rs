//! rmail_common::auth — authentication helpers
//!
//! Provides password verification helpers used by SMTP and IMAP servers.
//!
//! Notes:
//! - Accepts PHC-style password hashes (e.g. argon2id strings produced by password-hash compatible libraries)
//! - Test builds only: the `insecure-plaintext-passwords` feature accepts a
//!   "plain:..." prefix for plaintext fixtures. Release builds reject it.

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
/// - "plain:secret" — only with the test-only `insecure-plaintext-passwords` feature
///
/// Returns Ok(true) if the password matches, Ok(false) if it does not, or Err on malformed hashes.
///
/// Argon2 is deliberately expensive; async callers should use
/// [`verify_password_async`] so verification does not stall the runtime.
pub fn verify_password(password: &str, password_hash: &str) -> anyhow::Result<bool> {
    if let Some(rest) = password_hash.strip_prefix("plain:") {
        if cfg!(any(test, feature = "insecure-plaintext-passwords")) {
            return Ok(crate::http::constant_time_eq(
                password.as_bytes(),
                rest.as_bytes(),
            ));
        }
        anyhow::bail!("plaintext password hashes are not accepted; reset the password");
    }

    // Parse PHC-format password hash and verify with Argon2
    let parsed = PasswordHash::new(password_hash).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let argon2 = Argon2::default();
    match argon2.verify_password(password.as_bytes(), &parsed) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify a password on the blocking thread pool.
pub async fn verify_password_async(
    password: String,
    password_hash: String,
) -> anyhow::Result<bool> {
    tokio::task::spawn_blocking(move || verify_password(&password, &password_hash))
        .await
        .map_err(|error| anyhow::anyhow!("password verification task failed: {error}"))?
}

/// Spend roughly the same time as a real verification so a missing account
/// cannot be distinguished from a wrong password by response latency.
pub async fn burn_password_verification(password: String) {
    static DUMMY_HASH: once_cell::sync::Lazy<String> = once_cell::sync::Lazy::new(|| {
        use argon2::PasswordHasher;
        let salt = password_hash::SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(b"rmail-dummy-password", &salt)
            .map(|hash| hash.to_string())
            .unwrap_or_default()
    });
    let _ = tokio::task::spawn_blocking(move || {
        let _ = verify_password(&password, &DUMMY_HASH);
    })
    .await;
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
    // A name SASLprep rejects cannot match any account.
    let Ok(user) = normalize_login_name(user) else {
        return Ok(None);
    };
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
        Ok(None) => {
            burn_password_verification(password.to_string()).await;
            return PasswordAuthResult::Rejected;
        }
        Err(message) => {
            return PasswordAuthResult::Unavailable {
                mailbox: None,
                message,
            };
        }
    };
    let Some(hash) = mailbox.password_hash.clone() else {
        burn_password_verification(password.to_string()).await;
        return PasswordAuthResult::Rejected;
    };
    match verify_password_async(password.to_string(), hash).await {
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
    /// The channel binding selected with `p=` (SCRAM-*-PLUS), if any.
    pub channel_binding: Option<ChannelBindingType>,
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

/// What the server offered, which decides the acceptable GS2
/// channel-binding flags (RFC 5802 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScramChannelBindingPolicy {
    /// Plain SCRAM and the server does not advertise SCRAM-*-PLUS in this
    /// session: `n` and `y` are accepted.
    NotOffered,
    /// Plain SCRAM while SCRAM-*-PLUS is advertised in this session: `y`
    /// ("client supports channel binding but thinks the server does not")
    /// signals a downgrade attack and fails authentication.
    OfferedButNotSelected,
    /// SCRAM-*-PLUS: `p=<type>` with a supported type is required.
    Required,
}

/// Why a client-first message was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScramClientFirstError {
    /// Syntax error or a flag not allowed for the mechanism.
    Malformed,
    /// The `y` flag while SCRAM-*-PLUS was advertised (RFC 5802 §6); an
    /// authentication failure, not a protocol error.
    ChannelBindingDowngrade,
    /// `p=` names a channel-binding type the server does not support.
    UnsupportedChannelBinding,
}

/// Parse a client-first message for the plain SCRAM mechanism
/// (`channel_binding_required == false`, SCRAM-*-PLUS not advertised) or for
/// SCRAM-*-PLUS (`true`). Servers that advertise SCRAM-*-PLUS must use
/// [`parse_scram_client_first_with_policy`] for the plain mechanism so the
/// `y` downgrade is detected.
pub fn parse_scram_client_first(
    message: &str,
    channel_binding_required: bool,
) -> Option<ScramClientFirst> {
    parse_scram_client_first_with_policy(
        message,
        if channel_binding_required {
            ScramChannelBindingPolicy::Required
        } else {
            ScramChannelBindingPolicy::NotOffered
        },
    )
    .ok()
}

pub fn parse_scram_client_first_with_policy(
    message: &str,
    policy: ScramChannelBindingPolicy,
) -> Result<ScramClientFirst, ScramClientFirstError> {
    use ScramClientFirstError::Malformed;

    let first_comma = message.find(',').ok_or(Malformed)?;
    let second_comma = message[first_comma + 1..].find(',').ok_or(Malformed)? + first_comma + 1;
    let channel_binding_flag = &message[..first_comma];
    let channel_binding = match (channel_binding_flag, policy) {
        ("n", ScramChannelBindingPolicy::Required) | ("y", ScramChannelBindingPolicy::Required) => {
            return Err(Malformed);
        }
        ("n", _) | ("y", ScramChannelBindingPolicy::NotOffered) => None,
        ("y", ScramChannelBindingPolicy::OfferedButNotSelected) => {
            return Err(ScramClientFirstError::ChannelBindingDowngrade);
        }
        (flag, ScramChannelBindingPolicy::Required) => {
            let name = flag.strip_prefix("p=").ok_or(Malformed)?;
            Some(
                ChannelBindingType::from_name(name)
                    .ok_or(ScramClientFirstError::UnsupportedChannelBinding)?,
            )
        }
        _ => return Err(Malformed),
    };
    parse_scram_client_first_rest(message, first_comma, second_comma, channel_binding)
        .ok_or(Malformed)
}

fn parse_scram_client_first_rest(
    message: &str,
    first_comma: usize,
    second_comma: usize,
    channel_binding: Option<ChannelBindingType>,
) -> Option<ScramClientFirst> {
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
        channel_binding,
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
///
/// The password is SASLprep'd first (RFC 5802 §2.2 `Normalize`), as SCRAM
/// clients do before deriving the salted password; ASCII passwords without
/// control characters are unchanged, so verifiers created before SASLprep
/// was applied stay valid. Fails if SASLprep prohibits the password, since
/// no SCRAM client could then authenticate with it.
pub fn create_scram_verifier(password: &str, iterations: u32) -> anyhow::Result<String> {
    let password = saslprep(password)
        .map_err(|error| anyhow::anyhow!("password cannot be used with SCRAM: {error}"))?;

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
    let stored_key = Sha256::digest(client_key);

    // server_key = HMAC(salted_password, "Server Key")
    let mut mac2 = <HmacSha256 as KeyInit>::new_from_slice(&salted_password)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    mac2.update(b"Server Key");
    let server_key = mac2.finalize().into_bytes();

    let obj = serde_json::json!({
        "salt": base64::engine::general_purpose::STANDARD.encode(salt),
        "iter": iterations,
        "stored_key": base64::engine::general_purpose::STANDARD.encode(stored_key),
        "server_key": base64::engine::general_purpose::STANDARD.encode(server_key)
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

/// Why a string was rejected by [`saslprep`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslprepError {
    /// The prepared string contains a character prohibited by RFC 4013 §2.3.
    ProhibitedCharacter(char),
    /// The prepared string violates the RFC 3454 §6 bidirectional rules.
    ProhibitedBidirectionalText,
}

impl std::fmt::Display for SaslprepError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProhibitedCharacter(character) => write!(
                formatter,
                "SASLprep prohibits character U+{:04X}",
                *character as u32
            ),
            Self::ProhibitedBidirectionalText => {
                formatter.write_str("SASLprep prohibits this bidirectional text")
            }
        }
    }
}

impl std::error::Error for SaslprepError {}

/// SASLprep (RFC 4013), the stringprep (RFC 3454) profile for user names
/// and passwords, with "query" semantics: unassigned code points are
/// allowed (RFC 3454 §7), so newer Unicode characters keep working.
///
/// 1. Map non-ASCII space characters (C.1.2) to U+0020 and remove the
///    characters "commonly mapped to nothing" (B.1).
/// 2. Normalize with NFKC.
/// 3. Reject the prohibited output of RFC 4013 §2.3 (C.1.2, C.2.1, C.2.2,
///    C.3, C.4, C.5, C.6, C.7, C.8, C.9).
/// 4. Apply the bidirectional checks of RFC 3454 §6.
///
/// An error means the string can never match a stored identity, so callers
/// treat it as an authentication failure.
pub fn saslprep(input: &str) -> Result<String, SaslprepError> {
    use stringprep::tables;

    if input
        .chars()
        .all(|character| character.is_ascii() && !tables::ascii_control_character(character))
    {
        return Ok(input.to_string());
    }
    let mapped = input
        .chars()
        .filter(|character| !tables::commonly_mapped_to_nothing(*character))
        .map(|character| {
            if tables::non_ascii_space_character(character) {
                ' '
            } else {
                character
            }
        });
    let normalized = mapped.nfkc().collect::<String>();
    if let Some(character) = normalized.chars().find(|character| {
        let character = *character;
        tables::non_ascii_space_character(character)
            || tables::ascii_control_character(character)
            || tables::non_ascii_control_character(character)
            || tables::private_use(character)
            || tables::non_character_code_point(character)
            || tables::surrogate_code(character)
            || tables::inappropriate_for_plain_text(character)
            || tables::inappropriate_for_canonical_representation(character)
            || tables::change_display_properties_or_deprecated(character)
            || tables::tagging_character(character)
    }) {
        return Err(SaslprepError::ProhibitedCharacter(character));
    }
    // RFC 3454 §6: a string with any RandALCat character must not contain
    // LCat characters and must start and end with a RandALCat character.
    if normalized.contains(tables::bidi_r_or_al)
        && (normalized.contains(tables::bidi_l)
            || !normalized.starts_with(tables::bidi_r_or_al)
            || !normalized.ends_with(tables::bidi_r_or_al))
    {
        return Err(SaslprepError::ProhibitedBidirectionalText);
    }
    Ok(normalized)
}

/// The SASLprep'd, lower-cased form used to look up an account.
pub fn normalize_login_name(input: &str) -> Result<String, SaslprepError> {
    saslprep(input).map(|prepared| prepared.to_ascii_lowercase())
}

/// Iteration count used for new SCRAM verifiers and for the fake
/// server-first message of unknown users.
pub const SCRAM_ITERATIONS: u32 = 4096;

/// Salt and iteration count to put in the server-first message for a user
/// who has no SCRAM verifier (unknown user, or no SCRAM credentials), so the
/// exchange looks like a real one and fails only at client-final
/// (RFC 5802 §9: prevent user enumeration).
///
/// The salt is HMAC-SHA-256(per-install secret, username) truncated to 16
/// bytes, so repeated attempts for the same name always see the same salt.
/// The secret is read from `<db_path>.scram-fake-key`, which is created
/// (mode 0600, 32 random bytes) on first use; without a database path, or
/// if the file cannot be read or created, a random per-process secret is
/// used instead. `username` should be the normalized login name.
pub fn scram_fake_verifier(db_path: Option<&str>, username: &str) -> (String, u32) {
    scram_fake_verifier_with_secret(&scram_fake_secret(db_path), username)
}

/// [`scram_fake_verifier`] with an explicit secret.
pub fn scram_fake_verifier_with_secret(secret: &[u8], username: &str) -> (String, u32) {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(secret).expect("HMAC accepts any key");
    mac.update(b"rmail SCRAM fake salt\0");
    mac.update(username.as_bytes());
    let digest = mac.finalize().into_bytes();
    (
        base64::engine::general_purpose::STANDARD.encode(&digest[..16]),
        SCRAM_ITERATIONS,
    )
}

fn scram_fake_secret(db_path: Option<&str>) -> Vec<u8> {
    use std::collections::HashMap;
    use std::sync::Mutex;

    static PROCESS_SECRET: once_cell::sync::Lazy<[u8; 32]> = once_cell::sync::Lazy::new(|| {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        secret
    });
    static INSTALL_SECRETS: once_cell::sync::Lazy<Mutex<HashMap<String, Vec<u8>>>> =
        once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

    let Some(db_path) = db_path else {
        return PROCESS_SECRET.to_vec();
    };
    let mut cache = INSTALL_SECRETS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(secret) = cache.get(db_path) {
        return secret.clone();
    }
    match load_or_create_secret(&format!("{db_path}.scram-fake-key")) {
        Ok(secret) => {
            cache.insert(db_path.to_string(), secret.clone());
            secret
        }
        Err(_) => PROCESS_SECRET.to_vec(),
    }
}

fn load_or_create_secret(path: &str) -> std::io::Result<Vec<u8>> {
    use std::io::Write;

    if let Ok(secret) = std::fs::read(path)
        && secret.len() >= 32
    {
        return Ok(secret);
    }
    let mut secret = vec![0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(&secret)?;
            file.sync_all()?;
            Ok(secret)
        }
        // Another process created it first; use theirs.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = std::fs::read(path)?;
            if existing.len() >= 32 {
                Ok(existing)
            } else {
                Err(std::io::Error::other("incomplete SCRAM fake-salt key"))
            }
        }
        Err(error) => Err(error),
    }
}

/// A SCRAM channel-binding type (RFC 5929, RFC 9266).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelBindingType {
    /// Hash of the server certificate (RFC 5929 §4).
    TlsServerEndPoint,
    /// TLS exporter "EXPORTER-Channel-Binding" (RFC 9266), TLS 1.3 only.
    TlsExporter,
}

impl ChannelBindingType {
    pub fn name(self) -> &'static str {
        match self {
            Self::TlsServerEndPoint => "tls-server-end-point",
            Self::TlsExporter => "tls-exporter",
        }
    }

    /// Channel binding names are case-sensitive.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "tls-server-end-point" => Some(Self::TlsServerEndPoint),
            "tls-exporter" => Some(Self::TlsExporter),
            _ => None,
        }
    }
}

/// RFC 9266 exporter label.
pub const TLS_EXPORTER_LABEL: &[u8] = b"EXPORTER-Channel-Binding";
/// RFC 9266 exporter output length.
pub const TLS_EXPORTER_LENGTH: usize = 32;

/// The channel-binding data of one TLS connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChannelBindings {
    /// SHA-256 of the server's leaf certificate.
    pub tls_server_end_point: Option<Vec<u8>>,
    /// RFC 9266 exporter value; only set for TLS 1.3 connections.
    pub tls_exporter: Option<Vec<u8>>,
}

impl ChannelBindings {
    /// Collect the bindings for an established TLS server connection.
    pub fn for_connection(
        server_end_point: Option<&[u8]>,
        connection: &tokio_rustls::rustls::ServerConnection,
    ) -> Self {
        Self {
            tls_server_end_point: server_end_point.map(<[u8]>::to_vec),
            tls_exporter: tls_exporter_channel_binding(connection),
        }
    }

    pub fn get(&self, binding: ChannelBindingType) -> Option<&[u8]> {
        match binding {
            ChannelBindingType::TlsServerEndPoint => self.tls_server_end_point.as_deref(),
            ChannelBindingType::TlsExporter => self.tls_exporter.as_deref(),
        }
    }

    /// Whether any channel binding can be offered (SCRAM-*-PLUS).
    pub fn is_available(&self) -> bool {
        self.tls_server_end_point.is_some() || self.tls_exporter.is_some()
    }
}

/// The RFC 9266 `tls-exporter` channel binding of a TLS 1.3 connection.
/// Returns `None` for earlier TLS versions, where RFC 9266 §3 does not
/// define it (no extended master secret guarantee).
pub fn tls_exporter_channel_binding(
    connection: &tokio_rustls::rustls::ServerConnection,
) -> Option<Vec<u8>> {
    if connection.protocol_version() != Some(tokio_rustls::rustls::ProtocolVersion::TLSv1_3) {
        return None;
    }
    let mut output = vec![0u8; TLS_EXPORTER_LENGTH];
    connection
        .export_keying_material(&mut output, TLS_EXPORTER_LABEL, Some(&[]))
        .ok()?;
    Some(output)
}

/// Verify the client-final `c=` attribute against the GS2 header of the
/// client-first message and, for SCRAM-*-PLUS, the connection's channel
/// binding data of the type the client selected.
pub fn verify_scram_channel_binding(
    client_first: &ScramClientFirst,
    bindings: &ChannelBindings,
    c_b64: &str,
) -> anyhow::Result<()> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(c_b64)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let mut expected = client_first.gs2_header.as_bytes().to_vec();
    if let Some(binding) = client_first.channel_binding {
        let data = bindings.get(binding).ok_or_else(|| {
            anyhow::anyhow!("{} channel binding is not available", binding.name())
        })?;
        expected.extend_from_slice(data);
    }
    if !crate::http::constant_time_eq(&decoded, &expected) {
        anyhow::bail!("channel binding mismatch");
    }
    Ok(())
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
        assert_eq!(saslprep("simple").unwrap(), "simple");
    }

    #[test]
    fn saslprep_follows_rfc4013_examples_and_tables() {
        // RFC 4013 §3 examples.
        assert_eq!(saslprep("I\u{00AD}X").unwrap(), "IX");
        assert_eq!(saslprep("user").unwrap(), "user");
        assert_eq!(saslprep("USER").unwrap(), "USER");
        assert_eq!(saslprep("\u{00AA}").unwrap(), "a");
        assert_eq!(saslprep("\u{2168}").unwrap(), "IX");
        assert_eq!(
            saslprep("\u{0007}"),
            Err(SaslprepError::ProhibitedCharacter('\u{0007}'))
        );
        assert_eq!(
            saslprep("\u{0627}\u{0031}"),
            Err(SaslprepError::ProhibitedBidirectionalText)
        );
        // Non-ASCII spaces map to U+0020; zero-width characters vanish.
        assert_eq!(saslprep("a\u{00A0}b\u{200B}c").unwrap(), "a bc");
        // Prohibited output: private use, non-characters, tagging.
        assert!(saslprep("a\u{E000}").is_err());
        assert!(saslprep("a\u{FFFF}").is_err());
        assert!(saslprep("a\u{E0001}").is_err());
        // Right-to-left text is fine when it is all RandALCat.
        assert!(saslprep("\u{0627}\u{0628}").is_ok());
        // Query semantics: code points unassigned in Unicode 3.2 are allowed.
        assert_eq!(saslprep("key\u{1F511}").unwrap(), "key\u{1F511}");
        assert_eq!(
            normalize_login_name("User@Example.TEST").unwrap(),
            "user@example.test"
        );
    }

    #[test]
    fn scram_verifier_applies_saslprep_and_keeps_ascii_compatible() {
        // A client derives SaltedPassword from SASLprep(password).
        let verifier = create_scram_verifier("pass\u{00A0}word\u{00AD}", 4096).unwrap();
        let (salt_b64, iterations) = parse_scram_verifier(&verifier).unwrap();
        let salt = base64::engine::general_purpose::STANDARD
            .decode(salt_b64)
            .unwrap();
        let mut salted = [0u8; 32];
        pbkdf2::<HmacSha256>(b"pass word", &salt, iterations, &mut salted);
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&salted).unwrap();
        mac.update(b"Client Key");
        let stored_key = Sha256::digest(mac.finalize().into_bytes());
        let json: serde_json::Value = serde_json::from_str(&verifier).unwrap();
        assert_eq!(
            json["stored_key"].as_str().unwrap(),
            base64::engine::general_purpose::STANDARD.encode(stored_key)
        );
        // ASCII passwords are unchanged by SASLprep, so older verifiers
        // derived from the raw password still match.
        assert_eq!(
            saslprep("correct horse battery staple").unwrap(),
            "correct horse battery staple"
        );
        assert!(create_scram_verifier("bad\u{0007}", 4096).is_err());
    }

    #[test]
    fn fake_scram_verifier_is_deterministic_per_install_and_user() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("config.db");
        let db = db.to_str().unwrap();
        let (salt, iterations) = scram_fake_verifier(Some(db), "nobody@example.test");
        assert_eq!(iterations, SCRAM_ITERATIONS);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&salt)
                .unwrap()
                .len(),
            16
        );
        assert_eq!(
            scram_fake_verifier(Some(db), "nobody@example.test"),
            (salt.clone(), iterations)
        );
        assert_ne!(scram_fake_verifier(Some(db), "other@example.test").0, salt);
        // The secret persists next to the database.
        let secret = std::fs::read(format!("{db}.scram-fake-key")).unwrap();
        assert_eq!(
            scram_fake_verifier_with_secret(&secret, "nobody@example.test").0,
            salt
        );
        assert_ne!(
            scram_fake_verifier_with_secret(b"another install", "nobody@example.test").0,
            salt
        );
    }

    #[test]
    fn scram_gs2_policy_rejects_downgrade_and_selects_binding_type() {
        use ScramChannelBindingPolicy::*;
        assert!(parse_scram_client_first_with_policy("y,,n=u,r=n", NotOffered).is_ok());
        assert_eq!(
            parse_scram_client_first_with_policy("y,,n=u,r=n", OfferedButNotSelected),
            Err(ScramClientFirstError::ChannelBindingDowngrade)
        );
        assert!(parse_scram_client_first_with_policy("n,,n=u,r=n", OfferedButNotSelected).is_ok());
        assert_eq!(
            parse_scram_client_first_with_policy("p=tls-unique,,n=u,r=n", Required),
            Err(ScramClientFirstError::UnsupportedChannelBinding)
        );
        assert_eq!(
            parse_scram_client_first_with_policy("p=tls-exporter,,n=u,r=n", Required)
                .unwrap()
                .channel_binding,
            Some(ChannelBindingType::TlsExporter)
        );
        assert_eq!(
            parse_scram_client_first_with_policy("p=tls-server-end-point,,n=u,r=n", Required)
                .unwrap()
                .channel_binding,
            Some(ChannelBindingType::TlsServerEndPoint)
        );
        assert!(parse_scram_client_first_with_policy("y,,n=u,r=n", Required).is_err());
    }

    #[test]
    fn scram_channel_binding_verification_uses_selected_type() {
        let bindings = ChannelBindings {
            tls_server_end_point: Some(vec![1, 2, 3]),
            tls_exporter: Some(vec![9; 32]),
        };
        let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        let exporter = parse_scram_client_first("p=tls-exporter,,n=u,r=n", true).unwrap();
        let mut expected = b"p=tls-exporter,,".to_vec();
        expected.extend_from_slice(&[9; 32]);
        assert!(verify_scram_channel_binding(&exporter, &bindings, &encode(&expected)).is_ok());
        let mut wrong = b"p=tls-exporter,,".to_vec();
        wrong.extend_from_slice(&[1, 2, 3]);
        assert!(verify_scram_channel_binding(&exporter, &bindings, &encode(&wrong)).is_err());
        let no_exporter = ChannelBindings {
            tls_exporter: None,
            ..bindings.clone()
        };
        assert!(verify_scram_channel_binding(&exporter, &no_exporter, &encode(&expected)).is_err());

        let plain = parse_scram_client_first("n,,n=u,r=n", false).unwrap();
        assert!(verify_scram_channel_binding(&plain, &bindings, "biws").is_ok());
        assert!(verify_scram_channel_binding(&plain, &bindings, "eSws").is_err());
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
        let stored_key = Sha256::digest(client_key);

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
