use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use once_cell::sync::Lazy;
use rand::RngCore;
use rmail_common::db::Mailbox;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SaslSecurity {
    PlaintextPassword,
    ChallengeResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SaslMechanism {
    pub(crate) name: &'static str,
    pub(crate) capability: &'static str,
    pub(crate) security: SaslSecurity,
    pub(crate) channel_binding_required: bool,
}

const SASL_MECHANISMS: &[SaslMechanism] = &[
    SaslMechanism {
        name: "PLAIN",
        capability: "AUTH=PLAIN",
        security: SaslSecurity::PlaintextPassword,
        channel_binding_required: false,
    },
    SaslMechanism {
        name: "LOGIN",
        capability: "AUTH=LOGIN",
        security: SaslSecurity::PlaintextPassword,
        channel_binding_required: false,
    },
    SaslMechanism {
        name: "SCRAM-SHA-256",
        capability: "AUTH=SCRAM-SHA-256",
        security: SaslSecurity::ChallengeResponse,
        channel_binding_required: false,
    },
    SaslMechanism {
        name: "SCRAM-SHA-256-PLUS",
        capability: "AUTH=SCRAM-SHA-256-PLUS",
        security: SaslSecurity::ChallengeResponse,
        channel_binding_required: true,
    },
];

#[derive(Debug, Clone)]
pub(crate) struct AuthPolicy {
    mechanisms: Vec<SaslMechanism>,
}

impl Default for AuthPolicy {
    fn default() -> Self {
        Self {
            mechanisms: SASL_MECHANISMS.to_vec(),
        }
    }
}

impl AuthPolicy {
    pub(crate) fn from_names(names: &[String]) -> anyhow::Result<Self> {
        if names.is_empty() {
            anyhow::bail!("security.imap_sasl_mechanisms must not be empty");
        }
        let mut mechanisms = Vec::with_capacity(names.len());
        for name in names {
            let mechanism = sasl_mechanism(name)
                .ok_or_else(|| anyhow::anyhow!("unsupported IMAP SASL mechanism {name:?}"))?;
            if mechanisms
                .iter()
                .any(|configured: &SaslMechanism| configured.name == mechanism.name)
            {
                anyhow::bail!("duplicate IMAP SASL mechanism {:?}", mechanism.name);
            }
            mechanisms.push(mechanism);
        }
        Ok(Self { mechanisms })
    }

    pub(crate) fn mechanism(&self, name: &str) -> Option<SaslMechanism> {
        self.mechanisms
            .iter()
            .copied()
            .find(|mechanism| mechanism.name.eq_ignore_ascii_case(name))
    }

    pub(crate) fn advertised_mechanisms(
        &self,
        encrypted: bool,
        channel_binding_available: bool,
    ) -> impl Iterator<Item = SaslMechanism> + '_ {
        self.mechanisms.iter().filter_map(move |mechanism| {
            ((encrypted || mechanism.security != SaslSecurity::PlaintextPassword)
                && (!mechanism.channel_binding_required || channel_binding_available))
                .then_some(*mechanism)
        })
    }
}

pub(crate) fn sasl_mechanism(name: &str) -> Option<SaslMechanism> {
    SASL_MECHANISMS
        .iter()
        .copied()
        .find(|mechanism| mechanism.name.eq_ignore_ascii_case(name))
}

#[derive(Clone)]
struct AuthFailInfo {
    count: u32,
    first: Instant,
    locked_until: Option<Instant>,
}

static AUTH_FAILS: Lazy<Mutex<HashMap<IpAddr, AuthFailInfo>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub(crate) fn auth_block_remaining(ip: IpAddr) -> Option<Duration> {
    let m = AUTH_FAILS.lock().unwrap();
    if let Some(info) = m.get(&ip) {
        if let Some(until) = info.locked_until {
            let now = Instant::now();
            if until > now {
                return Some(until - now);
            }
        }
    }
    None
}

pub(crate) fn record_auth_failure(ip: IpAddr) {
    let mut m = AUTH_FAILS.lock().unwrap();
    let now = Instant::now();
    let entry = m.entry(ip).or_insert(AuthFailInfo {
        count: 0,
        first: now,
        locked_until: None,
    });
    entry.count = entry.count.saturating_add(1);
    rmail_common::metrics::inc_auth_failures();
    if entry.count >= 5 {
        entry.locked_until = Some(now + Duration::from_secs(30 * 60));
        entry.count = 0;
        entry.first = now;
    }
}

pub(crate) fn reset_auth_failures(ip: IpAddr) {
    let mut m = AUTH_FAILS.lock().unwrap();
    m.remove(&ip);
}

pub(crate) enum PasswordAuthResult {
    Success(Mailbox),
    Rejected,
    Unavailable {
        mailbox: Option<Mailbox>,
        message: String,
    },
}

async fn lookup_mailbox(db_path: Option<&String>, user: &str) -> Result<Option<Mailbox>, String> {
    let Some(db_path) = db_path else {
        return Err("authentication database is not configured".to_string());
    };
    let user = rmail_common::auth::saslprep(user).to_ascii_lowercase();
    let db_path = db_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        if user.contains('@') {
            rmail_common::db::get_mailbox(db_path, &user)
        } else {
            rmail_common::db::find_mailbox_by_localpart(db_path, &user)
        }
    })
    .await;
    match result {
        Ok(Ok(mailbox)) => Ok(mailbox),
        Ok(Err(error)) => Err(error.to_string()),
        Err(error) => Err(error.to_string()),
    }
}

pub(crate) async fn verify_password(
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
    match rmail_common::auth::verify_password(password, hash) {
        Ok(true) => PasswordAuthResult::Success(mailbox),
        Ok(false) => PasswordAuthResult::Rejected,
        Err(error) => PasswordAuthResult::Unavailable {
            mailbox: Some(mailbox),
            message: error.to_string(),
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SaslCredentials {
    pub(crate) authcid: String,
    pub(crate) authzid: Option<String>,
    pub(crate) password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SaslProgress {
    Challenge(&'static str),
    Credentials(SaslCredentials),
    ScramClientFirst(ScramClientFirst),
    ScramClientFinal(ScramClientFinal),
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SaslExchangeError {
    InvalidResponse,
    UnexpectedResponse,
}

pub(crate) trait SaslExchange: Send {
    fn start(&mut self, initial: Option<&str>) -> Result<SaslProgress, SaslExchangeError>;
    fn receive(&mut self, response: &str) -> Result<SaslProgress, SaslExchangeError>;
}

enum ScramState {
    New,
    ClientFinal,
    ClientFinalReceived,
    FinalAcknowledgment,
    Complete,
}

pub(crate) struct ScramExchange {
    channel_binding_required: bool,
    state: ScramState,
}

impl ScramExchange {
    pub(crate) fn new(channel_binding_required: bool) -> Self {
        Self {
            channel_binding_required,
            state: ScramState::New,
        }
    }

    pub(crate) fn expect_final_acknowledgment(&mut self) -> Result<(), SaslExchangeError> {
        if !matches!(self.state, ScramState::ClientFinalReceived) {
            return Err(SaslExchangeError::UnexpectedResponse);
        }
        self.state = ScramState::FinalAcknowledgment;
        Ok(())
    }
}

impl SaslExchange for ScramExchange {
    fn start(&mut self, initial: Option<&str>) -> Result<SaslProgress, SaslExchangeError> {
        if !matches!(self.state, ScramState::New) {
            return Err(SaslExchangeError::UnexpectedResponse);
        }
        let Some(initial) = initial else {
            return Ok(SaslProgress::Challenge(""));
        };
        let message = decode_sasl_message(initial).ok_or(SaslExchangeError::InvalidResponse)?;
        let first = parse_scram_client_first(&message, self.channel_binding_required)
            .ok_or(SaslExchangeError::InvalidResponse)?;
        self.state = ScramState::ClientFinal;
        Ok(SaslProgress::ScramClientFirst(first))
    }

    fn receive(&mut self, response: &str) -> Result<SaslProgress, SaslExchangeError> {
        match self.state {
            ScramState::New => {
                let message =
                    decode_sasl_message(response).ok_or(SaslExchangeError::InvalidResponse)?;
                let first = parse_scram_client_first(&message, self.channel_binding_required)
                    .ok_or(SaslExchangeError::InvalidResponse)?;
                self.state = ScramState::ClientFinal;
                Ok(SaslProgress::ScramClientFirst(first))
            }
            ScramState::ClientFinal => {
                let message =
                    decode_sasl_message(response).ok_or(SaslExchangeError::InvalidResponse)?;
                let final_message =
                    parse_scram_client_final(&message).ok_or(SaslExchangeError::InvalidResponse)?;
                self.state = ScramState::ClientFinalReceived;
                Ok(SaslProgress::ScramClientFinal(final_message))
            }
            ScramState::ClientFinalReceived => Err(SaslExchangeError::UnexpectedResponse),
            ScramState::FinalAcknowledgment if response.is_empty() || response == "=" => {
                self.state = ScramState::Complete;
                Ok(SaslProgress::Complete)
            }
            ScramState::FinalAcknowledgment | ScramState::Complete => {
                Err(SaslExchangeError::UnexpectedResponse)
            }
        }
    }
}

fn plain_credentials(response: &str) -> Option<SaslCredentials> {
    let decoded = BASE64_ENGINE.decode(response.trim()).ok()?;
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
pub(crate) struct PlainExchange {
    waiting: bool,
}

impl SaslExchange for PlainExchange {
    fn start(&mut self, initial: Option<&str>) -> Result<SaslProgress, SaslExchangeError> {
        if self.waiting {
            return Err(SaslExchangeError::UnexpectedResponse);
        }
        match initial {
            Some(response) => plain_credentials(response)
                .map(SaslProgress::Credentials)
                .ok_or(SaslExchangeError::InvalidResponse),
            None => {
                self.waiting = true;
                Ok(SaslProgress::Challenge(""))
            }
        }
    }

    fn receive(&mut self, response: &str) -> Result<SaslProgress, SaslExchangeError> {
        if !self.waiting {
            return Err(SaslExchangeError::UnexpectedResponse);
        }
        self.waiting = false;
        plain_credentials(response)
            .map(SaslProgress::Credentials)
            .ok_or(SaslExchangeError::InvalidResponse)
    }
}

#[derive(Default)]
pub(crate) struct LoginExchange {
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

impl SaslExchange for LoginExchange {
    fn start(&mut self, initial: Option<&str>) -> Result<SaslProgress, SaslExchangeError> {
        if !matches!(self.state, LoginState::New) {
            return Err(SaslExchangeError::UnexpectedResponse);
        }
        match initial {
            Some(response) => {
                self.username =
                    Some(decode_sasl_message(response).ok_or(SaslExchangeError::InvalidResponse)?);
                self.state = LoginState::Password;
                Ok(SaslProgress::Challenge("UGFzc3dvcmQ6"))
            }
            None => {
                self.state = LoginState::Username;
                Ok(SaslProgress::Challenge("VXNlcm5hbWU6"))
            }
        }
    }

    fn receive(&mut self, response: &str) -> Result<SaslProgress, SaslExchangeError> {
        match self.state {
            LoginState::Username => {
                self.username =
                    Some(decode_sasl_message(response).ok_or(SaslExchangeError::InvalidResponse)?);
                self.state = LoginState::Password;
                Ok(SaslProgress::Challenge("UGFzc3dvcmQ6"))
            }
            LoginState::Password => {
                let password =
                    decode_sasl_message(response).ok_or(SaslExchangeError::InvalidResponse)?;
                self.state = LoginState::Complete;
                Ok(SaslProgress::Credentials(SaslCredentials {
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

pub(crate) fn decode_sasl_message(response: &str) -> Option<String> {
    if response.trim() == "=" {
        return Some(String::new());
    }
    let decoded = BASE64_ENGINE.decode(response.trim()).ok()?;
    String::from_utf8(decoded).ok()
}

#[cfg(test)]
pub(crate) fn parse_scram_attr<'a>(message: &'a str, key: &str) -> Option<&'a str> {
    message.split(',').find_map(|part| part.strip_prefix(key))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScramClientFirst {
    pub(crate) username: String,
    pub(crate) authzid: Option<String>,
    pub(crate) nonce: String,
    pub(crate) bare: String,
    pub(crate) gs2_header: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScramClientFinal {
    pub(crate) without_proof: String,
    pub(crate) proof: String,
    pub(crate) channel_binding: String,
    pub(crate) nonce: String,
}

fn decode_scram_name(value: &str) -> Option<String> {
    let mut decoded = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '=' {
            decoded.push(ch);
            continue;
        }
        match (chars.next(), chars.next()) {
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

pub(crate) fn parse_scram_client_first(
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

pub(crate) fn parse_scram_client_final(message: &str) -> Option<ScramClientFinal> {
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

pub(crate) fn generate_scram_nonce() -> String {
    let mut bytes = [0u8; 18];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    BASE64_ENGINE.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scram_client_first_validates_gs2_names_nonce_and_attributes() {
        let first = parse_scram_client_first("y,,n=user=2Cname=3Dtest,r=nonce-123", false).unwrap();
        assert_eq!(first.username, "user,name=test");
        assert_eq!(first.nonce, "nonce-123");
        assert_eq!(first.gs2_header, "y,,");
        assert_eq!(first.bare, "n=user=2Cname=3Dtest,r=nonce-123");

        let authorized =
            parse_scram_client_first("n,a=user@example.test,n=user@example.test,r=n", false)
                .unwrap();
        assert_eq!(authorized.authzid.as_deref(), Some("user@example.test"));
        let plus = parse_scram_client_first("p=tls-server-end-point,,n=user,r=n", true).unwrap();
        assert_eq!(plus.gs2_header, "p=tls-server-end-point,,");
        assert!(parse_scram_client_first("p=tls-server-end-point,,n=user,r=n", false).is_none());
        assert!(parse_scram_client_first("n,,n=user,r=n", true).is_none());
        assert!(parse_scram_client_first("n,,n=user,n=duplicate,r=n", false).is_none());
        assert!(parse_scram_client_first("n,,m=reserved,n=user,r=n", false).is_none());
        assert!(parse_scram_client_first("n,,n=bad=escape,r=n", false).is_none());
        assert!(parse_scram_client_first("n,,n=user,r=bad,nonce", false).is_none());
    }

    #[test]
    fn scram_client_final_requires_unique_c_r_and_last_proof() {
        let final_message = parse_scram_client_final("c=biws,r=nonce,p=cHJvb2Y=").unwrap();
        assert_eq!(final_message.channel_binding, "biws");
        assert_eq!(final_message.nonce, "nonce");
        assert_eq!(final_message.proof, "cHJvb2Y=");
        assert_eq!(final_message.without_proof, "c=biws,r=nonce");

        assert!(parse_scram_client_final("r=nonce,p=cHJvb2Y=").is_none());
        assert!(parse_scram_client_final("c=biws,r=one,r=two,p=cHJvb2Y=").is_none());
        assert!(parse_scram_client_final("c=biws,r=nonce,p=cHJvb2Y=,x=late").is_none());
        assert!(parse_scram_client_final("c=biws,r=nonce,m=x,p=cHJvb2Y=").is_none());
    }

    #[test]
    fn sasl_payload_decoding_rejects_invalid_utf8() {
        assert!(decode_sasl_message("/w==").is_none());
        assert_eq!(decode_sasl_message("="), Some(String::new()));
    }

    #[test]
    fn plain_and_login_exchanges_share_stateful_challenge_lifecycle() {
        let mut plain = PlainExchange::default();
        assert_eq!(plain.start(None), Ok(SaslProgress::Challenge("")));
        assert_eq!(
            plain.receive("AHVzZXIAcGFzcw=="),
            Ok(SaslProgress::Credentials(SaslCredentials {
                authcid: "user".to_string(),
                authzid: None,
                password: "pass".to_string(),
            }))
        );
        assert_eq!(
            PlainExchange::default().start(Some("YWRtaW4AdXNlcgBwYXNz")),
            Ok(SaslProgress::Credentials(SaslCredentials {
                authcid: "user".to_string(),
                authzid: Some("admin".to_string()),
                password: "pass".to_string(),
            }))
        );

        let mut login = LoginExchange::default();
        assert_eq!(
            login.start(None),
            Ok(SaslProgress::Challenge("VXNlcm5hbWU6"))
        );
        assert_eq!(
            login.receive("dXNlcg=="),
            Ok(SaslProgress::Challenge("UGFzc3dvcmQ6"))
        );
        assert!(matches!(
            login.receive("cGFzcw=="),
            Ok(SaslProgress::Credentials(_))
        ));
        assert_eq!(
            login.receive("cGFzcw=="),
            Err(SaslExchangeError::UnexpectedResponse)
        );
    }

    #[test]
    fn scram_exchange_enforces_first_final_and_acknowledgment_order() {
        let mut exchange = ScramExchange::new(false);
        assert_eq!(exchange.start(None), Ok(SaslProgress::Challenge("")));
        let first = BASE64_ENGINE.encode("n,,n=user,r=nonce");
        assert!(matches!(
            exchange.receive(&first),
            Ok(SaslProgress::ScramClientFirst(_))
        ));
        let final_message = BASE64_ENGINE.encode("c=biws,r=nonce-server,p=cHJvb2Y=");
        assert!(matches!(
            exchange.receive(&final_message),
            Ok(SaslProgress::ScramClientFinal(_))
        ));
        assert!(exchange.expect_final_acknowledgment().is_ok());
        assert_eq!(exchange.receive(""), Ok(SaslProgress::Complete));
        assert_eq!(
            exchange.receive(""),
            Err(SaslExchangeError::UnexpectedResponse)
        );

        let mut plus = ScramExchange::new(true);
        assert!(
            plus.start(Some(&BASE64_ENGINE.encode("n,,n=user,r=nonce")))
                .is_err()
        );
        assert!(matches!(
            plus.start(Some(
                &BASE64_ENGINE.encode("p=tls-server-end-point,,n=user,r=nonce")
            )),
            Ok(SaslProgress::ScramClientFirst(_))
        ));
        assert!(plus.expect_final_acknowledgment().is_err());
    }

    #[test]
    fn auth_policy_validates_and_filters_configured_mechanisms() {
        assert!(AuthPolicy::from_names(&[]).is_err());
        assert!(AuthPolicy::from_names(&["UNKNOWN".to_string()]).is_err());
        assert!(AuthPolicy::from_names(&["PLAIN".to_string(), "plain".to_string()]).is_err());

        let policy =
            AuthPolicy::from_names(&["LOGIN".to_string(), "SCRAM-SHA-256".to_string()]).unwrap();
        assert!(policy.mechanism("PLAIN").is_none());
        assert!(policy.mechanism("LOGIN").is_some());
        assert_eq!(
            policy
                .advertised_mechanisms(false, false)
                .map(|mechanism| mechanism.name)
                .collect::<Vec<_>>(),
            ["SCRAM-SHA-256"]
        );
        assert_eq!(
            policy
                .advertised_mechanisms(true, false)
                .map(|mechanism| mechanism.name)
                .collect::<Vec<_>>(),
            ["LOGIN", "SCRAM-SHA-256"]
        );
    }
}
