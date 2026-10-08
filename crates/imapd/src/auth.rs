use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use once_cell::sync::Lazy;
use rand::RngCore;
use std::{net::IpAddr, time::Duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SaslSecurity {
    PlaintextPassword,
    ChallengeResponse,
    BearerToken,
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
    SaslMechanism {
        name: "OAUTHBEARER",
        capability: "AUTH=OAUTHBEARER",
        security: SaslSecurity::BearerToken,
        channel_binding_required: false,
    },
    SaslMechanism {
        name: "XOAUTH2",
        capability: "AUTH=XOAUTH2",
        security: SaslSecurity::BearerToken,
        channel_binding_required: false,
    },
];

/// Inactivity autologout (RFC 3501 §5.4, RFC 9051 §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionTimeouts {
    /// Before authentication; may be shorter than 30 minutes.
    pub(crate) unauthenticated: Duration,
    /// After authentication; RFC 3501 requires at least 30 minutes.
    pub(crate) authenticated: Duration,
    /// Longest IDLE without DONE; clients re-issue IDLE every 29 minutes
    /// (RFC 2177), so a stuck IDLE ends after 30.
    pub(crate) idle: Duration,
}

impl Default for SessionTimeouts {
    fn default() -> Self {
        Self {
            unauthenticated: Duration::from_secs(3 * 60),
            authenticated: Duration::from_secs(30 * 60),
            idle: Duration::from_secs(30 * 60),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AuthPolicy {
    mechanisms: Vec<SaslMechanism>,
    oauth: Option<rmail_common::oauth::OAuthValidator>,
    max_commands_per_minute: usize,
    timeouts: SessionTimeouts,
    /// RFC 9738 MESSAGELIMIT; `None` when unlimited.
    message_limit: Option<usize>,
}

impl Default for AuthPolicy {
    fn default() -> Self {
        Self {
            mechanisms: SASL_MECHANISMS
                .iter()
                .copied()
                .filter(|mechanism| mechanism.security != SaslSecurity::BearerToken)
                .collect(),
            oauth: None,
            max_commands_per_minute: 300,
            timeouts: SessionTimeouts::default(),
            message_limit: None,
        }
    }
}

impl AuthPolicy {
    #[cfg(test)]
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
        if mechanisms
            .iter()
            .any(|mechanism| mechanism.security == SaslSecurity::BearerToken)
        {
            anyhow::bail!("OAuth SASL mechanisms require security.oauth configuration");
        }
        Ok(Self {
            mechanisms,
            oauth: None,
            max_commands_per_minute: 300,
            timeouts: SessionTimeouts::default(),
            message_limit: None,
        })
    }

    pub(crate) fn from_security(
        security: &rmail_common::config::SecurityConfig,
    ) -> anyhow::Result<Self> {
        let mut policy = Self::from_names_without_oauth(&security.imap_sasl_mechanisms)?;
        let oauth = security
            .oauth
            .clone()
            .map(rmail_common::oauth::OAuthValidator::new)
            .transpose()?;
        if policy
            .mechanisms
            .iter()
            .any(|mechanism| mechanism.security == SaslSecurity::BearerToken)
            && oauth.is_none()
        {
            anyhow::bail!("OAuth SASL mechanisms require security.oauth configuration");
        }
        policy.oauth = oauth;
        policy.max_commands_per_minute = security.imap_max_commands_per_minute.max(1);
        policy.message_limit =
            (security.imap_message_limit > 0).then_some(security.imap_message_limit);
        Ok(policy)
    }

    fn from_names_without_oauth(names: &[String]) -> anyhow::Result<Self> {
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
        Ok(Self {
            mechanisms,
            oauth: None,
            max_commands_per_minute: 300,
            timeouts: SessionTimeouts::default(),
            message_limit: None,
        })
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
            ((encrypted || mechanism.security == SaslSecurity::ChallengeResponse)
                && (mechanism.security != SaslSecurity::BearerToken || self.oauth.is_some())
                && (!mechanism.channel_binding_required || channel_binding_available))
                .then_some(*mechanism)
        })
    }

    pub(crate) fn oauth(&self) -> Option<&rmail_common::oauth::OAuthValidator> {
        self.oauth.as_ref()
    }

    pub(crate) fn timeouts(&self) -> SessionTimeouts {
        self.timeouts
    }

    #[cfg(test)]
    pub(crate) fn with_timeouts(mut self, timeouts: SessionTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    pub(crate) fn max_commands_per_minute(&self) -> usize {
        self.max_commands_per_minute
    }

    pub(crate) fn message_limit(&self) -> Option<usize> {
        self.message_limit
    }

    #[cfg(test)]
    pub(crate) fn with_message_limit(mut self, limit: usize) -> Self {
        self.message_limit = Some(limit);
        self
    }
}

pub(crate) fn sasl_mechanism(name: &str) -> Option<SaslMechanism> {
    SASL_MECHANISMS
        .iter()
        .copied()
        .find(|mechanism| mechanism.name.eq_ignore_ascii_case(name))
}

// In-process brute-force protection keyed by client address (IPv6 by /64).
static AUTH_THROTTLE: Lazy<rmail_common::throttle::AuthThrottle> =
    Lazy::new(rmail_common::throttle::AuthThrottle::default);

/// Remaining authentication lockout for the client, if any.
pub(crate) fn auth_block_remaining(ip: IpAddr) -> Option<Duration> {
    AUTH_THROTTLE.blocked_for(ip)
}

/// Record a failed authentication; repeated failures lock the client out.
pub(crate) fn record_auth_failure(ip: IpAddr) {
    rmail_common::metrics::inc_auth_failures();
    AUTH_THROTTLE.record_failure(ip);
}

/// Clear recorded failures after a successful authentication.
pub(crate) fn reset_auth_failures(ip: IpAddr) {
    AUTH_THROTTLE.reset(ip);
}

pub(crate) use rmail_common::auth::{PasswordAuthResult, lookup_mailbox};

pub(crate) async fn verify_password(
    db_path: Option<&String>,
    user: &str,
    password: &str,
) -> PasswordAuthResult {
    rmail_common::auth::authenticate_password(db_path, user, password).await
}

pub(crate) use rmail_common::auth::{
    ScramChannelBindingPolicy, ScramClientFinal, ScramClientFirst, ScramClientFirstError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SaslProgress {
    Challenge(&'static str),
    ScramClientFirst(ScramClientFirst),
    ScramClientFinal(ScramClientFinal),
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SaslExchangeError {
    InvalidResponse,
    UnexpectedResponse,
    /// RFC 5802 §6: gs2 flag `y` while SCRAM-SHA-256-PLUS was advertised.
    ChannelBindingDowngrade,
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
    policy: ScramChannelBindingPolicy,
    state: ScramState,
}

impl ScramExchange {
    pub(crate) fn new(policy: ScramChannelBindingPolicy) -> Self {
        Self {
            policy,
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

    fn client_first(&mut self, wire: &str) -> Result<SaslProgress, SaslExchangeError> {
        let message = decode_sasl_message(wire).ok_or(SaslExchangeError::InvalidResponse)?;
        let first = rmail_common::auth::parse_scram_client_first_with_policy(&message, self.policy)
            .map_err(|error| match error {
                ScramClientFirstError::ChannelBindingDowngrade => {
                    SaslExchangeError::ChannelBindingDowngrade
                }
                ScramClientFirstError::Malformed
                | ScramClientFirstError::UnsupportedChannelBinding => {
                    SaslExchangeError::InvalidResponse
                }
            })?;
        self.state = ScramState::ClientFinal;
        Ok(SaslProgress::ScramClientFirst(first))
    }
}

impl SaslExchange for ScramExchange {
    fn start(&mut self, initial: Option<&str>) -> Result<SaslProgress, SaslExchangeError> {
        if !matches!(self.state, ScramState::New) {
            return Err(SaslExchangeError::UnexpectedResponse);
        }
        match initial {
            Some(initial) => self.client_first(initial),
            None => Ok(SaslProgress::Challenge("")),
        }
    }

    fn receive(&mut self, response: &str) -> Result<SaslProgress, SaslExchangeError> {
        match self.state {
            ScramState::New => self.client_first(response),
            ScramState::ClientFinal => {
                let message =
                    decode_sasl_message(response).ok_or(SaslExchangeError::InvalidResponse)?;
                let final_message = rmail_common::auth::parse_scram_client_final(&message)
                    .ok_or(SaslExchangeError::InvalidResponse)?;
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

pub(crate) fn generate_scram_nonce() -> String {
    let mut bytes = [0u8; 18];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    BASE64_ENGINE.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(message: &str, policy: ScramChannelBindingPolicy) -> Option<ScramClientFirst> {
        rmail_common::auth::parse_scram_client_first_with_policy(message, policy).ok()
    }

    #[test]
    fn scram_client_first_validates_gs2_names_nonce_and_attributes() {
        use ScramChannelBindingPolicy::{NotOffered, Required};
        let first = parse("y,,n=user=2Cname=3Dtest,r=nonce-123", NotOffered).unwrap();
        assert_eq!(first.username, "user,name=test");
        assert_eq!(first.nonce, "nonce-123");
        assert_eq!(first.gs2_header, "y,,");
        assert_eq!(first.bare, "n=user=2Cname=3Dtest,r=nonce-123");

        let authorized =
            parse("n,a=user@example.test,n=user@example.test,r=n", NotOffered).unwrap();
        assert_eq!(authorized.authzid.as_deref(), Some("user@example.test"));
        let plus = parse("p=tls-server-end-point,,n=user,r=n", Required).unwrap();
        assert_eq!(plus.gs2_header, "p=tls-server-end-point,,");
        let exporter = parse("p=tls-exporter,,n=user,r=n", Required).unwrap();
        assert_eq!(
            exporter.channel_binding,
            Some(rmail_common::auth::ChannelBindingType::TlsExporter)
        );
        assert!(parse("p=tls-unique,,n=user,r=n", Required).is_none());
        assert!(parse("p=tls-server-end-point,,n=user,r=n", NotOffered).is_none());
        assert!(parse("n,,n=user,r=n", Required).is_none());
        assert!(parse("n,,n=user,n=duplicate,r=n", NotOffered).is_none());
        assert!(parse("n,,m=reserved,n=user,r=n", NotOffered).is_none());
        assert!(parse("n,,n=bad=escape,r=n", NotOffered).is_none());
        assert!(parse("n,,n=user,r=bad,nonce", NotOffered).is_none());
    }

    #[test]
    fn scram_exchange_rejects_y_flag_when_plus_was_advertised() {
        let first = BASE64_ENGINE.encode("y,,n=user,r=nonce");
        let mut exchange = ScramExchange::new(ScramChannelBindingPolicy::OfferedButNotSelected);
        assert_eq!(
            exchange.start(Some(&first)),
            Err(SaslExchangeError::ChannelBindingDowngrade)
        );
        let mut exchange = ScramExchange::new(ScramChannelBindingPolicy::OfferedButNotSelected);
        assert!(matches!(
            exchange.start(Some(&BASE64_ENGINE.encode("n,,n=user,r=nonce"))),
            Ok(SaslProgress::ScramClientFirst(_))
        ));
        let mut exchange = ScramExchange::new(ScramChannelBindingPolicy::NotOffered);
        assert!(matches!(
            exchange.start(Some(&first)),
            Ok(SaslProgress::ScramClientFirst(_))
        ));
    }

    #[test]
    fn scram_client_final_requires_unique_c_r_and_last_proof() {
        use rmail_common::auth::parse_scram_client_final;
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
    fn scram_exchange_enforces_first_final_and_acknowledgment_order() {
        let mut exchange = ScramExchange::new(ScramChannelBindingPolicy::NotOffered);
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

        let mut plus = ScramExchange::new(ScramChannelBindingPolicy::Required);
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
