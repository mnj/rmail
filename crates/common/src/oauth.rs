use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::config::OAuthConfig;

pub const MAX_ACCESS_TOKEN_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthSaslCredentials {
    pub asserted_identity: Option<String>,
    pub token: String,
    pub host: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct OAuthValidator {
    client: reqwest::Client,
    config: OAuthConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthValidation {
    Active { identity: String },
    Rejected,
    Unavailable(String),
}

#[derive(Debug, Deserialize)]
struct IntrospectionResponse {
    active: bool,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    aud: Option<Audience>,
    #[serde(default)]
    exp: Option<i64>,
    #[serde(default)]
    nbf: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
        }
    }
}

impl OAuthValidator {
    pub fn new(config: OAuthConfig) -> anyhow::Result<Self> {
        validate_config(&config)?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()?;
        Ok(Self { client, config })
    }

    pub async fn validate(&self, token: &str, asserted_identity: Option<&str>) -> OAuthValidation {
        if token.is_empty()
            || token.len() > MAX_ACCESS_TOKEN_BYTES
            || token.chars().any(char::is_whitespace)
        {
            return OAuthValidation::Rejected;
        }
        let mut request = self
            .client
            .post(&self.config.introspection_url)
            .form(&[("token", token), ("token_type_hint", "access_token")]);
        if let Some(client_id) = self.config.client_id.as_deref() {
            request = request.basic_auth(client_id, self.config.client_secret.as_deref());
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                return OAuthValidation::Unavailable(format!(
                    "token introspection request failed: {error}"
                ));
            }
        };
        if !response.status().is_success() {
            return OAuthValidation::Unavailable(format!(
                "token introspection returned HTTP {}",
                response.status()
            ));
        }
        let response: IntrospectionResponse = match response.json().await {
            Ok(response) => response,
            Err(error) => {
                return OAuthValidation::Unavailable(format!(
                    "invalid token introspection response: {error}"
                ));
            }
        };
        validate_response(&self.config, response, asserted_identity)
    }
}

pub fn parse_oauth_sasl_response(
    mechanism: &str,
    decoded: &[u8],
) -> anyhow::Result<OAuthSaslCredentials> {
    let response = std::str::from_utf8(decoded).map_err(|_| anyhow::anyhow!("invalid UTF-8"))?;
    if !response.ends_with("\x01\x01") {
        anyhow::bail!("missing SASL terminator");
    }
    match mechanism.to_ascii_uppercase().as_str() {
        "OAUTHBEARER" => parse_oauthbearer(response),
        "XOAUTH2" => parse_xoauth2(response),
        _ => anyhow::bail!("unsupported OAuth SASL mechanism"),
    }
}

fn parse_oauthbearer(response: &str) -> anyhow::Result<OAuthSaslCredentials> {
    let (gs2, fields) = response
        .split_once('\x01')
        .ok_or_else(|| anyhow::anyhow!("missing GS2 separator"))?;
    if !gs2.starts_with("n,") || !gs2.ends_with(',') {
        anyhow::bail!("invalid OAUTHBEARER GS2 header");
    }
    let asserted_identity = gs2
        .strip_prefix("n,")
        .and_then(|value| value.strip_suffix(','))
        .and_then(|value| value.strip_prefix("a="))
        .map(decode_gs2_name)
        .transpose()?;
    parse_oauth_fields(fields, asserted_identity, false)
}

fn parse_xoauth2(response: &str) -> anyhow::Result<OAuthSaslCredentials> {
    parse_oauth_fields(response, None, true)
}

fn parse_oauth_fields(
    fields: &str,
    mut asserted_identity: Option<String>,
    xoauth2: bool,
) -> anyhow::Result<OAuthSaslCredentials> {
    let mut token = None;
    let mut host = None;
    let mut port = None;
    for field in fields.split('\x01').filter(|field| !field.is_empty()) {
        let (key, value) = field
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("invalid OAuth SASL field"))?;
        match key {
            "auth" if token.is_none() => {
                let (scheme, value) = value
                    .split_once(' ')
                    .ok_or_else(|| anyhow::anyhow!("invalid OAuth authorization field"))?;
                if !scheme.eq_ignore_ascii_case("Bearer")
                    || value.is_empty()
                    || value.len() > MAX_ACCESS_TOKEN_BYTES
                    || value.chars().any(char::is_whitespace)
                {
                    anyhow::bail!("invalid bearer token");
                }
                token = Some(value.to_string());
            }
            "user" if xoauth2 && asserted_identity.is_none() && !value.is_empty() => {
                asserted_identity = Some(value.to_string());
            }
            "host" if !xoauth2 && host.is_none() && !value.is_empty() => {
                host = Some(value.to_ascii_lowercase());
            }
            "port" if !xoauth2 && port.is_none() => {
                port = Some(
                    value
                        .parse()
                        .map_err(|_| anyhow::anyhow!("invalid SASL port"))?,
                );
            }
            // RFC 7628 requires unknown key/value pairs to be ignored.
            _ if !matches!(key, "auth" | "user" | "host" | "port") => {}
            _ => anyhow::bail!("duplicate or invalid OAuth SASL field"),
        }
    }
    if xoauth2 && asserted_identity.is_none() {
        anyhow::bail!("XOAUTH2 user is required");
    }
    Ok(OAuthSaslCredentials {
        asserted_identity,
        token: token.ok_or_else(|| anyhow::anyhow!("bearer token is required"))?,
        host,
        port,
    })
}

fn decode_gs2_name(value: &str) -> anyhow::Result<String> {
    let mut decoded = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '=' {
            decoded.push(ch);
            continue;
        }
        match (chars.next(), chars.next()) {
            (Some('2'), Some('C' | 'c')) => decoded.push(','),
            (Some('3'), Some('D' | 'd')) => decoded.push('='),
            _ => anyhow::bail!("invalid GS2 authorization identity escape"),
        }
    }
    if decoded.is_empty() {
        anyhow::bail!("empty GS2 authorization identity");
    }
    Ok(decoded)
}

fn validate_config(config: &OAuthConfig) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(&config.introspection_url)?;
    if url.scheme() != "https" && !(config.allow_insecure_http && url.scheme() == "http") {
        anyhow::bail!("OAuth introspection URL must use HTTPS unless allow_insecure_http is true");
    }
    if config.timeout_ms == 0 {
        anyhow::bail!("OAuth introspection timeout must be greater than zero");
    }
    if config.client_id.is_some() != config.client_secret.is_some() {
        anyhow::bail!(
            "OAuth introspection client_id and client_secret must be configured together"
        );
    }
    if !matches!(config.identity_claim.as_str(), "username" | "sub" | "email") {
        anyhow::bail!("OAuth identity_claim must be username, sub, or email");
    }
    if config
        .required_scopes
        .iter()
        .any(|scope| scope.is_empty() || scope.chars().any(char::is_whitespace))
    {
        anyhow::bail!("OAuth required scopes must be non-empty single tokens");
    }
    Ok(())
}

fn validate_response(
    config: &OAuthConfig,
    response: IntrospectionResponse,
    asserted_identity: Option<&str>,
) -> OAuthValidation {
    if !response.active {
        return OAuthValidation::Rejected;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(i64::MAX, |duration| duration.as_secs() as i64);
    if response.exp.is_some_and(|expiry| expiry <= now)
        || response.nbf.is_some_and(|not_before| not_before > now)
        || config
            .issuer
            .as_ref()
            .is_some_and(|expected| response.iss.as_ref() != Some(expected))
        || config.audience.as_ref().is_some_and(|expected| {
            !response
                .aud
                .as_ref()
                .is_some_and(|audience| audience.contains(expected))
        })
    {
        return OAuthValidation::Rejected;
    }
    let scopes = response
        .scope
        .as_deref()
        .unwrap_or_default()
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    if config
        .required_scopes
        .iter()
        .any(|required| !scopes.contains(&required.as_str()))
    {
        return OAuthValidation::Rejected;
    }
    let identity = match config.identity_claim.as_str() {
        "username" => response.username,
        "sub" => response.sub,
        "email" => response.email,
        _ => None,
    }
    .map(|identity| identity.trim().to_ascii_lowercase());
    let Some(identity) = identity.filter(|identity| !identity.is_empty()) else {
        return OAuthValidation::Rejected;
    };
    if asserted_identity.is_some_and(|asserted| !asserted.trim().eq_ignore_ascii_case(&identity)) {
        return OAuthValidation::Rejected;
    }
    OAuthValidation::Active { identity }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> OAuthConfig {
        OAuthConfig {
            introspection_url: "https://identity.example.test/introspect".to_string(),
            client_id: Some("rmail".to_string()),
            client_secret: Some("secret".to_string()),
            required_scopes: vec!["mail".to_string()],
            identity_claim: "username".to_string(),
            issuer: Some("https://identity.example.test/".to_string()),
            audience: Some("rmail".to_string()),
            timeout_ms: 1_000,
            allow_insecure_http: false,
        }
    }

    #[test]
    fn configuration_is_fail_closed_and_redacts_client_secret() {
        let mut value = config();
        assert!(OAuthValidator::new(value.clone()).is_ok());
        assert!(!format!("{value:?}").contains("Some(\"secret\")"));
        value.introspection_url = "http://identity.example.test/introspect".to_string();
        assert!(OAuthValidator::new(value.clone()).is_err());
        value.allow_insecure_http = true;
        assert!(OAuthValidator::new(value).is_ok());
    }

    #[test]
    fn active_response_requires_identity_scope_time_issuer_and_audience() {
        let value = config();
        let response = IntrospectionResponse {
            active: true,
            username: Some("User@Example.Test".to_string()),
            sub: None,
            email: None,
            scope: Some("openid mail".to_string()),
            iss: value.issuer.clone(),
            aud: Some(Audience::Many(vec![
                "other".to_string(),
                "rmail".to_string(),
            ])),
            exp: Some(i64::MAX),
            nbf: Some(0),
        };
        assert_eq!(
            validate_response(&value, response, Some("user@example.test")),
            OAuthValidation::Active {
                identity: "user@example.test".to_string()
            }
        );
    }

    #[test]
    fn inactive_mismatched_and_under_scoped_tokens_are_rejected() {
        let value = config();
        let make_response = || IntrospectionResponse {
            active: true,
            username: Some("user@example.test".to_string()),
            sub: None,
            email: None,
            scope: Some("openid".to_string()),
            iss: value.issuer.clone(),
            aud: Some(Audience::One("rmail".to_string())),
            exp: Some(i64::MAX),
            nbf: None,
        };
        assert_eq!(
            validate_response(&value, make_response(), None),
            OAuthValidation::Rejected
        );
        let mut no_scope = value.clone();
        no_scope.required_scopes.clear();
        assert_eq!(
            validate_response(&no_scope, make_response(), Some("other@example.test")),
            OAuthValidation::Rejected
        );
    }

    #[test]
    fn oauthbearer_and_xoauth2_sasl_payloads_are_strictly_parsed() {
        assert_eq!(
            parse_oauth_sasl_response(
                "OAUTHBEARER",
                b"n,a=user@example.test,\x01host=mail.example.test\x01port=993\x01auth=Bearer token-1\x01\x01",
            )
            .unwrap(),
            OAuthSaslCredentials {
                asserted_identity: Some("user@example.test".to_string()),
                token: "token-1".to_string(),
                host: Some("mail.example.test".to_string()),
                port: Some(993),
            }
        );
        assert_eq!(
            parse_oauth_sasl_response(
                "XOAUTH2",
                b"user=user@example.test\x01auth=Bearer token-2\x01\x01",
            )
            .unwrap()
            .asserted_identity
            .as_deref(),
            Some("user@example.test")
        );
        for invalid in [
            b"n,,\x01auth=Basic token\x01\x01".as_slice(),
            b"n,,\x01auth=Bearer token\x01auth=Bearer duplicate\x01\x01".as_slice(),
            b"n,,\x01auth=Bearer token".as_slice(),
        ] {
            assert!(parse_oauth_sasl_response("OAUTHBEARER", invalid).is_err());
        }
    }
}
