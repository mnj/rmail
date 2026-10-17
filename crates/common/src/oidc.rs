//! OpenID Connect sign-in for webmail (authorization code flow with PKCE).
//!
//! - The provider is found from its issuer's discovery document.
//! - The ID token comes straight from the provider's token endpoint over
//!   TLS, in exchange for the code and the client secret, so its issuer,
//!   audience, expiry and nonce are checked and its signature is not (OIDC
//!   Core 3.1.3.7, item 6).
//! - The issuer must be HTTPS, except on the loopback address (a provider
//!   run on the same machine, and tests).

use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::OidcConfig;

/// The endpoints sign-in uses, from the discovery document.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Provider {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
}

/// Who signed in: the address the provider vouches for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub email: String,
    pub email_verified: bool,
}

fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("rMail-webmail/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default()
    })
}

/// HTTPS, or HTTP to the loopback address.
fn check_url(text: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(text.trim()).with_context(|| format!("invalid URL {text}"))?;
    let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']);
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    match url.scheme() {
        "https" => Ok(url),
        "http" if loopback => Ok(url),
        _ => bail!("{text} must use HTTPS"),
    }
}

/// Settings check on save: an issuer must be a usable URL.
pub fn validate_config(config: &OidcConfig) -> Result<()> {
    if !config.issuer.trim().is_empty() {
        check_url(&config.issuer).context("oidc.issuer")?;
    }
    Ok(())
}

/// Whether the settings are complete enough to offer sign-in.
pub fn configured(config: &OidcConfig) -> bool {
    config.enabled
        && !config.issuer.trim().is_empty()
        && !config.client_id.trim().is_empty()
        && config
            .client_secret
            .as_ref()
            .is_some_and(|secret| !secret.expose().is_empty())
}

/// The provider's endpoints, from `<issuer>/.well-known/openid-configuration`.
pub async fn discover(issuer: &str) -> Result<Provider> {
    let issuer = issuer.trim().trim_end_matches('/');
    let url = check_url(&format!("{issuer}/.well-known/openid-configuration"))?;
    let provider: Provider = client()
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("invalid discovery document")?;
    if provider.issuer.trim_end_matches('/') != issuer {
        bail!(
            "the discovery document is for another issuer ({})",
            provider.issuer
        );
    }
    check_url(&provider.authorization_endpoint)?;
    check_url(&provider.token_endpoint)?;
    Ok(provider)
}

/// A random URL-safe token (state, nonce, PKCE verifier).
pub fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

/// The PKCE challenge of a verifier (S256).
pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Where to send the browser to sign in.
pub fn authorize_url(
    provider: &Provider,
    config: &OidcConfig,
    redirect_uri: &str,
    state: &str,
    nonce: &str,
    verifier: &str,
) -> Result<String> {
    let mut url = check_url(&provider.authorization_endpoint)?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", config.client_id.trim())
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", "openid email")
        .append_pair("state", state)
        .append_pair("nonce", nonce)
        .append_pair("code_challenge", &challenge(verifier))
        .append_pair("code_challenge_method", "S256");
    Ok(url.to_string())
}

/// Exchange the code for an ID token and check it.
pub async fn exchange(
    provider: &Provider,
    config: &OidcConfig,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
    nonce: &str,
) -> Result<Identity> {
    let secret = config
        .client_secret
        .as_ref()
        .map(|secret| secret.expose().to_string())
        .unwrap_or_default();
    let response = client()
        .post(check_url(&provider.token_endpoint)?)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
            ("client_id", config.client_id.trim()),
            ("client_secret", secret.as_str()),
        ])
        .send()
        .await?;
    let status = response.status();
    let body: Value = response.json().await.context("invalid token response")?;
    if !status.is_success() {
        bail!(
            "the provider refused the code: {}",
            body["error_description"]
                .as_str()
                .or(body["error"].as_str())
                .unwrap_or(status.as_str())
        );
    }
    let token = body["id_token"].as_str().context("no ID token")?;
    check_id_token(
        token,
        provider,
        config,
        nonce,
        chrono::Utc::now().timestamp(),
    )
}

/// The claims of an ID token from the token endpoint, checked against the
/// issuer, this client, the time and the nonce sent.
pub fn check_id_token(
    token: &str,
    provider: &Provider,
    config: &OidcConfig,
    nonce: &str,
    now: i64,
) -> Result<Identity> {
    let payload = token.split('.').nth(1).context("malformed ID token")?;
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload.trim_end_matches('='))
            .context("malformed ID token")?,
    )
    .context("malformed ID token")?;
    if claims["iss"].as_str().map(|i| i.trim_end_matches('/'))
        != Some(provider.issuer.trim_end_matches('/'))
    {
        bail!("the ID token is from another issuer");
    }
    let client_id = config.client_id.trim();
    let audience_ok = match &claims["aud"] {
        Value::String(aud) => aud == client_id,
        Value::Array(list) => {
            list.iter().any(|a| a.as_str() == Some(client_id))
                && (list.len() == 1 || claims["azp"].as_str() == Some(client_id))
        }
        _ => false,
    };
    if !audience_ok {
        bail!("the ID token is for another client");
    }
    // A minute's leeway for clocks.
    if claims["exp"].as_i64().is_none_or(|exp| exp + 60 < now) {
        bail!("the ID token has expired");
    }
    if claims["nonce"].as_str() != Some(nonce) {
        bail!("the ID token is not for this sign-in");
    }
    let email = claims["email"]
        .as_str()
        .context("the provider sent no email address")?
        .trim()
        .to_ascii_lowercase();
    let email_verified = match &claims["email_verified"] {
        Value::Bool(verified) => *verified,
        Value::String(text) => text.eq_ignore_ascii_case("true"),
        _ => false,
    };
    Ok(Identity {
        email,
        email_verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecretString;
    use serde_json::json;

    fn config() -> OidcConfig {
        OidcConfig {
            enabled: true,
            issuer: "https://id.example.test".into(),
            client_id: "rmail".into(),
            client_secret: Some(SecretString("s".into())),
            ..OidcConfig::default()
        }
    }

    fn provider() -> Provider {
        Provider {
            issuer: "https://id.example.test".into(),
            authorization_endpoint: "https://id.example.test/auth".into(),
            token_endpoint: "https://id.example.test/token".into(),
        }
    }

    fn token(claims: Value) -> String {
        format!(
            "{}.{}.sig",
            URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\"}"),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    }

    #[test]
    fn id_tokens_are_checked_against_issuer_client_time_and_nonce() {
        let good = json!({"iss": "https://id.example.test", "aud": "rmail", "exp": 1000, "nonce": "n", "email": "Ann@Example.test", "email_verified": true});
        assert_eq!(
            check_id_token(&token(good.clone()), &provider(), &config(), "n", 900).unwrap(),
            Identity {
                email: "ann@example.test".into(),
                email_verified: true
            }
        );
        let with = |key: &str, value: Value| {
            let mut claims = good.clone();
            claims[key] = value;
            check_id_token(&token(claims), &provider(), &config(), "n", 900)
        };
        assert!(with("iss", json!("https://evil.test")).is_err());
        assert!(with("aud", json!("other")).is_err());
        assert!(
            with("aud", json!(["other", "rmail"])).is_err(),
            "several audiences need azp"
        );
        assert!(with("exp", json!(800)).is_err());
        assert!(with("nonce", json!("m")).is_err());
        assert!(!with("email_verified", json!(null)).unwrap().email_verified);
        assert!(check_id_token("garbage", &provider(), &config(), "n", 900).is_err());
    }

    #[test]
    fn issuers_are_checked_when_saved() {
        assert!(validate_config(&config()).is_ok());
        let issuer = |issuer: &str| OidcConfig {
            issuer: issuer.into(),
            ..config()
        };
        assert!(validate_config(&issuer("http://id.example.test")).is_err());
        assert!(validate_config(&issuer("not a url")).is_err());
        assert!(validate_config(&issuer("")).is_ok(), "empty until set up");
    }

    #[test]
    fn urls_must_be_https_but_loopback() {
        assert!(check_url("https://id.example.test/x").is_ok());
        assert!(check_url("http://127.0.0.1:8080/x").is_ok());
        assert!(check_url("http://localhost/x").is_ok());
        assert!(check_url("http://id.example.test/x").is_err());
        let url = authorize_url(
            &provider(),
            &config(),
            "https://mail.test/api/oidc/callback",
            "st",
            "no",
            "ver",
        )
        .unwrap();
        assert!(url.starts_with("https://id.example.test/auth?response_type=code&client_id=rmail"));
        assert!(url.contains("code_challenge_method=S256") && url.contains(&challenge("ver")));
        assert!(!configured(&OidcConfig {
            client_secret: None,
            ..config()
        }));
    }
}
