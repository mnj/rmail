use anyhow::{Context, Result, anyhow};
use mail_auth::dmarc::{Dmarc, Policy, verify::DmarcParameters};
use mail_auth::spf::verify::SpfParameters;
use mail_auth::{AuthenticatedMessage, DkimResult, DmarcResult, MessageAuthenticator, SpfResult};
use once_cell::sync::OnceCell;
use serde::Deserialize;
use std::borrow::Cow;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

static AUTHENTICATOR: OnceCell<MessageAuthenticator> = OnceCell::new();

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AuthenticationResults {
    pub dkim: Option<String>,
    pub spf: Option<String>,
    pub dmarc: Option<String>,
    pub arc: Option<String>,
    pub header_from: Option<String>,
}

fn authenticator() -> Result<&'static MessageAuthenticator> {
    AUTHENTICATOR.get_or_try_init(|| {
        MessageAuthenticator::new_system_conf().context("loading the system DNS configuration")
    })
}

/// Verify DKIM, ARC, SPF and DMARC using the system's asynchronous DNS resolver.
///
/// The message is borrowed throughout verification; callers do not need to clone
/// its body or move the work onto a blocking thread.
pub async fn analyze_message(
    data: &[u8],
    peer_ip: Option<IpAddr>,
    helo_domain: Option<&str>,
    host_domain: &str,
    mail_from: Option<&str>,
) -> Result<AuthenticationResults> {
    let message = AuthenticatedMessage::parse(data)
        .ok_or_else(|| anyhow!("message does not contain valid RFC 5322 headers"))?;
    let resolver = authenticator()?;

    let dkim_output = resolver.verify_dkim(&message).await;
    let arc_output = resolver.verify_arc(&message).await;
    let dkim = aggregate_dkim(&dkim_output);
    let arc = dkim_result_name(arc_output.result());

    let helo_domain = helo_domain
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown");
    let sender = mail_from.filter(|value| !value.is_empty()).unwrap_or("");
    let spf_output = if let Some(peer_ip) = peer_ip {
        resolver
            .verify_spf(SpfParameters::verify_mail_from(
                peer_ip,
                helo_domain,
                host_domain,
                sender,
            ))
            .await
    } else {
        mail_auth::SpfOutput::new(
            sender
                .rsplit_once('@')
                .map_or(helo_domain, |(_, domain)| domain)
                .to_string(),
        )
    };
    let spf = Some(spf_result_name(spf_output.result()).to_string());

    let envelope_domain = sender
        .rsplit_once('@')
        .map_or(helo_domain, |(_, domain)| domain);
    let dmarc_output = resolver
        .verify_dmarc(DmarcParameters {
            message: &message,
            dkim_output: &dkim_output,
            dkim2_output: None,
            rfc5321_mail_from_domain: envelope_domain,
            spf_output: &spf_output,
        })
        .await;
    let dmarc = Some(dmarc_disposition(&dmarc_output).to_string());

    Ok(AuthenticationResults {
        dkim,
        spf,
        dmarc,
        arc,
        header_from: message.from.first().cloned(),
    })
}

fn aggregate_dkim(outputs: &[mail_auth::DkimOutput<'_>]) -> Option<String> {
    if outputs.is_empty() {
        return Some("none".to_string());
    }
    if outputs
        .iter()
        .any(|output| output.result() == &DkimResult::Pass)
    {
        return Some("pass".to_string());
    }
    let result = outputs
        .iter()
        .map(|output| output.result())
        .find(|result| matches!(result, DkimResult::TempError(_)))
        .unwrap_or_else(|| outputs[0].result());
    dkim_result_name(result)
}

fn dkim_result_name(result: &DkimResult) -> Option<String> {
    Some(
        match result {
            DkimResult::Pass => "pass",
            DkimResult::Fail(_) => "fail",
            DkimResult::PermError(_) => "permerror",
            DkimResult::TempError(_) => "temperror",
            DkimResult::Neutral(_) => "neutral",
            DkimResult::None => "none",
        }
        .to_string(),
    )
}

fn spf_result_name(result: SpfResult) -> &'static str {
    match result {
        SpfResult::Pass => "pass",
        SpfResult::Fail => "fail",
        SpfResult::SoftFail => "softfail",
        SpfResult::Neutral => "neutral",
        SpfResult::TempError => "temperror",
        SpfResult::PermError => "permerror",
        SpfResult::None => "none",
    }
}

fn dmarc_disposition(output: &mail_auth::DmarcOutput) -> &'static str {
    if output.dkim_result() == &DmarcResult::Pass || output.spf_result() == &DmarcResult::Pass {
        return "pass";
    }
    if matches!(
        output.dkim_result(),
        DmarcResult::TempError(_) | DmarcResult::PermError(_)
    ) || matches!(
        output.spf_result(),
        DmarcResult::TempError(_) | DmarcResult::PermError(_)
    ) {
        return "temperror";
    }
    match output.policy() {
        Policy::Reject => "reject",
        Policy::Quarantine => "quarantine",
        Policy::None | Policy::Unspecified => "none",
    }
}

/// Parse the DMARC record and return its aggregate-report mailboxes.
pub async fn get_dmarc_rua(domain: &str) -> Result<Vec<String>> {
    let domain = crate::domain::canonicalize_domain(domain)?;
    let record = authenticator()?
        .txt_lookup::<Dmarc>(format!("_dmarc.{domain}"), None::<&NoResolverCache>)
        .await;
    let Ok(record) = record else {
        return Ok(Vec::new());
    };
    Ok(record
        .rua()
        .iter()
        .filter_map(|uri| uri.uri.strip_prefix("mailto:"))
        .map(str::to_string)
        .collect())
}

/// Retrieve the published DMARC policy for a domain, if one exists.
pub async fn get_dmarc_policy(domain: &str) -> Result<Option<String>> {
    let domain = crate::domain::canonicalize_domain(domain)?;
    let record = authenticator()?
        .txt_lookup::<Dmarc>(format!("_dmarc.{domain}"), None::<&NoResolverCache>)
        .await;
    Ok(record.ok().map(|record| record.p.to_string()))
}

// The resolver API needs a concrete cache type even when no cache is supplied.
type NoResolverCache = mail_auth::common::cache::NoCache<Box<str>, mail_auth::Txt>;

#[derive(Debug, Deserialize)]
struct SigningFile {
    #[serde(default)]
    signer: Vec<SigningEntry>,
}

#[derive(Debug, Deserialize)]
struct SigningEntry {
    domain: String,
    selector: String,
    private_key: String,
    #[serde(default = "default_signed_headers")]
    headers: Vec<String>,
}

fn default_signed_headers() -> Vec<String> {
    [
        "From",
        "To",
        "Subject",
        "Date",
        "Message-ID",
        "MIME-Version",
        "Content-Type",
    ]
    .map(str::to_string)
    .to_vec()
}

/// Add a DKIM signature for a configured envelope-sender domain.
///
/// Configuration is read from `<mail_root>/dkim.toml`. An absent file disables
/// signing; a present but invalid configuration fails queue publication.
pub fn sign_outbound<'a>(
    mail_root: &Path,
    data: &'a [u8],
    envelope_from: Option<&str>,
) -> Result<Cow<'a, [u8]>> {
    let Some(sender_domain) = envelope_from
        .and_then(|sender| sender.rsplit_once('@'))
        .map(|(_, domain)| domain)
    else {
        return Ok(Cow::Borrowed(data));
    };
    let config_path = mail_root.join("dkim.toml");
    let config = match fs::read_to_string(&config_path) {
        Ok(config) => config,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Cow::Borrowed(data));
        }
        Err(error) => return Err(error).context("reading DKIM signing configuration"),
    };
    let config: SigningFile = toml::from_str(&config).context("parsing dkim.toml")?;
    let Some(entry) = config
        .signer
        .iter()
        .find(|entry| entry.domain.eq_ignore_ascii_case(sender_domain))
    else {
        return Ok(Cow::Borrowed(data));
    };

    let domain = crate::domain::canonicalize_domain(&entry.domain)?;
    if entry.selector.is_empty()
        || !entry
            .selector
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        anyhow::bail!("invalid DKIM selector for {domain}");
    }
    let key_path = Path::new(&entry.private_key);
    ensure_private_key_permissions(key_path)?;
    let pem = fs::read(key_path).context("reading DKIM private key")?;
    use mail_auth::common::crypto::{RsaKey, Sha256};
    use mail_auth::common::headers::HeaderWriter;
    use mail_auth::dkim::DkimSigner;
    use rustls_pki_types::pem::PemObject;
    let key_der = rustls_pki_types::PrivateKeyDer::from_pem_slice(&pem)
        .context("parsing DKIM private key PEM")?;
    let key = RsaKey::<Sha256>::from_key_der(key_der).context("loading RSA DKIM private key")?;
    let signature = DkimSigner::from_key(key)
        .domain(domain)
        .selector(entry.selector.clone())
        .headers(entry.headers.iter().map(String::as_str))
        .sign(data)
        .context("signing outbound message")?;
    let header = signature.to_header();
    let mut signed = Vec::with_capacity(header.len() + data.len());
    signed.extend_from_slice(header.as_bytes());
    signed.extend_from_slice(data);
    Ok(Cow::Owned(signed))
}

#[cfg(unix)]
fn ensure_private_key_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let mode = fs::metadata(path)
        .context("reading DKIM private key metadata")?
        .mode();
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "DKIM private key {} must not be accessible by group or other users",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_key_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_result_names_are_stable() {
        assert_eq!(spf_result_name(SpfResult::SoftFail), "softfail");
        assert_eq!(dkim_result_name(&DkimResult::Pass).as_deref(), Some("pass"));
    }

    #[test]
    fn dkim_aggregation_prefers_any_valid_signature() {
        let outputs = [
            mail_auth::DkimOutput::fail(mail_auth::Error::ParseError),
            mail_auth::DkimOutput::pass(),
        ];
        assert_eq!(aggregate_dkim(&outputs).as_deref(), Some("pass"));
    }
}
