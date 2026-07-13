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

/// Confirm that the configured asynchronous DNS resolver can complete a lookup.
pub async fn dns_health_check() -> Result<()> {
    let started = std::time::Instant::now();
    let result = authenticator()?.resolver().lookup_ip("localhost.").await;
    crate::metrics::observe_dns_duration(started.elapsed());
    result.context("resolving the DNS health-check name")?;
    Ok(())
}

/// Return true when a message has at least one RFC 5322 From mailbox and all
/// parsed From mailboxes match the authenticated submission identity.
pub fn submission_from_matches(data: &[u8], authenticated_user: &str) -> bool {
    let Ok(authenticated_user) = crate::domain::canonicalize_mailbox_address(authenticated_user)
    else {
        return false;
    };
    let Some(message) = AuthenticatedMessage::parse(data) else {
        return false;
    };
    !message.from.is_empty()
        && message.from.iter().all(|from| {
            crate::domain::canonicalize_mailbox_address(from)
                .is_ok_and(|from| from.eq_ignore_ascii_case(&authenticated_user))
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

    let started = std::time::Instant::now();
    let dkim_output = resolver.verify_dkim(&message).await;
    crate::metrics::observe_dns_duration(started.elapsed());
    let started = std::time::Instant::now();
    let arc_output = resolver.verify_arc(&message).await;
    crate::metrics::observe_dns_duration(started.elapsed());
    let dkim = aggregate_dkim(&dkim_output);
    let arc = dkim_result_name(arc_output.result());

    let helo_domain = helo_domain
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown");
    let sender = mail_from.filter(|value| !value.is_empty()).unwrap_or("");
    let spf_output = if let Some(peer_ip) = peer_ip {
        let started = std::time::Instant::now();
        let output = resolver
            .verify_spf(SpfParameters::verify_mail_from(
                peer_ip,
                helo_domain,
                host_domain,
                sender,
            ))
            .await;
        crate::metrics::observe_dns_duration(started.elapsed());
        output
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
    let started = std::time::Instant::now();
    let dmarc_output = resolver
        .verify_dmarc(DmarcParameters {
            message: &message,
            dkim_output: &dkim_output,
            dkim2_output: None,
            rfc5321_mail_from_domain: envelope_domain,
            spf_output: &spf_output,
        })
        .await;
    crate::metrics::observe_dns_duration(started.elapsed());
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
    let started = std::time::Instant::now();
    let record = authenticator()?
        .txt_lookup::<Dmarc>(format!("_dmarc.{domain}"), None::<&NoResolverCache>)
        .await;
    crate::metrics::observe_dns_duration(started.elapsed());
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
    let started = std::time::Instant::now();
    let record = authenticator()?
        .txt_lookup::<Dmarc>(format!("_dmarc.{domain}"), None::<&NoResolverCache>)
        .await;
    crate::metrics::observe_dns_duration(started.elapsed());
    Ok(record.ok().map(|record| record.p.to_string()))
}

// The resolver API needs a concrete cache type even when no cache is supplied.
type NoResolverCache = mail_auth::common::cache::NoCache<Box<str>, mail_auth::Txt>;

#[derive(Debug, Deserialize)]
struct SigningFile {
    #[serde(default)]
    signer: Vec<SigningEntry>,
    /// Local administrative identity used only when rMail forwards mail.
    arc_signer: Option<SigningEntry>,
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
    validate_signing_selector(&domain, &entry.selector)?;
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

/// Add an ARC set when a message is being forwarded by a local alias or
/// catchall. An absent ARC signer leaves the message untouched. A failed ARC
/// chain is deliberately not extended.
pub async fn seal_forwarded<'a>(
    mail_root: &Path,
    data: &'a [u8],
    peer_ip: IpAddr,
    helo_domain: &str,
    host_domain: &str,
    mail_from: Option<&str>,
) -> Result<Cow<'a, [u8]>> {
    let config_path = mail_root.join("dkim.toml");
    let config = match fs::read_to_string(&config_path) {
        Ok(config) => config,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Cow::Borrowed(data));
        }
        Err(error) => return Err(error).context("reading ARC signing configuration"),
    };
    let config: SigningFile = toml::from_str(&config).context("parsing dkim.toml")?;
    let Some(entry) = config.arc_signer.as_ref() else {
        return Ok(Cow::Borrowed(data));
    };
    let domain = crate::domain::canonicalize_domain(&entry.domain)?;
    validate_signing_selector(&domain, &entry.selector)?;
    let key_path = Path::new(&entry.private_key);
    ensure_private_key_permissions(key_path)?;

    let message = AuthenticatedMessage::parse(data)
        .ok_or_else(|| anyhow!("message does not contain valid RFC 5322 headers"))?;
    let resolver = authenticator()?;
    let arc_output = resolver.verify_arc(&message).await;
    if !arc_output.can_be_sealed()
        || (contains_arc_header(data) && arc_output.result() != &DkimResult::Pass)
    {
        return Ok(Cow::Borrowed(data));
    }
    let dkim_output = resolver.verify_dkim(&message).await;
    let sender = mail_from.filter(|value| !value.is_empty()).unwrap_or("");
    let spf_output = resolver
        .verify_spf(SpfParameters::verify_mail_from(
            peer_ip,
            helo_domain,
            host_domain,
            sender,
        ))
        .await;
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

    let header_from = message.from.first().map(String::as_str).unwrap_or("");
    let auth_results = mail_auth::AuthenticationResults::new(&domain)
        .with_dkim_results(&dkim_output, header_from)
        .with_spf_mailfrom_result(&spf_output, peer_ip, sender, helo_domain)
        .with_dmarc_result(&dmarc_output)
        .with_arc_result(&arc_output, peer_ip);
    let pem = fs::read(key_path).context("reading ARC private key")?;
    use mail_auth::arc::ArcSealer;
    use mail_auth::common::crypto::{RsaKey, Sha256};
    use mail_auth::common::headers::HeaderWriter;
    use rustls_pki_types::pem::PemObject;
    let key_der = rustls_pki_types::PrivateKeyDer::from_pem_slice(&pem)
        .context("parsing ARC private key PEM")?;
    let key = RsaKey::<Sha256>::from_key_der(key_der).context("loading RSA ARC private key")?;
    let arc_set = ArcSealer::from_key(key)
        .domain(domain.clone())
        .selector(entry.selector.clone())
        .headers(entry.headers.iter().map(String::as_str))
        .seal(&message, &auth_results, &arc_output)
        .context("sealing forwarded message")?;
    let headers = arc_set.to_header();
    let mut sealed = Vec::with_capacity(headers.len() + data.len());
    sealed.extend_from_slice(headers.as_bytes());
    sealed.extend_from_slice(data);
    crate::metrics::inc_arc_sealed();
    Ok(Cow::Owned(sealed))
}

fn contains_arc_header(data: &[u8]) -> bool {
    data.split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .take_while(|line| !line.is_empty())
        .any(|line| {
            [
                b"arc-seal:".as_slice(),
                b"arc-message-signature:".as_slice(),
                b"arc-authentication-results:".as_slice(),
            ]
            .iter()
            .any(|name| {
                line.get(..name.len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(name))
            })
        })
}

fn validate_signing_selector(domain: &str, selector: &str) -> Result<()> {
    if selector.is_empty()
        || !selector
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        anyhow::bail!("invalid signing selector for {domain}");
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_private_key_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let mode = fs::metadata(path)
        .context("reading DKIM private key metadata")?
        .mode();
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "mail signing private key {} must not be accessible by group or other users",
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

    const TEST_RSA_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIICXwIBAAKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFC
jxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gb
to/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB
AoGBALmn+XwWk7akvkUlqb+dOxyLB9i5VBVfje89Teolwc9YJT36BGN/l4e0l6QX
/1//6DWUTB3KI6wFcm7TWJcxbS0tcKZX7FsJvUz1SbQnkS54DJck1EZO/BLa5ckJ
gAYIaqlA9C0ZwM6i58lLlPadX/rtHb7pWzeNcZHjKrjM461ZAkEA+itss2nRlmyO
n1/5yDyCluST4dQfO8kAB3toSEVc7DeFeDhnC1mZdjASZNvdHS4gbLIA1hUGEF9m
3hKsGUMMPwJBAPW5v/U+AWTADFCS22t72NUurgzeAbzb1HWMqO4y4+9Hpjk5wvL/
eVYizyuce3/fGke7aRYw/ADKygMJdW8H/OcCQQDz5OQb4j2QDpPZc0Nc4QlbvMsj
7p7otWRO5xRa6SzXqqV3+F0VpqvDmshEBkoCydaYwc2o6WQ5EBmExeV8124XAkEA
qZzGsIxVP+sEVRWZmW6KNFSdVUpk3qzK0Tz/WjQMe5z0UunY9Ax9/4PVhp/j61bf
eAYXunajbBSOLlx4D+TunwJBANkPI5S9iylsbLs6NkaMHV6k5ioHBBmgCak95JGX
GMot/L2x0IYyMLAz6oLWh2hm7zwtb0CgOrPo1ke44hFYnfc=
-----END RSA PRIVATE KEY-----"#;

    fn configure_arc(directory: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let key = directory.join("arc.pem");
        fs::write(&key, TEST_RSA_KEY).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(
            directory.join("dkim.toml"),
            format!(
                "[arc_signer]\ndomain = \"forwarder.example\"\nselector = \"arc1\"\nprivate_key = {:?}\nheaders = [\"From\", \"To\", \"Subject\"]\n",
                key.to_string_lossy()
            ),
        )
        .unwrap();
    }

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

    #[test]
    fn submission_from_alignment_uses_parsed_mailboxes() {
        assert!(submission_from_matches(
            b"From: Display Name <User@B\xC3\x9CCHER.example>\r\nSubject: test\r\n\r\nbody",
            "user@xn--bcher-kva.example"
        ));
        assert!(!submission_from_matches(
            b"From: user@example.test, other@example.test\r\n\r\nbody",
            "user@example.test"
        ));
        assert!(!submission_from_matches(
            b"Subject: missing author\r\n\r\nbody",
            "user@example.test"
        ));
    }

    #[tokio::test]
    async fn forwarded_message_gets_complete_arc_set() {
        let directory = tempfile::tempdir().unwrap();
        configure_arc(directory.path());
        let message =
            b"From: sender@localhost\r\nTo: list@localhost\r\nSubject: forwarded\r\n\r\nbody\r\n";

        let sealed = seal_forwarded(
            directory.path(),
            message,
            "127.0.0.1".parse().unwrap(),
            "localhost",
            "localhost",
            None,
        )
        .await
        .unwrap()
        .into_owned();

        let text = String::from_utf8(sealed).unwrap();
        assert!(text.starts_with("ARC-Seal: i=1; a=rsa-sha256;"), "{text}");
        assert!(text.contains("\r\nARC-Message-Signature: i=1;"), "{text}");
        assert!(
            text.contains("\r\nARC-Authentication-Results: i=1;"),
            "{text}"
        );
        assert!(text.ends_with(std::str::from_utf8(message).unwrap()));
    }

    #[tokio::test]
    async fn broken_arc_chain_is_not_extended() {
        let directory = tempfile::tempdir().unwrap();
        configure_arc(directory.path());
        let message = b"ARC-Seal: i=2; a=rsa-sha256; d=bad.example; s=x; cv=pass; b=AA==\r\nFrom: sender@localhost\r\nTo: list@localhost\r\nSubject: broken\r\n\r\nbody\r\n";

        let output = seal_forwarded(
            directory.path(),
            message,
            "127.0.0.1".parse().unwrap(),
            "localhost",
            "localhost",
            None,
        )
        .await
        .unwrap();

        assert!(matches!(output, Cow::Borrowed(_)));
    }

    #[tokio::test]
    async fn absent_arc_configuration_leaves_forwarded_message_borrowed() {
        let directory = tempfile::tempdir().unwrap();
        let message = b"From: sender@example.test\r\n\r\nbody\r\n";
        let output = seal_forwarded(
            directory.path(),
            message,
            "127.0.0.1".parse().unwrap(),
            "localhost",
            "localhost",
            None,
        )
        .await
        .unwrap();
        assert!(matches!(output, Cow::Borrowed(_)));
    }
}
