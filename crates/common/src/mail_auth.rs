use anyhow::{Context, Result, anyhow, bail};
use mail_auth::dmarc::{Dmarc, Policy, verify::DmarcParameters};
use mail_auth::spf::verify::SpfParameters;
use mail_auth::{AuthenticatedMessage, DkimResult, DmarcResult, MessageAuthenticator, SpfResult};
use once_cell::sync::OnceCell;
use std::borrow::Cow;
use std::net::IpAddr;

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

/// Resolve `name` to its A/AAAA addresses with the shared resolver. NXDOMAIN
/// and other failures are errors.
pub async fn lookup_ip_addrs(name: &str) -> Result<Vec<IpAddr>> {
    let name = if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    };
    let started = std::time::Instant::now();
    let result = authenticator()?.resolver().lookup_ip(name).await;
    crate::metrics::observe_dns_duration(started.elapsed());
    Ok(result?.iter().collect())
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

/// Add a DKIM signature from every key stored for the envelope sender's
/// domain (see `crate::dkim`). Without a registered key database, or keys for
/// the domain, the message is left unsigned; a failing key stops it from
/// entering the queue.
pub fn sign_outbound<'a>(data: &'a [u8], envelope_from: Option<&str>) -> Result<Cow<'a, [u8]>> {
    let Some(sender_domain) = envelope_from
        .and_then(|sender| sender.rsplit_once('@'))
        .map(|(_, domain)| domain)
    else {
        return Ok(Cow::Borrowed(data));
    };
    let Some(db_path) = crate::dkim::database() else {
        return Ok(Cow::Borrowed(data));
    };
    sign_with_keys(&db_path, data, sender_domain)
}

fn sign_with_keys<'a>(
    db_path: &std::path::Path,
    data: &'a [u8],
    sender_domain: &str,
) -> Result<Cow<'a, [u8]>> {
    let mut headers = String::new();
    for key in crate::dkim::keys_for_domain(db_path, sender_domain)? {
        headers.push_str(&dkim_signature(&key, data)?);
    }
    if headers.is_empty() {
        return Ok(Cow::Borrowed(data));
    }
    let mut signed = Vec::with_capacity(headers.len() + data.len());
    signed.extend_from_slice(headers.as_bytes());
    signed.extend_from_slice(data);
    Ok(Cow::Owned(signed))
}

/// The DKIM-Signature header `key` adds to `data`.
fn dkim_signature(key: &crate::dkim::DkimKey, data: &[u8]) -> Result<String> {
    use crate::dkim::SigningKey;
    use mail_auth::common::headers::HeaderWriter;
    use mail_auth::dkim::DkimSigner;
    let headers = crate::dkim::SIGNED_HEADERS.iter().copied();
    let signature = match crate::dkim::parse_key(&key.private_key)? {
        SigningKey::Rsa(signing) => DkimSigner::from_key(signing)
            .domain(key.domain.clone())
            .selector(key.selector.clone())
            .headers(headers)
            .sign(data),
        SigningKey::Ed25519(signing) => DkimSigner::from_key(signing)
            .domain(key.domain.clone())
            .selector(key.selector.clone())
            .headers(headers)
            .sign(data),
    }
    .with_context(|| format!("signing with {}", key.dns_name()))?;
    Ok(signature.to_header())
}

/// Add an ARC set when a message is being forwarded by a local alias or
/// catchall. An absent ARC signer leaves the message untouched. A failed ARC
/// chain is deliberately not extended.
pub async fn seal_forwarded<'a>(
    db_path: Option<&std::path::Path>,
    data: &'a [u8],
    peer_ip: IpAddr,
    helo_domain: &str,
    host_domain: &str,
    mail_from: Option<&str>,
) -> Result<Cow<'a, [u8]>> {
    let Some(db_path) = db_path else {
        return Ok(Cow::Borrowed(data));
    };
    let Some(arc_key) = crate::dkim::arc_key(db_path)? else {
        return Ok(Cow::Borrowed(data));
    };
    // ARC verifiers expect rsa-sha256 (RFC 8617 section 4.1.3).
    let crate::dkim::SigningKey::Rsa(key) = crate::dkim::parse_key(&arc_key.private_key)? else {
        bail!("the ARC key {} is not RSA", arc_key.dns_name());
    };
    let domain = arc_key.domain.clone();

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
    use mail_auth::arc::ArcSealer;
    use mail_auth::common::headers::HeaderWriter;
    let arc_set = ArcSealer::from_key(key)
        .domain(domain.clone())
        .selector(arc_key.selector.clone())
        .headers(crate::dkim::ARC_SIGNED_HEADERS.iter().copied())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key_db() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rmail.db");
        crate::db::init_db(&path).unwrap();
        (dir, path)
    }

    #[test]
    fn domains_can_be_signed_with_rsa_and_ed25519_together() {
        use crate::dkim::Algorithm;
        let (_dir, db) = key_db();
        crate::dkim::add_key(
            &db,
            "example.test",
            "rsa1",
            Algorithm::Rsa,
            Some(TEST_RSA_KEY),
        )
        .unwrap();
        crate::dkim::add_key(&db, "example.test", "ed1", Algorithm::Ed25519, None).unwrap();
        let message = b"From: a@example.test\r\nTo: b@example.net\r\nSubject: hi\r\n\r\nbody\r\n";
        let signed = sign_with_keys(&db, message, "example.test").unwrap();
        let signed = String::from_utf8(signed.into_owned()).unwrap();
        assert_eq!(signed.matches("DKIM-Signature:").count(), 2, "{signed}");
        assert!(signed.contains("a=rsa-sha256"), "{signed}");
        assert!(signed.contains("a=ed25519-sha256"), "{signed}");
        assert!(signed.contains("s=ed1"), "{signed}");
        assert!(signed.ends_with("\r\n\r\nbody\r\n"));
        // Other domains stay unsigned.
        let other = sign_with_keys(&db, message, "other.test").unwrap();
        assert!(matches!(other, Cow::Borrowed(_)));
    }

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

    fn configure_arc() -> (tempfile::TempDir, std::path::PathBuf) {
        let (dir, db) = key_db();
        crate::dkim::add_key(
            &db,
            "forwarder.example",
            "arc1",
            crate::dkim::Algorithm::Rsa,
            Some(TEST_RSA_KEY),
        )
        .unwrap();
        crate::dkim::set_arc_key(&db, Some(("forwarder.example", "arc1"))).unwrap();
        (dir, db)
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
        let (_dir, db) = configure_arc();
        let message =
            b"From: sender@localhost\r\nTo: list@localhost\r\nSubject: forwarded\r\n\r\nbody\r\n";

        let sealed = seal_forwarded(
            Some(&db),
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
        let (_dir, db) = configure_arc();
        let message = b"ARC-Seal: i=2; a=rsa-sha256; d=bad.example; s=x; cv=pass; b=AA==\r\nFrom: sender@localhost\r\nTo: list@localhost\r\nSubject: broken\r\n\r\nbody\r\n";

        let output = seal_forwarded(
            Some(&db),
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
        let (_dir, db) = key_db();
        let message = b"From: sender@example.test\r\n\r\nbody\r\n";
        let output = seal_forwarded(
            Some(&db),
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
