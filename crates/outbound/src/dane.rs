//! TLS for outbound SMTP sessions, with DANE (RFC 7672) when enabled.
//!
//! The handshake runs with OpenSSL peer verification off and the result is
//! checked afterwards against what the destination requires:
//! - DANE: a DNSSEC-secure TLSA RRset with usable DANE-TA(2) or DANE-EE(3)
//!   records must match the presented chain.
//! - PKIX: MTA-STS enforce and REQUIRETLS need a WebPKI chain valid for the
//!   MX host name.
//! - Mandatory: TLS is required but not authenticated (a secure TLSA RRset
//!   with no usable records, RFC 7672 section 2.2).
//! - Opportunistic: any certificate is accepted (RFC 7435); the session only
//!   records whether it happened to verify.
//!
//! DNSSEC status comes from the AD bit of the system's recursive resolver,
//! as in Postfix: run a local validating resolver (unbound, for example) for
//! DANE to apply. A resolver that does not validate never sets AD, so DANE
//! never applies and nothing is deferred because of it.

use anyhow::{Result, bail};
use hickory_resolver::proto::op::{Edns, Message, Query, ResponseCode};
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::system_conf::read_system_conf;
use openssl::sha::{sha256, sha512};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::stack::StackRef;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::{X509VerifyFlags, X509VerifyParam};
use openssl::x509::{X509, X509Ref, X509StoreContext, X509VerifyResult};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::OnceCell;
use tokio_openssl::SslStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TlsaRecord {
    pub usage: u8,
    pub selector: u8,
    pub mtype: u8,
    pub data: Vec<u8>,
}

impl TlsaRecord {
    /// RFC 7672 section 3.1: SMTP uses only DANE-TA(2) and DANE-EE(3), with
    /// the standard selectors and matching types.
    fn usable(&self) -> bool {
        matches!(self.usage, 2 | 3) && self.selector <= 1 && self.mtype <= 2
    }

    fn matches(&self, cert: &X509Ref) -> bool {
        let target = match self.selector {
            0 => cert.to_der(),
            _ => cert.public_key().and_then(|key| key.public_key_to_der()),
        };
        let Ok(target) = target else {
            return false;
        };
        match self.mtype {
            0 => target == self.data,
            1 => sha256(&target).as_slice() == self.data.as_slice(),
            2 => sha512(&target).as_slice() == self.data.as_slice(),
            _ => false,
        }
    }
}

/// What a destination host's DNS says about DANE.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DaneLookup {
    /// No DNSSEC-secure TLSA RRset: DANE does not apply.
    NotApplicable,
    /// A secure TLSA RRset; holds its usable records, possibly none.
    Secure(Vec<TlsaRecord>),
}

/// How a session's TLS must be authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TlsRequirement<'a> {
    Opportunistic,
    Mandatory,
    Pkix,
    Dane(&'a [TlsaRecord]),
}

impl TlsRequirement<'_> {
    pub(crate) fn needs_tls(&self) -> bool {
        !matches!(self, Self::Opportunistic)
    }

    /// Whether a session authenticated as `auth` may carry this delivery.
    pub(crate) fn satisfied_by(&self, auth: TlsAuth) -> bool {
        match self {
            Self::Opportunistic => true,
            Self::Mandatory => auth != TlsAuth::Plaintext,
            Self::Pkix => auth == TlsAuth::Pkix,
            Self::Dane(_) => auth == TlsAuth::Dane,
        }
    }

    /// RFC 8460 policy type for reports about this session.
    pub(crate) fn report_policy(&self) -> Option<&'static str> {
        match self {
            Self::Dane(_) | Self::Mandatory => Some("tlsa"),
            _ => None,
        }
    }
}

/// How an established session's peer was authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TlsAuth {
    Plaintext,
    Unauthenticated,
    Pkix,
    Dane,
}

static NAME_SERVERS: OnceCell<Vec<IpAddr>> = OnceCell::const_new();
const DNS_TIMEOUT: Duration = Duration::from_secs(10);

async fn name_servers() -> Result<&'static [IpAddr]> {
    NAME_SERVERS
        .get_or_try_init(|| async {
            let (config, _) = read_system_conf().map_err(|error| {
                anyhow::anyhow!("reading the system DNS configuration: {error}")
            })?;
            let mut servers = Vec::new();
            for server in config.name_servers() {
                if !servers.contains(&server.ip) {
                    servers.push(server.ip);
                }
            }
            Ok(servers)
        })
        .await
        .map(Vec::as_slice)
}

/// A recursive resolver's answer.
struct Reply {
    code: ResponseCode,
    /// The resolver validated the answer with DNSSEC (the AD bit).
    authentic: bool,
    answers: Vec<Record>,
}

/// Ask the system resolvers for `name`/`record_type` with DNSSEC OK and AD
/// set (RFC 6840 section 5.7), over TCP since signed answers are large.
async fn query(name: &str, record_type: RecordType) -> Result<Reply> {
    let mut request = Message::query();
    request.metadata.id = rand_id();
    request.metadata.recursion_desired = true;
    request.metadata.authentic_data = true;
    request.add_query(Query::query(Name::from_ascii(name)?, record_type));
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true);
    edns.set_max_payload(1232);
    request.set_edns(edns);
    let wire = request.to_vec()?;

    let mut last_error = None;
    for server in name_servers().await? {
        match tokio::time::timeout(DNS_TIMEOUT, exchange(*server, &wire)).await {
            Ok(Ok(response)) if response.metadata.id == request.metadata.id => {
                return Ok(Reply {
                    code: response.metadata.response_code,
                    authentic: response.metadata.authentic_data,
                    answers: response.answers,
                });
            }
            Ok(Ok(_)) => last_error = Some(anyhow::anyhow!("{server}: mismatched DNS reply id")),
            Ok(Err(error)) => last_error = Some(error.context(format!("{server}"))),
            Err(_) => last_error = Some(anyhow::anyhow!("{server}: DNS query timed out")),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no DNS servers configured")))
}

async fn exchange(server: IpAddr, wire: &[u8]) -> Result<Message> {
    let mut stream = TcpStream::connect(SocketAddr::new(server, 53)).await?;
    let length = u16::try_from(wire.len())?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(wire).await?;
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).await?;
    let mut buffer = vec![0u8; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut buffer).await?;
    Ok(Message::from_vec(&buffer)?)
}

fn rand_id() -> u16 {
    let mut id = [0u8; 2];
    openssl::rand::rand_bytes(&mut id).expect("OpenSSL random bytes");
    u16::from_ne_bytes(id)
}

fn has(reply: &Reply, record_type: RecordType) -> bool {
    reply
        .answers
        .iter()
        .any(|record| record.record_type() == record_type)
}

/// Whether `domain`'s MX RRset is DNSSEC-secure. Only then are the MX host
/// names trustworthy TLSA base domains (RFC 7672 section 2.2.1). With no MX
/// the domain itself is the host, and `tlsa_for` checks its addresses.
pub(crate) async fn mx_is_secure(domain: &str) -> Result<bool> {
    let reply = query(
        &format!("{}.", domain.trim_end_matches('.')),
        RecordType::MX,
    )
    .await?;
    Ok(match reply.code {
        ResponseCode::NoError | ResponseCode::NXDomain => reply.authentic,
        // The ordinary MX lookup reports resolver failures.
        _ => false,
    })
}

/// The TLSA records for `host`:`port`, when DANE applies to it.
///
/// DANE applies only when the host's address records and its TLSA RRset are
/// DNSSEC-secure. An insecure or absent answer means no DANE. A failed TLSA
/// lookup (a validating resolver answers SERVFAIL for bogus data) is an
/// error, and the host must not be used (RFC 7672 section 2.2).
pub(crate) async fn tlsa_for(host: &str, port: u16) -> Result<DaneLookup> {
    let fqdn = format!("{}.", host.trim_end_matches('.'));
    for record_type in [RecordType::A, RecordType::AAAA] {
        let reply = query(&fqdn, record_type).await?;
        // Unresolvable hosts fail when connecting; insecure ones get no DANE.
        if reply.code != ResponseCode::NoError || !reply.authentic {
            return Ok(DaneLookup::NotApplicable);
        }
    }

    let reply = query(&format!("_{port}._tcp.{fqdn}"), RecordType::TLSA).await?;
    match reply.code {
        ResponseCode::NoError if has(&reply, RecordType::TLSA) => {}
        ResponseCode::NoError | ResponseCode::NXDomain => return Ok(DaneLookup::NotApplicable),
        ResponseCode::ServFail => {
            bail!("TLSA lookup for {host} failed (SERVFAIL, possibly DNSSEC validation)")
        }
        code => bail!("TLSA lookup for {host} failed: {code}"),
    }
    if !reply.authentic {
        return Ok(DaneLookup::NotApplicable);
    }
    let records = reply
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::TLSA(tlsa) => Some(TlsaRecord {
                usage: tlsa.cert_usage.into(),
                selector: tlsa.selector.into(),
                mtype: tlsa.matching.into(),
                data: tlsa.cert_data.clone(),
            }),
            _ => None,
        })
        .filter(TlsaRecord::usable)
        .collect();
    Ok(DaneLookup::Secure(records))
}

/// Check a presented chain against usable TLSA records (RFC 7672 section 3).
///
/// DANE-EE(3) matches the leaf and ignores names and validity dates.
/// DANE-TA(2) matches a certificate in the chain, which then anchors normal
/// chain validation of the leaf, including validity dates and the name
/// `host`.
pub(crate) fn verify_dane(
    records: &[TlsaRecord],
    leaf: &X509Ref,
    chain: Option<&StackRef<X509>>,
    host: &str,
) -> bool {
    if records
        .iter()
        .any(|record| record.usage == 3 && record.matches(leaf))
    {
        return true;
    }
    let Some(chain) = chain else {
        return false;
    };
    let leaf_der = leaf.to_der().ok();
    for anchor in chain.iter() {
        // A DANE-TA record names an issuer, not the leaf itself.
        if anchor.to_der().ok() == leaf_der {
            continue;
        }
        if records
            .iter()
            .any(|record| record.usage == 2 && record.matches(anchor))
            && chain_anchored_at(leaf, chain, anchor, host).unwrap_or(false)
        {
            return true;
        }
    }
    false
}

fn chain_anchored_at(
    leaf: &X509Ref,
    chain: &StackRef<X509>,
    anchor: &X509Ref,
    host: &str,
) -> Result<bool> {
    let mut store = X509StoreBuilder::new()?;
    store.add_cert(anchor.to_owned())?;
    let mut param = X509VerifyParam::new()?;
    // The anchor need not be self-signed.
    param.set_flags(X509VerifyFlags::PARTIAL_CHAIN)?;
    param.set_host(host.trim_end_matches('.'))?;
    store.set_param(&param)?;
    let store = store.build();
    let mut context = X509StoreContext::new()?;
    Ok(context.init(&store, leaf, chain, |context| context.verify_cert())?)
}

/// Run the client TLS handshake on `stream` and authenticate the peer as
/// `requirement` demands.
pub(crate) async fn connect<S>(
    stream: S,
    host: &str,
    requirement: TlsRequirement<'_>,
) -> Result<(SslStream<S>, TlsAuth)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let host = host.trim_end_matches('.');
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    // Verification happens after the handshake so opportunistic sessions
    // still encrypt with self-signed or mismatched certificates.
    builder.set_verify(SslVerifyMode::NONE);
    let ssl = builder.build().configure()?.into_ssl(host)?;
    let mut tls = SslStream::new(ssl, stream)?;
    Pin::new(&mut tls)
        .connect()
        .await
        .map_err(|error| anyhow::anyhow!("TLS handshake with {host} failed: {error}"))?;

    let pkix = tls.ssl().verify_result();
    let auth = match requirement {
        TlsRequirement::Dane(records) => {
            let leaf = tls
                .ssl()
                .peer_certificate()
                .ok_or_else(|| anyhow::anyhow!("{host} presented no TLS certificate"))?;
            if !verify_dane(records, &leaf, tls.ssl().peer_cert_chain(), host) {
                bail!("TLS certificate from {host} does not match its DANE TLSA records");
            }
            TlsAuth::Dane
        }
        TlsRequirement::Pkix if pkix != X509VerifyResult::OK => {
            bail!(
                "TLS certificate verification failed for {host}: {}",
                pkix.error_string()
            );
        }
        _ if pkix == X509VerifyResult::OK => TlsAuth::Pkix,
        _ => TlsAuth::Unauthenticated,
    };
    Ok((tls, auth))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::stack::Stack;
    use openssl::x509::X509NameBuilder;
    use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};

    fn key() -> PKey<Private> {
        PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
    }

    fn cert(
        name: &str,
        key: &PKey<Private>,
        issuer: Option<(&X509, &PKey<Private>)>,
        ca: bool,
    ) -> X509 {
        let mut subject = X509NameBuilder::new().unwrap();
        subject.append_entry_by_text("CN", name).unwrap();
        let subject = subject.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        let serial = BigNum::from_u32(rand_serial()).unwrap().to_asn1_integer();
        builder.set_serial_number(&serial.unwrap()).unwrap();
        builder.set_subject_name(&subject).unwrap();
        builder
            .set_issuer_name(issuer.map_or(&subject, |(cert, _)| cert.subject_name()))
            .unwrap();
        builder.set_pubkey(key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();
        if ca {
            builder
                .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
        } else {
            let san = SubjectAlternativeName::new()
                .dns(name)
                .build(&builder.x509v3_context(issuer.map(|(cert, _)| &**cert), None))
                .unwrap();
            builder.append_extension(san).unwrap();
        }
        let signer = issuer.map_or(key, |(_, key)| key);
        builder.sign(signer, MessageDigest::sha256()).unwrap();
        builder.build()
    }

    fn rand_serial() -> u32 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    }

    fn record(usage: u8, selector: u8, cert: &X509) -> TlsaRecord {
        let target = if selector == 0 {
            cert.to_der().unwrap()
        } else {
            cert.public_key().unwrap().public_key_to_der().unwrap()
        };
        TlsaRecord {
            usage,
            selector,
            mtype: 1,
            data: sha256(&target).to_vec(),
        }
    }

    struct Pki {
        ca: X509,
        leaf: X509,
        chain: Stack<X509>,
    }

    fn pki(host: &str) -> Pki {
        let ca_key = key();
        let ca = cert("Test CA", &ca_key, None, true);
        let leaf = cert(host, &key(), Some((&ca, &ca_key)), false);
        let mut chain = Stack::new().unwrap();
        chain.push(leaf.clone()).unwrap();
        chain.push(ca.clone()).unwrap();
        Pki { ca, leaf, chain }
    }

    #[test]
    fn dane_ee_matches_the_leaf_key_regardless_of_name() {
        let pki = pki("mx.example.test");
        let records = [record(3, 1, &pki.leaf)];
        assert!(verify_dane(&records, &pki.leaf, None, "other.example.test"));
        let wrong = [record(3, 1, &pki.ca)];
        assert!(!verify_dane(
            &wrong,
            &pki.leaf,
            Some(&pki.chain),
            "mx.example.test"
        ));
    }

    #[test]
    fn dane_ta_anchors_chain_validation_including_the_name() {
        let pki = pki("mx.example.test");
        let records = [record(2, 0, &pki.ca)];
        assert!(verify_dane(
            &records,
            &pki.leaf,
            Some(&pki.chain),
            "mx.example.test"
        ));
        assert!(!verify_dane(
            &records,
            &pki.leaf,
            Some(&pki.chain),
            "evil.example.test"
        ));
        // A DANE-TA record for the leaf itself is not a trust anchor.
        let leaf_as_ta = [record(2, 0, &pki.leaf)];
        assert!(!verify_dane(
            &leaf_as_ta,
            &pki.leaf,
            Some(&pki.chain),
            "mx.example.test"
        ));
    }

    #[test]
    fn pkix_usages_are_unusable_for_smtp() {
        let pki = pki("mx.example.test");
        assert!(!record(1, 1, &pki.leaf).usable());
        assert!(!record(0, 0, &pki.ca).usable());
        assert!(record(3, 1, &pki.leaf).usable());
        assert!(record(2, 0, &pki.ca).usable());
    }

    #[test]
    fn requirements_accept_only_strong_enough_sessions() {
        let records = [];
        assert!(TlsRequirement::Opportunistic.satisfied_by(TlsAuth::Plaintext));
        assert!(!TlsRequirement::Mandatory.satisfied_by(TlsAuth::Plaintext));
        assert!(TlsRequirement::Mandatory.satisfied_by(TlsAuth::Unauthenticated));
        assert!(!TlsRequirement::Pkix.satisfied_by(TlsAuth::Unauthenticated));
        assert!(!TlsRequirement::Dane(&records).satisfied_by(TlsAuth::Pkix));
        assert!(TlsRequirement::Dane(&records).satisfied_by(TlsAuth::Dane));
    }

    /// Live DNS through a validating resolver (AD bit):
    /// `cargo test -p rmail_outbound live_dnssec -- --ignored`.
    #[tokio::test]
    #[ignore = "needs a validating recursive resolver"]
    async fn live_dnssec_secure_and_insecure_domains() {
        // Cloudflare validates; a local stub such as systemd-resolved may not.
        let _ = NAME_SERVERS.set(vec!["1.1.1.1".parse().unwrap()]);
        assert!(mx_is_secure("ietf.org").await.unwrap());
        assert!(!mx_is_secure("gmail.com").await.unwrap());
        match tlsa_for("mail2.ietf.org", 25).await.unwrap() {
            DaneLookup::Secure(records) => assert!(!records.is_empty()),
            other => panic!("expected TLSA for mail2.ietf.org: {other:?}"),
        }
        assert_eq!(
            tlsa_for("gmail-smtp-in.l.google.com", 25).await.unwrap(),
            DaneLookup::NotApplicable
        );
    }

    #[tokio::test]
    async fn opportunistic_tls_accepts_a_self_signed_certificate() {
        use openssl::ssl::SslAcceptor;
        let server_key = key();
        let server_cert = cert("mx.example.test", &server_key, None, false);
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acceptor.set_private_key(&server_key).unwrap();
        acceptor.set_certificate(&server_cert).unwrap();
        let acceptor = acceptor.build();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
            let mut tls = SslStream::new(ssl, server).unwrap();
            Pin::new(&mut tls).accept().await.unwrap();
        });
        let (_tls, auth) = connect(client, "mx.example.test", TlsRequirement::Opportunistic)
            .await
            .unwrap();
        assert_eq!(auth, TlsAuth::Unauthenticated);
        server.await.unwrap();

        let server_key = key();
        let server_cert = cert("mx.example.test", &server_key, None, false);
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acceptor.set_private_key(&server_key).unwrap();
        acceptor.set_certificate(&server_cert).unwrap();
        let acceptor = acceptor.build();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
            let mut tls = SslStream::new(ssl, server).unwrap();
            let _ = Pin::new(&mut tls).accept().await;
        });
        let records = [record(3, 1, &server_cert)];
        let (_tls, auth) = connect(client, "mx.example.test", TlsRequirement::Dane(&records))
            .await
            .unwrap();
        assert_eq!(auth, TlsAuth::Dane);
        server.await.unwrap();
    }
}
