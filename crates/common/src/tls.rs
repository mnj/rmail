use crate::config::{Global, TlsMinimumVersion, TlsPolicy};
use anyhow::Context;
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::{fs, fs::File, io::BufReader, sync::Arc};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{Certificate, PrivateKey, ServerConfig, SupportedCipherSuite},
};

#[derive(Clone)]
pub struct ServerTlsContext {
    pub acceptor: TlsAcceptor,
}

pub struct ServerTlsMaterial {
    pub certificates: Vec<Certificate>,
    pub private_key: PrivateKey,
    pub leaf_der: Vec<u8>,
    pub ocsp_response: Vec<u8>,
}

const MAX_OCSP_RESPONSE_BYTES: u64 = 1024 * 1024;

pub type ServerTlsSender = tokio::sync::watch::Sender<Option<Arc<ServerTlsContext>>>;
pub type ServerTlsReceiver = tokio::sync::watch::Receiver<Option<Arc<ServerTlsContext>>>;

pub fn web_tls_channel(global: &Global) -> anyhow::Result<(ServerTlsSender, ServerTlsReceiver)> {
    let context = if global.tls.web_http_only {
        None
    } else {
        match (&global.tls_cert, &global.tls_key) {
            (None, None) => None,
            (Some(cert), Some(key)) => Some(load_server_tls_context(cert, key, &global.tls)?),
            _ => anyhow::bail!("TLS certificate and key must both be configured"),
        }
    };
    Ok(tokio::sync::watch::channel(context))
}

pub fn spawn_web_tls_reloader(
    sender: ServerTlsSender,
    cert_path: Option<String>,
    key_path: Option<String>,
    policy: TlsPolicy,
    component: &'static str,
) {
    if policy.web_http_only {
        return;
    }
    let (Some(cert_path), Some(key_path)) = (cert_path, key_path) else {
        return;
    };
    #[cfg(unix)]
    tokio::spawn(async move {
        let Ok(mut signal) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        else {
            eprintln!("{component}: failed to install SIGHUP TLS reload handler");
            return;
        };
        while signal.recv().await.is_some() {
            match reload_server_tls_context(&sender, &cert_path, &key_path, &policy) {
                Ok(()) => println!("{component}: reloaded TLS certificate, key, and OCSP bundle"),
                Err(error) => eprintln!(
                    "{component}: TLS reload failed; keeping current TLS bundle: {error:#}"
                ),
            }
        }
    });
}

pub fn load_server_tls_context(
    cert_path: &str,
    key_path: &str,
    policy: &TlsPolicy,
) -> anyhow::Result<Arc<ServerTlsContext>> {
    let material = load_server_tls_material(cert_path, key_path, policy.ocsp_response.as_deref())?;
    let config = build_server_config(material, policy)?;
    Ok(Arc::new(ServerTlsContext {
        acceptor: TlsAcceptor::from(Arc::new(config)),
    }))
}

pub fn load_server_tls_material(
    cert_path: &str,
    key_path: &str,
    ocsp_path: Option<&str>,
) -> anyhow::Result<ServerTlsMaterial> {
    let mut cert_reader = BufReader::new(File::open(cert_path).context("opening cert file")?);
    let certificates = certs(&mut cert_reader).context("reading certs")?;
    if certificates.is_empty() {
        anyhow::bail!("no certificates found in cert file");
    }
    let leaf_der = certificates[0].clone();
    let certificates = certificates.into_iter().map(Certificate).collect();

    let mut key_reader = BufReader::new(File::open(key_path).context("opening key file")?);
    let mut keys = pkcs8_private_keys(&mut key_reader).context("reading pkcs8 keys")?;
    if keys.is_empty() {
        let mut key_reader =
            BufReader::new(File::open(key_path).context("reopening key file for rsa")?);
        keys = rsa_private_keys(&mut key_reader).context("reading rsa keys")?;
    }
    let private_key = keys
        .into_iter()
        .next()
        .map(PrivateKey)
        .context("no private keys found in key file")?;

    let ocsp_response = match ocsp_path {
        Some(path) => {
            let metadata = fs::metadata(path).context("reading OCSP response metadata")?;
            if metadata.len() == 0 {
                anyhow::bail!("OCSP response file is empty");
            }
            if metadata.len() > MAX_OCSP_RESPONSE_BYTES {
                anyhow::bail!("OCSP response exceeds 1 MiB safety limit");
            }
            fs::read(path).context("reading DER OCSP response")?
        }
        None => Vec::new(),
    };
    Ok(ServerTlsMaterial {
        certificates,
        private_key,
        leaf_der,
        ocsp_response,
    })
}

pub fn build_server_config(
    material: ServerTlsMaterial,
    policy: &TlsPolicy,
) -> anyhow::Result<ServerConfig> {
    let versions = match policy.minimum_version {
        TlsMinimumVersion::Tls12 => vec![
            &tokio_rustls::rustls::version::TLS13,
            &tokio_rustls::rustls::version::TLS12,
        ],
        TlsMinimumVersion::Tls13 => vec![&tokio_rustls::rustls::version::TLS13],
    };
    ServerConfig::builder()
        .with_cipher_suites(&cipher_suites(policy)?)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions)
        .context("configuring TLS versions and cipher suites")?
        .with_no_client_auth()
        .with_single_cert_with_ocsp_and_sct(
            material.certificates,
            material.private_key,
            material.ocsp_response,
            Vec::new(),
        )
        .context("creating server TLS config")
}

pub fn reload_server_tls_context(
    sender: &tokio::sync::watch::Sender<Option<Arc<ServerTlsContext>>>,
    cert_path: &str,
    key_path: &str,
    policy: &TlsPolicy,
) -> anyhow::Result<()> {
    sender.send_replace(Some(load_server_tls_context(cert_path, key_path, policy)?));
    Ok(())
}

fn cipher_suites(policy: &TlsPolicy) -> anyhow::Result<Vec<SupportedCipherSuite>> {
    if policy.cipher_suites.is_empty() {
        return Ok(tokio_rustls::rustls::DEFAULT_CIPHER_SUITES.to_vec());
    }
    policy
        .cipher_suites
        .iter()
        .map(|name| {
            tokio_rustls::rustls::ALL_CIPHER_SUITES
                .iter()
                .copied()
                .find(|suite| format!("{:?}", suite.suite()) == *name)
                .ok_or_else(|| anyhow::anyhow!("unsupported TLS cipher suite {name:?}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_cipher_suite() {
        let policy = TlsPolicy {
            cipher_suites: vec!["TLS_FAKE_SUITE".into()],
            ..TlsPolicy::default()
        };
        assert!(cipher_suites(&policy).is_err());
    }

    #[test]
    fn ocsp_response_is_required_to_be_nonempty_and_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let empty = temp.path().join("empty.der");
        File::create(&empty).unwrap();
        let cert_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/certs/localhost.crt"
        );
        let key_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/certs/localhost.key"
        );
        assert!(load_server_tls_material(cert_path, key_path, empty.to_str()).is_err());

        let oversized = temp.path().join("oversized.der");
        File::create(&oversized)
            .unwrap()
            .set_len(MAX_OCSP_RESPONSE_BYTES + 1)
            .unwrap();
        assert!(load_server_tls_material(cert_path, key_path, oversized.to_str()).is_err());
    }
}
