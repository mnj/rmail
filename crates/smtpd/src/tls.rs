use anyhow::Context;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use rmail_common::config::{TlsMinimumVersion, TlsPolicy};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig, SupportedCipherSuite};

/// TLS acceptor wrapper that also stores the server_end_point (certificate fingerprint)
/// used for SCRAM channel-binding (tls-server-end-point). The fingerprint is the
/// SHA-256 digest of the server certificate DER bytes.
pub struct TlsContext {
    pub acceptor: TlsAcceptor,
}

#[cfg(test)]
pub fn load_tls_context(cert_path: &str, key_path: &str) -> anyhow::Result<Arc<TlsContext>> {
    load_tls_context_with_policy(cert_path, key_path, &TlsPolicy::default())
}

pub fn load_tls_context_with_policy(
    cert_path: &str,
    key_path: &str,
    policy: &TlsPolicy,
) -> anyhow::Result<Arc<TlsContext>> {
    let cert_file = File::open(cert_path).context("opening cert file")?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = certs(&mut cert_reader).context("reading certs")?;
    if certs.is_empty() {
        return Err(anyhow::anyhow!("no certificates found in cert file"));
    }
    let certs_wrapped = certs.iter().cloned().map(Certificate).collect::<Vec<_>>();

    let key_file = File::open(key_path).context("opening key file")?;
    let mut key_reader = BufReader::new(key_file);
    let mut keys = pkcs8_private_keys(&mut key_reader).context("reading pkcs8 keys")?;
    if keys.is_empty() {
        // try RSA keys
        let key_file = File::open(key_path).context("reopening key file for rsa")?;
        let mut key_reader = BufReader::new(key_file);
        keys = rsa_private_keys(&mut key_reader).context("reading rsa keys")?;
    }
    if keys.is_empty() {
        return Err(anyhow::anyhow!("no private keys found in key file"));
    }
    let key = PrivateKey(keys.remove(0));

    let cipher_suites = cipher_suites(policy)?;
    let versions = match policy.minimum_version {
        TlsMinimumVersion::Tls12 => vec![
            &tokio_rustls::rustls::version::TLS13,
            &tokio_rustls::rustls::version::TLS12,
        ],
        TlsMinimumVersion::Tls13 => vec![&tokio_rustls::rustls::version::TLS13],
    };
    let server_config = ServerConfig::builder()
        .with_cipher_suites(&cipher_suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions)
        .context("configuring TLS versions and cipher suites")?
        .with_no_client_auth()
        .with_single_cert(certs_wrapped.clone(), key)
        .context("creating server config")?;

    // compute SHA-256 of first certificate's DER bytes for tls-server-end-point channel binding
    let ctx = TlsContext {
        acceptor: TlsAcceptor::from(Arc::new(server_config)),
    };
    Ok(Arc::new(ctx))
}

pub fn reload_tls_context(
    sender: &tokio::sync::watch::Sender<Option<Arc<TlsContext>>>,
    cert_path: &str,
    key_path: &str,
    policy: &TlsPolicy,
) -> anyhow::Result<()> {
    let context = load_tls_context_with_policy(cert_path, key_path, policy)?;
    sender.send_replace(Some(context));
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
    fn policy_rejects_unknown_and_version_incompatible_suites() {
        let unknown = TlsPolicy {
            minimum_version: TlsMinimumVersion::Tls12,
            cipher_suites: vec!["TLS_FAKE_SUITE".into()],
            web_http_only: false,
        };
        assert!(cipher_suites(&unknown).is_err());

        let tls12_only = TlsPolicy {
            minimum_version: TlsMinimumVersion::Tls13,
            cipher_suites: vec!["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".into()],
            web_http_only: false,
        };
        let cert_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/certs/localhost.crt"
        );
        let key_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/certs/localhost.key"
        );
        let error = load_tls_context_with_policy(cert_path, key_path, &tls12_only)
            .err()
            .unwrap();
        assert!(error.to_string().contains("TLS versions and cipher suites"));
    }

    #[test]
    fn reload_swaps_only_after_replacement_validates() {
        let cert_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/certs/localhost.crt"
        );
        let key_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/certs/localhost.key"
        );
        let initial = load_tls_context(cert_path, key_path).unwrap();
        let (sender, receiver) = tokio::sync::watch::channel(Some(initial.clone()));
        assert!(
            reload_tls_context(
                &sender,
                cert_path,
                "/missing/key.pem",
                &TlsPolicy::default()
            )
            .is_err()
        );
        assert!(Arc::ptr_eq(receiver.borrow().as_ref().unwrap(), &initial));

        reload_tls_context(&sender, cert_path, key_path, &TlsPolicy::default()).unwrap();
        assert!(!Arc::ptr_eq(receiver.borrow().as_ref().unwrap(), &initial));
    }
}
