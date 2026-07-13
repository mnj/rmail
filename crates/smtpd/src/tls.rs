use std::sync::Arc;

use rmail_common::config::TlsPolicy;
use tokio_rustls::TlsAcceptor;

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
    let material = rmail_common::tls::load_server_tls_material(
        cert_path,
        key_path,
        policy.ocsp_response.as_deref(),
    )?;
    let server_config = rmail_common::tls::build_server_config(material, policy)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use rmail_common::config::TlsMinimumVersion;

    #[test]
    fn policy_rejects_unknown_and_version_incompatible_suites() {
        let unknown = TlsPolicy {
            minimum_version: TlsMinimumVersion::Tls12,
            cipher_suites: vec!["TLS_FAKE_SUITE".into()],
            ..TlsPolicy::default()
        };
        let cert_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/certs/localhost.crt"
        );
        let key_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/certs/localhost.key"
        );
        assert!(load_tls_context_with_policy(cert_path, key_path, &unknown).is_err());

        let tls12_only = TlsPolicy {
            minimum_version: TlsMinimumVersion::Tls13,
            cipher_suites: vec!["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".into()],
            ..TlsPolicy::default()
        };
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
