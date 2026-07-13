use std::sync::Arc;

use rmail_common::config::TlsPolicy;
use sha2::{Digest, Sha256};
use tokio_rustls::TlsAcceptor;

#[allow(dead_code)]
pub struct TlsContext {
    pub acceptor: TlsAcceptor,
    pub server_end_point: Vec<u8>,
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
    let server_end_point = Sha256::digest(&material.leaf_der).to_vec();
    let server_config = rmail_common::tls::build_server_config(material, policy)?;

    let ctx = TlsContext {
        acceptor: TlsAcceptor::from(Arc::new(server_config)),
        server_end_point,
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
    use std::io::Cursor;
    use std::time::SystemTime;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::client::{ServerCertVerified, ServerCertVerifier};
    use tokio_rustls::rustls::{
        Certificate, ClientConfig, Error as TlsError, RootCertStore, ServerName,
    };

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

        let missing_ocsp = TlsPolicy {
            ocsp_response: Some("/missing/ocsp.der".to_string()),
            ..TlsPolicy::default()
        };
        assert!(reload_tls_context(&sender, cert_path, key_path, &missing_ocsp).is_err());
        assert!(Arc::ptr_eq(receiver.borrow().as_ref().unwrap(), &initial));

        reload_tls_context(&sender, cert_path, key_path, &TlsPolicy::default()).unwrap();
        assert!(!Arc::ptr_eq(receiver.borrow().as_ref().unwrap(), &initial));
    }

    struct PinnedCertificateAndOcsp {
        certificate: Vec<u8>,
        ocsp: Vec<u8>,
    }

    impl ServerCertVerifier for PinnedCertificateAndOcsp {
        fn verify_server_cert(
            &self,
            end_entity: &Certificate,
            _intermediates: &[Certificate],
            _server_name: &ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            ocsp_response: &[u8],
            _now: SystemTime,
        ) -> Result<ServerCertVerified, TlsError> {
            if end_entity.0 == self.certificate && ocsp_response == self.ocsp {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(TlsError::General(
                    "unexpected certificate or OCSP staple".to_string(),
                ))
            }
        }
    }

    #[tokio::test]
    async fn configured_ocsp_response_is_stapled_in_handshake() {
        let cert_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/certs/localhost.crt"
        );
        let key_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/certs/localhost.key"
        );
        let temp = tempfile::tempdir().unwrap();
        let ocsp_path = temp.path().join("ocsp.der");
        let ocsp = b"test DER OCSP response".to_vec();
        std::fs::write(&ocsp_path, &ocsp).unwrap();
        let policy = TlsPolicy {
            ocsp_response: Some(ocsp_path.to_string_lossy().into_owned()),
            ..TlsPolicy::default()
        };
        let server = load_tls_context_with_policy(cert_path, key_path, &policy).unwrap();
        let certificates =
            rustls_pemfile::certs(&mut Cursor::new(std::fs::read(cert_path).unwrap())).unwrap();
        let mut client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        client_config
            .dangerous()
            .set_certificate_verifier(Arc::new(PinnedCertificateAndOcsp {
                certificate: certificates[0].clone(),
                ocsp,
            }));
        let connector = TlsConnector::from(Arc::new(client_config));
        let (client_io, server_io) = duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            let mut stream = server.acceptor.accept(server_io).await.unwrap();
            stream.write_all(b"ok").await.unwrap();
        });
        let mut client = connector
            .connect(ServerName::try_from("localhost").unwrap(), client_io)
            .await
            .unwrap();
        let mut bytes = [0; 2];
        client.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ok");
        server_task.await.unwrap();
    }
}
