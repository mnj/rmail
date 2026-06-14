use anyhow::Context;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use sha2::{Digest, Sha256};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};

/// TLS acceptor wrapper that also stores the server_end_point (certificate fingerprint)
/// used for SCRAM channel-binding (tls-server-end-point). The fingerprint is the
/// SHA-256 digest of the server certificate DER bytes.
pub struct TlsContext {
    pub acceptor: TlsAcceptor,
    pub server_end_point: Vec<u8>,
}

pub fn load_tls_context(cert_path: &str, key_path: &str) -> anyhow::Result<Arc<TlsContext>> {
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

    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs_wrapped.clone(), key)
        .context("creating server config")?;

    // compute SHA-256 of first certificate's DER bytes for tls-server-end-point channel binding
    let server_end_point = Sha256::digest(&certs[0]).to_vec();

    let ctx = TlsContext {
        acceptor: TlsAcceptor::from(Arc::new(server_config)),
        server_end_point,
    };
    Ok(Arc::new(ctx))
}
