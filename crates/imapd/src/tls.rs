use anyhow::Context;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use tokio_rustls::TlsAcceptor;

pub fn load_tls_acceptor(cert_path: &str, key_path: &str) -> anyhow::Result<TlsAcceptor> {
    let cert_file = File::open(cert_path).context("opening cert file")?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = certs(&mut cert_reader).context("reading certs")?;
    let certs = certs.into_iter().map(Certificate).collect::<Vec<_>>();

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
        .with_single_cert(certs, key)
        .context("creating server config")?;

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}
