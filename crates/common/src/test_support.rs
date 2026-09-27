//! Test helpers shared across the workspace (`test-support` feature).

use std::path::PathBuf;
use std::sync::OnceLock;

/// PEM certificate and key paths for a self-signed `localhost` certificate,
/// generated once per test process so TLS tests need no checked-in keys.
pub fn localhost_cert() -> (&'static str, &'static str) {
    static PATHS: OnceLock<(String, String)> = OnceLock::new();
    let (cert, key) = PATHS.get_or_init(|| {
        let generated = rcgen::generate_simple_self_signed(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .expect("generating test certificate");
        let dir: PathBuf = std::env::temp_dir().join(format!(
            "rmail-test-certs-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).expect("creating certificate directory");
        let cert = dir.join("localhost.crt");
        let key = dir.join("localhost.key");
        std::fs::write(&cert, generated.cert.pem()).expect("writing certificate");
        std::fs::write(&key, generated.key_pair.serialize_pem()).expect("writing key");
        (
            cert.to_string_lossy().into_owned(),
            key.to_string_lossy().into_owned(),
        )
    });
    (cert.as_str(), key.as_str())
}
