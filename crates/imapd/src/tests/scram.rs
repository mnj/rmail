//! SCRAM-SHA-256(-PLUS): downgrade detection (RFC 5802 §6), user
//! enumeration resistance (RFC 5802 §9) and tls-exporter channel binding
//! (RFC 9266).

use super::*;
use std::path::PathBuf;

fn scram_account(dir: &tempfile::TempDir) -> (PathBuf, PathBuf) {
    let mail_root = dir.path().join("mail");
    let db_path = dir.path().join("config.db");
    let scram =
        rmail_common::auth::create_scram_verifier("password", 4096).expect("create verifier");
    rmail_common::db::init_db(&db_path).expect("init db");
    rmail_common::db::add_mailbox(
        &db_path,
        "user@example.test",
        Some("plain:password"),
        None,
        Some(&scram),
    )
    .expect("add mailbox");
    rmail_common::db::add_mailbox(
        &db_path,
        "nosecret@example.test",
        Some("plain:password"),
        None,
        None,
    )
    .expect("add mailbox without SCRAM");
    (mail_root, db_path)
}

/// A TLS context whose tls-server-end-point value is known, without a real
/// handshake (the session is marked encrypted).
fn fake_tls_context() -> Arc<crate::tls::TlsContext> {
    let server_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(
            tokio_rustls::rustls::server::ResolvesServerCertUsingSni::new(),
        ));
    Arc::new(crate::tls::TlsContext {
        acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(server_config)),
        server_end_point: vec![0x5a; 32],
    })
}

async fn start(
    tls: Option<Arc<crate::tls::TlsContext>>,
    mail_root: PathBuf,
    db_path: PathBuf,
) -> (
    BufReader<tokio::io::DuplexStream>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
    String,
) {
    let (client, server) = duplex(32 * 1024);
    let task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            mail_root.to_string_lossy().to_string(),
            tls,
            Some(db_path.to_string_lossy().to_string()),
            None,
            true,
        )
        .await
    });
    let mut reader = BufReader::new(client);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.expect("greeting");
    let mut capability = String::new();
    reader.read_line(&mut capability).await.expect("capability");
    (reader, task, capability)
}

async fn send<W: tokio::io::AsyncWrite + Unpin>(writer: &mut W, line: &str) {
    writer
        .write_all(format!("{line}\r\n").as_bytes())
        .await
        .expect("write");
    writer.flush().await.expect("flush");
}

fn decode_challenge(lines: &[String]) -> String {
    let line = lines
        .iter()
        .find(|line| line.starts_with("+ "))
        .expect("continuation");
    String::from_utf8(
        crate::BASE64_ENGINE
            .decode(line.trim_end().trim_start_matches("+ "))
            .expect("base64 challenge"),
    )
    .expect("UTF-8 challenge")
}

#[tokio::test]
async fn scram_y_flag_fails_when_plus_is_advertised() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mail_root, db_path) = scram_account(&dir);
    let (mut reader, task, capability) = start(Some(fake_tls_context()), mail_root, db_path).await;
    assert!(capability.contains("AUTH=SCRAM-SHA-256-PLUS"));
    let first = crate::BASE64_ENGINE.encode("y,,n=user@example.test,r=clientnonce");
    send(
        reader.get_mut(),
        &format!("A1 AUTHENTICATE SCRAM-SHA-256 {first}"),
    )
    .await;
    let lines = read_until_contains_bounded(&mut reader, "A1 ").await;
    assert!(
        lines
            .last()
            .unwrap()
            .starts_with("A1 NO [AUTHENTICATIONFAILED]"),
        "{lines:?}"
    );
    assert!(!lines.iter().any(|line| line.starts_with("+ ")));
    send(reader.get_mut(), "A2 LOGOUT").await;
    read_until_contains_bounded(&mut reader, "A2 OK").await;
    task.await.expect("join").expect("server");
}

#[tokio::test]
async fn scram_y_flag_is_accepted_when_plus_is_not_advertised() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mail_root, db_path) = scram_account(&dir);
    let (mut reader, task, capability) = start(None, mail_root, db_path).await;
    assert!(!capability.contains("SCRAM-SHA-256-PLUS"));
    let bare = "n=user@example.test,r=clientnonce";
    let first = crate::BASE64_ENGINE.encode(format!("y,,{bare}"));
    send(
        reader.get_mut(),
        &format!("A1 AUTHENTICATE SCRAM-SHA-256 {first}"),
    )
    .await;
    let server_first = decode_challenge(&read_until_contains_bounded(&mut reader, "+ ").await);
    let client_final =
        scram_client_final_with_binding("password", bare, &server_first, b"y,,", &[]);
    send(reader.get_mut(), &crate::BASE64_ENGINE.encode(client_final)).await;
    read_until_contains_bounded(&mut reader, "+ ").await;
    send(reader.get_mut(), "").await;
    let done = read_until_contains_bounded(&mut reader, "A1 ").await;
    assert!(done.last().unwrap().starts_with("A1 OK"), "{done:?}");
    send(reader.get_mut(), "A2 LOGOUT").await;
    read_until_contains_bounded(&mut reader, "A2 OK").await;
    task.await.expect("join").expect("server");
}

#[tokio::test]
async fn scram_unknown_users_get_a_stable_fake_challenge_and_fail_at_client_final() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mail_root, db_path) = scram_account(&dir);
    let (mut reader, task, _) = start(None, mail_root, db_path).await;
    let mut salts = Vec::new();
    for (tag, user) in [
        ("A1", "ghost@example.test"),
        ("A2", "ghost@example.test"),
        ("A3", "nosecret@example.test"),
        ("A4", "user@example.test"),
    ] {
        let bare = format!("n={user},r=nonce{tag}");
        let first = crate::BASE64_ENGINE.encode(format!("n,,{bare}"));
        send(
            reader.get_mut(),
            &format!("{tag} AUTHENTICATE SCRAM-SHA-256 {first}"),
        )
        .await;
        let server_first = decode_challenge(&read_until_contains_bounded(&mut reader, "+ ").await);
        assert_eq!(
            crate::parse_scram_attr(&server_first, "i="),
            Some("4096"),
            "{user}"
        );
        salts.push(
            crate::parse_scram_attr(&server_first, "s=")
                .unwrap()
                .to_string(),
        );
        // A wrong password fails at client-final for every kind of user.
        let client_final = scram_client_final("wrong", &bare, &server_first);
        send(reader.get_mut(), &crate::BASE64_ENGINE.encode(client_final)).await;
        let lines = read_until_contains_bounded(&mut reader, &format!("{tag} ")).await;
        assert!(
            lines
                .last()
                .unwrap()
                .starts_with(&format!("{tag} NO [AUTHENTICATIONFAILED]")),
            "{user}: {lines:?}"
        );
    }
    assert_eq!(salts[0], salts[1], "fake salt must be deterministic");
    assert_ne!(salts[0], salts[2]);
    send(reader.get_mut(), "Z LOGOUT").await;
    read_until_contains_bounded(&mut reader, "Z OK").await;
    task.await.expect("join").expect("server");
}

#[derive(Debug)]
struct AcceptAnyCertificate;

impl tokio_rustls::rustls::client::ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::Certificate,
        _intermediates: &[tokio_rustls::rustls::Certificate],
        _server_name: &tokio_rustls::rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<tokio_rustls::rustls::client::ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::ServerCertVerified::assertion())
    }
}

#[tokio::test]
async fn scram_plus_verifies_tls_exporter_binding_over_tls13() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mail_root, db_path) = scram_account(&dir);
    let (cert_path, key_path) = rmail_common::test_support::localhost_cert();
    let tls = crate::tls::load_tls_context(cert_path, key_path).expect("TLS context");
    let (client_io, server_io) = duplex(64 * 1024);
    let server_tls = tls.clone();
    let server = tokio::spawn(async move {
        let stream = server_tls
            .acceptor
            .accept(server_io)
            .await
            .expect("server handshake");
        let bindings = server_tls.channel_bindings(stream.get_ref().1);
        crate::session::process_tls_stream(
            Box::new(stream),
            mail_root.to_string_lossy().to_string(),
            Some(server_tls),
            Some(db_path.to_string_lossy().to_string()),
            None,
            bindings,
            Arc::new(crate::auth::AuthPolicy::default()),
        )
        .await
    });
    let mut client_config = tokio_rustls::rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(tokio_rustls::rustls::RootCertStore::empty())
        .with_no_client_auth();
    client_config
        .dangerous()
        .set_certificate_verifier(Arc::new(AcceptAnyCertificate));
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let client = connector
        .connect(
            tokio_rustls::rustls::ServerName::try_from("localhost").unwrap(),
            client_io,
        )
        .await
        .expect("client handshake");
    assert_eq!(
        client.get_ref().1.protocol_version(),
        Some(tokio_rustls::rustls::ProtocolVersion::TLSv1_3)
    );
    let mut exporter = [0u8; 32];
    client
        .get_ref()
        .1
        .export_keying_material(&mut exporter, b"EXPORTER-Channel-Binding", Some(&[]))
        .expect("exporter");
    let mut reader = BufReader::new(client);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.expect("greeting");
    let mut capability = String::new();
    reader.read_line(&mut capability).await.expect("capability");
    assert!(
        capability.contains("AUTH=SCRAM-SHA-256-PLUS"),
        "{capability}"
    );

    // A binding computed for another connection is rejected.
    for (tag, binding, expect_ok) in [("A1", [7u8; 32], false), ("A2", exporter, true)] {
        let bare = format!("n=user@example.test,r=exporter{tag}");
        let gs2 = b"p=tls-exporter,,";
        let first = crate::BASE64_ENGINE.encode(format!("p=tls-exporter,,{bare}"));
        send(
            reader.get_mut(),
            &format!("{tag} AUTHENTICATE SCRAM-SHA-256-PLUS {first}"),
        )
        .await;
        let server_first = decode_challenge(&read_until_contains_bounded(&mut reader, "+ ").await);
        let client_final =
            scram_client_final_with_binding("password", &bare, &server_first, gs2, &binding);
        send(reader.get_mut(), &crate::BASE64_ENGINE.encode(client_final)).await;
        if expect_ok {
            read_until_contains_bounded(&mut reader, "+ ").await;
            send(reader.get_mut(), "").await;
            let done = read_until_contains_bounded(&mut reader, &format!("{tag} ")).await;
            assert!(done.last().unwrap().starts_with("A2 OK"), "{done:?}");
        } else {
            let done = read_until_contains_bounded(&mut reader, &format!("{tag} ")).await;
            assert!(
                done.last()
                    .unwrap()
                    .starts_with("A1 NO [AUTHENTICATIONFAILED]"),
                "{done:?}"
            );
        }
    }
    send(reader.get_mut(), "Z LOGOUT").await;
    read_until_contains_bounded(&mut reader, "Z OK").await;
    server.await.expect("join").expect("server");
}
