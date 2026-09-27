//! Connection-level behaviour: capabilities, framing, literals, rate limits, COMPRESS, STARTTLS, ID, ENABLE and state rules.

use super::*;

#[test]
fn capability_advertises_starttls_and_login_policy() {
    let plain_caps = capability_tokens(CapabilityPhase::NotAuthenticatedPlain, false);
    let plain_tokens = plain_caps.split_ascii_whitespace().collect::<HashSet<_>>();
    assert_eq!(
        plain_tokens,
        HashSet::from([
            "IMAP4rev1",
            "IMAP4rev2",
            "ID",
            "ENABLE",
            "IDLE",
            "SASL-IR",
            "LITERAL+",
            "LITERAL-",
            "LOGINDISABLED",
            "AUTH=SCRAM-SHA-256",
        ])
    );
    assert!(plain_caps.contains("LOGINDISABLED"));
    assert!(plain_caps.contains("SASL-IR"));
    assert!(plain_caps.contains("ENABLE"));
    assert!(plain_caps.contains("LITERAL-"));
    assert!(plain_caps.contains("LITERAL+"));
    assert!(!plain_caps.contains("AUTH=PLAIN"));
    assert!(plain_caps.contains("AUTH=SCRAM-SHA-256"));
    assert!(!plain_caps.contains("STARTTLS"));
    assert!(!plain_caps.contains("CONDSTORE"));
    assert!(!plain_caps.contains("QRESYNC"));
    assert!(!plain_caps.contains("COMPRESS=DEFLATE"));

    let starttls_caps = capability_tokens(CapabilityPhase::NotAuthenticatedPlain, true);
    assert!(starttls_caps.contains("STARTTLS"));

    let tls_caps = capability_tokens(CapabilityPhase::NotAuthenticatedTls, false);
    assert!(!tls_caps.contains("LOGINDISABLED"));
    assert!(tls_caps.contains("SASL-IR"));
    assert!(tls_caps.contains("ENABLE"));
    assert!(tls_caps.contains("AUTH=PLAIN"));
    assert!(tls_caps.contains("AUTH=LOGIN"));
    assert!(tls_caps.contains("AUTH=SCRAM-SHA-256"));
    assert!(!tls_caps.contains("AUTH=SCRAM-SHA-256-PLUS"));
    assert!(tls_caps.contains("LITERAL-"));
    assert!(tls_caps.contains("LITERAL+"));
    assert!(!tls_caps.contains("STARTTLS"));
    assert!(!tls_caps.contains("CONDSTORE"));
    assert!(!tls_caps.contains("QRESYNC"));
    assert!(!tls_caps.contains("COMPRESS=DEFLATE"));

    let tls_binding_caps = capability_tokens(CapabilityPhase::NotAuthenticatedTls, true);
    assert!(tls_binding_caps.contains("AUTH=SCRAM-SHA-256-PLUS"));

    let authenticated = capability_tokens(CapabilityPhase::Authenticated, false);
    let authenticated_tokens = authenticated
        .split_ascii_whitespace()
        .collect::<HashSet<_>>();
    assert_eq!(
        authenticated_tokens,
        HashSet::from([
            "IMAP4rev1",
            "IMAP4rev2",
            "ID",
            "ENABLE",
            "IDLE",
            "SASL-IR",
            "LITERAL+",
            "LITERAL-",
            "UIDPLUS",
            "MULTIAPPEND",
            "CATENATE",
            "QUOTA",
            "NAMESPACE",
            "SPECIAL-USE",
            "LIST-EXTENDED",
            "CHILDREN",
            "LIST-STATUS",
            "CONDSTORE",
            "QRESYNC",
            "ESEARCH",
            "SEARCHRES",
            "PARTIAL",
            "SORT",
            "THREAD=ORDEREDSUBJECT",
            "THREAD=REFERENCES",
            "THREAD=REFS",
            "WITHIN",
            "STATUS=SIZE",
            "SAVEDATE",
            "PREVIEW",
            "SNIPPET=FUZZY",
            "BINARY",
            "UTF8=ACCEPT",
            "COMPRESS=DEFLATE",
            "MOVE",
            "UNSELECT",
            "UNAUTHENTICATE",
            "CREATE-SPECIAL-USE",
            "OBJECTID",
            "METADATA",
            "NOTIFY",
            "UIDONLY",
            "APPENDLIMIT=104857600",
        ])
    );
    assert!(
        !authenticated_tokens.contains("QRESYNC") || authenticated_tokens.contains("CONDSTORE")
    );
    assert!(
        !authenticated_tokens.contains("LIST-STATUS")
            || authenticated_tokens.contains("LIST-EXTENDED")
    );
    assert!(authenticated.contains("UIDPLUS"));
    assert!(authenticated.contains("CONDSTORE"));
    assert!(authenticated.contains("UNSELECT"));
    assert!(!authenticated.contains("AUTH=PLAIN"));
    assert!(!authenticated.contains("LOGINDISABLED"));
    assert!(!authenticated.contains("STARTTLS"));
    assert_eq!(
        authenticated,
        capability_tokens(CapabilityPhase::Selected, false)
    );

    let scram_only = crate::auth::AuthPolicy::from_names(&["SCRAM-SHA-256".to_string()])
        .expect("SCRAM-only policy");
    let configured = crate::response::capability_tokens_with_policy(
        CapabilityPhase::NotAuthenticatedTls,
        true,
        &scram_only,
    );
    assert!(configured.contains("AUTH=SCRAM-SHA-256"));
    assert!(!configured.contains("AUTH=PLAIN"));
    assert!(!configured.contains("AUTH=LOGIN"));
    assert!(!configured.contains("AUTH=SCRAM-SHA-256-PLUS"));
}
#[test]
fn connection_rate_limit_is_source_keyed() {
    let first: std::net::IpAddr = "192.0.2.201".parse().unwrap();
    let second: std::net::IpAddr = "192.0.2.202".parse().unwrap();
    crate::CONNECTION_ATTEMPTS.lock().unwrap().remove(&first);
    crate::CONNECTION_ATTEMPTS.lock().unwrap().remove(&second);
    assert!(crate::accept_connection_from(first, 2));
    assert!(crate::accept_connection_from(first, 2));
    assert!(!crate::accept_connection_from(first, 2));
    assert!(crate::accept_connection_from(second, 2));
}
#[test]
fn authentication_command_arguments_are_never_logged() {
    assert_eq!(
        crate::logged_command_args("LOGIN", "\"user\" \"secret\""),
        "[REDACTED]"
    );
    assert_eq!(
        crate::logged_command_args("authenticate", "PLAIN payload"),
        "[REDACTED]"
    );
    assert_eq!(crate::logged_command_args("NOOP", "trailing"), "trailing");
}
#[tokio::test]
async fn compress_deflate_round_trip_and_rejects_duplicate_activation() {
    let td = tempfile::tempdir().expect("tempdir");
    let db_path = td.path().join("config.db");
    rmail_common::db::init_db(&db_path).expect("init db");
    rmail_common::db::add_mailbox(
        &db_path,
        "user@example.test",
        Some("plain:password"),
        None,
        None,
    )
    .expect("mailbox");
    let (client, server) = duplex(64 * 1024);
    let server_task = tokio::spawn(process_stream(
        Box::new(server),
        td.path().join("mail").to_string_lossy().to_string(),
        None,
        Some(db_path.to_string_lossy().to_string()),
        None,
        true,
    ));
    let mut reader = BufReader::new(client);
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("greeting");
    line.clear();
    reader.read_line(&mut line).await.expect("capability");
    reader
        .get_mut()
        .write_all(b"A001 LOGIN \"user@example.test\" \"password\"\r\n")
        .await
        .expect("login");
    reader.get_mut().flush().await.expect("flush");
    let _login = read_until_contains(&mut reader, "A001 OK").await;
    reader
        .get_mut()
        .write_all(b"A002 CAPABILITY\r\n")
        .await
        .expect("capability");
    reader.get_mut().flush().await.expect("flush");
    let caps = read_until_contains(&mut reader, "A002 OK").await.join("");
    assert!(caps.contains("COMPRESS=DEFLATE"));
    reader
        .get_mut()
        .write_all(b"A003 COMPRESS DEFLATE\r\n")
        .await
        .expect("compress");
    reader.get_mut().flush().await.expect("flush");
    let switched = read_until_contains(&mut reader, "A003 OK").await.join("");
    assert!(switched.contains("Begin compression"));

    let (read, write) = tokio::io::split(reader.into_inner());
    let mut compressed_reader = BufReader::new(DeflateDecoder::new(BufReader::new(read)));
    let mut compressed_writer = DeflateEncoder::new(write);
    compressed_writer
        .write_all(b"A004 NOOP\r\nA005 CAPABILITY\r\nA006 COMPRESS DEFLATE\r\nA007 LOGOUT\r\n")
        .await
        .expect("compressed commands");
    compressed_writer.flush().await.expect("compressed flush");
    let noop = read_until_contains(&mut compressed_reader, "A004 OK")
        .await
        .join("");
    assert!(noop.contains("NOOP completed"));
    let compressed_caps = read_until_contains(&mut compressed_reader, "A005 OK")
        .await
        .join("");
    assert!(compressed_caps.contains("COMPRESS=DEFLATE"));
    let duplicate = read_until_contains(&mut compressed_reader, "A006 NO")
        .await
        .join("");
    assert!(duplicate.contains("COMPRESSIONACTIVE"));
    let _logout = read_until_contains(&mut compressed_reader, "A007 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn compress_rejects_pipelined_plaintext_without_switching_streams() {
    let td = tempfile::tempdir().expect("tempdir");
    let db_path = td.path().join("config.db");
    rmail_common::db::init_db(&db_path).expect("init db");
    rmail_common::db::add_mailbox(
        &db_path,
        "user@example.test",
        Some("plain:password"),
        None,
        None,
    )
    .expect("mailbox");
    let (client, server) = duplex(32 * 1024);
    let server_task = tokio::spawn(process_stream(
        Box::new(server),
        td.path().join("mail").to_string_lossy().to_string(),
        None,
        Some(db_path.to_string_lossy().to_string()),
        None,
        true,
    ));
    let mut reader = BufReader::new(client);
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("greeting");
    line.clear();
    reader.read_line(&mut line).await.expect("capability");
    reader
        .get_mut()
        .write_all(b"A001 LOGIN \"user@example.test\" \"password\"\r\n")
        .await
        .expect("login");
    reader.get_mut().flush().await.expect("flush");
    let _login = read_until_contains(&mut reader, "A001 OK").await;
    reader
        .get_mut()
        .write_all(b"A002 COMPRESS DEFLATE\r\nA003 NOOP\r\n")
        .await
        .expect("pipeline");
    reader.get_mut().flush().await.expect("flush");
    let rejected = read_until_contains(&mut reader, "A002 BAD").await.join("");
    assert!(rejected.contains("did not wait for COMPRESS reply"));
    let noop = read_until_contains(&mut reader, "A003 OK").await.join("");
    assert!(noop.contains("NOOP completed"));
    reader
        .get_mut()
        .write_all(b"A004 LOGOUT\r\n")
        .await
        .expect("logout");
    reader.get_mut().flush().await.expect("flush");
    let _logout = read_until_contains(&mut reader, "A004 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn post_starttls_session_continues_without_a_second_greeting() {
    let td = tempfile::tempdir().expect("tempdir");
    let (client, server) = duplex(8 * 1024);
    let server_task = tokio::spawn(process_stream_inner(
        Box::new(server),
        td.path().to_string_lossy().to_string(),
        None::<Arc<crate::tls::TlsContext>>,
        None,
        None,
        true,
        false,
        Arc::new(crate::auth::AuthPolicy::default()),
    ));
    let mut reader = BufReader::new(client);
    reader
        .get_mut()
        .write_all(b"A001 CAPABILITY\r\nA002 LOGOUT\r\n")
        .await
        .expect("commands");
    reader.get_mut().flush().await.expect("flush");

    let mut first = String::new();
    reader.read_line(&mut first).await.expect("first response");
    assert!(first.starts_with("* CAPABILITY "));
    assert!(!first.contains("rMail IMAPD ready"));
    let _capability = read_until_contains(&mut reader, "A001 OK").await;
    let _logout = read_until_contains(&mut reader, "A002 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn starttls_rejects_pipelined_plaintext_without_losing_commands() {
    let td = tempfile::tempdir().expect("tempdir");
    let server_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(
            tokio_rustls::rustls::server::ResolvesServerCertUsingSni::new(),
        ));
    let tls_context = Arc::new(crate::tls::TlsContext {
        acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(server_config)),
        server_end_point: vec![0; 32],
    });
    let (client, server) = duplex(8 * 1024);
    let server_task = tokio::spawn(process_stream(
        Box::new(server),
        td.path().to_string_lossy().to_string(),
        Some(tls_context),
        None,
        None,
        false,
    ));
    let mut reader = BufReader::new(client);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.expect("greeting");
    let mut capabilities = String::new();
    reader
        .read_line(&mut capabilities)
        .await
        .expect("capabilities");
    assert!(capabilities.contains("STARTTLS"));

    reader
        .get_mut()
        .write_all(b"A001 STARTTLS\r\nA002 NOOP\r\nA003 LOGOUT\r\n")
        .await
        .expect("pipelined commands");
    reader.get_mut().flush().await.expect("flush");
    let rejected = read_until_contains(&mut reader, "A001 BAD").await.join("");
    assert!(rejected.contains("did not wait for STARTTLS reply"));
    let noop = read_until_contains(&mut reader, "A002 OK").await.join("");
    assert!(noop.contains("NOOP completed"));
    let _logout = read_until_contains(&mut reader, "A003 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn starttls_completes_real_handshake_and_resumes_imap_over_tls() {
    use std::io::Cursor;
    use std::time::SystemTime;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::client::{ServerCertVerified, ServerCertVerifier};
    use tokio_rustls::rustls::{
        Certificate, ClientConfig, Error as TlsError, RootCertStore, ServerName,
    };

    struct PinnedCertificate(Vec<u8>);

    impl ServerCertVerifier for PinnedCertificate {
        fn verify_server_cert(
            &self,
            end_entity: &Certificate,
            _intermediates: &[Certificate],
            _server_name: &ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: SystemTime,
        ) -> Result<ServerCertVerified, TlsError> {
            if end_entity.0 == self.0 {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(TlsError::General(
                    "STARTTLS test received an unexpected certificate".to_string(),
                ))
            }
        }
    }

    let td = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path) = rmail_common::test_support::localhost_cert();
    let tls_context = crate::tls::load_tls_context(cert_path, key_path).expect("TLS context");
    let cert_pem = std::fs::read(cert_path).expect("read certificate");
    let certificates = rustls_pemfile::certs(&mut Cursor::new(cert_pem)).expect("parse cert");
    let mut client_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    client_config
        .dangerous()
        .set_certificate_verifier(Arc::new(PinnedCertificate(certificates[0].clone())));

    let (client, server) = duplex(32 * 1024);
    let server_task = tokio::spawn(process_stream(
        Box::new(server),
        td.path().to_string_lossy().to_string(),
        Some(tls_context),
        None,
        None,
        false,
    ));
    let mut plaintext = BufReader::new(client);
    let mut greeting = String::new();
    plaintext.read_line(&mut greeting).await.expect("greeting");
    let mut capabilities = String::new();
    plaintext
        .read_line(&mut capabilities)
        .await
        .expect("capabilities");
    assert!(capabilities.contains("STARTTLS"));
    plaintext
        .get_mut()
        .write_all(b"A001 STARTTLS\r\n")
        .await
        .expect("STARTTLS");
    plaintext.get_mut().flush().await.expect("flush");
    let mut starttls_reply = String::new();
    plaintext
        .read_line(&mut starttls_reply)
        .await
        .expect("STARTTLS reply");
    assert!(starttls_reply.contains("A001 OK Begin TLS negotiation now"));

    let connector = TlsConnector::from(Arc::new(client_config));
    let tls_stream = connector
        .connect(
            ServerName::try_from("localhost").expect("server name"),
            plaintext.into_inner(),
        )
        .await
        .expect("TLS handshake");
    let mut encrypted = BufReader::new(tls_stream);
    encrypted
        .get_mut()
        .write_all(b"A002 CAPABILITY\r\nA003 LOGOUT\r\n")
        .await
        .expect("encrypted commands");
    encrypted.get_mut().flush().await.expect("flush");
    let post_tls = read_until_contains(&mut encrypted, "A002 OK")
        .await
        .join("");
    assert!(post_tls.contains("IMAP4rev1"));
    assert!(!post_tls.contains("STARTTLS"));
    let logout = read_until_contains(&mut encrypted, "A003 OK")
        .await
        .join("");
    assert!(logout.contains("LOGOUT completed"));
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn id_accepts_nil_and_client_fields_and_rejects_malformed_lists() {
    let td = tempfile::tempdir().expect("tempdir");
    let (client, server) = duplex(8 * 1024);
    let server_task = tokio::spawn(process_stream(
        Box::new(server),
        td.path().to_string_lossy().to_string(),
        None::<Arc<crate::tls::TlsContext>>,
        None,
        None,
        true,
    ));
    let mut reader = BufReader::new(client);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.expect("greeting");
    let mut capability = String::new();
    reader.read_line(&mut capability).await.expect("capability");
    reader
            .get_mut()
            .write_all(
                b"A001 ID NIL\r\nA002 ID (\"name\" \"Geary\" \"version\" \"46.0\")\r\nA003 ID (\"name\")\r\nA004 LOGOUT\r\n",
            )
            .await
            .expect("commands");
    reader.get_mut().flush().await.expect("flush");

    let nil = read_until_contains(&mut reader, "A001 OK").await.join("");
    assert!(nil.contains("* ID (\"name\" \"rMail\""));
    let fields = read_until_contains(&mut reader, "A002 OK").await.join("");
    assert!(fields.contains(&format!("\"version\" \"{}\"", env!("CARGO_PKG_VERSION"))));
    let malformed = read_until_contains(&mut reader, "A003 BAD").await.join("");
    assert!(malformed.contains("Invalid ID arguments"));
    let _logout = read_until_contains(&mut reader, "A004 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn command_framing_rejects_invalid_tags_utf8_and_oversized_lines_then_recovers() {
    let td = tempfile::tempdir().expect("tempdir");
    let (client, server) = duplex(32 * 1024);
    let server_task = tokio::spawn(process_stream(
        Box::new(server),
        td.path().to_string_lossy().to_string(),
        None::<Arc<crate::tls::TlsContext>>,
        None,
        None,
        true,
    ));
    let mut reader = BufReader::new(client);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.expect("greeting");
    let mut capability = String::new();
    reader.read_line(&mut capability).await.expect("capability");
    let mut input = Vec::new();
    input.extend_from_slice(b"bad+tag NOOP\r\n");
    input.extend_from_slice(b"A001\r\n");
    input.extend_from_slice(b"A002 NOOP \xff\r\n");
    input.extend_from_slice(&vec![b'x'; crate::MAX_PREAUTH_LINE_BYTES + 1]);
    input.extend_from_slice(b"\r\nA003 NOOP trailing\r\nA004 NOOP\r\nA005 LOGOUT\r\n");
    reader.get_mut().write_all(&input).await.expect("commands");
    reader.get_mut().flush().await.expect("flush");

    let invalid_tag = read_until_contains(&mut reader, "* BAD").await.join("");
    assert!(invalid_tag.contains("InvalidTag"));
    let missing_command = read_until_contains(&mut reader, "A001 BAD").await.join("");
    assert!(missing_command.contains("MissingCommand"));
    let invalid_utf8 = read_until_contains(&mut reader, "* BAD").await.join("");
    assert!(invalid_utf8.contains("not valid UTF-8"));
    let oversized = read_until_contains(&mut reader, "* BAD").await.join("");
    assert!(oversized.contains("Command line too long"));
    let trailing = read_until_contains(&mut reader, "A003 BAD").await.join("");
    assert!(trailing.contains("Invalid NOOP arguments"));
    let recovered = read_until_contains(&mut reader, "A004 OK").await.join("");
    assert!(recovered.contains("NOOP completed"));
    let _logout = read_until_contains(&mut reader, "A005 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn command_rate_limit_closes_abusive_imap_sessions() {
    let td = tempfile::tempdir().expect("tempdir");
    let mail_root = td.path().join("mail");
    let db_path = td.path().join("config.db");
    rmail_common::db::init_db(&db_path).expect("init db");
    let security = rmail_common::config::SecurityConfig {
        imap_max_commands_per_minute: 2,
        ..Default::default()
    };
    let policy = Arc::new(crate::auth::AuthPolicy::from_security(&security).unwrap());
    let (client, server) = duplex(4096);
    let server_task = tokio::spawn(async move {
        process_stream_with_policy(
            Box::new(server),
            mail_root.to_string_lossy().into_owned(),
            None,
            Some(db_path.to_string_lossy().into_owned()),
            None,
            false,
            policy,
        )
        .await
    });
    let mut reader = BufReader::new(client);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.unwrap();
    reader.read_line(&mut greeting).await.unwrap();
    reader
        .get_mut()
        .write_all(b"A1 NOOP\r\nA2 NOOP\r\nA3 NOOP\r\n")
        .await
        .unwrap();
    reader.get_mut().flush().await.unwrap();
    let responses = read_until_contains_bounded(&mut reader, "Command rate limit exceeded")
        .await
        .join("");
    assert!(responses.contains("A1 OK NOOP completed"), "{responses}");
    assert!(responses.contains("A2 OK NOOP completed"), "{responses}");
    assert!(
        responses.contains("* BYE Command rate limit exceeded"),
        "{responses}"
    );
    assert!(!responses.contains("A3 OK"), "{responses}");
    server_task.await.unwrap().unwrap();
}
#[test]
fn unsupported_log_selected_mailbox_placeholder_is_stable() {
    assert_eq!(crate::selected_mailbox_for_log(&None), "-");
}
#[tokio::test]
async fn enable_tracks_supported_session_features_only_after_authentication() {
    let td = tempfile::tempdir().expect("tempdir");
    let mail_root = td.path().join("mail");
    let db_path = td.path().join("config.db");
    rmail_common::db::init_db(&db_path).expect("init db");
    rmail_common::db::add_mailbox(
        &db_path,
        "user@example.test",
        Some("plain:password"),
        None,
        None,
    )
    .expect("add mailbox");

    let (client, server) = duplex(32 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            mail_root.to_string_lossy().to_string(),
            None::<Arc<crate::tls::TlsContext>>,
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
    assert!(capability.contains("ENABLE"));

    reader
            .get_mut()
            .write_all(
                b"A001 ENABLE IMAP4rev1\r\nA002 LOGIN \"user@example.test\" \"password\"\r\nA003 ENABLE IMAP4rev1 CONDSTORE QRESYNC UTF8=ACCEPT\r\nA004 ENABLE QRESYNC\r\nA005 LOGOUT\r\n",
            )
            .await
            .expect("write enable commands");
    reader.get_mut().flush().await.expect("flush");

    let preauth = read_until_contains(&mut reader, "A001 NO").await;
    assert!(
        preauth
            .iter()
            .any(|l| l.contains("Authentication required"))
    );
    let _login = read_until_contains(&mut reader, "A002 OK").await;
    let enabled = read_until_contains(&mut reader, "A003 OK").await;
    assert!(
        enabled
            .iter()
            .any(|l| l.trim_end() == "* ENABLED CONDSTORE QRESYNC UTF8=ACCEPT")
    );
    assert!(enabled.iter().any(|l| l.contains("QRESYNC")));
    assert!(enabled.iter().any(|l| l.contains("UTF8=ACCEPT")));
    let ignored = read_until_contains(&mut reader, "A004 OK").await;
    assert!(ignored.iter().any(|l| l.trim_end() == "* ENABLED QRESYNC"));
    let _logout = read_until_contains(&mut reader, "A005 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn textual_command_literals_resume_search_list_and_nested_arguments() {
    let td = tempfile::tempdir().expect("tempdir");
    let mail_root = td.path().join("mail");
    let db_path = td.path().join("config.db");
    rmail_common::db::init_db(&db_path).expect("init db");
    rmail_common::db::add_mailbox(
        &db_path,
        "user@example.test",
        Some("plain:password"),
        None,
        None,
    )
    .expect("mailbox");
    rmail_common::maildir::deliver(
        &mail_root,
        "example.test",
        "user",
        b"Subject: needle\r\n\r\nbody\r\n",
    )
    .expect("delivery");
    let (client, server) = duplex(64 * 1024);
    let server_task = tokio::spawn(process_stream(
        Box::new(server),
        mail_root.to_string_lossy().to_string(),
        None,
        Some(db_path.to_string_lossy().to_string()),
        None,
        true,
    ));
    let mut reader = BufReader::new(client);
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("greeting");
    line.clear();
    reader.read_line(&mut line).await.expect("capability");
    reader
        .get_mut()
        .write_all(b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\n")
        .await
        .expect("setup");
    reader.get_mut().flush().await.expect("flush");
    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let _select = read_until_contains(&mut reader, "A002 OK").await;

    reader
        .get_mut()
        .write_all(b"A003 SEARCH SUBJECT {6}\r\n")
        .await
        .expect("search marker");
    reader.get_mut().flush().await.expect("flush");
    let continuation = read_until_contains(&mut reader, "+ Ready").await.join("");
    assert!(continuation.contains("+ Ready for literal data"));
    reader
        .get_mut()
        .write_all(b"needle\r\n")
        .await
        .expect("search literal");
    reader.get_mut().flush().await.expect("flush");
    let search = read_until_contains(&mut reader, "A003 OK").await.join("");
    assert!(search.contains("* SEARCH 1"));

    reader
            .get_mut()
            .write_all(
                b"A004 SEARCH OR SUBJECT {6}\r\nneedle SUBJECT {7+}\r\nmissing\r\nA005 LIST \"\" {5+}\r\nINBOX\r\nA006 ID (\"name\" {6+}\r\nGearyX)\r\nA007 LOGOUT\r\n",
            )
            .await
            .expect("multi literal pipeline");
    reader.get_mut().flush().await.expect("flush");
    let second_continuation = read_until_contains(&mut reader, "+ Ready").await.join("");
    assert!(second_continuation.contains("+ Ready for literal data"));
    let multi = read_until_contains(&mut reader, "A004 OK").await.join("");
    assert!(multi.contains("* SEARCH 1"));
    let list = read_until_contains(&mut reader, "A005 OK").await.join("");
    assert!(list.contains("* LIST") && list.contains("\"INBOX\""));
    let id = read_until_contains(&mut reader, "A006 OK").await.join("");
    assert!(id.contains("* ID (\"name\" \"rMail\""));
    let _logout = read_until_contains(&mut reader, "A007 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn unsupported_commands_return_bad_after_logging_context() {
    let td = tempfile::tempdir().expect("tempdir");
    let mail_root = td.path().join("mail");
    let db_path = td.path().join("config.db");
    rmail_common::db::init_db(&db_path).expect("init db");
    rmail_common::db::add_mailbox(
        &db_path,
        "user@example.test",
        Some("plain:password"),
        None,
        None,
    )
    .expect("add mailbox");

    let (client, server) = duplex(32 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            mail_root.to_string_lossy().to_string(),
            None::<Arc<crate::tls::TlsContext>>,
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

    reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID SORT RETURN (ALL)\r\nA004 XLIST \"\" \"*\"\r\nA005 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let _select = read_until_contains(&mut reader, "A002 OK").await;

    let uid_sort = read_until_contains(&mut reader, "A003 BAD").await;
    assert!(
        uid_sort
            .iter()
            .any(|l| l.contains("Invalid UID SORT arguments"))
    );

    let xlist = read_until_contains(&mut reader, "A004 OK").await;
    assert!(
        xlist
            .iter()
            .any(|l| l.contains("\\Inbox") && l.contains("\"INBOX\""))
    );

    let _logout = read_until_contains(&mut reader, "A005 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn command_preflight_enforces_auth_and_selected_states() {
    let td = tempfile::tempdir().expect("tempdir");
    let mail_root = td.path().join("mail");
    let db_path = td.path().join("config.db");
    rmail_common::db::init_db(&db_path).expect("init db");
    rmail_common::db::add_mailbox(
        &db_path,
        "user@example.test",
        Some("plain:password"),
        None,
        None,
    )
    .expect("add mailbox");

    let (client, server) = duplex(32 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            mail_root.to_string_lossy().to_string(),
            None::<Arc<crate::tls::TlsContext>>,
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

    reader
            .get_mut()
            .write_all(
                b"A001 LIST \"\" \"*\"\r\nA002 FETCH 1:* FLAGS\r\nA003 LOGIN \"user@example.test\" \"password\"\r\nA004 LOGIN \"user@example.test\" \"password\"\r\nA005 FETCH 1:* FLAGS\r\nA006 SELECT INBOX\r\nA007 FETCH 1:* FLAGS\r\nA008 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let list = read_until_contains(&mut reader, "A001 NO").await;
    assert!(list.iter().any(|l| l.contains("Authentication required")));
    let fetch_before_auth = read_until_contains(&mut reader, "A002 NO").await;
    assert!(
        fetch_before_auth
            .iter()
            .any(|l| l.contains("Authentication required"))
    );
    let login = read_until_contains(&mut reader, "A003 OK").await;
    assert!(login.iter().any(|l| l.contains("LOGIN completed")));
    let login_after_auth = read_until_contains(&mut reader, "A004 BAD").await;
    assert!(
        login_after_auth
            .iter()
            .any(|l| l.contains("Command not allowed after authentication"))
    );
    let fetch_before_select = read_until_contains(&mut reader, "A005 BAD").await;
    assert!(
        fetch_before_select
            .iter()
            .any(|l| l.contains("No mailbox selected"))
    );
    let _select = read_until_contains(&mut reader, "A006 OK").await;
    let fetch_after_select = read_until_contains(&mut reader, "A007 OK").await;
    assert!(fetch_after_select.iter().any(|l| l.contains("FETCH")));
    let _logout = read_until_contains(&mut reader, "A008 OK").await;
    server_task.await.expect("join").expect("server");
}
