//! LOGIN and AUTHENTICATE (PLAIN, LOGIN, SCRAM, OAuth) and the failure lockout.

use super::*;

#[tokio::test]
async fn xoauth2_authenticates_through_the_configured_authority() {
    let (introspection_url, introspection) =
        oauth_introspection_server(r#"{"active":true,"username":"user@example.test"}"#).await;
    let td = tempfile::tempdir().expect("tempdir");
    let mail_root = td.path().join("mail");
    let db_path = td.path().join("config.db");
    rmail_common::db::init_db(&db_path).expect("init db");
    rmail_common::db::add_mailbox(&db_path, "user@example.test", None, None, None)
        .expect("add mailbox");
    let security = rmail_common::config::SecurityConfig {
        imap_sasl_mechanisms: vec!["XOAUTH2".into()],
        oauth: Some(rmail_common::config::OAuthConfig {
            introspection_url,
            client_id: None,
            client_secret: None,
            required_scopes: Vec::new(),
            identity_claim: "username".into(),
            issuer: None,
            audience: None,
            timeout_ms: 2_000,
            allow_insecure_http: true,
        }),
        ..Default::default()
    };
    let policy = Arc::new(crate::auth::AuthPolicy::from_security(&security).unwrap());
    let response = base64::engine::general_purpose::STANDARD
        .encode(b"user=user@example.test\x01auth=Bearer good-token\x01\x01");
    let (client, server) = duplex(16 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream_with_policy(
            Box::new(server),
            mail_root.to_string_lossy().into_owned(),
            None,
            Some(db_path.to_string_lossy().into_owned()),
            None,
            true,
            policy,
        )
        .await
    });
    let mut reader = BufReader::new(client);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.unwrap();
    let mut capabilities = String::new();
    reader.read_line(&mut capabilities).await.unwrap();
    assert!(capabilities.contains("AUTH=XOAUTH2"), "{capabilities:?}");
    assert!(
        !capabilities.contains("AUTH=OAUTHBEARER"),
        "{capabilities:?}"
    );
    reader
        .get_mut()
        .write_all(format!("A1 AUTHENTICATE XOAUTH2 {response}\r\nA2 LOGOUT\r\n").as_bytes())
        .await
        .unwrap();
    reader.get_mut().flush().await.unwrap();
    let authenticated = read_until_contains_bounded(&mut reader, "A1 OK").await;
    assert!(authenticated.iter().any(|line| line.contains("A1 OK")));
    read_until_contains_bounded(&mut reader, "A2 OK").await;
    server_task.await.unwrap().unwrap();
    assert_eq!(
        introspection.await.unwrap(),
        "token=good-token&token_type_hint=access_token"
    );
}
#[tokio::test]
async fn authentication_failures_are_indistinguishable_and_share_lockout() {
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
    rmail_common::db::add_mailbox(&db_path, "nopass@example.test", None, None, None)
        .expect("add passwordless mailbox");
    let peer = Some("192.0.2.123:4143".parse().expect("peer"));
    let (client, server) = duplex(32 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            mail_root.to_string_lossy().to_string(),
            None::<Arc<crate::tls::TlsContext>>,
            Some(db_path.to_string_lossy().to_string()),
            peer,
            true,
        )
        .await
    });
    let mut reader = BufReader::new(client);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.expect("greeting");
    let mut capability = String::new();
    reader.read_line(&mut capability).await.expect("capability");
    let plain_bad = base64::engine::general_purpose::STANDARD.encode(b"\0user@example.test\0wrong");
    let commands = format!(
        "A001 LOGIN missing@example.test wrong\r\n\
             A002 LOGIN nopass@example.test wrong\r\n\
             A003 LOGIN user@example.test wrong\r\n\
             A004 LOGIN user@example.test wrong\r\n\
             A005 AUTHENTICATE PLAIN {}\r\n\
             A006 LOGIN user@example.test password\r\n\
             A007 LOGOUT\r\n",
        plain_bad
    );
    reader
        .get_mut()
        .write_all(commands.as_bytes())
        .await
        .expect("write auth failures");
    reader.get_mut().flush().await.expect("flush");
    for tag in ["A001", "A002", "A003", "A004", "A005"] {
        let lines = read_until_contains(&mut reader, &format!("{tag} NO")).await;
        assert!(
            lines
                .iter()
                .any(|line| line.contains("[AUTHENTICATIONFAILED] Authentication failed")),
            "failure leaked account state or lacked response code: {lines:?}"
        );
    }
    let blocked = read_until_contains(&mut reader, "A006 NO").await;
    assert!(
        blocked
            .iter()
            .any(|line| line.contains("Too many failed auth attempts"))
    );
    let _logout = read_until_contains(&mut reader, "A007 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn authenticate_plain_is_tls_only_and_logs_in() {
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

    let payload = crate::BASE64_ENGINE.encode(b"\0user@example.test\0password");
    let (client, server) = duplex(32 * 1024);
    let encrypted_mail_root = mail_root.clone();
    let encrypted_db_path = db_path.clone();
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            encrypted_mail_root.to_string_lossy().to_string(),
            None::<Arc<crate::tls::TlsContext>>,
            Some(encrypted_db_path.to_string_lossy().to_string()),
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
    assert!(capability.contains("AUTH=PLAIN"));
    reader
        .get_mut()
        .write_all(
            format!(
                "A001 AUTHENTICATE PLAIN {}\r\nA002 SELECT INBOX\r\nA003 LOGOUT\r\n",
                payload
            )
            .as_bytes(),
        )
        .await
        .expect("write encrypted auth commands");
    reader.get_mut().flush().await.expect("flush");
    let auth_lines = read_until_contains(&mut reader, "A001 OK").await;
    assert!(
        auth_lines
            .iter()
            .any(|line| line.contains("[CAPABILITY IMAP4rev1") && line.contains("UIDPLUS"))
    );
    assert!(
        auth_lines
            .iter()
            .any(|l| l.contains("AUTHENTICATE completed"))
    );
    let select_lines = read_until_contains(&mut reader, "A002 OK").await;
    assert!(select_lines.iter().any(|l| l.contains("SELECT completed")));
    let _logout = read_until_contains(&mut reader, "A003 OK").await;
    server_task.await.expect("join").expect("server");

    let (client, server) = duplex(16 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            mail_root.to_string_lossy().to_string(),
            None::<Arc<crate::tls::TlsContext>>,
            Some(db_path.to_string_lossy().to_string()),
            None,
            false,
        )
        .await
    });
    let mut reader = BufReader::new(client);
    let mut greeting = String::new();
    reader
        .read_line(&mut greeting)
        .await
        .expect("plain greeting");
    let mut capability = String::new();
    reader
        .read_line(&mut capability)
        .await
        .expect("plain capability");
    assert!(!capability.contains("AUTH=PLAIN"));
    reader
        .get_mut()
        .write_all(format!("A001 AUTHENTICATE PLAIN {}\r\nA002 LOGOUT\r\n", payload).as_bytes())
        .await
        .expect("write plain auth commands");
    reader.get_mut().flush().await.expect("flush");
    let auth_lines = read_until_contains(&mut reader, "A001 NO").await;
    assert!(auth_lines.iter().any(|l| l.contains("Encryption required")));
    let _logout = read_until_contains(&mut reader, "A002 OK").await;
    server_task.await.expect("join").expect("plain server");
}
#[tokio::test]
async fn authenticate_login_sasl_is_tls_only_and_logs_in() {
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
    let encrypted_mail_root = mail_root.clone();
    let encrypted_db_path = db_path.clone();
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            encrypted_mail_root.to_string_lossy().to_string(),
            None::<Arc<crate::tls::TlsContext>>,
            Some(encrypted_db_path.to_string_lossy().to_string()),
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
    assert!(capability.contains("AUTH=LOGIN"));
    reader
        .get_mut()
        .write_all(b"A000 AUTHENTICATE PLAIN\r\n")
        .await
        .expect("plain cancellation command");
    reader.get_mut().flush().await.expect("flush");
    let empty_challenge = read_until_contains(&mut reader, "+ ").await;
    assert!(empty_challenge.iter().any(|line| line == "+ \r\n"));
    reader.get_mut().write_all(b"*\r\n").await.expect("cancel");
    reader.get_mut().flush().await.expect("flush");
    let cancelled = read_until_contains(&mut reader, "A000 BAD").await.join("");
    assert!(cancelled.contains("AUTHENTICATE cancelled"));
    let forbidden_authzid =
        crate::BASE64_ENGINE.encode(b"admin@example.test\0user@example.test\0password");
    reader
        .get_mut()
        .write_all(format!("A000B AUTHENTICATE PLAIN {forbidden_authzid}\r\n").as_bytes())
        .await
        .expect("authzid");
    reader.get_mut().flush().await.expect("flush");
    let authzid = read_until_contains(&mut reader, "A000B NO").await.join("");
    assert!(authzid.contains("Authorization identity is not permitted"));
    reader
        .get_mut()
        .write_all(b"A001 AUTHENTICATE LOGIN\r\n")
        .await
        .expect("write auth command");
    reader.get_mut().flush().await.expect("flush");
    let username_challenge = read_until_contains(&mut reader, "+ VXNlcm5hbWU6").await;
    assert!(username_challenge.iter().any(|l| l.starts_with("+ ")));
    reader
        .get_mut()
        .write_all(format!("{}\r\n", crate::BASE64_ENGINE.encode(b"user@example.test")).as_bytes())
        .await
        .expect("write username");
    reader.get_mut().flush().await.expect("flush");
    let password_challenge = read_until_contains(&mut reader, "+ UGFzc3dvcmQ6").await;
    assert!(password_challenge.iter().any(|l| l.starts_with("+ ")));
    reader
        .get_mut()
        .write_all(
            format!(
                "{}\r\nA002 SELECT INBOX\r\nA003 LOGOUT\r\n",
                crate::BASE64_ENGINE.encode(b"password")
            )
            .as_bytes(),
        )
        .await
        .expect("write password and commands");
    reader.get_mut().flush().await.expect("flush");
    let auth_lines = read_until_contains(&mut reader, "A001 OK").await;
    assert!(
        auth_lines
            .iter()
            .any(|line| line.contains("[CAPABILITY IMAP4rev1") && line.contains("UIDPLUS"))
    );
    assert!(
        auth_lines
            .iter()
            .any(|l| l.contains("AUTHENTICATE completed"))
    );
    let select_lines = read_until_contains(&mut reader, "A002 OK").await;
    assert!(select_lines.iter().any(|l| l.contains("SELECT completed")));
    let _logout = read_until_contains(&mut reader, "A003 OK").await;
    server_task.await.expect("join").expect("server");

    let (client, server) = duplex(16 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            mail_root.to_string_lossy().to_string(),
            None::<Arc<crate::tls::TlsContext>>,
            Some(db_path.to_string_lossy().to_string()),
            None,
            false,
        )
        .await
    });
    let mut reader = BufReader::new(client);
    let mut greeting = String::new();
    reader
        .read_line(&mut greeting)
        .await
        .expect("plain greeting");
    let mut capability = String::new();
    reader
        .read_line(&mut capability)
        .await
        .expect("plain capability");
    assert!(!capability.contains("AUTH=LOGIN"));
    reader
        .get_mut()
        .write_all(b"A001 AUTHENTICATE LOGIN\r\nA002 LOGOUT\r\n")
        .await
        .expect("write plain auth commands");
    reader.get_mut().flush().await.expect("flush");
    let auth_lines = read_until_contains(&mut reader, "A001 NO").await;
    assert!(auth_lines.iter().any(|l| l.contains("Encryption required")));
    let _logout = read_until_contains(&mut reader, "A002 OK").await;
    server_task.await.expect("join").expect("plain server");
}
#[tokio::test]
async fn authenticate_scram_sha256_logs_in_with_real_proof_without_tls() {
    let td = tempfile::tempdir().expect("tempdir");
    let mail_root = td.path().join("mail");
    let db_path = td.path().join("config.db");
    let scram =
        rmail_common::auth::create_scram_verifier("password", 4096).expect("create scram verifier");
    rmail_common::db::init_db(&db_path).expect("init db");
    rmail_common::db::add_mailbox(
        &db_path,
        "user@example.test",
        Some("plain:password"),
        None,
        Some(&scram),
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
            false,
        )
        .await
    });

    let mut reader = BufReader::new(client);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.expect("greeting");
    let mut capability = String::new();
    reader.read_line(&mut capability).await.expect("capability");
    assert!(capability.contains("AUTH=SCRAM-SHA-256"));

    reader
        .get_mut()
        .write_all(b"A000 AUTHENTICATE SCRAM-SHA-256\r\n")
        .await
        .expect("start cancellable scram");
    reader.get_mut().flush().await.expect("flush");
    let challenge = read_until_contains(&mut reader, "+ ").await;
    assert!(challenge.iter().any(|line| line == "+ \r\n"));
    reader
        .get_mut()
        .write_all(b"*\r\n")
        .await
        .expect("cancel scram");
    reader.get_mut().flush().await.expect("flush");
    let cancelled = read_until_contains(&mut reader, "A000 BAD").await.join("");
    assert!(cancelled.contains("AUTHENTICATE cancelled"));

    reader
        .get_mut()
        .write_all(b"A000B AUTHENTICATE SCRAM-SHA-256 !!!\r\n")
        .await
        .expect("malformed scram");
    reader.get_mut().flush().await.expect("flush");
    let malformed = read_until_contains(&mut reader, "A000B BAD").await.join("");
    assert!(malformed.contains("Invalid SCRAM client-first message"));

    let client_first_bare = "n=user@example.test,r=clientnonce";
    let client_first = format!("n,,{}", client_first_bare);
    let client_first_b64 = crate::BASE64_ENGINE.encode(client_first.as_bytes());
    reader
        .get_mut()
        .write_all(format!("A001 AUTHENTICATE SCRAM-SHA-256 {}\r\n", client_first_b64).as_bytes())
        .await
        .expect("write client first");
    reader.get_mut().flush().await.expect("flush");

    let server_first_lines = read_until_contains(&mut reader, "+ ").await;
    let server_first_line = server_first_lines
        .iter()
        .find(|line| line.starts_with("+ "))
        .expect("server first")
        .trim();
    let server_first_b64 = server_first_line.trim_start_matches("+ ").trim();
    let server_first = String::from_utf8(
        crate::BASE64_ENGINE
            .decode(server_first_b64)
            .expect("decode server first"),
    )
    .expect("server first utf8");
    let client_final = scram_client_final("password", client_first_bare, &server_first);
    reader
        .get_mut()
        .write_all(format!("{}\r\n", crate::BASE64_ENGINE.encode(client_final)).as_bytes())
        .await
        .expect("write client final");
    reader.get_mut().flush().await.expect("flush");

    let server_final_lines = read_until_contains(&mut reader, "+ ").await;
    assert!(
        server_final_lines
            .iter()
            .any(|line| line.starts_with("+ ") && line.contains('='))
    );
    reader
        .get_mut()
        .write_all(b"\r\nA002 SELECT INBOX\r\nA003 LOGOUT\r\n")
        .await
        .expect("finish scram and write commands");
    reader.get_mut().flush().await.expect("flush");

    let auth_lines = read_until_contains(&mut reader, "A001 OK").await;
    assert!(
        auth_lines
            .iter()
            .any(|line| line.contains("[CAPABILITY IMAP4rev1") && line.contains("UIDPLUS"))
    );
    assert!(
        auth_lines
            .iter()
            .any(|line| line.contains("AUTHENTICATE completed"))
    );
    let select_lines = read_until_contains(&mut reader, "A002 OK").await;
    assert!(
        select_lines
            .iter()
            .any(|line| line.contains("SELECT completed"))
    );
    let _logout = read_until_contains(&mut reader, "A003 OK").await;

    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn authenticate_scram_sha256_plus_verifies_tls_server_endpoint_binding() {
    let td = tempfile::tempdir().expect("tempdir");
    let mail_root = td.path().join("mail");
    let db_path = td.path().join("config.db");
    let scram =
        rmail_common::auth::create_scram_verifier("password", 4096).expect("create scram verifier");
    rmail_common::db::init_db(&db_path).expect("init db");
    rmail_common::db::add_mailbox(
        &db_path,
        "user@example.test",
        Some("plain:password"),
        None,
        Some(&scram),
    )
    .expect("add mailbox");

    let server_end_point = vec![0x5a; 32];
    let server_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(
            tokio_rustls::rustls::server::ResolvesServerCertUsingSni::new(),
        ));
    let tls_context = Arc::new(crate::tls::TlsContext {
        acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(server_config)),
        server_end_point: server_end_point.clone(),
    });
    let (client, server) = duplex(32 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            mail_root.to_string_lossy().to_string(),
            Some(tls_context),
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
    assert!(capability.contains("AUTH=SCRAM-SHA-256-PLUS"));

    let client_first_bare = "n=user@example.test,r=plusnonce";
    let gs2_header = b"p=tls-server-end-point,,";
    let client_first = format!(
        "{}{}",
        std::str::from_utf8(gs2_header).unwrap(),
        client_first_bare
    );
    reader
        .get_mut()
        .write_all(
            format!(
                "A001 AUTHENTICATE SCRAM-SHA-256-PLUS {}\r\n",
                crate::BASE64_ENGINE.encode(client_first)
            )
            .as_bytes(),
        )
        .await
        .expect("client first");
    reader.get_mut().flush().await.expect("flush");
    let server_first_line = read_until_contains(&mut reader, "+ ")
        .await
        .into_iter()
        .find(|line| line.starts_with("+ "))
        .expect("server first");
    let server_first = String::from_utf8(
        crate::BASE64_ENGINE
            .decode(server_first_line.trim().trim_start_matches("+ "))
            .expect("decode server first"),
    )
    .expect("server first UTF-8");
    let client_final = scram_client_final_with_binding(
        "password",
        client_first_bare,
        &server_first,
        gs2_header,
        &server_end_point,
    );
    reader
        .get_mut()
        .write_all(format!("{}\r\n", crate::BASE64_ENGINE.encode(client_final)).as_bytes())
        .await
        .expect("client final");
    reader.get_mut().flush().await.expect("flush");
    let server_final = read_until_contains(&mut reader, "+ ").await;
    assert!(server_final.iter().any(|line| line.starts_with("+ ")));
    reader
        .get_mut()
        .write_all(b"\r\nA002 LOGOUT\r\n")
        .await
        .expect("finish");
    reader.get_mut().flush().await.expect("flush");
    let auth = read_until_contains(&mut reader, "A001 OK").await.join("");
    assert!(auth.contains("AUTHENTICATE completed"));
    let _logout = read_until_contains(&mut reader, "A002 OK").await;
    server_task.await.expect("join").expect("server");
}
