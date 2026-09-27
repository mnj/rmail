//! APPEND, MULTIAPPEND, CATENATE and quota enforcement.

use super::*;

#[tokio::test]
async fn append_preserves_literal_bytes_returns_appenduid_and_requires_existing_mailbox() {
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

    let server_mail_root = mail_root.clone();
    let (client, server) = duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            server_mail_root.to_string_lossy().to_string(),
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
    assert!(!capability.contains("UIDPLUS"));
    assert!(capability.contains("LITERAL-"));
    assert!(capability.contains("LITERAL+"));

    let raw = b"Subject: appended\r\nX-Raw: \xff\r\n\r\nbody\x00bytes\r\n";
    let raw_non_sync = b"Subject: non-sync\r\n\r\nliteral-minus\r\n";
    let mut commands = Vec::new();
    commands.extend_from_slice(b"A001 LOGIN \"user@example.test\" \"password\"\r\n");
    commands
        .extend_from_slice(format!("A002 APPEND Sent (\\Seen) {{{}}}\r\n", raw.len()).as_bytes());
    commands.extend_from_slice(raw);
    commands.extend_from_slice(b"\r\n");
    commands.extend_from_slice(
        format!("A003 APPEND Archive {{{}+}}\r\n", raw_non_sync.len()).as_bytes(),
    );
    commands.extend_from_slice(raw_non_sync);
    commands.extend_from_slice(b"\r\n");
    commands.extend_from_slice(b"A004 APPEND Sent ~{3+}\r\n");
    commands.extend_from_slice(b"x\0y\r\n");
    let large_non_sync = vec![b'x'; 4097];
    commands.extend_from_slice(b"A005 APPEND Sent {4097+}\r\n");
    commands.extend_from_slice(&large_non_sync);
    commands.extend_from_slice(b"\r\n");
    commands.extend_from_slice(format!("A006 APPEND Missing {{{}}}\r\n", raw.len()).as_bytes());
    commands.extend_from_slice(format!("A007 APPEND Missing {{{}+}}\r\n", raw.len()).as_bytes());
    commands.extend_from_slice(raw);
    commands.extend_from_slice(b"\r\nA008 LOGOUT\r\n");
    reader
        .get_mut()
        .write_all(&commands)
        .await
        .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let append_lines = read_until_contains(&mut reader, "A002 OK").await;
    assert!(append_lines.iter().any(|l| l.starts_with("+ ")));
    assert!(append_lines.iter().any(|l| l.contains("APPENDUID")));

    let non_sync_append_lines = read_until_contains(&mut reader, "A003 OK").await;
    assert!(!non_sync_append_lines.iter().any(|l| l.starts_with("+ ")));
    assert!(
        non_sync_append_lines
            .iter()
            .any(|l| l.contains("APPENDUID"))
    );

    let literal8_lines = read_until_contains(&mut reader, "A004 OK").await;
    assert!(literal8_lines.iter().any(|l| l.contains("APPENDUID")));

    let large_non_sync_lines = read_until_contains(&mut reader, "A005 OK").await;
    assert!(!large_non_sync_lines.iter().any(|l| l.starts_with("+ ")));
    assert!(large_non_sync_lines.iter().any(|l| l.contains("APPENDUID")));

    let missing_lines = read_until_contains(&mut reader, "A006 NO").await;
    assert!(!missing_lines.iter().any(|l| l.starts_with("+ ")));
    assert!(missing_lines.iter().any(|l| l.contains("TRYCREATE")));

    let non_sync_missing_lines = read_until_contains(&mut reader, "A007 NO").await;
    assert!(
        non_sync_missing_lines
            .iter()
            .any(|l| l.contains("APPEND failed"))
    );
    assert!(
        non_sync_missing_lines
            .iter()
            .any(|l| l.contains("TRYCREATE"))
    );

    let _logout = read_until_contains(&mut reader, "A008 OK").await;
    server_task.await.expect("join").expect("server");

    let (_, sent) =
        rmail_common::imap_state::load_folder(&mail_root, "example.test", "user", "Sent")
            .expect("load sent");
    assert_eq!(sent.len(), 3);
    assert!(sent.iter().any(|message| {
        std::fs::read(&message.path).is_ok_and(|bytes| bytes == large_non_sync)
    }));
    assert!(
        sent[0]
            .flags
            .iter()
            .any(|f| f.eq_ignore_ascii_case("\\Seen"))
    );
    assert_eq!(std::fs::read(&sent[0].path).expect("read appended"), raw);
    assert_eq!(
        std::fs::read(&sent[1].path).expect("read binary appended"),
        b"x\0y"
    );
    let (_, archive) =
        rmail_common::imap_state::load_folder(&mail_root, "example.test", "user", "Archive")
            .expect("load archive");
    assert_eq!(archive.len(), 1);
    assert_eq!(
        std::fs::read(&archive[0].path).expect("read non-sync appended"),
        raw_non_sync
    );
    assert!(
        !rmail_common::imap_state::folder_exists(&mail_root, "example.test", "user", "Missing")
            .expect("missing folder check")
    );
}
#[tokio::test]
async fn multiappend_streams_messages_atomically_and_returns_ordered_uids() {
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
    let server_root = mail_root.clone();
    let (client, server) = duplex(32 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            server_root.to_string_lossy().to_string(),
            None::<Arc<crate::tls::TlsContext>>,
            Some(db_path.to_string_lossy().to_string()),
            None,
            true,
        )
        .await
    });
    let mut reader = BufReader::new(client);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.unwrap();
    let mut capability = String::new();
    reader.read_line(&mut capability).await.unwrap();

    let first = b"Subject: first\r\n\r\none";
    let second = b"Subject: second\r\n\r\ntwo";
    let third = b"Subject: third\r\n\r\nthree";
    let fourth = b"Subject: fourth\r\n\r\nfour";
    let mut commands = b"A001 LOGIN user@example.test password\r\n".to_vec();
    commands.extend_from_slice(
        format!("A002 APPEND INBOX (\\Seen) {{{}+}}\r\n", first.len()).as_bytes(),
    );
    commands.extend_from_slice(first);
    commands.extend_from_slice(format!(" (\\Flagged) {{{}}}\r\n", second.len()).as_bytes());
    commands.extend_from_slice(second);
    commands.extend_from_slice(format!(" CATENATE (TEXT {{{}+}}\r\n", third.len()).as_bytes());
    commands.extend_from_slice(third);
    commands.extend_from_slice(b")\r\n");
    commands.extend_from_slice(
        format!("A003 APPEND INBOX CATENATE (TEXT {{{}+}}\r\n", third.len()).as_bytes(),
    );
    commands.extend_from_slice(third);
    commands.extend_from_slice(format!(") (\\Draft) {{{}+}}\r\n", fourth.len()).as_bytes());
    commands.extend_from_slice(fourth);
    commands.extend_from_slice(b"\r\nA004 APPEND INBOX {0+}\r\n {1+}\r\nx\r\nA005 LOGOUT\r\n");
    reader.get_mut().write_all(&commands).await.unwrap();
    reader.get_mut().flush().await.unwrap();

    let login = read_until_contains(&mut reader, "A001 OK").await;
    assert!(login.iter().any(|line| line.contains("MULTIAPPEND")));
    let appended = read_until_contains(&mut reader, "A002 OK").await;
    let response = appended.join("");
    assert!(response.contains("APPENDUID"));
    assert!(response.contains(':'));
    assert!(response.contains("+ Ready"));
    let reverse_mix = read_until_contains(&mut reader, "A003 OK").await.join("");
    assert!(reverse_mix.contains("APPENDUID"), "{reverse_mix:?}");
    assert!(reverse_mix.contains(':'));
    let cancelled = read_until_contains(&mut reader, "A004 NO").await;
    assert!(cancelled.join("").contains("zero-length MULTIAPPEND"));
    let _logout = read_until_contains(&mut reader, "A005 OK").await;
    server_task.await.unwrap().unwrap();

    let (_, mut messages) =
        rmail_common::imap_state::load_folder(&mail_root, "example.test", "user", "INBOX").unwrap();
    messages.sort_by_key(|message| message.uid);
    assert_eq!(messages.len(), 5);
    assert_eq!(std::fs::read(&messages[0].path).unwrap(), first);
    assert_eq!(std::fs::read(&messages[1].path).unwrap(), second);
    assert_eq!(std::fs::read(&messages[2].path).unwrap(), third);
    assert_eq!(std::fs::read(&messages[3].path).unwrap(), third);
    assert_eq!(std::fs::read(&messages[4].path).unwrap(), fourth);
    assert!(
        messages[0]
            .flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\Seen"))
    );
    assert!(
        messages[1]
            .flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\Flagged"))
    );
    assert!(
        messages[4]
            .flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\Draft"))
    );
    assert_eq!(messages[1].uid, messages[0].uid + 1);
}
#[tokio::test]
async fn catenate_appends_text_and_same_session_url_sections_atomically() {
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

    let server_mail_root = mail_root.clone();
    let (client, server) = duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            server_mail_root.to_string_lossy().to_string(),
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
    assert!(!capability.contains("CATENATE"));

    let source = b"Subject: source\r\nX-Test: yes\r\n\r\nsource body\r\n";
    let prefix = b"Subject: composed\r\n\r\nprefix ";
    let suffix = b" suffix\r\n";
    let mut commands = Vec::new();
    commands.extend_from_slice(b"A001 LOGIN \"user@example.test\" \"password\"\r\n");
    commands.extend_from_slice(format!("A002 APPEND INBOX {{{}+}}\r\n", source.len()).as_bytes());
    commands.extend_from_slice(source);
    commands.extend_from_slice(b"\r\n");
    commands.extend_from_slice(
        format!(
            "A003 APPEND Sent (\\Seen) CATENATE (TEXT {{{}+}}\r\n",
            prefix.len()
        )
        .as_bytes(),
    );
    commands.extend_from_slice(prefix);
    commands.extend_from_slice(
        format!(
            " URL \"/INBOX/;UID=1/;section=TEXT\" TEXT {{{}+}}\r\n",
            suffix.len()
        )
        .as_bytes(),
    );
    commands.extend_from_slice(suffix);
    let literal_url = b"/INBOX/;UID=1";
    commands.extend_from_slice(
        format!(
            ")\r\nA004 APPEND Sent CATENATE (URL {{{}+}}\r\n",
            literal_url.len()
        )
        .as_bytes(),
    );
    commands.extend_from_slice(literal_url);
    commands.extend_from_slice(b")\r\nA005 APPEND Sent CATENATE (URL \"/INBOX/;UID=999\")\r\n");
    reader.get_mut().write_all(&commands).await.expect("write");
    reader.get_mut().flush().await.expect("flush");

    let login = read_until_contains(&mut reader, "A001 OK").await.join("");
    assert!(login.contains("CATENATE"));
    let source_append = read_until_contains(&mut reader, "A002 OK").await;
    assert!(source_append.iter().any(|line| line.contains("APPENDUID")));
    let catenate = read_until_contains(&mut reader, "A003 OK").await;
    assert!(catenate.iter().any(|line| line.contains("APPENDUID")));
    assert!(!catenate.iter().any(|line| line.starts_with("+ ")));
    let literal_url_append = read_until_contains(&mut reader, "A004 OK").await;
    assert!(
        literal_url_append
            .iter()
            .any(|line| line.contains("APPENDUID"))
    );
    let bad_url = read_until_contains(&mut reader, "A005 NO").await.join("");
    assert!(bad_url.contains("BADURL \"/INBOX/;UID=999\""));
    reader
        .get_mut()
        .write_all(format!("A006 APPEND Sent CATENATE (TEXT {{{}}}\r\n", suffix.len()).as_bytes())
        .await
        .expect("write synchronizing CATENATE");
    reader.get_mut().flush().await.expect("flush sync marker");
    let mut continuation = String::new();
    reader
        .read_line(&mut continuation)
        .await
        .expect("CATENATE continuation");
    assert!(continuation.starts_with("+ "));
    reader
        .get_mut()
        .write_all(suffix)
        .await
        .expect("write sync text");
    reader
        .get_mut()
        .write_all(b")\r\nA007 LOGOUT\r\n")
        .await
        .expect("finish commands");
    reader.get_mut().flush().await.expect("flush finish");
    let sync_append = read_until_contains(&mut reader, "A006 OK").await;
    assert!(sync_append.iter().any(|line| line.contains("APPENDUID")));
    let _logout = read_until_contains(&mut reader, "A007 OK").await;
    server_task.await.expect("join").expect("server");

    let (_, sent) =
        rmail_common::imap_state::load_folder(&mail_root, "example.test", "user", "Sent")
            .expect("load Sent");
    assert_eq!(sent.len(), 3);
    let mut expected = prefix.to_vec();
    expected.extend_from_slice(b"source body\r\n");
    expected.extend_from_slice(suffix);
    assert_eq!(
        std::fs::read(&sent[0].path).expect("read CATENATE result"),
        expected
    );
    assert!(sent[0].flags.iter().any(|flag| flag == "\\SEEN"));
    assert_eq!(
        std::fs::read(&sent[1].path).expect("read literal-URL result"),
        source
    );
    assert_eq!(
        std::fs::read(&sent[2].path).expect("read sync TEXT result"),
        suffix
    );
}
#[tokio::test]
async fn append_internal_date_is_validated_persisted_and_fetched_with_timezone() {
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

    let server_mail_root = mail_root.clone();
    let (client, server) = duplex(32 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            server_mail_root.to_string_lossy().to_string(),
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

    let raw = b"Subject: dated\r\n\r\nbody\r\n";
    let mut commands = Vec::new();
    commands.extend_from_slice(b"A001 LOGIN \"user@example.test\" \"password\"\r\n");
    commands.extend_from_slice(
        format!(
            "A002 APPEND Sent (\\Seen) \"17-Jul-1996 02:44:25 -0700\" {{{}}}\r\n",
            raw.len()
        )
        .as_bytes(),
    );
    commands.extend_from_slice(raw);
    commands.extend_from_slice(b"\r\nA003 SELECT Sent\r\nA004 FETCH 1 (UID INTERNALDATE)\r\n");
    commands.extend_from_slice(
        b"A005 APPEND Sent \"31-Apr-2025 12:00:00 +0000\" {1}\r\nA006 LOGOUT\r\n",
    );
    reader.get_mut().write_all(&commands).await.expect("write");
    reader.get_mut().flush().await.expect("flush");

    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let append = read_until_contains(&mut reader, "A002 OK").await;
    assert!(append.iter().any(|line| line.starts_with("+ ")));
    let _select = read_until_contains(&mut reader, "A003 OK").await;
    let fetch = read_until_contains(&mut reader, "A004 OK").await.join("");
    assert!(fetch.contains("INTERNALDATE \"17-Jul-1996 02:44:25 -0700\""));
    let invalid = read_until_contains(&mut reader, "A005 BAD").await;
    assert!(
        invalid
            .iter()
            .any(|line| line.contains("Invalid APPEND internal date"))
    );
    let _logout = read_until_contains(&mut reader, "A006 OK").await;
    server_task.await.expect("join").expect("server");

    let (_, messages) =
        rmail_common::imap_state::load_folder(&mail_root, "example.test", "user", "Sent")
            .expect("reload Sent");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].internaldate, 837_596_665);
    assert_eq!(messages[0].internaldate_tz, -420);
}
#[tokio::test]
async fn append_rejects_configured_storage_quota_without_publishing_message() {
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
    rmail_common::db::set_mailbox_quota(&db_path, "user@example.test", Some(5)).expect("set quota");
    let server_mail_root = mail_root.clone();
    let (client, server) = duplex(32 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            server_mail_root.to_string_lossy().to_string(),
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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 GETQUOTA \"\"\r\nA003 GETQUOTAROOT INBOX\r\nA004 SETQUOTA \"\" (STORAGE 2)\r\nA005 APPEND INBOX {6+}\r\n123456\r\nA006 LOGOUT\r\n",
            )
            .await
            .expect("commands");
    reader.get_mut().flush().await.expect("flush");
    let _login = read_until_contains_bounded(&mut reader, "A001 OK").await;
    let getquota = read_until_contains_bounded(&mut reader, "A002 OK").await;
    assert!(
        getquota
            .iter()
            .any(|line| line.trim_end() == "* QUOTA \"\" (STORAGE 0 1)")
    );
    let root = read_until_contains_bounded(&mut reader, "A003 OK").await;
    assert!(
        root.iter()
            .any(|line| line.trim_end() == "* QUOTAROOT \"INBOX\" \"\"")
    );
    assert!(
        root.iter()
            .any(|line| line.trim_end() == "* QUOTA \"\" (STORAGE 0 1)")
    );
    let setquota = read_until_contains_bounded(&mut reader, "A004 NO").await;
    assert!(setquota.iter().any(|line| line.contains("[NOPERM]")));
    let append = read_until_contains_bounded(&mut reader, "A005 NO").await;
    assert!(append.iter().any(|line| line.contains("[OVERQUOTA]")));
    let _logout = read_until_contains_bounded(&mut reader, "A006 OK").await;
    server_task.await.expect("join").expect("server");
    assert_eq!(
        rmail_common::imap_state::storage_quota(mail_root.as_path(), "example.test", "user")
            .expect("quota state"),
        (0, Some(5))
    );
}
