//! FETCH and UID FETCH: sections, partials, BINARY, BODYSTRUCTURE and \Seen side effects.

use super::*;

#[tokio::test]
async fn fetch_refreshes_after_new_delivery() {
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
    rmail_common::maildir::deliver(
        &mail_root,
        "example.test",
        "user",
        b"Subject: one\r\n\r\nfirst\r\n",
    )
    .expect("deliver first");

    let (client, server) = duplex(16 * 1024);
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
    assert!(greeting.starts_with("* OK"));

    reader
        .get_mut()
        .write_all(b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\n")
        .await
        .expect("write login/select");
    reader.get_mut().flush().await.expect("flush");

    let select_lines = read_until_contains(&mut reader, "A002 OK").await;
    assert!(select_lines.iter().any(|l| l.contains("* 1 EXISTS")));

    rmail_common::maildir::deliver(
        td.path().join("mail").as_path(),
        "example.test",
        "user",
        b"Subject: two\r\n\r\nsecond\r\n",
    )
    .expect("deliver second");

    reader
        .get_mut()
        .write_all(b"A003 FETCH 1:* RFC822\r\nA004 LOGOUT\r\n")
        .await
        .expect("write fetch");
    reader.get_mut().flush().await.expect("flush");

    let fetch_lines = read_until_contains(&mut reader, "A003 OK").await;
    let fetched = fetch_lines
        .iter()
        .filter(|l| l.starts_with("* ") && l.contains(" FETCH "))
        .count();
    assert_eq!(fetched, 2);

    let logout_lines = read_until_contains(&mut reader, "A004 OK").await;
    assert!(logout_lines.iter().any(|l| l.starts_with("* BYE")));

    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn uid_fetch_flags_does_not_send_full_message_literal() {
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
    rmail_common::maildir::deliver(
        &mail_root,
        "example.test",
        "user",
        b"Subject: one\r\n\r\nfirst\r\n",
    )
    .expect("deliver");

    let (client, server) = duplex(16 * 1024);
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
    reader
        .read_line(&mut capability)
        .await
        .expect("capability greeting");

    reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID FETCH 1:* (FLAGS)\r\nA004 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _select_lines = read_until_contains(&mut reader, "A002 OK").await;
    let fetch_lines = read_until_contains(&mut reader, "A003 OK").await;
    assert!(fetch_lines.iter().any(|l| l.contains("FLAGS")));
    assert!(fetch_lines.iter().any(|l| l.contains("UID ")));
    assert!(!fetch_lines.iter().any(|l| l.contains("RFC822 {")));
    assert!(!fetch_lines.iter().any(|l| l.contains("BODY[] {")));

    let _logout_lines = read_until_contains(&mut reader, "A004 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn uid_fetch_header_fields_uses_matching_body_section_name() {
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
    rmail_common::maildir::deliver(
        &mail_root,
        "example.test",
        "user",
        b"From: a@example.test\r\nTo: user@example.test\r\nSubject: one\r\n\r\nfirst\r\n",
    )
    .expect("deliver");

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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID FETCH 1:* (UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT)])\r\nA004 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _select_lines = read_until_contains(&mut reader, "A002 OK").await;
    let fetch_lines = read_until_contains(&mut reader, "A003 OK").await;
    assert!(
        fetch_lines
            .iter()
            .any(|l| l.contains("BODY[HEADER.FIELDS (FROM TO SUBJECT)] {"))
    );
    let joined = fetch_lines.join("");
    assert!(joined.contains("From: a@example.test"));
    assert!(joined.contains("To: user@example.test"));
    assert!(joined.contains("Subject: one"));
    assert!(!joined.contains("Date:"));
    assert!(!joined.contains("\r\n\r\nfirst"));
    assert!(joined.contains("Subject: one\r\n\r\n)\r\n"));
    assert!(!joined.contains("Subject: one\r\n\r\n\r\n)\r\n"));

    let _logout_lines = read_until_contains(&mut reader, "A004 OK").await;
    server_task.await.expect("join").expect("server");
}
#[test]
fn fetch_parser_keeps_nested_header_fields_together() {
    let items = crate::parser::parse_fetch_request(
            "(UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (From To Cc Bcc Subject Date Message-ID Priority X-Priority References Newsgroups In-Reply-To Content-Type Reply-To Received)])",
        )
        .unwrap()
        .items;

    assert_eq!(
        items,
        vec![
            "BODY.PEEK[HEADER.FIELDS (FROM TO CC BCC SUBJECT DATE MESSAGE-ID PRIORITY X-PRIORITY REFERENCES NEWSGROUPS IN-REPLY-TO CONTENT-TYPE REPLY-TO RECEIVED)]",
            "FLAGS",
            "RFC822.SIZE",
            "UID",
        ]
    );
}
#[tokio::test]
async fn uid_fetch_header_fields_not_excludes_requested_headers() {
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
    rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"From: a@example.test\r\nTo: user@example.test\r\nSubject: one\r\nX-Spam: no\r\n\r\nfirst\r\n",
        )
        .expect("deliver");

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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID FETCH 1:* (UID BODY.PEEK[HEADER.FIELDS.NOT (SUBJECT)])\r\nA004 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _select_lines = read_until_contains(&mut reader, "A002 OK").await;
    let fetch_lines = read_until_contains(&mut reader, "A003 OK").await;
    let joined = fetch_lines.join("");
    assert!(joined.contains("BODY[HEADER.FIELDS.NOT (SUBJECT)] {"));
    assert!(joined.contains("From: a@example.test"));
    assert!(joined.contains("X-Spam: no"));
    assert!(!joined.contains("Subject: one"));

    let _logout_lines = read_until_contains(&mut reader, "A004 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn uid_fetch_supports_body_text_and_partial_literals() {
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
    rmail_common::maildir::deliver(
        &mail_root,
        "example.test",
        "user",
        b"From: a@example.test\r\nSubject: body ranges\r\n\r\n0123456789abcdef\r\n",
    )
    .expect("deliver");

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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID FETCH 1:* (UID BODY[TEXT]<2.5>)\r\nA004 UID FETCH 1:* (UID BODY.PEEK[HEADER] BODY.PEEK[]<0.12>)\r\nA005 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _select_lines = read_until_contains(&mut reader, "A002 OK").await;
    let text_lines = read_until_contains(&mut reader, "A003 OK").await;
    let joined_text = text_lines.join("");
    assert!(joined_text.contains("BODY[TEXT]<2> {5}"));
    assert!(joined_text.contains("23456"));
    assert!(!joined_text.contains("Subject: body ranges"));

    let partial_lines = read_until_contains(&mut reader, "A004 OK").await;
    let joined_partial = partial_lines.join("");
    assert!(joined_partial.contains("BODY[HEADER] {"));
    assert!(joined_partial.contains("Subject: body ranges"));
    assert!(joined_partial.contains("BODY[]<0> {12}"));
    assert!(joined_partial.contains("From: a@exam"));
    assert!(!joined_partial.contains("0123456789abcdef"));

    let _logout_lines = read_until_contains(&mut reader, "A005 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn fetch_body_seen_side_effect_respects_peek_headers_and_examine() {
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
    for subject in ["peek", "body", "examine"] {
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            format!("Subject: {subject}\r\n\r\ncontents\r\n").as_bytes(),
        )
        .expect("deliver");
    }

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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 FETCH 1 (FLAGS MODSEQ BODY.PEEK[])\r\nA004 FETCH 1 (FLAGS MODSEQ RFC822.HEADER)\r\nA005 FETCH 2 (FLAGS MODSEQ BODY[TEXT])\r\nA006 FETCH 2 (FLAGS MODSEQ BODY[TEXT])\r\nA007 EXAMINE INBOX\r\nA008 FETCH 3 (FLAGS MODSEQ RFC822.TEXT)\r\nA009 LOGOUT\r\n",
            )
            .await
            .expect("commands");
    reader.get_mut().flush().await.expect("flush");

    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let _select = read_until_contains(&mut reader, "A002 OK").await;
    let peek = read_until_contains(&mut reader, "A003 OK").await.join("");
    assert!(!peek.contains("\\Seen"));
    let header = read_until_contains(&mut reader, "A004 OK").await.join("");
    assert!(!header.contains("\\Seen"));
    let body = read_until_contains(&mut reader, "A005 OK").await.join("");
    assert!(body.contains("\\Seen"));
    assert!(body.contains("\\Recent"));
    let body_modseq = body
        .split("MODSEQ (")
        .nth(1)
        .and_then(|value| value.split(')').next())
        .expect("body modseq")
        .to_string();
    let repeated = read_until_contains(&mut reader, "A006 OK").await.join("");
    assert!(repeated.contains(&format!("MODSEQ ({body_modseq})")));
    let _examine = read_until_contains(&mut reader, "A007 OK").await;
    let examined = read_until_contains(&mut reader, "A008 OK").await.join("");
    assert!(!examined.contains("\\Seen"));

    let _logout = read_until_contains(&mut reader, "A009 OK").await;
    server_task.await.expect("join").expect("server");
    let (_, messages) =
        rmail_common::imap_state::load_folder(&mail_root, "example.test", "user", "INBOX")
            .expect("folder");
    assert!(!messages[0].flags.iter().any(|flag| flag == "\\Seen"));
    assert!(messages[1].flags.iter().any(|flag| flag == "\\Seen"));
    assert!(!messages[2].flags.iter().any(|flag| flag == "\\Seen"));
}
#[tokio::test]
async fn binary_fetch_decodes_sizes_partials_failures_and_seen_semantics() {
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
    rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8Ad29ybGQ=\r\n--x\r\nContent-Transfer-Encoding: base64\r\n\r\n%%%\r\n--x--\r\n",
        )
        .expect("deliver");

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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CAPABILITY\r\nA003 SELECT INBOX\r\nA004 UID FETCH 1 (FLAGS BODY[0])\r\nA005 UID FETCH 1 (FLAGS BINARY.SIZE[1] BINARY.PEEK[1]<6.5> BINARY.PEEK[2])\r\nA006 UID FETCH 1 (FLAGS MODSEQ BINARY[1]<0.5>)\r\nA007 LOGOUT\r\n",
            )
            .await
            .expect("commands");
    reader.get_mut().flush().await.expect("flush");
    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let caps = read_until_contains(&mut reader, "A002 OK").await.join("");
    assert!(caps.contains(" BINARY"));
    let _select = read_until_contains(&mut reader, "A003 OK").await;
    let invalid = read_until_contains(&mut reader, "A004 BAD").await.join("");
    assert!(invalid.contains("Invalid UID FETCH arguments"));
    let peek = read_until_contains(&mut reader, "A005 OK").await.join("");
    assert!(peek.contains("BINARY.SIZE[1] 11"));
    assert!(peek.contains("BINARY[1]<6> ~{5}\r\nworld"));
    assert!(peek.contains("BINARY[2] NIL"));
    assert!(!peek.contains("\\Seen"));
    let body = read_until_contains(&mut reader, "A006 OK").await.join("");
    assert!(body.contains("\\Seen"));
    assert!(body.contains("\\Recent"));
    assert!(body.contains("BINARY[1]<0> ~{5}\r\nhello"));
    let _logout = read_until_contains(&mut reader, "A007 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn fetch_macros_envelope_and_bodystructure_are_parseable() {
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
    rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Date: Sun, 14 Jun 2026 12:00:00 +0000\r\nFrom: Sender Name <sender@example.test>\r\nTo: User <user@example.test>\r\nCc: copy@example.test\r\nMessage-ID: <m1@example.test>\r\nSubject: macro\r\n\r\nbody\r\n",
        )
        .expect("deliver");

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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 FETCH 1 FULL\r\nA004 UID FETCH 1:* (UID BODYSTRUCTURE ENVELOPE)\r\nA005 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _select = read_until_contains(&mut reader, "A002 OK").await;
    let full_lines = read_until_contains(&mut reader, "A003 OK").await;
    let joined_full = full_lines.join("");
    assert!(joined_full.contains("FLAGS"));
    assert!(joined_full.contains("INTERNALDATE"));
    assert!(joined_full.contains("RFC822.SIZE"));
    assert!(joined_full.contains("ENVELOPE"));
    assert!(joined_full.contains("BODYSTRUCTURE"));

    let uid_lines = read_until_contains(&mut reader, "A004 OK").await;
    let joined_uid = uid_lines.join("");
    assert!(joined_uid.contains("UID "));
    assert!(joined_uid.contains("BODYSTRUCTURE"));
    assert!(joined_uid.contains("ENVELOPE"));
    assert!(joined_uid.contains("(\"Sender Name\" NIL \"sender\" \"example.test\")"));
    assert!(joined_uid.contains("(\"User\" NIL \"user\" \"example.test\")"));
    assert!(joined_uid.contains("(NIL NIL \"copy\" \"example.test\")"));
    assert!(joined_uid.contains("\"<m1@example.test>\""));

    let _logout = read_until_contains(&mut reader, "A005 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn bodystructure_describes_multipart_html_inline_and_attachment_parts() {
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
    rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"From: a@example.test\r\nSubject: multipart\r\nContent-Type: multipart/mixed; boundary=\"mix\"\r\n\r\n--mix\r\nContent-Type: multipart/alternative; boundary=\"alt\"\r\n\r\n--alt\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nPlain body\r\n--alt\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<p>HTML body</p>\r\n--alt--\r\n--mix\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\nContent-ID: <logo@example.test>\r\nContent-Disposition: inline; filename=\"logo.png\"\r\n\r\naGVsbG8=\r\n--mix\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"file.pdf\"\r\n\r\n%PDF\r\n--mix--\r\n",
        )
        .expect("deliver");

    let (client, server) = duplex(64 * 1024);
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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID FETCH 1:* (UID BODYSTRUCTURE)\r\nA004 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _select = read_until_contains(&mut reader, "A002 OK").await;
    let fetch_lines = read_until_contains(&mut reader, "A003 OK").await;
    let joined = fetch_lines.join("");
    assert!(joined.contains("BODYSTRUCTURE"));
    assert!(joined.contains("\"MIXED\""));
    assert!(joined.contains("\"ALTERNATIVE\""));
    assert!(joined.contains("\"TEXT\" \"HTML\""));
    assert!(joined.contains("\"IMAGE\" \"PNG\""));
    assert!(joined.contains("\"APPLICATION\" \"PDF\""));
    assert!(joined.contains("\"INLINE\" (\"FILENAME\" \"logo.png\")"));
    assert!(joined.contains("\"ATTACHMENT\" (\"FILENAME\" \"file.pdf\")"));
    assert!(joined.contains("logo@example.test"));

    let _logout = read_until_contains(&mut reader, "A004 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn fetch_body_sections_return_mime_part_content_and_headers() {
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
    rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"From: a@example.test\r\nSubject: sections\r\nContent-Type: multipart/mixed; boundary=\"mix\"\r\n\r\n--mix\r\nContent-Type: text/plain; charset=UTF-8\r\nX-Part: one\r\n\r\nPlain part body\r\n--mix\r\nContent-Type: multipart/alternative; boundary=\"alt\"\r\n\r\n--alt\r\nContent-Type: text/plain\r\n\r\nAlt plain\r\n--alt\r\nContent-Type: text/html\r\n\r\n<p>Alt HTML</p>\r\n--alt--\r\n--mix--\r\n",
        )
        .expect("deliver");

    let (client, server) = duplex(64 * 1024);
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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID FETCH 1:* (UID BODY.PEEK[1])\r\nA004 UID FETCH 1:* (UID BODY.PEEK[1.MIME])\r\nA005 UID FETCH 1:* (UID BODY.PEEK[2.2])\r\nA006 UID FETCH 1:* (UID BODY.PEEK[2.2]<3.8>)\r\nA007 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let _select = read_until_contains(&mut reader, "A002 OK").await;

    let part_body = read_until_contains(&mut reader, "A003 OK").await;
    let joined = part_body.join("");
    assert!(joined.contains("BODY[1]"));
    assert!(joined.contains("Plain part body"));
    assert!(!joined.contains("Content-Type: text/plain; charset=UTF-8"));
    assert!(!joined.contains("<p>Alt HTML</p>"));

    let part_mime = read_until_contains(&mut reader, "A004 OK").await;
    let joined = part_mime.join("");
    assert!(joined.contains("BODY[1.MIME]"));
    assert!(joined.contains("Content-Type: text/plain; charset=UTF-8"));
    assert!(joined.contains("X-Part: one"));
    assert!(!joined.contains("Plain part body"));

    let nested_html = read_until_contains(&mut reader, "A005 OK").await;
    let joined = nested_html.join("");
    assert!(joined.contains("BODY[2.2]"));
    assert!(joined.contains("<p>Alt HTML</p>"));
    assert!(!joined.contains("Alt plain"));

    let partial_html = read_until_contains(&mut reader, "A006 OK").await;
    let joined = partial_html.join("");
    assert!(joined.contains("BODY[2.2]<3> {8}"));
    assert!(joined.contains("Alt HTML"));
    assert!(!joined.contains("<p>"));

    let _logout = read_until_contains(&mut reader, "A007 OK").await;
    server_task.await.expect("join").expect("server");
}
