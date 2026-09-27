//! SEARCH/ESEARCH/SEARCHRES, SORT, THREAD and date-based search keys.

use super::*;

#[tokio::test]
async fn search_supports_headers_text_dates_ranges_or_and_not() {
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
            b"Date: Sun, 14 Jun 2026 12:00:00 +0000\r\nFrom: alice@example.test\r\nTo: user@example.test\r\nCc: team@example.test\r\nSubject: Alpha Project\r\n\r\nbody has rocket text\r\n",
        )
        .expect("deliver one");
    rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Date: Mon, 15 Jun 2026 12:00:00 +0000\r\nFrom: bob@example.test\r\nTo: user@example.test\r\nSubject: Beta Report\r\n\r\nbody has invoice text\r\n",
        )
        .expect("deliver two");

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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID STORE 1 +FLAGS (\\Seen)\r\nA004 SEARCH UNSEEN\r\nA005 SEARCH FROM alice\r\nA006 SEARCH BODY invoice\r\nA007 SEARCH TEXT rocket\r\nA008 UID SEARCH UID 2:*\r\nA009 SEARCH OR SUBJECT Alpha SUBJECT Beta\r\nA010 SEARCH NOT FROM alice\r\nA011 SEARCH 2\r\nA012 UID SEARCH SENTSINCE 15-Jun-2026 SENTBEFORE 16-Jun-2026\r\nA013 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _select = read_until_contains(&mut reader, "A002 OK").await;
    let _store = read_until_contains(&mut reader, "A003 OK").await;

    let unseen = read_until_contains(&mut reader, "A004 OK").await;
    assert!(unseen.iter().any(|l| l.trim_end() == "* SEARCH 2"));

    let from = read_until_contains(&mut reader, "A005 OK").await;
    assert!(from.iter().any(|l| l.trim_end() == "* SEARCH 1"));

    let body = read_until_contains(&mut reader, "A006 OK").await;
    assert!(body.iter().any(|l| l.trim_end() == "* SEARCH 2"));

    let text = read_until_contains(&mut reader, "A007 OK").await;
    assert!(text.iter().any(|l| l.trim_end() == "* SEARCH 1"));

    let uid_range = read_until_contains(&mut reader, "A008 OK").await;
    assert!(uid_range.iter().any(|l| l.trim_end() == "* SEARCH 2"));

    let or_lines = read_until_contains(&mut reader, "A009 OK").await;
    assert!(or_lines.iter().any(|l| l.trim_end() == "* SEARCH 1 2"));

    let not_lines = read_until_contains(&mut reader, "A010 OK").await;
    assert!(not_lines.iter().any(|l| l.trim_end() == "* SEARCH 2"));

    let seq_range = read_until_contains(&mut reader, "A011 OK").await;
    assert!(seq_range.iter().any(|l| l.trim_end() == "* SEARCH 2"));

    let sent_date = read_until_contains(&mut reader, "A012 OK").await;
    assert!(sent_date.iter().any(|l| l.trim_end() == "* SEARCH 2"));

    let _logout = read_until_contains(&mut reader, "A013 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn search_supports_base_flags_keywords_sizes_headers_and_charset() {
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
    let large_body = "x".repeat(1500);
    rmail_common::imap_state::append_message(
            &mail_root,
            "example.test",
            "user",
            "INBOX",
            format!(
                "Date: Wed, 10 Jun 2026 12:00:00 +0000\r\nFrom: one@example.test\r\nSubject: First\r\nMessage-ID: <one@example.test>\r\n\r\n{}\r\n",
                large_body
            )
            .as_bytes(),
            vec!["\\Answered".to_string(), "$Work".to_string()],
        )
        .expect("append one");
    rmail_common::imap_state::append_message(
            &mail_root,
            "example.test",
            "user",
            "INBOX",
            b"Date: Thu, 11 Jun 2026 12:00:00 +0000\r\nFrom: two@example.test\r\nSubject: Second\r\nMessage-ID: <two@example.test>\r\n\r\nshort\r\n",
            vec!["\\Flagged".to_string(), "\\Draft".to_string()],
        )
        .expect("append two");
    rmail_common::imap_state::append_message(
            &mail_root,
            "example.test",
            "user",
            "INBOX",
            b"Date: Fri, 12 Jun 2026 12:00:00 +0000\r\nFrom: three@example.test\r\nSubject: Third\r\nMessage-ID: <three@example.test>\r\n\r\nshort\r\n",
            vec!["\\Recent".to_string()],
        )
        .expect("append three");

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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 SEARCH ANSWERED\r\nA004 SEARCH UNANSWERED\r\nA005 SEARCH FLAGGED DRAFT\r\nA006 SEARCH KEYWORD $Work\r\nA007 SEARCH UNKEYWORD $Work\r\nA008 SEARCH NEW\r\nA009 SEARCH OLD\r\nA010 SEARCH SENTON 11-Jun-2026\r\nA011 SEARCH HEADER Message-ID two\r\nA012 SEARCH LARGER 1000\r\nA013 SEARCH SMALLER 1000\r\nA014 SEARCH CHARSET US-ASCII SUBJECT First\r\nA015 SEARCH CHARSET KOI8-R SUBJECT First\r\nA016 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let _select = read_until_contains(&mut reader, "A002 OK").await;
    let answered = read_until_contains(&mut reader, "A003 OK").await;
    assert!(answered.iter().any(|l| l.trim_end() == "* SEARCH 1"));
    let unanswered = read_until_contains(&mut reader, "A004 OK").await;
    assert!(unanswered.iter().any(|l| l.trim_end() == "* SEARCH 2 3"));
    let flagged_draft = read_until_contains(&mut reader, "A005 OK").await;
    assert!(flagged_draft.iter().any(|l| l.trim_end() == "* SEARCH 2"));
    let keyword = read_until_contains(&mut reader, "A006 OK").await;
    assert!(keyword.iter().any(|l| l.trim_end() == "* SEARCH 1"));
    let unkeyword = read_until_contains(&mut reader, "A007 OK").await;
    assert!(unkeyword.iter().any(|l| l.trim_end() == "* SEARCH 2 3"));
    let new = read_until_contains(&mut reader, "A008 OK").await;
    assert!(new.iter().any(|l| l.trim_end() == "* SEARCH 3"));
    let old = read_until_contains(&mut reader, "A009 OK").await;
    assert!(old.iter().any(|l| l.trim_end() == "* SEARCH 1 2"));
    let sent_on = read_until_contains(&mut reader, "A010 OK").await;
    assert!(sent_on.iter().any(|l| l.trim_end() == "* SEARCH 2"));
    let header = read_until_contains(&mut reader, "A011 OK").await;
    assert!(header.iter().any(|l| l.trim_end() == "* SEARCH 2"));
    let larger = read_until_contains(&mut reader, "A012 OK").await;
    assert!(larger.iter().any(|l| l.trim_end() == "* SEARCH 1"));
    let smaller = read_until_contains(&mut reader, "A013 OK").await;
    assert!(smaller.iter().any(|l| l.trim_end() == "* SEARCH 2 3"));
    let charset_supported = read_until_contains(&mut reader, "A014 OK").await;
    assert!(
        charset_supported
            .iter()
            .any(|l| l.trim_end() == "* SEARCH 1")
    );
    let charset_unsupported = read_until_contains(&mut reader, "A015 NO").await;
    assert!(
        charset_unsupported
            .iter()
            .any(|line| line.contains("[BADCHARSET (US-ASCII UTF-8)]"))
    );
    let _logout = read_until_contains(&mut reader, "A016 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn esearch_returns_requested_aggregates_ranges_uid_marker_and_empty_counts() {
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
    for index in 1..=5 {
        rmail_common::imap_state::append_message(
            &mail_root,
            "example.test",
            "user",
            "INBOX",
            format!("Subject: message {}\r\n\r\nbody\r\n", index).as_bytes(),
            if index == 2 {
                vec!["\\Seen".to_string()]
            } else {
                Vec::new()
            },
        )
        .expect("append");
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
    assert!(!capability.contains("ESEARCH"));
    reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CAPABILITY\r\nA003 SELECT INBOX\r\nA004 SEARCH RETURN (MIN MAX ALL COUNT) UNSEEN\r\nA005 UID SEARCH RETURN (MIN MAX COUNT) SEEN\r\nA006 SEARCH RETURN (ALL COUNT) SUBJECT \"missing\"\r\nA007 SEARCH RETURN (PARTIAL) ALL\r\nA008 LOGOUT\r\n",
            )
            .await
            .expect("commands");
    reader.get_mut().flush().await.expect("flush");

    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let post_auth_capability = read_until_contains(&mut reader, "A002 OK").await.join("");
    assert!(post_auth_capability.contains("ESEARCH"));
    let _select = read_until_contains(&mut reader, "A003 OK").await;
    let unseen = read_until_contains(&mut reader, "A004 OK").await.join("");
    assert!(unseen.contains("* ESEARCH (TAG \"A004\") MIN 1 MAX 5 ALL 1,3:5 COUNT 4"));
    let seen = read_until_contains(&mut reader, "A005 OK").await.join("");
    assert!(seen.contains("* ESEARCH (TAG \"A005\") UID MIN 2 MAX 2 COUNT 1"));
    let empty = read_until_contains(&mut reader, "A006 OK").await.join("");
    assert!(empty.contains("* ESEARCH (TAG \"A006\") COUNT 0"));
    assert!(!empty.contains(" ALL "));
    let unsupported = read_until_contains(&mut reader, "A007 BAD").await.join("");
    assert!(unsupported.contains("Invalid SEARCH arguments"));
    let _logout = read_until_contains(&mut reader, "A008 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn searchres_save_tracks_uids_across_expunge_and_resolves_dollar_everywhere() {
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
    for index in 1..=3 {
        rmail_common::imap_state::append_message(
            &mail_root,
            "example.test",
            "user",
            "INBOX",
            format!("Subject: message {}\r\n\r\nbody\r\n", index).as_bytes(),
            if index == 2 {
                vec!["\\Seen".to_string()]
            } else {
                Vec::new()
            },
        )
        .expect("append");
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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CAPABILITY\r\nA003 SELECT INBOX\r\nA004 UID SEARCH RETURN (SAVE) SEEN\r\nA005 STORE 1 +FLAGS (\\Deleted)\r\nA006 EXPUNGE\r\nA007 FETCH $ (UID FLAGS)\r\nA008 UID STORE $ +FLAGS (\\Flagged)\r\nA009 UID SEARCH RETURN (SAVE ALL COUNT) $\r\nA010 UID SEARCH RETURN (SAVE) SUBJECT \"missing\"\r\nA011 UID FETCH $ (UID FLAGS)\r\nA012 LOGOUT\r\n",
            )
            .await
            .expect("commands");
    reader.get_mut().flush().await.expect("flush");

    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let caps = read_until_contains(&mut reader, "A002 OK").await.join("");
    assert!(caps.contains("SEARCHRES"));
    let _select = read_until_contains(&mut reader, "A003 OK").await;
    let save_only = read_until_contains(&mut reader, "A004 OK").await.join("");
    assert!(!save_only.contains("* ESEARCH"));
    let _store = read_until_contains(&mut reader, "A005 OK").await;
    let expunge = read_until_contains(&mut reader, "A006 OK").await.join("");
    assert!(expunge.contains("* 1 EXPUNGE"));
    let fetch = read_until_contains(&mut reader, "A007 OK").await.join("");
    assert!(fetch.contains("* 1 FETCH"));
    assert!(fetch.contains("UID 2"));
    let uid_store = read_until_contains(&mut reader, "A008 OK").await.join("");
    assert!(uid_store.contains("UID 2"));
    assert!(uid_store.contains("\\FLAGGED"));
    let resave = read_until_contains(&mut reader, "A009 OK").await.join("");
    assert!(resave.contains("* ESEARCH (TAG \"A009\") UID ALL 2 COUNT 1"));
    let clear = read_until_contains(&mut reader, "A010 OK").await.join("");
    assert!(!clear.contains("* ESEARCH"));
    let empty_fetch = read_until_contains(&mut reader, "A011 OK").await;
    assert!(
        !empty_fetch
            .iter()
            .any(|line| line.starts_with("* ") && line.contains(" FETCH "))
    );
    let _logout = read_until_contains(&mut reader, "A012 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn sort_and_uid_sort_apply_rfc5256_keys_reverse_and_search_filtering() {
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
    let messages: [(&[u8], Vec<String>, i64); 3] = [
            (
                b"Date: Tue, 2 Jan 2024 00:00:00 +0000\r\nFrom: Zed <zed@example.test>\r\nTo: beta@example.test\r\nCc: charlie@example.test\r\nSubject: Re: Zebra\r\n\r\nlarge body one\r\n",
                Vec::new(),
                1_704_153_600,
            ),
            (
                b"Date: Mon, 1 Jan 2024 00:00:00 +0000\r\nFrom: Alice <alice@example.test>\r\nTo: alpha@example.test\r\nCc: delta@example.test\r\nSubject: =?UTF-8?Q?Apple?=\r\n\r\nx\r\n",
                vec!["\\Seen".to_string()],
                1_704_067_200,
            ),
            (
                b"From: Bob <bob@example.test>\r\nTo: gamma@example.test\r\nCc: able@example.test\r\nSubject: Fwd: Zebra (fwd)\r\n\r\nmedium\r\n",
                Vec::new(),
                1_704_240_000,
            ),
        ];
    for (data, flags, internal_date) in messages {
        rmail_common::imap_state::append_message_with_internal_date(
            &mail_root,
            "example.test",
            "user",
            "INBOX",
            data,
            flags,
            Some((internal_date, 0)),
        )
        .expect("append");
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
    assert!(!capability.contains(" SORT"));
    reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CAPABILITY\r\nA003 SELECT INBOX\r\nA004 SORT (DATE) UTF-8 ALL\r\nA005 UID SORT (SUBJECT DATE) UTF-8 ALL\r\nA006 SORT (REVERSE FROM) US-ASCII ALL\r\nA007 SORT (CC) UTF-8 ALL\r\nA008 SORT (TO) UTF-8 ALL\r\nA009 SORT (ARRIVAL) UTF-8 SEEN\r\nA010 SORT (DATE REVERSE) UTF-8 ALL\r\nA011 SORT (DATE) ISO-8859-1 ALL\r\nA012 LOGOUT\r\n",
            )
            .await
            .expect("commands");
    reader.get_mut().flush().await.expect("flush");

    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let caps = read_until_contains(&mut reader, "A002 OK").await.join("");
    assert!(caps.contains(" SORT"));
    let _select = read_until_contains(&mut reader, "A003 OK").await;
    assert!(
        read_until_contains(&mut reader, "A004 OK")
            .await
            .join("")
            .contains("* SORT 2 1 3")
    );
    assert!(
        read_until_contains(&mut reader, "A005 OK")
            .await
            .join("")
            .contains("* SORT 2 1 3")
    );
    assert!(
        read_until_contains(&mut reader, "A006 OK")
            .await
            .join("")
            .contains("* SORT 1 3 2")
    );
    assert!(
        read_until_contains(&mut reader, "A007 OK")
            .await
            .join("")
            .contains("* SORT 3 1 2")
    );
    assert!(
        read_until_contains(&mut reader, "A008 OK")
            .await
            .join("")
            .contains("* SORT 2 1 3")
    );
    assert!(
        read_until_contains(&mut reader, "A009 OK")
            .await
            .join("")
            .contains("* SORT 2")
    );
    let malformed = read_until_contains(&mut reader, "A010 BAD").await.join("");
    assert!(malformed.contains("Invalid SORT arguments"));
    let charset = read_until_contains(&mut reader, "A011 NO").await.join("");
    assert!(charset.contains("[BADCHARSET (US-ASCII UTF-8)]"));
    let _logout = read_until_contains(&mut reader, "A012 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn thread_and_uid_thread_build_references_and_orderedsubject_trees() {
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
    let (_, discarded_uid) = rmail_common::imap_state::append_message(
        &mail_root,
        "example.test",
        "user",
        "INBOX",
        b"Subject: discarded\r\n\r\n",
        Vec::new(),
    )
    .expect("append discarded");
    rmail_common::maildir::delete_message_by_uid_for_mailbox(
        &mail_root,
        "example.test",
        "user",
        "INBOX",
        discarded_uid,
    )
    .expect("expunge discarded");
    let messages: [(&[u8], Vec<String>); 4] = [
            (
                b"Date: Mon, 1 Jan 2024 00:00:00 +0000\r\nMessage-ID: <root@x>\r\nSubject: Topic\r\n\r\n",
                Vec::new(),
            ),
            (
                b"Date: Tue, 2 Jan 2024 00:00:00 +0000\r\nMessage-ID: <child@x>\r\nReferences: <root@x>\r\nSubject: Re: Topic\r\n\r\n",
                vec!["\\Seen".to_string()],
            ),
            (
                b"Date: Wed, 3 Jan 2024 00:00:00 +0000\r\nMessage-ID: <leaf@x>\r\nReferences: <root@x> <child@x>\r\nSubject: Re: Topic\r\n\r\n",
                Vec::new(),
            ),
            (
                b"Date: Thu, 4 Jan 2024 00:00:00 +0000\r\nMessage-ID: <orphan@x>\r\nReferences: <missing@x>\r\nSubject: Other\r\n\r\n",
                Vec::new(),
            ),
        ];
    for (data, flags) in messages {
        rmail_common::imap_state::append_message(
            &mail_root,
            "example.test",
            "user",
            "INBOX",
            data,
            flags,
        )
        .expect("append threaded message");
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
    assert!(!capability.contains("THREAD="));
    reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CAPABILITY\r\nA003 SELECT INBOX\r\nA004 THREAD REFERENCES UTF-8 ALL\r\nA005 UID THREAD REFERENCES UTF-8 ALL\r\nA006 THREAD ORDEREDSUBJECT UTF-8 ALL\r\nA007 THREAD REFERENCES UTF-8 SEEN\r\nA008 THREAD REFS UTF-8 ALL\r\nA009 THREAD UNKNOWN UTF-8 ALL\r\nA010 THREAD REFERENCES ISO-8859-1 ALL\r\nA011 LOGOUT\r\n",
            )
            .await
            .expect("commands");
    reader.get_mut().flush().await.expect("flush");

    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let caps = read_until_contains(&mut reader, "A002 OK").await.join("");
    assert!(caps.contains("THREAD=REFERENCES"));
    assert!(caps.contains("THREAD=REFS"));
    assert!(caps.contains("THREAD=ORDEREDSUBJECT"));
    let _select = read_until_contains(&mut reader, "A003 OK").await;
    let refs = read_until_contains(&mut reader, "A004 OK").await.join("");
    assert!(refs.contains("* THREAD (1 2 3)(4)"));
    let uid_refs = read_until_contains(&mut reader, "A005 OK").await.join("");
    assert!(uid_refs.contains("* THREAD (2 3 4)(5)"));
    let ordered = read_until_contains(&mut reader, "A006 OK").await.join("");
    assert!(ordered.contains("* THREAD (1 (2)(3))(4)"));
    let filtered = read_until_contains(&mut reader, "A007 OK").await.join("");
    assert!(filtered.contains("* THREAD (2)"));
    let refs2 = read_until_contains(&mut reader, "A008 OK").await.join("");
    assert!(refs2.contains("* THREAD (1 2 3)(4)"));
    let unknown = read_until_contains(&mut reader, "A009 BAD").await.join("");
    assert!(unknown.contains("Invalid THREAD arguments"));
    let charset = read_until_contains(&mut reader, "A010 NO").await.join("");
    assert!(charset.contains("[BADCHARSET (US-ASCII UTF-8)]"));
    let _logout = read_until_contains(&mut reader, "A011 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn within_younger_and_older_use_persisted_internal_dates() {
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
    let now = chrono::Utc::now().timestamp();
    for (index, age) in [60_i64, 3_600, 86_400].into_iter().enumerate() {
        rmail_common::imap_state::append_message_with_internal_date(
            &mail_root,
            "example.test",
            "user",
            "INBOX",
            format!("Subject: age {}\r\n\r\n", age).as_bytes(),
            Vec::new(),
            Some((now - age, 0)),
        )
        .unwrap_or_else(|error| panic!("append message {}: {}", index, error));
    }
    let server_mail_root = mail_root.clone();
    let (client, server) = duplex(16 * 1024);
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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CAPABILITY\r\nA003 SELECT INBOX\r\nA004 SEARCH YOUNGER 300\r\nA005 SEARCH OLDER 300\r\nA006 UID SEARCH YOUNGER 4000\r\nA007 SORT (ARRIVAL) UTF-8 YOUNGER 4000\r\nA008 LOGOUT\r\n",
            )
            .await
            .expect("commands");
    reader.get_mut().flush().await.expect("flush");

    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let caps = read_until_contains(&mut reader, "A002 OK").await.join("");
    assert!(caps.contains("WITHIN"));
    let _select = read_until_contains(&mut reader, "A003 OK").await;
    assert!(
        read_until_contains(&mut reader, "A004 OK")
            .await
            .join("")
            .contains("* SEARCH 1")
    );
    assert!(
        read_until_contains(&mut reader, "A005 OK")
            .await
            .join("")
            .contains("* SEARCH 2 3")
    );
    assert!(
        read_until_contains(&mut reader, "A006 OK")
            .await
            .join("")
            .contains("* SEARCH 1 2")
    );
    assert!(
        read_until_contains(&mut reader, "A007 OK")
            .await
            .join("")
            .contains("* SORT 2 1")
    );
    let _logout = read_until_contains(&mut reader, "A008 OK").await;
    server_task.await.expect("join").expect("server");
}
