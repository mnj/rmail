//! SELECT/EXAMINE, CONDSTORE/QRESYNC, IDLE/NOOP updates, STORE/EXPUNGE, COPY/MOVE, LIST/LSUB, RENAME, SUBSCRIBE and mailbox naming.

use super::*;

#[tokio::test]
async fn condstore_select_fetch_status_and_conditional_store_work() {
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
    rmail_common::imap_state::append_message(
        mail_root.as_path(),
        "example.test",
        "user",
        "INBOX",
        b"Subject: one\r\n\r\nfirst",
        vec![],
    )
    .expect("append first");
    rmail_common::imap_state::append_message(
        mail_root.as_path(),
        "example.test",
        "user",
        "INBOX",
        b"Subject: two\r\n\r\nsecond",
        vec![],
    )
    .expect("append second");

    let server_mail_root = mail_root.clone();
    let server_db_path = db_path.clone();
    let (client, server) = duplex(32 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            server_mail_root.to_string_lossy().to_string(),
            None::<Arc<crate::tls::TlsContext>>,
            Some(server_db_path.to_string_lossy().to_string()),
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
    assert!(!capability.contains("CONDSTORE"));
    assert!(!capability.contains("QRESYNC"));

    reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 ENABLE CONDSTORE\r\nA003 SELECT INBOX (CONDSTORE)\r\nA004 STATUS INBOX (MESSAGES UIDNEXT HIGHESTMODSEQ)\r\nA005 UID FETCH 1:* (UID FLAGS MODSEQ)\r\nA006 UID FETCH 1:* (UID FLAGS MODSEQ) (CHANGEDSINCE 999999)\r\nA007 UID STORE 1 (UNCHANGEDSINCE 1) +FLAGS (\\Seen)\r\nA008 UID STORE 1 (UNCHANGEDSINCE 999999) +FLAGS (\\Seen)\r\nA009 UID FETCH 1:* (UID FLAGS MODSEQ) (CHANGEDSINCE 1)\r\nA010 LOGOUT\r\n",
            )
            .await
            .expect("write condstore commands");
    reader.get_mut().flush().await.expect("flush");

    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let enabled = read_until_contains(&mut reader, "A002 OK").await;
    assert!(
        enabled
            .iter()
            .any(|line| line.trim_end() == "* ENABLED CONDSTORE")
    );
    let select = read_until_contains(&mut reader, "A003 OK").await;
    assert!(select.iter().any(|line| line.contains("[HIGHESTMODSEQ ")));
    let status = read_until_contains(&mut reader, "A004 OK").await;
    assert!(
        status
            .iter()
            .any(|line| line.contains("HIGHESTMODSEQ") && line.contains("MESSAGES 2"))
    );
    let fetch = read_until_contains(&mut reader, "A005 OK").await;
    assert_eq!(
        fetch
            .iter()
            .filter(|line| line.starts_with("* ") && line.contains(" FETCH "))
            .count(),
        2
    );
    assert!(fetch.iter().all(|line| {
        !(line.starts_with("* ") && line.contains(" FETCH "))
            || (line.contains("UID ") && line.contains("MODSEQ ("))
    }));
    let changed_since_future = read_until_contains(&mut reader, "A006 OK").await;
    assert!(
        !changed_since_future
            .iter()
            .any(|line| line.starts_with("* ") && line.contains(" FETCH "))
    );
    let conditional_fail = read_until_contains(&mut reader, "A007 OK").await;
    assert!(
        conditional_fail
            .iter()
            .any(|line| line.contains("[MODIFIED 1]"))
    );
    let conditional_success = read_until_contains(&mut reader, "A008 OK").await;
    assert!(
        conditional_success
            .iter()
            .any(|line| line.contains("FETCH") && line.contains("MODSEQ ("))
    );
    let changed_since_past = read_until_contains(&mut reader, "A009 OK").await;
    assert!(
        changed_since_past
            .iter()
            .filter(|line| line.starts_with("* ") && line.contains(" FETCH "))
            .count()
            >= 1
    );
    let _logout = read_until_contains(&mut reader, "A010 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn qresync_select_returns_vanished_changes_and_uses_vanished_for_live_expunges() {
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
    let mut uids = Vec::new();
    for subject in ["one", "two", "three"] {
        let (_, uid) = rmail_common::imap_state::append_message(
            &mail_root,
            "example.test",
            "user",
            "INBOX",
            format!("Subject: {}\r\n\r\n", subject).as_bytes(),
            Vec::new(),
        )
        .expect("append");
        uids.push(uid);
    }
    let (baseline_folder, _) =
        rmail_common::imap_state::load_folder(&mail_root, "example.test", "user", "INBOX")
            .expect("baseline");
    rmail_common::imap_state::set_uid_flags(
        &mail_root,
        "example.test",
        "user",
        "INBOX",
        uids[0],
        vec!["\\Seen".to_string()],
    )
    .expect("flag change");
    rmail_common::imap_state::delete_message_by_uid(
        &mail_root,
        "example.test",
        "user",
        "INBOX",
        uids[1],
    )
    .expect("delete");
    rmail_common::imap_state::append_message(
        &mail_root,
        "example.test",
        "user",
        "INBOX",
        b"Subject: new\r\n\r\n",
        Vec::new(),
    )
    .expect("new delivery");

    let server_mail_root = mail_root.clone();
    let server_db_path = db_path.clone();
    let (client, server) = duplex(32 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            server_mail_root.to_string_lossy().to_string(),
            None::<Arc<crate::tls::TlsContext>>,
            Some(server_db_path.to_string_lossy().to_string()),
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
                format!(
                    "A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX (QRESYNC ({} {} 1:3))\r\nA003 ENABLE QRESYNC\r\nA004 SELECT INBOX (QRESYNC ({} {} 1:3))\r\n",
                    baseline_folder.uidvalidity,
                    baseline_folder.highest_modseq,
                    baseline_folder.uidvalidity,
                    baseline_folder.highest_modseq
                )
                .as_bytes(),
            )
            .await
            .expect("initial commands");
    reader.get_mut().flush().await.expect("flush");
    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let disabled = read_until_contains(&mut reader, "A002 BAD").await.join("");
    assert!(disabled.contains("QRESYNC is not enabled"));
    let _enable = read_until_contains(&mut reader, "A003 OK").await;
    let select = read_until_contains(&mut reader, "A004 OK").await.join("");
    assert!(select.contains("* VANISHED (EARLIER) 2"));
    assert!(select.contains("FETCH (UID 1 FLAGS (\\Seen) MODSEQ"));
    assert!(!select.contains("FETCH (UID 4 "));

    reader
        .get_mut()
        .write_all(b"A005 UID STORE 1 +FLAGS (\\Deleted)\r\nA006 UID EXPUNGE 1\r\n")
        .await
        .expect("expunge commands");
    reader.get_mut().flush().await.expect("flush");
    let _store = read_until_contains(&mut reader, "A005 OK").await;
    let expunge = read_until_contains(&mut reader, "A006 OK").await.join("");
    assert!(expunge.contains("* VANISHED 1"));
    assert!(!expunge.contains("* 1 EXPUNGE"));

    let (_, current) =
        rmail_common::imap_state::load_folder(&mail_root, "example.test", "user", "INBOX")
            .expect("current folder");
    let uid3 = current.iter().find(|message| message.uid == 3).unwrap();
    std::fs::remove_file(&uid3.path).expect("external remove");
    reader
            .get_mut()
            .write_all(
                format!(
                    "A007 NOOP\r\nA008 SELECT INBOX (QRESYNC ({} 1))\r\nA009 SELECT INBOX (QRESYNC ({} 1))\r\nA010 LOGOUT\r\n",
                    baseline_folder.uidvalidity,
                    baseline_folder.uidvalidity.saturating_add(1)
                )
                .as_bytes(),
            )
            .await
            .expect("final commands");
    reader.get_mut().flush().await.expect("flush");
    let noop = read_until_contains(&mut reader, "A007 OK").await.join("");
    assert!(noop.contains("* VANISHED 3"));
    let reselect = read_until_contains(&mut reader, "A008 OK").await.join("");
    assert!(reselect.contains("* OK [CLOSED]"));
    let mismatch = read_until_contains(&mut reader, "A009 OK").await.join("");
    assert!(mismatch.contains("* OK [CLOSED]"));
    assert!(!mismatch.contains("VANISHED (EARLIER)"));
    let _logout = read_until_contains(&mut reader, "A010 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn examine_selected_mailbox_is_read_only_for_mutating_commands() {
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
    let (_uidvalidity, uid) = rmail_common::imap_state::append_message(
        mail_root.as_path(),
        "example.test",
        "user",
        "INBOX",
        b"Subject: read only\r\n\r\nbody",
        vec!["\\Deleted".to_string()],
    )
    .expect("append");

    let server_mail_root = mail_root.clone();
    let server_db_path = db_path.clone();
    let (client, server) = duplex(32 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            server_mail_root.to_string_lossy().to_string(),
            None::<Arc<crate::tls::TlsContext>>,
            Some(server_db_path.to_string_lossy().to_string()),
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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 EXAMINE INBOX\r\nA003 UID STORE 1 +FLAGS (\\Seen)\r\nA004 STORE 1 +FLAGS (\\Seen)\r\nA005 EXPUNGE\r\nA006 UID EXPUNGE 1\r\nA007 MOVE 1 Trash\r\nA008 UID MOVE 1 Trash\r\nA009 UID COPY 1 Archive\r\nA010 CLOSE\r\nA011 SELECT INBOX\r\nA012 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let examine = read_until_contains(&mut reader, "A002 OK").await;
    assert!(
        examine
            .iter()
            .any(|line| line.contains("OK [READ-ONLY] EXAMINE completed"))
    );
    for tag in ["A003", "A004", "A005", "A006", "A007", "A008"] {
        let lines = read_until_contains(&mut reader, &format!("{tag} NO")).await;
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Mailbox is read-only")),
            "expected read-only rejection for {tag}, got {lines:?}"
        );
    }
    let copy = read_until_contains(&mut reader, "A009 OK").await;
    assert!(copy.iter().any(|line| line.contains("COPY completed")));
    let close = read_until_contains(&mut reader, "A010 OK").await;
    assert!(close.iter().any(|line| line.contains("CLOSE completed")));
    let select = read_until_contains(&mut reader, "A011 OK").await;
    assert!(select.iter().any(|line| line.trim_end() == "* 1 EXISTS"));
    let _logout = read_until_contains(&mut reader, "A012 OK").await;
    server_task.await.expect("join").expect("server");

    let (_folder, messages) =
        rmail_common::imap_state::load_folder(mail_root.as_path(), "example.test", "user", "INBOX")
            .expect("load inbox");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].uid, uid);
    assert_eq!(messages[0].flags, vec!["\\Deleted"]);
}
#[tokio::test]
async fn select_accepts_quoted_inbox_name() {
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
    let mut capability = String::new();
    reader
        .read_line(&mut capability)
        .await
        .expect("capability greeting");

    reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT \"Inbox\"\r\nA003 LOGOUT\r\n",
            )
            .await
            .expect("write login/select");
    reader.get_mut().flush().await.expect("flush");

    let select_lines = read_until_contains(&mut reader, "A002 OK").await;
    assert!(select_lines.iter().any(|l| l.contains("SELECT completed")));

    let logout_lines = read_until_contains(&mut reader, "A003 OK").await;
    assert!(logout_lines.iter().any(|l| l.starts_with("* BYE")));

    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn idle_completes_after_done() {
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
    reader.read_line(&mut capability).await.expect("capability");
    assert!(capability.contains("IDLE"));

    reader
        .get_mut()
        .write_all(
            b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 IDLE\r\n",
        )
        .await
        .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _login_lines = read_until_contains(&mut reader, "A001 OK").await;
    let _select_lines = read_until_contains(&mut reader, "A002 OK").await;
    let idle_start = read_until_contains(&mut reader, "+ idling").await;
    assert!(idle_start.iter().any(|line| line.contains("+ idling")));
    reader
        .get_mut()
        .write_all(b"DO")
        .await
        .expect("partial done");
    reader.get_mut().flush().await.expect("flush partial done");
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    reader
        .get_mut()
        .write_all(b"NE\r\nA004 LOGOUT\r\n")
        .await
        .expect("finish done and logout");
    reader.get_mut().flush().await.expect("flush done");
    let idle_done = read_until_contains(&mut reader, "A003 OK").await;
    assert!(idle_done.iter().any(|line| line.contains("IDLE completed")));
    let _logout_lines = read_until_contains(&mut reader, "A004 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn noop_and_idle_send_unsolicited_exists_for_new_delivery() {
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
    let server_db_path = db_path.clone();
    let (client, server) = duplex(32 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            server_mail_root.to_string_lossy().to_string(),
            None::<Arc<crate::tls::TlsContext>>,
            Some(server_db_path.to_string_lossy().to_string()),
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
        .write_all(b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\n")
        .await
        .expect("write login select");
    reader.get_mut().flush().await.expect("flush");
    let _login = read_until_contains_bounded(&mut reader, "A001 OK").await;
    let select = read_until_contains_bounded(&mut reader, "A002 OK").await;
    assert!(select.iter().any(|line| line.contains("* 0 EXISTS")));

    rmail_common::imap_state::append_message(
        mail_root.as_path(),
        "example.test",
        "user",
        "INBOX",
        b"From: a@example.test\r\nSubject: noop sync\r\n\r\nhello",
        vec![],
    )
    .expect("append first message");
    reader
        .get_mut()
        .write_all(b"A003 NOOP\r\n")
        .await
        .expect("write noop");
    reader.get_mut().flush().await.expect("flush");
    let noop = read_until_contains_bounded(&mut reader, "A003 OK").await;
    assert!(noop.iter().any(|line| line.trim_end() == "* 1 EXISTS"));
    assert!(!noop.iter().any(|line| line.contains(" RECENT")));

    reader
        .get_mut()
        .write_all(b"A004 IDLE\r\n")
        .await
        .expect("write idle");
    reader.get_mut().flush().await.expect("flush");
    let idle_start = read_until_contains_bounded(&mut reader, "+ idling").await;
    assert!(idle_start.iter().any(|line| line.contains("+ idling")));
    let inbox =
        rmail_common::imap_state::account_maildir(mail_root.as_path(), "example.test", "user");
    std::fs::write(
        inbox.join("new").join("external-idle-delivery"),
        b"From: b@example.test\r\nSubject: idle sync\r\n\r\nhello",
    )
    .expect("write external delivery");
    let exists = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        read_until_contains_bounded(&mut reader, "* 2 EXISTS"),
    )
    .await
    .expect("idle exists timeout");
    assert!(exists.iter().any(|line| line.trim_end() == "* 2 EXISTS"));
    let recent = if exists.iter().any(|line| line.trim_end() == "* 1 RECENT") {
        exists
    } else {
        read_until_contains_bounded(&mut reader, "* 1 RECENT").await
    };
    assert!(recent.iter().any(|line| line.trim_end() == "* 1 RECENT"));
    reader
            .get_mut()
            .write_all(
                b"DONE\r\nA005 SEARCH RECENT\r\nA006 SEARCH NEW\r\nA007 FETCH 2 FLAGS\r\nA008 STORE 2 +FLAGS (\\Recent)\r\nA009 STATUS INBOX (RECENT)\r\nA010 LOGOUT\r\n",
            )
            .await
            .expect("done logout");
    reader.get_mut().flush().await.expect("flush");
    let idle_done = read_until_contains_bounded(&mut reader, "A004 OK").await;
    assert!(idle_done.iter().any(|line| line.contains("IDLE completed")));
    let search_recent = read_until_contains_bounded(&mut reader, "A005 OK").await;
    assert!(
        search_recent
            .iter()
            .any(|line| line.trim_end() == "* SEARCH 2")
    );
    let search_new = read_until_contains_bounded(&mut reader, "A006 OK").await;
    assert!(
        search_new
            .iter()
            .any(|line| line.trim_end() == "* SEARCH 2")
    );
    let fetch = read_until_contains_bounded(&mut reader, "A007 OK").await;
    assert!(fetch.iter().any(|line| line.contains("FLAGS (\\Recent)")));
    let store = read_until_contains_bounded(&mut reader, "A008 OK").await;
    assert!(store.iter().any(|line| line.contains("FLAGS (\\Recent)")));
    let status = read_until_contains_bounded(&mut reader, "A009 OK").await;
    assert!(status.iter().any(|line| line.contains("(RECENT 0)")));
    let _logout = read_until_contains_bounded(&mut reader, "A010 OK").await;
    tokio::time::timeout(std::time::Duration::from_secs(5), server_task)
        .await
        .expect("server join timeout")
        .expect("join")
        .expect("server");
}
#[tokio::test]
async fn noop_sync_reports_external_expunge_before_flag_changes() {
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
    let (_uidvalidity, uid1) = rmail_common::imap_state::append_message(
        mail_root.as_path(),
        "example.test",
        "user",
        "INBOX",
        b"From: a@example.test\r\nSubject: first\r\n\r\nhello",
        vec![],
    )
    .expect("append first");
    let (_uidvalidity, uid2) = rmail_common::imap_state::append_message(
        mail_root.as_path(),
        "example.test",
        "user",
        "INBOX",
        b"From: b@example.test\r\nSubject: second\r\n\r\nhello",
        vec![],
    )
    .expect("append second");

    let server_mail_root = mail_root.clone();
    let server_db_path = db_path.clone();
    let (client, server) = duplex(32 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            server_mail_root.to_string_lossy().to_string(),
            None::<Arc<crate::tls::TlsContext>>,
            Some(server_db_path.to_string_lossy().to_string()),
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
        .write_all(b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\n")
        .await
        .expect("write login select");
    reader.get_mut().flush().await.expect("flush");
    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let select = read_until_contains(&mut reader, "A002 OK").await;
    assert!(select.iter().any(|line| line.contains("* 2 EXISTS")));

    rmail_common::imap_state::set_uid_flags(
        mail_root.as_path(),
        "example.test",
        "user",
        "INBOX",
        uid1,
        vec!["\\Seen".to_string()],
    )
    .expect("set flags");
    rmail_common::imap_state::delete_message_by_uid(
        mail_root.as_path(),
        "example.test",
        "user",
        "INBOX",
        uid2,
    )
    .expect("delete uid2");

    reader
        .get_mut()
        .write_all(b"A003 NOOP\r\nA004 LOGOUT\r\n")
        .await
        .expect("write noop logout");
    reader.get_mut().flush().await.expect("flush");
    let noop = read_until_contains(&mut reader, "A003 OK").await;
    let expunge_pos = noop
        .iter()
        .position(|line| line.trim_end() == "* 2 EXPUNGE")
        .expect("expunge response");
    let fetch_pos = noop
        .iter()
        .position(|line| {
            line.contains("* 1 FETCH")
                && line.contains("FLAGS (\\Seen)")
                && line.contains(&format!("UID {}", uid1))
        })
        .expect("flag fetch response");
    assert!(expunge_pos < fetch_pos);
    // The EXPUNGE already brought the client's count to 1.
    assert!(!noop.iter().any(|line| line.contains("EXISTS")));
    let _logout = read_until_contains(&mut reader, "A004 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn store_deleted_and_expunge_removes_message() {
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
    .expect("deliver one");
    rmail_common::maildir::deliver(
        &mail_root,
        "example.test",
        "user",
        b"Subject: two\r\n\r\nsecond\r\n",
    )
    .expect("deliver two");

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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID STORE 1 +FLAGS (\\Deleted)\r\nA004 EXPUNGE\r\nA005 SELECT INBOX\r\nA006 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _select1 = read_until_contains(&mut reader, "A002 OK").await;
    let store_lines = read_until_contains(&mut reader, "A003 OK").await;
    assert!(
        store_lines
            .iter()
            .any(|l| l.contains("\\Deleted") || l.contains("\\DELETED"))
    );

    let expunge_lines = read_until_contains(&mut reader, "A004 OK").await;
    assert!(expunge_lines.iter().any(|l| l.contains("EXPUNGE")));

    let select2 = read_until_contains(&mut reader, "A005 OK").await;
    assert!(select2.iter().any(|l| l.contains("* 1 EXISTS")));

    let _logout = read_until_contains(&mut reader, "A006 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn savedate_and_status_size_use_persisted_message_metadata() {
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
    let first = b"Subject: one\r\n\r\nfirst body\r\n";
    let second = b"Subject: two\r\n\r\nsecond body is longer\r\n";
    for data in [first.as_slice(), second.as_slice()] {
        rmail_common::imap_state::append_message_with_internal_date(
            &mail_root,
            "example.test",
            "user",
            "INBOX",
            data,
            Vec::new(),
            Some((837_596_665, -420)),
        )
        .expect("append");
    }
    let expected_size = first.len() + second.len();
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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CAPABILITY\r\nA003 STATUS INBOX (MESSAGES SIZE)\r\nA004 SELECT INBOX\r\nA005 UID FETCH 1:* (UID INTERNALDATE SAVEDATE RFC822.SIZE)\r\nA006 STATUS INBOX (BOGUS)\r\nA007 LOGOUT\r\n",
            )
            .await
            .expect("commands");
    reader.get_mut().flush().await.expect("flush");

    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let caps = read_until_contains(&mut reader, "A002 OK").await.join("");
    assert!(caps.contains("STATUS=SIZE"));
    assert!(caps.contains("SAVEDATE"));
    let status = read_until_contains(&mut reader, "A003 OK").await.join("");
    assert!(status.contains(&format!("MESSAGES 2 SIZE {}", expected_size)));
    let _select = read_until_contains(&mut reader, "A004 OK").await;
    let fetch = read_until_contains(&mut reader, "A005 OK").await.join("");
    assert_eq!(fetch.matches("SAVEDATE \"").count(), 2);
    assert_eq!(
        fetch
            .matches("INTERNALDATE \"17-Jul-1996 02:44:25 -0700\"")
            .count(),
        2
    );
    assert!(!fetch.contains("SAVEDATE \"17-Jul-1996"));
    let invalid = read_until_contains(&mut reader, "A006 BAD").await.join("");
    assert!(invalid.contains("Invalid STATUS item"));
    let _logout = read_until_contains(&mut reader, "A007 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn check_unselect_uid_copy_and_uid_move_work() {
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
    .expect("deliver one");
    rmail_common::maildir::deliver(
        &mail_root,
        "example.test",
        "user",
        b"Subject: two\r\n\r\nsecond\r\n",
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
    assert!(!capability.contains("MOVE"));

    reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 CHECK\r\nA004 UID COPY 1 Archive\r\nA005 UID MOVE 2 Archive\r\nA05B UID FROB 1\r\nA006 UNSELECT\r\nA007 SELECT INBOX\r\nA008 STATUS Archive (UIDNEXT MESSAGES UNSEEN RECENT)\r\nA009 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _select1 = read_until_contains(&mut reader, "A002 OK").await;
    let check_lines = read_until_contains(&mut reader, "A003 OK").await;
    assert!(check_lines.iter().any(|l| l.contains("CHECK completed")));

    let copy_lines = read_until_contains(&mut reader, "A004 OK").await;
    assert!(copy_lines.iter().any(|l| l.contains("COPYUID")));

    let move_lines = read_until_contains(&mut reader, "A005 OK").await;
    assert!(move_lines.iter().any(|l| l.contains("COPYUID")));
    // Each UID COPY/MOVE gets exactly one tagged reply.
    assert!(
        !move_lines.iter().any(|l| l.contains(" BAD ")),
        "{move_lines:?}"
    );

    let unknown_uid = read_until_contains(&mut reader, "A05B ").await;
    assert!(
        unknown_uid
            .iter()
            .any(|l| l.contains("A05B BAD Unsupported UID subcommand")),
        "{unknown_uid:?}"
    );

    let unselect_lines = read_until_contains(&mut reader, "A006 OK").await;
    assert!(
        unselect_lines
            .iter()
            .any(|l| l.contains("UNSELECT completed"))
    );

    let select2 = read_until_contains(&mut reader, "A007 OK").await;
    assert!(select2.iter().any(|l| l.contains("* 1 EXISTS")));

    let status = read_until_contains(&mut reader, "A008 OK").await;
    assert!(
        status
            .iter()
            .any(|l| l.contains("* STATUS \"Archive\" (MESSAGES 2 UIDNEXT 3 UNSEEN 2 RECENT 0)"))
    );

    let _logout = read_until_contains(&mut reader, "A009 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn rename_mailbox_updates_list_and_preserves_messages() {
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
    rmail_common::imap_state::create_folder(&mail_root, "example.test", "user", "Projects")
        .expect("create folder");
    rmail_common::imap_state::append_message(
        &mail_root,
        "example.test",
        "user",
        "Projects",
        b"Subject: project\r\n\r\nbody\r\n",
        Vec::new(),
    )
    .expect("append project");

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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CREATE Projects\r\nA003 CREATE Projects trailing\r\nA004 RENAME Projects \"Renamed\"\r\nA005 LIST \"\" \"*\"\r\nA006 SELECT Renamed\r\nA007 DELETE Renamed\r\nA008 FETCH 1 FLAGS\r\nA009 RENAME INBOX Nope\r\nA010 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let duplicate = read_until_contains(&mut reader, "A002 NO").await;
    assert!(
        duplicate
            .iter()
            .any(|line| line.contains("[ALREADYEXISTS]"))
    );
    let malformed = read_until_contains(&mut reader, "A003 BAD").await;
    assert!(
        malformed
            .iter()
            .any(|line| line.contains("Invalid CREATE arguments"))
    );
    let rename = read_until_contains(&mut reader, "A004 OK").await;
    assert!(rename.iter().any(|l| l.contains("RENAME completed")));

    let list = read_until_contains(&mut reader, "A005 OK").await;
    let joined = list.join("");
    assert!(joined.contains("\"Renamed\""));
    assert!(!joined.contains("\"Projects\""));

    let select = read_until_contains(&mut reader, "A006 OK").await;
    assert!(select.iter().any(|l| l.contains("* 1 EXISTS")));

    let deleted = read_until_contains(&mut reader, "A007 OK").await;
    assert!(deleted.iter().any(|line| line.contains("DELETE completed")));
    let stale_selection = read_until_contains(&mut reader, "A008 BAD").await;
    assert!(
        stale_selection
            .iter()
            .any(|line| line.contains("No mailbox selected"))
    );

    let inbox_rename = read_until_contains(&mut reader, "A009 NO").await;
    assert!(
        inbox_rename
            .iter()
            .any(|l| l.contains("cannot rename INBOX"))
    );

    let _logout = read_until_contains(&mut reader, "A010 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn list_exposes_standard_special_use_folders() {
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
    assert!(!capability.contains("SPECIAL-USE"));

    reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 LIST \"\" \"*\"\r\nA003 SELECT Sent\r\nA004 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let list_lines = read_until_contains(&mut reader, "A002 OK").await;
    assert!(list_lines.iter().any(|l| l.contains("\"INBOX\"")));
    assert!(!list_lines.iter().any(|l| l.contains("\\Inbox")));
    assert!(
        list_lines
            .iter()
            .any(|l| l.contains("\\Sent") && l.contains("\"Sent\""))
    );
    assert!(
        list_lines
            .iter()
            .any(|l| l.contains("\\Drafts") && l.contains("\"Drafts\""))
    );
    assert!(
        list_lines
            .iter()
            .any(|l| l.contains("\\Trash") && l.contains("\"Trash\""))
    );
    assert!(
        list_lines
            .iter()
            .any(|l| l.contains("\\Junk") && l.contains("\"Junk\""))
    );
    assert!(
        list_lines
            .iter()
            .any(|l| l.contains("\\Archive") && l.contains("\"Archive\""))
    );

    let select_lines = read_until_contains(&mut reader, "A003 OK").await;
    assert!(select_lines.iter().any(|l| l.contains("* 0 EXISTS")));

    let _logout = read_until_contains(&mut reader, "A004 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn list_extended_returns_special_use_children_and_status() {
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
    rmail_common::imap_state::append_message(
        &mail_root,
        "example.test",
        "user",
        "Sent",
        b"Subject: sent\r\n\r\nbody",
        Vec::new(),
    )
    .expect("append sent message");

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
    assert!(!capability.contains("LIST-EXTENDED"));
    assert!(!capability.contains("CHILDREN"));
    assert!(!capability.contains("LIST-STATUS"));

    reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CREATE Projects\r\nA003 CREATE Projects/Child\r\nA004 DELETE Projects\r\nA005 UNSUBSCRIBE Projects\r\nA006 LIST \"\" \"Projects\" RETURN (CHILDREN)\r\nA007 LIST (SUBSCRIBED RECURSIVEMATCH) \"\" \"Projects%\" RETURN (SUBSCRIBED CHILDREN)\r\nA008 LIST (REMOTE) \"\" \"*\"\r\nA009 LIST (SPECIAL-USE) \"\" (\"INBOX\" \"Sent\") RETURN (SPECIAL-USE STATUS (MESSAGES UIDNEXT UNSEEN SIZE))\r\nA010 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let _create_parent = read_until_contains(&mut reader, "A002 OK").await;
    let _create_child = read_until_contains(&mut reader, "A003 OK").await;
    let parent_delete = read_until_contains(&mut reader, "A004 NO").await;
    assert!(
        parent_delete
            .iter()
            .any(|line| line.contains("mailbox has children"))
    );
    let _unsubscribe_parent = read_until_contains(&mut reader, "A005 OK").await;
    let children = read_until_contains(&mut reader, "A006 OK").await;
    assert!(
        children
            .iter()
            .any(|l| l.contains("* LIST (\\HasChildren)") && l.contains("\"Projects\""))
    );
    let recursive = read_until_contains(&mut reader, "A007 OK").await;
    assert!(
        recursive
            .iter()
            .any(|line| { line.contains("\"Projects\" (CHILDINFO (\"SUBSCRIBED\"))") })
    );
    let remote = read_until_contains(&mut reader, "A008 OK").await;
    assert!(!remote.iter().any(|line| line.starts_with("* LIST")));
    let special_status = read_until_contains(&mut reader, "A009 OK").await;
    assert!(
        special_status
            .iter()
            .any(|l| l.contains("* LIST (\\Sent)") && l.contains("\"Sent\""))
    );
    assert!(special_status.iter().any(|l| {
        l.contains("* STATUS \"Sent\"") && l.contains("MESSAGES 1") && l.contains("SIZE 21")
    }));
    assert!(
        !special_status
            .iter()
            .any(|l| l.contains("* STATUS \"INBOX\""))
    );
    let _logout = read_until_contains(&mut reader, "A010 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn mailbox_names_use_modified_utf7_on_the_imap_wire() {
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
    let server_db_path = db_path.clone();
    let (client, server) = duplex(32 * 1024);
    let server_task = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            server_mail_root.to_string_lossy().to_string(),
            None::<Arc<crate::tls::TlsContext>>,
            Some(server_db_path.to_string_lossy().to_string()),
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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CREATE &ZeVnLIqe-\r\nA003 LIST \"\" \"&ZeVnLIqe-\"\r\nA004 STATUS &ZeVnLIqe- (MESSAGES UIDNEXT)\r\nA005 SELECT &ZeVnLIqe-\r\nA006 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let create = read_until_contains(&mut reader, "A002 OK").await;
    assert!(create.iter().any(|line| line.contains("CREATE completed")));
    let list = read_until_contains(&mut reader, "A003 OK").await;
    assert!(
        list.iter()
            .any(|line| line.contains("* LIST") && line.contains("\"&ZeVnLIqe-\""))
    );
    assert!(!list.iter().any(|line| line.contains("日本語")));
    let status = read_until_contains(&mut reader, "A004 OK").await;
    assert!(
        status
            .iter()
            .any(|line| line.contains("* STATUS \"&ZeVnLIqe-\""))
    );
    let select = read_until_contains(&mut reader, "A005 OK").await;
    assert!(select.iter().any(|line| line.contains("SELECT completed")));
    let _logout = read_until_contains(&mut reader, "A006 OK").await;
    server_task.await.expect("join").expect("server");

    assert!(
        rmail_common::imap_state::folder_exists(
            mail_root.as_path(),
            "example.test",
            "user",
            "日本語"
        )
        .expect("folder exists")
    );
}
#[tokio::test]
async fn imap4rev2_switches_mailbox_wire_format_append_and_search_rules() {
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
    reader
            .get_mut()
            .write_all(
                "A001 LOGIN \"user@example.test\" \"password\"\r\nA002 CAPABILITY\r\nA003 ENABLE IMAP4rev2\r\nA004 CREATE \"旅行 & Stuff\"\r\nA005 LIST \"\" \"旅行 & Stuff\"\r\nA006 SELECT \"旅行 & Stuff\"\r\nA007 SEARCH CHARSET UTF-8 ALL\r\n"
                    .as_bytes(),
            )
            .await
            .expect("commands");
    reader.get_mut().flush().await.expect("flush");
    let _login = read_until_contains(&mut reader, "A001 OK").await;
    let caps = read_until_contains(&mut reader, "A002 OK").await.join("");
    assert!(caps.contains("IMAP4rev2"));
    assert!(caps.contains("UTF8=ACCEPT"));
    let enabled = read_until_contains(&mut reader, "A003 OK").await.join("");
    assert!(enabled.contains("* ENABLED IMAP4REV2"));
    let _create = read_until_contains(&mut reader, "A004 OK").await;
    let list = read_until_contains(&mut reader, "A005 OK").await.join("");
    assert!(list.contains("\"旅行 & Stuff\""));
    assert!(!list.contains("&ZcWITA-"));
    let _select = read_until_contains(&mut reader, "A006 OK").await;
    let search = read_until_contains(&mut reader, "A007 BAD").await.join("");
    assert!(search.contains("Cannot set SEARCH charset"));

    let utf8_message = "Subject: 日本語\r\n\r\nこんにちは\r\n".as_bytes();
    reader
        .get_mut()
        .write_all(
            format!(
                "A008 APPEND \"旅行 & Stuff\" UTF8 (~{{{}}})\r\n",
                utf8_message.len()
            )
            .as_bytes(),
        )
        .await
        .expect("utf8 append command");
    reader.get_mut().flush().await.expect("flush");
    let continuation = read_until_contains(&mut reader, "+ Ready").await.join("");
    assert!(continuation.contains("+ Ready"));
    reader
        .get_mut()
        .write_all(utf8_message)
        .await
        .expect("utf8 message");
    reader.get_mut().flush().await.expect("flush");
    let appended = read_until_contains(&mut reader, "A008 OK").await.join("");
    assert!(appended.contains("APPENDUID"));

    reader
        .get_mut()
        .write_all(b"A009 APPEND INBOX ~{3+}\r\na\0b\r\nA010 LOGOUT\r\n")
        .await
        .expect("binary append and logout");
    reader.get_mut().flush().await.expect("flush");
    let binary = read_until_contains(&mut reader, "A009 OK").await.join("");
    assert!(binary.contains("APPENDUID"));
    let _logout = read_until_contains(&mut reader, "A010 OK").await;
    server_task.await.expect("join").expect("server");

    assert!(
        rmail_common::imap_state::folder_exists(&mail_root, "example.test", "user", "旅行 & Stuff")
            .expect("utf8 folder")
    );
}
#[tokio::test]
async fn geary_account_probe_gets_inbox_special_use_and_namespace() {
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
                b"A001 CAPABILITY\r\nA002 LOGIN user@example.test password\r\nA003 CAPABILITY\r\nA004 LIST \"\" INBOX\r\nA005 NAMESPACE\r\nA006 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _initial_capability = read_until_contains(&mut reader, "A001 OK").await;
    let _login = read_until_contains(&mut reader, "A002 OK").await;
    let _authed_capability = read_until_contains(&mut reader, "A003 OK").await;
    let inbox = read_until_contains(&mut reader, "A004 OK").await;
    assert!(inbox.iter().any(|l| l.contains("\"INBOX\"")));
    assert!(!inbox.iter().any(|l| l.contains("\\Inbox")));

    let namespace = read_until_contains(&mut reader, "A005 OK").await;
    assert!(
        namespace
            .iter()
            .any(|l| l == "* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n")
    );

    let _logout = read_until_contains(&mut reader, "A006 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn list_and_lsub_honor_reference_and_patterns() {
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
    rmail_common::imap_state::create_folder(&mail_root, "example.test", "user", "Projects")
        .expect("create projects");
    rmail_common::imap_state::set_subscription(
        &mail_root,
        "example.test",
        "user",
        "Projects",
        false,
    )
    .expect("unsubscribe projects");

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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 LIST \"\" \"Pro*\"\r\nA003 LIST \"\" \"INBOX\"\r\nA004 LIST \"Projects\" \"\"\r\nA005 LSUB \"\" \"Pro*\"\r\nA006 LSUB \"\" \"*\"\r\nA007 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _login = read_until_contains(&mut reader, "A001 OK").await;

    let pro_star = read_until_contains(&mut reader, "A002 OK").await;
    let joined = pro_star.join("");
    assert!(joined.contains("\"Projects\""));
    assert!(!joined.contains("\"INBOX\""));

    let inbox = read_until_contains(&mut reader, "A003 OK").await;
    let joined = inbox.join("");
    assert!(joined.contains("\"INBOX\""));
    assert!(!joined.contains("\"Projects\""));

    let reference = read_until_contains(&mut reader, "A004 OK").await;
    let joined = reference.join("");
    assert!(joined.contains("\"Projects\""));
    assert!(!joined.contains("\"INBOX\""));

    let unsubscribed = read_until_contains(&mut reader, "A005 OK").await;
    assert!(!unsubscribed.join("").contains("\"Projects\""));

    let subscribed = read_until_contains(&mut reader, "A006 OK").await;
    let joined = subscribed.join("");
    assert!(joined.contains("\"INBOX\""));
    assert!(!joined.contains("\"Projects\""));

    let _logout = read_until_contains(&mut reader, "A007 OK").await;
    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn subscribe_and_unsubscribe_update_lsub_state() {
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
    rmail_common::imap_state::create_folder(&mail_root, "example.test", "user", "Projects")
        .expect("create projects");
    rmail_common::imap_state::set_subscription(
        &mail_root,
        "example.test",
        "user",
        "Projects",
        false,
    )
    .expect("initial unsubscribe");

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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 LSUB \"\" \"Projects\"\r\nA003 SUBSCRIBE Ghost\r\nA004 LSUB \"\" \"Ghost\"\r\nA005 LIST (SUBSCRIBED) \"\" \"Ghost\" RETURN (SUBSCRIBED)\r\nA006 SELECT Ghost\r\nA007 UNSUBSCRIBE Ghost\r\nA008 LSUB \"\" \"Ghost\"\r\nA009 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
    reader.get_mut().flush().await.expect("flush");

    let _login = read_until_contains(&mut reader, "A001 OK").await;

    let initial = read_until_contains(&mut reader, "A002 OK").await;
    assert!(!initial.join("").contains("\"Projects\""));

    let subscribe = read_until_contains(&mut reader, "A003 OK").await;
    assert!(subscribe.iter().any(|l| l.contains("SUBSCRIBE completed")));

    let subscribed = read_until_contains(&mut reader, "A004 OK").await;
    assert!(
        subscribed
            .join("")
            .contains("* LSUB (\\Noselect) \"/\" \"Ghost\"")
    );

    let extended = read_until_contains(&mut reader, "A005 OK").await;
    assert!(
        extended
            .join("")
            .contains("* LIST (\\NonExistent \\Subscribed) \"/\" \"Ghost\"")
    );

    let select = read_until_contains(&mut reader, "A006 NO").await;
    assert!(select.join("").contains("does not exist"));

    let unsubscribe = read_until_contains(&mut reader, "A007 OK").await;
    assert!(
        unsubscribe
            .iter()
            .any(|l| l.contains("UNSUBSCRIBE completed"))
    );

    let final_lsub = read_until_contains(&mut reader, "A008 OK").await;
    assert!(!final_lsub.join("").contains("\"Ghost\""));

    let _logout = read_until_contains(&mut reader, "A009 OK").await;
    server_task.await.expect("join").expect("server");
}
