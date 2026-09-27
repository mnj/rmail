//! NOTIFY (RFC 5465): changes reported without a command, for the selected
//! mailbox and for others.

use super::sync::{authenticated_session, selected_session};

const USER: (&str, &str) = ("example.test", "user");

fn append(fixture: &super::sync::Fixture, mailbox: &str) -> u64 {
    rmail_common::imap_state::append_message(
        &fixture.mail_root,
        USER.0,
        USER.1,
        mailbox,
        b"From: a@example.test\r\nSubject: pushed\r\n\r\nbody\r\n",
        vec![],
    )
    .expect("append")
    .1
}

#[tokio::test]
async fn capability_and_argument_errors() {
    let mut session = authenticated_session(0).await;
    let capability = session.command("C1 CAPABILITY", "C1 OK").await;
    assert!(capability[0].contains(" NOTIFY"), "{capability:?}");

    let bad = session
        .command("N1 NOTIFY SET (personal (MessageNew))", "N1 ")
        .await;
    assert!(bad.last().unwrap().starts_with("N1 BAD"), "{bad:?}");
    let bad_event = session
        .command(
            "N2 NOTIFY SET (personal (MessageNew MessageExpunge AnnotationChange))",
            "N2 ",
        )
        .await;
    assert!(
        bad_event
            .last()
            .unwrap()
            .starts_with("N2 NO [BADEVENT (MessageNew MessageExpunge FlagChange"),
        "{bad_event:?}"
    );
    let fetch_elsewhere = session
        .command(
            "N3 NOTIFY SET (inboxes (MessageNew (UID) MessageExpunge))",
            "N3 ",
        )
        .await;
    assert!(fetch_elsewhere.last().unwrap().starts_with("N3 BAD"));
    session.command("N4 NOTIFY NONE", "N4 OK").await;
    session.finish().await;
}

#[tokio::test]
async fn set_status_reports_every_watched_mailbox() {
    let mut session = authenticated_session(2).await;
    session.command("C1 CREATE Lists", "C1 OK").await;
    append(&session, "Lists");
    let lines = session
        .command(
            "N1 NOTIFY SET STATUS (personal (MessageNew MessageExpunge))",
            "N1 OK",
        )
        .await;
    assert!(
        lines.iter().any(|line| line.trim_end()
            == "* STATUS \"Lists\" (MESSAGES 1 UIDNEXT 2 UIDVALIDITY 1 UNSEEN 1)"
            || line.starts_with("* STATUS \"Lists\" (MESSAGES 1 UIDNEXT 2 ")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("* STATUS \"INBOX\" (MESSAGES 2 ")),
        "{lines:?}"
    );
    session.finish().await;
}

#[tokio::test]
async fn selected_mailbox_changes_arrive_without_a_command() {
    let mut session = selected_session(1).await;
    session
        .command(
            "N1 NOTIFY SET (selected (MessageNew (UID BODY.PEEK[HEADER.FIELDS (SUBJECT)]) MessageExpunge FlagChange))",
            "N1 OK",
        )
        .await;
    let uid = append(&session, "INBOX");
    let arrived = session.expect("FETCH").await;
    assert!(
        arrived.iter().any(|line| line.trim_end() == "* 2 EXISTS"),
        "{arrived:?}"
    );
    let fetch = arrived.last().unwrap();
    assert!(fetch.starts_with("* 2 FETCH ("), "{arrived:?}");
    assert!(fetch.contains(&format!("UID {uid}")), "{fetch:?}");
    assert!(fetch.contains("BODY[HEADER.FIELDS (SUBJECT)]"), "{fetch:?}");
    // The literal body follows.
    session.expect("Subject: pushed").await;

    let first = session.uids[0];
    session.expunge_elsewhere(first);
    session.expect("* 1 EXPUNGE").await;
    assert!(
        session.flags(uid).is_empty(),
        "notification must not set \\Seen"
    );
    session.finish().await;
}

#[tokio::test]
async fn selected_delayed_holds_expunges_for_a_command() {
    let mut session = selected_session(2).await;
    session
        .command(
            "N1 NOTIFY SET (selected-delayed (MessageNew MessageExpunge))",
            "N1 OK",
        )
        .await;
    let first = session.uids[0];
    session.expunge_elsewhere(first);
    append(&session, "INBOX");
    // The arrival is pushed; the expunged message keeps its slot.
    session.expect("* 3 EXISTS").await;
    let noop = session.command("A1 NOOP", "A1 OK").await;
    assert!(
        noop.iter().any(|line| line.trim_end() == "* 1 EXPUNGE"),
        "{noop:?}"
    );
    session.finish().await;
}

#[tokio::test]
async fn other_mailboxes_report_status_and_mailbox_events() {
    let mut session = selected_session(0).await;
    session.command("C1 CREATE Lists", "C1 OK").await;
    session
        .command(
            "N1 NOTIFY SET (selected (MessageNew MessageExpunge)) (personal (MessageNew MessageExpunge MailboxName SubscriptionChange))",
            "N1 OK",
        )
        .await;

    append(&session, "Lists");
    let status = session.expect("* STATUS").await;
    assert!(
        status
            .last()
            .unwrap()
            .starts_with("* STATUS \"Lists\" (MESSAGES 1 UIDNEXT 2 "),
        "{status:?}"
    );

    let root = session.mail_root.clone();
    rmail_common::imap_state::create_folder(&root, USER.0, USER.1, "Projects").unwrap();
    // New and renamed mailboxes are subscribed; one LIST covers both events.
    let created = session.expect("\"Projects\"").await;
    assert_eq!(
        created.last().unwrap().trim_end(),
        "* LIST (\\Subscribed) \"/\" \"Projects\"",
        "{created:?}"
    );

    rmail_common::imap_state::rename_folder(&root, USER.0, USER.1, "Projects", "Done").unwrap();
    let renamed = session.expect("OLDNAME").await;
    assert_eq!(
        renamed.last().unwrap().trim_end(),
        "* LIST (\\Subscribed) \"/\" \"Done\" (\"OLDNAME\" (\"Projects\"))",
        "{renamed:?}"
    );

    rmail_common::imap_state::set_subscription(&root, USER.0, USER.1, "Done", false).unwrap();
    session.expect("* LIST () \"/\" \"Done\"").await;

    rmail_common::imap_state::delete_folder(&root, USER.0, USER.1, "Done").unwrap();
    session
        .expect("* LIST (\\NonExistent) \"/\" \"Done\"")
        .await;

    // NOTIFY NONE stops notifications; the next command sees nothing extra.
    session.command("N2 NOTIFY NONE", "N2 OK").await;
    append(&session, "Lists");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let noop = session.command("A1 NOOP", "A1 OK").await;
    assert_eq!(noop.len(), 1, "{noop:?}");
    session.finish().await;
}

#[tokio::test]
async fn metadata_changes_are_reported() {
    let mut session = authenticated_session(0).await;
    session
        .command(
            "N1 NOTIFY SET (inboxes (MailboxMetadataChange ServerMetadataChange))",
            "N1 OK",
        )
        .await;
    let root = session.mail_root.clone();
    rmail_common::imap_state::set_metadata(
        &root,
        USER.0,
        USER.1,
        Some("INBOX"),
        &[("/private/comment".to_string(), Some("hi".to_string()))],
        100,
    )
    .unwrap();
    session
        .expect("* METADATA \"INBOX\" \"/private/comment\"")
        .await;
    rmail_common::imap_state::set_metadata(
        &root,
        USER.0,
        USER.1,
        None,
        &[("/shared/comment".to_string(), Some("server".to_string()))],
        100,
    )
    .unwrap();
    session.expect("* METADATA \"\" \"/shared/comment\"").await;
    session.finish().await;
}

#[tokio::test]
async fn idle_reports_other_mailboxes() {
    let mut session = selected_session(0).await;
    session.command("C1 CREATE Lists", "C1 OK").await;
    session
        .command(
            "N1 NOTIFY SET (subtree Lists (MessageNew MessageExpunge))",
            "N1 OK",
        )
        .await;
    session.command("I1 IDLE", "+ idling").await;
    append(&session, "Lists");
    session.expect("* STATUS \"Lists\"").await;
    append(&session, "INBOX");
    // Without a SELECTED group, IDLE still reports the selected mailbox.
    session.expect("* 1 EXISTS").await;
    session.command("DONE", "I1 OK").await;
    session.finish().await;
}
