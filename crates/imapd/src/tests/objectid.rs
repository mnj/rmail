//! OBJECTID (RFC 8474) and the IMAP4rev2 LIST `OLDNAME` item sent after
//! RENAME (RFC 9051 §7.3.1).

use super::sync::authenticated_session;

/// The value of `NAME (value)` in a response line.
fn object_id<'a>(line: &'a str, name: &str) -> &'a str {
    let start = line
        .find(&format!("{name} ("))
        .unwrap_or_else(|| panic!("{name} in {line}"))
        + name.len()
        + 2;
    let end = start + line[start..].find(')').unwrap();
    &line[start..end]
}

#[tokio::test]
async fn mailbox_ids_are_reported_by_create_select_and_status_and_survive_rename() {
    let mut session = authenticated_session(0).await;
    let create = session.command("C1 CREATE Projects", "C1 OK").await;
    let created_id = object_id(create.last().unwrap(), "MAILBOXID").to_string();
    assert!(
        create.last().unwrap().starts_with("C1 OK [MAILBOXID ("),
        "{create:?}"
    );

    let status = session
        .command("S1 STATUS Projects (MAILBOXID MESSAGES)", "S1 OK")
        .await;
    assert_eq!(
        status[0].trim_end(),
        format!("* STATUS \"Projects\" (MESSAGES 0 MAILBOXID ({created_id}))")
    );

    session.command("R1 RENAME Projects Renamed", "R1 OK").await;
    let select = session.command("S2 SELECT Renamed", "S2 OK").await;
    let selected = select
        .iter()
        .find(|line| line.contains("[MAILBOXID ("))
        .unwrap_or_else(|| panic!("{select:?}"));
    assert_eq!(object_id(selected, "MAILBOXID"), created_id);

    let inbox = session
        .command("S3 STATUS INBOX (MAILBOXID)", "S3 OK")
        .await;
    assert_ne!(object_id(&inbox[0], "MAILBOXID"), created_id);
    let list = session
        .command(
            "L1 LIST \"\" \"Renamed\" RETURN (STATUS (MAILBOXID))",
            "L1 OK",
        )
        .await;
    assert!(
        list.iter()
            .any(|line| line.trim_end()
                == format!("* STATUS \"Renamed\" (MAILBOXID ({created_id}))")),
        "{list:?}"
    );
    session.finish().await;
}

#[tokio::test]
async fn email_ids_follow_messages_across_copy_and_move() {
    let mut session = authenticated_session(2).await;
    session.command("C1 CREATE Other", "C1 OK").await;
    session.command("S1 SELECT INBOX", "S1 OK").await;
    let fetch = session
        .command("F1 FETCH 1:2 (UID EMAILID THREADID)", "F1 OK")
        .await;
    let first = object_id(&fetch[0], "EMAILID").to_string();
    let second = object_id(&fetch[1], "EMAILID").to_string();
    assert_ne!(first, second);
    // THREADID is the email's JMAP thread.
    let first_thread = object_id(&fetch[0], "THREADID").to_string();
    assert!(first_thread.starts_with('T'), "{fetch:?}");
    let thread_search = session
        .command(&format!("Q0 SEARCH THREADID {first_thread}"), "Q0 OK")
        .await;
    assert_eq!(thread_search[0].trim_end(), "* SEARCH 1");
    // Thread membership is fixed when the search runs, so it cannot back
    // an updating context.
    let update = session
        .command(
            &format!("Q9 SEARCH RETURN (UPDATE) THREADID {first_thread}"),
            "Q9 OK",
        )
        .await;
    assert!(
        update.iter().any(|line| line.contains("[NOUPDATE \"Q9\"]")),
        "{update:?}"
    );

    let search = session
        .command(&format!("Q1 SEARCH EMAILID {second}"), "Q1 OK")
        .await;
    assert_eq!(search[0].trim_end(), "* SEARCH 2");
    let none = session.command("Q2 SEARCH THREADID T123", "Q2 OK").await;
    assert_eq!(none[0].trim_end(), "* SEARCH");
    let bad = session.command("Q3 SEARCH EMAILID a.b", "Q3 BAD").await;
    assert!(bad.last().unwrap().starts_with("Q3 BAD"), "{bad:?}");

    session.command("K1 COPY 1 Other", "K1 OK").await;
    session.command("M1 MOVE 2 Other", "M1 OK").await;
    session.command("S2 SELECT Other", "S2 OK").await;
    let fetch = session
        .command("F2 FETCH 1:2 (EMAILID THREADID)", "F2 OK")
        .await;
    assert_eq!(object_id(&fetch[0], "EMAILID"), first);
    assert_eq!(object_id(&fetch[1], "EMAILID"), second);
    assert_eq!(object_id(&fetch[0], "THREADID"), first_thread);
    session.finish().await;
}

#[tokio::test]
async fn rename_reports_oldname_to_imap4rev2_sessions_only() {
    let mut session = authenticated_session(0).await;
    session.command("C1 CREATE Projects", "C1 OK").await;
    session.command("C2 CREATE Projects/Child", "C2 OK").await;
    let rev1 = session.command("R1 RENAME Projects Work", "R1 OK").await;
    assert_eq!(rev1.len(), 1, "{rev1:?}");

    session.command("E1 ENABLE IMAP4rev2", "E1 OK").await;
    let rev2 = session
        .command("R2 RENAME Work Archive/Work", "R2 OK")
        .await;
    assert_eq!(
        rev2.iter().map(|line| line.trim_end()).collect::<Vec<_>>(),
        vec![
            "* LIST (\\HasChildren) \"/\" \"Archive/Work\" (\"OLDNAME\" (\"Work\"))",
            "* LIST (\\HasNoChildren) \"/\" \"Archive/Work/Child\" (\"OLDNAME\" (\"Work/Child\"))",
            "R2 OK RENAME completed",
        ]
    );
    session.finish().await;
}
