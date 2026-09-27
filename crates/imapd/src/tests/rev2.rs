//! IMAP4rev2 (RFC 9051) behaviour after ENABLE IMAP4rev2.

use super::sync::authenticated_session;

#[tokio::test]
async fn enable_does_not_report_imap4rev1() {
    let mut session = authenticated_session(0).await;
    let enabled = session.command("E1 ENABLE IMAP4rev1", "E1 OK").await;
    assert_eq!(enabled[0].trim_end(), "* ENABLED", "{enabled:?}");
    let enabled = session
        .command("E2 ENABLE IMAP4rev1 IMAP4rev2", "E2 OK")
        .await;
    assert_eq!(enabled[0].trim_end(), "* ENABLED IMAP4REV2", "{enabled:?}");
    session.finish().await;
}

#[tokio::test]
async fn rev1_sessions_keep_recent_and_plain_search() {
    let mut session = authenticated_session(1).await;
    session.deliver_recent();
    let select = session.command("S1 SELECT INBOX", "S1 OK").await;
    assert!(select.iter().any(|line| line.trim_end() == "* 1 RECENT"));
    let fetch = session.command("F1 FETCH 2 FLAGS", "F1 OK").await;
    assert!(fetch[0].contains("\\Recent"), "{fetch:?}");
    let search = session.command("Q1 SEARCH ALL", "Q1 OK").await;
    assert_eq!(search[0].trim_end(), "* SEARCH 1 2");
    session.finish().await;
}

#[tokio::test]
async fn rev2_drops_recent_uses_esearch_and_lists_the_selected_mailbox() {
    let mut session = authenticated_session(2).await;
    session.deliver_recent();
    session.command("E1 ENABLE IMAP4rev2", "E1 OK").await;
    let select = session.command("S1 SELECT INBOX", "S1 OK").await;
    assert!(
        !select.iter().any(|line| line.contains("RECENT")),
        "{select:?}"
    );
    assert!(
        select
            .iter()
            .any(|line| line.starts_with("* LIST (") && line.contains("INBOX")),
        "{select:?}"
    );
    let fetch = session.command("F1 FETCH 1:* FLAGS", "F1 OK").await;
    assert!(
        !fetch.iter().any(|line| line.contains("\\Recent")),
        "{fetch:?}"
    );
    session
        .command("T1 STORE 2 +FLAGS (\\Deleted)", "T1 OK")
        .await;

    let search = session.command("Q1 SEARCH ALL", "Q1 OK").await;
    assert_eq!(
        search[0].trim_end(),
        "* ESEARCH (TAG \"Q1\") ALL 1:3",
        "{search:?}"
    );
    let uid_search = session.command("Q2 UID SEARCH DELETED", "Q2 OK").await;
    assert_eq!(
        uid_search[0].trim_end(),
        format!("* ESEARCH (TAG \"Q2\") UID ALL {}", session.uids[1])
    );
    let none = session.command("Q3 SEARCH SUBJECT nothing", "Q3 OK").await;
    assert_eq!(none[0].trim_end(), "* ESEARCH (TAG \"Q3\")");
    let count = session
        .command("Q4 SEARCH RETURN (COUNT) ALL", "Q4 OK")
        .await;
    assert_eq!(count[0].trim_end(), "* ESEARCH (TAG \"Q4\") COUNT 3");

    session.command("U1 UNSELECT", "U1 OK").await;
    let status = session
        .command("S2 STATUS INBOX (MESSAGES DELETED SIZE)", "S2 OK")
        .await;
    assert!(
        status[0].starts_with("* STATUS \"INBOX\" (MESSAGES 3 SIZE ")
            && status[0].trim_end().ends_with(" DELETED 1)"),
        "{status:?}"
    );
    let list = session
        .command("L2 LIST \"\" \"INBOX\" RETURN (STATUS (DELETED))", "L2 OK")
        .await;
    assert!(
        list.iter()
            .any(|line| line.starts_with("* STATUS \"INBOX\" (DELETED 1)")),
        "{list:?}"
    );
    session.finish().await;
}
