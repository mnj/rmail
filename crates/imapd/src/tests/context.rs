//! ESORT and CONTEXT=SEARCH / CONTEXT=SORT (RFC 5267): ESEARCH results for
//! SORT, PARTIAL windows, and ADDTO/REMOVEFROM updates as the mailbox
//! changes.

use super::sync::{Fixture, selected_session};

fn append(fixture: &Fixture, subject: &str) -> u64 {
    rmail_common::imap_state::append_message(
        &fixture.mail_root,
        "example.test",
        "user",
        "INBOX",
        format!("From: a@example.test\r\nSubject: {subject}\r\n\r\nbody\r\n").as_bytes(),
        vec![],
    )
    .expect("append")
    .1
}

fn position(lines: &[String], prefix: &str) -> usize {
    lines
        .iter()
        .position(|line| line.starts_with(prefix))
        .unwrap_or_else(|| panic!("no line starting with {prefix:?} in {lines:?}"))
}

fn esearch_lines(lines: &[String]) -> Vec<&str> {
    lines
        .iter()
        .filter(|line| line.starts_with("* ESEARCH"))
        .map(|line| line.trim_end())
        .collect()
}

#[tokio::test]
async fn capabilities_are_advertised() {
    let mut session = selected_session(0).await;
    let capability = session.command("C1 CAPABILITY", "C1 OK").await;
    for token in [" ESORT", " CONTEXT=SEARCH", " CONTEXT=SORT"] {
        assert!(capability[0].contains(token), "{token}: {capability:?}");
    }
    session.finish().await;
}

#[tokio::test]
async fn esort_returns_esearch_in_sort_order() {
    let mut session = selected_session(3).await;
    let uids = session.uids.clone();
    let lines = session
        .command(
            "E1 SORT RETURN (MIN MAX COUNT ALL) (REVERSE SUBJECT) UTF-8 ALL",
            "E1 OK",
        )
        .await;
    assert_eq!(
        lines[0].trim_end(),
        "* ESEARCH (TAG \"E1\") MIN 3 MAX 1 ALL 3,2,1 COUNT 3"
    );

    let lines = session
        .command("E2 UID SORT RETURN () (SUBJECT) UTF-8 ALL", "E2 OK")
        .await;
    assert_eq!(
        lines[0].trim_end(),
        format!("* ESEARCH (TAG \"E2\") UID ALL {}:{}", uids[0], uids[2])
    );
    assert_eq!(lines[1].trim_end(), "E2 OK UID SORT completed");

    let lines = session
        .command(
            "E3 SORT RETURN (PARTIAL 2:5) (REVERSE SUBJECT) UTF-8 ALL",
            "E3 OK",
        )
        .await;
    assert_eq!(
        lines[0].trim_end(),
        "* ESEARCH (TAG \"E3\") PARTIAL (2:5 2,1)"
    );

    let lines = session
        .command("E4 SORT RETURN (COUNT) (SUBJECT) UTF-8 SEEN", "E4 OK")
        .await;
    assert_eq!(lines[0].trim_end(), "* ESEARCH (TAG \"E4\") COUNT 0");

    // SAVE works for SORT too (RFC 5182).
    session
        .command("E5 SORT RETURN (SAVE) (REVERSE SUBJECT) UTF-8 2:3", "E5 OK")
        .await;
    let lines = session.command("E6 SEARCH RETURN (ALL) $", "E6 OK").await;
    assert_eq!(lines[0].trim_end(), "* ESEARCH (TAG \"E6\") ALL 2:3");

    // RFC 9394 PARTIAL on SORT: negative ranges count from the end of the
    // sorted result, and SAVE keeps only what MAX and PARTIAL report.
    let lines = session
        .command(
            "E7 SORT RETURN (PARTIAL -1:-1) (REVERSE SUBJECT) UTF-8 ALL",
            "E7 OK",
        )
        .await;
    assert_eq!(
        lines[0].trim_end(),
        "* ESEARCH (TAG \"E7\") PARTIAL (-1:-1 1)"
    );
    let lines = session
        .command(
            "E8 SORT RETURN (SAVE MAX PARTIAL 1:1) (REVERSE SUBJECT) UTF-8 ALL",
            "E8 OK",
        )
        .await;
    assert_eq!(
        lines[0].trim_end(),
        "* ESEARCH (TAG \"E8\") MAX 1 PARTIAL (1:1 3)"
    );
    let lines = session.command("E9 SEARCH RETURN (ALL) $", "E9 OK").await;
    assert_eq!(lines[0].trim_end(), "* ESEARCH (TAG \"E9\") ALL 1,3");

    for (tag, command) in [
        ("B1", "SORT RETURN (ALL PARTIAL 1:2) (DATE) UTF-8 ALL"),
        ("B2", "SORT RETURN (PARTIAL 0:2) (DATE) UTF-8 ALL"),
        ("B3", "SORT RETURN (BOGUS) (DATE) UTF-8 ALL"),
        ("B4", "SEARCH RETURN (PARTIAL 1:2 PARTIAL 3:4) ALL"),
    ] {
        let lines = session.command(&format!("{tag} {command}"), tag).await;
        assert!(
            lines.last().unwrap().starts_with(&format!("{tag} BAD")),
            "{command}: {lines:?}"
        );
    }
    session.finish().await;
}

#[tokio::test]
async fn search_partial_returns_windows_in_mailbox_order() {
    let mut session = selected_session(4).await;
    let uids = session.uids.clone();
    let lines = session
        .command("P1 UID SEARCH RETURN (PARTIAL 3:2) ALL", "P1 OK")
        .await;
    assert_eq!(
        lines[0].trim_end(),
        format!(
            "* ESEARCH (TAG \"P1\") UID PARTIAL (3:2 {}:{})",
            uids[1], uids[2]
        )
    );
    let lines = session
        .command("P2 SEARCH RETURN (PARTIAL 10:20 COUNT) ALL", "P2 OK")
        .await;
    assert_eq!(
        lines[0].trim_end(),
        "* ESEARCH (TAG \"P2\") PARTIAL (10:20 NIL) COUNT 4"
    );
    // CONTEXT is only a hint.
    let lines = session
        .command("P3 SEARCH RETURN (CONTEXT COUNT) ALL", "P3 OK")
        .await;
    assert_eq!(lines[0].trim_end(), "* ESEARCH (TAG \"P3\") COUNT 4");
    session.finish().await;
}

#[tokio::test]
async fn search_context_tracks_flags_arrivals_and_expunges() {
    let mut session = selected_session(3).await;
    let uids = session.uids.clone();
    let lines = session
        .command("U1 UID SEARCH RETURN (UPDATE) UNSEEN", "U1 OK")
        .await;
    assert_eq!(
        lines[0].trim_end(),
        format!("* ESEARCH (TAG \"U1\") UID ALL {}:{}", uids[0], uids[2])
    );
    // Only UPDATE: the tag may not be reused for another updating context.
    let reuse = session
        .command("U1 SORT RETURN (UPDATE) (DATE) UTF-8 ALL", "U1 ")
        .await;
    assert!(reuse.last().unwrap().starts_with("U1 BAD"), "{reuse:?}");

    // The session's own STORE.
    session.command("S2 STORE 1 +FLAGS (\\Seen)", "S2 OK").await;
    let update = session.expect("* ESEARCH").await;
    assert_eq!(
        update.last().unwrap().trim_end(),
        format!("* ESEARCH (TAG \"U1\") UID REMOVEFROM (0 {})", uids[0])
    );

    // A delivery, reported after EXISTS.
    let new = append(&session, "new");
    let lines = session.command("N1 NOOP", "N1 OK").await;
    assert!(
        position(&lines, "* 4 EXISTS") < position(&lines, "* ESEARCH"),
        "{lines:?}"
    );
    assert_eq!(
        esearch_lines(&lines),
        vec![format!("* ESEARCH (TAG \"U1\") UID ADDTO (0 {new})")]
    );

    // An expunge elsewhere, reported before EXPUNGE.
    session.expunge_elsewhere(uids[1]);
    let lines = session.command("N2 NOOP", "N2 OK").await;
    assert!(
        position(&lines, "* ESEARCH") < position(&lines, "* 2 EXPUNGE"),
        "{lines:?}"
    );
    assert_eq!(
        esearch_lines(&lines),
        vec![format!(
            "* ESEARCH (TAG \"U1\") UID REMOVEFROM (0 {})",
            uids[1]
        )]
    );

    let lines = session.command("X1 CANCELUPDATE \"U9\"", "X1 ").await;
    assert!(lines.last().unwrap().starts_with("X1 BAD"), "{lines:?}");
    session.command("X2 CANCELUPDATE \"U1\"", "X2 OK").await;
    append(&session, "after cancel");
    let lines = session.command("N3 NOOP", "N3 OK").await;
    assert!(esearch_lines(&lines).is_empty(), "{lines:?}");
    // The tag is free again.
    session
        .command("U1 SEARCH RETURN (UPDATE COUNT) ALL", "U1 OK")
        .await;
    session.finish().await;
}

#[tokio::test]
async fn message_number_contexts_remove_before_expunge() {
    let mut session = selected_session(3).await;
    session
        .command("U1 SEARCH RETURN (UPDATE) ALL", "U1 OK")
        .await;
    session
        .command("S1 STORE 2 +FLAGS.SILENT (\\Deleted)", "S1 OK")
        .await;
    // The session's own EXPUNGE: REMOVEFROM with the old number first.
    let lines = session.command("X1 EXPUNGE", "X1 OK").await;
    assert!(
        position(&lines, "* ESEARCH (TAG \"U1\") REMOVEFROM (0 2)")
            < position(&lines, "* 2 EXPUNGE"),
        "{lines:?}"
    );

    // An expunge during a command that may not report it: the message
    // leaves the result at once, while its number is still valid.
    let uids = session.uids.clone();
    session.expunge_elsewhere(uids[2]);
    let lines = session.command("F1 FETCH 1 FLAGS", "F1 OK").await;
    assert_eq!(
        esearch_lines(&lines),
        vec!["* ESEARCH (TAG \"U1\") REMOVEFROM (0 2)"]
    );
    assert!(
        !lines.iter().any(|line| line.contains("EXPUNGE")),
        "{lines:?}"
    );
    let lines = session.command("N1 NOOP", "N1 OK").await;
    assert!(lines.iter().any(|line| line.trim_end() == "* 2 EXPUNGE"));
    assert!(esearch_lines(&lines).is_empty(), "{lines:?}");
    session.finish().await;
}

#[tokio::test]
async fn sort_context_updates_carry_positions() {
    let mut session = selected_session(3).await;
    let uids = session.uids.clone();
    let lines = session
        .command(
            "T1 SORT RETURN (UPDATE) (REVERSE SUBJECT) UTF-8 ALL",
            "T1 OK",
        )
        .await;
    assert_eq!(lines[0].trim_end(), "* ESEARCH (TAG \"T1\") ALL 3,2,1");
    session
        .command(
            "T2 UID SORT RETURN (UPDATE COUNT) (SUBJECT) UTF-8 UNDELETED",
            "T2 OK",
        )
        .await;

    // "message 5" sorts first in reverse subject order, last in forward.
    let new = append(&session, "message 5");
    let lines = session.command("N1 NOOP", "N1 OK").await;
    assert!(
        position(&lines, "* 4 EXISTS") < position(&lines, "* ESEARCH"),
        "{lines:?}"
    );
    assert_eq!(
        esearch_lines(&lines),
        vec![
            "* ESEARCH (TAG \"T1\") ADDTO (1 4)".to_string(),
            format!("* ESEARCH (TAG \"T2\") UID ADDTO (4 {new})"),
        ]
    );

    // Results are now [4, 3, 2, 1]; "message 1" (number 2) is third.
    session.expunge_elsewhere(uids[1]);
    let lines = session.command("N2 NOOP", "N2 OK").await;
    assert!(
        position(&lines, "* ESEARCH (TAG \"T1\")") < position(&lines, "* 2 EXPUNGE"),
        "{lines:?}"
    );
    assert_eq!(
        esearch_lines(&lines),
        vec![
            "* ESEARCH (TAG \"T1\") REMOVEFROM (3 2)".to_string(),
            format!("* ESEARCH (TAG \"T2\") UID REMOVEFROM (2 {})", uids[1]),
        ]
    );

    // A flag change moves a message out of the UNDELETED context only.
    session
        .command("S1 STORE 1 +FLAGS.SILENT (\\Deleted)", "S1 OK")
        .await;
    let update = session.expect("* ESEARCH").await;
    assert_eq!(
        update.last().unwrap().trim_end(),
        format!("* ESEARCH (TAG \"T2\") UID REMOVEFROM (1 {})", uids[0])
    );
    session.finish().await;
}

#[tokio::test]
async fn contexts_end_with_the_selection_and_are_limited() {
    let mut session = selected_session(1).await;
    for index in 0..crate::commands::context::MAX_UPDATE_CONTEXTS {
        let tag = format!("Q{index}");
        let lines = session
            .command(
                &format!("{tag} SEARCH RETURN (UPDATE COUNT) ALL"),
                &format!("{tag} OK"),
            )
            .await;
        assert!(!lines.iter().any(|line| line.contains("NOUPDATE")));
    }
    let lines = session
        .command("QX SEARCH RETURN (UPDATE COUNT) ALL", "QX OK")
        .await;
    assert_eq!(lines[0].trim_end(), "* ESEARCH (TAG \"QX\") COUNT 1");
    assert!(lines[1].starts_with("* NO [NOUPDATE \"QX\"]"), "{lines:?}");

    session.command("S2 SELECT INBOX", "S2 OK").await;
    append(&session, "later");
    let lines = session.command("N1 NOOP", "N1 OK").await;
    assert!(esearch_lines(&lines).is_empty(), "{lines:?}");
    let lines = session.command("X1 CANCELUPDATE \"Q0\"", "X1 ").await;
    assert!(lines.last().unwrap().starts_with("X1 BAD"), "{lines:?}");
    session.finish().await;
}

#[tokio::test]
async fn updates_arrive_during_idle() {
    let mut session = selected_session(1).await;
    session
        .command("U1 UID SEARCH RETURN (UPDATE) ALL", "U1 OK")
        .await;
    session.command("I1 IDLE", "+ idling").await;
    let new = append(&session, "pushed");
    let lines = session.expect("* ESEARCH").await;
    assert!(lines.iter().any(|line| line.trim_end() == "* 2 EXISTS"));
    assert_eq!(
        lines.last().unwrap().trim_end(),
        format!("* ESEARCH (TAG \"U1\") UID ADDTO (0 {new})")
    );
    session.command("DONE", "I1 OK").await;
    session.finish().await;
}

#[tokio::test]
async fn replace_updates_contexts_around_expunge_and_exists() {
    let mut session = selected_session(3).await;
    let uids = session.uids.clone();
    session
        .command("U1 UID SEARCH RETURN (UPDATE) ALL", "U1 OK")
        .await;
    let message = b"From: a@example.test\r\nSubject: replacement\r\n\r\nnew\r\n";
    let mut bytes = format!(
        "R1 UID REPLACE {} INBOX {{{}+}}\r\n",
        uids[1],
        message.len()
    )
    .into_bytes();
    bytes.extend_from_slice(message);
    bytes.extend_from_slice(b"\r\n");
    session.send(&bytes).await;
    let lines = session.expect("R1 OK").await;
    // ADDTO follows EXISTS and REMOVEFROM precedes EXPUNGE; the two share
    // one ESEARCH response.
    let update = position(
        &lines,
        &format!(
            "* ESEARCH (TAG \"U1\") UID REMOVEFROM (0 {}) ADDTO (0 ",
            uids[1]
        ),
    );
    assert!(position(&lines, "* 4 EXISTS") < update, "{lines:?}");
    assert!(update < position(&lines, "* 2 EXPUNGE"), "{lines:?}");
    session.finish().await;
}
