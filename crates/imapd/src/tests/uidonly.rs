//! UIDONLY (RFC 9586): no message sequence numbers in either direction once
//! enabled.

use super::sync::{authenticated_session, selected_session};

const USER: (&str, &str) = ("example.test", "user");

fn set_flags(fixture: &super::sync::Fixture, uid: u64, flags: &[&str]) {
    rmail_common::imap_state::set_uid_flags_batch(
        &fixture.mail_root,
        USER.0,
        USER.1,
        "INBOX",
        &[(uid, flags.iter().map(|flag| flag.to_string()).collect())],
    )
    .expect("set flags");
}

fn append(fixture: &super::sync::Fixture) -> u64 {
    rmail_common::imap_state::append_message(
        &fixture.mail_root,
        USER.0,
        USER.1,
        "INBOX",
        b"From: a@example.test\r\nSubject: pushed\r\n\r\nbody\r\n",
        vec![],
    )
    .expect("append")
    .1
}

fn no_sequence_fetch(lines: &[String]) -> bool {
    !lines
        .iter()
        .any(|line| line.contains(" FETCH (") && !line.contains(" UIDFETCH ("))
}

#[tokio::test]
async fn advertised_and_enabled() {
    let mut session = authenticated_session(0).await;
    let capability = session.command("C1 CAPABILITY", "C1 OK").await;
    assert!(capability[0].contains(" UIDONLY"), "{capability:?}");
    let enabled = session.command("E1 ENABLE UIDONLY", "E1 OK").await;
    assert!(
        enabled
            .iter()
            .any(|line| line.trim_end() == "* ENABLED UIDONLY"),
        "{enabled:?}"
    );
    session.finish().await;
}

#[tokio::test]
async fn sequence_number_commands_are_refused() {
    let mut session = authenticated_session(2).await;
    session.command("E1 ENABLE UIDONLY", "E1 OK").await;
    session.command("S1 SELECT INBOX", "S1 OK").await;
    for (tag, command) in [
        ("A1", "FETCH 1 (FLAGS)"),
        ("A2", "STORE 1 +FLAGS (\\Seen)"),
        ("A3", "SEARCH ALL"),
        ("A4", "COPY 1 INBOX"),
        ("A5", "MOVE 1 INBOX"),
        ("A6", "SORT (ARRIVAL) UTF-8 ALL"),
        ("A7", "THREAD REFERENCES UTF-8 ALL"),
        ("A8", "UID SEARCH 1:2"),
        ("A9", "UID SEARCH NOT OR SEEN 1"),
        ("B1", "UID SORT (ARRIVAL) UTF-8 1"),
        ("B2", "UID THREAD REFERENCES UTF-8 1:*"),
    ] {
        let lines = session
            .command(&format!("{tag} {command}"), &format!("{tag} "))
            .await;
        assert_eq!(
            lines.last().unwrap().trim_end(),
            format!(
                "{tag} BAD [UIDREQUIRED] Message numbers are not allowed once UIDONLY is enabled"
            ),
            "{command}: {lines:?}"
        );
    }
    // Nothing was stored.
    assert!(session.flags(session.uids[0]).is_empty());

    // UID criteria and ALL stay available.
    let search = session
        .command(&format!("B3 UID SEARCH UID {}:*", session.uids[1]), "B3 OK")
        .await;
    assert!(
        search
            .iter()
            .any(|line| line.trim_end() == format!("* SEARCH {}", session.uids[1])),
        "{search:?}"
    );
    let esearch = session
        .command("B4 UID SEARCH RETURN (MIN MAX) ALL", "B4 OK")
        .await;
    assert!(
        esearch.iter().any(|line| line.trim_end()
            == format!(
                "* ESEARCH (TAG \"B4\") UID MIN {} MAX {}",
                session.uids[0], session.uids[1]
            )),
        "{esearch:?}"
    );
    session
        .command("B5 UID SORT (ARRIVAL) UTF-8 ALL", "B5 OK")
        .await;
    session.finish().await;
}

#[tokio::test]
async fn uid_fetch_and_store_answer_with_uidfetch() {
    let mut session = selected_session(2).await;
    let uids = session.uids.clone();
    session.command("E1 ENABLE UIDONLY", "E1 OK").await;

    let fetch = session.command("F1 UID FETCH 1:* (FLAGS)", "F1 OK").await;
    assert_eq!(
        fetch[..2]
            .iter()
            .map(|line| line.trim_end().to_string())
            .collect::<Vec<_>>(),
        vec![
            format!("* {} UIDFETCH (FLAGS ())", uids[0]),
            format!("* {} UIDFETCH (FLAGS ())", uids[1]),
        ]
    );
    // The UID item appears only when asked for.
    let fetch = session
        .command(
            &format!(
                "F2 UID FETCH {} (UID BODY.PEEK[HEADER.FIELDS (SUBJECT)])",
                uids[1]
            ),
            "F2 OK",
        )
        .await;
    assert!(
        fetch[0].starts_with(&format!(
            "* {} UIDFETCH (UID {} BODY[HEADER.FIELDS (SUBJECT)] {{",
            uids[1], uids[1]
        )),
        "{fetch:?}"
    );

    let store = session
        .command(
            &format!("T1 UID STORE {} +FLAGS (\\Flagged)", uids[0]),
            "T1 OK",
        )
        .await;
    assert!(
        store[0]
            .trim_end()
            .eq_ignore_ascii_case(&format!("* {} UIDFETCH (FLAGS (\\Flagged))", uids[0])),
        "{store:?}"
    );

    // CONDSTORE: MODSEQ goes into UIDFETCH, silent stores still report it.
    session.command("E2 ENABLE CONDSTORE", "E2 OK").await;
    let store = session
        .command(
            &format!("T2 UID STORE {} +FLAGS.SILENT (\\Seen)", uids[0]),
            "T2 OK",
        )
        .await;
    assert!(
        store[0].starts_with(&format!("* {} UIDFETCH (MODSEQ (", uids[0])),
        "{store:?}"
    );
    let fetch = session
        .command(&format!("F3 UID FETCH {} (FLAGS)", uids[1]), "F3 OK")
        .await;
    assert!(
        fetch[0].starts_with(&format!("* {} UIDFETCH (FLAGS () MODSEQ (", uids[1])),
        "{fetch:?}"
    );
    assert!(no_sequence_fetch(&fetch));
    session.finish().await;
}

#[tokio::test]
async fn expunges_are_reported_as_vanished() {
    let mut session = selected_session(4).await;
    let uids = session.uids.clone();
    session.command("E1 ENABLE UIDONLY", "E1 OK").await;
    session
        .command(
            &format!(
                "T1 UID STORE {},{} +FLAGS.SILENT (\\Deleted)",
                uids[0], uids[1]
            ),
            "T1 OK",
        )
        .await;
    let expunge = session.command("X1 EXPUNGE", "X1 OK").await;
    assert_eq!(
        expunge[0].trim_end(),
        format!("* VANISHED {}:{}", uids[0], uids[1])
    );
    assert!(!expunge.iter().any(|line| line.contains(" EXPUNGE\r")));

    session.command("C1 CREATE Kept", "C1 OK").await;
    let moved = session
        .command(&format!("M1 UID MOVE {} Kept", uids[2]), "M1 OK")
        .await;
    assert!(
        moved.iter().any(|line| line.contains("[COPYUID ")),
        "{moved:?}"
    );
    assert!(
        moved
            .iter()
            .any(|line| line.trim_end() == format!("* VANISHED {}", uids[2])),
        "{moved:?}"
    );

    // Changes by others: VANISHED, EXISTS and UIDFETCH, never numbers.
    let added = append(&session);
    set_flags(&session, added, &["\\Answered"]);
    session.expunge_elsewhere(uids[3]);
    set_flags(&session, added, &["\\Flagged"]);
    let noop = session.command("N1 NOOP", "N1 OK").await;
    assert!(
        noop.iter()
            .any(|line| line.trim_end() == format!("* VANISHED {}", uids[3])),
        "{noop:?}"
    );
    assert!(
        noop.iter().any(|line| line.trim_end() == "* 1 EXISTS"),
        "{noop:?}"
    );

    set_flags(&session, added, &["\\Seen"]);
    let noop = session.command("N2 NOOP", "N2 OK").await;
    assert!(
        noop.iter()
            .any(|line| line.trim_end() == format!("* {added} UIDFETCH (FLAGS (\\Seen))")),
        "{noop:?}"
    );
    assert!(no_sequence_fetch(&noop));
    session.finish().await;
}

#[tokio::test]
async fn idle_and_notify_use_uid_responses() {
    let mut session = selected_session(2).await;
    let uids = session.uids.clone();
    session.command("E1 ENABLE UIDONLY", "E1 OK").await;

    session.command("I1 IDLE", "+ idling").await;
    session.expunge_elsewhere(uids[0]);
    session.expect(&format!("* VANISHED {}", uids[0])).await;
    set_flags(&session, uids[1], &["\\Flagged"]);
    session
        .expect(&format!("* {} UIDFETCH (FLAGS (\\Flagged))", uids[1]))
        .await;
    session.command("DONE", "I1 OK").await;

    session
        .command(
            "N1 NOTIFY SET (selected (MessageNew (UID FLAGS) MessageExpunge FlagChange))",
            "N1 OK",
        )
        .await;
    let added = append(&session);
    let arrived = session.expect("UIDFETCH").await;
    assert_eq!(
        arrived.last().unwrap().trim_end(),
        format!("* {added} UIDFETCH (FLAGS () UID {added})")
    );
    session.expunge_elsewhere(uids[1]);
    session.expect(&format!("* VANISHED {}", uids[1])).await;
    session.command("N2 NOTIFY NONE", "N2 OK").await;
    session.finish().await;
}

#[tokio::test]
async fn select_omits_sequence_numbers_and_qresync_match_data() {
    let mut session = authenticated_session(2).await;
    let uids = session.uids.clone();
    session.command("E1 ENABLE UIDONLY QRESYNC", "E1 OK").await;
    let select = session.command("S1 SELECT INBOX", "S1 OK").await;
    assert!(
        !select.iter().any(|line| line.contains("[UNSEEN ")),
        "{select:?}"
    );
    let uidvalidity = select
        .iter()
        .find_map(|line| line.strip_prefix("* OK [UIDVALIDITY "))
        .and_then(|rest| rest.split(']').next())
        .expect("UIDVALIDITY")
        .to_string();

    let refused = session
        .command(
            &format!("S2 SELECT INBOX (QRESYNC ({uidvalidity} 1 1:2 (1:2 1:2)))"),
            "S2 ",
        )
        .await;
    assert!(
        refused.last().unwrap().starts_with("S2 BAD [UIDREQUIRED]"),
        "{refused:?}"
    );

    set_flags(&session, uids[1], &["\\Seen"]);
    let resync = session
        .command(
            &format!("S3 SELECT INBOX (QRESYNC ({uidvalidity} 1))"),
            "S3 OK",
        )
        .await;
    assert!(
        resync
            .iter()
            .any(|line| line
                .starts_with(&format!("* {} UIDFETCH (FLAGS (\\Seen) MODSEQ (", uids[1]))),
        "{resync:?}"
    );
    assert!(no_sequence_fetch(&resync));
    session.finish().await;
}
