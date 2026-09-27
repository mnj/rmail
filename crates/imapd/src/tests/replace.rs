//! REPLACE and UID REPLACE (RFC 8508).

use super::sync::{Fixture, authenticated_session, selected_session};

const NEW_MESSAGE: &[u8] = b"From: a@example.test\r\nSubject: replacement\r\n\r\nnew body\r\n";

fn messages(session: &Fixture, mailbox: &str) -> Vec<rmail_common::imap_state::Message> {
    rmail_common::imap_state::load_folder(&session.mail_root, "example.test", "user", mailbox)
        .expect("load folder")
        .1
}

fn body(message: &rmail_common::imap_state::Message) -> Vec<u8> {
    std::fs::read(&message.path).expect("read message")
}

/// Send `command {n}` or `command {n+}` followed by `data`, waiting for the
/// continuation of a synchronizing literal.
async fn send_with_literal(session: &mut Fixture, command: &str, data: &[u8], non_sync: bool) {
    if non_sync {
        let mut bytes = format!("{command} {{{}+}}\r\n", data.len()).into_bytes();
        bytes.extend_from_slice(data);
        bytes.extend_from_slice(b"\r\n");
        session.send(&bytes).await;
    } else {
        let continuation = session
            .command(&format!("{command} {{{}}}", data.len()), "+ ")
            .await;
        assert!(continuation.last().unwrap().starts_with("+ "));
        let mut bytes = data.to_vec();
        bytes.extend_from_slice(b"\r\n");
        session.send(&bytes).await;
    }
}

fn position(lines: &[String], prefix: &str) -> usize {
    lines
        .iter()
        .position(|line| line.starts_with(prefix))
        .unwrap_or_else(|| panic!("no line starting with {prefix:?} in {lines:?}"))
}

#[tokio::test]
async fn replace_into_other_mailbox_expunges_old_message_like_move() {
    let mut session = selected_session(3).await;
    let old_uid = session.uids[1];
    send_with_literal(
        &mut session,
        "A1 REPLACE 2 Drafts (\\Seen \\Draft) \"17-Jul-1996 02:44:25 -0700\"",
        NEW_MESSAGE,
        false,
    )
    .await;
    let lines = session.expect("A1 ").await;
    let drafts = messages(&session, "Drafts");
    assert_eq!(drafts.len(), 1);
    let ok = position(&lines, "* OK [APPENDUID ");
    assert!(
        lines[ok].contains(&format!(" {}] ", drafts[0].uid)),
        "{lines:?}"
    );
    let expunge = position(&lines, "* 2 EXPUNGE");
    assert!(ok < expunge, "{lines:?}");
    assert!(
        !lines.iter().any(|line| line.contains("EXISTS")),
        "{lines:?}"
    );
    assert_eq!(lines.last().unwrap().trim_end(), "A1 OK REPLACE completed");

    assert_eq!(body(&drafts[0]), NEW_MESSAGE);
    assert!(
        drafts[0]
            .flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\Seen"))
    );
    assert!(
        drafts[0]
            .flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\Draft"))
    );
    assert_eq!(drafts[0].internaldate, 837_596_665);
    assert_eq!(drafts[0].internaldate_tz, -7 * 60);
    let inbox = messages(&session, "INBOX");
    assert_eq!(inbox.len(), 2);
    assert!(inbox.iter().all(|message| message.uid != old_uid));

    // The session's view was renumbered: sequence 2 is now the third message.
    let fetch = session.command("A2 FETCH 2 (UID)", "A2 OK").await;
    assert!(
        fetch[0].contains(&format!("UID {}", session.uids[2])),
        "{fetch:?}"
    );
    let noop = session.command("A3 NOOP", "A3 OK").await;
    assert_eq!(noop.len(), 1, "{noop:?}");
    session.finish().await;
}

#[tokio::test]
async fn uid_replace_in_selected_mailbox_reports_exists_then_expunge() {
    let mut session = selected_session(3).await;
    let old_uid = session.uids[0];
    send_with_literal(
        &mut session,
        &format!("A1 UID REPLACE {old_uid} INBOX (\\Flagged)"),
        NEW_MESSAGE,
        true,
    )
    .await;
    let lines = session.expect("A1 ").await;
    assert!(
        !lines.iter().any(|line| line.starts_with("+ ")),
        "{lines:?}"
    );
    let ok = position(&lines, "* OK [APPENDUID ");
    let exists = position(&lines, "* 4 EXISTS");
    let expunge = position(&lines, "* 1 EXPUNGE");
    assert!(ok < exists && exists < expunge, "{lines:?}");
    assert_eq!(
        lines.last().unwrap().trim_end(),
        "A1 OK UID REPLACE completed"
    );

    let inbox = messages(&session, "INBOX");
    assert_eq!(inbox.len(), 3);
    let new = inbox.iter().max_by_key(|message| message.uid).unwrap();
    assert!(new.uid > session.uids[2]);
    assert_eq!(body(new), NEW_MESSAGE);
    assert!(lines[ok].contains(&format!(" {}] ", new.uid)), "{lines:?}");

    let fetch = session.command("A2 FETCH 3 (UID FLAGS)", "A2 OK").await;
    assert!(fetch[0].contains(&format!("UID {}", new.uid)), "{fetch:?}");
    assert!(
        fetch[0].to_ascii_lowercase().contains("\\flagged"),
        "{fetch:?}"
    );
    let noop = session.command("A3 NOOP", "A3 OK").await;
    assert_eq!(noop.len(), 1, "{noop:?}");
    session.finish().await;
}

#[tokio::test]
async fn replace_reports_vanished_with_qresync() {
    let mut session = authenticated_session(2).await;
    session.command("E1 ENABLE QRESYNC", "E1 OK").await;
    session.command("S1 SELECT INBOX", "S1 OK").await;
    let old_uid = session.uids[1];
    send_with_literal(&mut session, "A1 REPLACE 2 Drafts", NEW_MESSAGE, true).await;
    let lines = session.expect("A1 ").await;
    assert!(
        lines
            .iter()
            .any(|line| line.trim_end() == format!("* VANISHED {old_uid}")),
        "{lines:?}"
    );
    assert!(
        !lines.iter().any(|line| line.contains("EXPUNGE")),
        "{lines:?}"
    );
    assert!(lines.last().unwrap().starts_with("A1 OK"), "{lines:?}");
    session.finish().await;
}

#[tokio::test]
async fn replace_under_uidonly_needs_uid_and_reports_vanished() {
    let mut session = authenticated_session(2).await;
    session.command("E1 ENABLE UIDONLY", "E1 OK").await;
    session.command("S1 SELECT INBOX", "S1 OK").await;
    let refused = session
        .command(
            &format!("A1 REPLACE 2 Drafts {{{}}}", NEW_MESSAGE.len()),
            "A1 ",
        )
        .await;
    assert!(
        refused.last().unwrap().starts_with("A1 BAD [UIDREQUIRED]"),
        "{refused:?}"
    );
    let old_uid = session.uids[1];
    send_with_literal(
        &mut session,
        &format!("A2 UID REPLACE {old_uid} Drafts"),
        NEW_MESSAGE,
        true,
    )
    .await;
    let lines = session.expect("A2 ").await;
    assert!(
        lines
            .iter()
            .any(|line| line.trim_end() == format!("* VANISHED {old_uid}")),
        "{lines:?}"
    );
    assert!(
        !lines.iter().any(|line| line.contains("EXPUNGE")),
        "{lines:?}"
    );
    assert!(lines.last().unwrap().starts_with("A2 OK"), "{lines:?}");
    session.finish().await;
}

#[tokio::test]
async fn replace_supports_literal8_utf8_and_catenate() {
    let mut session = authenticated_session(2).await;
    session.command("E1 ENABLE UTF8=ACCEPT", "E1 OK").await;
    session.command("S1 SELECT INBOX", "S1 OK").await;

    let utf8 = "Subject: caf\u{e9}\r\n\r\nbody\r\n".as_bytes();
    // Same framing as APPEND's UTF8 data extension.
    let mut bytes = format!("A1 REPLACE 1 Drafts UTF8 (~{{{}+}})\r\n", utf8.len()).into_bytes();
    bytes.extend_from_slice(utf8);
    bytes.extend_from_slice(b"\r\n");
    session.send(&bytes).await;
    let lines = session.expect("A1 ").await;
    assert!(lines.last().unwrap().starts_with("A1 OK"), "{lines:?}");
    assert_eq!(body(&messages(&session, "Drafts")[0]), utf8);

    // CATENATE: prepend a header to the remaining INBOX message.
    let source_uid = session.uids[1];
    let header = b"X-Prefix: yes\r\n";
    let mut bytes =
        format!("A2 REPLACE 1 Sent CATENATE (TEXT {{{}+}}\r\n", header.len()).into_bytes();
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(format!(" URL \"/INBOX/;UID={source_uid}\")\r\n").as_bytes());
    session.send(&bytes).await;
    let lines = session.expect("A2 ").await;
    assert!(lines.last().unwrap().starts_with("A2 OK"), "{lines:?}");
    assert!(lines.iter().any(|line| line.starts_with("* 1 EXPUNGE")));
    let sent = messages(&session, "Sent");
    let content = body(&sent[0]);
    assert!(content.starts_with(header));
    assert!(content.ends_with(b"body 1\r\n"));
    assert!(messages(&session, "INBOX").is_empty());
    session.finish().await;
}

#[tokio::test]
async fn failed_replace_keeps_the_old_message() {
    let mut session = selected_session(2).await;

    // Missing target: refused before the literal is requested.
    let lines = session
        .command(
            &format!("A1 REPLACE 1 Missing {{{}}}", NEW_MESSAGE.len()),
            "A1 ",
        )
        .await;
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].starts_with("A1 NO [TRYCREATE]"), "{lines:?}");

    // A non-synchronizing literal is skipped so the next command is intact.
    send_with_literal(&mut session, "A2 REPLACE 1 Missing", NEW_MESSAGE, true).await;
    let lines = session.expect("A2 ").await;
    assert!(
        lines.last().unwrap().starts_with("A2 NO [TRYCREATE]"),
        "{lines:?}"
    );
    session.command("A3 NOOP", "A3 OK").await;

    // Sequence numbers must exist; UIDs that do not get NO.
    let lines = session
        .command(
            &format!("A4 REPLACE 9 Drafts {{{}}}", NEW_MESSAGE.len()),
            "A4 ",
        )
        .await;
    assert!(lines[0].starts_with("A4 BAD"), "{lines:?}");
    send_with_literal(&mut session, "A5 UID REPLACE 999 Drafts", NEW_MESSAGE, true).await;
    let lines = session.expect("A5 ").await;
    assert!(lines.last().unwrap().starts_with("A5 NO"), "{lines:?}");
    session.command("A6 NOOP", "A6 OK").await;

    // Malformed arguments and MULTIAPPEND-style extra messages.
    let lines = session.command("A7 REPLACE 1:2 Drafts {3}", "A7 ").await;
    assert!(lines[0].starts_with("A7 BAD"), "{lines:?}");
    let lines = session.command("A8 REPLACE 1 Drafts", "A8 ").await;
    assert!(lines[0].starts_with("A8 BAD"), "{lines:?}");
    session
        .send(b"A9 REPLACE 1 Drafts {3+}\r\nabc (\\Seen) {3}\r\n")
        .await;
    let lines = session.expect("A9 ").await;
    assert!(lines.last().unwrap().starts_with("A9 BAD"), "{lines:?}");

    // Too large for APPENDLIMIT.
    let lines = session
        .command(
            &format!(
                "A10 REPLACE 1 Drafts {{{}}}",
                crate::MAX_APPEND_LITERAL_BYTES + 1
            ),
            "A10 ",
        )
        .await;
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].starts_with("A10 NO [TOOBIG]"), "{lines:?}");

    session.command("A11 NOOP", "A11 OK").await;
    assert_eq!(messages(&session, "INBOX").len(), 2);
    assert!(messages(&session, "Drafts").is_empty());
    session.finish().await;
}

#[tokio::test]
async fn replace_is_refused_in_a_read_only_mailbox() {
    let mut session = authenticated_session(1).await;
    session.command("S1 EXAMINE INBOX", "S1 OK").await;
    send_with_literal(&mut session, "A1 REPLACE 1 Drafts", NEW_MESSAGE, true).await;
    let lines = session.expect("A1 ").await;
    assert!(lines.last().unwrap().starts_with("A1 NO"), "{lines:?}");
    session.command("A2 NOOP", "A2 OK").await;
    assert_eq!(messages(&session, "INBOX").len(), 1);
    assert!(messages(&session, "Drafts").is_empty());

    // REPLACE needs a selected mailbox.
    session.command("U1 UNSELECT", "U1 OK").await;
    let lines = session.command("A3 REPLACE 1 Drafts {3}", "A3 ").await;
    assert!(lines[0].starts_with("A3 BAD"), "{lines:?}");
    session.finish().await;
}
