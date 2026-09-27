//! Mailbox synchronization: when EXPUNGE/EXISTS/FETCH updates may be sent
//! (RFC 3501 §7.4.1, RFC 9051 §7.5.1) and CONDSTORE MODSEQ reporting
//! (RFC 7162 §3.1).

use super::*;
use std::path::PathBuf;

pub(super) struct Fixture {
    _dir: tempfile::TempDir,
    pub(super) mail_root: PathBuf,
    pub(super) uids: Vec<u64>,
    reader: BufReader<tokio::io::DuplexStream>,
    server: tokio::task::JoinHandle<anyhow::Result<()>>,
}

pub(super) async fn selected_session(messages: usize) -> Fixture {
    let mut fixture = authenticated_session(messages).await;
    fixture.command("S1 SELECT INBOX", "S1 OK").await;
    fixture
}

/// A logged-in session (no mailbox selected) with `messages` in INBOX.
pub(super) async fn authenticated_session(messages: usize) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let mail_root = dir.path().join("mail");
    let db_path = dir.path().join("config.db");
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
    for index in 0..messages {
        let (_, uid) = rmail_common::imap_state::append_message(
            &mail_root,
            "example.test",
            "user",
            "INBOX",
            format!("From: a@example.test\r\nSubject: message {index}\r\n\r\nbody {index}\r\n")
                .as_bytes(),
            vec![],
        )
        .expect("append");
        uids.push(uid);
    }
    let server_root = mail_root.to_string_lossy().to_string();
    let (client, server) = duplex(64 * 1024);
    let server = tokio::spawn(async move {
        process_stream(
            Box::new(server),
            server_root,
            None::<Arc<crate::tls::TlsContext>>,
            Some(db_path.to_string_lossy().to_string()),
            None,
            true,
        )
        .await
    });
    let mut reader = BufReader::new(client);
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("greeting");
    line.clear();
    reader.read_line(&mut line).await.expect("capability");
    let mut fixture = Fixture {
        _dir: dir,
        mail_root,
        uids,
        reader,
        server,
    };
    fixture
        .command("L1 LOGIN \"user@example.test\" \"password\"", "L1 OK")
        .await;
    fixture
}

impl Fixture {
    pub(super) async fn command(&mut self, command: &str, done: &str) -> Vec<String> {
        self.reader
            .get_mut()
            .write_all(format!("{command}\r\n").as_bytes())
            .await
            .expect("write command");
        self.reader.get_mut().flush().await.expect("flush");
        read_until_contains_bounded(&mut self.reader, done).await
    }

    /// Read unsolicited responses until one contains `needle`.
    pub(super) async fn expect(&mut self, needle: &str) -> Vec<String> {
        read_until_contains_bounded(&mut self.reader, needle).await
    }

    /// Deliver a message as the MTA does, so it is \Recent.
    pub(super) fn deliver_recent(&mut self) {
        let (_, uid) = rmail_common::imap_state::deliver_message(
            &self.mail_root,
            "example.test",
            "user",
            b"Subject: delivered\r\n\r\nbody\r\n",
        )
        .expect("deliver");
        self.uids.push(uid);
    }

    pub(super) fn expunge_elsewhere(&self, uid: u64) {
        rmail_common::imap_state::delete_message_by_uid(
            &self.mail_root,
            "example.test",
            "user",
            "INBOX",
            uid,
        )
        .expect("external expunge");
    }

    pub(super) fn flags(&self, uid: u64) -> Vec<String> {
        rmail_common::imap_state::load_folder(&self.mail_root, "example.test", "user", "INBOX")
            .expect("load folder")
            .1
            .into_iter()
            .find(|message| message.uid == uid)
            .map(|message| message.flags)
            .unwrap_or_default()
    }

    pub(super) async fn finish(mut self) {
        self.command("Z LOGOUT", "Z OK").await;
        self.server.await.expect("join").expect("server");
    }
}

#[tokio::test]
async fn sequence_commands_do_not_report_expunges_or_renumber() {
    let mut session = selected_session(3).await;
    let uids = session.uids.clone();
    session.expunge_elsewhere(uids[0]);

    // Sequence number 2 still refers to the second message the client saw.
    let store = session
        .command("A1 STORE 2 +FLAGS (\\Flagged)", "A1 ")
        .await;
    assert!(
        !store
            .iter()
            .any(|line| line.trim_end().ends_with(" EXPUNGE")),
        "{store:?}"
    );
    assert!(
        store
            .iter()
            .any(|line| line.starts_with("* 2 FETCH") && line.contains(&format!("UID {}", uids[1]))),
        "{store:?}"
    );
    assert!(store.last().unwrap().starts_with("A1 OK"), "{store:?}");
    assert!(
        session
            .flags(uids[1])
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\Flagged"))
    );
    assert!(session.flags(uids[2]).is_empty());

    for (tag, command) in [
        ("A2", "SEARCH ALL"),
        ("A3", "FETCH 1:3 (UID)"),
        ("A4", "SORT (ARRIVAL) UTF-8 ALL"),
        ("A5", "THREAD REFERENCES UTF-8 ALL"),
    ] {
        let lines = session
            .command(&format!("{tag} {command}"), &format!("{tag} "))
            .await;
        assert!(
            !lines
                .iter()
                .any(|line| line.trim_end().ends_with(" EXPUNGE") || line.starts_with("* VANISHED")),
            "{command}: {lines:?}"
        );
        if tag == "A2" {
            // The expunged message keeps its slot but no longer matches.
            assert!(lines.iter().any(|line| line.trim_end() == "* SEARCH 2 3"));
        }
        if tag == "A3" {
            assert!(
                lines.iter().any(|line| line.starts_with("* 2 FETCH (UID ")),
                "{lines:?}"
            );
            assert!(!lines.iter().any(|line| line.starts_with("* 1 FETCH")));
            assert!(
                lines.last().unwrap().starts_with("A3 NO [EXPUNGEISSUED]"),
                "{lines:?}"
            );
        }
    }

    // COPY of an expunged message fails as a whole.
    session.command("C0 CREATE Kept", "C0 ").await;
    let copy = session.command("C1 COPY 1:2 Kept", "C1 ").await;
    assert!(
        copy.last().unwrap().starts_with("C1 NO [EXPUNGEISSUED]"),
        "{copy:?}"
    );

    // NOOP may report the expunge; afterwards numbering follows storage.
    let noop = session.command("A6 NOOP", "A6 OK").await;
    assert!(noop.iter().any(|line| line.trim_end() == "* 1 EXPUNGE"));
    assert!(!noop.iter().any(|line| line.contains("EXISTS")), "{noop:?}");
    let fetch = session.command("A7 FETCH 1 (UID)", "A7 OK").await;
    assert!(
        fetch
            .iter()
            .any(|line| line.trim_end() == format!("* 1 FETCH (UID {})", uids[1]))
    );
    session.finish().await;
}

#[tokio::test]
async fn uid_commands_report_pending_expunges_first() {
    let mut session = selected_session(2).await;
    let uids = session.uids.clone();
    session.expunge_elsewhere(uids[0]);
    let fetch = session.command("A1 FETCH 1:* (UID)", "A1 ").await;
    assert!(
        !fetch
            .iter()
            .any(|line| line.trim_end().ends_with(" EXPUNGE"))
    );
    let uid_fetch = session.command("A2 UID FETCH 1:* (FLAGS)", "A2 OK").await;
    assert_eq!(uid_fetch[0].trim_end(), "* 1 EXPUNGE", "{uid_fetch:?}");
    assert!(
        uid_fetch
            .iter()
            .any(|line| line.starts_with("* 1 FETCH") && line.contains(&format!("UID {}", uids[1])))
    );
    session.finish().await;
}

#[tokio::test]
async fn exists_is_sent_when_arrivals_cancel_out_expunges() {
    let mut session = selected_session(2).await;
    let uids = session.uids.clone();
    session.expunge_elsewhere(uids[0]);
    rmail_common::imap_state::append_message(
        &session.mail_root,
        "example.test",
        "user",
        "INBOX",
        b"Subject: new\r\n\r\nnew\r\n",
        vec![],
    )
    .expect("append");
    let noop = session.command("A1 NOOP", "A1 OK").await;
    let expunge = noop
        .iter()
        .position(|line| line.trim_end() == "* 1 EXPUNGE")
        .expect("expunge");
    let exists = noop
        .iter()
        .position(|line| line.trim_end() == "* 2 EXISTS")
        .expect("exists");
    assert!(expunge < exists, "{noop:?}");
    session.finish().await;
}

#[tokio::test]
async fn arrivals_during_sequence_commands_are_counted_with_pending_expunges() {
    let mut session = selected_session(2).await;
    let uids = session.uids.clone();
    session.expunge_elsewhere(uids[0]);
    rmail_common::imap_state::append_message(
        &session.mail_root,
        "example.test",
        "user",
        "INBOX",
        b"Subject: new\r\n\r\nnew\r\n",
        vec![],
    )
    .expect("append");
    // The pending expunge keeps its slot, so the client now sees 3.
    let fetch = session.command("A1 FETCH 3 (UID)", "A1 OK").await;
    assert!(fetch.iter().any(|line| line.trim_end() == "* 3 EXISTS"));
    let noop = session.command("A2 NOOP", "A2 OK").await;
    assert!(noop.iter().any(|line| line.trim_end() == "* 1 EXPUNGE"));
    assert!(!noop.iter().any(|line| line.contains("EXISTS")), "{noop:?}");
    session.finish().await;
}

#[tokio::test]
async fn condstore_adds_modseq_to_every_untagged_fetch() {
    let mut session = selected_session(2).await;
    let uids = session.uids.clone();

    // Before CONDSTORE: implicit \Seen is reported with FLAGS, no MODSEQ.
    let fetch = session.command("A1 FETCH 1 (BODY[TEXT])", "A1 OK").await;
    let line = fetch
        .iter()
        .find(|line| line.starts_with("* 1 FETCH"))
        .expect("fetch");
    assert!(line.contains("FLAGS (\\Seen)"), "{line}");
    assert!(!line.contains("MODSEQ"), "{line}");

    session.command("A2 ENABLE CONDSTORE", "A2 OK").await;
    let fetch = session.command("A3 FETCH 2 (BODY[TEXT])", "A3 OK").await;
    let line = fetch
        .iter()
        .find(|line| line.starts_with("* 2 FETCH"))
        .expect("fetch");
    assert!(line.contains("FLAGS (\\Seen)"), "{line}");
    assert!(line.contains("MODSEQ ("), "{line}");
    assert!(line.contains(&format!("UID {}", uids[1])), "{line}");

    // Flag changes made elsewhere carry MODSEQ too.
    rmail_common::imap_state::set_uid_flags(
        &session.mail_root,
        "example.test",
        "user",
        "INBOX",
        uids[0],
        vec!["\\Flagged".to_string()],
    )
    .expect("set flags");
    let noop = session.command("A4 NOOP", "A4 OK").await;
    let line = noop
        .iter()
        .find(|line| line.starts_with("* 1 FETCH"))
        .expect("flag update");
    assert!(line.contains("FLAGS (\\Flagged)"), "{line}");
    assert!(line.contains("MODSEQ ("), "{line}");

    // So do responses to STORE, even .SILENT ones.
    let store = session
        .command("A5 STORE 1 +FLAGS.SILENT (\\Answered)", "A5 OK")
        .await;
    assert!(
        store
            .iter()
            .any(|line| line.starts_with("* 1 FETCH (UID ") && line.contains("MODSEQ (")),
        "{store:?}"
    );
    session.finish().await;
}

#[tokio::test]
async fn condstore_enabling_fetch_activates_modseq_reporting() {
    let mut session = selected_session(1).await;
    let uid = session.uids[0];
    session.command("A1 FETCH 1 (MODSEQ)", "A1 OK").await;
    rmail_common::imap_state::set_uid_flags(
        &session.mail_root,
        "example.test",
        "user",
        "INBOX",
        uid,
        vec!["\\Seen".to_string()],
    )
    .expect("set flags");
    let noop = session.command("A2 NOOP", "A2 OK").await;
    assert!(
        noop.iter()
            .any(|line| line.starts_with("* 1 FETCH") && line.contains("MODSEQ (")),
        "{noop:?}"
    );
    session.finish().await;
}
