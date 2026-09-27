//! Scripted transcripts from real clients.

use super::*;

#[tokio::test]
async fn scripted_thunderbird_compatibility_fixture_completes() {
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
            b"Date: Sun, 14 Jun 2026 12:00:00 +0000\r\nFrom: alice@example.test\r\nTo: user@example.test\r\nSubject: one\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nfirst body\r\n",
        )
        .expect("deliver first");
    rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Date: Mon, 15 Jun 2026 12:00:00 +0000\r\nFrom: bob@example.test\r\nTo: user@example.test\r\nSubject: two\r\nContent-Type: multipart/alternative; boundary=\"alt\"\r\n\r\n--alt\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nsecond plain\r\n--alt\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<p>second html</p>\r\n--alt--\r\n",
        )
        .expect("deliver second");

    let (client, server) = duplex(128 * 1024);
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

    run_scripted_fixture(
        &mut reader,
        include_str!("../../fixtures/thunderbird_compat.imap"),
    )
    .await;

    server_task.await.expect("join").expect("server");
}
#[tokio::test]
async fn scripted_evolution_compatibility_fixture_completes() {
    run_compatibility_fixture(include_str!("../../fixtures/evolution_compat.imap")).await;
}
#[tokio::test]
async fn scripted_geary_compatibility_fixture_completes() {
    run_compatibility_fixture(include_str!("../../fixtures/geary_compat.imap")).await;
}
#[tokio::test]
async fn scripted_mailspring_compatibility_fixture_completes() {
    run_compatibility_fixture(include_str!("../../fixtures/mailspring_compat.imap")).await;
}
