//! Inactivity autologout (RFC 3501 §5.4) and the IDLE time limit.

use super::*;
use crate::auth::{AuthPolicy, SessionTimeouts};
use std::time::Duration;

async fn start(
    timeouts: SessionTimeouts,
) -> (
    tempfile::TempDir,
    BufReader<tokio::io::DuplexStream>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
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
    let (client, server) = duplex(32 * 1024);
    let policy = Arc::new(AuthPolicy::default().with_timeouts(timeouts));
    let task = tokio::spawn(async move {
        process_stream_with_policy(
            Box::new(server),
            mail_root.to_string_lossy().to_string(),
            None::<Arc<crate::tls::TlsContext>>,
            Some(db_path.to_string_lossy().to_string()),
            None,
            true,
            policy,
        )
        .await
    });
    let mut reader = BufReader::new(client);
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("greeting");
    line.clear();
    reader.read_line(&mut line).await.expect("capability");
    (dir, reader, task)
}

async fn expect_bye_and_close(
    reader: &mut BufReader<tokio::io::DuplexStream>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let lines = read_until_contains_bounded(reader, "* BYE").await;
    assert_eq!(
        lines.last().unwrap().trim_end(),
        "* BYE Autologout; idle for too long"
    );
    let mut rest = String::new();
    let read = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut rest))
        .await
        .expect("connection closes");
    assert_eq!(read.expect("read"), 0, "unexpected data: {rest:?}");
    task.await.expect("join").expect("server");
}

#[test]
fn default_authenticated_autologout_is_at_least_thirty_minutes() {
    let timeouts = SessionTimeouts::default();
    assert!(timeouts.authenticated >= Duration::from_secs(30 * 60));
    assert!(timeouts.idle >= Duration::from_secs(29 * 60));
    assert!(timeouts.unauthenticated < timeouts.authenticated);
}

#[tokio::test]
async fn unauthenticated_sessions_are_logged_out_when_idle() {
    let (_dir, mut reader, task) = start(SessionTimeouts {
        unauthenticated: Duration::from_millis(200),
        authenticated: Duration::from_secs(60),
        idle: Duration::from_secs(60),
    })
    .await;
    expect_bye_and_close(&mut reader, task).await;
}

#[tokio::test]
async fn authenticated_sessions_use_their_own_timer() {
    let (_dir, mut reader, task) = start(SessionTimeouts {
        unauthenticated: Duration::from_millis(400),
        authenticated: Duration::from_millis(1200),
        idle: Duration::from_secs(60),
    })
    .await;
    reader
        .get_mut()
        .write_all(b"A1 LOGIN \"user@example.test\" \"password\"\r\n")
        .await
        .unwrap();
    read_until_contains_bounded(&mut reader, "A1 OK").await;
    // Longer than the unauthenticated limit, shorter than the other.
    tokio::time::sleep(Duration::from_millis(600)).await;
    reader.get_mut().write_all(b"A2 NOOP\r\n").await.unwrap();
    read_until_contains_bounded(&mut reader, "A2 OK").await;
    expect_bye_and_close(&mut reader, task).await;
}

#[tokio::test]
async fn idle_ends_with_bye_after_the_idle_limit() {
    let (_dir, mut reader, task) = start(SessionTimeouts {
        unauthenticated: Duration::from_secs(60),
        authenticated: Duration::from_secs(60),
        idle: Duration::from_millis(1500),
    })
    .await;
    reader
        .get_mut()
        .write_all(b"A1 LOGIN \"user@example.test\" \"password\"\r\nA2 SELECT INBOX\r\nA3 IDLE\r\n")
        .await
        .unwrap();
    read_until_contains_bounded(&mut reader, "A2 OK").await;
    read_until_contains_bounded(&mut reader, "+ idling").await;
    expect_bye_and_close(&mut reader, task).await;
}
