use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use once_cell::sync::Lazy;
use rand::RngCore;
use rmail_common::db::Mailbox;
use rmail_common::{auth, config::Config, maildir, net::bind_tcp_listener};
use std::path::Path;
use std::time::{Duration, Instant};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

mod tls;
use tls::load_tls_context;

// Trait object helper: combine AsyncRead + AsyncWrite into a single object-safe trait and require Unpin
// so that boxed trait objects can be used with tokio::io::BufReader.
trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized> AsyncStream for T {}

// Simple in-memory rate-limiter for authentication failures keyed by remote IP. This is a
// best-effort defensive measure; for multi-process deployments a shared store (Redis, etc.)
// should be used instead.
#[derive(Clone)]
struct AuthFailInfo {
    count: u32,
    first: Instant,
    locked_until: Option<Instant>,
}

static AUTH_FAILS: Lazy<Mutex<HashMap<IpAddr, AuthFailInfo>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Check whether the remote IP is currently blocked from authenticating. Returns remaining block Duration if blocked.
fn auth_block_remaining(ip: IpAddr) -> Option<Duration> {
    let m = AUTH_FAILS.lock().unwrap();
    if let Some(info) = m.get(&ip) {
        if let Some(until) = info.locked_until {
            let now = Instant::now();
            if until > now {
                return Some(until - now);
            }
        }
    }
    None
}

/// Record a failed auth attempt for the IP and apply a temporary lockout if threshold exceeded.
fn record_auth_failure(ip: IpAddr) {
    let mut m = AUTH_FAILS.lock().unwrap();
    let now = Instant::now();
    let entry = m.entry(ip).or_insert(AuthFailInfo {
        count: 0,
        first: now,
        locked_until: None,
    });
    entry.count = entry.count.saturating_add(1);
    // Increment global metric for monitoring
    rmail_common::metrics::inc_auth_failures();
    // if 5 failures within short window, lock for 30 minutes
    if entry.count >= 5 {
        entry.locked_until = Some(now + Duration::from_secs(30 * 60));
        entry.count = 0;
        entry.first = now;
    }
}

/// Reset any recorded failures for this IP (on successful authentication)
fn reset_auth_failures(ip: IpAddr) {
    let mut m = AUTH_FAILS.lock().unwrap();
    m.remove(&ip);
}

/// SelectedMailbox holds state for the currently selected mailbox in an IMAP session.
/// It maintains the mailbox domain/localpart, the persistent UIDVALIDITY value, and an
/// ordered Vec of (UID, PathBuf) where the order corresponds to IMAP sequence numbers.
/// This lightweight structure is recomputed on SELECT and reused for subsequent FETCH/UID commands
/// during the session to provide stable UIDs and predictable sequence numbers.
#[allow(dead_code)]
struct SelectedMailbox {
    pub domain: String,
    pub local: String,
    pub mailbox: String,
    pub uidvalidity: u64,
    pub uidnext: u64,
    pub msgs: Vec<(u64, std::path::PathBuf, Vec<String>)>,
}

async fn load_selected_mailbox(
    mail_root: &str,
    address: &str,
    mailbox: &str,
) -> Result<SelectedMailbox> {
    let at = address
        .find('@')
        .ok_or_else(|| anyhow::anyhow!("invalid mailbox address"))?;
    let local = address[..at].to_string();
    let domain = address[at + 1..].to_string();
    let mail_root = mail_root.to_string();
    let domain_c = domain.clone();
    let local_c = local.clone();
    let mailbox = maildir::normalize_mailbox_name(mailbox)?;
    match tokio::task::spawn_blocking(move || {
        let (folder, state_msgs) = rmail_common::imap_state::load_folder(
            std::path::Path::new(&mail_root),
            &domain_c,
            &local_c,
            &mailbox,
        )?;
        let msgs = state_msgs
            .into_iter()
            .map(|message| (message.uid, message.path, message.flags))
            .collect();
        Ok(SelectedMailbox {
            domain: domain_c,
            local: local_c,
            mailbox,
            uidvalidity: folder.uidvalidity,
            uidnext: folder.uidnext,
            msgs,
        })
    })
    .await
    {
        Ok(Ok(sel)) => Ok(sel),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(anyhow::anyhow!("task join error: {}", e)),
    }
}

async fn expunge_deleted(mail_root: &str, selected: &SelectedMailbox) -> Result<Vec<(usize, u64)>> {
    let mut deleted: Vec<(usize, u64)> = selected
        .msgs
        .iter()
        .enumerate()
        .filter_map(|(idx, (uid, _, flags))| {
            flags
                .iter()
                .any(|f| f.eq_ignore_ascii_case("\\Deleted"))
                .then_some((idx + 1, *uid))
        })
        .collect();
    deleted.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, uid) in &deleted {
        let mail_root = mail_root.to_string();
        let domain = selected.domain.clone();
        let local = selected.local.clone();
        let mailbox = selected.mailbox.clone();
        let uid = *uid;
        tokio::task::spawn_blocking(move || {
            maildir::delete_message_by_uid_for_mailbox(
                Path::new(&mail_root),
                &domain,
                &local,
                &mailbox,
                uid,
            )
        })
        .await??;
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::process_stream;
    use crate::capability_tokens;
    use base64::Engine;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, duplex};

    async fn read_until_contains(
        reader: &mut BufReader<tokio::io::DuplexStream>,
        needle: &str,
    ) -> Vec<String> {
        let mut out = Vec::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read line");
            if line.is_empty() {
                break;
            }
            out.push(line.clone());
            if line.contains(needle) {
                return out;
            }
        }
        out
    }

    async fn run_scripted_fixture(reader: &mut BufReader<tokio::io::DuplexStream>, fixture: &str) {
        for raw_line in fixture.lines() {
            let line = raw_line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(command) = line.strip_prefix("C: ") {
                reader
                    .get_mut()
                    .write_all(format!("{}\r\n", command).as_bytes())
                    .await
                    .expect("write fixture command");
                reader.get_mut().flush().await.expect("flush fixture");
            } else if let Some(expected) = line.strip_prefix("S: ") {
                let lines = read_until_contains(reader, expected).await;
                assert!(
                    lines.iter().any(|line| line.contains(expected)),
                    "expected fixture response containing {expected:?}, got {lines:?}"
                );
            } else {
                panic!("invalid fixture line: {line}");
            }
        }
    }

    #[tokio::test]
    async fn fetch_refreshes_after_new_delivery() {
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
        .expect("deliver first");

        let (client, server) = duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
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

        reader
            .get_mut()
            .write_all(b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\n")
            .await
            .expect("write login/select");
        reader.get_mut().flush().await.expect("flush");

        let select_lines = read_until_contains(&mut reader, "A002 OK").await;
        assert!(select_lines.iter().any(|l| l.contains("* 1 EXISTS")));

        rmail_common::maildir::deliver(
            td.path().join("mail").as_path(),
            "example.test",
            "user",
            b"Subject: two\r\n\r\nsecond\r\n",
        )
        .expect("deliver second");

        reader
            .get_mut()
            .write_all(b"A003 FETCH 1:* RFC822\r\nA004 LOGOUT\r\n")
            .await
            .expect("write fetch");
        reader.get_mut().flush().await.expect("flush");

        let fetch_lines = read_until_contains(&mut reader, "A003 OK").await;
        let fetched = fetch_lines
            .iter()
            .filter(|l| l.starts_with("* ") && l.contains(" FETCH "))
            .count();
        assert_eq!(fetched, 2);

        let logout_lines = read_until_contains(&mut reader, "A004 OK").await;
        assert!(logout_lines.iter().any(|l| l.starts_with("* BYE")));

        server_task.await.expect("join").expect("server");
    }

    #[test]
    fn capability_advertises_starttls_and_login_policy() {
        let plain_caps = capability_tokens(false, None);
        assert!(plain_caps.contains("LOGINDISABLED"));
        assert!(!plain_caps.contains("AUTH=PLAIN"));
        assert!(!plain_caps.contains("AUTH=SCRAM-SHA-256"));
        assert!(!plain_caps.contains("STARTTLS"));
        assert!(!plain_caps.contains("CONDSTORE"));
        assert!(!plain_caps.contains("QRESYNC"));
        assert!(!plain_caps.contains("COMPRESS=DEFLATE"));

        let tls_caps = capability_tokens(true, None);
        assert!(!tls_caps.contains("LOGINDISABLED"));
        assert!(tls_caps.contains("AUTH=PLAIN"));
        assert!(tls_caps.contains("AUTH=SCRAM-SHA-256"));
        assert!(!tls_caps.contains("STARTTLS"));
        assert!(!tls_caps.contains("CONDSTORE"));
        assert!(!tls_caps.contains("QRESYNC"));
        assert!(!tls_caps.contains("COMPRESS=DEFLATE"));
    }

    #[test]
    fn unsupported_log_selected_mailbox_placeholder_is_stable() {
        assert_eq!(super::selected_mailbox_for_log(&None), "-");
    }

    #[tokio::test]
    async fn authenticate_plain_is_tls_only_and_logs_in() {
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

        let payload = crate::BASE64_ENGINE.encode(b"\0user@example.test\0password");
        let (client, server) = duplex(32 * 1024);
        let encrypted_mail_root = mail_root.clone();
        let encrypted_db_path = db_path.clone();
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                encrypted_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(encrypted_db_path.to_string_lossy().to_string()),
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
        assert!(capability.contains("AUTH=PLAIN"));
        reader
            .get_mut()
            .write_all(
                format!(
                    "A001 AUTHENTICATE PLAIN {}\r\nA002 SELECT INBOX\r\nA003 LOGOUT\r\n",
                    payload
                )
                .as_bytes(),
            )
            .await
            .expect("write encrypted auth commands");
        reader.get_mut().flush().await.expect("flush");
        let auth_lines = read_until_contains(&mut reader, "A001 OK").await;
        assert!(
            auth_lines
                .iter()
                .any(|l| l.contains("AUTHENTICATE completed"))
        );
        let select_lines = read_until_contains(&mut reader, "A002 OK").await;
        assert!(select_lines.iter().any(|l| l.contains("SELECT completed")));
        let _logout = read_until_contains(&mut reader, "A003 OK").await;
        server_task.await.expect("join").expect("server");

        let (client, server) = duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
                Some(db_path.to_string_lossy().to_string()),
                None,
                false,
            )
            .await
        });
        let mut reader = BufReader::new(client);
        let mut greeting = String::new();
        reader
            .read_line(&mut greeting)
            .await
            .expect("plain greeting");
        let mut capability = String::new();
        reader
            .read_line(&mut capability)
            .await
            .expect("plain capability");
        assert!(!capability.contains("AUTH=PLAIN"));
        reader
            .get_mut()
            .write_all(format!("A001 AUTHENTICATE PLAIN {}\r\nA002 LOGOUT\r\n", payload).as_bytes())
            .await
            .expect("write plain auth commands");
        reader.get_mut().flush().await.expect("flush");
        let auth_lines = read_until_contains(&mut reader, "A001 NO").await;
        assert!(auth_lines.iter().any(|l| l.contains("Encryption required")));
        let _logout = read_until_contains(&mut reader, "A002 OK").await;
        server_task.await.expect("join").expect("plain server");
    }

    fn scram_client_final(password: &str, client_first_bare: &str, server_first: &str) -> String {
        use hmac::Mac;
        use hmac::digest::KeyInit;
        use pbkdf2::pbkdf2;
        use sha2::{Digest, Sha256};

        type HmacSha256 = hmac::Hmac<Sha256>;

        let salt_b64 = super::parse_scram_attr(server_first, "s=").expect("salt");
        let iterations = super::parse_scram_attr(server_first, "i=")
            .expect("iterations")
            .parse::<u32>()
            .expect("parse iterations");
        let nonce = super::parse_scram_attr(server_first, "r=").expect("nonce");
        let salt = crate::BASE64_ENGINE.decode(salt_b64).expect("decode salt");
        let gs2_header_b64 = crate::BASE64_ENGINE.encode(b"n,,");
        let client_final_without_proof = format!("c={},r={}", gs2_header_b64, nonce);
        let auth_message = format!(
            "{},{},{}",
            client_first_bare, server_first, client_final_without_proof
        );

        let mut salted_password = [0u8; 32];
        pbkdf2::<HmacSha256>(password.as_bytes(), &salt, iterations, &mut salted_password)
            .expect("derive salted password");
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&salted_password).unwrap();
        mac.update(b"Client Key");
        let client_key = mac.finalize().into_bytes();
        let stored_key = Sha256::digest(&client_key);
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&stored_key).unwrap();
        mac.update(auth_message.as_bytes());
        let client_signature = mac.finalize().into_bytes();
        let proof = client_key
            .iter()
            .zip(client_signature.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<_>>();
        format!(
            "{},p={}",
            client_final_without_proof,
            crate::BASE64_ENGINE.encode(proof)
        )
    }

    #[tokio::test]
    async fn authenticate_scram_sha256_logs_in_with_real_proof() {
        let td = tempfile::tempdir().expect("tempdir");
        let mail_root = td.path().join("mail");
        let db_path = td.path().join("config.db");
        let scram = rmail_common::auth::create_scram_verifier("password", 4096)
            .expect("create scram verifier");
        rmail_common::db::init_db(&db_path).expect("init db");
        rmail_common::db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:password"),
            None,
            Some(&scram),
        )
        .expect("add mailbox");

        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
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
        assert!(capability.contains("AUTH=SCRAM-SHA-256"));

        let client_first_bare = "n=user@example.test,r=clientnonce";
        let client_first = format!("n,,{}", client_first_bare);
        let client_first_b64 = crate::BASE64_ENGINE.encode(client_first.as_bytes());
        reader
            .get_mut()
            .write_all(
                format!("A001 AUTHENTICATE SCRAM-SHA-256 {}\r\n", client_first_b64).as_bytes(),
            )
            .await
            .expect("write client first");
        reader.get_mut().flush().await.expect("flush");

        let server_first_lines = read_until_contains(&mut reader, "+ ").await;
        let server_first_line = server_first_lines
            .iter()
            .find(|line| line.starts_with("+ "))
            .expect("server first")
            .trim();
        let server_first_b64 = server_first_line.trim_start_matches("+ ").trim();
        let server_first = String::from_utf8(
            crate::BASE64_ENGINE
                .decode(server_first_b64)
                .expect("decode server first"),
        )
        .expect("server first utf8");
        let client_final = scram_client_final("password", client_first_bare, &server_first);
        reader
            .get_mut()
            .write_all(format!("{}\r\n", crate::BASE64_ENGINE.encode(client_final)).as_bytes())
            .await
            .expect("write client final");
        reader.get_mut().flush().await.expect("flush");

        let server_final_lines = read_until_contains(&mut reader, "+ ").await;
        assert!(
            server_final_lines
                .iter()
                .any(|line| line.starts_with("+ ") && line.contains('='))
        );
        reader
            .get_mut()
            .write_all(b"\r\nA002 SELECT INBOX\r\nA003 LOGOUT\r\n")
            .await
            .expect("finish scram and write commands");
        reader.get_mut().flush().await.expect("flush");

        let auth_lines = read_until_contains(&mut reader, "A001 OK").await;
        assert!(
            auth_lines
                .iter()
                .any(|line| line.contains("AUTHENTICATE completed"))
        );
        let select_lines = read_until_contains(&mut reader, "A002 OK").await;
        assert!(
            select_lines
                .iter()
                .any(|line| line.contains("SELECT completed"))
        );
        let _logout = read_until_contains(&mut reader, "A003 OK").await;

        server_task.await.expect("join").expect("server");
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
                None::<Arc<super::tls::TlsContext>>,
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
    async fn uid_fetch_flags_does_not_send_full_message_literal() {
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
        .expect("deliver");

        let (client, server) = duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
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
        reader
            .read_line(&mut capability)
            .await
            .expect("capability greeting");

        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID FETCH 1:* (FLAGS)\r\nA004 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _select_lines = read_until_contains(&mut reader, "A002 OK").await;
        let fetch_lines = read_until_contains(&mut reader, "A003 OK").await;
        assert!(fetch_lines.iter().any(|l| l.contains("FLAGS")));
        assert!(fetch_lines.iter().any(|l| l.contains("UID ")));
        assert!(!fetch_lines.iter().any(|l| l.contains("RFC822 {")));
        assert!(!fetch_lines.iter().any(|l| l.contains("BODY[] {")));

        let _logout_lines = read_until_contains(&mut reader, "A004 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn uid_fetch_header_fields_uses_matching_body_section_name() {
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
            b"From: a@example.test\r\nTo: user@example.test\r\nSubject: one\r\n\r\nfirst\r\n",
        )
        .expect("deliver");

        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID FETCH 1:* (UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT)])\r\nA004 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _select_lines = read_until_contains(&mut reader, "A002 OK").await;
        let fetch_lines = read_until_contains(&mut reader, "A003 OK").await;
        assert!(
            fetch_lines
                .iter()
                .any(|l| l.contains("BODY[HEADER.FIELDS (FROM TO SUBJECT)] {"))
        );
        let joined = fetch_lines.join("");
        assert!(joined.contains("From: a@example.test"));
        assert!(joined.contains("To: user@example.test"));
        assert!(joined.contains("Subject: one"));
        assert!(!joined.contains("Date:"));
        assert!(!joined.contains("\r\n\r\nfirst"));

        let _logout_lines = read_until_contains(&mut reader, "A004 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[test]
    fn normalize_fetch_items_keeps_nested_header_fields_together() {
        let items = super::normalize_fetch_items(
            "(UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (From To Cc Bcc Subject Date Message-ID Priority X-Priority References Newsgroups In-Reply-To Content-Type Reply-To Received)])",
        );

        assert_eq!(
            items,
            vec![
                "BODY.PEEK[HEADER.FIELDS (FROM TO CC BCC SUBJECT DATE MESSAGE-ID PRIORITY X-PRIORITY REFERENCES NEWSGROUPS IN-REPLY-TO CONTENT-TYPE REPLY-TO RECEIVED)]",
                "FLAGS",
                "RFC822.SIZE",
                "UID",
            ]
        );
    }

    #[tokio::test]
    async fn uid_fetch_header_fields_not_excludes_requested_headers() {
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
            b"From: a@example.test\r\nTo: user@example.test\r\nSubject: one\r\nX-Spam: no\r\n\r\nfirst\r\n",
        )
        .expect("deliver");

        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID FETCH 1:* (UID BODY.PEEK[HEADER.FIELDS.NOT (SUBJECT)])\r\nA004 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _select_lines = read_until_contains(&mut reader, "A002 OK").await;
        let fetch_lines = read_until_contains(&mut reader, "A003 OK").await;
        let joined = fetch_lines.join("");
        assert!(joined.contains("BODY[HEADER.FIELDS.NOT (SUBJECT)] {"));
        assert!(joined.contains("From: a@example.test"));
        assert!(joined.contains("X-Spam: no"));
        assert!(!joined.contains("Subject: one"));

        let _logout_lines = read_until_contains(&mut reader, "A004 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn uid_fetch_supports_body_text_and_partial_literals() {
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
            b"From: a@example.test\r\nSubject: body ranges\r\n\r\n0123456789abcdef\r\n",
        )
        .expect("deliver");

        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID FETCH 1:* (UID BODY[TEXT]<2.5>)\r\nA004 UID FETCH 1:* (UID BODY.PEEK[]<0.12>)\r\nA005 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _select_lines = read_until_contains(&mut reader, "A002 OK").await;
        let text_lines = read_until_contains(&mut reader, "A003 OK").await;
        let joined_text = text_lines.join("");
        assert!(joined_text.contains("BODY[TEXT]<2> {5}"));
        assert!(joined_text.contains("23456"));
        assert!(!joined_text.contains("Subject: body ranges"));

        let partial_lines = read_until_contains(&mut reader, "A004 OK").await;
        let joined_partial = partial_lines.join("");
        assert!(joined_partial.contains("BODY[]<0> {12}"));
        assert!(joined_partial.contains("From: a@exam"));
        assert!(!joined_partial.contains("0123456789abcdef"));

        let _logout_lines = read_until_contains(&mut reader, "A005 OK").await;
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
                None::<Arc<super::tls::TlsContext>>,
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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 IDLE\r\nDONE\r\nA003 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _login_lines = read_until_contains(&mut reader, "A001 OK").await;
        let idle_start = read_until_contains(&mut reader, "+ idling").await;
        assert!(idle_start.iter().any(|line| line.contains("+ idling")));
        let idle_done = read_until_contains(&mut reader, "A002 OK").await;
        assert!(idle_done.iter().any(|line| line.contains("IDLE completed")));
        let _logout_lines = read_until_contains(&mut reader, "A003 OK").await;
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
                None::<Arc<super::tls::TlsContext>>,
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
    async fn search_supports_headers_text_dates_ranges_or_and_not() {
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
            b"Date: Sun, 14 Jun 2026 12:00:00 +0000\r\nFrom: alice@example.test\r\nTo: user@example.test\r\nCc: team@example.test\r\nSubject: Alpha Project\r\n\r\nbody has rocket text\r\n",
        )
        .expect("deliver one");
        rmail_common::maildir::deliver(
            &mail_root,
            "example.test",
            "user",
            b"Date: Mon, 15 Jun 2026 12:00:00 +0000\r\nFrom: bob@example.test\r\nTo: user@example.test\r\nSubject: Beta Report\r\n\r\nbody has invoice text\r\n",
        )
        .expect("deliver two");

        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID STORE 1 +FLAGS (\\Seen)\r\nA004 SEARCH UNSEEN\r\nA005 SEARCH FROM alice\r\nA006 SEARCH BODY invoice\r\nA007 SEARCH TEXT rocket\r\nA008 UID SEARCH UID 2:*\r\nA009 SEARCH OR SUBJECT Alpha SUBJECT Beta\r\nA010 SEARCH NOT FROM alice\r\nA011 SEARCH 2\r\nA012 UID SEARCH SENTSINCE 15-Jun-2026 SENTBEFORE 16-Jun-2026\r\nA013 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _select = read_until_contains(&mut reader, "A002 OK").await;
        let _store = read_until_contains(&mut reader, "A003 OK").await;

        let unseen = read_until_contains(&mut reader, "A004 OK").await;
        assert!(unseen.iter().any(|l| l.trim_end() == "* SEARCH 2"));

        let from = read_until_contains(&mut reader, "A005 OK").await;
        assert!(from.iter().any(|l| l.trim_end() == "* SEARCH 1"));

        let body = read_until_contains(&mut reader, "A006 OK").await;
        assert!(body.iter().any(|l| l.trim_end() == "* SEARCH 2"));

        let text = read_until_contains(&mut reader, "A007 OK").await;
        assert!(text.iter().any(|l| l.trim_end() == "* SEARCH 1"));

        let uid_range = read_until_contains(&mut reader, "A008 OK").await;
        assert!(uid_range.iter().any(|l| l.trim_end() == "* SEARCH 2"));

        let or_lines = read_until_contains(&mut reader, "A009 OK").await;
        assert!(or_lines.iter().any(|l| l.trim_end() == "* SEARCH 1 2"));

        let not_lines = read_until_contains(&mut reader, "A010 OK").await;
        assert!(not_lines.iter().any(|l| l.trim_end() == "* SEARCH 2"));

        let seq_range = read_until_contains(&mut reader, "A011 OK").await;
        assert!(seq_range.iter().any(|l| l.trim_end() == "* SEARCH 2"));

        let sent_date = read_until_contains(&mut reader, "A012 OK").await;
        assert!(sent_date.iter().any(|l| l.trim_end() == "* SEARCH 2"));

        let _logout = read_until_contains(&mut reader, "A013 OK").await;
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
                None::<Arc<super::tls::TlsContext>>,
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
        assert!(capability.contains("MOVE"));

        reader
            .get_mut()
            .write_all(
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 CHECK\r\nA004 UID COPY 1 Archive\r\nA005 UID MOVE 2 Archive\r\nA006 UNSELECT\r\nA007 SELECT INBOX\r\nA008 STATUS Archive (UIDNEXT MESSAGES UNSEEN RECENT)\r\nA009 LOGOUT\r\n",
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
            status.iter().any(
                |l| l.contains("* STATUS \"Archive\" (MESSAGES 2 UIDNEXT 3 UNSEEN 2 RECENT 0)")
            )
        );

        let _logout = read_until_contains(&mut reader, "A009 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn append_preserves_literal_bytes_returns_appenduid_and_requires_existing_mailbox() {
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
        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                server_mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
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
        assert!(capability.contains("UIDPLUS"));

        let raw = b"Subject: appended\r\nX-Raw: \xff\r\n\r\nbody\x00bytes\r\n";
        let mut commands = Vec::new();
        commands.extend_from_slice(b"A001 LOGIN \"user@example.test\" \"password\"\r\n");
        commands.extend_from_slice(
            format!("A002 APPEND Sent (\\Seen) {{{}}}\r\n", raw.len()).as_bytes(),
        );
        commands.extend_from_slice(raw);
        commands.extend_from_slice(b"\r\n");
        commands.extend_from_slice(format!("A003 APPEND Missing {{{}}}\r\n", raw.len()).as_bytes());
        commands.extend_from_slice(raw);
        commands.extend_from_slice(b"\r\nA004 LOGOUT\r\n");
        reader
            .get_mut()
            .write_all(&commands)
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let append_lines = read_until_contains(&mut reader, "A002 OK").await;
        assert!(append_lines.iter().any(|l| l.starts_with("+ ")));
        assert!(append_lines.iter().any(|l| l.contains("APPENDUID")));

        let missing_lines = read_until_contains(&mut reader, "A003 NO").await;
        assert!(missing_lines.iter().any(|l| l.contains("APPEND failed")));

        let _logout = read_until_contains(&mut reader, "A004 OK").await;
        server_task.await.expect("join").expect("server");

        let (_, sent) =
            rmail_common::imap_state::load_folder(&mail_root, "example.test", "user", "Sent")
                .expect("load sent");
        assert_eq!(sent.len(), 1);
        assert!(
            sent[0]
                .flags
                .iter()
                .any(|f| f.eq_ignore_ascii_case("\\Seen"))
        );
        assert_eq!(std::fs::read(&sent[0].path).expect("read appended"), raw);
        assert!(
            !rmail_common::imap_state::folder_exists(&mail_root, "example.test", "user", "Missing")
                .expect("missing folder check")
        );
    }

    #[tokio::test]
    async fn unsupported_commands_return_bad_after_logging_context() {
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
                None::<Arc<super::tls::TlsContext>>,
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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID SORT RETURN (ALL)\r\nA004 XLIST \"\" \"*\"\r\nA005 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let _select = read_until_contains(&mut reader, "A002 OK").await;

        let uid_sort = read_until_contains(&mut reader, "A003 BAD").await;
        assert!(
            uid_sort
                .iter()
                .any(|l| l.contains("Unsupported UID subcommand"))
        );

        let xlist = read_until_contains(&mut reader, "A004 BAD").await;
        assert!(
            xlist
                .iter()
                .any(|l| l.contains("Unknown or unimplemented command"))
        );

        let _logout = read_until_contains(&mut reader, "A005 OK").await;
        server_task.await.expect("join").expect("server");
    }

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
                None::<Arc<super::tls::TlsContext>>,
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
            include_str!("../fixtures/thunderbird_compat.imap"),
        )
        .await;

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
                None::<Arc<super::tls::TlsContext>>,
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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 RENAME Projects \"Renamed\"\r\nA003 LIST \"\" \"*\"\r\nA004 SELECT Renamed\r\nA005 RENAME INBOX Nope\r\nA006 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _login = read_until_contains(&mut reader, "A001 OK").await;
        let rename = read_until_contains(&mut reader, "A002 OK").await;
        assert!(rename.iter().any(|l| l.contains("RENAME completed")));

        let list = read_until_contains(&mut reader, "A003 OK").await;
        let joined = list.join("");
        assert!(joined.contains("\"Renamed\""));
        assert!(!joined.contains("\"Projects\""));

        let select = read_until_contains(&mut reader, "A004 OK").await;
        assert!(select.iter().any(|l| l.contains("* 1 EXISTS")));

        let inbox_rename = read_until_contains(&mut reader, "A005 NO").await;
        assert!(
            inbox_rename
                .iter()
                .any(|l| l.contains("cannot rename INBOX"))
        );

        let _logout = read_until_contains(&mut reader, "A006 OK").await;
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
                None::<Arc<super::tls::TlsContext>>,
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
        assert!(capability.contains("SPECIAL-USE"));

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
                None::<Arc<super::tls::TlsContext>>,
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
                None::<Arc<super::tls::TlsContext>>,
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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 LSUB \"\" \"Projects\"\r\nA003 SUBSCRIBE Projects\r\nA004 LSUB \"\" \"Projects\"\r\nA005 UNSUBSCRIBE Projects\r\nA006 LSUB \"\" \"Projects\"\r\nA007 LOGOUT\r\n",
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
        assert!(subscribed.join("").contains("\"Projects\""));

        let unsubscribe = read_until_contains(&mut reader, "A005 OK").await;
        assert!(
            unsubscribe
                .iter()
                .any(|l| l.contains("UNSUBSCRIBE completed"))
        );

        let final_lsub = read_until_contains(&mut reader, "A006 OK").await;
        assert!(!final_lsub.join("").contains("\"Projects\""));

        let _logout = read_until_contains(&mut reader, "A007 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn fetch_macros_envelope_and_bodystructure_are_parseable() {
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
            b"Date: Sun, 14 Jun 2026 12:00:00 +0000\r\nFrom: Sender Name <sender@example.test>\r\nTo: User <user@example.test>\r\nCc: copy@example.test\r\nMessage-ID: <m1@example.test>\r\nSubject: macro\r\n\r\nbody\r\n",
        )
        .expect("deliver");

        let (client, server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 FETCH 1 FULL\r\nA004 UID FETCH 1:* (UID BODYSTRUCTURE ENVELOPE)\r\nA005 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _select = read_until_contains(&mut reader, "A002 OK").await;
        let full_lines = read_until_contains(&mut reader, "A003 OK").await;
        let joined_full = full_lines.join("");
        assert!(joined_full.contains("FLAGS"));
        assert!(joined_full.contains("INTERNALDATE"));
        assert!(joined_full.contains("RFC822.SIZE"));
        assert!(joined_full.contains("ENVELOPE"));
        assert!(joined_full.contains("BODYSTRUCTURE"));

        let uid_lines = read_until_contains(&mut reader, "A004 OK").await;
        let joined_uid = uid_lines.join("");
        assert!(joined_uid.contains("UID "));
        assert!(joined_uid.contains("BODYSTRUCTURE"));
        assert!(joined_uid.contains("ENVELOPE"));
        assert!(joined_uid.contains("(\"Sender Name\" NIL \"sender\" \"example.test\")"));
        assert!(joined_uid.contains("(\"User\" NIL \"user\" \"example.test\")"));
        assert!(joined_uid.contains("(NIL NIL \"copy\" \"example.test\")"));
        assert!(joined_uid.contains("\"<m1@example.test>\""));

        let _logout = read_until_contains(&mut reader, "A005 OK").await;
        server_task.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn bodystructure_describes_multipart_html_inline_and_attachment_parts() {
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
            b"From: a@example.test\r\nSubject: multipart\r\nContent-Type: multipart/mixed; boundary=\"mix\"\r\n\r\n--mix\r\nContent-Type: multipart/alternative; boundary=\"alt\"\r\n\r\n--alt\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nPlain body\r\n--alt\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<p>HTML body</p>\r\n--alt--\r\n--mix\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\nContent-ID: <logo@example.test>\r\nContent-Disposition: inline; filename=\"logo.png\"\r\n\r\naGVsbG8=\r\n--mix\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"file.pdf\"\r\n\r\n%PDF\r\n--mix--\r\n",
        )
        .expect("deliver");

        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            process_stream(
                Box::new(server),
                mail_root.to_string_lossy().to_string(),
                None::<Arc<super::tls::TlsContext>>,
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
                b"A001 LOGIN \"user@example.test\" \"password\"\r\nA002 SELECT INBOX\r\nA003 UID FETCH 1:* (UID BODYSTRUCTURE)\r\nA004 LOGOUT\r\n",
            )
            .await
            .expect("write commands");
        reader.get_mut().flush().await.expect("flush");

        let _select = read_until_contains(&mut reader, "A002 OK").await;
        let fetch_lines = read_until_contains(&mut reader, "A003 OK").await;
        let joined = fetch_lines.join("");
        assert!(joined.contains("BODYSTRUCTURE"));
        assert!(joined.contains("\"MIXED\""));
        assert!(joined.contains("\"ALTERNATIVE\""));
        assert!(joined.contains("\"TEXT\" \"HTML\""));
        assert!(joined.contains("\"IMAGE\" \"PNG\""));
        assert!(joined.contains("\"APPLICATION\" \"PDF\""));
        assert!(joined.contains("\"INLINE\" (\"FILENAME\" \"logo.png\")"));
        assert!(joined.contains("\"ATTACHMENT\" (\"FILENAME\" \"file.pdf\")"));
        assert!(joined.contains("logo@example.test"));

        let _logout = read_until_contains(&mut reader, "A004 OK").await;
        server_task.await.expect("join").expect("server");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg_path =
        std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let cfg = Config::from_file(&cfg_path).context(format!("loading {}", cfg_path))?;
    let mail_root = cfg.global.mail_root.clone();
    rmail_common::runtime::redirect_stdio_to_log(std::path::Path::new(&mail_root), "imapd")
        .context("redirecting logs")?;

    // SQLite DB is the authoritative source for mailboxes/catchalls
    let db_path = cfg.global.db_path.clone();
    if db_path.is_none() {
        eprintln!("No db_path configured; SQLite DB is required");
        std::process::exit(1);
    }

    // TLS context if certs present
    let tls_context = if let (Some(cert), Some(key)) = (&cfg.global.tls_cert, &cfg.global.tls_key) {
        match load_tls_context(cert, key) {
            Ok(ctx) => Some(ctx),
            Err(e) => {
                eprintln!("Failed to load TLS: {}", e);
                None
            }
        }
    } else {
        None
    };

    let db_path = cfg.global.db_path.clone();
    // Plain IMAP listener (supports STARTTLS if tls_context present)
    let imap_port = cfg.global.imap_port.unwrap_or(143);
    let imap_addrs = cfg
        .global
        .imap_listen_addrs
        .clone()
        .unwrap_or_else(|| vec![format!("0.0.0.0:{}", imap_port)]);
    let mut listener_count = 0usize;
    for addr in imap_addrs {
        let listener = bind_tcp_listener(&addr)
            .with_context(|| format!("starting IMAP plain listener on {addr}"))?;
        println!("rMail IMAPD listening on {}", addr);
        listener_count += 1;
        let mail_root_clone = mail_root.clone();
        let acceptor_clone = tls_context.clone();
        let db_clone = db_path.clone();
        tokio::spawn(async move {
            if let Err(e) =
                run_plain_listener(addr, listener, mail_root_clone, acceptor_clone, db_clone).await
            {
                eprintln!("IMAP plain listener failed: {}", e);
            }
        });
    }

    // IMAPS (implicit TLS) listener
    if let Some(ctx) = tls_context.clone() {
        if let Some(imaps_port) = cfg.global.imaps_port {
            let imaps_addrs = cfg
                .global
                .imaps_listen_addrs
                .clone()
                .unwrap_or_else(|| vec![format!("0.0.0.0:{}", imaps_port)]);
            for addr in imaps_addrs {
                let listener = bind_tcp_listener(&addr)
                    .with_context(|| format!("starting IMAPS listener on {addr}"))?;
                println!("rMail IMAPD (IMAPS) listening on {}", addr);
                listener_count += 1;
                let mail_root_clone = mail_root.clone();
                let ctx_clone = ctx.clone();
                let db_clone = db_path.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        run_imaps_listener(addr, listener, ctx_clone, mail_root_clone, db_clone)
                            .await
                    {
                        eprintln!("IMAPS listener failed: {}", e);
                    }
                });
            }
        }
    } else if cfg.global.imaps_port.is_some() || cfg.global.imaps_listen_addrs.is_some() {
        eprintln!("IMAPS listener not started because TLS certificate/key could not be loaded");
    }

    if listener_count == 0 {
        return Err(anyhow!("no IMAP listeners were started"));
    }

    // keep running
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

async fn run_plain_listener(
    addr: String,
    listener: tokio::net::TcpListener,
    mail_root: String,
    tls_ctx: Option<Arc<tls::TlsContext>>,
    db_path: Option<String>,
) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        println!(
            "Accepted IMAP plaintext connection on {} from {} (starttls_available={})",
            addr,
            peer,
            tls_ctx.is_some()
        );
        let mail_root = mail_root.clone();
        let acceptor = tls_ctx.clone();
        let db_clone = db_path.clone();
        tokio::spawn(async move {
            if let Err(e) = process_stream(
                Box::new(stream),
                mail_root,
                acceptor,
                db_clone,
                Some(peer),
                false,
            )
            .await
            {
                eprintln!("IMAP client error: {}", e);
            }
        });
    }
}

async fn run_imaps_listener(
    addr: String,
    listener: tokio::net::TcpListener,
    ctx: Arc<tls::TlsContext>,
    mail_root: String,
    db_path: Option<String>,
) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        println!("Accepted IMAPS TCP connection on {} from {}", addr, peer);
        let ctx = ctx.clone();
        let mail_root = mail_root.clone();
        let db_clone = db_path.clone();
        tokio::spawn(async move {
            match ctx.acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(e) = process_stream(
                        Box::new(tls_stream),
                        mail_root,
                        Some(ctx.clone()),
                        db_clone,
                        Some(peer),
                        true,
                    )
                    .await
                    {
                        eprintln!("IMAPS client error: {}", e);
                    }
                }
                Err(e) => eprintln!("IMAPS TLS accept error from {}: {}", peer, e),
            }
        });
    }
}

fn unquote(s: &str) -> &str {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        &s[1..(s.len() - 1)]
    } else {
        s
    }
}

fn capability_tokens(session_encrypted: bool, tls_ctx: Option<&Arc<tls::TlsContext>>) -> String {
    let mut caps = vec![
        "IMAP4rev1",
        "UIDPLUS",
        "NAMESPACE",
        "SPECIAL-USE",
        "IDLE",
        "MOVE",
    ];
    if !session_encrypted {
        caps.push("LOGINDISABLED");
        if tls_ctx.is_some() {
            caps.push("STARTTLS");
        }
    } else {
        caps.push("AUTH=PLAIN");
        caps.push("AUTH=SCRAM-SHA-256");
    }
    caps.join(" ")
}

fn address_parts(address: &str) -> Result<(String, String)> {
    let at = address
        .find('@')
        .ok_or_else(|| anyhow::anyhow!("invalid mailbox address"))?;
    Ok((address[..at].to_string(), address[at + 1..].to_string()))
}

fn selected_mailbox_name(selected: &Option<SelectedMailbox>) -> &str {
    selected
        .as_ref()
        .map(|s| s.mailbox.as_str())
        .unwrap_or("INBOX")
}

fn selected_mailbox_for_log(selected: &Option<SelectedMailbox>) -> &str {
    selected.as_ref().map(|s| s.mailbox.as_str()).unwrap_or("-")
}

fn log_unsupported_imap(
    peer: Option<SocketAddr>,
    selected: &Option<SelectedMailbox>,
    tag: &str,
    command: &str,
    raw_args: &str,
) {
    eprintln!(
        "imap_unsupported peer={:?} selected_mailbox={} tag={} command={} raw_args={:?}",
        peer,
        selected_mailbox_for_log(selected),
        tag,
        command,
        raw_args
    );
}

fn next_uid(sel: &SelectedMailbox) -> u64 {
    sel.uidnext
}

fn first_unseen(sel: &SelectedMailbox) -> u64 {
    sel.msgs
        .iter()
        .enumerate()
        .find(|(_, (_, _, flags))| !flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen")))
        .map(|(idx, _)| idx as u64 + 1)
        .unwrap_or(0)
}

fn unseen_count(sel: &SelectedMailbox) -> usize {
    sel.msgs
        .iter()
        .filter(|(_, _, flags)| !flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen")))
        .count()
}

fn format_internal_date(path: &Path) -> String {
    let modified = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    let dt: chrono::DateTime<chrono::Utc> = modified.into();
    dt.format("%d-%b-%Y %H:%M:%S +0000").to_string()
}

fn seqs_from_set(seq_set: &str, total: usize) -> Vec<usize> {
    if seq_set == "1:*" {
        (1..=total).collect()
    } else if seq_set.contains(':') {
        let mut parts = seq_set.split(':');
        let start = parts
            .next()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(1);
        let end = parts
            .next()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(total);
        (start..=end).collect()
    } else if let Ok(v) = seq_set.parse::<usize>() {
        vec![v]
    } else {
        vec![]
    }
}

fn uids_from_set(uid_set: &str, msgs: &[(u64, std::path::PathBuf, Vec<String>)]) -> Vec<u64> {
    if uid_set == "1:*" {
        msgs.iter().map(|(u, _, _)| *u).collect()
    } else if uid_set.contains(':') {
        let mut parts = uid_set.split(':');
        let start = parts
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(1);
        let end = parts
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or_else(|| msgs.last().map(|(u, _, _)| *u).unwrap_or(start));
        msgs.iter()
            .filter_map(|(u, _, _)| (*u >= start && *u <= end).then_some(*u))
            .collect()
    } else if let Ok(v) = uid_set.parse::<u64>() {
        vec![v]
    } else {
        vec![]
    }
}

fn ids_from_set(id_set: &str, max: u64) -> Vec<u64> {
    if id_set == "*" {
        return (1..=max).collect();
    }
    let mut out = Vec::new();
    for part in id_set.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once(':') {
            let start = if start == "*" {
                max
            } else {
                start.parse::<u64>().unwrap_or(1)
            };
            let end = if end == "*" {
                max
            } else {
                end.parse::<u64>().unwrap_or(max)
            };
            let (lo, hi) = if start <= end {
                (start, end)
            } else {
                (end, start)
            };
            out.extend(lo..=hi);
        } else if let Ok(id) = part.parse::<u64>() {
            out.push(id);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

#[derive(Debug, Clone)]
enum SearchCriterion {
    All,
    Seen,
    Unseen,
    SeqSet(String),
    UidSet(String),
    Since(chrono::NaiveDate),
    Before(chrono::NaiveDate),
    SentSince(chrono::NaiveDate),
    SentBefore(chrono::NaiveDate),
    Header(String, String),
    Body(String),
    Text(String),
    Not(Box<SearchCriterion>),
    Or(Box<SearchCriterion>, Box<SearchCriterion>),
    And(Vec<SearchCriterion>),
}

#[derive(Debug)]
struct SearchMessage<'a> {
    seq: usize,
    uid: u64,
    flags: &'a [String],
    path: &'a Path,
    data: &'a [u8],
}

fn tokenize_search(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            ' ' | '\t' | '\r' | '\n' => {}
            '(' | ')' => tokens.push(ch.to_string()),
            '"' => {
                let mut token = String::new();
                let mut escaped = false;
                for next in chars.by_ref() {
                    if escaped {
                        token.push(next);
                        escaped = false;
                    } else if next == '\\' {
                        escaped = true;
                    } else if next == '"' {
                        break;
                    } else {
                        token.push(next);
                    }
                }
                tokens.push(token);
            }
            _ => {
                let mut token = String::new();
                token.push(ch);
                while let Some(next) = chars.peek().copied() {
                    if next.is_whitespace() || next == '(' || next == ')' {
                        break;
                    }
                    token.push(next);
                    chars.next();
                }
                tokens.push(token);
            }
        }
    }
    tokens
}

fn parse_imap_date(token: &str) -> Option<chrono::NaiveDate> {
    chrono::NaiveDate::parse_from_str(token, "%d-%b-%Y").ok()
}

fn parse_search_criterion(tokens: &[String], pos: &mut usize) -> Option<SearchCriterion> {
    let token = tokens.get(*pos)?.clone();
    *pos += 1;
    if token == "(" {
        let mut items = Vec::new();
        while tokens.get(*pos).map(|s| s.as_str()) != Some(")") {
            items.push(parse_search_criterion(tokens, pos)?);
        }
        *pos += 1;
        return Some(SearchCriterion::And(items));
    }
    if token == ")" {
        return None;
    }
    let upper = token.to_uppercase();
    match upper.as_str() {
        "ALL" => Some(SearchCriterion::All),
        "SEEN" => Some(SearchCriterion::Seen),
        "UNSEEN" => Some(SearchCriterion::Unseen),
        "UID" => {
            let set = tokens.get(*pos)?.clone();
            *pos += 1;
            Some(SearchCriterion::UidSet(set))
        }
        "SINCE" => {
            let date = parse_imap_date(tokens.get(*pos)?)?;
            *pos += 1;
            Some(SearchCriterion::Since(date))
        }
        "BEFORE" => {
            let date = parse_imap_date(tokens.get(*pos)?)?;
            *pos += 1;
            Some(SearchCriterion::Before(date))
        }
        "SENTSINCE" => {
            let date = parse_imap_date(tokens.get(*pos)?)?;
            *pos += 1;
            Some(SearchCriterion::SentSince(date))
        }
        "SENTBEFORE" => {
            let date = parse_imap_date(tokens.get(*pos)?)?;
            *pos += 1;
            Some(SearchCriterion::SentBefore(date))
        }
        "FROM" | "TO" | "CC" | "BCC" | "SUBJECT" => {
            let value = tokens.get(*pos)?.clone();
            *pos += 1;
            Some(SearchCriterion::Header(upper, value))
        }
        "BODY" => {
            let value = tokens.get(*pos)?.clone();
            *pos += 1;
            Some(SearchCriterion::Body(value))
        }
        "TEXT" => {
            let value = tokens.get(*pos)?.clone();
            *pos += 1;
            Some(SearchCriterion::Text(value))
        }
        "NOT" => Some(SearchCriterion::Not(Box::new(parse_search_criterion(
            tokens, pos,
        )?))),
        "OR" => {
            let left = parse_search_criterion(tokens, pos)?;
            let right = parse_search_criterion(tokens, pos)?;
            Some(SearchCriterion::Or(Box::new(left), Box::new(right)))
        }
        _ if token
            .chars()
            .all(|c| c.is_ascii_digit() || c == ':' || c == '*' || c == ',') =>
        {
            Some(SearchCriterion::SeqSet(token))
        }
        _ => None,
    }
}

fn parse_search(input: &str) -> Option<SearchCriterion> {
    let tokens = tokenize_search(input);
    if tokens.is_empty() {
        return Some(SearchCriterion::All);
    }
    let mut pos = 0;
    let mut criteria = Vec::new();
    while pos < tokens.len() {
        criteria.push(parse_search_criterion(&tokens, &mut pos)?);
    }
    Some(SearchCriterion::And(criteria))
}

fn message_internal_date(path: &Path) -> Option<chrono::NaiveDate> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let dt: chrono::DateTime<chrono::Utc> = modified.into();
    Some(dt.date_naive())
}

fn message_sent_date(data: &[u8]) -> Option<chrono::NaiveDate> {
    let raw = header_value(data, "Date")?;
    chrono::DateTime::parse_from_rfc2822(&raw)
        .ok()
        .map(|dt| dt.date_naive())
}

fn contains_ascii_casefold(haystack: &[u8], needle: &str) -> bool {
    String::from_utf8_lossy(haystack)
        .to_lowercase()
        .contains(&needle.to_lowercase())
}

fn search_matches(criterion: &SearchCriterion, msg: &SearchMessage<'_>, total: usize) -> bool {
    match criterion {
        SearchCriterion::All => true,
        SearchCriterion::Seen => msg.flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen")),
        SearchCriterion::Unseen => !msg.flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen")),
        SearchCriterion::SeqSet(set) => ids_from_set(set, total as u64).contains(&(msg.seq as u64)),
        SearchCriterion::UidSet(set) => {
            ids_from_set(set, msg.uid.max(total as u64)).contains(&msg.uid)
        }
        SearchCriterion::Since(date) => message_internal_date(msg.path)
            .map(|msg_date| msg_date >= *date)
            .unwrap_or(false),
        SearchCriterion::Before(date) => message_internal_date(msg.path)
            .map(|msg_date| msg_date < *date)
            .unwrap_or(false),
        SearchCriterion::SentSince(date) => message_sent_date(msg.data)
            .map(|msg_date| msg_date >= *date)
            .unwrap_or(false),
        SearchCriterion::SentBefore(date) => message_sent_date(msg.data)
            .map(|msg_date| msg_date < *date)
            .unwrap_or(false),
        SearchCriterion::Header(name, value) => header_value(msg.data, name)
            .map(|header| header.to_lowercase().contains(&value.to_lowercase()))
            .unwrap_or(false),
        SearchCriterion::Body(value) => contains_ascii_casefold(body_after_header(msg.data), value),
        SearchCriterion::Text(value) => contains_ascii_casefold(msg.data, value),
        SearchCriterion::Not(inner) => !search_matches(inner, msg, total),
        SearchCriterion::Or(left, right) => {
            search_matches(left, msg, total) || search_matches(right, msg, total)
        }
        SearchCriterion::And(items) => items.iter().all(|item| search_matches(item, msg, total)),
    }
}

fn copy_uid_pairs(
    source_set: &[u64],
    destination_uids: &[u64],
    uidvalidity: u64,
) -> Option<String> {
    if source_set.is_empty() || destination_uids.is_empty() {
        None
    } else {
        let source = source_set
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let dest = destination_uids
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        Some(format!("[COPYUID {} {} {}] ", uidvalidity, source, dest))
    }
}

fn normalize_fetch_items(spec: &str) -> Vec<String> {
    let trimmed = spec.trim();
    let inner = trimmed
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(trimmed);
    let mut out = Vec::new();
    for item in split_fetch_items(inner)
        .into_iter()
        .map(|s| s.to_uppercase())
    {
        match item.as_str() {
            "ALL" => {
                out.extend(["FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE"].map(str::to_string))
            }
            "FAST" => out.extend(["FLAGS", "INTERNALDATE", "RFC822.SIZE"].map(str::to_string)),
            "FULL" => out.extend(
                ["FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", "BODY"].map(str::to_string),
            ),
            _ => out.push(item),
        }
    }
    out.sort();
    out.dedup();
    out
}

fn split_fetch_items(spec: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let mut start = None;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut in_quote = false;
    let mut escaped = false;

    for (idx, ch) in spec.char_indices() {
        if start.is_none() {
            if ch.is_whitespace() {
                continue;
            }
            start = Some(idx);
        }

        if in_quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_quote = false;
            }
            continue;
        }

        match ch {
            '"' => in_quote = true,
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '(' if bracket_depth == 0 => paren_depth += 1,
            ')' if bracket_depth == 0 => paren_depth = paren_depth.saturating_sub(1),
            c if c.is_whitespace() && paren_depth == 0 && bracket_depth == 0 => {
                if let Some(item_start) = start.take() {
                    items.push(spec[item_start..idx].trim());
                }
            }
            _ => {}
        }
    }

    if let Some(item_start) = start {
        let item = spec[item_start..].trim();
        if !item.is_empty() {
            items.push(item);
        }
    }

    items
}

fn fetch_inner_spec(spec: &str) -> &str {
    let trimmed = spec.trim();
    trimmed
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(trimmed)
}

fn header_section_response_name(spec: &str) -> Option<String> {
    let inner = fetch_inner_spec(spec);
    let upper = inner.to_uppercase();
    let start = upper
        .find("BODY.PEEK[HEADER")
        .or_else(|| upper.find("BODY[HEADER"))?;
    let candidate = inner[start..].trim();
    let end = candidate.rfind(']')?;
    let mut section = candidate[..=end].to_string();
    if section.to_uppercase().starts_with("BODY.PEEK[") {
        section = format!("BODY[{}", &section["BODY.PEEK[".len()..]);
    }
    Some(section)
}

fn body_section_response_name(spec: &str) -> Option<String> {
    let inner = fetch_inner_spec(spec);
    let upper = inner.to_uppercase();
    let start = upper.find("BODY.PEEK[").or_else(|| upper.find("BODY["))?;
    if upper[start..].starts_with("BODY.PEEK[HEADER") || upper[start..].starts_with("BODY[HEADER") {
        return None;
    }
    let candidate = inner[start..].trim();
    let end = candidate.find(']')?;
    let section = &candidate[..=end];
    let mut name = if section.to_uppercase().starts_with("BODY.PEEK[") {
        format!("BODY[{}", &section["BODY.PEEK[".len()..])
    } else {
        section.to_string()
    };
    if let Some((offset, _count)) = partial_fetch_range(candidate) {
        name.push_str(&format!("<{}>", offset));
    }
    Some(name)
}

fn partial_fetch_range(section: &str) -> Option<(usize, usize)> {
    let start = section.find('<')?;
    let end = section[start + 1..].find('>')? + start + 1;
    let mut parts = section[start + 1..end].splitn(2, '.');
    let offset = parts.next()?.parse::<usize>().ok()?;
    let count = parts.next()?.parse::<usize>().ok()?;
    Some((offset, count))
}

fn body_after_header(data: &[u8]) -> &[u8] {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| &data[pos + 4..])
        .or_else(|| {
            data.windows(2)
                .position(|w| w == b"\n\n")
                .map(|pos| &data[pos + 2..])
        })
        .unwrap_or(data)
}

fn apply_partial_range(data: &[u8], range: Option<(usize, usize)>) -> Vec<u8> {
    let Some((offset, count)) = range else {
        return data.to_vec();
    };
    if offset >= data.len() {
        return Vec::new();
    }
    let end = offset.saturating_add(count).min(data.len());
    data[offset..end].to_vec()
}

fn requested_header_fields(spec: &str) -> Option<(Vec<String>, bool)> {
    let upper = spec.to_uppercase();
    let (marker, exclude) = if upper.contains("HEADER.FIELDS.NOT (") {
        ("HEADER.FIELDS.NOT (", true)
    } else {
        ("HEADER.FIELDS (", false)
    };
    let start = upper.find(marker)?;
    let after = &spec[start + marker.len()..];
    let end = after.find(')')?;
    let fields = after[..end]
        .split_whitespace()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    Some((fields, exclude))
}

fn extract_header_literal(data: &[u8], requested_fields: Option<(&[String], bool)>) -> Vec<u8> {
    let header_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
        .unwrap_or(data.len());
    let header = &data[..header_end];
    let Some((fields, exclude)) = requested_fields else {
        return header.to_vec();
    };
    if fields.is_empty() {
        return b"\r\n".to_vec();
    }

    let header_str = String::from_utf8_lossy(header);
    let mut out = String::new();
    let mut include_current = false;
    for line in header_str.split_inclusive("\r\n") {
        if line == "\r\n" {
            break;
        }
        let first = line.as_bytes().first().copied().unwrap_or_default();
        if first == b' ' || first == b'\t' {
            if include_current {
                out.push_str(line);
            }
            continue;
        }
        if let Some((name, _)) = line.split_once(':') {
            let matched = fields.iter().any(|f| f.eq_ignore_ascii_case(name.trim()));
            include_current = if exclude { !matched } else { matched };
            if include_current {
                out.push_str(line);
            }
        } else {
            include_current = false;
        }
    }
    out.push_str("\r\n");
    out.into_bytes()
}

fn read_message_header(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
        if let Some(pos) = out.windows(4).position(|w| w == b"\r\n\r\n") {
            out.truncate(pos + 4);
            break;
        }
        if out.len() > 256 * 1024 {
            break;
        }
    }
    Ok(out)
}

fn header_value(data: &[u8], field: &str) -> Option<String> {
    let header_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(data.len());
    let header = String::from_utf8_lossy(&data[..header_end]);
    for line in header.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case(field) {
            return Some(value.trim().replace(['\\', '"'], ""));
        }
    }
    None
}

fn nstring(value: Option<&str>) -> String {
    match value {
        Some(value) if !value.is_empty() => {
            format!("\"{}\"", value.replace(['\\', '"'], ""))
        }
        _ => "NIL".to_string(),
    }
}

fn parse_address(value: &str) -> Option<(Option<String>, String, String)> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (name, addr) = if let Some(start) = trimmed.rfind('<') {
        let end = trimmed[start + 1..]
            .find('>')
            .map(|pos| start + 1 + pos)
            .unwrap_or(trimmed.len());
        let display = trimmed[..start].trim().trim_matches('"').trim();
        let name = (!display.is_empty()).then(|| display.to_string());
        (name, trimmed[start + 1..end].trim())
    } else {
        (None, trimmed.trim_matches('"'))
    };
    let (mailbox, host) = addr.rsplit_once('@')?;
    if mailbox.is_empty() || host.is_empty() {
        return None;
    }
    Some((name, mailbox.to_string(), host.to_string()))
}

fn envelope_address_list(value: Option<String>) -> String {
    let Some(value) = value else {
        return "NIL".to_string();
    };
    let addresses = value
        .split(',')
        .filter_map(parse_address)
        .map(|(name, mailbox, host)| {
            format!(
                "({} NIL \"{}\" \"{}\")",
                nstring(name.as_deref()),
                mailbox.replace(['\\', '"'], ""),
                host.replace(['\\', '"'], "")
            )
        })
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        "NIL".to_string()
    } else {
        format!("({})", addresses.join(" "))
    }
}

fn envelope_response(data: &[u8]) -> String {
    let date = header_value(data, "Date").unwrap_or_default();
    let subject = header_value(data, "Subject").unwrap_or_default();
    let from = header_value(data, "From");
    let sender = header_value(data, "Sender").or_else(|| from.clone());
    let reply_to = header_value(data, "Reply-To").or_else(|| from.clone());
    let to = header_value(data, "To");
    let cc = header_value(data, "Cc");
    let bcc = header_value(data, "Bcc");
    let in_reply_to = header_value(data, "In-Reply-To");
    let message_id = header_value(data, "Message-ID");
    format!(
        "({} {} {} {} {} {} {} {} {} {})",
        nstring(Some(&date)),
        nstring(Some(&subject)),
        envelope_address_list(from),
        envelope_address_list(sender),
        envelope_address_list(reply_to),
        envelope_address_list(to),
        envelope_address_list(cc),
        envelope_address_list(bcc),
        nstring(in_reply_to.as_deref()),
        nstring(message_id.as_deref())
    )
}

fn parse_header_params(value: &str) -> (String, Vec<(String, String)>) {
    let mut parts = value.split(';');
    let main = parts
        .next()
        .unwrap_or("text/plain")
        .trim()
        .to_ascii_lowercase();
    let params = parts
        .filter_map(|part| {
            let (name, value) = part.split_once('=')?;
            let value = value.trim().trim_matches('"').to_string();
            Some((name.trim().to_ascii_uppercase(), value))
        })
        .collect();
    (main, params)
}

fn imap_param_list(params: &[(String, String)]) -> String {
    if params.is_empty() {
        "NIL".to_string()
    } else {
        let values = params
            .iter()
            .map(|(name, value)| format!("\"{}\" {}", name, nstring(Some(value))))
            .collect::<Vec<_>>();
        format!("({})", values.join(" "))
    }
}

fn content_type_parts(data: &[u8]) -> (String, String, Vec<(String, String)>) {
    let raw = header_value(data, "Content-Type").unwrap_or_else(|| "text/plain".to_string());
    let (main, params) = parse_header_params(&raw);
    let (typ, subtype) = main
        .split_once('/')
        .map(|(typ, subtype)| (typ.to_ascii_uppercase(), subtype.to_ascii_uppercase()))
        .unwrap_or_else(|| ("TEXT".to_string(), "PLAIN".to_string()));
    (typ, subtype, params)
}

fn content_disposition(data: &[u8]) -> String {
    let Some(raw) = header_value(data, "Content-Disposition") else {
        return "NIL".to_string();
    };
    let (disposition, params) = parse_header_params(&raw);
    format!(
        "({} {})",
        nstring(Some(&disposition.to_ascii_uppercase())),
        imap_param_list(&params)
    )
}

fn body_line_count(body: &[u8]) -> usize {
    if body.is_empty() {
        0
    } else {
        bytecount_newlines(body).max(1)
    }
}

fn bytecount_newlines(data: &[u8]) -> usize {
    data.iter().filter(|b| **b == b'\n').count()
}

fn multipart_boundary(params: &[(String, String)]) -> Option<String> {
    params
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("BOUNDARY"))
        .map(|(_, value)| value.clone())
}

fn split_multipart_parts(body: &[u8], boundary: &str) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(body);
    let marker = format!("--{}", boundary);
    let closing = format!("--{}--", boundary);
    let mut parts = Vec::new();
    let mut current = Vec::new();
    let mut in_part = false;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed == marker {
            if in_part && !current.is_empty() {
                parts.push(current.join("").into_bytes());
                current.clear();
            }
            in_part = true;
        } else if trimmed == closing {
            if in_part && !current.is_empty() {
                parts.push(current.join("").into_bytes());
            }
            break;
        } else if in_part {
            current.push(line);
        }
    }
    parts
}

fn bodystructure_response(data: &[u8]) -> String {
    let (typ, subtype, params) = content_type_parts(data);
    let body = body_after_header(data);
    if typ == "MULTIPART" {
        let boundary = multipart_boundary(&params);
        let parts = boundary
            .as_ref()
            .map(|boundary| split_multipart_parts(body, boundary))
            .unwrap_or_default();
        if parts.is_empty() {
            return format!("(\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" {} 0)", body.len());
        }
        let children = parts
            .iter()
            .map(|part| bodystructure_response(part))
            .collect::<Vec<_>>()
            .join(" ");
        return format!(
            "({} \"{}\" {} NIL NIL)",
            children,
            subtype,
            imap_param_list(&params)
        );
    }

    let encoding = header_value(data, "Content-Transfer-Encoding")
        .unwrap_or_else(|| "7BIT".to_string())
        .to_ascii_uppercase();
    let content_id = header_value(data, "Content-ID");
    let description = header_value(data, "Content-Description");
    let disposition = content_disposition(data);
    if typ == "TEXT" {
        format!(
            "(\"TEXT\" \"{}\" {} {} {} {} {} {} NIL {} NIL)",
            subtype,
            imap_param_list(&params),
            nstring(content_id.as_deref()),
            nstring(description.as_deref()),
            nstring(Some(&encoding)),
            body.len(),
            body_line_count(body),
            disposition
        )
    } else {
        format!(
            "(\"{}\" \"{}\" {} {} {} {} {} NIL {} NIL)",
            typ,
            subtype,
            imap_param_list(&params),
            nstring(content_id.as_deref()),
            nstring(description.as_deref()),
            nstring(Some(&encoding)),
            body.len(),
            disposition
        )
    }
}

fn parse_store_items(spec: &str) -> Vec<String> {
    normalize_fetch_items(spec)
}

fn split_first_imap_astring(input: &str) -> Option<(String, &str)> {
    let input = input.trim_start();
    if input.is_empty() {
        return None;
    }
    if let Some(rest) = input.strip_prefix('"') {
        let mut value = String::new();
        let mut escaped = false;
        for (idx, ch) in rest.char_indices() {
            if escaped {
                value.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                return Some((value, &rest[idx + 1..]));
            } else {
                value.push(ch);
            }
        }
        None
    } else {
        let end = input.find(char::is_whitespace).unwrap_or(input.len());
        Some((input[..end].to_string(), &input[end..]))
    }
}

fn parse_append_args(args: &str) -> Option<(String, Vec<String>, usize)> {
    let trimmed = args.trim();
    let literal_start = trimmed.rfind('{')?;
    let literal_end = trimmed[literal_start + 1..].find('}')? + literal_start + 1;
    if literal_end != trimmed.len() - 1 {
        return None;
    }
    let literal_len = trimmed[literal_start + 1..literal_end]
        .parse::<usize>()
        .ok()?;
    let before_literal = trimmed[..literal_start].trim_end();
    let (mailbox, rest) = split_first_imap_astring(before_literal)?;
    let rest = rest.trim();
    let flags = if let Some(start) = rest.find('(') {
        let end = rest[start + 1..].find(')')? + start + 1;
        parse_store_items(&rest[start..=end])
    } else {
        Vec::new()
    };
    Some((mailbox, flags, literal_len))
}

fn parse_list_args(args: &str) -> Option<(String, String)> {
    let (reference, rest) = split_first_imap_astring(args)?;
    let (pattern, _) = split_first_imap_astring(rest)?;
    Some((reference, pattern))
}

fn list_effective_pattern(reference: &str, pattern: &str) -> String {
    if pattern.is_empty() {
        reference.to_string()
    } else if reference.is_empty() || pattern.starts_with('/') {
        pattern.to_string()
    } else {
        format!("{}/{}", reference.trim_end_matches('/'), pattern)
    }
}

fn mailbox_pattern_matches(name: &str, reference: &str, pattern: &str) -> bool {
    let effective = list_effective_pattern(reference, pattern);
    if effective.is_empty() {
        return name.is_empty();
    }
    mailbox_pattern_match_bytes(name.as_bytes(), effective.as_bytes())
}

fn mailbox_pattern_match_bytes(name: &[u8], pattern: &[u8]) -> bool {
    if pattern.is_empty() {
        return name.is_empty();
    }
    match pattern[0] {
        b'*' => {
            mailbox_pattern_match_bytes(name, &pattern[1..])
                || (!name.is_empty() && mailbox_pattern_match_bytes(&name[1..], pattern))
        }
        b'%' => {
            mailbox_pattern_match_bytes(name, &pattern[1..])
                || (!name.is_empty()
                    && name[0] != b'/'
                    && mailbox_pattern_match_bytes(&name[1..], pattern))
        }
        ch => {
            !name.is_empty()
                && name[0].eq_ignore_ascii_case(&ch)
                && mailbox_pattern_match_bytes(&name[1..], &pattern[1..])
        }
    }
}

fn decode_authenticate_plain(response: &str) -> Option<(String, String)> {
    let decoded = BASE64_ENGINE.decode(response.trim()).ok()?;
    let mut parts = decoded.split(|b| *b == 0);
    let _authzid = parts.next()?;
    let authcid = parts.next()?;
    let password = parts.next()?;
    if parts.next().is_some() || authcid.is_empty() {
        return None;
    }
    Some((
        String::from_utf8_lossy(authcid).to_string(),
        String::from_utf8_lossy(password).to_string(),
    ))
}

fn decode_sasl_message(response: &str) -> Option<String> {
    let decoded = BASE64_ENGINE.decode(response.trim()).ok()?;
    Some(String::from_utf8_lossy(&decoded).to_string())
}

fn parse_scram_attr<'a>(message: &'a str, key: &str) -> Option<&'a str> {
    message.split(',').find_map(|part| part.strip_prefix(key))
}

fn parse_scram_client_first(message: &str) -> Option<(String, String, String)> {
    let (gs2_header, client_first_bare) = if let Some(idx) = message.find(",,") {
        (&message[..idx + 2], &message[idx + 2..])
    } else {
        ("", message)
    };
    if !gs2_header.is_empty() && gs2_header != "n,," {
        return None;
    }
    let username = parse_scram_attr(client_first_bare, "n=")?;
    let nonce = parse_scram_attr(client_first_bare, "r=")?;
    if username.is_empty() || nonce.is_empty() {
        return None;
    }
    Some((
        username.to_string(),
        nonce.to_string(),
        client_first_bare.to_string(),
    ))
}

fn parse_scram_client_final(message: &str) -> Option<(String, String)> {
    let proof_pos = message.find(",p=")?;
    let without_proof = message[..proof_pos].to_string();
    let proof = message[proof_pos + 3..].to_string();
    if proof.is_empty() {
        return None;
    }
    Some((without_proof, proof))
}

fn generate_scram_nonce() -> String {
    let mut bytes = [0u8; 18];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    BASE64_ENGINE.encode(bytes)
}

fn apply_flag_operation(existing: &[String], op: &str, flags: &[String]) -> Vec<String> {
    let mut current = existing.to_vec();
    let silent_op = op.trim_end_matches(".SILENT");
    match silent_op {
        "FLAGS" => current = flags.to_vec(),
        "+FLAGS" => {
            for flag in flags {
                if !current.iter().any(|f| f == flag) {
                    current.push(flag.clone());
                }
            }
        }
        "-FLAGS" => {
            current.retain(|f| !flags.iter().any(|x| x == f));
        }
        _ => {}
    }
    current.sort();
    current.dedup();
    current
}

async fn write_fetch_response(
    reader: &mut BufReader<Box<dyn AsyncStream + Send + 'static>>,
    seq: usize,
    uid: u64,
    flags: &[String],
    path: std::path::PathBuf,
    requested: &[String],
    raw_spec: &str,
    force_uid: bool,
) -> Result<()> {
    let include_uid = force_uid || requested.iter().any(|i| i == "UID");
    let include_flags = requested.iter().any(|i| i == "FLAGS");
    let include_size = requested.iter().any(|i| i == "RFC822.SIZE");
    let include_internaldate = requested.iter().any(|i| i == "INTERNALDATE");
    let include_rfc822 = requested.iter().any(|i| i == "RFC822");
    let include_envelope = requested.iter().any(|i| i == "ENVELOPE");
    let include_bodystructure = requested
        .iter()
        .any(|i| i == "BODYSTRUCTURE" || i == "BODY");
    let include_body = requested.iter().any(|i| {
        i == "BODY[]"
            || i == "BODY.PEEK[]"
            || i == "BODY[TEXT]"
            || i.starts_with("BODY[TEXT]<")
            || i.starts_with("BODY.PEEK[TEXT]<")
            || i == "RFC822.TEXT"
            || ((i.starts_with("BODY.PEEK[") || i.starts_with("BODY["))
                && !i.starts_with("BODY.PEEK[HEADER")
                && !i.starts_with("BODY[HEADER"))
    });
    let header_section_name = header_section_response_name(raw_spec);
    let body_section_name = body_section_response_name(raw_spec);
    let body_partial = body_section_name
        .as_ref()
        .and_then(|_| partial_fetch_range(fetch_inner_spec(raw_spec)));
    let requested_headers = requested_header_fields(raw_spec);
    let include_headers = header_section_name.is_some();

    let need_data = include_size
        || include_rfc822
        || include_body
        || include_headers
        || include_envelope
        || include_bodystructure;
    let internal_date = include_internaldate.then(|| format_internal_date(&path));
    let metadata_len = if include_size || include_bodystructure {
        Some(
            tokio::task::spawn_blocking({
                let path = path.clone();
                move || std::fs::metadata(path).map(|m| m.len() as usize)
            })
            .await??,
        )
    } else {
        None
    };
    let data = if include_rfc822 || include_body || include_bodystructure {
        Some(tokio::task::spawn_blocking(move || std::fs::read(path)).await??)
    } else if include_headers || include_envelope {
        Some(tokio::task::spawn_blocking(move || read_message_header(&path)).await??)
    } else if need_data {
        Some(Vec::new())
    } else {
        None
    };

    let mut attrs: Vec<String> = Vec::new();
    if include_flags {
        attrs.push(format!("FLAGS ({})", flags.join(" ")));
    }
    if include_uid {
        attrs.push(format!("UID {}", uid));
    }
    if include_size {
        let len = metadata_len
            .or_else(|| data.as_ref().map(|d| d.len()))
            .unwrap_or(0);
        attrs.push(format!("RFC822.SIZE {}", len));
    }
    if include_internaldate {
        attrs.push(format!(
            "INTERNALDATE \"{}\"",
            internal_date.unwrap_or_default()
        ));
    }
    if include_envelope {
        attrs.push(format!(
            "ENVELOPE {}",
            envelope_response(data.as_deref().unwrap_or_default())
        ));
    }
    if include_bodystructure {
        attrs.push(format!(
            "BODYSTRUCTURE {}",
            bodystructure_response(data.as_deref().unwrap_or_default())
        ));
    }

    let w = reader.get_mut();
    if !include_rfc822 && !include_body && !include_headers {
        w.write_all(format!("* {} FETCH ({})\r\n", seq, attrs.join(" ")).as_bytes())
            .await?;
        w.flush().await?;
        return Ok(());
    }

    let mut prefix = format!("* {} FETCH (", seq);
    if !attrs.is_empty() {
        prefix.push_str(&attrs.join(" "));
        prefix.push(' ');
    }
    let literal_name = if include_headers {
        header_section_name.as_deref().unwrap_or("BODY[HEADER]")
    } else if include_body {
        body_section_name.as_deref().unwrap_or("BODY[]")
    } else {
        "RFC822"
    };
    let data = data.unwrap_or_default();
    let literal = if include_headers {
        extract_header_literal(
            &data,
            requested_headers
                .as_ref()
                .map(|(fields, exclude)| (fields.as_slice(), *exclude)),
        )
    } else if include_body && literal_name.starts_with("BODY[TEXT]") {
        apply_partial_range(body_after_header(&data), body_partial)
    } else if include_body && literal_name.starts_with("BODY[") {
        apply_partial_range(&data, body_partial)
    } else if include_body && raw_spec.to_uppercase().contains("RFC822.TEXT") {
        body_after_header(&data).to_vec()
    } else {
        data
    };
    prefix.push_str(&format!("{} {{{}}}\r\n", literal_name, literal.len()));
    w.write_all(prefix.as_bytes()).await?;
    w.write_all(&literal).await?;
    w.write_all(b"\r\n)\r\n").await?;
    w.flush().await?;
    Ok(())
}

// session_encrypted indicates whether the current connection is protected by TLS (true for IMAPS
// and after a successful STARTTLS). Enforcing authentication methods (like LOGIN) only on
// encrypted sessions prevents accidental credential disclosure over plain-text.
// session_encrypted indicates whether the current connection is protected by TLS (true for IMAPS
// and after a successful STARTTLS). `peer` is the remote socket address of the client and is used
// for per-IP rate-limiting of authentication attempts.
async fn process_stream(
    stream: Box<dyn AsyncStream + Send + 'static>,
    mail_root: String,
    tls_ctx: Option<Arc<tls::TlsContext>>,
    db_path: Option<String>,
    peer: Option<SocketAddr>,
    session_encrypted: bool,
) -> Result<()> {
    let mut reader = BufReader::new(stream);
    println!(
        "Starting IMAP session peer={:?} encrypted={} tls_configured={}",
        peer,
        session_encrypted,
        tls_ctx.is_some()
    );
    {
        let w = reader.get_mut();
        w.write_all(b"* OK rMail IMAPD ready\r\n").await?;
        let caps = capability_tokens(session_encrypted, tls_ctx.as_ref());
        println!(
            "Greeting peer={:?} encrypted={} capabilities={}",
            peer, session_encrypted, caps
        );
        w.write_all(format!("* CAPABILITY {}\r\n", caps).as_bytes())
            .await?;
        w.flush().await?;
    }
    let mut line = String::new();
    let mut authed_mailbox: Option<String> = None; // store address lowercase
    // current mailbox selection state (set by SELECT)
    let mut selected: Option<SelectedMailbox> = None;

    loop {
        line.clear();
        let n = match reader.read_line(&mut line).await {
            Ok(n) => n,
            Err(e) => {
                eprintln!(
                    "IMAP read error peer={:?} encrypted={} err={}",
                    peer, session_encrypted, e
                );
                return Err(e.into());
            }
        };
        if n == 0 {
            println!(
                "IMAP session peer={:?} encrypted={} closed by client",
                peer, session_encrypted
            );
            break;
        }
        let input = line.trim_end_matches("\r\n");
        if input.is_empty() {
            continue;
        }
        let mut parts = input.splitn(3, ' ');
        let tag = parts.next().unwrap_or("*");
        let cmd = parts.next().unwrap_or("").to_uppercase();
        let args = parts.next().unwrap_or("");
        println!(
            "IMAP peer={:?} encrypted={} tag={} cmd={} args={:?} authed={} selected={}",
            peer,
            session_encrypted,
            tag,
            cmd,
            args,
            authed_mailbox.is_some(),
            selected.is_some()
        );
        match cmd.as_str() {
            "CAPABILITY" => {
                let w = reader.get_mut();
                let caps = capability_tokens(session_encrypted, tls_ctx.as_ref());
                w.write_all(format!("* CAPABILITY {}\r\n", caps).as_bytes())
                    .await?;
                w.write_all(format!("{} OK CAPABILITY completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "LOGIN" => {
                // Rate-limiting: block repeated failures per remote IP
                if let Some(peer_addr) = peer {
                    if let Some(rem) = auth_block_remaining(peer_addr.ip()) {
                        let w = reader.get_mut();
                        w.write_all(
                            format!(
                                "{} NO Too many failed auth attempts; try again in {}s\r\n",
                                tag,
                                rem.as_secs()
                            )
                            .as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    }
                }
                // Require an encrypted session for LOGIN to avoid sending cleartext passwords
                if !session_encrypted {
                    let w = reader.get_mut();
                    w.write_all(
                        format!("{} NO Encryption required for authentication\r\n", tag).as_bytes(),
                    )
                    .await?;
                    w.flush().await?;
                    continue;
                }
                // LOGIN requires two args: user and password. Clients may quote them.
                let mut a = args.trim().splitn(2, ' ');
                let user_raw = a.next().unwrap_or("");
                let pass_raw = a.next().unwrap_or("");
                let user = unquote(user_raw);
                let pass = unquote(pass_raw);
                println!(
                    "IMAP LOGIN attempt peer={:?} encrypted={} user={:?} password_len={}",
                    peer,
                    session_encrypted,
                    user,
                    pass.len()
                );
                // find mailbox (prefer DB if configured)
                let mut mb: Option<Mailbox> = None;
                if let Some(dbp) = db_path.as_ref() {
                    let dbp2 = dbp.clone();
                    let user_lookup = user.to_ascii_lowercase();
                    if user_lookup.contains('@') {
                        match tokio::task::spawn_blocking(move || {
                            rmail_common::db::get_mailbox(dbp2, &user_lookup)
                        })
                        .await
                        {
                            Ok(Ok(Some(m))) => mb = Some(m),
                            Ok(Ok(None)) => {}
                            Ok(Err(e)) => eprintln!("db get_mailbox error: {}", e),
                            Err(e) => eprintln!("db task join error: {}", e),
                        }
                    } else {
                        let dbp3 = dbp.clone();
                        let user_local = user.to_string();
                        match tokio::task::spawn_blocking(move || {
                            rmail_common::db::find_mailbox_by_localpart(dbp3, &user_local)
                        })
                        .await
                        {
                            Ok(Ok(Some(m))) => mb = Some(m),
                            Ok(Ok(None)) => {}
                            Ok(Err(e)) => eprintln!("db query error: {}", e),
                            Err(e) => eprintln!("db task join error: {}", e),
                        }
                    }
                }
                // If DB lookup didn't find a mailbox, report not found (DB is authoritative)
                if mb.is_none() {
                    println!(
                        "IMAP LOGIN user lookup failed peer={:?} user={:?}",
                        peer, user
                    );
                    if let Some(peer_addr) = peer {
                        record_auth_failure(peer_addr.ip());
                    }
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO No such user\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                if let Some(mailbox) = mb {
                    if let Some(ref hash) = mailbox.password_hash {
                        match auth::verify_password(pass, hash) {
                            Ok(true) => {
                                authed_mailbox = Some(mailbox.address.to_ascii_lowercase());
                                println!(
                                    "IMAP LOGIN success peer={:?} mailbox={}",
                                    peer, mailbox.address
                                );
                                if let Some(peer_addr) = peer {
                                    reset_auth_failures(peer_addr.ip());
                                }
                                let w = reader.get_mut();
                                w.write_all(format!("{} OK LOGIN completed\r\n", tag).as_bytes())
                                    .await?;
                                w.flush().await?;
                            }
                            Ok(false) => {
                                println!(
                                    "IMAP LOGIN bad password peer={:?} mailbox={}",
                                    peer, mailbox.address
                                );
                                if let Some(peer_addr) = peer {
                                    record_auth_failure(peer_addr.ip());
                                }
                                let w = reader.get_mut();
                                w.write_all(
                                    format!("{} NO Authentication failed\r\n", tag).as_bytes(),
                                )
                                .await?;
                                w.flush().await?;
                            }
                            Err(e) => {
                                eprintln!(
                                    "IMAP LOGIN auth verify error peer={:?} mailbox={} err={}",
                                    peer, mailbox.address, e
                                );
                                if let Some(peer_addr) = peer {
                                    record_auth_failure(peer_addr.ip());
                                }
                                let w = reader.get_mut();
                                w.write_all(
                                    format!("{} NO Authentication error\r\n", tag).as_bytes(),
                                )
                                .await?;
                                w.flush().await?;
                                eprintln!("auth verify error: {}", e);
                            }
                        }
                    } else {
                        let w = reader.get_mut();
                        w.write_all(
                            format!("{} NO No password set for account\r\n", tag).as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                    }
                } else {
                    if let Some(peer_addr) = peer {
                        record_auth_failure(peer_addr.ip());
                    }
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO No such user\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                }
            }
            "AUTHENTICATE" => {
                let mut auth_parts = args.trim().splitn(2, ' ');
                let mechanism = auth_parts.next().unwrap_or("").to_uppercase();
                let initial_response = auth_parts.next().map(str::trim).filter(|s| !s.is_empty());
                if mechanism != "PLAIN" && mechanism != "SCRAM-SHA-256" {
                    let w = reader.get_mut();
                    w.write_all(
                        format!("{} NO Unsupported authentication mechanism\r\n", tag).as_bytes(),
                    )
                    .await?;
                    w.flush().await?;
                    continue;
                }
                if let Some(peer_addr) = peer {
                    if let Some(rem) = auth_block_remaining(peer_addr.ip()) {
                        let w = reader.get_mut();
                        w.write_all(
                            format!(
                                "{} NO Too many failed auth attempts; try again in {}s\r\n",
                                tag,
                                rem.as_secs()
                            )
                            .as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    }
                }
                if !session_encrypted {
                    let w = reader.get_mut();
                    w.write_all(
                        format!("{} NO Encryption required for authentication\r\n", tag).as_bytes(),
                    )
                    .await?;
                    w.flush().await?;
                    continue;
                }
                let response = if let Some(initial_response) = initial_response {
                    initial_response.to_string()
                } else {
                    {
                        let w = reader.get_mut();
                        w.write_all(b"+ \r\n").await?;
                        w.flush().await?;
                    }
                    let mut auth_line = String::new();
                    let n = reader.read_line(&mut auth_line).await?;
                    if n == 0 {
                        return Ok(());
                    }
                    auth_line.trim_end_matches("\r\n").to_string()
                };
                if mechanism == "SCRAM-SHA-256" {
                    let Some(client_first_msg) = decode_sasl_message(&response) else {
                        let w = reader.get_mut();
                        w.write_all(
                            format!("{} BAD Invalid SCRAM client-first response\r\n", tag)
                                .as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    };
                    let Some((username, client_nonce, client_first_bare)) =
                        parse_scram_client_first(&client_first_msg)
                    else {
                        let w = reader.get_mut();
                        w.write_all(
                            format!("{} BAD Invalid SCRAM client-first message\r\n", tag)
                                .as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    };
                    let user_lookup = auth::saslprep(&username).to_ascii_lowercase();
                    let mut mb: Option<Mailbox> = None;
                    if let Some(dbp) = db_path.as_ref() {
                        let dbp2 = dbp.clone();
                        if user_lookup.contains('@') {
                            match tokio::task::spawn_blocking(move || {
                                rmail_common::db::get_mailbox(dbp2, &user_lookup)
                            })
                            .await
                            {
                                Ok(Ok(Some(m))) => mb = Some(m),
                                Ok(Ok(None)) => {}
                                Ok(Err(e)) => eprintln!("db get_mailbox error: {}", e),
                                Err(e) => eprintln!("db task join error: {}", e),
                            }
                        } else {
                            match tokio::task::spawn_blocking(move || {
                                rmail_common::db::find_mailbox_by_localpart(dbp2, &user_lookup)
                            })
                            .await
                            {
                                Ok(Ok(Some(m))) => mb = Some(m),
                                Ok(Ok(None)) => {}
                                Ok(Err(e)) => eprintln!("db query error: {}", e),
                                Err(e) => eprintln!("db task join error: {}", e),
                            }
                        }
                    }
                    let Some(mailbox) = mb else {
                        if let Some(peer_addr) = peer {
                            record_auth_failure(peer_addr.ip());
                        }
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO Authentication failed\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    };
                    let Some(scram_json) = mailbox.scram.as_ref() else {
                        if let Some(peer_addr) = peer {
                            record_auth_failure(peer_addr.ip());
                        }
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO Authentication failed\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    };
                    let (salt_b64, iterations) = match auth::parse_scram_verifier(scram_json) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!(
                                "IMAP SCRAM verifier parse error peer={:?} mailbox={} err={}",
                                peer, mailbox.address, e
                            );
                            let w = reader.get_mut();
                            w.write_all(format!("{} NO Authentication error\r\n", tag).as_bytes())
                                .await?;
                            w.flush().await?;
                            continue;
                        }
                    };
                    let combined_nonce = format!("{}{}", client_nonce, generate_scram_nonce());
                    let server_first =
                        format!("r={},s={},i={}", combined_nonce, salt_b64, iterations);
                    let server_first_b64 = BASE64_ENGINE.encode(server_first.as_bytes());
                    {
                        let w = reader.get_mut();
                        w.write_all(format!("+ {}\r\n", server_first_b64).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                    let mut final_line = String::new();
                    let n = reader.read_line(&mut final_line).await?;
                    if n == 0 {
                        return Ok(());
                    }
                    let Some(client_final_msg) =
                        decode_sasl_message(final_line.trim_end_matches("\r\n"))
                    else {
                        let w = reader.get_mut();
                        w.write_all(
                            format!("{} BAD Invalid SCRAM client-final response\r\n", tag)
                                .as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    };
                    let Some((client_final_without_proof, proof_b64)) =
                        parse_scram_client_final(&client_final_msg)
                    else {
                        let w = reader.get_mut();
                        w.write_all(
                            format!("{} BAD Invalid SCRAM client-final message\r\n", tag)
                                .as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    };
                    if !client_final_without_proof
                        .split(',')
                        .any(|part| part == format!("r={}", combined_nonce))
                    {
                        if let Some(peer_addr) = peer {
                            record_auth_failure(peer_addr.ip());
                        }
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO Authentication failed\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                    let auth_message = format!(
                        "{},{},{}",
                        client_first_bare, server_first, client_final_without_proof
                    );
                    match auth::verify_scram_proof(scram_json, &auth_message, &proof_b64) {
                        Ok(server_signature) => {
                            let server_final =
                                format!("v={}", BASE64_ENGINE.encode(server_signature));
                            let server_final_b64 = BASE64_ENGINE.encode(server_final.as_bytes());
                            {
                                let w = reader.get_mut();
                                w.write_all(format!("+ {}\r\n", server_final_b64).as_bytes())
                                    .await?;
                                w.flush().await?;
                            }
                            let mut empty_line = String::new();
                            let n = reader.read_line(&mut empty_line).await?;
                            if n == 0 {
                                return Ok(());
                            }
                            authed_mailbox = Some(mailbox.address.to_ascii_lowercase());
                            if let Some(peer_addr) = peer {
                                reset_auth_failures(peer_addr.ip());
                            }
                            let w = reader.get_mut();
                            w.write_all(
                                format!("{} OK AUTHENTICATE completed\r\n", tag).as_bytes(),
                            )
                            .await?;
                            w.flush().await?;
                        }
                        Err(e) => {
                            if let Some(peer_addr) = peer {
                                record_auth_failure(peer_addr.ip());
                            }
                            eprintln!(
                                "IMAP SCRAM verify error peer={:?} mailbox={} err={}",
                                peer, mailbox.address, e
                            );
                            let w = reader.get_mut();
                            w.write_all(format!("{} NO Authentication failed\r\n", tag).as_bytes())
                                .await?;
                            w.flush().await?;
                        }
                    }
                    continue;
                }
                let Some((user, pass)) = decode_authenticate_plain(&response) else {
                    let w = reader.get_mut();
                    w.write_all(
                        format!("{} BAD Invalid AUTHENTICATE PLAIN response\r\n", tag).as_bytes(),
                    )
                    .await?;
                    w.flush().await?;
                    continue;
                };
                println!(
                    "IMAP AUTHENTICATE PLAIN attempt peer={:?} encrypted={} user={:?} password_len={}",
                    peer,
                    session_encrypted,
                    user,
                    pass.len()
                );
                let mut mb: Option<Mailbox> = None;
                if let Some(dbp) = db_path.as_ref() {
                    let user_lookup = user.to_ascii_lowercase();
                    if user_lookup.contains('@') {
                        let dbp2 = dbp.clone();
                        match tokio::task::spawn_blocking(move || {
                            rmail_common::db::get_mailbox(dbp2, &user_lookup)
                        })
                        .await
                        {
                            Ok(Ok(Some(m))) => mb = Some(m),
                            Ok(Ok(None)) => {}
                            Ok(Err(e)) => eprintln!("db get_mailbox error: {}", e),
                            Err(e) => eprintln!("db task join error: {}", e),
                        }
                    } else {
                        let dbp2 = dbp.clone();
                        let user_local = user.to_string();
                        match tokio::task::spawn_blocking(move || {
                            rmail_common::db::find_mailbox_by_localpart(dbp2, &user_local)
                        })
                        .await
                        {
                            Ok(Ok(Some(m))) => mb = Some(m),
                            Ok(Ok(None)) => {}
                            Ok(Err(e)) => eprintln!("db query error: {}", e),
                            Err(e) => eprintln!("db task join error: {}", e),
                        }
                    }
                }
                let Some(mailbox) = mb else {
                    if let Some(peer_addr) = peer {
                        record_auth_failure(peer_addr.ip());
                    }
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication failed\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                };
                let Some(hash) = mailbox.password_hash.as_ref() else {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO No password set for account\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                };
                match auth::verify_password(&pass, hash) {
                    Ok(true) => {
                        authed_mailbox = Some(mailbox.address.to_ascii_lowercase());
                        if let Some(peer_addr) = peer {
                            reset_auth_failures(peer_addr.ip());
                        }
                        let w = reader.get_mut();
                        w.write_all(format!("{} OK AUTHENTICATE completed\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                    Ok(false) => {
                        if let Some(peer_addr) = peer {
                            record_auth_failure(peer_addr.ip());
                        }
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO Authentication failed\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                    Err(e) => {
                        if let Some(peer_addr) = peer {
                            record_auth_failure(peer_addr.ip());
                        }
                        eprintln!(
                            "IMAP AUTHENTICATE PLAIN verify error peer={:?} mailbox={} err={}",
                            peer, mailbox.address, e
                        );
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO Authentication error\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                }
            }
            "NOOP" => {
                let w = reader.get_mut();
                w.write_all(format!("{} OK NOOP completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "CHECK" => {
                if selected.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let w = reader.get_mut();
                w.write_all(format!("{} OK CHECK completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "UNSELECT" => {
                if selected.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                selected = None;
                let w = reader.get_mut();
                w.write_all(format!("{} OK UNSELECT completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "APPEND" => {
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let Some((mailbox_name, flags, literal_len)) = parse_append_args(args) else {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD Invalid APPEND arguments\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                };
                {
                    let w = reader.get_mut();
                    w.write_all(b"+ Ready for literal data\r\n").await?;
                    w.flush().await?;
                }
                let mut literal = vec![0u8; literal_len];
                if let Err(e) = reader.read_exact(&mut literal).await {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Error reading literal\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    eprintln!("IMAP APPEND literal read error peer={:?}: {}", peer, e);
                    continue;
                }
                let addr = authed_mailbox.as_ref().unwrap();
                let (local, domain) = address_parts(addr)?;
                let mail_root_clone = mail_root.clone();
                let mailbox_for_task = mailbox_name.clone();
                let append_result = tokio::task::spawn_blocking(move || {
                    rmail_common::imap_state::append_message(
                        Path::new(&mail_root_clone),
                        &domain,
                        &local,
                        &mailbox_for_task,
                        &literal,
                        flags,
                    )
                })
                .await?;
                match append_result {
                    Ok((uidvalidity, uid)) => {
                        if let Some(addr) = authed_mailbox.as_ref() {
                            if selected
                                .as_ref()
                                .map(|sel| sel.mailbox.eq_ignore_ascii_case(&mailbox_name))
                                .unwrap_or(false)
                            {
                                selected = Some(
                                    load_selected_mailbox(&mail_root, addr, &mailbox_name).await?,
                                );
                            }
                        }
                        let w = reader.get_mut();
                        w.write_all(
                            format!(
                                "{} OK [APPENDUID {} {}] APPEND completed\r\n",
                                tag, uidvalidity, uid
                            )
                            .as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                    }
                    Err(e) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO APPEND failed: {}\r\n", tag, e).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                }
            }
            "LIST" => {
                // Require authentication to list user's mailboxes in this simple implementation
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let Some((reference, pattern)) = parse_list_args(args) else {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD Invalid LIST arguments\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                };
                let addr = authed_mailbox.as_ref().unwrap();
                let (local, domain) = address_parts(addr)?;
                let mail_root_clone = mail_root.clone();
                let boxes = tokio::task::spawn_blocking(move || {
                    maildir::list_mailboxes(Path::new(&mail_root_clone), &domain, &local)
                })
                .await??;
                println!(
                    "IMAP LIST peer={:?} returning {} mailboxes",
                    peer,
                    boxes.len()
                );
                let w = reader.get_mut();
                for (name, special) in boxes {
                    if !mailbox_pattern_matches(&name, &reference, &pattern) {
                        continue;
                    }
                    let mut attrs = vec!["\\HasNoChildren".to_string()];
                    if let Some(special) = special {
                        attrs.push(special);
                    }
                    w.write_all(
                        format!("* LIST ({}) \"/\" \"{}\"\r\n", attrs.join(" "), name).as_bytes(),
                    )
                    .await?;
                }
                w.write_all(format!("{} OK LIST completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "LSUB" => {
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let Some((reference, pattern)) = parse_list_args(args) else {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD Invalid LSUB arguments\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                };
                let addr = authed_mailbox.as_ref().unwrap();
                let (local, domain) = address_parts(addr)?;
                let mail_root_clone = mail_root.clone();
                let boxes = tokio::task::spawn_blocking(move || {
                    maildir::list_subscribed_mailboxes(Path::new(&mail_root_clone), &domain, &local)
                })
                .await??;
                println!("IMAP LSUB peer={:?} returning subscriptions", peer);
                let w = reader.get_mut();
                for (name, special) in boxes {
                    if !mailbox_pattern_matches(&name, &reference, &pattern) {
                        continue;
                    }
                    let mut attrs = vec!["\\HasNoChildren".to_string()];
                    if let Some(special) = special {
                        attrs.push(special);
                    }
                    w.write_all(
                        format!("* LSUB ({}) \"/\" \"{}\"\r\n", attrs.join(" "), name).as_bytes(),
                    )
                    .await?;
                }
                w.write_all(format!("{} OK LSUB completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "NAMESPACE" => {
                println!("IMAP NAMESPACE peer={:?}", peer);
                let w = reader.get_mut();
                w.write_all(b"* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n")
                    .await?;
                w.write_all(format!("{} OK NAMESPACE completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "CREATE" => {
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let mailbox_name = unquote(args.trim()).to_string();
                let addr = authed_mailbox.as_ref().unwrap();
                let (local, domain) = address_parts(addr)?;
                let mail_root_clone = mail_root.clone();
                tokio::task::spawn_blocking(move || {
                    maildir::create_mailbox(
                        Path::new(&mail_root_clone),
                        &domain,
                        &local,
                        &mailbox_name,
                    )
                })
                .await??;
                let w = reader.get_mut();
                w.write_all(format!("{} OK CREATE completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "DELETE" => {
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let mailbox_name = unquote(args.trim()).to_string();
                let addr = authed_mailbox.as_ref().unwrap();
                let (local, domain) = address_parts(addr)?;
                let mail_root_clone = mail_root.clone();
                match tokio::task::spawn_blocking(move || {
                    maildir::delete_mailbox(
                        Path::new(&mail_root_clone),
                        &domain,
                        &local,
                        &mailbox_name,
                    )
                })
                .await?
                {
                    Ok(()) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} OK DELETE completed\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                    Err(e) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO DELETE failed: {}\r\n", tag, e).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                }
            }
            "RENAME" => {
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let Some((source_mailbox, rest)) = split_first_imap_astring(args) else {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD Invalid RENAME arguments\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                };
                let Some((destination_mailbox, _)) = split_first_imap_astring(rest) else {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD Invalid RENAME arguments\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                };
                let addr = authed_mailbox.as_ref().unwrap();
                let (local, domain) = address_parts(addr)?;
                let mail_root_clone = mail_root.clone();
                let source_for_task = source_mailbox.clone();
                let destination_for_task = destination_mailbox.clone();
                match tokio::task::spawn_blocking(move || {
                    maildir::rename_mailbox(
                        Path::new(&mail_root_clone),
                        &domain,
                        &local,
                        &source_for_task,
                        &destination_for_task,
                    )
                })
                .await?
                {
                    Ok(()) => {
                        if let Some(addr) = authed_mailbox.as_ref() {
                            if selected
                                .as_ref()
                                .map(|sel| sel.mailbox.eq_ignore_ascii_case(&source_mailbox))
                                .unwrap_or(false)
                            {
                                selected = Some(
                                    load_selected_mailbox(&mail_root, addr, &destination_mailbox)
                                        .await?,
                                );
                            }
                        }
                        let w = reader.get_mut();
                        w.write_all(format!("{} OK RENAME completed\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                    Err(e) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO RENAME failed: {}\r\n", tag, e).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                }
            }
            "SUBSCRIBE" | "UNSUBSCRIBE" => {
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let mailbox_name = unquote(args.trim()).to_string();
                let addr = authed_mailbox.as_ref().unwrap();
                let (local, domain) = address_parts(addr)?;
                let mail_root_clone = mail_root.clone();
                let subscribed = cmd == "SUBSCRIBE";
                match tokio::task::spawn_blocking(move || {
                    maildir::set_mailbox_subscription(
                        Path::new(&mail_root_clone),
                        &domain,
                        &local,
                        &mailbox_name,
                        subscribed,
                    )
                })
                .await?
                {
                    Ok(()) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} OK {} completed\r\n", tag, cmd).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                    Err(e) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO {} failed: {}\r\n", tag, cmd, e).as_bytes())
                            .await?;
                        w.flush().await?;
                    }
                }
            }
            "ID" => {
                let w = reader.get_mut();
                w.write_all(b"* ID (\"name\" \"rMail\" \"vendor\" \"rMail\")\r\n")
                    .await?;
                w.write_all(format!("{} OK ID completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "SELECT" | "EXAMINE" => {
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let mailbox_name = unquote(args.trim());
                println!(
                    "IMAP {} peer={:?} raw_args={:?} normalized_mailbox={:?}",
                    cmd, peer, args, mailbox_name
                );
                let addr = authed_mailbox.as_ref().unwrap();
                match load_selected_mailbox(&mail_root, addr, mailbox_name).await {
                    Ok(sel) => {
                        let count = sel.msgs.len();
                        let uidvalidity = sel.uidvalidity;
                        let uidnext = next_uid(&sel);
                        let unseen = first_unseen(&sel);
                        println!(
                            "IMAP {} success peer={:?} mailbox={} exists={} uidvalidity={}",
                            cmd, peer, mailbox_name, count, uidvalidity
                        );
                        selected = Some(sel);
                        let w = reader.get_mut();
                        w.write_all(b"* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n")
                            .await?;
                        w.flush().await?;
                        let w = reader.get_mut();
                        w.write_all(
                            b"* OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft \\*)] Flags permitted.\r\n",
                        )
                        .await?;
                        w.flush().await?;
                        let w = reader.get_mut();
                        w.write_all(format!("* {} EXISTS\r\n", count).as_bytes())
                            .await?;
                        w.flush().await?;
                        let w = reader.get_mut();
                        w.write_all(b"* 0 RECENT\r\n").await?;
                        w.flush().await?;
                        let w = reader.get_mut();
                        w.write_all(
                            format!("* OK [UIDVALIDITY {}] UIDs valid\r\n", uidvalidity).as_bytes(),
                        )
                        .await?;
                        w.write_all(
                            format!("* OK [UIDNEXT {}] Predicted next UID\r\n", uidnext).as_bytes(),
                        )
                        .await?;
                        w.write_all(
                            format!("* OK [UNSEEN {}] First unseen\r\n", unseen).as_bytes(),
                        )
                        .await?;
                        w.write_all(
                            format!(
                                "{} OK [{}] {} completed\r\n",
                                tag,
                                if cmd == "EXAMINE" {
                                    "READ-ONLY"
                                } else {
                                    "READ-WRITE"
                                },
                                cmd
                            )
                            .as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                    }
                    Err(e) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO Error opening mailbox\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        eprintln!("load_selected_mailbox error: {}", e);
                    }
                }
            }
            "STATUS" => {
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let mut parts = args.trim().splitn(2, ' ');
                let mailbox_name = unquote(parts.next().unwrap_or(""));
                let items = parts.next().unwrap_or("");
                let addr = authed_mailbox.as_ref().unwrap();
                let sel = match load_selected_mailbox(&mail_root, addr, mailbox_name).await {
                    Ok(sel) => sel,
                    Err(_) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO No such mailbox\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                let items_upper = normalize_fetch_items(items);
                println!(
                    "IMAP STATUS peer={:?} mailbox={:?} items={:?}",
                    peer, mailbox_name, items_upper
                );
                let mut values = Vec::new();
                if items_upper.iter().any(|i| i == "MESSAGES") {
                    values.push(format!("MESSAGES {}", sel.msgs.len()));
                }
                if items_upper.iter().any(|i| i == "UIDNEXT") {
                    values.push(format!("UIDNEXT {}", next_uid(&sel)));
                }
                if items_upper.iter().any(|i| i == "UIDVALIDITY") {
                    values.push(format!("UIDVALIDITY {}", sel.uidvalidity));
                }
                if items_upper.iter().any(|i| i == "UNSEEN") {
                    values.push(format!("UNSEEN {}", unseen_count(&sel)));
                }
                if items_upper.iter().any(|i| i == "RECENT") {
                    values.push("RECENT 0".to_string());
                }
                let w = reader.get_mut();
                println!(
                    "IMAP STATUS response peer={:?} mailbox={} values={:?}",
                    peer, sel.mailbox, values
                );
                w.write_all(
                    format!("* STATUS \"{}\" ({})\r\n", sel.mailbox, values.join(" ")).as_bytes(),
                )
                .await?;
                w.write_all(format!("{} OK STATUS completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "STARTTLS" => {
                if tls_ctx.is_none() {
                    println!("IMAP STARTTLS unavailable peer={:?}", peer);
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO TLS not available\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let w = reader.get_mut();
                w.write_all(format!("{} OK Begin TLS negotiation now\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
                println!("IMAP STARTTLS begin peer={:?}", peer);
                // perform TLS handshake and continue inside TLS context
                let inner = reader.into_inner();
                match tls_ctx.clone().unwrap().acceptor.accept(inner).await {
                    Ok(tls_stream) => {
                        println!("IMAP STARTTLS handshake success peer={:?}", peer);
                        // Box the TLS stream to the AsyncStream trait object and recurse inside TLS context.
                        // Pass the same tls_ctx along and mark the session as encrypted.
                        let fut = Box::pin(process_stream(
                            Box::new(tls_stream),
                            mail_root,
                            tls_ctx.clone(),
                            db_path.clone(),
                            peer,
                            true,
                        ));
                        return fut.await;
                    }
                    Err(e) => {
                        eprintln!("IMAP STARTTLS handshake failed peer={:?}: {}", peer, e);
                        return Err(anyhow::anyhow!("TLS accept failed: {}", e));
                    }
                }
            }

            "FETCH" => {
                if authed_mailbox.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO Authentication required\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                // Ensure a mailbox has been selected with SELECT first
                if selected.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let args = args.trim();
                if let Some(addr) = authed_mailbox.as_ref() {
                    let mailbox = selected_mailbox_name(&selected).to_string();
                    selected = Some(load_selected_mailbox(&mail_root, addr, &mailbox).await?);
                }
                let mut a = args.splitn(2, ' ');
                let seq_set = a.next().unwrap_or("");
                let what = a.next().unwrap_or("");
                let requested = normalize_fetch_items(what);
                println!(
                    "IMAP FETCH peer={:?} seq_set={} requested={:?}",
                    peer, seq_set, requested
                );
                let sel = selected.as_ref().unwrap();
                let total = sel.msgs.len();
                let seqs: Vec<usize> = if seq_set == "1:*" {
                    (1..=total).collect()
                } else if seq_set.contains(':') {
                    let mut parts = seq_set.split(':');
                    let start = parts
                        .next()
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(1);
                    let end = parts
                        .next()
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(total);
                    (start..=end).collect()
                } else {
                    if let Ok(v) = seq_set.parse::<usize>() {
                        vec![v]
                    } else {
                        vec![]
                    }
                };
                for seq in seqs {
                    if seq == 0 || seq > total {
                        continue;
                    }
                    let idx = seq - 1;
                    let uid = sel.msgs[idx].0;
                    let flags = sel.msgs[idx].2.clone();
                    let path = sel.msgs[idx].1.clone();
                    match write_fetch_response(
                        &mut reader,
                        seq,
                        uid,
                        &flags,
                        path,
                        &requested,
                        what,
                        false,
                    )
                    .await
                    {
                        Ok(()) => {}
                        Err(e) => {
                            let w = reader.get_mut();
                            w.write_all(format!("{} NO Error reading message\r\n", tag).as_bytes())
                                .await?;
                            w.flush().await?;
                            eprintln!("FETCH response error peer={:?}: {}", peer, e);
                        }
                    }
                }
                let w = reader.get_mut();
                w.write_all(format!("{} OK FETCH completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }

            "COPY" | "MOVE" => {
                if selected.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let mut parts = args.trim().splitn(2, ' ');
                let seq_set = parts.next().unwrap_or("");
                let destination = unquote(parts.next().unwrap_or("").trim()).to_string();
                let sel = selected.as_ref().unwrap();
                let seqs = seqs_from_set(seq_set, sel.msgs.len());
                let source_uids = seqs
                    .iter()
                    .filter_map(|seq| {
                        (*seq > 0 && *seq <= sel.msgs.len()).then_some(sel.msgs[*seq - 1].0)
                    })
                    .collect::<Vec<_>>();
                let mut destination_uids = Vec::new();
                let mut command_error = None;
                for uid in &source_uids {
                    let mail_root = mail_root.clone();
                    let domain = sel.domain.clone();
                    let local = sel.local.clone();
                    let mailbox = sel.mailbox.clone();
                    let destination = destination.clone();
                    let uid = *uid;
                    let copied = if cmd == "COPY" {
                        tokio::task::spawn_blocking(move || {
                            rmail_common::imap_state::copy_message_by_uid(
                                Path::new(&mail_root),
                                &domain,
                                &local,
                                &mailbox,
                                uid,
                                &destination,
                            )
                        })
                        .await?
                    } else {
                        tokio::task::spawn_blocking(move || {
                            maildir::move_message_by_uid_for_mailbox(
                                Path::new(&mail_root),
                                &domain,
                                &local,
                                &mailbox,
                                uid,
                                &destination,
                            )
                        })
                        .await?
                    };
                    match copied {
                        Ok(Some(dest_uid)) => destination_uids.push(dest_uid),
                        Ok(None) => {}
                        Err(e) => {
                            command_error = Some(e);
                            break;
                        }
                    }
                }
                if let Some(e) = command_error {
                    let w = reader.get_mut();
                    w.write_all(format!("{} NO {} failed: {}\r\n", tag, cmd, e).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let destination_sel = match load_selected_mailbox(
                    &mail_root,
                    authed_mailbox.as_ref().unwrap(),
                    &destination,
                )
                .await
                {
                    Ok(sel) => sel,
                    Err(e) => {
                        let w = reader.get_mut();
                        w.write_all(format!("{} NO {} failed: {}\r\n", tag, cmd, e).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                };
                if let Some(addr) = authed_mailbox.as_ref() {
                    let mailbox = selected_mailbox_name(&selected).to_string();
                    selected = Some(load_selected_mailbox(&mail_root, addr, &mailbox).await?);
                }
                let copyuid =
                    copy_uid_pairs(&source_uids, &destination_uids, destination_sel.uidvalidity)
                        .unwrap_or_default();
                let w = reader.get_mut();
                w.write_all(format!("{} OK {}{} completed\r\n", tag, copyuid, cmd).as_bytes())
                    .await?;
                w.flush().await?;
            }

            "UID" => {
                let mut a = args.trim().splitn(2, ' ');
                let subcmd = a.next().unwrap_or("").to_uppercase();
                let subargs = a.next().unwrap_or("");
                if subcmd.as_str() == "FETCH" {
                    if selected.is_none() {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                    if let Some(addr) = authed_mailbox.as_ref() {
                        let mailbox = selected_mailbox_name(&selected).to_string();
                        selected = Some(load_selected_mailbox(&mail_root, addr, &mailbox).await?);
                    }
                    let mut b = subargs.splitn(2, ' ');
                    let uid_set = b.next().unwrap_or("");
                    let what = b.next().unwrap_or("");
                    let requested = normalize_fetch_items(what);
                    println!(
                        "IMAP UID FETCH peer={:?} uid_set={} requested={:?}",
                        peer, uid_set, requested
                    );
                    let sel = selected.as_ref().unwrap();
                    // Build list of UIDs to return, handling ranges
                    let uids = uids_from_set(uid_set, &sel.msgs);
                    for uid in uids {
                        if let Some(pos) = sel.msgs.iter().position(|(u, _, _)| *u == uid) {
                            let seq = pos + 1;
                            let uid = sel.msgs[pos].0;
                            let flags = sel.msgs[pos].2.clone();
                            let path = sel.msgs[pos].1.clone();
                            match write_fetch_response(
                                &mut reader,
                                seq,
                                uid,
                                &flags,
                                path,
                                &requested,
                                what,
                                true,
                            )
                            .await
                            {
                                Ok(()) => {}
                                Err(e) => {
                                    let w = reader.get_mut();
                                    w.write_all(
                                        format!("{} NO Error reading message\r\n", tag).as_bytes(),
                                    )
                                    .await?;
                                    w.flush().await?;
                                    eprintln!("UID FETCH response error peer={:?}: {}", peer, e);
                                }
                            }
                        }
                    }
                    let w = reader.get_mut();
                    w.write_all(format!("{} OK UID FETCH completed\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                } else if subcmd.as_str() == "SEARCH" {
                    if selected.is_none() {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                    let sel = selected.as_ref().unwrap();
                    let criteria = parse_search(subargs).unwrap_or(SearchCriterion::All);
                    println!("IMAP UID SEARCH peer={:?} criteria={:?}", peer, criteria);
                    let mut matches = Vec::new();
                    for (idx, (uid, path, flags)) in sel.msgs.iter().enumerate() {
                        let data = tokio::task::spawn_blocking({
                            let path = path.clone();
                            move || std::fs::read(path)
                        })
                        .await??;
                        let msg = SearchMessage {
                            seq: idx + 1,
                            uid: *uid,
                            flags,
                            path,
                            data: &data,
                        };
                        if search_matches(&criteria, &msg, sel.msgs.len()) {
                            matches.push(uid.to_string());
                        }
                    }
                    let w = reader.get_mut();
                    println!("IMAP UID SEARCH matches peer={:?} uids={:?}", peer, matches);
                    w.write_all(format!("* SEARCH {}\r\n", matches.join(" ")).as_bytes())
                        .await?;
                    w.write_all(format!("{} OK UID SEARCH completed\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                } else if subcmd.as_str() == "STORE" {
                    if selected.is_none() {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                    let sel = selected.as_ref().unwrap();
                    let mut parts = subargs.trim().splitn(3, ' ');
                    let uid_set = parts.next().unwrap_or("");
                    let op = parts.next().unwrap_or("");
                    let flags = parse_store_items(parts.next().unwrap_or(""));
                    let silent = op.to_uppercase().ends_with(".SILENT");
                    let ids = uids_from_set(uid_set, &sel.msgs);
                    println!(
                        "IMAP UID STORE peer={:?} uid_set={} ids={:?} op={} flags={:?} silent={}",
                        peer, uid_set, ids, op, flags, silent
                    );
                    for uid in ids {
                        if let Some(pos) = sel.msgs.iter().position(|(u, _, _)| *u == uid) {
                            let seq = pos + 1;
                            let current = sel.msgs[pos].2.clone();
                            let updated =
                                apply_flag_operation(&current, &op.to_uppercase(), &flags);
                            println!(
                                "IMAP UID STORE apply peer={:?} seq={} uid={} old_flags={:?} new_flags={:?}",
                                peer, seq, uid, current, updated
                            );
                            maildir::set_uid_flags_for_mailbox(
                                Path::new(&mail_root),
                                &sel.domain,
                                &sel.local,
                                &sel.mailbox,
                                uid,
                                updated.clone(),
                            )?;
                            if !silent {
                                let w = reader.get_mut();
                                w.write_all(
                                    format!(
                                        "* {} FETCH (FLAGS ({}) UID {})\r\n",
                                        seq,
                                        updated.join(" "),
                                        uid
                                    )
                                    .as_bytes(),
                                )
                                .await?;
                                w.flush().await?;
                            }
                        }
                    }
                    if let Some(addr) = authed_mailbox.as_ref() {
                        let mailbox = selected_mailbox_name(&selected).to_string();
                        selected = Some(load_selected_mailbox(&mail_root, addr, &mailbox).await?);
                    }
                    let w = reader.get_mut();
                    w.write_all(format!("{} OK UID STORE completed\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                } else if subcmd.as_str() == "EXPUNGE" {
                    if selected.is_none() {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                    let uid_set = subargs.trim();
                    let sel = selected.as_ref().unwrap();
                    let requested = uids_from_set(uid_set, &sel.msgs);
                    let requested: std::collections::HashSet<u64> = requested.into_iter().collect();
                    let mut deleted: Vec<(usize, u64)> = sel
                        .msgs
                        .iter()
                        .enumerate()
                        .filter_map(|(idx, (uid, _, flags))| {
                            (requested.contains(uid)
                                && flags.iter().any(|f| f.eq_ignore_ascii_case("\\Deleted")))
                            .then_some((idx + 1, *uid))
                        })
                        .collect();
                    deleted.sort_by(|a, b| b.0.cmp(&a.0));
                    for (_, uid) in &deleted {
                        maildir::delete_message_by_uid_for_mailbox(
                            Path::new(&mail_root),
                            &sel.domain,
                            &sel.local,
                            &sel.mailbox,
                            *uid,
                        )?;
                    }
                    let w = reader.get_mut();
                    for (seq, _) in &deleted {
                        w.write_all(format!("* {} EXPUNGE\r\n", seq).as_bytes())
                            .await?;
                    }
                    if let Some(addr) = authed_mailbox.as_ref() {
                        let mailbox = selected_mailbox_name(&selected).to_string();
                        selected = Some(load_selected_mailbox(&mail_root, addr, &mailbox).await?);
                    }
                    w.write_all(format!("{} OK UID EXPUNGE completed\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                } else if subcmd.as_str() == "COPY" || subcmd.as_str() == "MOVE" {
                    if selected.is_none() {
                        let w = reader.get_mut();
                        w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                            .await?;
                        w.flush().await?;
                        continue;
                    }
                    let mut parts = subargs.trim().splitn(2, ' ');
                    let uid_set = parts.next().unwrap_or("");
                    let destination = unquote(parts.next().unwrap_or("").trim()).to_string();
                    let sel = selected.as_ref().unwrap();
                    let source_uids = uids_from_set(uid_set, &sel.msgs);
                    let mut destination_uids = Vec::new();
                    let mut command_error = None;
                    for uid in &source_uids {
                        let mail_root = mail_root.clone();
                        let domain = sel.domain.clone();
                        let local = sel.local.clone();
                        let mailbox = sel.mailbox.clone();
                        let destination = destination.clone();
                        let uid = *uid;
                        let copied = if subcmd == "COPY" {
                            tokio::task::spawn_blocking(move || {
                                rmail_common::imap_state::copy_message_by_uid(
                                    Path::new(&mail_root),
                                    &domain,
                                    &local,
                                    &mailbox,
                                    uid,
                                    &destination,
                                )
                            })
                            .await?
                        } else {
                            tokio::task::spawn_blocking(move || {
                                maildir::move_message_by_uid_for_mailbox(
                                    Path::new(&mail_root),
                                    &domain,
                                    &local,
                                    &mailbox,
                                    uid,
                                    &destination,
                                )
                            })
                            .await?
                        };
                        match copied {
                            Ok(Some(dest_uid)) => destination_uids.push(dest_uid),
                            Ok(None) => {}
                            Err(e) => {
                                command_error = Some(e);
                                break;
                            }
                        }
                    }
                    if let Some(e) = command_error {
                        let w = reader.get_mut();
                        w.write_all(
                            format!("{} NO UID {} failed: {}\r\n", tag, subcmd, e).as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                        continue;
                    }
                    let destination_sel = match load_selected_mailbox(
                        &mail_root,
                        authed_mailbox.as_ref().unwrap(),
                        &destination,
                    )
                    .await
                    {
                        Ok(sel) => sel,
                        Err(e) => {
                            let w = reader.get_mut();
                            w.write_all(
                                format!("{} NO UID {} failed: {}\r\n", tag, subcmd, e).as_bytes(),
                            )
                            .await?;
                            w.flush().await?;
                            continue;
                        }
                    };
                    if let Some(addr) = authed_mailbox.as_ref() {
                        let mailbox = selected_mailbox_name(&selected).to_string();
                        selected = Some(load_selected_mailbox(&mail_root, addr, &mailbox).await?);
                    }
                    let copyuid = copy_uid_pairs(
                        &source_uids,
                        &destination_uids,
                        destination_sel.uidvalidity,
                    )
                    .unwrap_or_default();
                    let w = reader.get_mut();
                    w.write_all(
                        format!("{} OK {}UID {} completed\r\n", tag, copyuid, subcmd).as_bytes(),
                    )
                    .await?;
                    w.flush().await?;
                } else {
                    log_unsupported_imap(peer, &selected, tag, &format!("UID {}", subcmd), subargs);
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD Unsupported UID subcommand\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                }
            }
            "SEARCH" => {
                if selected.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let sel = selected.as_ref().unwrap();
                let criteria = parse_search(args).unwrap_or(SearchCriterion::All);
                println!("IMAP SEARCH peer={:?} criteria={:?}", peer, criteria);
                let mut matches = Vec::new();
                for (idx, (uid, path, flags)) in sel.msgs.iter().enumerate() {
                    let data = tokio::task::spawn_blocking({
                        let path = path.clone();
                        move || std::fs::read(path)
                    })
                    .await??;
                    let msg = SearchMessage {
                        seq: idx + 1,
                        uid: *uid,
                        flags,
                        path,
                        data: &data,
                    };
                    if search_matches(&criteria, &msg, sel.msgs.len()) {
                        matches.push((idx + 1).to_string());
                    }
                }
                let w = reader.get_mut();
                println!("IMAP SEARCH matches peer={:?} seqs={:?}", peer, matches);
                w.write_all(format!("* SEARCH {}\r\n", matches.join(" ")).as_bytes())
                    .await?;
                w.write_all(format!("{} OK SEARCH completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "STORE" => {
                if selected.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let sel = selected.as_ref().unwrap();
                let mut parts = args.trim().splitn(3, ' ');
                let seq_set = parts.next().unwrap_or("");
                let op = parts.next().unwrap_or("");
                let flags = parse_store_items(parts.next().unwrap_or(""));
                let silent = op.to_uppercase().ends_with(".SILENT");
                println!(
                    "IMAP STORE peer={:?} seq_set={} op={} flags={:?} silent={}",
                    peer, seq_set, op, flags, silent
                );
                for seq in seqs_from_set(seq_set, sel.msgs.len()) {
                    if seq == 0 || seq > sel.msgs.len() {
                        continue;
                    }
                    let idx = seq - 1;
                    let uid = sel.msgs[idx].0;
                    let current = sel.msgs[idx].2.clone();
                    let updated = apply_flag_operation(&current, &op.to_uppercase(), &flags);
                    println!(
                        "IMAP STORE apply peer={:?} seq={} uid={} old_flags={:?} new_flags={:?}",
                        peer, seq, uid, current, updated
                    );
                    maildir::set_uid_flags_for_mailbox(
                        Path::new(&mail_root),
                        &sel.domain,
                        &sel.local,
                        &sel.mailbox,
                        uid,
                        updated.clone(),
                    )?;
                    if !silent {
                        let w = reader.get_mut();
                        w.write_all(
                            format!(
                                "* {} FETCH (FLAGS ({}) UID {})\r\n",
                                seq,
                                updated.join(" "),
                                uid
                            )
                            .as_bytes(),
                        )
                        .await?;
                        w.flush().await?;
                    }
                }
                if let Some(addr) = authed_mailbox.as_ref() {
                    let mailbox = selected_mailbox_name(&selected).to_string();
                    selected = Some(load_selected_mailbox(&mail_root, addr, &mailbox).await?);
                }
                let w = reader.get_mut();
                w.write_all(format!("{} OK STORE completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "EXPUNGE" => {
                if selected.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let sel = selected.as_ref().unwrap();
                let deleted = expunge_deleted(&mail_root, sel).await?;
                println!("IMAP EXPUNGE peer={:?} removed={:?}", peer, deleted);
                let w = reader.get_mut();
                for (seq, _) in &deleted {
                    w.write_all(format!("* {} EXPUNGE\r\n", seq).as_bytes())
                        .await?;
                }
                selected = if let Some(addr) = authed_mailbox.as_ref() {
                    let mailbox = selected_mailbox_name(&selected).to_string();
                    Some(load_selected_mailbox(&mail_root, addr, &mailbox).await?)
                } else {
                    None
                };
                w.write_all(format!("{} OK EXPUNGE completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "CLOSE" => {
                if selected.is_none() {
                    let w = reader.get_mut();
                    w.write_all(format!("{} BAD No mailbox selected\r\n", tag).as_bytes())
                        .await?;
                    w.flush().await?;
                    continue;
                }
                let sel = selected.as_ref().unwrap();
                let deleted = expunge_deleted(&mail_root, sel).await?;
                println!("IMAP CLOSE peer={:?} expunged={:?}", peer, deleted);
                selected = None;
                let w = reader.get_mut();
                w.write_all(format!("{} OK CLOSE completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "IDLE" => {
                let idle_tag = tag.to_string();
                let w = reader.get_mut();
                w.write_all(b"+ idling\r\n").await?;
                w.flush().await?;
                let mut idle_line = String::new();
                loop {
                    idle_line.clear();
                    let n = reader.read_line(&mut idle_line).await?;
                    if n == 0 {
                        return Ok(());
                    }
                    if idle_line
                        .trim_end_matches("\r\n")
                        .eq_ignore_ascii_case("DONE")
                    {
                        break;
                    }
                }
                let w = reader.get_mut();
                w.write_all(format!("{} OK IDLE completed\r\n", idle_tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
            "LOGOUT" => {
                let w = reader.get_mut();
                w.write_all(b"* BYE Logging out\r\n").await?;
                w.flush().await?;
                let w = reader.get_mut();
                w.write_all(format!("{} OK LOGOUT completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
                break;
            }
            _ => {
                log_unsupported_imap(peer, &selected, tag, &cmd, args);
                let w = reader.get_mut();
                w.write_all(format!("{} BAD Unknown or unimplemented command\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
        }
    }
    Ok(())
}
