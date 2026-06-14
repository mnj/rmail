use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use rmail_common::db::Mailbox;
use rmail_common::{auth, config::Config, maildir};
use std::path::Path;
use std::time::{Duration, Instant};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

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
        assert!(!plain_caps.contains("STARTTLS"));

        let tls_caps = capability_tokens(true, None);
        assert!(!tls_caps.contains("LOGINDISABLED"));
        assert!(!tls_caps.contains("STARTTLS"));
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
            b"Date: Sun, 14 Jun 2026 12:00:00 +0000\r\nSubject: macro\r\n\r\nbody\r\n",
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

        let _logout = read_until_contains(&mut reader, "A005 OK").await;
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
    for addr in imap_addrs {
        let mail_root_clone = mail_root.clone();
        let acceptor_clone = tls_context.clone();
        let db_clone = db_path.clone();
        tokio::spawn(async move {
            if let Err(e) =
                run_plain_listener(&addr, mail_root_clone, acceptor_clone, db_clone).await
            {
                eprintln!("IMAP plain listener {} failed: {}", addr, e);
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
                let mail_root_clone = mail_root.clone();
                let ctx_clone = ctx.clone();
                let db_clone = db_path.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        run_imaps_listener(&addr, ctx_clone, mail_root_clone, db_clone).await
                    {
                        eprintln!("IMAPS listener {} failed: {}", addr, e);
                    }
                });
            }
        }
    }

    // keep running
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

async fn run_plain_listener(
    addr: &str,
    mail_root: String,
    tls_ctx: Option<Arc<tls::TlsContext>>,
    db_path: Option<String>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("rMail IMAPD listening on {}", addr);
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
    addr: &str,
    ctx: Arc<tls::TlsContext>,
    mail_root: String,
    db_path: Option<String>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("rMail IMAPD (IMAPS) listening on {}", addr);
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
    let mut caps = vec!["IMAP4rev1", "UIDPLUS", "NAMESPACE", "SPECIAL-USE"];
    if !session_encrypted {
        caps.push("LOGINDISABLED");
        if tls_ctx.is_some() {
            caps.push("STARTTLS");
        }
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

fn normalize_fetch_items(spec: &str) -> Vec<String> {
    let trimmed = spec.trim();
    let inner = trimmed
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(trimmed);
    let mut out = Vec::new();
    for item in inner.split_whitespace().map(|s| s.to_uppercase()) {
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

fn requested_header_fields(spec: &str) -> Option<Vec<String>> {
    let upper = spec.to_uppercase();
    let marker = "HEADER.FIELDS (";
    let start = upper.find(marker)?;
    let after = &spec[start + marker.len()..];
    let end = after.find(')')?;
    let fields = after[..end]
        .split_whitespace()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    Some(fields)
}

fn extract_header_literal(data: &[u8], requested_fields: Option<&[String]>) -> Vec<u8> {
    let header_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
        .unwrap_or(data.len());
    let header = &data[..header_end];
    let Some(fields) = requested_fields else {
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
            include_current = fields.iter().any(|f| f.eq_ignore_ascii_case(name.trim()));
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

fn envelope_response(data: &[u8]) -> String {
    let date = header_value(data, "Date").unwrap_or_default();
    let subject = header_value(data, "Subject").unwrap_or_default();
    format!(
        "(\"{}\" \"{}\" NIL NIL NIL NIL NIL NIL NIL NIL)",
        date, subject
    )
}

fn parse_store_items(spec: &str) -> Vec<String> {
    normalize_fetch_items(spec)
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
        i == "BODY[]" || i == "BODY.PEEK[]" || i.starts_with("BODY.PEEK[") || i == "RFC822.TEXT"
    });
    let header_section_name = header_section_response_name(raw_spec);
    let requested_headers = requested_header_fields(raw_spec);
    let include_headers = header_section_name.is_some();

    let need_data = include_size
        || include_rfc822
        || include_body
        || include_headers
        || include_envelope
        || include_bodystructure;
    let internal_date = include_internaldate.then(|| format_internal_date(&path));
    let data = if need_data {
        Some(tokio::task::spawn_blocking(move || std::fs::read(path)).await??)
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
        let len = data.as_ref().map(|d| d.len()).unwrap_or(0);
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
        let size = data.as_ref().map(|d| d.len()).unwrap_or(0);
        attrs.push(format!(
            "BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" {} 0)",
            size
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
        "BODY[]"
    } else {
        "RFC822"
    };
    let data = data.unwrap_or_default();
    let literal = if include_headers {
        extract_header_literal(&data, requested_headers.as_deref())
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
            "NOOP" => {
                let w = reader.get_mut();
                w.write_all(format!("{} OK NOOP completed\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
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
                let w = reader.get_mut();
                w.write_all(
                    format!(
                        "{} NO RENAME is not supported for this mailbox layout\r\n",
                        tag
                    )
                    .as_bytes(),
                )
                .await?;
                w.flush().await?;
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
                    values.push(format!("UNSEEN {}", first_unseen(&sel)));
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
                    let criteria = subargs.to_uppercase();
                    println!("IMAP UID SEARCH peer={:?} criteria={:?}", peer, criteria);
                    let mut matches = Vec::new();
                    for (uid, _, flags) in &sel.msgs {
                        let seen = flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen"));
                        if criteria.contains("ALL")
                            || (criteria.contains("UNSEEN") && !seen)
                            || (criteria.contains("SEEN") && seen)
                        {
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
                } else {
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
                let criteria = args.to_uppercase();
                println!("IMAP SEARCH peer={:?} criteria={:?}", peer, criteria);
                let mut matches = Vec::new();
                for (idx, (_, _, flags)) in sel.msgs.iter().enumerate() {
                    let seen = flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen"));
                    if criteria.contains("ALL")
                        || (criteria.contains("UNSEEN") && !seen)
                        || (criteria.contains("SEEN") && seen)
                    {
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
                eprintln!(
                    "IMAP unknown command peer={:?} encrypted={} tag={} cmd={} args={:?}",
                    peer, session_encrypted, tag, cmd, args
                );
                let w = reader.get_mut();
                w.write_all(format!("{} BAD Unknown or unimplemented command\r\n", tag).as_bytes())
                    .await?;
                w.flush().await?;
            }
        }
    }
    Ok(())
}
