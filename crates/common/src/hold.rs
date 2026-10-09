//! Scheduled sending: messages held until a release time (SMTP
//! FUTURERELEASE, RFC 4865; JMAP delayed send, RFC 8621 section 7).
//!
//! A held message is `<mail_root>/outbound/held/<id>.eml` with its envelope
//! in `<id>.json`, written last so a reader never sees half an entry. When
//! the time comes, the outbound worker hands it to the submission service
//! as the user who sent it (`local_submit`), so local and remote recipients,
//! rate limits, signing and filters are treated exactly as for mail sent
//! then. A permanent refusal leaves a notice in the sender's inbox.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// The longest a message may be held (RFC 4865 max-future-release-interval).
pub const MAX_HOLD_SECONDS: i64 = 30 * 24 * 60 * 60;
/// Wait before retrying a release the submission service could not take.
const RETRY_SECONDS: i64 = 5 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Held {
    pub id: String,
    /// The authenticated user the message is submitted as.
    pub user: String,
    pub mail_from: String,
    pub recipients: Vec<String>,
    /// Unix time to release at.
    pub release_at: i64,
    /// The JMAP EmailSubmission this is, if any.
    #[serde(default)]
    pub submission_id: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
}

fn held_dir(mail_root: &Path) -> PathBuf {
    mail_root.join("outbound").join("held")
}

fn valid_id(id: &str) -> bool {
    id.len() == 25 && id.starts_with('H') && id[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn paths(mail_root: &Path, id: &str) -> Result<(PathBuf, PathBuf)> {
    if !valid_id(id) {
        anyhow::bail!("invalid held message id");
    }
    let dir = held_dir(mail_root);
    Ok((
        dir.join(format!("{id}.eml")),
        dir.join(format!("{id}.json")),
    ))
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Hold `data` for release at `held.release_at`; fills in and returns the id.
pub fn hold(mail_root: &Path, mut held: Held, data: &[u8]) -> Result<Held> {
    if held.recipients.is_empty() {
        anyhow::bail!("a held message needs recipients");
    }
    held.id = format!("H{:024x}", rand::random::<u128>() >> 32);
    let dir = held_dir(mail_root);
    std::fs::create_dir_all(&dir)?;
    let (eml, json) = paths(mail_root, &held.id)?;
    write_atomic(&eml, data)?;
    write_atomic(&json, serde_json::to_string(&held)?.as_bytes())?;
    Ok(held)
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// The held message `id`, if it is still waiting.
pub fn get(mail_root: &Path, id: &str) -> Result<Option<Held>> {
    let (_, json) = paths(mail_root, id)?;
    match std::fs::read_to_string(&json) {
        Ok(text) => Ok(Some(serde_json::from_str(&text)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Cancel a held message; false when it was already released or gone.
pub fn cancel(mail_root: &Path, id: &str) -> Result<bool> {
    let (eml, json) = paths(mail_root, id)?;
    match std::fs::remove_file(&json) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    }
    let _ = std::fs::remove_file(eml);
    Ok(true)
}

/// Held messages whose time has come.
pub fn due(mail_root: &Path, at: i64) -> Result<Vec<Held>> {
    let dir = held_dir(mail_root);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(held) = serde_json::from_str::<Held>(&text) else {
            continue;
        };
        if held.release_at <= at && valid_id(&held.id) {
            out.push(held);
        }
    }
    out.sort_by_key(|held| held.release_at);
    Ok(out)
}

/// Mark a JMAP submission as sent once its message is released.
fn finish_submission(mail_root: &Path, held: &Held) {
    let (Some(submission), Some((local, domain))) =
        (&held.submission_id, held.user.split_once('@'))
    else {
        return;
    };
    let finished = (|| -> Result<()> {
        let conn = crate::jmap::store::open(mail_root, domain, local)?;
        conn.execute(
            "UPDATE jmap_submissions SET undo_status = 'final' WHERE id = ?1",
            rusqlite::params![submission],
        )?;
        crate::jmap::store::log_change(&conn, "EmailSubmission", submission, false, false)
    })();
    if let Err(error) = finished {
        crate::structured_log!("warn", "outbound", "held_submission_update_failed", {
            "submission": submission,
            "error": format!("{error:#}"),
        });
    }
}

/// Tell the sender in their inbox that a scheduled message was refused.
fn notify_refusal(mail_root: &Path, held: &Held, reason: &str) {
    let Some((local, domain)) = held.user.split_once('@') else {
        return;
    };
    let notice = format!(
        "From: Mail Delivery System <postmaster@{domain}>\r\nTo: {user}\r\n\
         Subject: Scheduled message not sent\r\nDate: {date}\r\n\
         Auto-Submitted: auto-generated\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\
         Your message scheduled for {release} to {recipients} was not sent:\r\n\r\n{reason}\r\n",
        user = held.user,
        date = chrono::Utc::now().to_rfc2822(),
        release = chrono::DateTime::from_timestamp(held.release_at, 0)
            .map(|at| at.to_rfc2822())
            .unwrap_or_default(),
        recipients = held.recipients.join(", "),
    );
    if let Err(error) =
        crate::imap_state::deliver_message(mail_root, domain, local, notice.as_bytes())
    {
        crate::structured_log!("warn", "outbound", "held_notice_failed", {
            "user": held.user,
            "error": format!("{error:#}"),
        });
    }
}

/// Submit every due held message. Transient failures are retried later;
/// a refusal is final and reported to the sender.
pub async fn release_due(mail_root: &Path, submission: std::net::SocketAddr) -> Result<usize> {
    let root = mail_root.to_path_buf();
    let due = tokio::task::spawn_blocking(move || due(&root, now())).await??;
    let mut released = 0;
    for mut held in due {
        let (eml, json) = paths(mail_root, &held.id)?;
        let Ok(data) = tokio::fs::read(&eml).await else {
            continue;
        };
        // Claim the entry so a second worker cannot send it too.
        let claimed = json.with_extension("sending");
        if tokio::fs::rename(&json, &claimed).await.is_err() {
            continue;
        }
        let sent = crate::local_submit::submit_as(
            submission,
            mail_root,
            &held.user,
            &held.mail_from,
            &held.recipients,
            &data,
        )
        .await;
        match sent {
            Ok(()) => {
                let _ = tokio::fs::remove_file(&claimed).await;
                let _ = tokio::fs::remove_file(&eml).await;
                let root = mail_root.to_path_buf();
                let finished = held.clone();
                let _ =
                    tokio::task::spawn_blocking(move || finish_submission(&root, &finished)).await;
                crate::structured_log!("info", "outbound", "held_message_released", {
                    "id": held.id,
                    "user": held.user,
                    "recipients": held.recipients.len(),
                });
                released += 1;
            }
            Err(error)
                if error
                    .downcast_ref::<crate::local_submit::Refused>()
                    .is_some() =>
            {
                let reason = format!("{error:#}");
                let _ = tokio::fs::remove_file(&claimed).await;
                let _ = tokio::fs::remove_file(&eml).await;
                let root = mail_root.to_path_buf();
                let refused = held.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    notify_refusal(&root, &refused, &reason);
                    finish_submission(&root, &refused);
                })
                .await;
                crate::structured_log!("warn", "outbound", "held_message_refused", {
                    "id": held.id,
                    "user": held.user,
                    "error": format!("{error:#}"),
                });
            }
            Err(error) => {
                held.release_at = now() + RETRY_SECONDS;
                held.last_error = Some(format!("{error:#}"));
                let text = serde_json::to_string(&held)?;
                tokio::fs::write(&claimed, text).await?;
                tokio::fs::rename(&claimed, &json).await?;
                crate::structured_log!("warn", "outbound", "held_message_retry", {
                    "id": held.id,
                    "error": format!("{error:#}"),
                });
            }
        }
    }
    Ok(released)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(release_at: i64) -> Held {
        Held {
            id: String::new(),
            user: "user@example.test".to_string(),
            mail_from: "user@example.test".to_string(),
            recipients: vec!["to@remote.test".to_string()],
            release_at,
            submission_id: None,
            last_error: None,
        }
    }

    /// A submission service answering RCPT with `rcpt_reply`; reports the
    /// envelope lines it saw.
    async fn fake_submission(
        rcpt_reply: &'static [u8],
    ) -> (
        std::net::SocketAddr,
        tokio::sync::mpsc::UnboundedReceiver<Vec<String>>,
    ) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (read, mut write) = stream.into_split();
                let mut lines = BufReader::new(read).lines();
                write.write_all(b"220 test\r\n").await.unwrap();
                let mut seen = Vec::new();
                let mut in_data = false;
                while let Ok(Some(line)) = lines.next_line().await {
                    if in_data {
                        if line == "." {
                            in_data = false;
                            write.write_all(b"250 ok\r\n").await.unwrap();
                        }
                        continue;
                    }
                    let reply: &[u8] = if line.starts_with("RCPT") {
                        seen.push(line.clone());
                        rcpt_reply
                    } else if line.starts_with("MAIL") {
                        seen.push(line.clone());
                        b"250 ok\r\n"
                    } else if line.starts_with("AUTH") {
                        b"235 ok\r\n"
                    } else if line == "DATA" {
                        in_data = true;
                        b"354 go\r\n"
                    } else if line == "QUIT" {
                        let _ = write.write_all(b"221 bye\r\n").await;
                        break;
                    } else {
                        b"250 ok\r\n"
                    };
                    write.write_all(reply).await.unwrap();
                }
                let _ = tx.send(seen);
            }
        });
        (address, rx)
    }

    #[tokio::test]
    async fn release_submits_as_the_sender_and_reports_refusals() {
        let dir = tempfile::tempdir().unwrap();
        crate::imap_state::init_account(dir.path(), "example.test", "user").unwrap();
        let (address, mut seen) = fake_submission(b"250 ok\r\n").await;
        hold(dir.path(), held(now() - 1), b"Subject: now\r\n\r\nx").unwrap();
        assert_eq!(release_due(dir.path(), address).await.unwrap(), 1);
        let envelope = seen.recv().await.unwrap();
        assert_eq!(envelope[0], "MAIL FROM:<user@example.test>");
        assert_eq!(envelope[1], "RCPT TO:<to@remote.test>");
        assert!(due(dir.path(), now() + 1).unwrap().is_empty());

        let (address, _) = fake_submission(b"550 5.1.1 no such user\r\n").await;
        hold(dir.path(), held(now() - 1), b"Subject: now\r\n\r\nx").unwrap();
        assert_eq!(release_due(dir.path(), address).await.unwrap(), 0);
        assert!(due(dir.path(), now() + 1).unwrap().is_empty());
        let inbox = crate::imap_state::load_folder(dir.path(), "example.test", "user", "INBOX")
            .unwrap()
            .1;
        let notice = std::fs::read_to_string(&inbox[0].path).unwrap();
        assert!(notice.contains("Scheduled message not sent"), "{notice}");
        assert!(notice.contains("no such user"), "{notice}");
    }

    #[test]
    fn held_messages_wait_for_their_time_and_can_be_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        let later = hold(dir.path(), held(now() + 3600), b"Subject: later\r\n\r\nx").unwrap();
        let soon = hold(dir.path(), held(now() - 1), b"Subject: now\r\n\r\nx").unwrap();
        let ready = due(dir.path(), now()).unwrap();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id, soon.id);
        assert!(get(dir.path(), &later.id).unwrap().is_some());
        assert!(cancel(dir.path(), &later.id).unwrap());
        assert!(!cancel(dir.path(), &later.id).unwrap());
        assert!(get(dir.path(), &later.id).unwrap().is_none());
        assert!(cancel(dir.path(), "../../etc/passwd").is_err());
    }
}
