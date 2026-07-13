use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QueueControl {
    pub attempts: u32,
    pub max_attempts: u32,
    pub priority: i32,
    pub next_try: Option<i64>,
    pub last_error: Option<String>,
    #[serde(default)]
    pub last_smtp_code: Option<u16>,
    #[serde(default)]
    pub last_enhanced_status: Option<String>,
    pub created_at: i64,
}

impl QueueControl {
    pub fn new(max_attempts: u32, priority: i32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        QueueControl {
            attempts: 0,
            max_attempts,
            priority,
            next_try: None,
            last_error: None,
            last_smtp_code: None,
            last_enhanced_status: None,
            created_at: now,
        }
    }
    pub fn default_with_timestamp(ts: i64) -> Self {
        QueueControl {
            attempts: 0,
            max_attempts: 5,
            priority: 0,
            next_try: None,
            last_error: None,
            last_smtp_code: None,
            last_enhanced_status: None,
            created_at: ts,
        }
    }
}

pub fn control_path_for_eml(eml_path: &Path) -> PathBuf {
    let parent = eml_path.parent().unwrap_or_else(|| Path::new("."));
    let fname = eml_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("message.eml");
    parent.join(format!("{}.json", fname))
}

/// Simple outbound queue: writes email files into <mail_root>/outbound/maildrop/queue with an atomic tmp->final move.
/// This is intentionally minimal — a more complete MTA would implement retry/backoff, SMTP delivery workers, and per-domain queuing.
pub fn queue_outbound(
    maildir_root: &Path,
    recipient: &str,
    data: &[u8],
    envelope_from: Option<&str>,
) -> anyhow::Result<PathBuf> {
    let recipient = crate::domain::canonicalize_mailbox_address(recipient)?;
    let envelope_from = envelope_from
        .map(crate::domain::canonicalize_mailbox_address)
        .transpose()?;
    if recipient.contains(['\r', '\n'])
        || envelope_from
            .as_deref()
            .is_some_and(|sender| sender.contains(['\r', '\n']))
    {
        anyhow::bail!("envelope addresses must not contain line breaks");
    }
    let outbound_dir = maildir_root.join("outbound").join("maildrop");
    let tmp_dir = outbound_dir.join("tmp");
    let queue_dir = outbound_dir.join("queue");
    fs::create_dir_all(&tmp_dir)?;
    fs::create_dir_all(&queue_dir)?;

    // sanitize recipient for filename (keeps only alnum and replaces others with underscore)
    let safe: String = recipient
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let pid = std::process::id();
    let rand: u64 = rand::random();
    let filename = format!("{}.{}.{}.{}.eml", now, pid, rand, safe);
    let tmp_path = tmp_dir.join(&filename);
    let final_path = queue_dir.join(&filename);
    let mut f = File::create(&tmp_path)?;

    // Persist envelope metadata as an internal header so the outbound worker can reconstruct the SMTP envelope.
    // These headers are a spool format, not RFC 5322 headers, and are stripped by the delivery worker.
    if let Some(env) = envelope_from.as_deref() {
        write!(f, "X-RMail-Envelope-From: {env}\r\n")?;
    }
    write!(f, "X-RMail-Envelope-To: {recipient}\r\n\r\n")?;

    // write the original message bytes unchanged
    f.write_all(data)?;
    // ensure data is flushed to disk before moving
    f.sync_all()?;

    // Write and sync the sidecar before publishing the message. The message rename is the
    // commit marker: a queue reader never sees an `.eml` without its control record.
    let control = QueueControl::new(5, 0);
    let control_json = serde_json::to_string(&control)?;
    let tmp_json = control_path_for_eml(&tmp_path);
    let mut control_file = File::create(&tmp_json)?;
    control_file.write_all(control_json.as_bytes())?;
    control_file.sync_all()?;

    let final_json = control_path_for_eml(&final_path);
    fs::rename(&tmp_json, &final_json)?;
    if let Err(error) = fs::rename(&tmp_path, &final_path) {
        let _ = fs::rename(&final_json, &tmp_json);
        return Err(error).context("publishing queued message");
    }
    // Persist directory entries as well as file contents before acknowledging the queue write.
    File::open(&queue_dir)?.sync_all()?;
    Ok(final_path)
}

#[cfg(test)]
mod tests {
    use super::{control_path_for_eml, queue_outbound};
    use std::path::Path;

    #[test]
    fn control_sidecar_uses_eml_json_suffix() {
        let path = Path::new("/tmp/message.eml");
        assert_eq!(
            control_path_for_eml(path),
            Path::new("/tmp/message.eml.json")
        );
    }

    #[test]
    fn queue_metadata_canonicalizes_idn_envelope_domains() {
        let temp = tempfile::tempdir().unwrap();
        let queued = queue_outbound(
            temp.path(),
            "to@BÜCHER.example",
            b"Subject: test\r\n\r\nbody\r\n",
            Some("from@BÜCHER.example"),
        )
        .unwrap();
        let data = std::fs::read_to_string(queued).unwrap();
        assert!(data.starts_with(
            "X-RMail-Envelope-From: from@xn--bcher-kva.example\r\nX-RMail-Envelope-To: to@xn--bcher-kva.example\r\n\r\n"
        ));
        assert!(data.contains("X-RMail-Envelope-From: from@xn--bcher-kva.example"));
        assert!(data.contains("X-RMail-Envelope-To: to@xn--bcher-kva.example"));
    }
}
