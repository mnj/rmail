use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QueueControl {
    pub attempts: u32,
    pub max_attempts: u32,
    pub priority: i32,
    pub next_try: Option<i64>,
    pub last_error: Option<String>,
    pub created_at: i64,
}

impl QueueControl {
    pub fn new(max_attempts: u32, priority: i32) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
        QueueControl { attempts: 0, max_attempts, priority, next_try: None, last_error: None, created_at: now }
    }
    pub fn default_with_timestamp(ts: i64) -> Self { QueueControl { attempts: 0, max_attempts: 5, priority: 0, next_try: None, last_error: None, created_at: ts } }
}

/// Simple outbound queue: writes email files into <mail_root>/outbound/maildrop/queue with an atomic tmp->final move.
/// This is intentionally minimal — a more complete MTA would implement retry/backoff, SMTP delivery workers, and per-domain queuing.
pub fn queue_outbound(maildir_root: &Path, recipient: &str, data: &[u8], envelope_from: Option<&str>) -> anyhow::Result<PathBuf> {
    let outbound_dir = maildir_root.join("outbound").join("maildrop");
    let tmp_dir = outbound_dir.join("tmp");
    let queue_dir = outbound_dir.join("queue");
    fs::create_dir_all(&tmp_dir)?;
    fs::create_dir_all(&queue_dir)?;

    // sanitize recipient for filename (keeps only alnum and replaces others with underscore)
    let safe: String = recipient.chars().map(|c| {
        if c.is_ascii_alphanumeric() { c } else { '_' }
    }).collect();

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let pid = std::process::id();
    let rand: u64 = rand::random();
    let filename = format!("{}.{}.{}.{}.eml", now, pid, rand, safe);
    let tmp_path = tmp_dir.join(&filename);
    let final_path = queue_dir.join(&filename);
    let mut f = File::create(&tmp_path)?;

    // Persist envelope metadata as an internal header so the outbound worker can reconstruct the SMTP envelope.
    if let Some(env) = envelope_from {
        writeln!(f, "X-RMail-Envelope-From: {}", env)?;
    }
    writeln!(f, "X-RMail-Envelope-To: {}", recipient)?;
    writeln!(f)?; // blank line separates metadata from RFC822 message

    // write the original message bytes unchanged
    f.write_all(data)?;
    // ensure data is flushed to disk before moving
    f.sync_all()?;

    // write control JSON to tmp and then move to queue dir
    let control = QueueControl::new(5, 0);
    let control_json = serde_json::to_string(&control)?;
    let tmp_json = tmp_dir.join(format!("{}.json", &filename));
    fs::write(&tmp_json, control_json.as_bytes())?;

    fs::rename(&tmp_path, &final_path)?;
    let final_json = queue_dir.join(format!("{}.json", &filename));
    fs::rename(&tmp_json, &final_json)?;
    Ok(final_path)
}