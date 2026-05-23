use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Simple outbound queue: writes email files into <mail_root>/outbound/queue with an atomic tmp->final move.
/// This is intentionally minimal — a more complete MTA would implement retry/backoff, SMTP delivery workers, and per-domain queuing.
pub fn queue_outbound(maildir_root: &Path, recipient: &str, data: &[u8], envelope_from: Option<&str>) -> anyhow::Result<PathBuf> {
    let outbound_dir = maildir_root.join("outbound");
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
    fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}