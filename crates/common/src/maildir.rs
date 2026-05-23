use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Ensure Maildir directories exist: tmp/new/cur
pub fn ensure_maildir(path: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(path.join("tmp"))?;
    fs::create_dir_all(path.join("new"))?;
    fs::create_dir_all(path.join("cur"))?;
    Ok(())
}

/// Deliver email bytes to Maildir using atomic tmp->new move.
/// This follows classic Maildir semantics (tmp -> new).
pub fn deliver(maildir_root: &Path, domain: &str, localpart: &str, data: &[u8]) -> anyhow::Result<PathBuf> {
    let mailbox_dir = maildir_root.join(domain).join(localpart).join("Maildir");
    ensure_maildir(&mailbox_dir)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let pid = std::process::id();
    let filename = format!("{}.{}", now, pid);
    let tmp_path = mailbox_dir.join("tmp").join(&filename);
    let new_path = mailbox_dir.join("new").join(&filename);
    let mut f = File::create(&tmp_path)?;
    f.write_all(data)?;
    fs::rename(&tmp_path, &new_path)?;
    Ok(new_path)
}

/// Count messages in Maildir (new + cur). Used by IMAP SELECT to report EXISTS.
pub fn count_messages(maildir_root: &Path, domain: &str, localpart: &str) -> anyhow::Result<usize> {
    let mailbox_dir = maildir_root.join(domain).join(localpart).join("Maildir");
    ensure_maildir(&mailbox_dir)?;
    let mut count = 0usize;
    for sub in &["new", "cur"] {
        let dir = mailbox_dir.join(sub);
        if dir.exists() && dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let e = entry?;
                if e.file_type()?.is_file() {
                    count += 1;
                }
            }
        }
    }
    Ok(count)
}
