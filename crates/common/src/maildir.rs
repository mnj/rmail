use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn ensure_maildir(path: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(path.join("tmp"))?;
    fs::create_dir_all(path.join("new"))?;
    fs::create_dir_all(path.join("cur"))?;
    Ok(())
}

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
