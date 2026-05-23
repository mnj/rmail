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
    // Sanity-check domain and localpart to avoid path traversal attacks
    for s in [domain, localpart] {
        if s.contains('/') || s.contains('\\') || s.contains('\0') || s.contains("..") {
            return Err(anyhow::anyhow!("invalid mailbox name"));
        }
    }

    let mailbox_dir = maildir_root.join(domain).join(localpart).join("Maildir");
    ensure_maildir(&mailbox_dir)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let pid = std::process::id();
    // include a short random component to reduce collision risk across processes
    let rand: u64 = rand::random();
    let filename = format!("{}.{}.{}", now, pid, rand);
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

/// List all message file paths in Maildir (new + cur), sorted by filename for stable ordering.
pub fn list_messages(maildir_root: &Path, domain: &str, localpart: &str) -> anyhow::Result<Vec<PathBuf>> {
    let mailbox_dir = maildir_root.join(domain).join(localpart).join("Maildir");
    ensure_maildir(&mailbox_dir)?;
    let mut msgs = Vec::new();
    for sub in &["new", "cur"] {
        let dir = mailbox_dir.join(sub);
        if dir.exists() && dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let e = entry?;
                if e.file_type()?.is_file() {
                    msgs.push(e.path());
                }
            }
        }
    }
    // Sort by filename to provide stable ordering for IMAP sequence numbers
    msgs.sort_by_key(|p| p.file_name().and_then(|n| n.to_str().map(|s| s.to_owned())).unwrap_or_default());
    Ok(msgs)
}

/// Read the message bytes at the given zero-based index from the Maildir (combined new+cur ordering).
pub fn read_message(maildir_root: &Path, domain: &str, localpart: &str, index: usize) -> anyhow::Result<Vec<u8>> {
    let msgs = list_messages(maildir_root, domain, localpart)?;
    if let Some(path) = msgs.get(index) {
        let data = fs::read(path)?;
        Ok(data)
    } else {
        Err(anyhow::anyhow!("no message at index"))
    }
}

use std::collections::HashMap;

/// Load or create a persistent UID mapping for a Maildir.
///
/// This function ensures a mailbox-specific UIDVALIDITY is present (stored in Maildir/uidvalidity)
/// and a filename -> UID map persisted in Maildir/uidmap.json. It returns the UIDVALIDITY and an
/// ordered Vec of (UID, PathBuf) matching the stable ordering used for IMAP sequence numbers.
///
/// Implementation notes:
/// - Filenames are used as stable identifiers; if a filename has an existing UID it is reused.
/// - New files receive monotonically increasing UIDs written back to the uidmap.json atomically.
/// - UIDVALIDITY is generated from time XOR randomness when first created.
pub fn load_uid_map(maildir_root: &Path, domain: &str, localpart: &str) -> anyhow::Result<(u64, Vec<(u64, PathBuf)>)> {
    let mailbox_dir = maildir_root.join(domain).join(localpart).join("Maildir");
    ensure_maildir(&mailbox_dir)?;
    let uidvalidity_path = mailbox_dir.join("uidvalidity");
    let uidmap_path = mailbox_dir.join("uidmap.json");

    // Load or initialize UIDVALIDITY
    let uidvalidity: u64 = if uidvalidity_path.exists() {
        let s = fs::read_to_string(&uidvalidity_path)?;
        s.trim().parse::<u64>().unwrap_or_else(|_| {
            let v = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64) ^ rand::random::<u64>();
            // attempt to persist repaired value
            let tmp = uidvalidity_path.with_extension("tmp");
            let _ = fs::write(&tmp, v.to_string());
            let _ = fs::rename(&tmp, &uidvalidity_path);
            v
        })
    } else {
        let v = (SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64) ^ rand::random::<u64>();
        let tmp = uidvalidity_path.with_extension("tmp");
        fs::write(&tmp, v.to_string())?;
        fs::rename(&tmp, &uidvalidity_path)?;
        v
    };

    // Load existing UID map (filename -> uid)
    let mut map: HashMap<String, u64> = if uidmap_path.exists() {
        let s = fs::read_to_string(&uidmap_path)?;
        match serde_json::from_str(&s) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("warning: failed to parse uidmap.json: {} — rebuilding", e);
                HashMap::new()
            }
        }
    } else {
        HashMap::new()
    };

    // Build ordered list of messages and assign UIDs to new files
    let msgs_paths = list_messages(maildir_root, domain, localpart)?;
    let mut max_uid = map.values().cloned().max().unwrap_or(0);
    let mut out: Vec<(u64, PathBuf)> = Vec::new();
    for p in msgs_paths.into_iter() {
        if let Some(fname_os) = p.file_name() {
            if let Some(fname) = fname_os.to_str() {
                let uid = if let Some(&u) = map.get(fname) {
                    u
                } else {
                    max_uid = max_uid.saturating_add(1);
                    map.insert(fname.to_string(), max_uid);
                    max_uid
                };
                out.push((uid, p));
            }
        }
    }

    // Persist updated map atomically
    let tmp = uidmap_path.with_extension("tmp");
    let json = serde_json::to_string(&map)?;
    fs::write(&tmp, json)?;
    fs::rename(&tmp, &uidmap_path)?;

    Ok((uidvalidity, out))
}
