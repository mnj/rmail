//! rmail_queue_manager: small queue manager helpers (claiming, backoff)

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rmail_common::outbound::QueueControl;

/// Exponential backoff base in seconds (60s * 2^(attempts-1))
pub fn next_backoff_seconds(attempts: u32) -> i64 {
    let base: i64 = 60;
    let exp = if attempts == 0 { 0 } else { attempts.saturating_sub(1) };
    let mul = 2i64.pow(exp);
    base.saturating_mul(mul)
}

/// Attempt to claim one eligible message from maildrop/queue by moving it into maildrop/inflight.
/// Returns the (inflight_eml_path, inflight_json_path) if a claim succeeded.
pub fn claim_one(maildrop_dir: &Path) -> Result<Option<(PathBuf, PathBuf)>> {
    let queue_dir = maildrop_dir.join("queue");
    let inflight_dir = maildrop_dir.join("inflight");
    fs::create_dir_all(&inflight_dir).with_context(|| format!("creating inflight dir {:?}", inflight_dir))?;

    let entries = match fs::read_dir(&queue_dir) {
        Ok(rd) => rd,
        Err(_) => return Ok(None),
    };

    // Collect .eml files in the queue directory
    let mut eml_files: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|ent| ent.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()).map(|s| s == "eml").unwrap_or(false))
        .collect();

    // Simple ordering (lexicographic) - callers can implement priority sorting later
    eml_files.sort();

    for eml in eml_files {
        let filename = match eml.file_name().and_then(|n| n.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let json_path = queue_dir.join(format!("{}.json", filename)); // matches existing writer semantics: <name>.eml + <name>.eml.json

        // read control JSON
        let ctl_bytes = match fs::read(&json_path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let ctl: QueueControl = match serde_json::from_slice(&ctl_bytes) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
        if let Some(next_try) = ctl.next_try {
            if next_try > now {
                // not ready yet
                continue;
            }
        }

        let inflight_eml = inflight_dir.join(&filename);
        let inflight_json = inflight_dir.join(format!("{}.json", filename));

        // attempt to atomically claim by renaming both files to inflight
        if let Err(_) = fs::rename(&eml, &inflight_eml) {
            continue; // contention - skip
        }
        if let Err(e) = fs::rename(&json_path, &inflight_json) {
            // try to revert eml rename; best-effort
            let _ = fs::rename(&inflight_eml, &eml);
            // skip this entry
            let _ = e; // suppress unused
            continue;
        }

        return Ok(Some((inflight_eml, inflight_json)));
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::io::Write;

    #[test]
    fn test_next_backoff_seconds() {
        assert_eq!(next_backoff_seconds(0), 60);
        assert_eq!(next_backoff_seconds(1), 60);
        assert_eq!(next_backoff_seconds(2), 120);
        assert_eq!(next_backoff_seconds(5), 960);
    }

    #[test]
    fn test_claim_one_moves_files() -> Result<()> {
        let td = tempdir()?;
        let maildrop = td.path().join("maildrop");
        let queue = maildrop.join("queue");
        fs::create_dir_all(&queue)?;

        let filename = "testmsg.eml";
        let eml_path = queue.join(filename);
        let mut f = fs::File::create(&eml_path)?;
        writeln!(f, "Subject: hello")?;
        f.sync_all()?;

        let ctl = QueueControl::new(5, 0);
        let json = serde_json::to_string(&ctl)?;
        let json_path = queue.join(format!("{}.json", filename));
        fs::write(&json_path, json.as_bytes())?;

        // claim
        let res = claim_one(&maildrop)?;
        assert!(res.is_some(), "expected a claimed item");
        let (inflight_eml, inflight_json) = res.unwrap();

        assert!(inflight_eml.exists());
        assert!(inflight_json.exists());
        assert!(!eml_path.exists());
        assert!(!json_path.exists());

        Ok(())
    }
}
