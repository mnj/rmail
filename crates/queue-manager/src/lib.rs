//! rmail_queue_manager: small queue manager helpers (claiming, backoff, per-destination limits, dead-letter, metrics)

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rmail_common::outbound::QueueControl;

/// Exponential backoff base in seconds (60s * 2^(attempts-1))
pub fn next_backoff_seconds(attempts: u32) -> i64 {
    let base: i64 = 60;
    let exp = if attempts == 0 {
        0
    } else {
        attempts.saturating_sub(1)
    };
    let mul = 2i64.pow(exp);
    base.saturating_mul(mul)
}

#[derive(Debug, Clone)]
pub struct QueueMetrics {
    pub queued: usize,
    pub inflight: usize,
    pub sent: usize,
    pub failed: usize,
    pub dead: usize,
    pub per_destination_inflight: HashMap<String, usize>,
}

fn find_json_for_eml(eml_path: &Path) -> Option<PathBuf> {
    let sidecar = rmail_common::outbound::control_path_for_eml(eml_path);
    if sidecar.exists() {
        return Some(sidecar);
    }
    None
}

fn read_envelope_to(eml_path: &Path) -> Result<Option<String>> {
    let f = fs::File::open(eml_path).with_context(|| format!("opening eml {:?}", eml_path))?;
    let mut r = BufReader::new(f);
    let mut line = String::new();
    loop {
        line.clear();
        let n = r.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(rest) = line.strip_prefix("X-RMail-Envelope-To:") {
            return Ok(Some(rest.trim().to_string()));
        }
    }
    Ok(None)
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct QueueEntry {
    pub filename: String,
    pub eml_path: PathBuf,
    pub json_path: Option<PathBuf>,
    pub control: QueueControl,
    pub created_at: i64,
    pub envelope_to: Option<String>,
    pub domain: Option<String>,
}

fn list_queue_entries(maildrop_dir: &Path) -> Result<Vec<QueueEntry>> {
    let queue_dir = maildrop_dir.join("queue");
    let mut out: Vec<QueueEntry> = Vec::new();
    let read_dir = match fs::read_dir(&queue_dir) {
        Ok(rd) => rd,
        Err(_) => return Ok(out),
    };
    for e in read_dir.filter_map(|r| r.ok()) {
        let p = e.path();
        if !p.is_file() {
            continue;
        }
        if p.extension()
            .and_then(|s| s.to_str())
            .map(|s| s == "eml")
            .unwrap_or(false)
        {
            let filename = p
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            let json_path = find_json_for_eml(&p);
            let control = if let Some(ref jp) = json_path {
                match fs::read_to_string(jp) {
                    Ok(s) => serde_json::from_str::<QueueControl>(&s)
                        .unwrap_or_else(|_| QueueControl::default_with_timestamp(0)),
                    Err(_) => QueueControl::default_with_timestamp(0),
                }
            } else {
                QueueControl::default_with_timestamp(0)
            };
            let created_at = if control.created_at != 0 {
                control.created_at
            } else {
                match fs::metadata(&p).and_then(|m| m.modified()) {
                    Ok(t) => t
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0),
                    Err(_) => 0,
                }
            };
            let envelope_to = read_envelope_to(&p).ok().flatten();
            let domain = envelope_to
                .as_ref()
                .and_then(|r| r.rfind('@').and_then(|i| Some(r[i + 1..].to_lowercase())));

            out.push(QueueEntry {
                filename,
                eml_path: p,
                json_path,
                control,
                created_at,
                envelope_to,
                domain,
            });
        }
    }
    Ok(out)
}

fn count_inflight_by_domain(maildrop_dir: &Path) -> Result<HashMap<String, usize>> {
    let inflight_dir = maildrop_dir.join("inflight");
    let mut counts: HashMap<String, usize> = HashMap::new();
    let rd = match fs::read_dir(&inflight_dir) {
        Ok(r) => r,
        Err(_) => return Ok(counts),
    };
    for e in rd.filter_map(|r| r.ok()) {
        let p = e.path();
        if !p.is_file() {
            continue;
        }
        if p.extension()
            .and_then(|s| s.to_str())
            .map(|s| s == "eml")
            .unwrap_or(false)
        {
            let to = read_envelope_to(&p).ok().flatten();
            if let Some(t) = to {
                if let Some(at) = t.rfind('@') {
                    let dom = t[at + 1..].to_lowercase();
                    *counts.entry(dom).or_insert(0) += 1;
                }
            }
        }
    }
    Ok(counts)
}

/// Claim an eligible message respecting per-destination concurrency limits.
/// Returns the inflight eml/json paths if a claim succeeded.
pub fn claim_one_with_limit(
    maildrop_dir: &Path,
    per_destination_limit: usize,
) -> Result<Option<(PathBuf, PathBuf)>> {
    let _queue_dir = maildrop_dir.join("queue");
    let inflight_dir = maildrop_dir.join("inflight");
    fs::create_dir_all(&inflight_dir)
        .with_context(|| format!("creating inflight dir {:?}", inflight_dir))?;

    let mut entries = list_queue_entries(maildrop_dir)?;
    // filter by next_try
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    entries.retain(|e| {
        if let Some(nt) = e.control.next_try {
            nt <= now
        } else {
            true
        }
    });

    // sort by priority desc, created_at asc
    entries.sort_by(|a, b| {
        b.control
            .priority
            .cmp(&a.control.priority)
            .then_with(|| a.created_at.cmp(&b.created_at))
    });

    let mut inflight_counts = count_inflight_by_domain(maildrop_dir)?;

    for ent in entries {
        let domain = ent.domain.clone().unwrap_or_else(|| "".to_string());
        let cur = *inflight_counts.get(&domain).unwrap_or(&0);
        if cur >= per_destination_limit {
            continue;
        }

        let eml_src = ent.eml_path.clone();
        let eml_dst = inflight_dir.join(eml_src.file_name().unwrap());

        // determine json src (if any) and destination name
        let json_src_opt = ent.json_path.clone();

        // attempt to rename eml
        if let Err(_) = fs::rename(&eml_src, &eml_dst) {
            continue; // contention
        }

        // handle json
        let inflight_json_dst = if let Some(json_src) = &json_src_opt {
            let dst = inflight_dir.join(json_src.file_name().unwrap());
            match fs::rename(json_src, &dst) {
                Ok(_) => dst,
                Err(e) => {
                    // revert eml move
                    let _ = fs::rename(&eml_dst, &eml_src);
                    eprintln!("failed to move json to inflight: {}", e);
                    continue;
                }
            }
        } else {
            // create default control json next to inflight eml
            let dst = rmail_common::outbound::control_path_for_eml(&eml_dst);
            let _ = fs::write(&dst, serde_json::to_string(&QueueControl::new(5, 0))?);
            dst
        };

        // increment inflight count for domain
        *inflight_counts.entry(domain).or_insert(0) += 1;

        return Ok(Some((eml_dst, inflight_json_dst)));
    }

    Ok(None)
}

pub fn collect_metrics(maildrop_dir: &Path) -> Result<QueueMetrics> {
    let queue_dir = maildrop_dir.join("queue");
    let inflight_dir = maildrop_dir.join("inflight");
    let outbound_root = maildrop_dir
        .parent()
        .unwrap_or_else(|| Path::new("./outbound"))
        .to_path_buf();
    let sent_dir = outbound_root.join("sent");
    let failed_dir = outbound_root.join("failed");
    let dead_dir = outbound_root.join("dead");

    let queued = fs::read_dir(&queue_dir)
        .map(|r| {
            r.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("eml"))
                .count()
        })
        .unwrap_or(0);
    let inflight = fs::read_dir(&inflight_dir)
        .map(|r| {
            r.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("eml"))
                .count()
        })
        .unwrap_or(0);
    let sent = fs::read_dir(&sent_dir)
        .map(|r| {
            r.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("eml"))
                .count()
        })
        .unwrap_or(0);
    let failed = fs::read_dir(&failed_dir)
        .map(|r| {
            r.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("eml"))
                .count()
        })
        .unwrap_or(0);
    let dead = fs::read_dir(&dead_dir)
        .map(|r| {
            r.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("eml"))
                .count()
        })
        .unwrap_or(0);

    let per_dest = count_inflight_by_domain(maildrop_dir)?;

    Ok(QueueMetrics {
        queued,
        inflight,
        sent,
        failed,
        dead,
        per_destination_inflight: per_dest,
    })
}

/// Move aged failed messages to dead-letter directory. Returns number moved.
pub fn dead_letter_cleanup(maildrop_dir: &Path, older_than_secs: i64) -> Result<usize> {
    let outbound_root = maildrop_dir
        .parent()
        .unwrap_or_else(|| Path::new("./outbound"))
        .to_path_buf();
    let failed_dir = outbound_root.join("failed");
    let dead_dir = outbound_root.join("dead");
    fs::create_dir_all(&dead_dir)?;

    let mut moved = 0usize;
    let rd = match fs::read_dir(&failed_dir) {
        Ok(r) => r,
        Err(_) => return Ok(moved),
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    for e in rd.filter_map(|r| r.ok()) {
        let p = e.path();
        if !p.is_file() {
            continue;
        }
        if p.extension().and_then(|s| s.to_str()) != Some("eml") {
            continue;
        }

        // find control json
        let json_path = find_json_for_eml(&p);
        let created_at = if let Some(ref jp) = json_path {
            match fs::read_to_string(jp)
                .ok()
                .and_then(|s| serde_json::from_str::<QueueControl>(&s).ok())
            {
                Some(c) if c.created_at != 0 => c.created_at,
                _ => 0,
            }
        } else {
            0
        };

        let age = if created_at != 0 {
            now - created_at
        } else {
            match fs::metadata(&p).and_then(|m| m.modified()) {
                Ok(t) => t
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
                Err(_) => 0,
            }
        };
        if age >= older_than_secs {
            let dst_eml = dead_dir.join(p.file_name().unwrap());
            if let Err(e) = fs::rename(&p, &dst_eml) {
                eprintln!("failed to move failed eml to dead: {}", e);
                continue;
            }
            if let Some(jp) = json_path {
                let dst_json = dead_dir.join(jp.file_name().unwrap());
                let _ = fs::rename(&jp, &dst_json);
            }
            moved += 1;
        }
    }
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_next_backoff_seconds() {
        assert_eq!(next_backoff_seconds(0), 60);
        assert_eq!(next_backoff_seconds(1), 60);
        assert_eq!(next_backoff_seconds(2), 120);
        assert_eq!(next_backoff_seconds(5), 960);
    }

    #[test]
    fn test_claim_with_limit() -> Result<()> {
        let td = tempdir()?;
        let outbound = td.path().join("outbound");
        let maildrop = outbound.join("maildrop");
        let queue = maildrop.join("queue");
        fs::create_dir_all(&queue)?;
        fs::create_dir_all(maildrop.join("inflight"))?;

        // create 3 messages to same domain
        for i in 0..3 {
            let filename = format!("msg{}.eml", i);
            let eml_path = queue.join(&filename);
            let mut f = fs::File::create(&eml_path)?;
            writeln!(f, "X-RMail-Envelope-To: user@example.com\r\n\r\nBody {}", i)?;
            f.sync_all()?;
            let ctl = QueueControl::new(5, 0);
            let json_path = queue.join(format!("{}.json", &filename));
            fs::write(&json_path, serde_json::to_string(&ctl)?)?;
        }

        // claim with limit 1 - first call should return Some, second should return None because inflight has one
        let claimed = claim_one_with_limit(&maildrop, 1)?;
        assert!(claimed.is_some());
        let _ = claimed.unwrap();
        let claimed2 = claim_one_with_limit(&maildrop, 1)?;
        assert!(claimed2.is_none());
        Ok(())
    }

    #[test]
    fn test_dead_letter_cleanup_moves_old() -> Result<()> {
        let td = tempdir()?;
        let outbound = td.path().join("outbound");
        let failed = outbound.join("failed");
        fs::create_dir_all(&failed)?;

        let filename = "old.eml";
        let eml_path = failed.join(filename);
        let mut f = fs::File::create(&eml_path)?;
        writeln!(f, "X-RMail-Envelope-To: user@example.com\r\n\r\nOld body")?;
        f.sync_all()?;
        let mut ctl = QueueControl::new(5, 0);
        // set created_at far in the past
        ctl.created_at = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64)
            - (60 * 60 * 24 * 40);
        let json_path = failed.join(format!("{}.json", filename));
        fs::write(&json_path, serde_json::to_string(&ctl)?)?;

        let maildrop = outbound.join("maildrop");
        let moved = dead_letter_cleanup(&maildrop, 60 * 60 * 24 * 30)?; // older than 30 days
        assert_eq!(moved, 1);
        let dead_dir = outbound.join("dead");
        assert!(dead_dir.join(filename).exists());
        Ok(())
    }
}
