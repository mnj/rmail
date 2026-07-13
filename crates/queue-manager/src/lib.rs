//! rmail_queue_manager: small queue manager helpers (claiming, backoff, per-destination limits, dead-letter, metrics)

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
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
    let mul = 2i64.checked_pow(exp).unwrap_or(i64::MAX);
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
            let domain = envelope_to.as_ref().and_then(|recipient| {
                recipient
                    .rfind('@')
                    .map(|index| recipient[index + 1..].to_lowercase())
            });

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
            if let Some(t) = to
                && let Some(at) = t.rfind('@')
            {
                let dom = t[at + 1..].to_lowercase();
                *counts.entry(dom).or_insert(0) += 1;
            }
        }
    }
    Ok(counts)
}

/// Move a message and its control sidecar between spool directories.
///
/// The sidecar is moved first and rolled back if the message rename fails. This
/// makes the `.eml` file the commit marker: queue readers never observe a
/// message in the destination before its existing control data is there.
fn move_pair(
    eml_src: &Path,
    json_src: Option<&Path>,
    eml_dst: &Path,
    allow_existing_destination_sidecar: bool,
) -> Result<PathBuf> {
    let destination_dir = eml_dst
        .parent()
        .ok_or_else(|| anyhow::anyhow!("destination message has no parent directory"))?;
    fs::create_dir_all(destination_dir)?;
    let json_dst = rmail_common::outbound::control_path_for_eml(eml_dst);
    if eml_dst.exists() {
        anyhow::bail!("destination message already exists: {:?}", eml_dst);
    }
    if json_src.is_some() && json_dst.exists() {
        anyhow::bail!("destination control sidecar already exists: {:?}", json_dst);
    }

    enum SidecarMove {
        Moved,
        Created,
        AlreadyPresent,
    }

    let sidecar_move = match json_src {
        Some(src) => {
            fs::rename(src, &json_dst)
                .with_context(|| format!("moving control sidecar {:?} to {:?}", src, json_dst))?;
            SidecarMove::Moved
        }
        None if json_dst.exists() && allow_existing_destination_sidecar => {
            SidecarMove::AlreadyPresent
        }
        None if json_dst.exists() => {
            anyhow::bail!("destination control sidecar already exists: {:?}", json_dst);
        }
        None => {
            let encoded = serde_json::to_vec(&QueueControl::new(5, 0))?;
            fs::write(&json_dst, encoded)
                .with_context(|| format!("creating control sidecar {:?}", json_dst))?;
            SidecarMove::Created
        }
    };

    if let Err(error) = fs::rename(eml_src, eml_dst) {
        match sidecar_move {
            SidecarMove::Moved => {
                if let Some(src) = json_src {
                    let _ = fs::rename(&json_dst, src);
                }
            }
            SidecarMove::Created => {
                let _ = fs::remove_file(&json_dst);
            }
            SidecarMove::AlreadyPresent => {}
        }
        return Err(error)
            .with_context(|| format!("moving message {:?} to {:?}", eml_src, eml_dst));
    }
    Ok(json_dst)
}

/// Move a message and its queue-control sidecar as one recoverable spool transition.
///
/// The sidecar is committed at the destination before the message. If the process
/// stops between the two renames, recovery can complete or roll back the transition
/// without losing the control record.
pub fn move_message_and_control(eml_src: &Path, eml_dst: &Path) -> Result<PathBuf> {
    let json_src = find_json_for_eml(eml_src);
    move_pair(eml_src, json_src.as_deref(), eml_dst, false)
}

/// Atomically replace a queue-control sidecar after syncing its contents.
///
/// A worker writes the updated retry state before changing spool locations. A
/// crash can therefore leave either the old valid JSON or the complete new JSON,
/// never a partially written control record.
pub fn write_control_atomic(path: &Path, control: &QueueControl) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("control sidecar has no parent directory"))?;
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("control sidecar has an invalid filename"))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), nonce));
    let encoded = serde_json::to_vec(control)?;
    let mut file = fs::File::create(&temporary)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

/// Complete queue publications interrupted after their sidecar was published.
///
/// A producer writes both files in `tmp`, moves the sidecar to `queue`, then
/// moves the message as the commit marker. Only the middle state is safe to
/// recover here: it has a synced destination sidecar and an intact temp message.
fn recover_pending_queue_publications(tmp_dir: &Path, queue_dir: &Path) -> Result<usize> {
    let entries = match fs::read_dir(tmp_dir) {
        Ok(entries) => entries,
        Err(_) => return Ok(0),
    };
    let mut recovered = 0;
    for entry in entries.filter_map(|entry| entry.ok()) {
        let temporary_eml = entry.path();
        if temporary_eml
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("eml")
        {
            continue;
        }
        let Some(filename) = temporary_eml.file_name() else {
            continue;
        };
        let queue_eml = queue_dir.join(filename);
        let queue_json = rmail_common::outbound::control_path_for_eml(&queue_eml);
        let temporary_json = rmail_common::outbound::control_path_for_eml(&temporary_eml);
        if !queue_eml.exists() && queue_json.exists() && !temporary_json.exists() {
            fs::rename(&temporary_eml, &queue_eml).with_context(|| {
                format!(
                    "completing interrupted queue publication {:?} to {:?}",
                    temporary_eml, queue_eml
                )
            })?;
            recovered += 1;
        }
    }
    Ok(recovered)
}

/// Complete a sidecar-first transition when the destination contains only its
/// `.eml.json` sidecar and exactly one other spool contains the message file.
///
/// This covers terminal moves (`inflight` -> `sent`/`failed`), administrative
/// queuectl moves, and failed -> dead-letter cleanup. The inflight destination
/// itself is intentionally left to its dedicated claim recovery below.
fn recover_sidecar_only_destinations(
    destinations: &[PathBuf],
    all_spools: &[PathBuf],
) -> Result<usize> {
    let mut recovered = 0;
    for destination_dir in destinations {
        let entries = match fs::read_dir(destination_dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.filter_map(|entry| entry.ok()) {
            let sidecar = entry.path();
            let Some(name) = sidecar.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(eml_name) = name.strip_suffix(".eml.json") else {
                continue;
            };
            let eml_name = format!("{eml_name}.eml");
            let destination_eml = destination_dir.join(&eml_name);
            if destination_eml.exists() {
                continue;
            }
            let sources = all_spools
                .iter()
                .filter(|source_dir| *source_dir != destination_dir)
                .map(|source_dir| source_dir.join(&eml_name))
                .filter(|source_eml| source_eml.exists())
                .collect::<Vec<_>>();
            if sources.len() != 1 {
                continue;
            }
            let source_eml = &sources[0];
            // A second sidecar would be an ambiguous, externally-corrupted
            // state. Leave it untouched for operator inspection rather than
            // picking one record and overwriting the other.
            if find_json_for_eml(source_eml).is_some() {
                continue;
            }
            move_pair(source_eml, None, &destination_eml, true)?;
            recovered += 1;
        }
    }
    Ok(recovered)
}

/// Recover interrupted queue publications and messages left in `inflight` by a
/// terminated worker.
///
/// This is intended to run once during worker startup, before claims begin. It
/// recognizes which destination already has a control sidecar, then completes
/// that specific transition rather than guessing that every inflight message
/// should return to `queue`.
pub fn recover_abandoned_inflight(maildrop_dir: &Path) -> Result<usize> {
    let queue_dir = maildrop_dir.join("queue");
    let inflight_dir = maildrop_dir.join("inflight");
    let tmp_dir = maildrop_dir.join("tmp");
    let outbound_root = maildrop_dir
        .parent()
        .unwrap_or_else(|| Path::new("./outbound"));
    let sent_dir = outbound_root.join("sent");
    let failed_dir = outbound_root.join("failed");
    let dead_dir = outbound_root.join("dead");
    fs::create_dir_all(&queue_dir)?;
    fs::create_dir_all(&inflight_dir)?;
    let mut recovered = recover_pending_queue_publications(&tmp_dir, &queue_dir)?;
    let all_spools = vec![
        tmp_dir.clone(),
        queue_dir.clone(),
        inflight_dir.clone(),
        sent_dir.clone(),
        failed_dir.clone(),
        dead_dir.clone(),
    ];
    recovered += recover_sidecar_only_destinations(
        &[
            queue_dir.clone(),
            sent_dir.clone(),
            failed_dir.clone(),
            dead_dir,
        ],
        &all_spools,
    )?;

    // Repair an interrupted queue -> inflight claim (sidecar moved first).
    for entry in fs::read_dir(&inflight_dir)?.filter_map(|entry| entry.ok()) {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.ends_with(".eml.json") {
            continue;
        }
        let eml_name = name.strip_suffix(".json").unwrap();
        let queue_eml = queue_dir.join(eml_name);
        let queue_json = queue_dir.join(name);
        let inflight_eml = inflight_dir.join(eml_name);
        if queue_eml.exists() && !queue_json.exists() && !inflight_eml.exists() {
            fs::rename(&path, &queue_json)?;
        }
    }

    for entry in fs::read_dir(&inflight_dir)?.filter_map(|entry| entry.ok()) {
        let eml_src = entry.path();
        if eml_src.extension().and_then(|ext| ext.to_str()) != Some("eml") {
            continue;
        }
        let filename = eml_src.file_name().unwrap();
        let queue_eml = queue_dir.join(filename);
        if queue_eml.exists() {
            continue;
        }
        let json_src = find_json_for_eml(&eml_src);
        let sent_eml = sent_dir.join(filename);
        let failed_eml = failed_dir.join(filename);
        if sent_eml.exists() || failed_eml.exists() {
            anyhow::bail!(
                "inconsistent spool state for {:?}: message exists in inflight and a terminal spool",
                eml_src
            );
        }

        // The following state means the source sidecar was already moved, but
        // the message rename did not happen. Finish that intended transition.
        let destinations = [&sent_eml, &failed_eml, &queue_eml];
        let mut completed = false;
        if json_src.is_none() {
            for destination in destinations {
                let destination_json = rmail_common::outbound::control_path_for_eml(destination);
                if destination_json.exists() && !destination.exists() {
                    move_pair(&eml_src, None, destination, true)?;
                    recovered += 1;
                    completed = true;
                    break;
                }
            }
        }
        if completed {
            continue;
        }

        // No destination sidecar exists, so this is a normal abandoned delivery.
        // Preserve an inflight control record if present, otherwise create one.
        move_pair(&eml_src, json_src.as_deref(), &queue_eml, false)?;
        recovered += 1;
    }
    Ok(recovered)
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

        let inflight_json_dst = match move_pair(&eml_src, json_src_opt.as_deref(), &eml_dst, false)
        {
            Ok(path) => path,
            Err(_) => continue, // contention or an incomplete competing claim
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
            if let Err(e) = move_message_and_control(&p, &dst_eml) {
                eprintln!("failed to move failed eml to dead: {}", e);
                continue;
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
        assert_eq!(next_backoff_seconds(u32::MAX), i64::MAX);
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
            let json_path = rmail_common::outbound::control_path_for_eml(&eml_path);
            fs::write(&json_path, serde_json::to_string(&ctl)?)?;
        }

        // claim with limit 1 - first call should return Some, second should return None because inflight has one
        let claimed = claim_one_with_limit(&maildrop, 1)?;
        assert!(claimed.is_some());
        let (inflight_eml, inflight_json) = claimed.unwrap();
        assert_eq!(
            inflight_json,
            rmail_common::outbound::control_path_for_eml(&inflight_eml)
        );
        assert!(inflight_json.exists());
        let claimed2 = claim_one_with_limit(&maildrop, 1)?;
        assert!(claimed2.is_none());
        Ok(())
    }

    #[test]
    fn claim_limit_allows_parallel_destinations() -> Result<()> {
        let td = tempdir()?;
        let maildrop = td.path().join("outbound/maildrop");
        let queue = maildrop.join("queue");
        fs::create_dir_all(&queue)?;

        for (filename, recipient) in [
            ("first.eml", "one@alpha.example"),
            ("second.eml", "two@alpha.example"),
            ("third.eml", "three@beta.example"),
        ] {
            let eml = queue.join(filename);
            fs::write(
                &eml,
                format!("X-RMail-Envelope-To: {recipient}\r\n\r\nbody").as_bytes(),
            )?;
            fs::write(
                rmail_common::outbound::control_path_for_eml(&eml),
                serde_json::to_vec(&QueueControl::new(5, 0))?,
            )?;
        }

        let first = claim_one_with_limit(&maildrop, 1)?.unwrap().0;
        let second = claim_one_with_limit(&maildrop, 1)?.unwrap().0;
        let first_domain = read_envelope_to(&first)?
            .unwrap()
            .split('@')
            .nth(1)
            .unwrap()
            .to_string();
        let second_domain = read_envelope_to(&second)?
            .unwrap()
            .split('@')
            .nth(1)
            .unwrap()
            .to_string();
        assert_ne!(first_domain, second_domain);
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
        let json_path = rmail_common::outbound::control_path_for_eml(&eml_path);
        fs::write(&json_path, serde_json::to_string(&ctl)?)?;

        let maildrop = outbound.join("maildrop");
        let moved = dead_letter_cleanup(&maildrop, 60 * 60 * 24 * 30)?; // older than 30 days
        assert_eq!(moved, 1);
        let dead_dir = outbound.join("dead");
        assert!(dead_dir.join(filename).exists());
        assert!(rmail_common::outbound::control_path_for_eml(&dead_dir.join(filename)).exists());
        Ok(())
    }

    #[test]
    fn recovers_abandoned_inflight_message_and_control() -> Result<()> {
        let td = tempdir()?;
        let maildrop = td.path().join("maildrop");
        let inflight = maildrop.join("inflight");
        fs::create_dir_all(&inflight)?;
        let eml = inflight.join("abandoned.eml");
        fs::write(&eml, b"X-RMail-Envelope-To: user@example.com\n\nbody")?;
        let json = rmail_common::outbound::control_path_for_eml(&eml);
        let mut control = QueueControl::new(7, 3);
        control.attempts = 2;
        fs::write(&json, serde_json::to_vec(&control)?)?;

        assert_eq!(recover_abandoned_inflight(&maildrop)?, 1);
        let queued = maildrop.join("queue/abandoned.eml");
        let recovered: QueueControl = serde_json::from_slice(&fs::read(
            rmail_common::outbound::control_path_for_eml(&queued),
        )?)?;
        assert!(queued.exists());
        assert_eq!(recovered.attempts, 2);
        assert_eq!(recover_abandoned_inflight(&maildrop)?, 0);
        Ok(())
    }

    #[test]
    fn repairs_claim_interrupted_after_sidecar_move() -> Result<()> {
        let td = tempdir()?;
        let maildrop = td.path().join("maildrop");
        let queue = maildrop.join("queue");
        let inflight = maildrop.join("inflight");
        fs::create_dir_all(&queue)?;
        fs::create_dir_all(&inflight)?;
        fs::write(queue.join("partial.eml"), b"body")?;
        let stranded = inflight.join("partial.eml.json");
        fs::write(&stranded, serde_json::to_vec(&QueueControl::new(5, 0))?)?;

        assert_eq!(recover_abandoned_inflight(&maildrop)?, 0);
        assert!(!stranded.exists());
        assert!(queue.join("partial.eml.json").exists());
        Ok(())
    }

    #[test]
    fn recovers_retry_interrupted_after_sidecar_move_without_resetting_control() -> Result<()> {
        let td = tempdir()?;
        let maildrop = td.path().join("maildrop");
        let queue = maildrop.join("queue");
        let inflight = maildrop.join("inflight");
        fs::create_dir_all(&queue)?;
        fs::create_dir_all(&inflight)?;
        let inflight_eml = inflight.join("retry.eml");
        fs::write(
            &inflight_eml,
            b"X-RMail-Envelope-To: user@example.com\r\n\r\nbody",
        )?;
        let mut control = QueueControl::new(7, 2);
        control.attempts = 4;
        control.next_try = Some(123_456);
        fs::write(
            rmail_common::outbound::control_path_for_eml(&queue.join("retry.eml")),
            serde_json::to_vec(&control)?,
        )?;

        assert_eq!(recover_abandoned_inflight(&maildrop)?, 1);
        assert!(!inflight_eml.exists());
        let recovered: QueueControl = serde_json::from_slice(&fs::read(
            rmail_common::outbound::control_path_for_eml(&queue.join("retry.eml")),
        )?)?;
        assert_eq!(recovered.attempts, 4);
        assert_eq!(recovered.next_try, Some(123_456));
        Ok(())
    }

    #[test]
    fn recovers_success_transition_by_finishing_sent_move() -> Result<()> {
        let td = tempdir()?;
        let outbound = td.path().join("outbound");
        let maildrop = outbound.join("maildrop");
        let inflight = maildrop.join("inflight");
        let sent = outbound.join("sent");
        fs::create_dir_all(&inflight)?;
        fs::create_dir_all(&sent)?;
        let inflight_eml = inflight.join("accepted.eml");
        fs::write(
            &inflight_eml,
            b"X-RMail-Envelope-To: user@example.com\r\n\r\nbody",
        )?;
        let mut control = QueueControl::new(5, 0);
        control.attempts = 1;
        fs::write(
            rmail_common::outbound::control_path_for_eml(&sent.join("accepted.eml")),
            serde_json::to_vec(&control)?,
        )?;

        assert_eq!(recover_abandoned_inflight(&maildrop)?, 1);
        assert!(!inflight_eml.exists());
        let sent_eml = sent.join("accepted.eml");
        assert!(sent_eml.exists());
        let recovered: QueueControl = serde_json::from_slice(&fs::read(
            rmail_common::outbound::control_path_for_eml(&sent_eml),
        )?)?;
        assert_eq!(recovered.attempts, 1);
        assert!(!maildrop.join("queue/accepted.eml").exists());
        Ok(())
    }

    #[test]
    fn recovers_queue_publication_after_sidecar_commit() -> Result<()> {
        let td = tempdir()?;
        let maildrop = td.path().join("maildrop");
        let tmp = maildrop.join("tmp");
        let queue = maildrop.join("queue");
        fs::create_dir_all(&tmp)?;
        fs::create_dir_all(&queue)?;
        let temporary_eml = tmp.join("published.eml");
        fs::write(
            &temporary_eml,
            b"X-RMail-Envelope-To: user@example.com\r\n\r\nbody",
        )?;
        let control = QueueControl::new(5, 0);
        fs::write(
            rmail_common::outbound::control_path_for_eml(&queue.join("published.eml")),
            serde_json::to_vec(&control)?,
        )?;

        assert_eq!(recover_abandoned_inflight(&maildrop)?, 1);
        assert!(!temporary_eml.exists());
        assert!(queue.join("published.eml").exists());
        Ok(())
    }

    #[test]
    fn recovers_dead_letter_transition_after_sidecar_move() -> Result<()> {
        let td = tempdir()?;
        let outbound = td.path().join("outbound");
        let maildrop = outbound.join("maildrop");
        let failed = outbound.join("failed");
        let dead = outbound.join("dead");
        fs::create_dir_all(&failed)?;
        fs::create_dir_all(&dead)?;
        let failed_eml = failed.join("expired.eml");
        fs::write(
            &failed_eml,
            b"X-RMail-Envelope-To: user@example.com\r\n\r\nbody",
        )?;
        let mut control = QueueControl::new(5, 0);
        control.attempts = 5;
        fs::write(
            rmail_common::outbound::control_path_for_eml(&dead.join("expired.eml")),
            serde_json::to_vec(&control)?,
        )?;

        assert_eq!(recover_abandoned_inflight(&maildrop)?, 1);
        assert!(!failed_eml.exists());
        assert!(dead.join("expired.eml").exists());
        Ok(())
    }
}
