use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rmail_common::outbound::QueueControl;
use serde_json::json;
use std::path::PathBuf;
use std::fs;

/// rmail_queuectl: inspect and manage the on-disk outbound queue (queue/inflight/sent/failed)
#[derive(Parser)]
#[command(name = "rmail_queuectl")]
struct Cli {
    /// Mail root directory (overrides RMAIL_MAIL_ROOT env)
    #[arg(long)]
    mail_root: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// List queued messages (default)
    List {
        /// Output JSON
        #[arg(long)]
        json: bool,
    },
    /// Show headers/body preview for a queued message
    Show {
        /// message filename (with or without .eml)
        name: String,
        /// number of body lines to show
        #[arg(long)]
        lines: Option<usize>,
    },
    /// Requeue a message from failed/inflight/sent back into queue (reset attempts)
    Requeue { name: String },
    /// Promote a message by setting a higher priority (moves to queue)
    Promote { name: String, #[arg(long)] priority: i32 },
    /// Delete a message (move to failed and mark as administratively deleted)
    Delete { name: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mail_root = cli.mail_root
        .or_else(|| std::env::var("RMAIL_MAIL_ROOT").ok())
        .unwrap_or_else(|| "./mail".to_string());
    let root = PathBuf::from(mail_root);

    match cli.command {
        None => cmd_list(&root, false)?,
        Some(Commands::List { json }) => cmd_list(&root, json)?,
        Some(Commands::Show { name, lines }) => cmd_show(&root, &name, lines.unwrap_or(20))?,
        Some(Commands::Requeue { name }) => cmd_requeue(&root, &name)?,
        Some(Commands::Promote { name, priority }) => cmd_promote(&root, &name, priority)?,
        Some(Commands::Delete { name }) => cmd_delete(&root, &name)?,
    }
    Ok(())
}

fn spool_dirs(base: &PathBuf) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let base = base.join("outbound");
    (base.join("queue"), base.join("inflight"), base.join("sent"), base.join("failed"))
}

fn read_entries(dir: &PathBuf) -> Result<Vec<(String, Option<QueueControl>)>> {
    let mut out = Vec::new();
    if !dir.exists() { return Ok(out); }
    for e in fs::read_dir(dir)? {
        let ent = e?;
        if !ent.file_type()?.is_file() { continue; }
        let fname = ent.file_name().into_string().unwrap_or_default();
        if !fname.ends_with(".eml") { continue; }
        let jsonp = dir.join(format!("{}.json", &fname));
        let control = if jsonp.exists() {
            match fs::read_to_string(&jsonp) {
                Ok(s) => serde_json::from_str::<QueueControl>(&s).ok(),
                Err(_) => None,
            }
        } else { None };
        out.push((fname, control));
    }
    out.sort_by(|a,b| a.0.cmp(&b.0));
    Ok(out)
}

fn cmd_list(root: &PathBuf, as_json: bool) -> Result<()> {
    let (queue, inflight, sent, failed) = spool_dirs(root);
    let q = read_entries(&queue).unwrap_or_default();
    let i = read_entries(&inflight).unwrap_or_default();
    let s = read_entries(&sent).unwrap_or_default();
    let f = read_entries(&failed).unwrap_or_default();

    if as_json {
        let mut arr = Vec::new();
        for (name, ctrl) in q.iter() {
            let mut obj = json!({"name": name});
            if let Some(c) = ctrl {
                obj["control"] = serde_json::to_value(&c).unwrap_or(json!(null));
            }
            arr.push(obj);
        }
        println!("{}", serde_json::to_string_pretty(&json!({"summary": {"queued": q.len(), "inflight": i.len(), "sent": s.len(), "failed": f.len()}, "queued_items": arr}))?);
        return Ok(());
    }

    println!("Outbound queue root: {}", root.join("outbound").display());
    println!("summary: queued={}, inflight={}, sent={}, failed={}", q.len(), i.len(), s.len(), f.len());
    if !q.is_empty() {
        println!("\nTop queued items:");
        for (idx, (name, control)) in q.iter().take(10).enumerate() {
            if let Some(c) = control {
                println!("{}. {} attempts={} max_attempts={} priority={} next_try={:?}", idx+1, name, c.attempts, c.max_attempts, c.priority, c.next_try);
            } else {
                println!("{}. {} (no control)", idx+1, name);
            }
        }
    }
    Ok(())
}

fn ensure_ext(name: &str) -> String {
    if name.ends_with(".eml") { name.to_string() } else { format!("{}.eml", name) }
}

fn find_message(root: &PathBuf, name: &str) -> Result<Option<(String, PathBuf, Option<PathBuf>)>> {
    let fname = ensure_ext(name);
    let (queue, inflight, sent, failed) = spool_dirs(root);
    let candidates = vec![("queue", queue), ("inflight", inflight), ("sent", sent), ("failed", failed)];
    for (spool, dir) in candidates {
        let eml = dir.join(&fname);
        if eml.exists() && eml.is_file() {
            let jsonp = dir.join(format!("{}.json", &fname));
            let j = if jsonp.exists() { Some(jsonp) } else { None };
            return Ok(Some((spool.to_string(), eml, j)));
        }
    }
    Ok(None)
}

fn read_control_opt(jsonp: &Option<PathBuf>) -> Option<QueueControl> {
    if let Some(p) = jsonp {
        match fs::read_to_string(p) {
            Ok(s) => serde_json::from_str::<QueueControl>(&s).ok(),
            Err(_) => None,
        }
    } else { None }
}

fn write_control(path: &PathBuf, ctrl: &QueueControl) -> Result<()> {
    let j = serde_json::to_string_pretty(ctrl)?;
    fs::write(path, j)?;
    Ok(())
}

fn cmd_show(root: &PathBuf, name: &str, body_lines: usize) -> Result<()> {
    if let Some((_spool, eml, jsonp)) = find_message(root, name)? {
        let data = fs::read(&eml)?;
        let s = String::from_utf8_lossy(&data);
        // split headers/body
        let split = if let Some(pos) = s.find("\r\n\r\n") { pos + 4 } else if let Some(pos) = s.find("\n\n") { pos + 2 } else { 0 };
        let header = &s[..split];
        let body = &s[split..];
        println!("Message: {}\n", eml.display());
        println!("== Headers ==\n{}");
        println!("{}", header);
        println!("== Body (first {} lines) ==", body_lines);
        for (i, line) in body.lines().take(body_lines).enumerate() {
            println!("{:3}: {}", i+1, line);
        }
        if let Some(c) = read_control_opt(&jsonp) {
            println!("\n== Control ==\n{:?}", c);
        } else {
            println!("\n== Control ==\n(none)");
        }
        Ok(())
    } else {
        Err(anyhow::anyhow!("message not found"))
    }
}

fn move_with_json(src_eml: &PathBuf, dst_dir: &PathBuf, json_opt: &Option<PathBuf>) -> Result<(PathBuf, Option<PathBuf>)> {
    fs::create_dir_all(dst_dir)?;
    let fname = src_eml.file_name().and_then(|n| n.to_str()).ok_or_else(|| anyhow::anyhow!("invalid filename"))?.to_string();
    let dst_eml = dst_dir.join(&fname);
    fs::rename(src_eml, &dst_eml)?;
    let dst_json = if let Some(jp) = json_opt {
        let dstj = dst_dir.join(jp.file_name().and_then(|n| n.to_str()).unwrap_or(""));
        fs::rename(jp, &dstj).ok();
        Some(dstj)
    } else { None };
    Ok((dst_eml, dst_json))
}

fn cmd_requeue(root: &PathBuf, name: &str) -> Result<()> {
    let fname = ensure_ext(name);
    if let Some((spool, eml, jsonp)) = find_message(root, &fname)? {
        let (queue, _inflight, _sent, _failed) = spool_dirs(root);
        if spool == "queue" {
            // reset attempts and next_try
            let ctrl = read_control_opt(&jsonp).unwrap_or_else(|| QueueControl::default_with_timestamp(0));
            let mut c = ctrl;
            c.attempts = 0;
            c.next_try = None;
            let jpath = queue.join(format!("{}.json", fname));
            write_control(&jpath, &c)?;
            println!("Reset attempts for {} in queue", fname);
            return Ok(());
        }
        let (dst_eml, dst_json) = move_with_json(&eml, &queue, &jsonp)?;
        // reset control
        let mut ctrl = read_control_opt(&dst_json).unwrap_or_else(|| QueueControl::default_with_timestamp(0));
        ctrl.attempts = 0;
        ctrl.next_try = None;
        ctrl.last_error = None;
        let jpath = queue.join(format!("{}.json", fname));
        write_control(&jpath, &ctrl)?;
        println!("Requeued {} (from {})", fname, spool);
        Ok(())
    } else {
        Err(anyhow::anyhow!("message not found"))
    }
}

fn cmd_promote(root: &PathBuf, name: &str, priority: i32) -> Result<()> {
    let fname = ensure_ext(name);
    if let Some((spool, eml, jsonp)) = find_message(root, &fname)? {
        let (queue, _inflight, _sent, _failed) = spool_dirs(root);
        // move to queue if not already
        let (dst_eml, dst_json) = if spool == "queue" {
            (eml.clone(), jsonp.clone())
        } else {
            move_with_json(&eml, &queue, &jsonp)?
        };
        let mut ctrl = read_control_opt(&dst_json).unwrap_or_else(|| QueueControl::default_with_timestamp(0));
        ctrl.priority = priority;
        let jpath = queue.join(format!("{}.json", fname));
        write_control(&jpath, &ctrl)?;
        println!("Promoted {} to priority {}", fname, priority);
        Ok(())
    } else {
        Err(anyhow::anyhow!("message not found"))
    }
}

fn cmd_delete(root: &PathBuf, name: &str) -> Result<()> {
    let fname = ensure_ext(name);
    if let Some((spool, eml, jsonp)) = find_message(root, &fname)? {
        let (_queue, _inflight, _sent, failed) = spool_dirs(root);
        let (dst_eml, dst_json) = if spool == "failed" {
            (eml.clone(), jsonp.clone())
        } else {
            move_with_json(&eml, &failed, &jsonp)?
        };
        // mark admin delete
        let mut ctrl = read_control_opt(&dst_json).unwrap_or_else(|| QueueControl::default_with_timestamp(0));
        ctrl.attempts = ctrl.max_attempts;
        ctrl.last_error = Some("deleted by admin".to_string());
        let jpath = failed.join(format!("{}.json", fname));
        write_control(&jpath, &ctrl)?;
        println!("Deleted (moved to failed) {}", fname);
        Ok(())
    } else {
        Err(anyhow::anyhow!("message not found"))
    }
}
