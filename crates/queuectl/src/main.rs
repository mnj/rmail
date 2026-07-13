#![allow(clippy::ptr_arg, clippy::type_complexity)]

use anyhow::Result;
use clap::{Parser, Subcommand};
use rmail_common::config::Config;
use rmail_common::db;
use rmail_common::outbound::QueueControl;
use serde_json::json;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
mod watch;

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
    /// Requeue a message by name or pattern
    Requeue {
        /// message filename or name (without .eml)
        #[arg(short, long)]
        name: Option<String>,
        /// pattern (supports '*' wildcard)
        #[arg(short, long)]
        pattern: Option<String>,
        /// Assume yes to all prompts
        #[arg(short = 'y', long, default_value_t = false)]
        yes: bool,
    },
    /// Promote a message by setting a higher priority (moves to queue)
    Promote {
        /// message filename or name (without .eml)
        #[arg(short, long)]
        name: Option<String>,
        /// pattern (supports '*' wildcard)
        #[arg(short, long)]
        pattern: Option<String>,
        /// priority value
        #[arg(long)]
        priority: i32,
        /// Assume yes to all prompts
        #[arg(short = 'y', long, default_value_t = false)]
        yes: bool,
    },
    /// Delete a message (move to failed and mark as administratively deleted)
    Delete {
        #[arg(short, long)]
        name: Option<String>,
        /// pattern (supports '*' wildcard)
        #[arg(short, long)]
        pattern: Option<String>,
        /// Assume yes to all prompts
        #[arg(short = 'y', long, default_value_t = false)]
        yes: bool,
    },
    /// Manage alias mappings (requires configured DB)
    Alias {
        #[command(subcommand)]
        action: AliasAction,
    },
    /// Watch live inbound and outbound SMTP activity
    Watch {
        /// Print events as a stream instead of opening the full-screen interface
        #[arg(long)]
        plain: bool,
        /// Number of recent durable events to load at startup
        #[arg(long, default_value_t = 250)]
        history: usize,
    },
    /// Show the durable event history for a message ID
    Track {
        message_id: String,
        #[arg(long, default_value_t = 500)]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum AliasAction {
    /// Add an alias mapping: address -> target1 target2 ...
    Add {
        /// address to alias (e.g., user@example.com)
        address: String,
        /// one or more target addresses
        targets: Vec<String>,
    },
    /// Remove an alias mapping for address
    Remove { address: String },
    /// List all aliases
    List {},
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mail_root = cli
        .mail_root
        .or_else(|| std::env::var("RMAIL_MAIL_ROOT").ok())
        .unwrap_or_else(|| "./mail".to_string());
    let root = PathBuf::from(mail_root);

    match cli.command {
        None => cmd_list(&root, false)?,
        Some(Commands::List { json }) => cmd_list(&root, json)?,
        Some(Commands::Show { name, lines }) => cmd_show(&root, &name, lines.unwrap_or(20))?,
        Some(Commands::Requeue { name, pattern, yes }) => {
            cmd_requeue(&root, name.as_deref(), pattern.as_deref(), yes)?
        }
        Some(Commands::Promote {
            name,
            pattern,
            priority,
            yes,
        }) => cmd_promote(&root, name.as_deref(), pattern.as_deref(), priority, yes)?,
        Some(Commands::Delete { name, pattern, yes }) => {
            cmd_delete(&root, name.as_deref(), pattern.as_deref(), yes)?
        }
        Some(Commands::Alias { action }) => match action {
            AliasAction::Add { address, targets } => cmd_alias_add(&root, &address, &targets)?,
            AliasAction::Remove { address } => cmd_alias_remove(&root, &address)?,
            AliasAction::List {} => cmd_alias_list(&root)?,
        },
        #[cfg(unix)]
        Some(Commands::Watch { plain, history }) => watch::run(&root, plain, history)?,
        #[cfg(not(unix))]
        Some(Commands::Watch { .. }) => anyhow::bail!("watch requires Unix-domain sockets"),
        Some(Commands::Track { message_id, limit }) => {
            for event in rmail_common::tracking::recent_events(&root, limit, Some(&message_id))? {
                println!("{}", serde_json::to_string(&event)?);
            }
        }
    }
    Ok(())
}

fn cmd_alias_add(_root: &PathBuf, address: &str, targets: &Vec<String>) -> Result<()> {
    // Use RMAIL_CONFIG or fall back to config/example.toml
    let cfg_path =
        std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let cfg = Config::from_file(&cfg_path)?;
    let dbp = cfg
        .global
        .db_path
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No db_path configured"))?
        .to_string();
    let addr_lc = address.to_ascii_lowercase();
    let tgt_refs: Vec<&str> = targets.iter().map(|s| s.as_str()).collect();
    db::add_alias(&dbp, &addr_lc, &tgt_refs)?;
    println!("Added alias {} -> {:?}", address, targets);
    Ok(())
}

fn cmd_alias_remove(_root: &PathBuf, address: &str) -> Result<()> {
    let cfg_path =
        std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let cfg = Config::from_file(&cfg_path)?;
    let dbp = cfg
        .global
        .db_path
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No db_path configured"))?
        .to_string();
    let addr_lc = address.to_ascii_lowercase();
    db::remove_alias(&dbp, &addr_lc)?;
    println!("Removed alias {}", address);
    Ok(())
}

fn cmd_alias_list(_root: &PathBuf) -> Result<()> {
    let cfg_path =
        std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let cfg = Config::from_file(&cfg_path)?;
    let dbp = cfg
        .global
        .db_path
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No db_path configured"))?
        .to_string();
    let aliases = db::list_aliases(&dbp)?;
    for (addr, targets) in aliases {
        println!("{} -> {}", addr, targets.join(", "));
    }
    Ok(())
}

fn spool_dirs(base: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let base = base.join("outbound");
    (
        base.join("maildrop").join("queue"),
        base.join("maildrop").join("inflight"),
        base.join("sent"),
        base.join("failed"),
    )
}

fn read_entries(dir: &PathBuf) -> Result<Vec<(String, Option<QueueControl>)>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for e in fs::read_dir(dir)? {
        let ent = e?;
        if !ent.file_type()?.is_file() {
            continue;
        }
        let fname = ent.file_name().into_string().unwrap_or_default();
        if !fname.ends_with(".eml") {
            continue;
        }
        let jsonp = rmail_common::outbound::control_path_for_eml(&dir.join(&fname));
        let control = if jsonp.exists() {
            match fs::read_to_string(&jsonp) {
                Ok(s) => serde_json::from_str::<QueueControl>(&s).ok(),
                Err(_) => None,
            }
        } else {
            None
        };
        out.push((fname, control));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn ensure_ext(name: &str) -> String {
    if name.ends_with(".eml") {
        name.to_string()
    } else {
        format!("{}.eml", name)
    }
}

fn find_message(root: &PathBuf, name: &str) -> Result<Option<(String, PathBuf, Option<PathBuf>)>> {
    let fname = ensure_ext(name);
    let (queue, inflight, sent, failed) = spool_dirs(root);
    let candidates = vec![
        ("queue", queue),
        ("inflight", inflight),
        ("sent", sent),
        ("failed", failed),
    ];
    for (spool, dir) in candidates {
        let eml = dir.join(&fname);
        if eml.exists() && eml.is_file() {
            let jsonp = rmail_common::outbound::control_path_for_eml(&eml);
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
    } else {
        None
    }
}

fn write_control(path: &PathBuf, ctrl: &QueueControl) -> Result<()> {
    let j = serde_json::to_string_pretty(ctrl)?;
    fs::write(path, j)?;
    Ok(())
}

fn move_with_json(
    src_eml: &Path,
    dst_dir: &PathBuf,
    _json_opt: &Option<PathBuf>,
) -> Result<(PathBuf, Option<PathBuf>)> {
    fs::create_dir_all(dst_dir)?;
    let fname = src_eml
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid filename"))?
        .to_string();
    let dst_eml = dst_dir.join(&fname);
    let dst_json = rmail_queue_manager::move_message_and_control(src_eml, &dst_eml)?;
    Ok((dst_eml, Some(dst_json)))
}

fn matches_pattern(name: &str, pattern: &str) -> bool {
    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        let mut rem = name;
        for (i, p) in parts.iter().enumerate() {
            if p.is_empty() {
                continue;
            }
            if let Some(pos) = rem.find(p) {
                if i == 0 && !pattern.starts_with('*') && pos != 0 {
                    return false;
                }
                rem = &rem[pos + p.len()..];
            } else {
                return false;
            }
        }
        if !pattern.ends_with('*')
            && let Some(last) = parts.iter().rev().find(|s| !s.is_empty())
            && !name.ends_with(last)
        {
            return false;
        }
        true
    } else {
        name == pattern || name == format!("{}.eml", pattern) || name.contains(pattern)
    }
}

fn find_messages_matching(
    root: &PathBuf,
    pattern: &str,
) -> Result<Vec<(String, PathBuf, Option<PathBuf>, String)>> {
    let (queue, inflight, sent, failed) = spool_dirs(root);
    let mut out = Vec::new();
    let dirs = vec![
        ("queue", queue),
        ("inflight", inflight),
        ("sent", sent),
        ("failed", failed),
    ];
    for (spool, dir) in dirs {
        if !dir.exists() {
            continue;
        }
        for e in fs::read_dir(&dir)? {
            let ent = e?;
            if !ent.file_type()?.is_file() {
                continue;
            }
            let fname = ent.file_name().into_string().unwrap_or_default();
            if !fname.ends_with(".eml") {
                continue;
            }
            if matches_pattern(&fname, pattern)
                || matches_pattern(&fname, &format!("{}.eml", pattern))
                || matches_pattern(&fname, pattern.trim_matches('*'))
            {
                let eml = dir.join(&fname);
                let jsonp = rmail_common::outbound::control_path_for_eml(&eml);
                let j = if jsonp.exists() { Some(jsonp) } else { None };
                out.push((spool.to_string(), eml, j, fname));
            }
        }
    }
    Ok(out)
}

fn confirm(prompt: &str, auto_yes: bool) -> bool {
    if auto_yes {
        return true;
    }
    print!("{} [y/N]: ", prompt);
    io::stdout().flush().ok();
    let mut line = String::new();
    match io::stdin().read_line(&mut line) {
        Ok(_) => {
            let t = line.trim().to_lowercase();
            t == "y" || t == "yes"
        }
        Err(_) => false,
    }
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
                obj["control"] = serde_json::to_value(c).unwrap_or(json!(null));
            }
            arr.push(obj);
        }
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"summary": {"queued": q.len(), "inflight": i.len(), "sent": s.len(), "failed": f.len()}, "queued_items": arr})
            )?
        );
        return Ok(());
    }

    println!(
        "Outbound queue root: {}",
        root.join("outbound").join("maildrop").display()
    );
    println!(
        "summary: queued={}, inflight={}, sent={}, failed={}",
        q.len(),
        i.len(),
        s.len(),
        f.len()
    );
    if !q.is_empty() {
        println!("\nTop queued items:");
        for (idx, (name, control)) in q.iter().take(10).enumerate() {
            if let Some(c) = control {
                println!(
                    "{}. {} attempts={} max_attempts={} priority={} next_try={:?}",
                    idx + 1,
                    name,
                    c.attempts,
                    c.max_attempts,
                    c.priority,
                    c.next_try
                );
            } else {
                println!("{}. {} (no control)", idx + 1, name);
            }
        }
    }
    Ok(())
}

fn cmd_show(root: &PathBuf, name: &str, body_lines: usize) -> Result<()> {
    if let Some((_spool, eml, jsonp)) = find_message(root, name)? {
        let data = fs::read(&eml)?;
        let s = String::from_utf8_lossy(&data);
        // split headers/body
        let split = if let Some(pos) = s.find("\r\n\r\n") {
            pos + 4
        } else if let Some(pos) = s.find("\n\n") {
            pos + 2
        } else {
            0
        };
        let header = &s[..split];
        let body = &s[split..];
        println!("Message: {}\n", eml.display());
        println!("== Headers ==");
        println!("{}", header);
        println!("== Body (first {} lines) ==", body_lines);
        for (i, line) in body.lines().take(body_lines).enumerate() {
            println!("{:3}: {}", i + 1, line);
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

fn requeue_single(
    spool: &str,
    eml: &PathBuf,
    jsonp: &Option<PathBuf>,
    root: &PathBuf,
) -> Result<()> {
    let (queue, _inflight, _sent, _failed) = spool_dirs(root);
    if spool == "queue" {
        let fname = eml.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let ctrl =
            read_control_opt(jsonp).unwrap_or_else(|| QueueControl::default_with_timestamp(0));
        let mut c = ctrl;
        c.attempts = 0;
        c.next_try = None;
        let jpath = queue.join(format!("{}.json", fname));
        write_control(&jpath, &c)?;
        println!("Reset attempts for {} in queue", fname);
        return Ok(());
    }
    let (dst_eml, dst_json) = move_with_json(eml, &queue, jsonp)?;
    let mut ctrl =
        read_control_opt(&dst_json).unwrap_or_else(|| QueueControl::default_with_timestamp(0));
    ctrl.attempts = 0;
    ctrl.next_try = None;
    ctrl.last_error = None;
    let fname = dst_eml.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let jpath = queue.join(format!("{}.json", fname));
    write_control(&jpath, &ctrl)?;
    println!("Requeued {} (from {})", fname, spool);
    Ok(())
}

fn cmd_requeue(root: &PathBuf, name: Option<&str>, pattern: Option<&str>, yes: bool) -> Result<()> {
    if let Some(n) = name {
        let fname = ensure_ext(n);
        if let Some((spool, eml, jsonp)) = find_message(root, &fname)? {
            if !confirm(&format!("Requeue {} from {}?", fname, spool), yes) {
                println!("aborted");
                return Ok(());
            }
            return requeue_single(&spool, &eml, &jsonp, root);
        } else {
            return Err(anyhow::anyhow!("message not found"));
        }
    }
    if let Some(pat) = pattern {
        let matches = find_messages_matching(root, pat)?;
        if matches.is_empty() {
            println!("No matches for pattern {}", pat);
            return Ok(());
        }
        println!("Found {} matches for pattern {}", matches.len(), pat);
        for (spool, eml, jsonp, fname) in matches {
            if !confirm(&format!("Requeue {} from {}?", fname, spool), yes) {
                println!("skipping {}", fname);
                continue;
            }
            requeue_single(&spool, &eml, &jsonp, root)?;
        }
        return Ok(());
    }
    Err(anyhow::anyhow!("Provide --name or --pattern"))
}

fn cmd_promote(
    root: &PathBuf,
    name: Option<&str>,
    pattern: Option<&str>,
    priority: i32,
    yes: bool,
) -> Result<()> {
    if let Some(n) = name {
        let fname = ensure_ext(n);
        if let Some((spool, eml, jsonp)) = find_message(root, &fname)? {
            if !confirm(
                &format!("Promote {} from {} to priority {}?", fname, spool, priority),
                yes,
            ) {
                println!("aborted");
                return Ok(());
            }
            let (queue, _i, _s, _f) = spool_dirs(root);
            let (_dst_eml, dst_json) = if spool == "queue" {
                (eml.clone(), jsonp.clone())
            } else {
                move_with_json(&eml, &queue, &jsonp)?
            };
            let mut ctrl = read_control_opt(&dst_json)
                .unwrap_or_else(|| QueueControl::default_with_timestamp(0));
            ctrl.priority = priority;
            let jpath = queue.join(format!("{}.json", ensure_ext(&fname)));
            write_control(&jpath, &ctrl)?;
            println!("Promoted {} to priority {}", fname, priority);
            return Ok(());
        } else {
            return Err(anyhow::anyhow!("message not found"));
        }
    }
    if let Some(pat) = pattern {
        let matches = find_messages_matching(root, pat)?;
        if matches.is_empty() {
            println!("No matches for pattern {}", pat);
            return Ok(());
        }
        println!("Found {} matches for pattern {}", matches.len(), pat);
        for (spool, eml, jsonp, fname) in matches {
            if !confirm(
                &format!("Promote {} from {} to priority {}?", fname, spool, priority),
                yes,
            ) {
                println!("skipping {}", fname);
                continue;
            }
            let (queue, _i, _s, _f) = spool_dirs(root);
            let (_dst_eml, dst_json) = if spool == "queue" {
                (eml.clone(), jsonp.clone())
            } else {
                move_with_json(&eml, &queue, &jsonp)?
            };
            let mut ctrl = read_control_opt(&dst_json)
                .unwrap_or_else(|| QueueControl::default_with_timestamp(0));
            ctrl.priority = priority;
            let jpath = queue.join(format!("{}.json", fname));
            write_control(&jpath, &ctrl)?;
            println!("Promoted {} to priority {}", fname, priority);
        }
        return Ok(());
    }
    Err(anyhow::anyhow!("Provide --name or --pattern"))
}

fn cmd_delete(root: &PathBuf, name: Option<&str>, pattern: Option<&str>, yes: bool) -> Result<()> {
    if let Some(n) = name {
        let fname = ensure_ext(n);
        if let Some((spool, eml, jsonp)) = find_message(root, &fname)? {
            if !confirm(
                &format!("Delete {} from {}? (move to failed)", fname, spool),
                yes,
            ) {
                println!("aborted");
                return Ok(());
            }
            let (_q, _i, _s, failed) = spool_dirs(root);
            let (_dst_eml, dst_json) = if spool == "failed" {
                (eml.clone(), jsonp.clone())
            } else {
                move_with_json(&eml, &failed, &jsonp)?
            };
            let mut ctrl = read_control_opt(&dst_json)
                .unwrap_or_else(|| QueueControl::default_with_timestamp(0));
            ctrl.attempts = ctrl.max_attempts;
            ctrl.last_error = Some("deleted by admin".to_string());
            let jpath = failed.join(format!("{}.json", fname));
            write_control(&jpath, &ctrl)?;
            println!("Deleted (moved to failed) {}", fname);
            return Ok(());
        } else {
            return Err(anyhow::anyhow!("message not found"));
        }
    }
    if let Some(pat) = pattern {
        let matches = find_messages_matching(root, pat)?;
        if matches.is_empty() {
            println!("No matches for pattern {}", pat);
            return Ok(());
        }
        println!("Found {} matches for pattern {}", matches.len(), pat);
        for (spool, eml, jsonp, fname) in matches {
            if !confirm(
                &format!("Delete {} from {}? (move to failed)", fname, spool),
                yes,
            ) {
                println!("skipping {}", fname);
                continue;
            }
            let (_dst_eml, _dst_json) = (eml.clone(), jsonp.clone());
            // move_with_json above is a bit awkward for batch; simpler: move to failed directly
            let (_q, _i, _s, failed) = spool_dirs(root);
            let (_dst_eml2, dst_json2) = move_with_json(&eml, &failed, &jsonp)?;
            let mut ctrl = read_control_opt(&dst_json2)
                .unwrap_or_else(|| QueueControl::default_with_timestamp(0));
            ctrl.attempts = ctrl.max_attempts;
            ctrl.last_error = Some("deleted by admin".to_string());
            let jpath = failed.join(format!("{}.json", fname));
            write_control(&jpath, &ctrl)?;
            println!("Deleted (moved to failed) {}", fname);
        }
        return Ok(());
    }
    Err(anyhow::anyhow!("Provide --name or --pattern"))
}
