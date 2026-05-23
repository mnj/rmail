use anyhow::Result;
use clap::Parser;
use rmail_common::outbound::QueueControl;
use std::path::PathBuf;
use std::fs;

/// rmail_queuectl: inspect the on-disk outbound queue (queue/inflight/sent/failed)
#[derive(Parser)]
#[command(name = "rmail_queuectl")]
struct Cli {
    /// Mail root directory (overrides RMAIL_MAIL_ROOT env)
    #[arg(long)]
    mail_root: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mail_root = cli.mail_root
        .or_else(|| std::env::var("RMAIL_MAIL_ROOT").ok())
        .unwrap_or_else(|| "./mail".to_string());
    inspect_queue(&PathBuf::from(mail_root))?;
    Ok(())
}

fn inspect_queue(mail_root: &PathBuf) -> Result<()> {
    let base = mail_root.join("outbound");
    let queue = base.join("queue");
    let inflight = base.join("inflight");
    let sent = base.join("sent");
    let failed = base.join("failed");

    println!("Outbound queue root: {}", base.display());

    let q = read_entries(&queue)?;
    let i = read_entries(&inflight)?;
    let s = read_entries(&sent)?;
    let f = read_entries(&failed)?;

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
    // sort by filename (which includes timestamp prefix)
    out.sort_by(|a,b| a.0.cmp(&b.0));
    Ok(out)
}
