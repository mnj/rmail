// rmail_web: minimal tokio-based HTTP UI for stats and logs (no hyper/axum)

use anyhow::{Context, Result};
use base64::Engine;
use rmail_common::auth;
use rmail_common::config::Config;
use rmail_common::outbound::QueueControl;
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

#[derive(Serialize)]
struct Stats {
    mailboxes: usize,
    total_messages: usize,
    delivered_count: u64,
    outbound_pending: usize,
}

fn tail_lines(s: &str, n: usize) -> String {
    let mut out: Vec<&str> = s.lines().rev().take(n).collect();
    out.reverse();
    out.join("\n")
}

fn scan_maildirs_sync(mail_root: &std::path::Path) -> Result<Stats> {
    let mut mailbox_count = 0usize;
    let mut total_messages = 0usize;
    if !mail_root.exists() || !mail_root.is_dir() {
        return Ok(Stats {
            mailboxes: 0,
            total_messages: 0,
            delivered_count: 0,
            outbound_pending: 0,
        });
    }
    for domain_entry in std::fs::read_dir(mail_root)? {
        let domain_entry = domain_entry?;
        if !domain_entry.file_type()?.is_dir() {
            continue;
        }
        let domain_path = domain_entry.path();
        for local_entry in std::fs::read_dir(domain_path)? {
            let local_entry = local_entry?;
            if !local_entry.file_type()?.is_dir() {
                continue;
            }
            let maildir_path = local_entry.path().join("Maildir");
            if !maildir_path.exists() {
                continue;
            }
            mailbox_count += 1;
            for dname in ["new", "cur"] {
                let dirpath = maildir_path.join(dname);
                if dirpath.exists() && dirpath.is_dir() {
                    for entry in std::fs::read_dir(&dirpath)? {
                        let e = entry?;
                        if e.file_type()?.is_file() {
                            total_messages += 1;
                        }
                    }
                }
            }
        }
    }
    Ok(Stats {
        mailboxes: mailbox_count,
        total_messages,
        delivered_count: 0,
        outbound_pending: count_queue_entries_sync(mail_root)?,
    })
}

// --- on-disk queue helper functions (synchronous) ---
fn spool_dirs(base: &PathBuf) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let base = base.join("outbound");
    (
        base.join("maildrop").join("queue"),
        base.join("maildrop").join("inflight"),
        base.join("sent"),
        base.join("failed"),
    )
}

fn count_queue_entries_sync(root: &std::path::Path) -> Result<usize> {
    let queue_dir = root.join("outbound").join("maildrop").join("queue");
    if !queue_dir.exists() {
        return Ok(0);
    }
    let mut count = 0usize;
    for entry in std::fs::read_dir(queue_dir)? {
        let ent = entry?;
        if ent.file_type()?.is_file()
            && ent.path().extension().and_then(|s| s.to_str()) == Some("eml")
        {
            count += 1;
        }
    }
    Ok(count)
}

fn read_queue_entries(dir: &PathBuf) -> Result<Vec<serde_json::Value>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for e in std::fs::read_dir(dir)? {
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
            match std::fs::read_to_string(&jsonp) {
                Ok(s) => serde_json::from_str::<QueueControl>(&s)
                    .ok()
                    .map(|c| serde_json::to_value(c).unwrap_or(serde_json::json!(null))),
                Err(_) => Some(serde_json::json!(null)),
            }
        } else {
            None
        };
        let mut obj = serde_json::json!({"name": fname});
        if let Some(c) = control {
            obj["control"] = c;
        }
        out.push(obj);
    }
    out.sort_by(|a, b| {
        a["name"]
            .as_str()
            .unwrap_or("")
            .cmp(&b["name"].as_str().unwrap_or(""))
    });
    Ok(out)
}

fn ensure_ext(name: &str) -> String {
    if name.ends_with(".eml") {
        name.to_string()
    } else {
        format!("{}.eml", name)
    }
}

fn find_message_sync(
    root: &PathBuf,
    name: &str,
) -> Result<Option<(String, PathBuf, Option<PathBuf>)>> {
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

fn read_control_opt_sync(jsonp: &Option<PathBuf>) -> Option<QueueControl> {
    if let Some(p) = jsonp {
        match std::fs::read_to_string(p) {
            Ok(s) => serde_json::from_str::<QueueControl>(&s).ok(),
            Err(_) => None,
        }
    } else {
        None
    }
}

fn write_control_sync(path: &PathBuf, ctrl: &QueueControl) -> Result<()> {
    let j = serde_json::to_string_pretty(ctrl)?;
    std::fs::write(path, j)?;
    Ok(())
}

fn move_with_json_sync(
    src_eml: &PathBuf,
    dst_dir: &PathBuf,
    json_opt: &Option<PathBuf>,
) -> Result<(PathBuf, Option<PathBuf>)> {
    std::fs::create_dir_all(dst_dir)?;
    let fname = src_eml
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid filename"))?
        .to_string();
    let dst_eml = dst_dir.join(&fname);
    std::fs::rename(src_eml, &dst_eml)?;
    let dst_json = if let Some(jp) = json_opt {
        let dstj = dst_dir.join(jp.file_name().and_then(|n| n.to_str()).unwrap_or(""));
        std::fs::rename(jp, &dstj).ok();
        Some(dstj)
    } else {
        None
    };
    Ok((dst_eml, dst_json))
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
        if !pattern.ends_with('*') {
            if let Some(last) = parts.iter().rev().find(|s| !s.is_empty()) {
                if !name.ends_with(last) {
                    return false;
                }
            }
        }
        true
    } else {
        name == pattern || name == format!("{}.eml", pattern) || name.contains(pattern)
    }
}

fn find_messages_matching_sync(
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
        for e in std::fs::read_dir(&dir)? {
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

fn requeue_single_sync(
    spool: &str,
    eml: &PathBuf,
    jsonp: &Option<PathBuf>,
    root: &PathBuf,
) -> Result<()> {
    let (queue, _inflight, _sent, _failed) = spool_dirs(root);
    if spool == "queue" {
        if let Some(j) = jsonp {
            if let Some(mut ctrl) = read_control_opt_sync(&Some(j.clone())) {
                ctrl.attempts = 0;
                ctrl.next_try = None;
                write_control_sync(j, &ctrl)?;
            }
        }
        return Ok(());
    }
    let (_dst_eml, dst_json) = move_with_json_sync(eml, &queue, jsonp)?;
    if let Some(jp) = dst_json {
        let mut ctrl = read_control_opt_sync(&Some(jp.clone()))
            .unwrap_or_else(|| QueueControl::default_with_timestamp(0));
        ctrl.attempts = 0;
        ctrl.next_try = None;
        write_control_sync(&jp, &ctrl)?;
    }
    Ok(())
}

fn promote_single_sync(
    spool: &str,
    eml: &PathBuf,
    jsonp: &Option<PathBuf>,
    root: &PathBuf,
    priority: i32,
) -> Result<()> {
    let (queue, _inflight, _sent, _failed) = spool_dirs(root);
    let dst_json = if spool == "queue" {
        jsonp.clone()
    } else {
        let (_dst_eml, dst_json) = move_with_json_sync(eml, &queue, jsonp)?;
        dst_json
    };
    if let Some(jp) = dst_json {
        let mut ctrl = read_control_opt_sync(&Some(jp.clone()))
            .unwrap_or_else(|| QueueControl::default_with_timestamp(0));
        ctrl.priority = priority;
        write_control_sync(&jp, &ctrl)?;
    }
    Ok(())
}

fn delete_single_sync(
    _spool: &str,
    eml: &PathBuf,
    jsonp: &Option<PathBuf>,
    root: &PathBuf,
) -> Result<()> {
    let (_queue, _inflight, _sent, failed) = spool_dirs(root);
    let (_dst_eml, dst_json) = move_with_json_sync(eml, &failed, jsonp)?;
    if let Some(jp) = dst_json {
        let mut ctrl = read_control_opt_sync(&Some(jp.clone()))
            .unwrap_or_else(|| QueueControl::default_with_timestamp(0));
        ctrl.attempts = ctrl.max_attempts;
        ctrl.last_error = Some("deleted by admin".to_string());
        write_control_sync(&jp, &ctrl)?;
    }
    Ok(())
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    mail_root: PathBuf,
    admin_user: Option<String>,
    admin_hash: Option<String>,
    db_path: Option<String>,
    acme_challenge_dir: Option<String>,
) {
    let peer = match stream.peer_addr() {
        Ok(p) => p.to_string(),
        Err(_) => "unknown".to_string(),
    };
    let mut reader = BufReader::new(stream);
    let mut first_line = String::new();
    // read request line
    match reader.read_line(&mut first_line).await {
        Ok(0) => return,
        Ok(_) => {}
        Err(_) => return,
    }
    let req_line = first_line
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string();
    // read headers until empty line, store them in a map
    let mut headers: HashMap<String, String> = HashMap::new();
    loop {
        let mut h = String::new();
        match reader.read_line(&mut h).await {
            Ok(0) => break,
            Ok(_) => {
                if h == "\r\n" || h == "\n" {
                    break;
                }
                if let Some(colon) = h.find(':') {
                    let name = h[..colon].trim().to_ascii_lowercase();
                    let val = h[colon + 1..].trim().to_string();
                    headers.insert(name, val);
                }
            }
            Err(_) => break,
        }
    }

    // parse request line: METHOD PATH HTTP/X
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path_q = parts.next().unwrap_or("/");

    // simple basic auth checker closure: returns true if no admin_user configured or credentials match
    let is_authorized = |headers: &HashMap<String, String>| -> bool {
        if admin_user.is_none() {
            return true;
        }
        let expected_user = admin_user.as_ref().unwrap();
        let expected_hash = match &admin_hash {
            Some(h) => h,
            None => return false,
        };
        if let Some(authz) = headers.get("authorization") {
            if authz.len() > 6 && authz[..6].eq_ignore_ascii_case("Basic ") {
                let b64 = authz[6..].trim();
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
                    if let Ok(creds) = String::from_utf8(bytes) {
                        if let Some(colon) = creds.find(':') {
                            let u = &creds[..colon];
                            let p = &creds[colon + 1..];
                            if u == expected_user {
                                if let Ok(valid) = auth::verify_password(p, expected_hash) {
                                    return valid;
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    };
    let mut extra_headers = String::new();

    // prepare response
    let mut status = 200;
    let mut content_type = "text/plain".to_string();
    let mut body = String::new();

    // read body for POST requests
    let mut body_bytes: Vec<u8> = Vec::new();
    if method == "POST" {
        if let Some(cl) = headers.get("content-length") {
            if let Ok(n) = cl.parse::<usize>() {
                body_bytes.resize(n, 0);
                let _ = reader.read_exact(&mut body_bytes).await;
            }
        }
    }

    let (path, query) = if let Some(pos) = path_q.find('?') {
        (&path_q[..pos], &path_q[pos + 1..])
    } else {
        (path_q, "")
    };
    // Serve ACME http-01 challenge files from configured directory
    if path.starts_with("/.well-known/acme-challenge/") {
        if method != "GET" {
            status = 405;
            body = "Method Not Allowed".to_string();
        } else {
            let token = &path["/.well-known/acme-challenge/".len()..];
            if let Some(acme_dir) = acme_challenge_dir.as_ref() {
                let fpath = std::path::Path::new(acme_dir).join(token);
                match tokio::fs::read_to_string(fpath).await {
                    Ok(s) => {
                        content_type = "text/plain".to_string();
                        body = s;
                    }
                    Err(_) => {
                        status = 404;
                        body = "Not Found".to_string();
                    }
                }
            } else {
                status = 404;
                body = "Not Found".to_string();
            }
        }
    } else {
        match path {
            "/" => {
                if method != "GET" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else {
                    content_type = "text/html".to_string();
                    body = "<html><body><h1>rMail Web UI</h1><ul><li><a href='/health'>health</a></li><li><a href='/stats'>stats</a></li><li><a href='/metrics'>metrics</a></li><li><a href='/logs?component=smtpd'>smtpd logs</a></li></ul></body></html>".to_string();
                }
            }
            "/health" => {
                if method != "GET" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else {
                    content_type = "text/plain".to_string();
                    body = "ok".to_string();
                }
            }
            "/stats" => {
                if method != "GET" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else if !is_authorized(&headers) {
                    status = 401;
                    body = "Unauthorized".to_string();
                    extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                } else {
                    // run blocking scan in threadpool
                    let mr_clone = mail_root.clone();
                    match tokio::task::spawn_blocking(move || scan_maildirs_sync(&mr_clone)).await {
                        Ok(Ok(mut stats)) => {
                            // attempt to read delivered count from metrics file (fallback)
                            let delivered = tokio::fs::read_to_string(
                                rmail_common::runtime::delivered_count_path(&mail_root),
                            )
                            .await
                            .ok()
                            .and_then(|s| s.trim().parse::<u64>().ok())
                            .unwrap_or(0);
                            stats.delivered_count = delivered;
                            content_type = "application/json".to_string();
                            body = match serde_json::to_string(&stats) {
                                Ok(s) => s,
                                Err(e) => {
                                    status = 500;
                                    format!("{{\"error\":\"{}\"}}", e)
                                }
                            };
                        }
                        Ok(Err(e)) => {
                            status = 500;
                            body = format!("scan error: {}", e);
                        }
                        Err(e) => {
                            status = 500;
                            body = format!("task join error: {}", e);
                        }
                    }
                }
            }
            "/metrics" => {
                if method != "GET" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else if !is_authorized(&headers) {
                    status = 401;
                    body = "Unauthorized".to_string();
                    extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                } else {
                    // Expose Prometheus-style metrics
                    let mut metrics_text = match tokio::fs::read_to_string(
                        rmail_common::runtime::prometheus_snapshot_path(&mail_root, "smtpd"),
                    )
                    .await
                    {
                        Ok(s) => s,
                        Err(_) => rmail_common::metrics::gather_prometheus(),
                    };
                    match count_queue_entries_sync(&mail_root) {
                        Ok(n) => {
                            metrics_text.push_str("# HELP rmail_outbound_pending Number of pending outbound messages\n");
                            metrics_text.push_str("# TYPE rmail_outbound_pending gauge\n");
                            metrics_text.push_str(&format!("rmail_outbound_pending {}\n", n));
                        }
                        Err(e) => {
                            eprintln!("failed to read outbound queue size: {}", e);
                        }
                    }
                    content_type = "text/plain".to_string();
                    body = metrics_text;
                }
            }
            "/dmarc" => {
                // DMARC reporting overview: domains with unreported events and counts
                if method != "GET" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else if !is_authorized(&headers) {
                    status = 401;
                    body = "Unauthorized".to_string();
                    extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                } else if let Some(dbp) = db_path.as_ref() {
                    // fetch unreported domains and counts in blocking thread
                    match tokio::task::spawn_blocking({
                        let dbp = dbp.clone();
                        move || rmail_common::db::get_unreported_dmarc_domains(&dbp)
                    })
                    .await
                    {
                        Ok(Ok(domains)) => {
                            let mut out: Vec<serde_json::Value> = Vec::new();
                            for d in domains {
                                match rmail_common::db::fetch_unreported_dmarc_events_for_domain(
                                    dbp.as_str(),
                                    &d,
                                ) {
                                    Ok(evts) => {
                                        out.push(
                                            serde_json::json!({"domain": d, "events": evts.len()}),
                                        );
                                    }
                                    Err(e) => {
                                        eprintln!("failed to fetch events for {}: {}", d, e);
                                    }
                                }
                            }
                            content_type = "application/json".to_string();
                            body = serde_json::to_string(&out).unwrap_or_else(|e| {
                                status = 500;
                                format!("{{\"error\":\"{}\"}}", e)
                            });
                        }
                        Ok(Err(e)) => {
                            status = 500;
                            body = format!("db error: {}", e);
                        }
                        Err(e) => {
                            status = 500;
                            body = format!("task join error: {}", e);
                        }
                    }
                } else {
                    status = 400;
                    body = "DB not configured".to_string();
                }
            }
            "/logs" => {
                if method != "GET" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else if !is_authorized(&headers) {
                    status = 401;
                    body = "Unauthorized".to_string();
                    extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                } else {
                    // parse query params for component and lines (simple parser, no percent-decoding)
                    let params: HashMap<_, _> = query
                        .split('&')
                        .filter_map(|kv| {
                            if kv.is_empty() {
                                return None;
                            }
                            let mut s = kv.splitn(2, '=');
                            let k = s.next().unwrap_or("").to_string();
                            let v = s.next().unwrap_or("").to_string();
                            if k.is_empty() { None } else { Some((k, v)) }
                        })
                        .collect();
                    let component = params
                        .get("component")
                        .map(|s| s.as_str())
                        .unwrap_or("smtpd");
                    let mut lines: usize = params
                        .get("lines")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(200);
                    lines = std::cmp::min(lines, 2000);
                    match component {
                        "smtpd" | "imapd" | "web" | "outbound" => {
                            let path = rmail_common::runtime::log_path(&mail_root, component);
                            match tokio::fs::read_to_string(&path).await {
                                Ok(s) => {
                                    content_type = "text/plain".to_string();
                                    body = tail_lines(&s, lines);
                                }
                                Err(e) => {
                                    status = 500;
                                    body = format!("read error from {}: {}", path.display(), e);
                                }
                            }
                        }
                        _ => {
                            status = 400;
                            body = "invalid component".to_string();
                        }
                    }
                }
            }
            "/api/queue/requeue" => {
                if method != "POST" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else {
                    if !is_authorized(&headers) {
                        status = 401;
                        body = "Unauthorized".to_string();
                        extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                    } else {
                        let b = String::from_utf8_lossy(&body_bytes).to_string();
                        match serde_json::from_str::<serde_json::Value>(&b) {
                            Ok(val) => {
                                let mr_clone = mail_root.clone();
                                let res = tokio::task::spawn_blocking(move || {
                                    if let Some(name) = val.get("name").and_then(|v| v.as_str()) {
                                        if let Ok(Some((spool, eml, jsonp))) =
                                            find_message_sync(&mr_clone, &ensure_ext(name))
                                        {
                                            return requeue_single_sync(
                                                &spool, &eml, &jsonp, &mr_clone,
                                            );
                                        }
                                        Err(anyhow::anyhow!("not found"))
                                    } else if let Some(pattern) =
                                        val.get("pattern").and_then(|v| v.as_str())
                                    {
                                        let matches =
                                            find_messages_matching_sync(&mr_clone, pattern)?;
                                        for (spool, eml, jsonp, _fname) in matches {
                                            requeue_single_sync(&spool, &eml, &jsonp, &mr_clone)?;
                                        }
                                        Ok(())
                                    } else {
                                        Err(anyhow::anyhow!("missing name or pattern"))
                                    }
                                })
                                .await;
                                match res {
                                    Ok(Ok(_)) => {
                                        content_type = "application/json".to_string();
                                        body = json!({"result":"ok"}).to_string();
                                    }
                                    Ok(Err(e)) => {
                                        status = 500;
                                        body = format!("error: {}", e);
                                    }
                                    Err(e) => {
                                        status = 500;
                                        body = format!("task join error: {}", e);
                                    }
                                }
                            }
                            Err(_) => {
                                status = 400;
                                body = "invalid JSON".to_string();
                            }
                        }
                    }
                }
            }
            "/api/queue/promote" => {
                if method != "POST" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else {
                    if !is_authorized(&headers) {
                        status = 401;
                        body = "Unauthorized".to_string();
                        extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                    } else {
                        let b = String::from_utf8_lossy(&body_bytes).to_string();
                        match serde_json::from_str::<serde_json::Value>(&b) {
                            Ok(val) => {
                                let priority =
                                    val.get("priority").and_then(|v| v.as_i64()).unwrap_or(0)
                                        as i32;
                                let mr_clone = mail_root.clone();
                                let res = tokio::task::spawn_blocking(move || {
                                    if let Some(name) = val.get("name").and_then(|v| v.as_str()) {
                                        if let Ok(Some((spool, eml, jsonp))) =
                                            find_message_sync(&mr_clone, &ensure_ext(name))
                                        {
                                            return promote_single_sync(
                                                &spool, &eml, &jsonp, &mr_clone, priority,
                                            );
                                        }
                                        Err(anyhow::anyhow!("not found"))
                                    } else if let Some(pattern) =
                                        val.get("pattern").and_then(|v| v.as_str())
                                    {
                                        let matches =
                                            find_messages_matching_sync(&mr_clone, pattern)?;
                                        for (spool, eml, jsonp, _fname) in matches {
                                            promote_single_sync(
                                                &spool, &eml, &jsonp, &mr_clone, priority,
                                            )?;
                                        }
                                        Ok(())
                                    } else {
                                        Err(anyhow::anyhow!("missing name or pattern"))
                                    }
                                })
                                .await;
                                match res {
                                    Ok(Ok(_)) => {
                                        content_type = "application/json".to_string();
                                        body = json!({"result":"ok"}).to_string();
                                    }
                                    Ok(Err(e)) => {
                                        status = 500;
                                        body = format!("error: {}", e);
                                    }
                                    Err(e) => {
                                        status = 500;
                                        body = format!("task join error: {}", e);
                                    }
                                }
                            }
                            Err(_) => {
                                status = 400;
                                body = "invalid JSON".to_string();
                            }
                        }
                    }
                }
            }
            "/api/queue/delete" => {
                if method != "POST" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else {
                    if !is_authorized(&headers) {
                        status = 401;
                        body = "Unauthorized".to_string();
                        extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                    } else {
                        let b = String::from_utf8_lossy(&body_bytes).to_string();
                        match serde_json::from_str::<serde_json::Value>(&b) {
                            Ok(val) => {
                                let mr_clone = mail_root.clone();
                                let res = tokio::task::spawn_blocking(move || {
                                    if let Some(name) = val.get("name").and_then(|v| v.as_str()) {
                                        if let Ok(Some((spool, eml, jsonp))) =
                                            find_message_sync(&mr_clone, &ensure_ext(name))
                                        {
                                            return delete_single_sync(
                                                &spool, &eml, &jsonp, &mr_clone,
                                            );
                                        }
                                        Err(anyhow::anyhow!("not found"))
                                    } else if let Some(pattern) =
                                        val.get("pattern").and_then(|v| v.as_str())
                                    {
                                        let matches =
                                            find_messages_matching_sync(&mr_clone, pattern)?;
                                        for (spool, eml, jsonp, _fname) in matches {
                                            delete_single_sync(&spool, &eml, &jsonp, &mr_clone)?;
                                        }
                                        Ok(())
                                    } else {
                                        Err(anyhow::anyhow!("missing name or pattern"))
                                    }
                                })
                                .await;
                                match res {
                                    Ok(Ok(_)) => {
                                        content_type = "application/json".to_string();
                                        body = json!({"result":"ok"}).to_string();
                                    }
                                    Ok(Err(e)) => {
                                        status = 500;
                                        body = format!("error: {}", e);
                                    }
                                    Err(e) => {
                                        status = 500;
                                        body = format!("task join error: {}", e);
                                    }
                                }
                            }
                            Err(_) => {
                                status = 400;
                                body = "invalid JSON".to_string();
                            }
                        }
                    }
                }
            }
            "/api/queue" => {
                if !is_authorized(&headers) {
                    status = 401;
                    body = "Unauthorized".to_string();
                    extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                } else {
                    let mr_clone = mail_root.clone();
                    match tokio::task::spawn_blocking(move || {
                        let (queue, _i, _s, _f) = spool_dirs(&mr_clone);
                        match read_queue_entries(&queue) {
                            Ok(list) => serde_json::to_string(&serde_json::json!({"queued": list}))
                                .map_err(|e| anyhow::anyhow!(e)),
                            Err(e) => Err(anyhow::anyhow!(format!("read error: {}", e))),
                        }
                    })
                    .await
                    {
                        Ok(Ok(s)) => {
                            content_type = "application/json".to_string();
                            body = s;
                        }
                        Ok(Err(e)) => {
                            status = 500;
                            body = format!("error: {}", e);
                        }
                        Err(e) => {
                            status = 500;
                            body = format!("task join error: {}", e);
                        }
                    }
                }
            }
            "/api/queue/action" => {
                if method != "POST" {
                    status = 405;
                    body = "Method Not Allowed".to_string();
                } else {
                    if !is_authorized(&headers) {
                        status = 401;
                        body = "Unauthorized".to_string();
                        extra_headers = "WWW-Authenticate: Basic realm=\"rMail\"\r\n".to_string();
                    } else {
                        let b = String::from_utf8_lossy(&body_bytes).to_string();
                        match serde_json::from_str::<serde_json::Value>(&b) {
                            Ok(val) => {
                                let action =
                                    val.get("action").and_then(|v| v.as_str()).unwrap_or("");
                                let mr_clone = mail_root.clone();
                                match action {
                                    "requeue" => {
                                        let res = tokio::task::spawn_blocking(move || {
                                            if let Some(name) =
                                                val.get("name").and_then(|v| v.as_str())
                                            {
                                                if let Ok(Some((spool, eml, jsonp))) =
                                                    find_message_sync(&mr_clone, &ensure_ext(name))
                                                {
                                                    return requeue_single_sync(
                                                        &spool, &eml, &jsonp, &mr_clone,
                                                    );
                                                }
                                                Err(anyhow::anyhow!("not found"))
                                            } else if let Some(pattern) =
                                                val.get("pattern").and_then(|v| v.as_str())
                                            {
                                                let matches = find_messages_matching_sync(
                                                    &mr_clone, pattern,
                                                )?;
                                                for (spool, eml, jsonp, _fname) in matches {
                                                    requeue_single_sync(
                                                        &spool, &eml, &jsonp, &mr_clone,
                                                    )?;
                                                }
                                                Ok(())
                                            } else {
                                                Err(anyhow::anyhow!("missing name or pattern"))
                                            }
                                        })
                                        .await;
                                        match res {
                                            Ok(Ok(_)) => {
                                                content_type = "application/json".to_string();
                                                body = json!({"result":"ok"}).to_string();
                                            }
                                            Ok(Err(e)) => {
                                                status = 500;
                                                body = format!("error: {}", e);
                                            }
                                            Err(e) => {
                                                status = 500;
                                                body = format!("task join error: {}", e);
                                            }
                                        }
                                    }
                                    "promote" => {
                                        let priority = val
                                            .get("priority")
                                            .and_then(|v| v.as_i64())
                                            .unwrap_or(0)
                                            as i32;
                                        let res = tokio::task::spawn_blocking(move || {
                                            if let Some(name) =
                                                val.get("name").and_then(|v| v.as_str())
                                            {
                                                if let Ok(Some((spool, eml, jsonp))) =
                                                    find_message_sync(&mr_clone, &ensure_ext(name))
                                                {
                                                    return promote_single_sync(
                                                        &spool, &eml, &jsonp, &mr_clone, priority,
                                                    );
                                                }
                                                Err(anyhow::anyhow!("not found"))
                                            } else if let Some(pattern) =
                                                val.get("pattern").and_then(|v| v.as_str())
                                            {
                                                let matches = find_messages_matching_sync(
                                                    &mr_clone, pattern,
                                                )?;
                                                for (spool, eml, jsonp, _fname) in matches {
                                                    promote_single_sync(
                                                        &spool, &eml, &jsonp, &mr_clone, priority,
                                                    )?;
                                                }
                                                Ok(())
                                            } else {
                                                Err(anyhow::anyhow!("missing name or pattern"))
                                            }
                                        })
                                        .await;
                                        match res {
                                            Ok(Ok(_)) => {
                                                content_type = "application/json".to_string();
                                                body = json!({"result":"ok"}).to_string();
                                            }
                                            Ok(Err(e)) => {
                                                status = 500;
                                                body = format!("error: {}", e);
                                            }
                                            Err(e) => {
                                                status = 500;
                                                body = format!("task join error: {}", e);
                                            }
                                        }
                                    }
                                    "delete" => {
                                        let res = tokio::task::spawn_blocking(move || {
                                            if let Some(name) =
                                                val.get("name").and_then(|v| v.as_str())
                                            {
                                                if let Ok(Some((spool, eml, jsonp))) =
                                                    find_message_sync(&mr_clone, &ensure_ext(name))
                                                {
                                                    return delete_single_sync(
                                                        &spool, &eml, &jsonp, &mr_clone,
                                                    );
                                                }
                                                Err(anyhow::anyhow!("not found"))
                                            } else if let Some(pattern) =
                                                val.get("pattern").and_then(|v| v.as_str())
                                            {
                                                let matches = find_messages_matching_sync(
                                                    &mr_clone, pattern,
                                                )?;
                                                for (spool, eml, jsonp, _fname) in matches {
                                                    delete_single_sync(
                                                        &spool, &eml, &jsonp, &mr_clone,
                                                    )?;
                                                }
                                                Ok(())
                                            } else {
                                                Err(anyhow::anyhow!("missing name or pattern"))
                                            }
                                        })
                                        .await;
                                        match res {
                                            Ok(Ok(_)) => {
                                                content_type = "application/json".to_string();
                                                body = json!({"result":"ok"}).to_string();
                                            }
                                            Ok(Err(e)) => {
                                                status = 500;
                                                body = format!("error: {}", e);
                                            }
                                            Err(e) => {
                                                status = 500;
                                                body = format!("task join error: {}", e);
                                            }
                                        }
                                    }
                                    _ => {
                                        status = 400;
                                        body = "unknown action".to_string();
                                    }
                                }
                            }
                            Err(_) => {
                                status = 400;
                                body = "invalid JSON".to_string();
                            }
                        }
                    }
                }
            }
            _ => {
                status = 404;
                body = "Not Found".to_string();
            }
        }
    }

    // write response (HTTP/1.1)
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n{}\r\n{}",
        status,
        if status == 200 { "OK" } else { "ERR" },
        body.as_bytes().len(),
        content_type,
        extra_headers,
        body
    );
    // take ownership of underlying stream and write once
    let mut stream = reader.into_inner();
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
    println!("Served {} {} -> {}", peer, path_q, status);
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg_path =
        std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let cfg = Config::from_file(&cfg_path).unwrap_or_else(|_| {
        // fallback default settings
        Config {
            global: rmail_common::config::Global {
                mail_root: "mail".into(),
                listen_addrs: None,
                smtps_listen_addrs: None,
                smtps_port: None,
                submission_port: None,
                imaps_listen_addrs: None,
                imaps_port: None,
                imap_listen_addrs: None,
                imap_port: None,
                web_listen_addrs: None,
                web_port: None,
                webmail_listen_addrs: None,
                webmail_port: None,
                webmail_session_secret: None,
                tls_cert: None,
                tls_key: None,
                log_level: None,
                web_admin_user: None,
                web_admin_password_hash: None,
                acme_challenge_dir: None,
                db_path: None,
                enforce_dmarc: None,
            },
        }
    });
    let mail_root = PathBuf::from(cfg.global.mail_root);
    rmail_common::runtime::redirect_stdio_to_log(&mail_root, "web").context("redirecting logs")?;
    let admin_user = cfg.global.web_admin_user.clone();
    let admin_hash = cfg.global.web_admin_password_hash.clone();
    let db_path = cfg.global.db_path.clone();
    let acme_dir = cfg.global.acme_challenge_dir.clone();
    let port = cfg.global.web_port.unwrap_or(8080);
    let bind_addrs = cfg
        .global
        .web_listen_addrs
        .clone()
        .unwrap_or_else(|| vec![format!("127.0.0.1:{}", port)]);
    for addr in bind_addrs {
        let listener = TcpListener::bind(&addr).await?;
        println!("rMail web UI listening on {}", addr);
        let mr = mail_root.clone();
        let admin_user = admin_user.clone();
        let admin_hash = admin_hash.clone();
        let db_path = db_path.clone();
        let acme_dir = acme_dir.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("web listener {} accept error: {}", addr, e);
                        break;
                    }
                };
                let mr = mr.clone();
                let admin_user = admin_user.clone();
                let admin_hash = admin_hash.clone();
                let db_path = db_path.clone();
                let acme_dir = acme_dir.clone();
                tokio::spawn(async move {
                    handle_connection(stream, mr, admin_user, admin_hash, db_path, acme_dir).await;
                });
            }
        });
    }
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}
