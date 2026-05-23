// rmail_web: minimal tokio-based HTTP UI for stats and logs (no hyper/axum)

use serde::Serialize;
use std::net::SocketAddr;
use rmail_common::config::Config;
use std::path::PathBuf;
use anyhow::Result;
use std::collections::HashMap;
use tokio::net::TcpListener;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

#[derive(Serialize)]
struct Stats {
    mailboxes: usize,
    total_messages: usize,
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
        return Ok(Stats { mailboxes: 0, total_messages: 0 });
    }
    for domain_entry in std::fs::read_dir(mail_root)? {
        let domain_entry = domain_entry?;
        if !domain_entry.file_type()?.is_dir() { continue; }
        let domain_path = domain_entry.path();
        for local_entry in std::fs::read_dir(domain_path)? {
            let local_entry = local_entry?;
            if !local_entry.file_type()?.is_dir() { continue; }
            let maildir_path = local_entry.path().join("Maildir");
            if !maildir_path.exists() { continue; }
            mailbox_count += 1;
            for dname in ["new", "cur"] {
                let dirpath = maildir_path.join(dname);
                if dirpath.exists() && dirpath.is_dir() {
                    for entry in std::fs::read_dir(&dirpath)? {
                        let e = entry?;
                        if e.file_type()?.is_file() { total_messages += 1; }
                    }
                }
            }
        }
    }
    Ok(Stats { mailboxes: mailbox_count, total_messages })
}

async fn handle_connection(mut stream: tokio::net::TcpStream, mail_root: PathBuf) {
    let peer = match stream.peer_addr() { Ok(p) => p.to_string(), Err(_) => "unknown".to_string() };
    let mut reader = BufReader::new(stream);
    let mut first_line = String::new();
    // read request line
    match reader.read_line(&mut first_line).await {
        Ok(0) => return,
        Ok(_) => {}
        Err(_) => return,
    }
    let req_line = first_line.trim_end_matches('\n').trim_end_matches('\r').to_string();
    // read and discard headers until empty line
    loop {
        let mut h = String::new();
        match reader.read_line(&mut h).await {
            Ok(0) => break,
            Ok(_) => {
                if h == "\r\n" || h == "\n" { break; }
            }
            Err(_) => break,
        }
    }

    // parse request line: METHOD PATH HTTP/X
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path_q = parts.next().unwrap_or("/");

    // prepare response
    let mut status = 200;
    let mut content_type = "text/plain".to_string();
    let mut body = String::new();

    if method != "GET" {
        status = 405;
        body = "Method Not Allowed".to_string();
    } else {
        let (path, query) = if let Some(pos) = path_q.find('?') { (&path_q[..pos], &path_q[pos+1..]) } else { (path_q, "") };
        match path {
            "/" => {
                content_type = "text/html".to_string();
                body = "<html><body><h1>rMail Web UI</h1><ul><li><a href='/health'>health</a></li><li><a href='/stats'>stats</a></li><li><a href='/logs?component=smtpd'>smtpd logs</a></li></ul></body></html>".to_string();
            }
            "/health" => {
                content_type = "text/plain".to_string();
                body = "ok".to_string();
            }
            "/stats" => {
                // run blocking scan
                match tokio::task::spawn_blocking(move || scan_maildirs_sync(&mail_root)).await {
                    Ok(Ok(stats)) => {
                        content_type = "application/json".to_string();
                        body = match serde_json::to_string(&stats) { Ok(s) => s, Err(e) => { status = 500; format!("{{\"error\":\"{}\"}}", e) } };
                    }
                    Ok(Err(e)) => { status = 500; body = format!("scan error: {}", e); }
                    Err(e) => { status = 500; body = format!("task join error: {}", e); }
                }
            }
            "/logs" => {
                // parse query params for component and lines (simple parser, no percent-decoding)
                let params: HashMap<_, _> = query.split('&').filter_map(|kv| {
                    if kv.is_empty() { return None; }
                    let mut s = kv.splitn(2, '=');
                    let k = s.next().unwrap_or("").to_string();
                    let v = s.next().unwrap_or("").to_string();
                    if k.is_empty() { None } else { Some((k, v)) }
                }).collect();
                let component = params.get("component").map(|s| s.as_str()).unwrap_or("smtpd");
                let mut lines: usize = params.get("lines").and_then(|s| s.parse().ok()).unwrap_or(200);
                lines = std::cmp::min(lines, 2000);
                let path = match component {
                    "smtpd" => "/tmp/rmail_smtpd.log",
                    "imapd" => "/tmp/rmail_imapd.log",
                    _ => { status = 400; body = "invalid component".to_string(); "" }
                };
                if !path.is_empty() {
                    match tokio::fs::read_to_string(path).await {
                        Ok(s) => { content_type = "text/plain".to_string(); body = tail_lines(&s, lines); }
                        Err(e) => { status = 500; body = format!("read error: {}", e); }
                    }
                }
            }
            _ => { status = 404; body = "Not Found".to_string(); }
        }
    }

    // write response (HTTP/1.1)
    let response = format!("HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n{}", status, if status==200 { "OK" } else { "ERR" }, body.as_bytes().len(), content_type, body);
    // take ownership of underlying stream and write once
    let mut stream = reader.into_inner();
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
    println!("Served {} {} -> {}", peer, path_q, status);
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg_path = std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let cfg = Config::from_file(&cfg_path).unwrap_or_else(|_| {
        // fallback default settings
        Config { global: rmail_common::config::Global { mail_root: "mail".into(), listen_addrs: None, smtps_port: None, submission_port: None, imaps_port: None, imap_port: None, web_port: None, tls_cert: None, tls_key: None, log_level: None }, mailboxes: None, catchalls: None }
    });
    let port = cfg.global.web_port.unwrap_or(8080);
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    println!("rMail web UI listening on {}", addr);
    let mail_root = PathBuf::from(cfg.global.mail_root);
    loop {
        let (stream, _) = listener.accept().await?;
        let mr = mail_root.clone();
        tokio::spawn(async move {
            handle_connection(stream, mr).await;
        });
    }
}
