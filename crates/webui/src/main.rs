// rmail_web: lightweight web UI for stats and logs

use axum::{routing::get, Router, extract::Query, response::IntoResponse, Json};
use axum::http::StatusCode;
use serde::Serialize;
use std::net::SocketAddr;
use rmail_common::config::Config;
use std::path::PathBuf;
use anyhow::Result;
use std::collections::HashMap;

#[derive(Serialize)]
struct Stats {
    mailboxes: usize,
    total_messages: usize,
}

async fn health() -> impl IntoResponse {
    (axum::http::StatusCode::OK, "ok")
}

async fn stats_handler(Query(_params): Query<HashMap<String, String>>) -> Result<Json<Stats>, (StatusCode, String)> {
    let cfg_path = std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let cfg = match Config::from_file(&cfg_path) {
        Ok(c) => c,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("config error: {}", e))),
    };
    let mail_root = PathBuf::from(cfg.global.mail_root);
    let res = tokio::task::spawn_blocking(move || scan_maildirs_sync(&mail_root)).await;
    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((StatusCode::INTERNAL_SERVER_ERROR, format!("scan error: {}", e))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, format!("task join error: {}", e))),
    }
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

async fn logs_handler(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let component = params.get("component").map(|s| s.as_str()).unwrap_or("smtpd");
    let lines: usize = params.get("lines").and_then(|s| s.parse().ok()).unwrap_or(200);
    let lines = std::cmp::min(lines, 2000);
    let path = match component {
        "smtpd" => "/tmp/rmail_smtpd.log",
        "imapd" => "/tmp/rmail_imapd.log",
        _ => return (axum::http::StatusCode::BAD_REQUEST, "invalid component".to_string()),
    };
    match tokio::fs::read_to_string(path).await {
        Ok(s) => {
            let tail = tail_lines(&s, lines);
            (axum::http::StatusCode::OK, tail)
        }
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("read error: {}", e)),
    }
}

fn tail_lines(s: &str, n: usize) -> String {
    let mut out: Vec<&str> = s.lines().rev().take(n).collect();
    out.reverse();
    out.join("\n")
}

async fn root_html() -> impl IntoResponse {
    let body = "<html><body><h1>rMail Web UI</h1><ul><li><a href=\"/health\">health</a></li><li><a href=\"/stats\">stats</a></li><li><a href=\"/logs?component=smtpd\">smtpd logs</a></li></ul></body></html>";
    (axum::http::StatusCode::OK, axum::response::Html(body.to_string()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg_path = std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let cfg = Config::from_file(&cfg_path).unwrap_or_else(|_| {
        // fallback default settings
        Config { global: rmail_common::config::Global { mail_root: "mail".into(), listen_addrs: None, smtps_port: None, submission_port: None, imaps_port: None, imap_port: None, web_port: None, tls_cert: None, tls_key: None, log_level: None }, mailboxes: None, catchalls: None }
    });
    let port = cfg.global.web_port.unwrap_or(8080);
    let addr = SocketAddr::from(([0,0,0,0], port as u16));

    let app = Router::new()
        .route("/", get(root_html))
        .route("/health", get(health))
        .route("/stats", get(stats_handler))
        .route("/logs", get(logs_handler));

    println!("rMail web UI listening on {}", addr);
    hyper::Server::bind(&addr).serve(app.into_make_service()).await?;
    Ok(())
}
