use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use percent_encoding::percent_decode_str;
use rmail_common::{auth, config::Config, db, imap_state};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::HashMap,
    env, fs,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

type HmacSha256 = Hmac<Sha256>;
const SESSION_COOKIE: &str = "rmail_webmail";
const SESSION_TTL_SECS: u64 = 12 * 60 * 60;

#[derive(Clone)]
struct AppState {
    mail_root: PathBuf,
    db_path: PathBuf,
    session_secret: Vec<u8>,
}

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct Response {
    status: u16,
    content_type: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Session {
    address: String,
    domain: String,
    localpart: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    address: String,
    password: String,
}

#[derive(Deserialize)]
struct PatchMessage {
    seen: Option<bool>,
}

#[derive(Deserialize)]
struct BulkRequest {
    action: String,
    uids: Vec<u64>,
}

#[derive(Serialize)]
struct SessionResponse {
    address: String,
}

#[derive(Serialize, Deserialize)]
struct FolderResponse {
    name: String,
    special_use: Option<String>,
    messages: usize,
    unread: usize,
}

#[derive(Serialize, Deserialize)]
struct MessageListItem {
    uid: u64,
    flags: Vec<String>,
    size: u64,
    internal_date: i64,
    from: String,
    to: String,
    subject: String,
    snippet: String,
}

#[derive(Serialize)]
struct MessageDetail {
    uid: u64,
    flags: Vec<String>,
    size: u64,
    internal_date: i64,
    from: String,
    to: String,
    subject: String,
    date: String,
    text_body: String,
    html_body: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg_path = env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let cfg = Config::from_file(&cfg_path).unwrap_or_else(|_| Config {
        global: rmail_common::config::Global {
            mail_root: "mail".to_string(),
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
            db_path: None,
            web_admin_user: None,
            web_admin_password_hash: None,
            acme_challenge_dir: None,
            enforce_dmarc: None,
        },
    });
    let mail_root = PathBuf::from(&cfg.global.mail_root);
    rmail_common::runtime::redirect_stdio_to_log(&mail_root, "webmail")
        .context("redirecting logs")?;
    let db_path = cfg
        .global
        .db_path
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(|| mail_root.join("rmail.sqlite"));
    let session_secret = cfg
        .global
        .webmail_session_secret
        .clone()
        .unwrap_or_else(|| {
            eprintln!("warning: webmail_session_secret is not configured; using ephemeral secret");
            format!("ephemeral-{}", randish())
        })
        .into_bytes();
    let state = Arc::new(AppState {
        mail_root,
        db_path,
        session_secret,
    });
    let port = cfg.global.webmail_port.unwrap_or(8081);
    let bind_addrs = cfg
        .global
        .webmail_listen_addrs
        .clone()
        .unwrap_or_else(|| vec![format!("127.0.0.1:{}", port)]);
    for addr in bind_addrs {
        let listener = TcpListener::bind(&addr).await?;
        println!("rMail webmail listening on {}", addr);
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_connection(stream, state).await {
                                eprintln!("webmail connection error: {err:#}");
                            }
                        });
                    }
                    Err(err) => {
                        eprintln!("webmail listener {addr} accept error: {err}");
                        break;
                    }
                }
            }
        });
    }
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

async fn handle_connection(mut stream: TcpStream, state: Arc<AppState>) -> Result<()> {
    let request = read_request(&mut stream).await?;
    let response = match request {
        Some(request) => route(request, &state).await,
        None => Response::empty(400),
    };
    write_response(&mut stream, response).await
}

async fn read_request(stream: &mut TcpStream) -> Result<Option<Request>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_bytes(&buf, b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        if buf.len() > 1024 * 1024 {
            return Ok(None);
        }
    }
    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = header_text.lines();
    let Some(start) = lines.next() else {
        return Ok(None);
    };
    let mut parts = start.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let content_length = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    while buf.len() < header_end + content_length {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = buf[header_end..buf.len().min(header_end + content_length)].to_vec();
    let (raw_path, query) = split_target(target);
    Ok(Some(Request {
        method,
        path: raw_path,
        query,
        headers,
        body,
    }))
}

async fn write_response(stream: &mut TcpStream, response: Response) -> Result<()> {
    let reason = match response.status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error",
    };
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: {}\r\nX-Content-Type-Options: nosniff\r\n",
        response.status,
        reason,
        response.body.len(),
        response.content_type
    );
    for (k, v) in response.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&response.body).await?;
    Ok(())
}

async fn route(request: Request, state: &AppState) -> Response {
    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/api/login") => login(request, state),
        ("POST", "/api/logout") => Response::empty(204).with_header(
            "Set-Cookie",
            format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"),
        ),
        ("GET", "/api/session") => match require_session(&request, state) {
            Ok(session) => json(
                200,
                &SessionResponse {
                    address: session.address,
                },
            ),
            Err(response) => response,
        },
        ("GET", "/api/folders") => match require_session(&request, state) {
            Ok(session) => folders(state, &session),
            Err(response) => response,
        },
        _ if request.path.starts_with("/api/folders/") => mailbox_api(request, state),
        _ if request.method == "GET" => spa(),
        _ => Response::empty(405),
    }
}

fn login(request: Request, state: &AppState) -> Response {
    let Ok(input) = serde_json::from_slice::<LoginRequest>(&request.body) else {
        return Response::text(400, "invalid json");
    };
    let address = input.address.trim().to_ascii_lowercase();
    let Some((localpart, domain)) = split_address(&address) else {
        return Response::text(401, "invalid login");
    };
    let mailbox = match db::get_mailbox(&state.db_path, &address) {
        Ok(Some(mailbox)) => mailbox,
        _ => return Response::text(401, "invalid login"),
    };
    let Some(hash) = mailbox.password_hash.as_deref() else {
        return Response::text(401, "invalid login");
    };
    match auth::verify_password(&input.password, hash) {
        Ok(true) => {
            let _ = imap_state::init_account(&state.mail_root, &domain, &localpart);
            let token = sign_session(&state.session_secret, &address);
            json(200, &SessionResponse { address }).with_header(
                "Set-Cookie",
                format!(
                    "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL_SECS}"
                ),
            )
        }
        _ => Response::text(401, "invalid login"),
    }
}

fn mailbox_api(request: Request, state: &AppState) -> Response {
    let session = match require_session(&request, state) {
        Ok(session) => session,
        Err(response) => return response,
    };
    let rest = request.path.trim_start_matches("/api/folders/");
    let parts = rest.split('/').collect::<Vec<_>>();
    if parts.len() < 2 || parts[1] != "messages" {
        return Response::empty(404);
    }
    let folder = decode_path(parts[0]);
    match (request.method.as_str(), parts.as_slice()) {
        ("GET", [_, "messages"]) => message_list(state, &session, &folder, &request.query),
        ("GET", [_, "messages", uid]) => uid
            .parse::<u64>()
            .ok()
            .map(|uid| message_detail(state, &session, &folder, uid))
            .unwrap_or_else(|| Response::empty(404)),
        ("PATCH", [_, "messages", uid]) => uid
            .parse::<u64>()
            .ok()
            .map(|uid| patch_message(state, &session, &folder, uid, &request.body))
            .unwrap_or_else(|| Response::empty(404)),
        ("POST", [_, "messages", "bulk"]) => bulk(state, &session, &folder, &request.body),
        _ => Response::empty(404),
    }
}

fn folders(state: &AppState, session: &Session) -> Response {
    match imap_state::list_folder_summaries(&state.mail_root, &session.domain, &session.localpart) {
        Ok(summaries) => json(
            200,
            &summaries
                .into_iter()
                .map(|s| FolderResponse {
                    name: s.folder.name,
                    special_use: s.folder.special_use,
                    messages: s.messages,
                    unread: s.unseen,
                })
                .collect::<Vec<_>>(),
        ),
        Err(err) => Response::text(500, &err.to_string()),
    }
}

fn message_list(
    state: &AppState,
    session: &Session,
    folder: &str,
    query: &HashMap<String, String>,
) -> Response {
    let limit = query
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    let offset = query
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let q = query
        .get("q")
        .map(|v| v.to_ascii_lowercase())
        .unwrap_or_default();
    let Ok((_folder, mut messages)) = imap_state::load_folder(
        &state.mail_root,
        &session.domain,
        &session.localpart,
        folder,
    ) else {
        return Response::empty(404);
    };
    messages.sort_by(|a, b| b.internaldate.cmp(&a.internaldate).then(b.uid.cmp(&a.uid)));
    let items = messages
        .into_iter()
        .filter_map(|message| {
            let parsed = parse_message(&fs::read(&message.path).ok()?);
            let haystack = format!(
                "{} {} {} {}",
                parsed.from, parsed.to, parsed.subject, parsed.text_body
            )
            .to_ascii_lowercase();
            if !q.is_empty() && !haystack.contains(&q) {
                return None;
            }
            Some(MessageListItem {
                uid: message.uid,
                flags: message.flags,
                size: message.size,
                internal_date: message.internaldate,
                from: parsed.from,
                to: parsed.to,
                subject: parsed.subject,
                snippet: snippet(&parsed.text_body),
            })
        })
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
    json(200, &items)
}

fn message_detail(state: &AppState, session: &Session, folder: &str, uid: u64) -> Response {
    let Ok((_folder, messages)) = imap_state::load_folder(
        &state.mail_root,
        &session.domain,
        &session.localpart,
        folder,
    ) else {
        return Response::empty(404);
    };
    let Some(message) = messages.into_iter().find(|m| m.uid == uid) else {
        return Response::empty(404);
    };
    let Ok(bytes) = fs::read(&message.path) else {
        return Response::empty(404);
    };
    let parsed = parse_message(&bytes);
    json(
        200,
        &MessageDetail {
            uid: message.uid,
            flags: message.flags,
            size: message.size,
            internal_date: message.internaldate,
            from: parsed.from,
            to: parsed.to,
            subject: parsed.subject,
            date: parsed.date,
            text_body: parsed.text_body,
            html_body: parsed.html_body.map(|html| sanitize_html(&html)),
        },
    )
}

fn patch_message(
    state: &AppState,
    session: &Session,
    folder: &str,
    uid: u64,
    body: &[u8],
) -> Response {
    let Ok(input) = serde_json::from_slice::<PatchMessage>(body) else {
        return Response::text(400, "invalid json");
    };
    let Ok((_folder, messages)) = imap_state::load_folder(
        &state.mail_root,
        &session.domain,
        &session.localpart,
        folder,
    ) else {
        return Response::empty(404);
    };
    let Some(message) = messages.into_iter().find(|m| m.uid == uid) else {
        return Response::empty(404);
    };
    let mut flags = message.flags;
    if let Some(seen) = input.seen {
        set_flag(&mut flags, "\\Seen", seen);
    }
    match imap_state::set_uid_flags(
        &state.mail_root,
        &session.domain,
        &session.localpart,
        folder,
        uid,
        flags,
    ) {
        Ok(()) => Response::empty(204),
        Err(err) => Response::text(500, &err.to_string()),
    }
}

fn bulk(state: &AppState, session: &Session, folder: &str, body: &[u8]) -> Response {
    let Ok(input) = serde_json::from_slice::<BulkRequest>(body) else {
        return Response::text(400, "invalid json");
    };
    for uid in input.uids {
        let result = match input.action.as_str() {
            "mark_read" => update_seen(state, session, folder, uid, true),
            "mark_unread" => update_seen(state, session, folder, uid, false),
            "archive" => imap_state::move_message_by_uid(
                &state.mail_root,
                &session.domain,
                &session.localpart,
                folder,
                uid,
                "Archive",
            )
            .map(|_| ()),
            "delete" => imap_state::delete_or_trash_message_by_uid(
                &state.mail_root,
                &session.domain,
                &session.localpart,
                folder,
                uid,
            ),
            _ => return Response::text(400, "unknown action"),
        };
        if let Err(err) = result {
            return Response::text(500, &err.to_string());
        }
    }
    Response::empty(204)
}

fn update_seen(
    state: &AppState,
    session: &Session,
    folder: &str,
    uid: u64,
    seen: bool,
) -> Result<()> {
    let (_, messages) = imap_state::load_folder(
        &state.mail_root,
        &session.domain,
        &session.localpart,
        folder,
    )?;
    if let Some(message) = messages.into_iter().find(|m| m.uid == uid) {
        let mut flags = message.flags;
        set_flag(&mut flags, "\\Seen", seen);
        imap_state::set_uid_flags(
            &state.mail_root,
            &session.domain,
            &session.localpart,
            folder,
            uid,
            flags,
        )?;
    }
    Ok(())
}

fn require_session(request: &Request, state: &AppState) -> std::result::Result<Session, Response> {
    let Some(cookie) = request.headers.get("cookie") else {
        return Err(Response::empty(401));
    };
    let Some(token) = cookie.split(';').find_map(|part| {
        let (k, v) = part.trim().split_once('=')?;
        (k == SESSION_COOKIE).then_some(v)
    }) else {
        return Err(Response::empty(401));
    };
    let Some(address) = verify_session(&state.session_secret, token) else {
        return Err(Response::empty(401));
    };
    let Some((localpart, domain)) = split_address(&address) else {
        return Err(Response::empty(401));
    };
    match db::get_mailbox(&state.db_path, &address) {
        Ok(Some(_)) => Ok(Session {
            address,
            domain,
            localpart,
        }),
        _ => Err(Response::empty(401)),
    }
}

fn sign_session(secret: &[u8], address: &str) -> String {
    let exp = now_secs() + SESSION_TTL_SECS;
    let payload = format!("{address}|{exp}");
    let sig = hmac(secret, payload.as_bytes());
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(payload.as_bytes()),
        URL_SAFE_NO_PAD.encode(sig)
    )
}

fn verify_session(secret: &[u8], token: &str) -> Option<String> {
    let (payload64, sig64) = token.split_once('.')?;
    let payload = URL_SAFE_NO_PAD.decode(payload64).ok()?;
    let sig = URL_SAFE_NO_PAD.decode(sig64).ok()?;
    if hmac(secret, &payload).as_slice() != sig.as_slice() {
        return None;
    }
    let payload = String::from_utf8(payload).ok()?;
    let (address, exp) = payload.rsplit_once('|')?;
    (exp.parse::<u64>().ok()? >= now_secs()).then(|| address.to_string())
}

fn hmac(secret: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(payload);
    mac.finalize().into_bytes().to_vec()
}

#[derive(Default)]
struct ParsedMessage {
    from: String,
    to: String,
    subject: String,
    date: String,
    text_body: String,
    html_body: Option<String>,
}

fn parse_message(bytes: &[u8]) -> ParsedMessage {
    let text = String::from_utf8_lossy(bytes).replace("\r\n", "\n");
    let (headers, body) = text.split_once("\n\n").unwrap_or(("", &text));
    let mut parsed = ParsedMessage::default();
    for line in headers.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.to_ascii_lowercase().as_str() {
            "from" => parsed.from = value.trim().to_string(),
            "to" => parsed.to = value.trim().to_string(),
            "subject" => parsed.subject = value.trim().to_string(),
            "date" => parsed.date = value.trim().to_string(),
            "content-type" if value.to_ascii_lowercase().contains("text/html") => {
                parsed.html_body = Some(body.trim().to_string());
            }
            _ => {}
        }
    }
    parsed.text_body = strip_html(body.trim());
    parsed
}

fn strip_html(input: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    html_unescape(&out)
}

fn sanitize_html(input: &str) -> String {
    html_escape(&strip_html(input)).replace('\n', "<br>")
}

fn snippet(input: &str) -> String {
    let compact = input.split_whitespace().collect::<Vec<_>>().join(" ");
    compact.chars().take(160).collect()
}

fn set_flag(flags: &mut Vec<String>, flag: &str, enabled: bool) {
    if enabled && !flags.iter().any(|f| f.eq_ignore_ascii_case(flag)) {
        flags.push(flag.to_string());
    } else if !enabled {
        flags.retain(|f| !f.eq_ignore_ascii_case(flag));
    }
}

fn split_address(address: &str) -> Option<(String, String)> {
    let (local, domain) = address.split_once('@')?;
    if local.is_empty() || domain.is_empty() || local.contains('/') || domain.contains('/') {
        return None;
    }
    Some((local.to_string(), domain.to_string()))
}

fn split_target(target: &str) -> (String, HashMap<String, String>) {
    let (path, raw_query) = target.split_once('?').unwrap_or((target, ""));
    let query = raw_query
        .split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((decode_path(k), decode_path(v)))
        })
        .collect();
    (decode_path(path), query)
}

fn decode_path(value: &str) -> String {
    percent_decode_str(value).decode_utf8_lossy().to_string()
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn html_unescape(input: &str) -> String {
    input
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&amp;", "&")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn randish() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ u64::from(std::process::id())
}

fn spa() -> Response {
    Response {
        status: 200,
        content_type: "text/html; charset=utf-8",
        headers: Vec::new(),
        body: EMBEDDED_SPA.as_bytes().to_vec(),
    }
}

const EMBEDDED_SPA: &str = r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>rMail Webmail</title>
    <style>
      body{margin:0;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f5f7f8;color:#222831}
      button,input{font:inherit}button{cursor:pointer}.login{min-height:100vh;display:grid;place-items:center;background:#edf3f2}
      form{width:min(360px,calc(100vw - 32px));display:grid;gap:12px;padding:24px;background:#fff;border:1px solid #d8dee2;border-radius:8px}
      input{border:1px solid #cfd7dc;border-radius:6px;padding:10px 12px}form button,.bar button{border:0;border-radius:6px;padding:10px 14px;background:#276ef1;color:#fff}
      .app{height:100vh;display:grid;grid-template-columns:220px minmax(340px,.95fr) minmax(380px,1.15fr);overflow:hidden}.folders{background:#24313a;color:#eef5f6;padding:14px 10px;overflow:auto}
      .folders button{width:100%;display:flex;justify-content:space-between;border:0;background:transparent;color:inherit;border-radius:6px;padding:9px 10px}.folders .active,.folders button:hover{background:#38505c}
      .list{display:grid;grid-template-rows:58px 1fr;border-right:1px solid #d8dee2;min-width:0;background:#fff}.bar{display:flex;gap:8px;align-items:center;padding:8px 12px;border-bottom:1px solid #d8dee2}.bar input{flex:1;min-width:0;background:#f3f6f7}
      .msg{display:grid;grid-template-columns:140px 1fr;gap:4px 12px;width:100%;border:0;border-bottom:1px solid #e3e8eb;background:#fff;text-align:left;padding:12px}.msg.unread{font-weight:700}.msg small{grid-column:2;color:#667780;font-weight:400;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
      .reader{background:#fff;padding:24px;overflow:auto}.reader pre{white-space:pre-wrap;font-family:inherit;line-height:1.5}.muted{color:#667780}
      @media(max-width:820px){.app{display:block}.folders,.list,.reader{height:auto;min-height:33vh}.msg{grid-template-columns:1fr}.msg small{grid-column:1}}
    </style>
  </head>
  <body><div id="root" class="login"></div><script>
    const root=document.getElementById('root');let folder='INBOX',q='';
    async function api(url,options={}){const r=await fetch(url,{credentials:'same-origin',headers:{'Content-Type':'application/json'},...options});if(!r.ok)throw new Error(await r.text()||r.statusText);return r.status===204?null:r.json()}
    function esc(s){return (s||'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
    async function load(){try{const s=await api('/api/session'),folders=await api('/api/folders'),msgs=await api('/api/folders/'+encodeURIComponent(folder)+'/messages?limit=100&q='+encodeURIComponent(q));root.className='app';root.innerHTML='<aside class="folders"><p class="muted">'+esc(s.address)+'</p>'+folders.map(f=>'<button class="'+(f.name===folder?'active':'')+'" data-folder="'+esc(f.name)+'"><span>'+esc(f.name)+'</span><small>'+(f.unread||f.messages)+'</small></button>').join('')+'</aside><main class="list"><div class="bar"><input id="q" placeholder="Search mail" value="'+esc(q)+'"><button id="refresh">Refresh</button><button id="archive">Archive</button><button id="delete">Delete</button></div><div>'+msgs.map(m=>'<button class="msg '+(m.flags.some(f=>f.toLowerCase()==='\\\\seen')?'':'unread')+'" data-uid="'+m.uid+'"><span>'+esc(m.from||'(unknown)')+'</span><span>'+esc(m.subject||'(no subject)')+'</span><small>'+esc(m.snippet)+'</small></button>').join('')+'</div></main><article class="reader" id="reader">Select a message</article>';document.querySelector('.folders').onclick=e=>{const b=e.target.closest('button[data-folder]');if(b){folder=b.dataset.folder;load()}};document.getElementById('refresh').onclick=()=>{q=document.getElementById('q').value;load()};document.getElementById('q').onkeydown=e=>{if(e.key==='Enter'){q=e.target.value;load()}};document.querySelector('.list').onclick=async e=>{const b=e.target.closest('button[data-uid]');if(!b)return;const m=await api('/api/folders/'+encodeURIComponent(folder)+'/messages/'+b.dataset.uid);document.getElementById('reader').innerHTML='<h2>'+esc(m.subject||'(no subject)')+'</h2><p class="muted">From '+esc(m.from||'(unknown)')+' to '+esc(m.to||s.address)+'</p><pre>'+esc(m.text_body)+'</pre>';window.currentUid=Number(b.dataset.uid)};document.getElementById('archive').onclick=()=>bulk('archive');document.getElementById('delete').onclick=()=>bulk('delete')}catch{login()}}
    async function bulk(action){if(!window.currentUid)return;await api('/api/folders/'+encodeURIComponent(folder)+'/messages/bulk',{method:'POST',body:JSON.stringify({action,uids:[window.currentUid]})});window.currentUid=null;load()}
    function login(){root.className='login';root.innerHTML='<form id="login"><h1>rMail</h1><input name="address" placeholder="Mailbox" autocomplete="username"><input name="password" placeholder="Password" type="password" autocomplete="current-password"><button>Sign in</button><p id="err"></p></form>';document.getElementById('login').onsubmit=async e=>{e.preventDefault();const fd=new FormData(e.target);try{await api('/api/login',{method:'POST',body:JSON.stringify({address:fd.get('address'),password:fd.get('password')})});load()}catch{document.getElementById('err').textContent='Invalid mailbox or password'}}}
    load();
  </script></body>
</html>"#;

fn json<T: Serialize>(status: u16, value: &T) -> Response {
    Response {
        status,
        content_type: "application/json",
        headers: Vec::new(),
        body: serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec()),
    }
}

impl Response {
    fn empty(status: u16) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn text(status: u16, text: &str) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            headers: Vec::new(),
            body: text.as_bytes().to_vec(),
        }
    }

    fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((key.into(), value.into()));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmail_common::maildir;

    fn state(td: &tempfile::TempDir) -> AppState {
        let db_path = td.path().join("accounts.sqlite");
        db::init_db(&db_path).unwrap();
        db::add_mailbox(
            &db_path,
            "user@example.test",
            Some("plain:secret"),
            None,
            None,
        )
        .unwrap();
        AppState {
            mail_root: td.path().join("mail"),
            db_path,
            session_secret: b"test secret".to_vec(),
        }
    }

    fn req(method: &str, path: &str, body: &[u8], cookie: Option<String>) -> Request {
        let mut headers = HashMap::new();
        if let Some(cookie) = cookie {
            headers.insert("cookie".to_string(), cookie);
        }
        let (path, query) = split_target(path);
        Request {
            method: method.to_string(),
            path,
            query,
            headers,
            body: body.to_vec(),
        }
    }

    #[tokio::test]
    async fn login_success_and_failure() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        let bad = route(
            req(
                "POST",
                "/api/login",
                br#"{"address":"user@example.test","password":"bad"}"#,
                None,
            ),
            &state,
        )
        .await;
        assert_eq!(bad.status, 401);
        let ok = route(
            req(
                "POST",
                "/api/login",
                br#"{"address":"user@example.test","password":"secret"}"#,
                None,
            ),
            &state,
        )
        .await;
        assert_eq!(ok.status, 200);
        assert!(ok.headers.iter().any(|(k, _)| k == "Set-Cookie"));
    }

    #[tokio::test]
    async fn folders_require_cookie_and_return_maildir_state() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        let denied = route(req("GET", "/api/folders", b"", None), &state).await;
        assert_eq!(denied.status, 401);
        maildir::deliver(
            &state.mail_root,
            "example.test",
            "user",
            b"From: a@example.test\r\nTo: user@example.test\r\nSubject: hello\r\n\r\nbody",
        )
        .unwrap();
        let token = sign_session(&state.session_secret, "user@example.test");
        let ok = route(
            req(
                "GET",
                "/api/folders",
                b"",
                Some(format!("{SESSION_COOKIE}={token}")),
            ),
            &state,
        )
        .await;
        assert_eq!(ok.status, 200);
        let folders: Vec<FolderResponse> = serde_json::from_slice(&ok.body).unwrap();
        let inbox = folders.iter().find(|f| f.name == "INBOX").unwrap();
        assert_eq!(inbox.messages, 1);
        assert_eq!(inbox.unread, 1);
    }

    #[tokio::test]
    async fn message_endpoints_and_bulk_archive() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        maildir::deliver(
            &state.mail_root,
            "example.test",
            "user",
            b"From: a@example.test\r\nTo: user@example.test\r\nSubject: hello\r\n\r\nbody text",
        )
        .unwrap();
        let token = sign_session(&state.session_secret, "user@example.test");
        let cookie = Some(format!("{SESSION_COOKIE}={token}"));
        let list = route(
            req(
                "GET",
                "/api/folders/INBOX/messages?q=hello",
                b"",
                cookie.clone(),
            ),
            &state,
        )
        .await;
        assert_eq!(list.status, 200);
        let items: Vec<MessageListItem> = serde_json::from_slice(&list.body).unwrap();
        assert_eq!(items.len(), 1);
        let patch = route(
            req(
                "PATCH",
                &format!("/api/folders/INBOX/messages/{}", items[0].uid),
                br#"{"seen":true}"#,
                cookie.clone(),
            ),
            &state,
        )
        .await;
        assert_eq!(patch.status, 204);
        let bulk = route(
            req(
                "POST",
                "/api/folders/INBOX/messages/bulk",
                format!(r#"{{"action":"archive","uids":[{}]}}"#, items[0].uid).as_bytes(),
                cookie,
            ),
            &state,
        )
        .await;
        assert_eq!(bulk.status, 204);
        assert_eq!(
            imap_state::load_folder(&state.mail_root, "example.test", "user", "INBOX")
                .unwrap()
                .1
                .len(),
            0
        );
        assert_eq!(
            imap_state::load_folder(&state.mail_root, "example.test", "user", "Archive")
                .unwrap()
                .1
                .len(),
            1
        );
    }
}
