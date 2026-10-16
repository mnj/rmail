//! Large files sent as download links (`/f/<token>`), when the admin turns
//! them on (`file_links.*` settings).
//!
//! - The browser uploads a file in chunks (each under the request size
//!   limit), then finishes it; the server answers with a link that works
//!   for `file_links.days` and deletes the file afterwards.
//! - Anyone with a link can download the file, always as an attachment
//!   (`application/octet-stream`), never shown in the browser, so a file
//!   cannot run as a page of this site.
//! - Files live in the account's directory (outside its Maildir folders);
//!   the list of files is in the accounts database, so a link finds its
//!   file without a session.

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{AppState, Session, Shared, blocking, internal_error};

/// Largest chunk one request carries (under the webmail body limit).
pub(crate) const CHUNK_BYTES: usize = 8 * 1024 * 1024;
/// Unfinished uploads are dropped after this long.
const STALE_UPLOAD_SECS: i64 = 24 * 3600;

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS shared_files (
        id TEXT PRIMARY KEY,
        address TEXT NOT NULL,
        name TEXT NOT NULL,
        size INTEGER NOT NULL,
        received INTEGER NOT NULL DEFAULT 0,
        token TEXT UNIQUE,
        created INTEGER NOT NULL,
        expires INTEGER,
        downloads INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_shared_files_address ON shared_files(address);
";

pub(crate) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/files", get(list).post(start))
        .route("/api/files/{id}", axum::routing::delete(remove))
        .route("/api/files/{id}/chunk", put(chunk))
        .route("/api/files/{id}/finish", post(finish))
        .route("/f/{token}", get(download))
}

fn open(state: &AppState) -> anyhow::Result<rmail_common::sqlite_pool::SqliteConnection> {
    let conn = rmail_common::sqlite_pool::connection(&state.db_path)?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

fn settings(state: &AppState) -> rmail_common::config::FileLinksConfig {
    rmail_common::settings::open(&state.db_path)
        .ok()
        .and_then(|conn| rmail_common::settings::file_links(&conn).ok())
        .unwrap_or_default()
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn random_hex(bytes: usize) -> String {
    (0..bytes)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect()
}

/// Where an account's file `id` is kept.
fn file_path(state: &AppState, address: &str, id: &str) -> Option<std::path::PathBuf> {
    let (local, domain) = address.split_once('@')?;
    let valid = !id.is_empty() && id.bytes().all(|b| b.is_ascii_hexdigit());
    valid.then(|| {
        rmail_common::imap_state::account_maildir(&state.mail_root, domain, local)
            .join("rmail-files")
            .join(id)
    })
}

fn refused(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// Delete expired files and uploads left unfinished.
pub(crate) fn sweep(state: &AppState) -> anyhow::Result<usize> {
    let conn = open(state)?;
    let rows: Vec<(String, String)> = conn
        .prepare(
            "SELECT id, address FROM shared_files
             WHERE (expires IS NOT NULL AND expires <= ?1) OR (token IS NULL AND created <= ?2)",
        )?
        .query_map(params![now(), now() - STALE_UPLOAD_SECS], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    for (id, address) in &rows {
        delete_file(state, &conn, address, id)?;
    }
    Ok(rows.len())
}

fn delete_file(state: &AppState, conn: &Connection, address: &str, id: &str) -> anyhow::Result<()> {
    if let Some(path) = file_path(state, address, id) {
        let _ = std::fs::remove_file(path);
    }
    conn.execute("DELETE FROM shared_files WHERE id = ?1", params![id])?;
    Ok(())
}

#[derive(Serialize)]
struct SharedFile {
    id: String,
    name: String,
    size: u64,
    url: String,
    created: i64,
    expires: i64,
    downloads: u64,
}

async fn list(app: State<Shared>, headers: HeaderMap) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let result = blocking(move || {
        let config = settings(&state);
        let conn = open(&state)?;
        let files = conn
            .prepare(
                "SELECT id, name, size, token, created, expires, downloads FROM shared_files
                 WHERE address = ?1 AND token IS NOT NULL AND expires > ?2 ORDER BY created DESC",
            )?
            .query_map(params![session.address, now()], |row| {
                Ok(SharedFile {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    size: row.get::<_, i64>(2)? as u64,
                    url: format!("/f/{}", row.get::<_, String>(3)?),
                    created: row.get(4)?,
                    expires: row.get(5)?,
                    downloads: row.get::<_, i64>(6)? as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let used: u64 = files.iter().map(|file| file.size).sum();
        Ok(json!({
            "enabled": config.enabled,
            "max_file_bytes": config.max_file_mb * 1024 * 1024,
            "per_user_bytes": config.per_user_mb * 1024 * 1024,
            "days": config.days,
            "chunk_bytes": CHUNK_BYTES,
            "used": used,
            "files": files,
        }))
    })
    .await;
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => internal_error(error),
    }
}

#[derive(Deserialize)]
struct Start {
    name: String,
    size: u64,
}

/// A file's name as given, without paths or control characters.
fn clean_name(name: &str) -> String {
    let name: String = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    let name = name.trim().to_string();
    if name.is_empty() {
        "file".to_string()
    } else {
        name
    }
}

async fn start(app: State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<Start>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "invalid json");
    };
    let result = blocking(move || {
        let config = settings(&state);
        if !config.enabled {
            return Ok(Err((StatusCode::CONFLICT, "Sending large files as links is not turned on here.".to_string())));
        }
        if input.size == 0 || input.size > config.max_file_mb * 1024 * 1024 {
            return Ok(Err((StatusCode::PAYLOAD_TOO_LARGE, format!("Files can be at most {} MB.", config.max_file_mb))));
        }
        sweep(&state)?;
        let conn = open(&state)?;
        let used: i64 = conn.query_row(
            "SELECT COALESCE(SUM(size), 0) FROM shared_files WHERE address = ?1",
            params![session.address],
            |row| row.get(0),
        )?;
        if used as u64 + input.size > config.per_user_mb * 1024 * 1024 {
            return Ok(Err((
                StatusCode::INSUFFICIENT_STORAGE,
                format!("You can share at most {} MB of files at a time; delete some under Compose settings.", config.per_user_mb),
            )));
        }
        let id = random_hex(16);
        let path = file_path(&state, &session.address, &id).ok_or_else(|| anyhow::anyhow!("no account directory"))?;
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::File::create(&path)?;
        conn.execute(
            "INSERT INTO shared_files (id, address, name, size, created) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, session.address, clean_name(&input.name), input.size as i64, now()],
        )?;
        Ok(Ok(json!({ "id": id, "chunk_bytes": CHUNK_BYTES })))
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err((status, message))) => refused(status, &message),
        Err(error) => internal_error(error),
    }
}

#[derive(Deserialize)]
struct Offset {
    offset: u64,
}

/// The user's unfinished upload `id`: (size, received).
fn upload(conn: &Connection, address: &str, id: &str) -> rusqlite::Result<Option<(u64, u64)>> {
    conn.query_row(
        "SELECT size, received FROM shared_files WHERE id = ?1 AND address = ?2 AND token IS NULL",
        params![id, address],
        |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64)),
    )
    .optional()
}

async fn chunk(
    app: State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(at): Query<Offset>,
    body: Bytes,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    if body.is_empty() || body.len() > CHUNK_BYTES {
        return refused(StatusCode::PAYLOAD_TOO_LARGE, "chunks are at most 8 MB");
    }
    let result = blocking(move || {
        use std::io::Write;
        let conn = open(&state)?;
        let Some((size, received)) = upload(&conn, &session.address, &id)? else {
            return Ok(Err((StatusCode::NOT_FOUND, "no such upload")));
        };
        // Chunks come in order; a repeated one (a retry) is not added twice.
        if at.offset != received {
            return Ok(Err((StatusCode::CONFLICT, "out of order")));
        }
        if received + body.len() as u64 > size {
            return Ok(Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                "more than the file's size",
            )));
        }
        let path =
            file_path(&state, &session.address, &id).ok_or_else(|| anyhow::anyhow!("bad id"))?;
        let mut file = std::fs::OpenOptions::new().append(true).open(&path)?;
        file.write_all(&body)?;
        file.flush()?;
        conn.execute(
            "UPDATE shared_files SET received = received + ?2 WHERE id = ?1",
            params![id, body.len() as i64],
        )?;
        Ok(Ok(received + body.len() as u64))
    })
    .await;
    match result {
        Ok(Ok(received)) => Json(json!({ "received": received })).into_response(),
        Ok(Err((status, message))) => refused(status, message),
        Err(error) => internal_error(error),
    }
}

async fn finish(app: State<Shared>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let result = blocking(move || {
        let config = settings(&state);
        let conn = open(&state)?;
        let Some((size, received)) = upload(&conn, &session.address, &id)? else {
            return Ok(Err((StatusCode::NOT_FOUND, "no such upload")));
        };
        if received != size {
            return Ok(Err((StatusCode::CONFLICT, "the upload is not complete")));
        }
        let token = random_hex(24);
        let expires = now() + config.days as i64 * 86_400;
        conn.execute(
            "UPDATE shared_files SET token = ?2, expires = ?3 WHERE id = ?1",
            params![id, token, expires],
        )?;
        Ok(Ok(
            json!({ "id": id, "url": format!("/f/{token}"), "expires": expires, "size": size }),
        ))
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err((status, message))) => refused(status, message),
        Err(error) => internal_error(error),
    }
}

async fn remove(app: State<Shared>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let result = blocking(move || {
        let conn = open(&state)?;
        let mine: Option<String> = conn
            .query_row(
                "SELECT id FROM shared_files WHERE id = ?1 AND address = ?2",
                params![id, session.address],
                |row| row.get(0),
            )
            .optional()?;
        let Some(id) = mine else {
            return Ok(false);
        };
        delete_file(&state, &conn, &session.address, &id)?;
        Ok(true)
    })
    .await;
    match result {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => internal_error(error),
    }
}

/// `filename*` (RFC 6266/8187) and an ASCII fallback for `Content-Disposition`.
fn disposition(name: &str) -> String {
    let ascii: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() && c != '"' && c != '\\' || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let encoded: String = name
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{encoded}")
}

async fn download(app: State<Shared>, Path(token): Path<String>) -> Response {
    let state = app.0;
    if token.len() != 48 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let found =
        {
            let state = state.clone();
            blocking(move || {
                let conn = open(&state)?;
                let row: Option<(String, String, String, i64, i64)> = conn
                .query_row(
                    "SELECT id, address, name, size, expires FROM shared_files WHERE token = ?1",
                    params![token],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                )
                .optional()?;
                let Some((id, address, name, size, expires)) = row else {
                    return Ok(None);
                };
                if expires <= now() {
                    delete_file(&state, &conn, &address, &id)?;
                    return Ok(None);
                }
                conn.execute(
                    "UPDATE shared_files SET downloads = downloads + 1 WHERE id = ?1",
                    params![id],
                )?;
                Ok(file_path(&state, &address, &id).map(|path| (path, name, size)))
            })
            .await
        };
    let (path, name, size) = match found {
        Ok(Some(found)) => found,
        Ok(None) => {
            return (StatusCode::GONE, "This link has expired or was removed.").into_response();
        }
        Err(error) => return internal_error(error),
    };
    let Ok(file) = tokio::fs::File::open(&path).await else {
        return (StatusCode::GONE, "This link has expired or was removed.").into_response();
    };
    let mut response = Body::from_stream(tokio_util::io::ReaderStream::new(file)).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size as u64));
    if let Ok(value) = HeaderValue::from_str(&disposition(&name)) {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::super::tests::{req, route, state};
    use super::super::{SESSION_COOKIE, sign_session};
    use serde_json::{Value, json};

    #[tokio::test]
    async fn large_files_become_links_that_expire() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        rmail_common::imap_state::init_account(&state.mail_root, "example.test", "user").unwrap();
        let cookie = Some(format!(
            "{SESSION_COOKIE}={}",
            sign_session(&state, "user@example.test")
        ));
        let call = |method: &'static str, path: String, body: Vec<u8>, cookie: Option<String>| {
            let state = state.clone();
            async move { route(req(method, &path, &body, cookie), &state).await }
        };
        let json_of = |body: &[u8]| serde_json::from_slice::<Value>(body).unwrap_or(Value::Null);
        let start = |size: u64| {
            json!({"name": "../holiday photos.zip", "size": size})
                .to_string()
                .into_bytes()
        };

        let off = call("POST", "/api/files".into(), start(10), cookie.clone()).await;
        assert_eq!(off.status, 409, "off until the admin turns it on");
        let mut settings = rmail_common::settings::open(&state.db_path).unwrap();
        rmail_common::settings::write_raw(
            &mut settings,
            &[
                ("file_links.enabled".to_string(), Some(json!(true))),
                ("file_links.max_file_mb".to_string(), Some(json!(1))),
                ("file_links.per_user_mb".to_string(), Some(json!(1))),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap();
        let too_big = call(
            "POST",
            "/api/files".into(),
            start(2 * 1024 * 1024),
            cookie.clone(),
        )
        .await;
        assert_eq!(too_big.status, 413);

        let data: Vec<u8> = (0..700_000u32).map(|i| (i % 251) as u8).collect();
        let made = call(
            "POST",
            "/api/files".into(),
            start(data.len() as u64),
            cookie.clone(),
        )
        .await;
        assert_eq!(made.status, 200);
        let id = json_of(&made.body)["id"].as_str().unwrap().to_string();
        let over = call("POST", "/api/files".into(), start(500_000), cookie.clone()).await;
        assert_eq!(
            over.status, 507,
            "the user's allowance counts unfinished uploads"
        );

        let first = call(
            "PUT",
            format!("/api/files/{id}/chunk?offset=0"),
            data[..400_000].to_vec(),
            cookie.clone(),
        )
        .await;
        assert_eq!(first.status, 200);
        let retry = call(
            "PUT",
            format!("/api/files/{id}/chunk?offset=0"),
            data[..400_000].to_vec(),
            cookie.clone(),
        )
        .await;
        assert_eq!(retry.status, 409, "a repeated chunk is not added twice");
        let early = call(
            "POST",
            format!("/api/files/{id}/finish"),
            vec![],
            cookie.clone(),
        )
        .await;
        assert_eq!(early.status, 409);
        let rest = call(
            "PUT",
            format!("/api/files/{id}/chunk?offset=400000"),
            data[400_000..].to_vec(),
            cookie.clone(),
        )
        .await;
        assert_eq!(rest.status, 200);
        let done = call(
            "POST",
            format!("/api/files/{id}/finish"),
            vec![],
            cookie.clone(),
        )
        .await;
        assert_eq!(done.status, 200);
        let url = json_of(&done.body)["url"].as_str().unwrap().to_string();

        // Anyone with the link gets the file, as a download.
        let fetched = call("GET", url.clone(), vec![], None).await;
        assert_eq!(fetched.status, 200);
        assert_eq!(fetched.body, data);
        let header = |name: &str| {
            fetched
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(header("content-type"), "application/octet-stream");
        assert!(
            header("content-disposition")
                .starts_with("attachment; filename=\"holiday photos.zip\""),
            "{}",
            header("content-disposition")
        );
        let listed = json_of(
            &call("GET", "/api/files".into(), vec![], cookie.clone())
                .await
                .body,
        );
        assert_eq!(listed["files"][0]["downloads"], 1);
        assert_eq!(listed["files"][0]["name"], "holiday photos.zip");
        let folders =
            rmail_common::imap_state::list_folders(&state.mail_root, "example.test", "user")
                .unwrap();
        assert!(
            !folders.iter().any(|f| f.name.contains("rmail-files")),
            "files are not a mail folder"
        );

        // Someone else cannot remove it; an expired link is gone with its file.
        rmail_common::db::add_mailbox(
            &state.db_path,
            "other@example.test",
            Some("plain:x"),
            None,
            None,
        )
        .unwrap();
        let other = Some(format!(
            "{SESSION_COOKIE}={}",
            sign_session(&state, "other@example.test")
        ));
        assert_eq!(
            call("DELETE", format!("/api/files/{id}"), vec![], other)
                .await
                .status,
            404
        );
        let conn = super::open(&state).unwrap();
        conn.execute("UPDATE shared_files SET expires = 1 WHERE id = ?1", [&id])
            .unwrap();
        assert_eq!(super::sweep(&state).unwrap(), 1);
        assert_eq!(call("GET", url, vec![], None).await.status, 410);
        assert!(
            !super::file_path(&state, "user@example.test", &id)
                .unwrap()
                .exists()
        );
    }

    #[tokio::test]
    async fn full_size_chunks_get_through() {
        // axum's own 2 MB body limit used to cut these (and big attachments) off.
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        rmail_common::imap_state::init_account(&state.mail_root, "example.test", "user").unwrap();
        let mut settings = rmail_common::settings::open(&state.db_path).unwrap();
        rmail_common::settings::write_raw(
            &mut settings,
            &[("file_links.enabled".to_string(), Some(json!(true)))]
                .into_iter()
                .collect(),
        )
        .unwrap();
        let cookie = Some(format!(
            "{SESSION_COOKIE}={}",
            sign_session(&state, "user@example.test")
        ));
        let size = super::CHUNK_BYTES + 1000;
        let made = route(
            req(
                "POST",
                "/api/files",
                json!({"name": "a", "size": size}).to_string().as_bytes(),
                cookie.clone(),
            ),
            &state,
        )
        .await;
        let id = serde_json::from_slice::<Value>(&made.body).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        let chunk = vec![7u8; super::CHUNK_BYTES];
        let put = route(
            req(
                "PUT",
                &format!("/api/files/{id}/chunk?offset=0"),
                &chunk,
                cookie,
            ),
            &state,
        )
        .await;
        assert_eq!(put.status, 200, "{}", String::from_utf8_lossy(&put.body));
    }
}
