//! Blobs (RFC 8620 section 6): uploads, and the stored messages and their
//! parts.
//!
//! - A message's blob id is its EMAILID; a part's is `<EMAILID>_<partId>`.
//! - Uploads get ids starting with `U` and live for a day in the uploading
//!   user's own directory, whatever account they were uploaded to, so only
//!   that user can use them.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Extension;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rmail_common::http::Peer;
use rmail_common::jmap::mime;
use serde_json::json;

use super::email::visible_emails;
use super::{
    Account, Ctx, MAX_SIZE_UPLOAD, MethodError, User, authenticate, blocking, json_response,
};
use crate::api::AppState;

const UPLOAD_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

fn uploads_dir(mail_root: &std::path::Path, user: &User) -> PathBuf {
    let account =
        rmail_common::imap_state::account_maildir(mail_root, &user.domain, &user.localpart);
    account
        .parent()
        .map(|parent| parent.join("jmap-uploads"))
        .unwrap_or_else(|| account.join("jmap-uploads"))
}

fn valid_upload_id(id: &str) -> bool {
    id.len() == 25 && id.starts_with('U') && id[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The bytes behind `blob_id`, if the user may read them in `account`.
pub(crate) fn blob_bytes(
    ctx: &Ctx,
    account: &Account,
    blob_id: &str,
) -> Result<Option<Vec<u8>>, MethodError> {
    if blob_id.starts_with('U') {
        if !valid_upload_id(blob_id) {
            return Ok(None);
        }
        let path = uploads_dir(&ctx.app.mail_root, &ctx.user).join(blob_id);
        return Ok(std::fs::read(path).ok());
    }
    let (email_id, part_id) = match blob_id.split_once('_') {
        Some((email_id, part_id)) => (email_id, Some(part_id)),
        None => (blob_id, None),
    };
    let Some(row) = visible_emails(ctx, account, Some(&[email_id.to_string()]))?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    let Some(data) = row
        .copies
        .iter()
        .find_map(|copy| std::fs::read(&copy.path).ok())
    else {
        return Ok(None);
    };
    Ok(match part_id {
        None => Some(data),
        Some(part_id) => mime::parse(&data)
            .find(part_id)
            .map(|part| part.decoded(&data)),
    })
}

fn upload_type(blob_id: &str, dir: &std::path::Path) -> String {
    std::fs::read_to_string(dir.join(format!("{blob_id}.type")))
        .unwrap_or_else(|_| "application/octet-stream".to_string())
}

/// Media types are `type/subtype` with token characters only.
fn sane_type(value: &str) -> Option<String> {
    let value = value.split(';').next()?.trim().to_ascii_lowercase();
    let (kind, sub) = value.split_once('/')?;
    let token = |text: &str| {
        !text.is_empty()
            && text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&byte))
    };
    (token(kind) && token(sub)).then_some(value)
}

pub(crate) async fn upload(
    app: State<Arc<AppState>>,
    Extension(peer): Extension<Peer>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let state = app.0;
    if super::from_another_site(&headers) {
        return super::cross_site_refusal();
    }
    let user = match authenticate(&state, &headers, &peer).await {
        Ok(user) => user,
        Err(response) => return *response,
    };
    if body.len() > MAX_SIZE_UPLOAD {
        return (StatusCode::PAYLOAD_TOO_LARGE, "upload too large").into_response();
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(sane_type)
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let task_state = state.clone();
    let outcome = blocking(move || {
        let accounts = super::accounts(&task_state, &user)?;
        if !accounts.iter().any(|account| account.id == account_id) {
            return Ok(None);
        }
        let dir = uploads_dir(&task_state.mail_root, &user);
        std::fs::create_dir_all(&dir)?;
        // Forget uploads nobody used within their lifetime.
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let stale = entry
                    .metadata()
                    .and_then(|metadata| metadata.modified())
                    .ok()
                    .and_then(|modified| SystemTime::now().duration_since(modified).ok())
                    .is_some_and(|age| age > UPLOAD_LIFETIME);
                if stale {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        let blob_id = format!("U{:024x}", rand::random::<u128>() >> 32);
        std::fs::write(dir.join(&blob_id), &body)?;
        std::fs::write(dir.join(format!("{blob_id}.type")), &content_type)?;
        Ok(Some(json!({
            "accountId": account_id,
            "blobId": blob_id,
            "type": content_type,
            "size": body.len(),
        })))
    })
    .await;
    match outcome {
        Ok(Some(value)) => {
            let mut response = json_response(&value);
            *response.status_mut() = StatusCode::CREATED;
            response
        }
        Ok(None) => (StatusCode::NOT_FOUND, "no such account").into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

/// `filename*=` value for Content-Disposition (RFC 6266, RFC 8187).
fn disposition(name: &str) -> String {
    let encoded = name
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&byte) {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect::<String>();
    format!("attachment; filename*=UTF-8''{encoded}")
}

pub(crate) async fn download(
    app: State<Arc<AppState>>,
    Extension(peer): Extension<Peer>,
    Path((account_id, blob_id, name)): Path<(String, String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let state = app.0;
    let user = match authenticate(&state, &headers, &peer).await {
        Ok(user) => user,
        Err(response) => return *response,
    };
    let task_state = state.clone();
    let task_blob = blob_id.clone();
    let outcome = blocking(move || {
        let accounts = super::accounts(&task_state, &user)?;
        let mut ctx = Ctx::new(task_state.clone(), user.clone(), accounts);
        let Ok(account) = ctx.account_by_id(&account_id) else {
            return Ok(None);
        };
        let data =
            blob_bytes(&ctx, &account, &task_blob).map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let stored_type = task_blob
            .starts_with('U')
            .then(|| upload_type(&task_blob, &uploads_dir(&task_state.mail_root, &user)));
        Ok(data.map(|data| (data, stored_type)))
    })
    .await;
    match outcome {
        Ok(Some((data, stored_type))) => {
            let content_type = params
                .get("accept")
                .and_then(|accept| sane_type(accept))
                .or(stored_type)
                .unwrap_or_else(|| "application/octet-stream".to_string());
            let mut response = (StatusCode::OK, data).into_response();
            let headers = response.headers_mut();
            if let Ok(value) = HeaderValue::from_str(&content_type) {
                headers.insert(header::CONTENT_TYPE, value);
            }
            if let Ok(value) = HeaderValue::from_str(&disposition(&name)) {
                headers.insert(header::CONTENT_DISPOSITION, value);
            }
            response
        }
        Ok(None) => (StatusCode::NOT_FOUND, "no such blob").into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}
