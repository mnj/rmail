//! Personal file storage over WebDAV (RFC 4918), at `/webdav/`, when the
//! admin turns it on (`files.*` settings). Webmail's Files view uses the
//! same endpoint.
//!
//! - Each user sees their own tree, kept in their account directory
//!   (`rmail-drive/`, outside the Maildir folders), within a quota.
//! - Clients sign in as for CalDAV and JMAP (password or app password, or a
//!   Bearer token); webmail sends its session cookie with its CSRF header.
//! - Class 1 plus the LOCK and UNLOCK that macOS Finder and Windows need
//!   to write: locks are granted but not enforced (one user, own files).
//! - Uploads stream to disk and stop at the file size or quota limit, so
//!   this route has its own body limit and a longer request deadline than
//!   the rest of webmail.
//! - Downloads are always attachments, never rendered, so an uploaded HTML
//!   file cannot run as a page of this site.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Extension;
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use futures_util::StreamExt;
use rmail_common::http::Peer;
use tokio::io::AsyncWriteExt;

use crate::api::AppState;
use crate::jmap::{self, User};

const PREFIX: &str = "/webdav";
/// How long one request (a large upload or download) may take.
const REQUEST_DEADLINE: Duration = Duration::from_secs(4 * 3600);
/// Largest PROPPATCH or LOCK body read.
const MAX_XML_BYTES: usize = 64 * 1024;

pub(crate) fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/webdav", any(handle))
        .route("/webdav/", any(handle))
        .route("/webdav/{*path}", any(handle))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_DEADLINE,
        ))
        .with_state(state)
}

fn settings(state: &AppState) -> rmail_common::config::FilesConfig {
    rmail_common::settings::open(&state.db_path)
        .ok()
        .and_then(|conn| rmail_common::settings::files(&conn).ok())
        .unwrap_or_default()
}

/// The user's storage root.
pub(crate) fn root(state: &AppState, user: &User) -> PathBuf {
    rmail_common::imap_state::account_maildir(&state.mail_root, &user.domain, &user.localpart)
        .join("rmail-drive")
}

fn percent_decode(segment: &str) -> Option<String> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = segment.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn percent_encode(segment: &str) -> String {
    segment
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// A name a file or folder may have: no separators, controls or `..`.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|c| c.is_control() || c == '/' || c == '\\')
}

/// The decoded path segments under `/webdav/`, or `None` for a path that
/// is not one of the user's.
pub(crate) fn segments(path: &str) -> Option<Vec<String>> {
    let rest = path.strip_prefix(PREFIX)?;
    if !rest.is_empty() && !rest.starts_with('/') {
        return None;
    }
    rest.split('/')
        .filter(|s| !s.is_empty())
        .map(|s| percent_decode(s).filter(|name| valid_name(name)))
        .collect()
}

fn href(segments: &[String], collection: bool) -> String {
    let mut out = String::from(PREFIX);
    out.push('/');
    out.push_str(
        &segments
            .iter()
            .map(|s| percent_encode(s))
            .collect::<Vec<_>>()
            .join("/"),
    );
    if collection && !segments.is_empty() {
        out.push('/');
    }
    out
}

fn status(code: StatusCode) -> Response {
    code.into_response()
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn http_date(time: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(time)
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

/// Bytes stored under `dir`.
fn usage(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| match entry.metadata() {
            Ok(meta) if meta.is_dir() => usage(&entry.path()),
            Ok(meta) => meta.len(),
            Err(_) => 0,
        })
        .sum()
}

fn options() -> Response {
    let mut response = status(StatusCode::OK);
    let headers = response.headers_mut();
    headers.insert("DAV", HeaderValue::from_static("1, 2"));
    headers.insert("MS-Author-Via", HeaderValue::from_static("DAV"));
    headers.insert(
        header::ALLOW,
        HeaderValue::from_static(
            "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK",
        ),
    );
    response
}

/// The signed-in user: an app or mail client's credentials, or webmail's
/// session cookie (with its CSRF header for anything but reading).
async fn user_of(
    state: &AppState,
    headers: &HeaderMap,
    peer: &Peer,
    method: &Method,
) -> Result<User, Response> {
    if !headers.contains_key(header::AUTHORIZATION) {
        let reads = matches!(method.as_str(), "GET" | "HEAD" | "PROPFIND");
        if (reads || headers.contains_key("x-rmail-webmail"))
            && let Ok(session) = crate::api::Session::signed_in(state, headers).await
        {
            return Ok(User {
                address: session.address,
                domain: session.domain,
                localpart: session.localpart,
            });
        }
    }
    jmap::authenticate(state, headers, peer)
        .await
        .map_err(|response| *response)
}

async fn handle(
    app: State<Arc<AppState>>,
    Extension(peer): Extension<Peer>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let state = app.0;
    if method == Method::OPTIONS {
        return options();
    }
    if !matches!(method, Method::GET | Method::HEAD) && jmap::from_another_site(&headers) {
        return jmap::cross_site_refusal();
    }
    let config = settings(&state);
    if !config.enabled {
        return status(StatusCode::NOT_FOUND);
    }
    let user = match user_of(&state, &headers, &peer, &method).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(path) = segments(uri.path()) else {
        return status(StatusCode::BAD_REQUEST);
    };
    let root = root(&state, &user);
    if let Err(error) = tokio::fs::create_dir_all(&root).await {
        return jmap::internal_response(error);
    }
    let target = path.iter().fold(root.clone(), |dir, name| dir.join(name));
    match method.as_str() {
        "GET" | "HEAD" => get(&target, method == Method::HEAD).await,
        "PUT" => put(&root, &target, &headers, body, &config).await,
        "PROPFIND" => {
            let depth = headers
                .get("depth")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("1")
                .to_string();
            let quota = config.quota_mb * 1024 * 1024;
            blocking(move || propfind(&root, &path, &target, &depth, quota)).await
        }
        "PROPPATCH" => {
            let Ok(bytes) = read_small(body).await else {
                return status(StatusCode::PAYLOAD_TOO_LARGE);
            };
            if !target.exists() {
                return status(StatusCode::NOT_FOUND);
            }
            proppatch(&path, target.is_dir(), &bytes)
        }
        "MKCOL" => {
            let Ok(bytes) = read_small(body).await else {
                return status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            };
            if !bytes.is_empty() {
                return status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
            blocking(move || mkcol(&target)).await
        }
        "DELETE" => {
            if path.is_empty() {
                return status(StatusCode::FORBIDDEN);
            }
            blocking(move || delete(&target)).await
        }
        "COPY" | "MOVE" => {
            let moving = method.as_str() == "MOVE";
            let Some(destination) = destination(&headers) else {
                return status(StatusCode::BAD_REQUEST);
            };
            if path.is_empty() || destination.is_empty() {
                return status(StatusCode::FORBIDDEN);
            }
            let to = destination
                .iter()
                .fold(root.clone(), |dir, name| dir.join(name));
            let overwrite = headers.get("overwrite").and_then(|v| v.to_str().ok()) != Some("F");
            let quota = config.quota_mb * 1024 * 1024;
            blocking(move || copy_or_move(&root, &target, &to, moving, overwrite, quota)).await
        }
        "LOCK" => {
            let _ = read_small(body).await;
            lock(&path, &target, &headers).await
        }
        "UNLOCK" => status(StatusCode::NO_CONTENT),
        _ => status(StatusCode::METHOD_NOT_ALLOWED),
    }
}

async fn blocking(work: impl FnOnce() -> Response + Send + 'static) -> Response {
    tokio::task::spawn_blocking(work)
        .await
        .unwrap_or_else(jmap::internal_response)
}

async fn read_small(body: Body) -> Result<Vec<u8>, ()> {
    let bytes = axum::body::to_bytes(body, MAX_XML_BYTES)
        .await
        .map_err(|_| ())?;
    Ok(bytes.to_vec())
}

/// The `Destination` header's path, if it is one of the user's.
fn destination(headers: &HeaderMap) -> Option<Vec<String>> {
    let value = headers.get("destination")?.to_str().ok()?;
    let path = match value.split_once("://") {
        Some((_, rest)) => &rest[rest.find('/')?..],
        None => value,
    };
    segments(path.split(['?', '#']).next()?)
}

async fn get(target: &Path, head: bool) -> Response {
    let Ok(meta) = tokio::fs::metadata(target).await else {
        return status(StatusCode::NOT_FOUND);
    };
    if meta.is_dir() {
        // Folders are listed with PROPFIND (or in webmail).
        let mut response = (
            StatusCode::OK,
            "This is a folder. Open it in a WebDAV client or in webmail's Files view.",
        )
            .into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        return response;
    }
    let body = if head {
        Body::empty()
    } else {
        match tokio::fs::File::open(target).await {
            Ok(file) => Body::from_stream(tokio_util::io::ReaderStream::new(file)),
            Err(_) => return status(StatusCode::NOT_FOUND),
        }
    };
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(meta.len()));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox"),
    );
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    if let Ok(value) = HeaderValue::from_str(&format!(
        "attachment; filename*=UTF-8''{}",
        percent_encode(name)
    )) {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
    if let Ok(modified) = meta.modified()
        && let Ok(value) = HeaderValue::from_str(&http_date(modified))
    {
        headers.insert(header::LAST_MODIFIED, value);
    }
    if let Ok(value) = HeaderValue::from_str(&etag(&meta)) {
        headers.insert(header::ETAG, value);
    }
    response
}

fn etag(meta: &std::fs::Metadata) -> String {
    let modified = meta
        .modified()
        .ok()
        .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("\"{:x}-{:x}\"", meta.len(), modified)
}

async fn put(
    root: &Path,
    target: &Path,
    headers: &HeaderMap,
    body: Body,
    config: &rmail_common::config::FilesConfig,
) -> Response {
    if target == root || target.is_dir() {
        return status(StatusCode::METHOD_NOT_ALLOWED);
    }
    let Some(parent) = target.parent().filter(|parent| parent.is_dir()) else {
        return status(StatusCode::CONFLICT);
    };
    let existed = target.exists();
    let replaced = std::fs::metadata(target)
        .map(|meta| meta.len())
        .unwrap_or(0);
    let (root_owned, max_file) = (root.to_path_buf(), config.max_file_mb * 1024 * 1024);
    let used = tokio::task::spawn_blocking(move || usage(&root_owned))
        .await
        .unwrap_or(0);
    let room = (config.quota_mb * 1024 * 1024).saturating_sub(used.saturating_sub(replaced));
    let limit = max_file.min(room);
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|length| length > limit) {
        return status(if length_over_file(declared, max_file) {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::INSUFFICIENT_STORAGE
        });
    }
    // Into a temporary file next to it, then into place: a reader never
    // sees half a file, and a failed upload leaves the old one.
    let temporary = parent.join(format!(".rmail-upload-{:016x}", rand::random::<u64>()));
    let Ok(mut file) = tokio::fs::File::create(&temporary).await else {
        return jmap::internal_response("could not create the upload file");
    };
    let mut written: u64 = 0;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else {
            let _ = tokio::fs::remove_file(&temporary).await;
            return status(StatusCode::BAD_REQUEST);
        };
        written += chunk.len() as u64;
        if written > limit {
            let _ = tokio::fs::remove_file(&temporary).await;
            return status(if written > max_file {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::INSUFFICIENT_STORAGE
            });
        }
        if file.write_all(&chunk).await.is_err() {
            let _ = tokio::fs::remove_file(&temporary).await;
            return jmap::internal_response("could not write the upload");
        }
    }
    if file.flush().await.is_err() || tokio::fs::rename(&temporary, target).await.is_err() {
        let _ = tokio::fs::remove_file(&temporary).await;
        return jmap::internal_response("could not store the upload");
    }
    let mut response = status(if existed {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::CREATED
    });
    if let Ok(meta) = std::fs::metadata(target)
        && let Ok(value) = HeaderValue::from_str(&etag(&meta))
    {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

fn length_over_file(declared: Option<u64>, max_file: u64) -> bool {
    declared.is_some_and(|length| length > max_file)
}

fn entry_xml(segments: &[String], meta: &std::fs::Metadata, quota: Option<(u64, u64)>) -> String {
    let collection = meta.is_dir();
    let name = segments.last().map(String::as_str).unwrap_or("");
    let mut props = format!("<D:displayname>{}</D:displayname>", xml_escape(name));
    if collection {
        props.push_str("<D:resourcetype><D:collection/></D:resourcetype>");
    } else {
        props.push_str(&format!(
            "<D:resourcetype/><D:getcontentlength>{}</D:getcontentlength><D:getcontenttype>application/octet-stream</D:getcontenttype><D:getetag>{}</D:getetag>",
            meta.len(),
            xml_escape(&etag(meta))
        ));
    }
    if let Ok(modified) = meta.modified() {
        props.push_str(&format!(
            "<D:getlastmodified>{}</D:getlastmodified>",
            http_date(modified)
        ));
        props.push_str(&format!(
            "<D:creationdate>{}</D:creationdate>",
            chrono::DateTime::<chrono::Utc>::from(meta.created().unwrap_or(modified))
                .format("%Y-%m-%dT%H:%M:%SZ")
        ));
    }
    if let Some((used, available)) = quota {
        props.push_str(&format!(
            "<D:quota-used-bytes>{used}</D:quota-used-bytes><D:quota-available-bytes>{available}</D:quota-available-bytes>"
        ));
    }
    props.push_str("<D:supportedlock><D:lockentry><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry></D:supportedlock>");
    format!(
        "<D:response><D:href>{}</D:href><D:propstat><D:prop>{props}</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
        xml_escape(&href(segments, collection))
    )
}

fn multistatus(body: String) -> Response {
    let mut response = (
        StatusCode::MULTI_STATUS,
        format!("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">{body}</D:multistatus>"),
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    response
}

fn propfind(root: &Path, path: &[String], target: &Path, depth: &str, quota: u64) -> Response {
    let Ok(meta) = std::fs::metadata(target) else {
        return status(StatusCode::NOT_FOUND);
    };
    let used = if meta.is_dir() { usage(root) } else { 0 };
    let quota_info = meta.is_dir().then(|| (used, quota.saturating_sub(used)));
    let mut body = entry_xml(path, &meta, quota_info);
    if meta.is_dir() && depth != "0" {
        let mut children: Vec<(String, std::fs::Metadata)> = std::fs::read_dir(target)
            .map(|entries| {
                entries
                    .flatten()
                    .filter_map(|entry| {
                        let name = entry.file_name().into_string().ok()?;
                        (valid_name(&name) && !name.starts_with(".rmail-upload-"))
                            .then(|| Some((name, entry.metadata().ok()?)))
                            .flatten()
                    })
                    .collect()
            })
            .unwrap_or_default();
        children.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, child) in children {
            let mut segments = path.to_vec();
            segments.push(name);
            body.push_str(&entry_xml(&segments, &child, None));
        }
    }
    multistatus(body)
}

/// Properties clients set (Windows timestamps, macOS tags) are accepted
/// and not kept.
fn proppatch(path: &[String], collection: bool, body: &[u8]) -> Response {
    let mut props = String::new();
    if let Ok(text) = std::str::from_utf8(body)
        && let Ok(doc) = roxmltree::Document::parse(text)
    {
        for prop in doc.descendants().filter(|n| n.tag_name().name() == "prop") {
            for element in prop.children().filter(|n| n.is_element()) {
                let ns = element.tag_name().namespace().unwrap_or("");
                props.push_str(&format!(
                    "<x:{} xmlns:x=\"{}\"/>",
                    element.tag_name().name(),
                    xml_escape(ns)
                ));
            }
        }
    }
    multistatus(format!(
        "<D:response><D:href>{}</D:href><D:propstat><D:prop>{props}</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
        xml_escape(&href(path, collection))
    ))
}

fn mkcol(target: &Path) -> Response {
    if target.exists() {
        return status(StatusCode::METHOD_NOT_ALLOWED);
    }
    if !target.parent().is_some_and(Path::is_dir) {
        return status(StatusCode::CONFLICT);
    }
    match std::fs::create_dir(target) {
        Ok(()) => status(StatusCode::CREATED),
        Err(error) => jmap::internal_response(error),
    }
}

fn delete(target: &Path) -> Response {
    let removed = if target.is_dir() {
        std::fs::remove_dir_all(target)
    } else if target.exists() {
        std::fs::remove_file(target)
    } else {
        return status(StatusCode::NOT_FOUND);
    };
    match removed {
        Ok(()) => status(StatusCode::NO_CONTENT),
        Err(error) => jmap::internal_response(error),
    }
}

fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    if from.is_dir() {
        std::fs::create_dir(to)?;
        for entry in std::fs::read_dir(from)? {
            let entry = entry?;
            copy_tree(&entry.path(), &to.join(entry.file_name()))?;
        }
        Ok(())
    } else {
        std::fs::copy(from, to).map(|_| ())
    }
}

fn copy_or_move(
    root: &Path,
    from: &Path,
    to: &Path,
    moving: bool,
    overwrite: bool,
    quota: u64,
) -> Response {
    if !from.exists() {
        return status(StatusCode::NOT_FOUND);
    }
    if from == to || to.starts_with(from) {
        return status(StatusCode::FORBIDDEN);
    }
    if !to.parent().is_some_and(Path::is_dir) {
        return status(StatusCode::CONFLICT);
    }
    let existed = to.exists();
    if existed && !overwrite {
        return status(StatusCode::PRECONDITION_FAILED);
    }
    if !moving {
        let size = if from.is_dir() {
            usage(from)
        } else {
            std::fs::metadata(from).map(|m| m.len()).unwrap_or(0)
        };
        let replaced = if existed {
            if to.is_dir() {
                usage(to)
            } else {
                std::fs::metadata(to).map(|m| m.len()).unwrap_or(0)
            }
        } else {
            0
        };
        if usage(root).saturating_sub(replaced) + size > quota {
            return status(StatusCode::INSUFFICIENT_STORAGE);
        }
    }
    if existed {
        let cleared = if to.is_dir() {
            std::fs::remove_dir_all(to)
        } else {
            std::fs::remove_file(to)
        };
        if let Err(error) = cleared {
            return jmap::internal_response(error);
        }
    }
    let done = if moving {
        std::fs::rename(from, to)
    } else {
        copy_tree(from, to)
    };
    match done {
        Ok(()) => status(if existed {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::CREATED
        }),
        Err(error) => jmap::internal_response(error),
    }
}

/// A lock that is granted but not enforced; locking a name that does not
/// exist creates an empty file there (RFC 4918 9.10.4).
async fn lock(path: &[String], target: &Path, headers: &HeaderMap) -> Response {
    let mut created = false;
    if !target.exists() {
        if !target.parent().is_some_and(Path::is_dir) {
            return status(StatusCode::CONFLICT);
        }
        if tokio::fs::File::create(target).await.is_err() {
            return jmap::internal_response("could not create the file");
        }
        created = true;
    }
    let token = headers
        .get("if")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once("<urn:uuid:"))
        .and_then(|(_, rest)| rest.split_once('>'))
        .map(|(uuid, _)| format!("urn:uuid:{uuid}"))
        .unwrap_or_else(|| {
            let hex = format!("{:032x}", rand::random::<u128>());
            format!(
                "urn:uuid:{}-{}-{}-{}-{}",
                &hex[..8],
                &hex[8..12],
                &hex[12..16],
                &hex[16..20],
                &hex[20..]
            )
        });
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:prop xmlns:D=\"DAV:\"><D:lockdiscovery><D:activelock>\
         <D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope><D:depth>0</D:depth>\
         <D:timeout>Second-3600</D:timeout><D:locktoken><D:href>{token}</D:href></D:locktoken>\
         <D:lockroot><D:href>{}</D:href></D:lockroot></D:activelock></D:lockdiscovery></D:prop>",
        xml_escape(&href(path, target.is_dir()))
    );
    let mut response = (
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        body,
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    if let Ok(value) = HeaderValue::from_str(&format!("<{token}>")) {
        headers.insert("lock-token", value);
    }
    response
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use base64::Engine;
    use rmail_common::http::Peer;
    use serde_json::json;

    use crate::api::tests::{route, state};

    fn dav(method: &str, path: &str, body: &[u8], extra: &[(&str, &str)]) -> Request<Body> {
        let auth = base64::engine::general_purpose::STANDARD.encode("user@example.test:secret");
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Basic {auth}"))
            .header("host", "mail.example.test");
        for (name, value) in extra {
            builder = builder.header(*name, *value);
        }
        let mut request = builder.body(Body::from(body.to_vec())).unwrap();
        request
            .extensions_mut()
            .insert(Peer(Some("192.0.2.1:40000".parse().unwrap())));
        request
    }

    #[tokio::test]
    async fn files_are_stored_listed_moved_and_limited() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        rmail_common::imap_state::init_account(&state.mail_root, "example.test", "user").unwrap();
        let off = route(dav("PROPFIND", "/webdav/", b"", &[("depth", "1")]), &state).await;
        assert_eq!(off.status, 404, "off until the admin turns it on");
        let mut settings = rmail_common::settings::open(&state.db_path).unwrap();
        rmail_common::settings::write_raw(
            &mut settings,
            &[
                ("files.enabled".to_string(), Some(json!(true))),
                ("files.quota_mb".to_string(), Some(json!(1))),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap();

        assert_eq!(
            route(dav("OPTIONS", "/webdav/", b"", &[]), &state)
                .await
                .status,
            200
        );
        assert_eq!(
            route(dav("MKCOL", "/webdav/Reports", b"", &[]), &state)
                .await
                .status,
            201
        );
        assert_eq!(
            route(dav("MKCOL", "/webdav/Reports", b"", &[]), &state)
                .await
                .status,
            405
        );
        assert_eq!(
            route(dav("MKCOL", "/webdav/a/b", b"", &[]), &state)
                .await
                .status,
            409
        );
        let put = route(
            dav("PUT", "/webdav/Reports/Q3%20plan.txt", b"hello", &[]),
            &state,
        )
        .await;
        assert_eq!(put.status, 201);
        assert_eq!(
            route(
                dav("PUT", "/webdav/Reports/Q3%20plan.txt", b"hello again", &[]),
                &state
            )
            .await
            .status,
            204
        );
        assert_eq!(
            route(dav("PUT", "/webdav/missing/x.txt", b"x", &[]), &state)
                .await
                .status,
            409
        );

        let listing = route(
            dav("PROPFIND", "/webdav/Reports/", b"", &[("depth", "1")]),
            &state,
        )
        .await;
        assert_eq!(listing.status, 207);
        let text = String::from_utf8(listing.body).unwrap();
        assert!(
            text.contains("<D:href>/webdav/Reports/Q3%20plan.txt</D:href>")
                && text.contains("<D:getcontentlength>11</D:getcontentlength>"),
            "{text}"
        );
        let root = String::from_utf8(
            route(dav("PROPFIND", "/webdav/", b"", &[("depth", "0")]), &state)
                .await
                .body,
        )
        .unwrap();
        assert!(
            root.contains("<D:quota-used-bytes>11</D:quota-used-bytes>"),
            "{root}"
        );

        let got = route(
            dav("GET", "/webdav/Reports/Q3%20plan.txt", b"", &[]),
            &state,
        )
        .await;
        assert_eq!(
            (got.status, got.body.as_slice()),
            (200, &b"hello again"[..])
        );
        let header = |name: &str| {
            got.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(header("content-type"), "application/octet-stream");
        assert!(header("content-disposition").starts_with("attachment"));

        let copy = route(
            dav(
                "COPY",
                "/webdav/Reports/Q3%20plan.txt",
                b"",
                &[("destination", "https://mail.example.test/webdav/copy.txt")],
            ),
            &state,
        )
        .await;
        assert_eq!(copy.status, 201);
        let refused = route(
            dav(
                "MOVE",
                "/webdav/copy.txt",
                b"",
                &[
                    ("destination", "/webdav/Reports/Q3%20plan.txt"),
                    ("overwrite", "F"),
                ],
            ),
            &state,
        )
        .await;
        assert_eq!(refused.status, 412);
        assert_eq!(
            route(
                dav(
                    "MOVE",
                    "/webdav/Reports",
                    b"",
                    &[("destination", "/webdav/Archive")]
                ),
                &state
            )
            .await
            .status,
            201
        );
        assert_eq!(
            route(
                dav("GET", "/webdav/Archive/Q3%20plan.txt", b"", &[]),
                &state
            )
            .await
            .status,
            200
        );
        assert_eq!(
            route(
                dav(
                    "MOVE",
                    "/webdav/Archive",
                    b"",
                    &[("destination", "/webdav/Archive/inside")]
                ),
                &state
            )
            .await
            .status,
            403
        );

        // The quota (1 MB here) stops an upload part-way.
        let big = vec![0u8; 1_100_000];
        assert_eq!(
            route(dav("PUT", "/webdav/big.bin", &big, &[]), &state)
                .await
                .status,
            507
        );
        assert_eq!(
            route(dav("GET", "/webdav/big.bin", b"", &[]), &state)
                .await
                .status,
            404,
            "nothing half-written stays"
        );

        // Locks are granted (Finder and Windows ask before writing).
        let lock = route(
            dav(
                "LOCK",
                "/webdav/new.docx",
                b"<?xml version=\"1.0\"?><D:lockinfo xmlns:D=\"DAV:\"/>",
                &[],
            ),
            &state,
        )
        .await;
        assert_eq!(lock.status, 201);
        assert!(
            lock.headers
                .iter()
                .any(|(k, v)| k == "Lock-Token" && v.starts_with("<urn:uuid:"))
        );
        assert_eq!(
            route(dav("UNLOCK", "/webdav/new.docx", b"", &[]), &state)
                .await
                .status,
            204
        );

        // No way out of the user's tree, and it is not a mail folder.
        assert_eq!(
            route(dav("GET", "/webdav/..%2F..%2Fsecret", b"", &[]), &state)
                .await
                .status,
            400
        );
        assert_eq!(
            route(dav("GET", "/webdav/a/../b", b"", &[]), &state)
                .await
                .status,
            400
        );
        let folders =
            rmail_common::imap_state::list_folders(&state.mail_root, "example.test", "user")
                .unwrap();
        assert!(!folders.iter().any(|f| f.name.contains("rmail-drive")));
        assert_eq!(
            route(dav("DELETE", "/webdav/Archive", b"", &[]), &state)
                .await
                .status,
            204
        );
        assert_eq!(
            route(dav("DELETE", "/webdav/", b"", &[]), &state)
                .await
                .status,
            403
        );

        // Wrong password: no access.
        let mut wrong = dav("PROPFIND", "/webdav/", b"", &[]);
        let bad = base64::engine::general_purpose::STANDARD.encode("user@example.test:nope");
        wrong
            .headers_mut()
            .insert("authorization", format!("Basic {bad}").parse().unwrap());
        assert_eq!(route(wrong, &state).await.status, 401);
    }
}
