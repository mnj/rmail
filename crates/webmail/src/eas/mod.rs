//! Exchange ActiveSync (MS-ASCMD, protocol 14.1) at
//! `/Microsoft-Server-ActiveSync`, so the mail apps built into phones (iOS
//! Mail, Android, Outlook) can sync without IMAP, when the admin turns it
//! on (`activesync.enabled`).
//!
//! - Mail only for now: folder list, mail sync with read and flag state,
//!   deletes and moves, whole messages and attachments on request, sending
//!   (and replies and forwards), push (Ping), estimates and settings.
//! - Devices sign in as for JMAP and CalDAV (an app password with 2FA).
//! - Provisioning answers with a policy that asks for nothing, and is not
//!   enforced: rMail does not manage devices.
//! - What each device was sent is kept per account (`state`), so changes
//!   since its sync key can be worked out.

mod commands;
mod state;
pub(crate) mod wbxml;

use std::sync::Arc;
use std::time::Duration;

use axum::Extension;
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use base64::Engine;
use rmail_common::http::Peer;

use crate::api::AppState;
use crate::jmap::{self, User};

pub(crate) const PATH: &str = "/Microsoft-Server-ActiveSync";
/// The longest a Ping may wait (MS-ASCMD allows up to 59 minutes; phones
/// ask for 8 to 30).
const MAX_HEARTBEAT: u64 = 30 * 60;
const MAX_REQUEST_BYTES: usize = 40 * 1024 * 1024;
const VERSIONS: &str = "14.0,14.1";
const COMMANDS: &str = "Sync,SendMail,SmartForward,SmartReply,GetAttachment,GetHierarchy,CreateCollection,DeleteCollection,MoveCollection,FolderSync,FolderCreate,FolderDelete,FolderUpdate,MoveItems,GetItemEstimate,MeetingResponse,Search,Settings,Ping,ItemOperations,Provision,ResolveRecipients,ValidateCert";

pub(crate) fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route(PATH, any(handle))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(MAX_HEARTBEAT + 120),
        ))
        .with_state(state)
}

fn enabled(state: &AppState) -> bool {
    rmail_common::settings::open(&state.db_path)
        .ok()
        .and_then(|conn| rmail_common::settings::activesync(&conn).ok())
        .is_some_and(|config| config.enabled)
}

fn options() -> Response {
    let mut response = StatusCode::OK.into_response();
    let headers = response.headers_mut();
    headers.insert("MS-Server-ActiveSync", HeaderValue::from_static("14.1"));
    headers.insert("MS-ASProtocolVersions", HeaderValue::from_static(VERSIONS));
    headers.insert("MS-ASProtocolCommands", HeaderValue::from_static(COMMANDS));
    headers.insert(header::ALLOW, HeaderValue::from_static("OPTIONS,POST"));
    headers.insert("Public", HeaderValue::from_static("OPTIONS,POST"));
    response
}

/// The request's parameters: `Cmd`, `DeviceId`, `DeviceType` and others,
/// from a plain query or the base64 form (MS-ASHTTP 2.2.1.1.1.1).
pub(crate) struct Params {
    pub command: String,
    pub device: String,
    pub device_type: String,
    pub extra: Vec<(String, String)>,
}

impl Params {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.extra
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn query_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |at: usize| bytes.get(at).and_then(|b| (*b as char).to_digit(16));
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if hex(i + 1).is_some() && hex(i + 2).is_some() => {
                out.push((hex(i + 1).unwrap() * 16 + hex(i + 2).unwrap()) as u8);
                i += 2;
            }
            byte => out.push(byte),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

const BASE64_COMMANDS: &[&str] = &[
    "Sync",
    "SendMail",
    "SmartForward",
    "SmartReply",
    "GetAttachment",
    "GetHierarchy",
    "CreateCollection",
    "DeleteCollection",
    "MoveCollection",
    "FolderSync",
    "FolderCreate",
    "FolderDelete",
    "FolderUpdate",
    "MoveItems",
    "GetItemEstimate",
    "MeetingResponse",
    "Search",
    "Settings",
    "Ping",
    "ItemOperations",
    "Provision",
    "ResolveRecipients",
    "ValidateCert",
];

pub(crate) fn params(query: &str) -> Option<Params> {
    if !query.contains('=') && !query.is_empty() {
        // The base64 form: version, command, locale, device id, policy
        // key, device type, then tagged parameters.
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(query_decode(query))
            .ok()?;
        let command = *bytes.get(1)?;
        let mut at = 4;
        let take = |at: &mut usize| -> Option<Vec<u8>> {
            let length = *bytes.get(*at)? as usize;
            let value = bytes.get(*at + 1..*at + 1 + length)?.to_vec();
            *at += 1 + length;
            Some(value)
        };
        let device = take(&mut at)?;
        let _policy = take(&mut at)?;
        let device_type = take(&mut at)?;
        let mut extra = Vec::new();
        const TAGS: &[(u8, &str)] = &[
            (0, "AttachmentName"),
            (1, "CollectionId"),
            (3, "ItemId"),
            (4, "LongId"),
            (6, "Occurrence"),
            (7, "Options"),
            (8, "User"),
        ];
        while at < bytes.len() {
            let tag = bytes[at];
            at += 1;
            let value = take(&mut at)?;
            if let Some((_, name)) = TAGS.iter().find(|(t, _)| *t == tag) {
                let value = if *name == "Options" {
                    match value.first() {
                        Some(flags) if flags & 0x01 != 0 => "SaveInSent".to_string(),
                        _ => String::new(),
                    }
                } else {
                    String::from_utf8_lossy(&value).into_owned()
                };
                extra.push((name.to_string(), value));
            }
        }
        return Some(Params {
            command: BASE64_COMMANDS.get(command as usize)?.to_string(),
            device: String::from_utf8_lossy(&device).into_owned(),
            device_type: String::from_utf8_lossy(&device_type).into_owned(),
            extra,
        });
    }
    let mut command = None;
    let mut device = None;
    let mut device_type = String::new();
    let mut extra = Vec::new();
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = query_decode(value);
        match key {
            "Cmd" => command = Some(value),
            "DeviceId" => device = Some(value),
            "DeviceType" => device_type = value,
            _ => extra.push((query_decode(key), value)),
        }
    }
    Some(Params {
        command: command?,
        device: device?,
        device_type,
        extra,
    })
}

fn valid_device(device: &str) -> bool {
    !device.is_empty() && device.len() <= 128 && device.bytes().all(|b| b.is_ascii_graphic())
}

pub(crate) fn wbxml_response(root: &wbxml::Element) -> Response {
    let mut response = (StatusCode::OK, wbxml::encode(root)).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.ms-sync.wbxml"),
    );
    headers.insert("MS-Server-ActiveSync", HeaderValue::from_static("14.1"));
    response
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
    if !enabled(&state) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if method == Method::OPTIONS {
        return options();
    }
    if method != Method::POST {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let user: User = match jmap::authenticate(&state, &headers, &peer).await {
        Ok(user) => user,
        Err(response) => return *response,
    };
    let Some(params) = params(uri.query().unwrap_or_default()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !valid_device(&params.device) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Ok(bytes) = axum::body::to_bytes(body, MAX_REQUEST_BYTES).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let raw_mime = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().starts_with("message/rfc822"));
    commands::run(state, user, params, bytes, raw_mime).await
}

#[cfg(test)]
mod tests;
