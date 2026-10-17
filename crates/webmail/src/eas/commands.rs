//! The ActiveSync commands rMail answers, over the account's Maildir.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use rmail_common::imap_state::{self, Folder, Message};
use rmail_common::mime;
use rusqlite::Connection;

use super::state::{self, Snapshot};
use super::wbxml::{self, Element};
use super::{Params, wbxml_response};
use crate::api::AppState;
use crate::jmap::User;

/// Changes sent per collection per Sync when the device asks for none.
const DEFAULT_WINDOW: usize = 100;
const MAX_WINDOW: usize = 512;
/// How often a waiting Ping looks for new mail.
const PING_POLL: Duration = Duration::from_secs(5);

pub(super) struct Account {
    pub(super) state: Arc<AppState>,
    pub(super) user: User,
    pub(super) device: String,
}

impl Account {
    pub(super) fn dir(&self) -> PathBuf {
        imap_state::account_maildir(
            &self.state.mail_root,
            &self.user.domain,
            &self.user.localpart,
        )
    }
    pub(super) fn db(&self) -> anyhow::Result<Connection> {
        state::open(&self.dir())
    }
    pub(super) fn root(&self) -> &std::path::Path {
        &self.state.mail_root
    }
    pub(super) fn folders(&self) -> anyhow::Result<Vec<Folder>> {
        imap_state::list_folders(self.root(), &self.user.domain, &self.user.localpart)
    }
    pub(super) fn messages(&self, folder: &str) -> anyhow::Result<(Folder, Vec<Message>)> {
        imap_state::load_folder(self.root(), &self.user.domain, &self.user.localpart, folder)
    }
}

pub(super) async fn run(
    state: Arc<AppState>,
    user: User,
    params: Params,
    body: Bytes,
    raw_mime: bool,
) -> Response {
    let account = Account {
        state,
        user,
        device: params.device.clone(),
    };
    if let Err(error) = account
        .db()
        .and_then(|db| state::touch_device(&db, &account.device, &params.device_type))
    {
        return crate::jmap::internal_response(format!("{error:#}"));
    }
    if params.command == "Ping" {
        return ping(account, body).await;
    }
    let outcome = tokio::task::spawn_blocking(move || -> anyhow::Result<Response> {
        let request = if raw_mime || body.is_empty() {
            None
        } else {
            Some(wbxml::decode(&body)?)
        };
        Ok(match params.command.as_str() {
            "FolderSync" => wbxml_response(&folder_sync(&account, request.as_ref())?),
            "Sync" => sync(&account, request, &body)?,
            "GetItemEstimate" => wbxml_response(&estimate(&account, request.as_ref())?),
            "ItemOperations" => wbxml_response(&item_operations(&account, request.as_ref())?),
            "MoveItems" => wbxml_response(&move_items(&account, request.as_ref())?),
            "MeetingResponse" => wbxml_response(&super::pim::meeting_response(
                &account,
                &account.db()?,
                request.as_ref(),
            )?),
            "SendMail" | "SmartReply" | "SmartForward" => {
                send(&account, &params, request.as_ref(), &body, raw_mime)?
            }
            "Provision" => wbxml_response(&provision(&account, request.as_ref())?),
            "Settings" => wbxml_response(&settings(&account, request.as_ref())?),
            "FolderCreate" | "FolderDelete" | "FolderUpdate" => {
                wbxml_response(&folder_change(&account, &params.command, request.as_ref())?)
            }
            _ => StatusCode::NOT_IMPLEMENTED.into_response(),
        })
    })
    .await;
    match outcome {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            webmail_log!("warn", "activesync_failed", { "error": format!("{error:#}") });
            StatusCode::BAD_REQUEST.into_response()
        }
        Err(error) => crate::jmap::internal_response(error),
    }
}

// ---------------------------------------------------------------------------
// Folders

/// The ActiveSync folder type (MS-ASCMD 2.2.3.186.3).
fn folder_type(folder: &Folder) -> u8 {
    if folder.name.eq_ignore_ascii_case("INBOX") {
        return 2;
    }
    match folder.special_use.as_deref() {
        Some("\\Drafts") => 3,
        Some("\\Trash") => 4,
        Some("\\Sent") => 5,
        _ => 12,
    }
}

/// The folders as a device sees them: id -> (parent id, name, type).
fn folder_list(account: &Account, db: &Connection) -> anyhow::Result<state::FolderList> {
    let folders = account.folders()?;
    let mut out = BTreeMap::new();
    // The notes folder is the device's Notes, not mail.
    for folder in folders
        .iter()
        .filter(|f| !crate::notes::is_notes_folder(&f.name))
    {
        let id = state::folder_id(db, &folder.name)?;
        let (parent, name) = match folder.name.rsplit_once('/') {
            Some((parent, name)) if folders.iter().any(|f| f.name == parent) => {
                (state::folder_id(db, parent)?, name.to_string())
            }
            _ => (
                "0".to_string(),
                if folder.name.eq_ignore_ascii_case("INBOX") {
                    "Inbox".to_string()
                } else {
                    folder.name.clone()
                },
            ),
        };
        out.insert(id, (parent, name, folder_type(folder)));
    }
    out.extend(super::pim::folders(account)?);
    out.insert(
        super::notes::ID.to_string(),
        ("0".to_string(), "Notes".to_string(), 10),
    );
    Ok(out)
}

fn folder_sync(account: &Account, request: Option<&Element>) -> anyhow::Result<Element> {
    let db = account.db()?;
    let key = request
        .and_then(|r| r.value("FolderHierarchy:SyncKey"))
        .unwrap_or_default();
    let (current_key, known) = state::folders(&db, &account.device)?;
    let mut response = Element::new("FolderHierarchy:FolderSync");
    let known = if key == "0" {
        BTreeMap::new()
    } else if key == current_key.to_string() {
        known
    } else {
        return Ok(response.with(Element::text("FolderHierarchy:Status", "9")));
    };
    let now = folder_list(account, &db)?;
    let mut changes = Element::new("FolderHierarchy:Changes");
    let mut count = 0;
    for (id, (parent, name, kind)) in &now {
        let tag = match known.get(id) {
            None => "FolderHierarchy:Add",
            Some(old) if old != &(parent.clone(), name.clone(), *kind) => "FolderHierarchy:Update",
            Some(_) => continue,
        };
        count += 1;
        changes.push(
            Element::new(tag)
                .with(Element::text("FolderHierarchy:ServerId", id.clone()))
                .with(Element::text("FolderHierarchy:ParentId", parent.clone()))
                .with(Element::text("FolderHierarchy:DisplayName", name.clone()))
                .with(Element::text("FolderHierarchy:Type", kind.to_string())),
        );
    }
    for id in known.keys().filter(|id| !now.contains_key(*id)) {
        count += 1;
        changes.push(
            Element::new("FolderHierarchy:Delete")
                .with(Element::text("FolderHierarchy:ServerId", id.clone())),
        );
        state::forget_collection(&db, &account.device, id)?;
    }
    changes
        .children
        .insert(0, Element::text("FolderHierarchy:Count", count.to_string()));
    let new_key = current_key + 1;
    state::set_folders(&db, &account.device, new_key, &now)?;
    response.push(Element::text("FolderHierarchy:Status", "1"));
    response.push(Element::text(
        "FolderHierarchy:SyncKey",
        new_key.to_string(),
    ));
    response.push(changes);
    Ok(response)
}

fn folder_change(
    account: &Account,
    command: &str,
    request: Option<&Element>,
) -> anyhow::Result<Element> {
    let request = request.ok_or_else(|| anyhow::anyhow!("no request"))?;
    let db = account.db()?;
    let (domain, local) = (&account.user.domain, &account.user.localpart);
    let root = &account.state.mail_root;
    let tag = format!("FolderHierarchy:{command}");
    let mut response = Element::new(&tag);
    let status = |code: &str| Element::text("FolderHierarchy:Status", code);
    let parent_name = |id: &str| -> anyhow::Result<Option<String>> {
        if id == "0" {
            Ok(None)
        } else {
            state::folder_name(&db, id)
        }
    };
    // The same rules as webmail: valid names, nothing under Other Users,
    // and INBOX and special folders are not renamed or deleted.
    let new_name = |parent: Option<String>, name: String| -> Option<String> {
        let full = match parent {
            Some(parent) => format!("{parent}/{name}"),
            None => name,
        };
        crate::api::valid_new_folder(&full)
    };
    let user_folder = |id: &str| -> anyhow::Result<Option<String>> {
        let Some(name) = state::folder_name(&db, id)? else {
            return Ok(None);
        };
        Ok(account
            .folders()?
            .into_iter()
            .find(|f| f.name == name)
            .filter(rmail_common::classifier_store::is_user_folder)
            .map(|f| f.name))
    };
    let parent = request
        .value("FolderHierarchy:ParentId")
        .unwrap_or_else(|| "0".into());
    let result: anyhow::Result<Result<Option<String>, &str>> = match command {
        "FolderCreate" => {
            let name = request
                .value("FolderHierarchy:DisplayName")
                .unwrap_or_default();
            match new_name(parent_name(&parent)?, name) {
                Some(full) => imap_state::create_folder(root, domain, local, &full)
                    .map(|_| Ok(Some(state::folder_id(&db, &full).unwrap_or_default()))),
                None => Ok(Err("10")),
            }
        }
        "FolderDelete" => {
            let id = request
                .value("FolderHierarchy:ServerId")
                .unwrap_or_default();
            match user_folder(&id)? {
                Some(name) => {
                    imap_state::delete_folder(root, domain, local, &name).map(|_| Ok(None))
                }
                None => Ok(Err("3")),
            }
        }
        _ => {
            let id = request
                .value("FolderHierarchy:ServerId")
                .unwrap_or_default();
            let name = request
                .value("FolderHierarchy:DisplayName")
                .unwrap_or_default();
            match (user_folder(&id)?, new_name(parent_name(&parent)?, name)) {
                (Some(old), Some(full)) => {
                    imap_state::rename_folder(root, domain, local, &old, &full)
                        .and_then(|_| state::rename_folder(&db, &old, &full))
                        .map(|_| Ok(None))
                }
                (None, _) => Ok(Err("3")),
                (_, None) => Ok(Err("10")),
            }
        }
    };
    let result = match result {
        Ok(Err(code)) => return Ok(response.with(status(code))),
        Ok(Ok(id)) => Ok(id),
        Err(error) => Err(error),
    };
    match result {
        Ok(id) => {
            // The device's folder list moves on with its own change.
            let (key, _) = state::folders(&db, &account.device)?;
            let now = folder_list(account, &db)?;
            state::set_folders(&db, &account.device, key + 1, &now)?;
            response.push(status("1"));
            response.push(Element::text(
                "FolderHierarchy:SyncKey",
                (key + 1).to_string(),
            ));
            if let Some(id) = id {
                response.push(Element::text("FolderHierarchy:ServerId", id));
            }
        }
        Err(_) => response.push(status("6")),
    }
    Ok(response)
}

// ---------------------------------------------------------------------------
// Mail

fn flags_code(flags: &[String]) -> String {
    let has = |flag: &str| flags.iter().any(|f| f.eq_ignore_ascii_case(flag));
    format!(
        "{}{}",
        if has("\\Seen") { "S" } else { "" },
        if has("\\Flagged") { "F" } else { "" }
    )
}

/// Seconds back a FilterType reaches (0: everything).
fn filter_seconds(filter: i64) -> i64 {
    match filter {
        1 => 86_400,
        2 => 3 * 86_400,
        3 => 7 * 86_400,
        4 => 14 * 86_400,
        5 => 31 * 86_400,
        6 => 92 * 86_400,
        7 => 183 * 86_400,
        _ => 0,
    }
}

/// The folder as the device should have it: UID -> flags, within the filter.
fn current(messages: &[Message], filter: i64) -> Snapshot {
    let since = match filter_seconds(filter) {
        0 => i64::MIN,
        seconds => chrono::Utc::now().timestamp() - seconds,
    };
    messages
        .iter()
        .filter(|m| {
            m.internaldate >= since && !m.flags.iter().any(|f| f.eq_ignore_ascii_case("\\Deleted"))
        })
        .map(|m| (m.uid, flags_code(&m.flags)))
        .collect()
}

fn date(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%S.000Z")
        .to_string()
}

/// How the device wants bodies: (type, truncation), from its options.
#[derive(Clone, Copy)]
struct BodyPreference {
    kind: u8,
    truncation: Option<usize>,
}

fn body_preference(options: Option<&Element>) -> BodyPreference {
    let preferences: Vec<BodyPreference> = options
        .map(|o| {
            o.children_named("AirSyncBase:BodyPreference")
                .map(|p| BodyPreference {
                    kind: p
                        .value("AirSyncBase:Type")
                        .and_then(|t| t.parse().ok())
                        .unwrap_or(1),
                    truncation: p
                        .value("AirSyncBase:TruncationSize")
                        .and_then(|t| t.parse().ok()),
                })
                .collect()
        })
        .unwrap_or_default();
    let mime = options
        .and_then(|o| o.value("AirSync:MIMESupport"))
        .is_some_and(|v| v == "2" || v == "1");
    preferences
        .iter()
        .copied()
        .find(|p| p.kind == 4 && mime)
        .or_else(|| preferences.iter().copied().find(|p| p.kind == 2))
        .or_else(|| preferences.first().copied())
        .unwrap_or(BodyPreference {
            kind: 1,
            truncation: None,
        })
}

fn truncated(text: String, limit: Option<usize>) -> (String, bool) {
    match limit {
        Some(limit) if text.len() > limit => {
            let mut end = limit;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            (text[..end].to_string(), true)
        }
        _ => (text, false),
    }
}

/// The ApplicationData (or ItemOperations Properties) of a message.
fn email_data(
    tag: &str,
    collection: &str,
    message: &Message,
    preference: BodyPreference,
) -> anyhow::Result<Element> {
    let raw = std::fs::read(&message.path)?;
    let parsed = mime::parse_message(&raw);
    let has = |flag: &str| message.flags.iter().any(|f| f.eq_ignore_ascii_case(flag));
    let mut data = Element::new(tag)
        .with(Element::text("Email:To", parsed.to.clone()))
        .with(Element::text("Email:Cc", parsed.cc.clone()))
        .with(Element::text("Email:From", parsed.from.clone()))
        .with(Element::text("Email:Subject", parsed.subject.clone()))
        .with(Element::text("Email:ReplyTo", parsed.reply_to.clone()))
        .with(Element::text(
            "Email:DateReceived",
            date(message.internaldate),
        ))
        .with(Element::text("Email:DisplayTo", parsed.to.clone()))
        .with(Element::text("Email:ThreadTopic", parsed.subject.clone()))
        .with(Element::text("Email:Importance", "1"))
        .with(Element::text(
            "Email:Read",
            if has("\\Seen") { "1" } else { "0" },
        ));
    let native = if parsed.html_body.is_some() { 2 } else { 1 };
    let (kind, content) = match preference.kind {
        4 => (4, String::from_utf8_lossy(&raw).into_owned()),
        2 if parsed.html_body.is_some() => (2, parsed.html_body.clone().unwrap_or_default()),
        _ => (1, parsed.text_body.replace('\n', "\r\n")),
    };
    let size = content.len();
    let (content, cut) = truncated(content, preference.truncation);
    data.push(
        Element::new("AirSyncBase:Body")
            .with(Element::text("AirSyncBase:Type", kind.to_string()))
            .with(Element::text(
                "AirSyncBase:EstimatedDataSize",
                size.to_string(),
            ))
            .with(Element::text(
                "AirSyncBase:Truncated",
                if cut { "1" } else { "0" },
            ))
            .with(Element::text("AirSyncBase:Data", content)),
    );
    // Invitations show as meeting requests, answered with MeetingResponse.
    match super::pim::meeting(&raw) {
        Some((class, request)) => {
            data.push(Element::text("Email:MessageClass", class));
            if let Some(request) = request {
                data.push(request);
            }
        }
        None => data.push(Element::text("Email:MessageClass", "IPM.Note")),
    }
    data.push(Element::text("Email:InternetCPID", "65001"));
    let mut flag = Element::new("Email:Flag");
    if has("\\Flagged") {
        flag.push(Element::text("Email:FlagStatus", "2"));
        flag.push(Element::text("Email:FlagType", "Flag for follow up"));
    }
    data.push(flag);
    data.push(Element::text(
        "Email:ContentClass",
        "urn:content-classes:message",
    ));
    data.push(Element::text(
        "AirSyncBase:NativeBodyType",
        native.to_string(),
    ));
    let attachments: Vec<&mime::Attachment> = parsed.attachments.iter().collect();
    if !attachments.is_empty() {
        let mut list = Element::new("AirSyncBase:Attachments");
        for attachment in attachments {
            list.push(
                Element::new("AirSyncBase:Attachment")
                    .with(Element::text(
                        "AirSyncBase:DisplayName",
                        attachment.filename.clone(),
                    ))
                    .with(Element::text(
                        "AirSyncBase:FileReference",
                        format!("{collection}:{}:{}", message.uid, attachment.index),
                    ))
                    .with(Element::text("AirSyncBase:Method", "1"))
                    .with(Element::text(
                        "AirSyncBase:EstimatedDataSize",
                        attachment.size.to_string(),
                    ))
                    .with(Element::text(
                        "AirSyncBase:IsInline",
                        if attachment.inline { "1" } else { "0" },
                    )),
            );
        }
        data.push(list);
    }
    Ok(data)
}

/// Apply a device's change to a message: read and flagged state.
fn apply_change(
    account: &Account,
    folder: &str,
    message: &Message,
    data: &Element,
) -> anyhow::Result<Vec<String>> {
    let mut flags: BTreeSet<String> = message.flags.iter().cloned().collect();
    let mut set = |flag: &str, on: bool| {
        flags.retain(|f| !f.eq_ignore_ascii_case(flag));
        if on {
            flags.insert(flag.to_string());
        }
    };
    if let Some(read) = data.value("Email:Read") {
        set("\\Seen", read == "1");
    }
    if let Some(flag) = data.child("Email:Flag") {
        set(
            "\\Flagged",
            flag.value("Email:FlagStatus").as_deref() == Some("2"),
        );
    }
    let flags: Vec<String> = flags.into_iter().collect();
    imap_state::set_uid_flags(
        account.root(),
        &account.user.domain,
        &account.user.localpart,
        folder,
        message.uid,
        flags.clone(),
    )?;
    Ok(flags)
}

fn server_id(collection: &str, uid: u64) -> String {
    format!("{collection}:{uid}")
}

fn parse_server_id(id: &str) -> Option<(String, u64)> {
    let (collection, uid) = id.split_once(':')?;
    Some((collection.to_string(), uid.parse().ok()?))
}

fn sync(account: &Account, request: Option<Element>, body: &[u8]) -> anyhow::Result<Response> {
    let db = account.db()?;
    // An empty Sync repeats the last full one (MS-ASCMD 2.2.1.21).
    let request = match request {
        Some(request) => {
            state::set_last_sync(&db, &account.device, body)?;
            request
        }
        None => match state::last_sync(&db, &account.device)? {
            // The same collections and options, at the current keys and
            // without the old commands (MS-ASCMD 2.2.3.166.2).
            Some(previous) => {
                let mut request = wbxml::decode(&previous)?;
                if let Some(collections) = request
                    .children
                    .iter_mut()
                    .find(|c| c.is("AirSync:Collections"))
                {
                    for collection in collections
                        .children
                        .iter_mut()
                        .filter(|c| c.is("AirSync:Collection"))
                    {
                        collection.children.retain(|c| !c.is("AirSync:Commands"));
                        let id = collection.value("AirSync:CollectionId").unwrap_or_default();
                        if let Some(known) = state::sync_state(&db, &account.device, &id)?
                            && let Some(key) = collection
                                .children
                                .iter_mut()
                                .find(|c| c.is("AirSync:SyncKey"))
                        {
                            key.text = Some(known.key.to_string());
                        }
                    }
                }
                request
            }
            None => {
                return Ok(wbxml_response(
                    &Element::new("AirSync:Sync").with(Element::text("AirSync:Status", "13")),
                ));
            }
        },
    };
    let window = request
        .value("AirSync:WindowSize")
        .and_then(|w| w.parse::<usize>().ok());
    let mut collections = Element::new("AirSync:Collections");
    let mut any = false;
    for collection in request
        .child("AirSync:Collections")
        .map(|c| c.children_named("AirSync:Collection").collect::<Vec<_>>())
        .unwrap_or_default()
    {
        any = true;
        let id = collection.value("AirSync:CollectionId").unwrap_or_default();
        collections.push(if super::notes::is_notes(&id) {
            super::notes::sync_collection(account, &db, collection, window)?
        } else if super::pim::is_pim(&id) {
            super::pim::sync_collection(account, &db, collection, window)?
        } else {
            sync_collection(account, &db, collection, window)?
        });
    }
    if !any {
        return Ok(wbxml_response(
            &Element::new("AirSync:Sync").with(Element::text("AirSync:Status", "4")),
        ));
    }
    Ok(wbxml_response(
        &Element::new("AirSync:Sync").with(collections),
    ))
}

fn sync_collection(
    account: &Account,
    db: &Connection,
    request: &Element,
    window: Option<usize>,
) -> anyhow::Result<Element> {
    let collection = request.value("AirSync:CollectionId").unwrap_or_default();
    let key: i64 = request
        .value("AirSync:SyncKey")
        .and_then(|k| k.parse().ok())
        .unwrap_or(-1);
    let mut response = Element::new("AirSync:Collection");
    let status = |code: &str| Element::text("AirSync:Status", code);
    let Some(folder) = state::folder_name(db, &collection)? else {
        return Ok(response
            .with(Element::text("AirSync:CollectionId", collection))
            .with(status("8")));
    };
    let options = request.child("AirSync:Options");
    let filter: i64 = options
        .and_then(|o| o.value("AirSync:FilterType"))
        .and_then(|f| f.parse().ok())
        .unwrap_or(0);
    let preference = body_preference(options);
    let known = state::sync_state(db, &account.device, &collection)?;
    // The first sync only hands out a key (MS-ASCMD 2.2.3.166.4).
    if key == 0 {
        state::save_sync(
            db,
            &account.device,
            &collection,
            1,
            &Snapshot::new(),
            None,
            filter,
        )?;
        return Ok(response
            .with(Element::text("AirSync:SyncKey", "1"))
            .with(Element::text("AirSync:CollectionId", collection))
            .with(status("1")));
    }
    let Some(known) = known else {
        return Ok(response
            .with(Element::text("AirSync:SyncKey", "0"))
            .with(Element::text("AirSync:CollectionId", collection))
            .with(status("3")));
    };
    let mut base = if key == known.key {
        known.snapshot.clone()
    } else if key == known.prev_key {
        known.prev_snapshot.clone()
    } else {
        return Ok(response
            .with(Element::text("AirSync:SyncKey", "0"))
            .with(Element::text("AirSync:CollectionId", collection))
            .with(status("3")));
    };
    let (_, messages) = account.messages(&folder)?;
    let by_uid: BTreeMap<u64, &Message> = messages.iter().map(|m| (m.uid, m)).collect();
    let mut responses = Element::new("AirSync:Responses");
    // The device's own changes first; they are not echoed back.
    let deletes_as_moves = request
        .value("AirSync:DeletesAsMoves")
        .is_none_or(|v| v != "0");
    // Whether the device changed anything, so the folder is read again.
    let mut touched = false;
    if let Some(commands) = request.child("AirSync:Commands") {
        for command in &commands.children {
            let id = command.value("AirSync:ServerId").unwrap_or_default();
            let target = parse_server_id(&id)
                .filter(|(c, _)| *c == collection)
                .and_then(|(_, uid)| by_uid.get(&uid).copied());
            match command.name {
                "Change" => match (target, command.child("AirSync:ApplicationData")) {
                    (Some(message), Some(data)) => {
                        let flags = apply_change(account, &folder, message, data)?;
                        base.insert(message.uid, flags_code(&flags));
                        touched = true;
                    }
                    _ => responses.push(
                        Element::new("AirSync:Change")
                            .with(Element::text("AirSync:ServerId", id))
                            .with(status("8")),
                    ),
                },
                "Delete" => {
                    if let Some(message) = target {
                        let (root, domain, local) = (
                            account.root(),
                            &account.user.domain,
                            &account.user.localpart,
                        );
                        if deletes_as_moves {
                            imap_state::delete_or_trash_message_by_uid(
                                root,
                                domain,
                                local,
                                &folder,
                                message.uid,
                            )?;
                        } else {
                            imap_state::delete_message_by_uid(
                                root,
                                domain,
                                local,
                                &folder,
                                message.uid,
                            )?;
                        }
                        base.remove(&message.uid);
                        touched = true;
                    }
                }
                "Fetch" => match target {
                    Some(message) => responses.push(
                        Element::new("AirSync:Fetch")
                            .with(Element::text("AirSync:ServerId", id))
                            .with(status("1"))
                            .with(email_data(
                                "AirSync:ApplicationData",
                                &collection,
                                message,
                                preference,
                            )?),
                    ),
                    None => responses.push(
                        Element::new("AirSync:Fetch")
                            .with(Element::text("AirSync:ServerId", id))
                            .with(status("8")),
                    ),
                },
                // New mail from a device goes through SendMail; drafts are not synced back.
                "Add" => responses.push(
                    Element::new("AirSync:Add")
                        .with(Element::text(
                            "AirSync:ClientId",
                            command.value("AirSync:ClientId").unwrap_or_default(),
                        ))
                        .with(status("6")),
                ),
                _ => {}
            }
        }
    }
    let messages = if touched {
        account.messages(&folder)?.1
    } else {
        messages
    };
    let now = current(&messages, filter);
    let by_uid: BTreeMap<u64, &Message> = messages.iter().map(|m| (m.uid, m)).collect();
    let get_changes = request.value("AirSync:GetChanges").is_none_or(|v| v != "0");
    let limit = request
        .value("AirSync:WindowSize")
        .and_then(|w| w.parse::<usize>().ok())
        .or(window)
        .unwrap_or(DEFAULT_WINDOW)
        .clamp(1, MAX_WINDOW);
    let mut commands = Element::new("AirSync:Commands");
    let mut sent = 0;
    let mut more = false;
    let mut next = base.clone();
    if get_changes {
        // Deletions and flag changes first, then new mail, newest first.
        for uid in base
            .keys()
            .filter(|uid| !now.contains_key(uid))
            .copied()
            .collect::<Vec<_>>()
        {
            if sent >= limit {
                more = true;
                break;
            }
            commands.push(Element::new("AirSync:Delete").with(Element::text(
                "AirSync:ServerId",
                server_id(&collection, uid),
            )));
            next.remove(&uid);
            sent += 1;
        }
        for (uid, flags) in now
            .iter()
            .filter(|(uid, flags)| base.get(uid).is_some_and(|known| known != *flags))
        {
            if sent >= limit {
                more = true;
                break;
            }
            let has = |code: char| flags.contains(code);
            let mut flag = Element::new("Email:Flag");
            if has('F') {
                flag.push(Element::text("Email:FlagStatus", "2"));
                flag.push(Element::text("Email:FlagType", "Flag for follow up"));
            }
            commands.push(
                Element::new("AirSync:Change")
                    .with(Element::text(
                        "AirSync:ServerId",
                        server_id(&collection, *uid),
                    ))
                    .with(
                        Element::new("AirSync:ApplicationData")
                            .with(Element::text(
                                "Email:Read",
                                if has('S') { "1" } else { "0" },
                            ))
                            .with(flag),
                    ),
            );
            next.insert(*uid, flags.clone());
            sent += 1;
        }
        for (uid, flags) in now.iter().rev().filter(|(uid, _)| !base.contains_key(uid)) {
            if sent >= limit {
                more = true;
                break;
            }
            let Some(message) = by_uid.get(uid) else {
                continue;
            };
            commands.push(
                Element::new("AirSync:Add")
                    .with(Element::text(
                        "AirSync:ServerId",
                        server_id(&collection, *uid),
                    ))
                    .with(email_data(
                        "AirSync:ApplicationData",
                        &collection,
                        message,
                        preference,
                    )?),
            );
            next.insert(*uid, flags.clone());
            sent += 1;
        }
    }
    // A device repeating its previous key (it lost our answer) gets the
    // answer again under the key it was then given.
    let new_key = if key == known.key {
        known.key + 1
    } else {
        known.key
    };
    state::save_sync(
        db,
        &account.device,
        &collection,
        new_key,
        &next,
        Some((key, &base)),
        filter,
    )?;
    response.push(Element::text("AirSync:SyncKey", new_key.to_string()));
    response.push(Element::text("AirSync:CollectionId", collection));
    response.push(status("1"));
    if more {
        response.push(Element::new("AirSync:MoreAvailable"));
    }
    if !commands.children.is_empty() {
        response.push(commands);
    }
    if !responses.children.is_empty() {
        response.push(responses);
    }
    Ok(response)
}

/// Changes waiting for a device in a collection.
fn pending(account: &Account, db: &Connection, collection: &str) -> anyhow::Result<usize> {
    if super::notes::is_notes(collection) {
        return super::notes::pending(account, db);
    }
    if super::pim::is_pim(collection) {
        return super::pim::pending(account, db, collection);
    }
    let Some(folder) = state::folder_name(db, collection)? else {
        return Ok(0);
    };
    let Some(known) = state::sync_state(db, &account.device, collection)? else {
        return Ok(1);
    };
    let now = current(&account.messages(&folder)?.1, known.filter);
    let changed = now
        .iter()
        .filter(|(uid, flags)| known.snapshot.get(uid) != Some(flags))
        .count();
    let gone = known
        .snapshot
        .keys()
        .filter(|uid| !now.contains_key(uid))
        .count();
    Ok(changed + gone)
}

fn estimate(account: &Account, request: Option<&Element>) -> anyhow::Result<Element> {
    let db = account.db()?;
    let mut response = Element::new("GetItemEstimate:GetItemEstimate");
    let collections = request
        .and_then(|r| r.child("GetItemEstimate:Collections"))
        .map(|c| {
            c.children_named("GetItemEstimate:Collection")
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for collection in collections {
        let id = collection
            .value("GetItemEstimate:CollectionId")
            .unwrap_or_default();
        let known = super::notes::is_notes(&id)
            || super::pim::is_pim(&id)
            || state::folder_name(&db, &id)?.is_some();
        let (status, count) = if known {
            ("1", pending(account, &db, &id)?)
        } else {
            ("2", 0)
        };
        response.push(
            Element::new("GetItemEstimate:Response")
                .with(Element::text("GetItemEstimate:Status", status))
                .with(
                    Element::new("GetItemEstimate:Collection")
                        .with(Element::text("GetItemEstimate:CollectionId", id))
                        .with(Element::text("GetItemEstimate:Estimate", count.to_string())),
                ),
        );
    }
    Ok(response)
}

async fn ping(account: Account, body: Bytes) -> Response {
    let setup = {
        let account = Account {
            state: account.state.clone(),
            user: account.user.clone(),
            device: account.device.clone(),
        };
        tokio::task::spawn_blocking(
            move || -> anyhow::Result<Result<(Vec<String>, u64), &'static str>> {
                let db = account.db()?;
                let (mut folders, mut interval) = state::ping(&db, &account.device)?;
                if !body.is_empty() {
                    let request = wbxml::decode(&body)?;
                    if let Some(seconds) = request
                        .value("Ping:HeartbeatInterval")
                        .and_then(|h| h.parse::<u64>().ok())
                    {
                        interval = seconds;
                    }
                    if let Some(list) = request.child("Ping:Folders") {
                        folders = list
                            .children_named("Ping:Folder")
                            .filter_map(|f| f.value("Ping:Id"))
                            .collect();
                    }
                    state::set_ping(&db, &account.device, &folders, interval)?;
                }
                if folders.is_empty() || interval == 0 {
                    return Ok(Err("3"));
                }
                if !(60..=super::MAX_HEARTBEAT).contains(&interval) {
                    return Ok(Err("5"));
                }
                Ok(Ok((folders, interval)))
            },
        )
        .await
    };
    let status = |code: &str| {
        wbxml_response(&Element::new("Ping:Ping").with(Element::text("Ping:Status", code)))
    };
    let (folders, interval) = match setup {
        Ok(Ok(Ok(setup))) => setup,
        Ok(Ok(Err("5"))) => {
            return wbxml_response(
                &Element::new("Ping:Ping")
                    .with(Element::text("Ping:Status", "5"))
                    .with(Element::text(
                        "Ping:HeartbeatInterval",
                        super::MAX_HEARTBEAT.min(1740).to_string(),
                    )),
            );
        }
        Ok(Ok(Err(code))) => return status(code),
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    let deadline = Instant::now() + Duration::from_secs(interval);
    let account = Arc::new(account);
    loop {
        let changed = {
            let (account, folders) = (account.clone(), folders.clone());
            tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<String>> {
                let db = account.db()?;
                let mut out = Vec::new();
                for folder in &folders {
                    if pending(&account, &db, folder)? > 0 {
                        out.push(folder.clone());
                    }
                }
                Ok(out)
            })
            .await
        };
        match changed {
            Ok(Ok(changed)) if !changed.is_empty() => {
                let mut list = Element::new("Ping:Folders");
                for id in changed {
                    list.push(Element::text("Ping:Folder", id));
                }
                return wbxml_response(
                    &Element::new("Ping:Ping")
                        .with(Element::text("Ping:Status", "2"))
                        .with(list),
                );
            }
            Ok(Ok(_)) => {}
            _ => return status("7"),
        }
        if Instant::now() + PING_POLL >= deadline {
            return status("1");
        }
        // A server going down answers "nothing new" rather than holding on.
        let mut shutdown = account.state.shutdown.clone();
        let stopping = async {
            match shutdown.as_mut() {
                Some(receiver) => {
                    let _ = receiver.wait_for(|stop| *stop).await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(PING_POLL) => {}
            _ = stopping => return status("1"),
        }
    }
}

fn item_operations(account: &Account, request: Option<&Element>) -> anyhow::Result<Element> {
    let db = account.db()?;
    let mut responses = Element::new("ItemOperations:Response");
    let request = request.ok_or_else(|| anyhow::anyhow!("no request"))?;
    for operation in &request.children {
        match operation.name {
            "Fetch" => responses.push(fetch(account, &db, operation)?),
            "EmptyFolderContents" => {
                let id = operation.value("AirSync:CollectionId").unwrap_or_default();
                let mut result = Element::new("ItemOperations:EmptyFolderContents");
                match state::folder_name(&db, &id)? {
                    Some(folder) => {
                        let (_, messages) = account.messages(&folder)?;
                        let uids: Vec<u64> = messages.iter().map(|m| m.uid).collect();
                        imap_state::delete_messages_by_uid(
                            account.root(),
                            &account.user.domain,
                            &account.user.localpart,
                            &folder,
                            &uids,
                        )?;
                        result.push(Element::text("ItemOperations:Status", "1"));
                    }
                    None => result.push(Element::text("ItemOperations:Status", "6")),
                }
                result.push(Element::text("AirSync:CollectionId", id));
                responses.push(result);
            }
            _ => {}
        }
    }
    Ok(Element::new("ItemOperations:ItemOperations")
        .with(Element::text("ItemOperations:Status", "1"))
        .with(responses))
}

fn fetch(account: &Account, db: &Connection, operation: &Element) -> anyhow::Result<Element> {
    let mut out = Element::new("ItemOperations:Fetch");
    if let Some(reference) = operation.value("AirSyncBase:FileReference") {
        let mut parts = reference.splitn(3, ':');
        let found = (|| -> anyhow::Result<Option<(String, Vec<u8>)>> {
            let (Some(collection), Some(uid), Some(index)) =
                (parts.next(), parts.next(), parts.next())
            else {
                return Ok(None);
            };
            let (Some(folder), Ok(uid), Ok(index)) = (
                state::folder_name(db, collection)?,
                uid.parse::<u64>(),
                index.parse::<usize>(),
            ) else {
                return Ok(None);
            };
            let (_, messages) = account.messages(&folder)?;
            let Some(message) = messages.iter().find(|m| m.uid == uid) else {
                return Ok(None);
            };
            Ok(mime::attachment_data(&std::fs::read(&message.path)?, index)
                .map(|(meta, data)| (meta.content_type, data)))
        })()?;
        out.push(Element::text(
            "ItemOperations:Status",
            if found.is_some() { "1" } else { "6" },
        ));
        out.push(Element::text("AirSyncBase:FileReference", reference));
        if let Some((content_type, data)) = found {
            out.push(
                Element::new("ItemOperations:Properties")
                    .with(Element::text("AirSyncBase:ContentType", content_type))
                    .with(Element::text(
                        "ItemOperations:Data",
                        base64::engine::general_purpose::STANDARD.encode(data),
                    )),
            );
        }
        return Ok(out);
    }
    let collection = operation.value("AirSync:CollectionId").unwrap_or_default();
    let id = operation.value("AirSync:ServerId").unwrap_or_default();
    let preference = body_preference(operation.child("ItemOperations:Options"));
    let message = match (state::folder_name(db, &collection)?, parse_server_id(&id)) {
        (Some(folder), Some((_, uid))) => account
            .messages(&folder)?
            .1
            .into_iter()
            .find(|m| m.uid == uid),
        _ => None,
    };
    out.push(Element::text(
        "ItemOperations:Status",
        if message.is_some() { "1" } else { "6" },
    ));
    out.push(Element::text("AirSync:CollectionId", collection.clone()));
    out.push(Element::text("AirSync:ServerId", id));
    out.push(Element::text("AirSync:Class", "Email"));
    if let Some(message) = message {
        out.push(email_data(
            "ItemOperations:Properties",
            &collection,
            &message,
            preference,
        )?);
    }
    Ok(out)
}

fn move_items(account: &Account, request: Option<&Element>) -> anyhow::Result<Element> {
    let db = account.db()?;
    let mut response = Element::new("Move:MoveItems");
    for movement in request
        .map(|r| r.children_named("Move:Move").collect::<Vec<_>>())
        .unwrap_or_default()
    {
        let source = movement.value("Move:SrcMsgId").unwrap_or_default();
        let from = movement.value("Move:SrcFldId").unwrap_or_default();
        let to = movement.value("Move:DstFldId").unwrap_or_default();
        let mut result =
            Element::new("Move:Response").with(Element::text("Move:SrcMsgId", source.clone()));
        let moved = match (
            state::folder_name(&db, &from)?,
            state::folder_name(&db, &to)?,
            parse_server_id(&source),
        ) {
            (Some(from_folder), Some(to_folder), Some((_, uid))) if from != to => {
                imap_state::move_message_by_uid(
                    account.root(),
                    &account.user.domain,
                    &account.user.localpart,
                    &from_folder,
                    uid,
                    &to_folder,
                )?
                .map(|new_uid| (to.clone(), new_uid))
            }
            _ => None,
        };
        match moved {
            Some((to, uid)) => {
                result.push(Element::text("Move:Status", "3"));
                result.push(Element::text("Move:DstMsgId", server_id(&to, uid)));
            }
            None => result.push(Element::text("Move:Status", "1")),
        }
        response.push(result);
    }
    Ok(response)
}

// ---------------------------------------------------------------------------
// Sending

/// The recipients of a message from its To, Cc and Bcc headers.
fn recipients(raw: &[u8]) -> Vec<String> {
    let parsed = mime::parse_message(raw);
    let mut out: Vec<String> = Vec::new();
    for value in [&parsed.to, &parsed.cc, &parsed.bcc] {
        for address in rmail_common::jmap::address::parse(value) {
            let email = address.email.trim().to_string();
            if email.contains('@') && !out.iter().any(|known| known.eq_ignore_ascii_case(&email)) {
                out.push(email);
            }
        }
    }
    out
}

/// The message without its Bcc header (and with CRLF line ends).
fn without_bcc(raw: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(raw).replace("\r\n", "\n");
    let (head, body) = text.split_once("\n\n").unwrap_or((&text, ""));
    let mut kept = Vec::new();
    let mut skipping = false;
    for line in head.split('\n') {
        if line.starts_with([' ', '\t']) {
            if !skipping {
                kept.push(line);
            }
            continue;
        }
        skipping = line.to_ascii_lowercase().starts_with("bcc:");
        if !skipping {
            kept.push(line);
        }
    }
    format!("{}\n\n{}", kept.join("\n"), body)
        .replace('\n', "\r\n")
        .into_bytes()
}

/// A forward: the device's message with the original attached.
fn with_original(message: &[u8], original: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(message).replace("\r\n", "\n");
    let (head, body) = text.split_once("\n\n").unwrap_or((&text, ""));
    let mut top = Vec::new();
    let mut entity = Vec::new();
    let mut current = &mut top;
    for line in head.split('\n') {
        if !line.starts_with([' ', '\t']) {
            let name = line
                .split(':')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            current = if name.starts_with("content-") || name == "mime-version" {
                &mut entity
            } else {
                &mut top
            };
        }
        current.push(line);
    }
    entity.retain(|line| !line.to_ascii_lowercase().starts_with("mime-version"));
    if !entity
        .iter()
        .any(|line| line.to_ascii_lowercase().starts_with("content-type"))
    {
        entity.push("Content-Type: text/plain; charset=utf-8");
    }
    let boundary = format!("=_rmail_eas_{:016x}", rand::random::<u64>());
    let original = String::from_utf8_lossy(original).replace("\r\n", "\n");
    format!(
        "{}\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"{boundary}\"\n\n--{boundary}\n{}\n\n{}\n--{boundary}\nContent-Type: message/rfc822\nContent-Disposition: attachment; filename=\"forwarded.eml\"\n\n{}\n--{boundary}--\n",
        top.join("\n"),
        entity.join("\n"),
        body.trim_end_matches('\n'),
        original.trim_end_matches('\n')
    )
    .replace('\n', "\r\n")
    .into_bytes()
}

fn send(
    account: &Account,
    params: &Params,
    request: Option<&Element>,
    body: &[u8],
    raw_mime: bool,
) -> anyhow::Result<Response> {
    let command = params.command.as_str();
    let tag = format!("ComposeMail:{command}");
    let failure = |code: &str| {
        wbxml_response(&Element::new(&tag).with(Element::text("ComposeMail:Status", code)))
    };
    // 14.x sends WBXML; 12.x the message itself with query parameters.
    let (mime_bytes, save, source, replace) = if raw_mime {
        let source = match (params.get("CollectionId"), params.get("ItemId")) {
            (Some(collection), Some(item)) => Some((collection.to_string(), item.to_string())),
            _ => None,
        };
        (
            body.to_vec(),
            params
                .get("SaveInSent")
                .is_some_and(|v| v == "T" || v == "SaveInSent"),
            source,
            false,
        )
    } else {
        let Some(request) = request else {
            return Ok(failure("103"));
        };
        let Some(mime_part) = request.child("ComposeMail:MIME") else {
            return Ok(failure("103"));
        };
        let data = mime_part
            .opaque
            .clone()
            .unwrap_or_else(|| mime_part.text.clone().unwrap_or_default().into_bytes());
        let source = request.child("ComposeMail:Source").and_then(|s| {
            Some((
                s.value("ComposeMail:FolderId")?,
                s.value("ComposeMail:ItemId")?,
            ))
        });
        (
            data,
            request.child("ComposeMail:SaveInSentItems").is_some(),
            source,
            request.child("ComposeMail:ReplaceMime").is_some(),
        )
    };
    let Some(address) = account.state.submission else {
        return Ok(failure("110"));
    };
    let db = account.db()?;
    let original = match &source {
        Some((collection, item)) => match (
            state::folder_name(&db, collection)?,
            parse_server_id(item)
                .map(|(_, uid)| uid)
                .or_else(|| item.parse().ok()),
        ) {
            (Some(folder), Some(uid)) => account
                .messages(&folder)?
                .1
                .into_iter()
                .find(|m| m.uid == uid)
                .map(|m| (folder, m)),
            _ => None,
        },
        None => None,
    };
    let message = match (&original, command) {
        (Some((_, original)), "SmartForward") if !replace => {
            with_original(&mime_bytes, &std::fs::read(&original.path)?)
        }
        _ => mime_bytes.clone(),
    };
    let recipients = recipients(&message);
    if recipients.is_empty() {
        return Ok(failure("103"));
    }
    let wire = without_bcc(&message);
    let user = account.user.address.clone();
    let mail_root = account.state.mail_root.clone();
    let sent = tokio::runtime::Handle::current().block_on(rmail_common::local_submit::submit_as(
        address,
        &mail_root,
        &user,
        &user,
        &recipients,
        &wire,
    ));
    if let Err(error) = sent {
        webmail_log!("warn", "activesync_send_failed", { "address": user, "error": format!("{error:#}") });
        return Ok(failure("120"));
    }
    let (root, domain, local) = (
        account.root(),
        &account.user.domain,
        &account.user.localpart,
    );
    if save {
        let sent_folder = account
            .folders()?
            .into_iter()
            .find(|f| f.special_use.as_deref() == Some("\\Sent"))
            .map(|f| f.name)
            .unwrap_or_else(|| "Sent".to_string());
        if !imap_state::folder_exists(root, domain, local, &sent_folder).unwrap_or(false) {
            let _ = imap_state::create_folder_with_special_use(
                root,
                domain,
                local,
                &sent_folder,
                Some("\\Sent"),
            );
        }
        imap_state::append_message(
            root,
            domain,
            local,
            &sent_folder,
            &message.replace_crlf(),
            vec!["\\Seen".to_string()],
        )?;
    }
    if let Some((folder, original)) = original {
        let mut flags = original.flags.clone();
        flags.push(if command == "SmartForward" {
            "$Forwarded".to_string()
        } else {
            "\\Answered".to_string()
        });
        let _ = imap_state::set_uid_flags(root, domain, local, &folder, original.uid, flags);
    }
    // Success is an empty response (MS-ASCMD 2.2.1.17).
    Ok(StatusCode::OK.into_response())
}

trait CrLf {
    fn replace_crlf(&self) -> Vec<u8>;
}
impl CrLf for Vec<u8> {
    /// The message with CRLF line ends, as Maildir copies elsewhere have.
    fn replace_crlf(&self) -> Vec<u8> {
        String::from_utf8_lossy(self)
            .replace("\r\n", "\n")
            .replace('\n', "\r\n")
            .into_bytes()
    }
}

// ---------------------------------------------------------------------------
// Provisioning and settings

fn provision(account: &Account, request: Option<&Element>) -> anyhow::Result<Element> {
    let db = account.db()?;
    let mut response = Element::new("Provision:Provision");
    if request
        .and_then(|r| r.child("Settings:DeviceInformation"))
        .is_some()
    {
        response.push(
            Element::new("Settings:DeviceInformation").with(Element::text("Settings:Status", "1")),
        );
    }
    response.push(Element::text("Provision:Status", "1"));
    let policy = request
        .and_then(|r| r.child("Provision:Policies"))
        .and_then(|p| p.child("Provision:Policy"));
    let acknowledged = policy
        .and_then(|p| p.value("Provision:PolicyKey"))
        .filter(|k| !k.is_empty());
    let key = format!(
        "{}",
        1_000_000_000u64 + rand::random::<u32>() as u64 % 3_000_000_000
    );
    let mut answer = Element::new("Provision:Policy")
        .with(Element::text(
            "Provision:PolicyType",
            "MS-EAS-Provisioning-WBXML",
        ))
        .with(Element::text("Provision:Status", "1"))
        .with(Element::text("Provision:PolicyKey", key.clone()));
    if acknowledged.is_none() {
        // A policy that asks nothing of the device.
        answer.push(
            Element::new("Provision:Data").with(
                Element::new("Provision:EASProvisionDoc")
                    .with(Element::text("Provision:DevicePasswordEnabled", "0"))
                    .with(Element::text("Provision:AllowSimpleDevicePassword", "1"))
                    .with(Element::text("Provision:AttachmentsEnabled", "1"))
                    .with(Element::text("Provision:AllowHTMLEmail", "1")),
            ),
        );
    }
    state::set_policy_key(&db, &account.device, &key)?;
    response.push(Element::new("Provision:Policies").with(answer));
    Ok(response)
}

fn settings(account: &Account, request: Option<&Element>) -> anyhow::Result<Element> {
    let mut response =
        Element::new("Settings:Settings").with(Element::text("Settings:Status", "1"));
    let Some(request) = request else {
        return Ok(response);
    };
    if request.child("Settings:DeviceInformation").is_some() {
        response.push(
            Element::new("Settings:DeviceInformation").with(Element::text("Settings:Status", "1")),
        );
    }
    if request.child("Settings:UserInformation").is_some() {
        let mut addresses = Element::new("Settings:EmailAddresses");
        for address in
            rmail_common::db::sender_addresses(&account.state.db_path, &account.user.address)
                .unwrap_or_else(|_| vec![account.user.address.clone()])
        {
            addresses.push(Element::text("Settings:SmtpAddress", address));
        }
        response.push(
            Element::new("Settings:UserInformation")
                .with(Element::text("Settings:Status", "1"))
                .with(
                    Element::new("Settings:Get")
                        .with(addresses)
                        .with(Element::text(
                            "Settings:PrimarySmtpAddress",
                            account.user.address.clone(),
                        )),
                ),
        );
    }
    if request.child("Settings:Oof").is_some() {
        // Out of office is set in webmail.
        response.push(Element::new("Settings:Oof").with(Element::text("Settings:Status", "1")));
    }
    Ok(response)
}
