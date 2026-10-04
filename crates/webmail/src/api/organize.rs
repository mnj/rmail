//! Folder suggestions for the signed-in mailbox: opting in, choosing folders,
//! and accepting or dismissing what the classifier suggested.

use std::collections::BTreeMap;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rmail_common::classifier_store::{self as store, Prefs};
use rmail_common::imap_state;
use rmail_common::settings::ClassifierModels;
use serde::{Deserialize, Serialize};

use super::{Session, Shared, blocking, internal_error};

const MAX_FOLDER_ENTRIES: usize = 500;

pub(crate) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/organize", get(overview).put(save))
        .route("/api/organize/folders", post(create_folder))
        .route("/api/suggestions/accept-all", post(accept_all))
        .route("/api/suggestions/{uid}/accept", post(accept))
        .route("/api/suggestions/{uid}/dismiss", post(dismiss))
}

/// A pending suggestion shown next to an INBOX message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SuggestionView {
    pub folder: String,
    pub score: f64,
    pub method: String,
}

/// The account's labels; empty when it never opted in.
pub(crate) fn labels(
    mail_root: &std::path::Path,
    domain: &str,
    localpart: &str,
) -> Vec<store::Label> {
    match store::open_existing(mail_root, domain, localpart) {
        Ok(Some(conn)) => store::labels(&conn).unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Pending suggestions for INBOX by UID; empty when the account never opted in.
pub(crate) fn pending_for_inbox(
    mail_root: &std::path::Path,
    domain: &str,
    localpart: &str,
    uidvalidity: u64,
) -> BTreeMap<u64, SuggestionView> {
    let Ok(Some(conn)) = store::open_existing(mail_root, domain, localpart) else {
        return BTreeMap::new();
    };
    if !store::prefs(&conn).is_ok_and(|prefs| prefs.enabled) {
        return BTreeMap::new();
    }
    store::pending_suggestions(&conn, uidvalidity)
        .unwrap_or_default()
        .into_iter()
        .map(|s| {
            (
                s.uid,
                SuggestionView {
                    folder: s.folder,
                    score: s.score,
                    method: s.method,
                },
            )
        })
        .collect()
}

#[derive(Serialize)]
struct FolderView {
    name: String,
    learned: u64,
    accepted: u64,
    dismissed: u64,
    excluded: bool,
    autofile: bool,
}

#[derive(Serialize)]
struct LabelView {
    name: String,
    description: String,
    keyword: String,
    /// `user`, `starter` or `ai`.
    origin: String,
    /// Messages labeled with it so far.
    count: u64,
}

/// A label used often enough that it might deserve its own folder.
#[derive(Serialize)]
struct FolderIdea {
    label: String,
    count: u64,
}

/// Labels applied to this many messages, with no folder of that name, are
/// offered as new folders.
const FOLDER_IDEA_MIN: u64 = 10;

#[derive(Serialize)]
struct Overview {
    /// Whether the administrator runs the classifier at all.
    server_enabled: bool,
    enabled: bool,
    /// Third parties that would receive this mailbox's message text; empty
    /// when everything runs on this server.
    cloud_providers: Vec<&'static str>,
    /// Whether the user agreed to all of `cloud_providers`.
    cloud_consent: bool,
    /// Whether learning itself runs in the cloud, so folder suggestions do
    /// nothing for this mailbox without consent.
    cloud_required: bool,
    /// Whether labels (and the folder fallback) use a cloud provider.
    labels_cloud: bool,
    /// Whether the administrator configured a model that can apply labels.
    labels_available: bool,
    labels_enabled: bool,
    labels: Vec<LabelView>,
    folder_ideas: Vec<FolderIdea>,
    pending: usize,
    folders: Vec<FolderView>,
}

fn server_settings(db_path: &std::path::Path) -> (bool, ClassifierModels) {
    let Ok(conn) = rmail_common::settings::open(db_path) else {
        return (false, ClassifierModels::default());
    };
    let enabled = rmail_common::settings::get(&conn, "classifier.enabled")
        .ok()
        .flatten()
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let models = rmail_common::settings::classifier_models(&conn).unwrap_or_default();
    (enabled, models)
}

async fn overview(State(state): State<Shared>, session: Session) -> Response {
    let result = blocking(move || {
        let (root, domain, local) = (&state.mail_root, &session.domain, &session.localpart);
        let (server_enabled, models) = server_settings(&state.db_path);
        let cloud_providers = models.cloud_providers();
        let conn = store::open_existing(root, domain, local)?;
        let (prefs, learned, outcomes, labels, label_counts) = match &conn {
            Some(conn) => (
                store::prefs(conn)?,
                store::example_counts(conn)?,
                store::recent_outcomes(conn)?,
                store::labels(conn)?,
                store::label_counts(conn)?,
            ),
            None => Default::default(),
        };
        let (inbox, _) = imap_state::load_folder(root, domain, local, "INBOX")?;
        let pending = match &conn {
            Some(conn) if prefs.enabled => {
                store::pending_suggestions(conn, inbox.uidvalidity)?.len()
            }
            _ => 0,
        };
        let all_folders = imap_state::list_folders(root, domain, local)?;
        let folder_ideas = labels
            .iter()
            .filter_map(|label| {
                let count = label_counts.get(&label.name).copied().unwrap_or(0);
                let exists = all_folders.iter().any(|folder| {
                    let leaf = folder.name.rsplit('/').next().unwrap_or(&folder.name);
                    leaf.eq_ignore_ascii_case(&label.name)
                });
                (count >= FOLDER_IDEA_MIN && !exists).then(|| FolderIdea {
                    label: label.name.clone(),
                    count,
                })
            })
            .collect();
        let folders = all_folders
            .into_iter()
            .filter(store::is_user_folder)
            .map(|folder| {
                let (accepted, dismissed) = outcomes.get(&folder.name).copied().unwrap_or_default();
                FolderView {
                    learned: learned.get(&folder.name).copied().unwrap_or(0),
                    excluded: prefs.excluded_folders.contains(&folder.name),
                    autofile: prefs.autofile_folders.contains(&folder.name),
                    accepted,
                    dismissed,
                    name: folder.name,
                }
            })
            .collect();
        Ok(Overview {
            server_enabled,
            enabled: prefs.enabled,
            cloud_consent: !cloud_providers.is_empty() && prefs.allows_cloud(&cloud_providers),
            cloud_required: models.embed_cloud.is_some(),
            labels_cloud: models.chat_cloud.is_some(),
            labels_available: models.chat_configured,
            cloud_providers,
            labels_enabled: prefs.labels_enabled,
            labels: labels
                .into_iter()
                .map(|label| LabelView {
                    count: label_counts.get(&label.name).copied().unwrap_or(0),
                    name: label.name,
                    description: label.description,
                    keyword: label.keyword,
                    origin: label.origin,
                })
                .collect(),
            folder_ideas,
            pending,
            folders,
        })
    })
    .await;
    match result {
        Ok(overview) => Json(overview).into_response(),
        Err(error) => internal_error(error),
    }
}

#[derive(Deserialize)]
struct LabelInput {
    name: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct SaveRequest {
    enabled: bool,
    #[serde(default)]
    excluded_folders: Vec<String>,
    #[serde(default)]
    autofile_folders: Vec<String>,
    /// Agree (or withdraw) for the providers currently configured; absent
    /// keeps what the user decided before.
    #[serde(default)]
    cloud_consent: Option<bool>,
    /// Absent keeps the current setting, as for `labels`.
    #[serde(default)]
    labels_enabled: Option<bool>,
    #[serde(default)]
    labels: Option<Vec<LabelInput>>,
    /// Label names the editor showed, so labels the model added meanwhile
    /// are not taken as removed.
    #[serde(default)]
    labels_seen: Option<Vec<String>>,
}

async fn save(State(state): State<Shared>, session: Session, body: Bytes) -> Response {
    let Ok(input) = serde_json::from_slice::<SaveRequest>(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid json").into_response();
    };
    if input.excluded_folders.len() > MAX_FOLDER_ENTRIES
        || input.autofile_folders.len() > MAX_FOLDER_ENTRIES
    {
        return (StatusCode::BAD_REQUEST, "too many folders").into_response();
    }
    let address = session.address.clone();
    let enabled = input.enabled;
    let cloud_consent = input.cloud_consent;
    let labels_enabled = input.labels_enabled;
    let result = blocking(move || {
        let (root, domain, local) = (&state.mail_root, &session.domain, &session.localpart);
        let existing = store::open_existing(root, domain, local)?;
        let current = match &existing {
            Some(conn) => store::prefs(conn)?,
            None => Prefs::default(),
        };
        let labels_on = input.labels_enabled.unwrap_or(current.labels_enabled);
        // Opting out of an account that never opted in leaves no file behind.
        let conn = match existing {
            Some(conn) => conn,
            None if input.enabled || labels_on || input.labels.is_some() => {
                store::open_or_create(root, domain, local)?
            }
            None => return Ok(Ok(())),
        };
        if let Some(labels) = &input.labels {
            let pairs: Vec<(String, String)> = labels
                .iter()
                .map(|label| (label.name.clone(), label.description.clone()))
                .collect();
            if let Err(error) = store::set_labels(&conn, &pairs, input.labels_seen.as_deref()) {
                return Ok(Err(error.to_string()));
            }
        }
        let known: Vec<String> = imap_state::list_folders(root, domain, local)?
            .into_iter()
            .filter(store::is_user_folder)
            .map(|folder| folder.name)
            .collect();
        let keep = |names: Vec<String>| -> Vec<String> {
            let mut names: Vec<String> = names
                .into_iter()
                .filter(|name| known.contains(name))
                .collect();
            names.sort();
            names.dedup();
            names
        };
        // Consent names the providers the user saw, so a provider added
        // later needs a new agreement.
        let cloud_consent = match input.cloud_consent {
            Some(true) => server_settings(&state.db_path)
                .1
                .cloud_providers()
                .into_iter()
                .map(str::to_string)
                .collect(),
            Some(false) => Vec::new(),
            None => current.cloud_consent,
        };
        let prefs = Prefs {
            enabled: input.enabled,
            excluded_folders: keep(input.excluded_folders),
            autofile_folders: keep(input.autofile_folders),
            cloud_consent,
            labels_enabled: labels_on,
        };
        store::set_prefs(&conn, &prefs)?;
        if prefs.labels_enabled {
            // Common labels, so labeling works without setting anything up.
            store::seed_starter_labels(&conn)?;
        }
        if !prefs.enabled {
            clear_pending(root, domain, local, &conn)?;
        }
        Ok(Ok(()))
    })
    .await;
    match result {
        Ok(Ok(())) => {
            webmail_log!("info", "organize_preferences_saved", { "address": address, "enabled": enabled, "cloud_consent": cloud_consent, "labels_enabled": labels_enabled });
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Err(message)) => (StatusCode::UNPROCESSABLE_ENTITY, message).into_response(),
        Err(error) => internal_error(error),
    }
}

#[derive(Deserialize)]
struct NewFolder {
    /// One of the user's labels; the folder takes its name.
    label: String,
    /// An existing folder to create it in; absent creates it at the top.
    #[serde(default)]
    parent: Option<String>,
}

/// Create a folder for a label used often, optionally inside an existing
/// folder. The name is built from the stored label and folder names, so the
/// request only selects among them.
async fn create_folder(State(state): State<Shared>, session: Session, body: Bytes) -> Response {
    let Ok(input) = serde_json::from_slice::<NewFolder>(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid json").into_response();
    };
    let result = blocking(move || {
        let (root, domain, local) = (&state.mail_root, &session.domain, &session.localpart);
        let Some(conn) = store::open_existing(root, domain, local)? else {
            return Ok(Err("no such label"));
        };
        let Some(label) = store::labels(&conn)?
            .into_iter()
            .find(|label| label.name == input.label)
        else {
            return Ok(Err("no such label"));
        };
        let name = match &input.parent {
            None => label.name,
            Some(parent) => {
                let Some(folder) = imap_state::list_folders(root, domain, local)?
                    .into_iter()
                    .filter(store::is_user_folder)
                    .find(|folder| &folder.name == parent)
                else {
                    return Ok(Err("no such folder"));
                };
                format!("{}/{}", folder.name, label.name)
            }
        };
        imap_state::create_folder(root, domain, local, &name)?;
        Ok(Ok(name))
    })
    .await;
    match result {
        Ok(Ok(folder)) => Json(serde_json::json!({ "folder": folder })).into_response(),
        Ok(Err(message)) => (StatusCode::UNPROCESSABLE_ENTITY, message).into_response(),
        Err(error) => (StatusCode::CONFLICT, error.to_string()).into_response(),
    }
}

/// Remove `$Suggested` and resolve suggestions when the user opts out.
fn clear_pending(
    root: &std::path::Path,
    domain: &str,
    local: &str,
    conn: &rmail_common::sqlite_pool::SqliteConnection,
) -> anyhow::Result<()> {
    let (inbox, _) = imap_state::load_folder(root, domain, local, "INBOX")?;
    for suggestion in store::pending_suggestions(conn, inbox.uidvalidity)? {
        store::set_keyword(
            root,
            domain,
            local,
            "INBOX",
            suggestion.uid,
            store::SUGGESTED_KEYWORD,
            false,
        )?;
        store::set_suggestion_state(conn, inbox.uidvalidity, suggestion.uid, "gone")?;
    }
    Ok(())
}

fn parse_uid(uid: &str) -> Option<u64> {
    uid.parse().ok()
}

async fn accept(
    State(state): State<Shared>,
    session: Session,
    Path(uid): Path<String>,
) -> Response {
    let Some(uid) = parse_uid(&uid) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let result =
        blocking(move || store::accept(&state.mail_root, &session.domain, &session.localpart, uid))
            .await;
    match result {
        Ok(folder) => Json(serde_json::json!({ "folder": folder })).into_response(),
        Err(error) => (StatusCode::CONFLICT, error.to_string()).into_response(),
    }
}

async fn dismiss(
    State(state): State<Shared>,
    session: Session,
    Path(uid): Path<String>,
) -> Response {
    let Some(uid) = parse_uid(&uid) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let result = blocking(move || {
        store::dismiss(&state.mail_root, &session.domain, &session.localpart, uid)
    })
    .await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => (StatusCode::CONFLICT, error.to_string()).into_response(),
    }
}

async fn accept_all(State(state): State<Shared>, session: Session) -> Response {
    let result = blocking(move || {
        let (root, domain, local) = (&state.mail_root, &session.domain, &session.localpart);
        let Some(conn) = store::open_existing(root, domain, local)? else {
            return Ok(0usize);
        };
        let (inbox, _) = imap_state::load_folder(root, domain, local, "INBOX")?;
        let pending = store::pending_suggestions(&conn, inbox.uidvalidity)?;
        drop(conn);
        let mut moved = 0;
        for suggestion in pending {
            if store::accept(root, domain, local, suggestion.uid).is_ok() {
                moved += 1;
            }
        }
        Ok(moved)
    })
    .await;
    match result {
        Ok(moved) => Json(serde_json::json!({ "moved": moved })).into_response(),
        Err(error) => internal_error(error),
    }
}
