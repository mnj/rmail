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
use serde::{Deserialize, Serialize};

use super::{Session, Shared, blocking, internal_error};

const MAX_FOLDER_ENTRIES: usize = 500;

pub(crate) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/organize", get(overview).put(save))
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
struct Overview {
    /// Whether the administrator runs the classifier at all.
    server_enabled: bool,
    enabled: bool,
    /// Third parties that would receive this mailbox's message text; empty
    /// when everything runs on this server.
    cloud_providers: Vec<&'static str>,
    /// Whether the user agreed to all of `cloud_providers`.
    cloud_consent: bool,
    /// Whether learning itself runs in the cloud, so nothing happens for
    /// this mailbox without consent (otherwise only the fallback is skipped).
    cloud_required: bool,
    pending: usize,
    folders: Vec<FolderView>,
}

async fn overview(State(state): State<Shared>, session: Session) -> Response {
    let result = blocking(move || {
        let (root, domain, local) = (&state.mail_root, &session.domain, &session.localpart);
        let server_enabled = rmail_common::settings::open(&state.db_path)
            .and_then(|conn| rmail_common::settings::get(&conn, "classifier.enabled"))
            .ok()
            .flatten()
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let cloud_providers = cloud_providers(&state.db_path);
        let cloud_required = rmail_common::settings::open(&state.db_path)
            .and_then(|conn| rmail_common::settings::get(&conn, "classifier.embed_provider"))
            .ok()
            .flatten()
            .and_then(|value| value.as_str().map(|provider| provider != "local"))
            .unwrap_or(false);
        let conn = store::open_existing(root, domain, local)?;
        let (prefs, learned, outcomes) = match &conn {
            Some(conn) => (
                store::prefs(conn)?,
                store::example_counts(conn)?,
                store::recent_outcomes(conn)?,
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
        let folders = imap_state::list_folders(root, domain, local)?
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
            cloud_required,
            cloud_providers,
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
}

/// The cloud providers in use, or none when the settings cannot be read.
fn cloud_providers(db_path: &std::path::Path) -> Vec<&'static str> {
    rmail_common::settings::open(db_path)
        .and_then(|conn| rmail_common::settings::classifier_cloud_providers(&conn))
        .unwrap_or_default()
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
    let result = blocking(move || {
        let (root, domain, local) = (&state.mail_root, &session.domain, &session.localpart);
        // Opting out of an account that never opted in leaves no file behind.
        let conn = if input.enabled {
            Some(store::open_or_create(root, domain, local)?)
        } else {
            store::open_existing(root, domain, local)?
        };
        let Some(conn) = conn else {
            return Ok(());
        };
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
            Some(true) => cloud_providers(&state.db_path)
                .into_iter()
                .map(str::to_string)
                .collect(),
            Some(false) => Vec::new(),
            None => store::prefs(&conn)?.cloud_consent,
        };
        let prefs = Prefs {
            enabled: input.enabled,
            excluded_folders: keep(input.excluded_folders),
            autofile_folders: keep(input.autofile_folders),
            cloud_consent,
        };
        store::set_prefs(&conn, &prefs)?;
        if !prefs.enabled {
            clear_pending(root, domain, local, &conn)?;
        }
        Ok(())
    })
    .await;
    match result {
        Ok(()) => {
            webmail_log!("info", "organize_preferences_saved", { "address": address, "enabled": enabled, "cloud_consent": cloud_consent });
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => internal_error(error),
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
