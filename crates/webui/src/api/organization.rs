//! Admin API for mail organization: download, choose and test the local
//! models the `rmail_classifier` daemon runs.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use rmail_common::classifier_control::{self, Request as Control};
use rmail_common::classifier_models::{self as models, DownloadRequest, ModelKind, Progress};
use rmail_common::http::Peer;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{Shared, blocking, error, outcome, parse, require_db};

const STATUS_WAIT: Duration = Duration::from_secs(3);
/// Chat tests on a CPU can take a while for large models.
const TEST_WAIT: Duration = Duration::from_secs(180);

#[derive(Default)]
pub(crate) struct Downloads {
    items: std::sync::Mutex<BTreeMap<String, Download>>,
}

struct Download {
    progress: Arc<Progress>,
    state: DownloadState,
}

#[derive(Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum DownloadState {
    Running,
    Done { sha256: String },
    Failed { error: String },
}

pub(crate) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/organization", get(overview))
        .route("/api/organization/download", post(download))
        .route("/api/organization/delete", post(delete))
        .route("/api/organization/activate", post(activate))
        .route("/api/organization/reload", post(reload))
        .route("/api/organization/test", post(test))
}

fn models_dir(state: &Shared) -> std::path::PathBuf {
    models::models_dir(&state.mail_root)
}

fn socket(state: &Shared) -> std::path::PathBuf {
    classifier_control::socket_path(&state.mail_root)
}

/// Current `classifier.*` settings, from the database when there is one.
/// Secrets such as API keys are reported only as `true` (set).
fn current_settings(db: Option<&str>) -> anyhow::Result<BTreeMap<String, Value>> {
    let Some(db) = db else {
        return Ok(BTreeMap::new());
    };
    let conn = rmail_common::settings::open(db)?;
    Ok(rmail_common::settings::load_all(&conn)?
        .into_iter()
        .filter_map(|(key, value)| {
            let secret = rmail_common::settings::spec_for(&key).is_some_and(|spec| {
                matches!(spec.kind, rmail_common::settings::SettingKind::Secret)
            });
            let value = if secret { Value::Bool(true) } else { value };
            key.strip_prefix("classifier.")
                .map(|k| (k.to_string(), value))
        })
        .collect())
}

async fn overview(State(state): State<Shared>) -> Response {
    let dir = models_dir(&state);
    let db = state.db_path.clone();
    let local = blocking(move || {
        Ok((
            models::list_installed(&dir)?,
            current_settings(db.as_deref())?,
        ))
    })
    .await;
    let (installed, settings) = match local {
        Ok(local) => local,
        Err(err) => return error(StatusCode::INTERNAL_SERVER_ERROR, format!("{err:#}")),
    };
    let daemon =
        match classifier_control::call(&socket(&state), &Control::Status, STATUS_WAIT).await {
            Ok(status) => json!({ "running": true, "status": status }),
            Err(err) => json!({ "running": false, "error": format!("{err:#}") }),
        };
    let downloads: Vec<Value> = state
        .downloads
        .items
        .lock()
        .unwrap()
        .iter()
        .map(|(file, download)| {
            json!({
                "file": file,
                "received": download.progress.received.load(Ordering::Relaxed),
                "total": download.progress.total.load(Ordering::Relaxed),
                "status": download.state,
            })
        })
        .collect();
    Json(json!({
        "models_dir": models_dir(&state),
        "catalog": models::CATALOG,
        "installed": installed,
        "downloads": downloads,
        "settings": settings,
        "daemon": daemon,
    }))
    .into_response()
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DownloadInput {
    Catalog { catalog_id: String },
    Custom(DownloadRequest),
}

async fn download(
    State(state): State<Shared>,
    Extension(peer): Extension<Peer>,
    body: Bytes,
) -> Response {
    let request = match parse::<DownloadInput>(&body) {
        Ok(DownloadInput::Catalog { catalog_id }) => {
            match models::CATALOG.iter().find(|m| m.id == catalog_id) {
                Some(model) => DownloadRequest::from_catalog(model),
                None => return error(StatusCode::BAD_REQUEST, "unknown catalog model"),
            }
        }
        Ok(DownloadInput::Custom(request)) => request,
        Err(err) => return err.into_response(),
    };
    if let Err(err) = request.validate() {
        return error(StatusCode::BAD_REQUEST, format!("{err:#}"));
    }
    let progress = Arc::new(Progress::default());
    {
        let mut items = state.downloads.items.lock().unwrap();
        if items
            .get(&request.file)
            .is_some_and(|d| matches!(d.state, DownloadState::Running))
        {
            return error(StatusCode::CONFLICT, "this model is already downloading");
        }
        items.insert(
            request.file.clone(),
            Download {
                progress: progress.clone(),
                state: DownloadState::Running,
            },
        );
    }
    web_log!("info", "model_download_started", { "peer": peer.0.map(|a| a.to_string()), "file": request.file, "url": request.url });
    let dir = models_dir(&state);
    let task_state = state.clone();
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .build();
        let result = match client {
            Ok(client) => models::download(&client, &dir, &request, progress).await,
            Err(err) => Err(err.into()),
        };
        let outcome = match result {
            Ok(meta) => {
                web_log!("info", "model_download_finished", { "file": request.file, "sha256": meta.sha256, "bytes": meta.size });
                DownloadState::Done {
                    sha256: meta.sha256,
                }
            }
            Err(err) => {
                web_log!("warn", "model_download_failed", { "file": request.file, "error": format!("{err:#}") });
                DownloadState::Failed {
                    error: format!("{err:#}"),
                }
            }
        };
        if let Some(download) = task_state
            .downloads
            .items
            .lock()
            .unwrap()
            .get_mut(&request.file)
        {
            download.state = outcome;
        }
    });
    (StatusCode::ACCEPTED, Json(json!({ "result": "started" }))).into_response()
}

#[derive(Deserialize)]
struct FileInput {
    file: String,
}

async fn delete(
    State(state): State<Shared>,
    Extension(peer): Extension<Peer>,
    body: Bytes,
) -> Response {
    let input: FileInput = match parse(&body) {
        Ok(input) => input,
        Err(err) => return err.into_response(),
    };
    let dir = models_dir(&state);
    let db = state.db_path.clone();
    let file = input.file.clone();
    let result = blocking(move || {
        let settings = current_settings(db.as_deref())?;
        for key in ["embed_model", "chat_model"] {
            if settings.get(key).and_then(Value::as_str) == Some(file.as_str()) {
                anyhow::bail!(
                    "{file} is the active {} model; choose another first",
                    key.trim_end_matches("_model")
                );
            }
        }
        models::delete_model(&dir, &file)
    })
    .await;
    if result.is_ok() {
        state.downloads.items.lock().unwrap().remove(&input.file);
        web_log!("info", "model_deleted", { "peer": peer.0.map(|a| a.to_string()), "file": input.file });
    }
    outcome(
        result.map(|()| json!({ "result": "ok" })),
        StatusCode::BAD_REQUEST,
    )
}

#[derive(Deserialize)]
struct ActivateInput {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    embed_model: Option<String>,
    #[serde(default)]
    chat_model: Option<String>,
}

async fn activate(
    State(state): State<Shared>,
    Extension(peer): Extension<Peer>,
    body: Bytes,
) -> Response {
    let db = match require_db(&state) {
        Ok(db) => db,
        Err(err) => return err.into_response(),
    };
    let input: ActivateInput = match parse(&body) {
        Ok(input) => input,
        Err(err) => return err.into_response(),
    };
    let dir = models_dir(&state);
    let result = blocking(move || {
        let mut changes = BTreeMap::new();
        if let Some(enabled) = input.enabled {
            changes.insert("classifier.enabled".to_string(), Value::Bool(enabled));
        }
        for (key, value, kind) in [
            (
                "classifier.embed_model",
                &input.embed_model,
                ModelKind::Embedding,
            ),
            ("classifier.chat_model", &input.chat_model, ModelKind::Chat),
        ] {
            let Some(file) = value else { continue };
            if !file.is_empty() {
                let path = models::model_path(&dir, file)?;
                if !path.is_file() {
                    anyhow::bail!("{file} is not installed");
                }
                if let Some(meta) = models::read_meta(&dir, file)
                    && meta.kind != kind
                {
                    anyhow::bail!(
                        "{file} is not {} model",
                        if kind == ModelKind::Chat {
                            "a chat"
                        } else {
                            "an embedding"
                        }
                    );
                }
            }
            changes.insert(key.to_string(), Value::String(file.clone()));
        }
        let mut conn = rmail_common::settings::open(&db)?;
        rmail_common::settings::update(&mut conn, &changes)
    })
    .await;
    let revision = match result {
        Ok(revision) => revision,
        Err(err) => return error(StatusCode::UNPROCESSABLE_ENTITY, format!("{err:#}")),
    };
    web_log!("info", "organization_settings_updated", { "peer": peer.0.map(|a| a.to_string()), "revision": revision });
    // Loading a model can take a while; the daemon answers once it is done.
    let reload = classifier_control::call(&socket(&state), &Control::Reload, TEST_WAIT).await;
    Json(json!({
        "revision": revision,
        "reloaded": reload.is_ok(),
        "reload_error": reload.err().map(|err| format!("{err:#}")),
    }))
    .into_response()
}

async fn reload(State(state): State<Shared>) -> Response {
    outcome(
        classifier_control::call(&socket(&state), &Control::Reload, TEST_WAIT).await,
        StatusCode::BAD_GATEWAY,
    )
}

#[derive(Deserialize)]
struct TestInput {
    kind: String,
    text: String,
    #[serde(default)]
    folders: Vec<String>,
}

async fn test(State(state): State<Shared>, body: Bytes) -> Response {
    let input: TestInput = match parse(&body) {
        Ok(input) => input,
        Err(err) => return err.into_response(),
    };
    if input.text.trim().is_empty() || input.text.len() > 16 * 1024 {
        return error(StatusCode::BAD_REQUEST, "text must be 1 to 16384 bytes");
    }
    let request = match input.kind.as_str() {
        "embed" => Control::TestEmbed { text: input.text },
        "chat" => Control::TestChat {
            text: input.text,
            folders: input
                .folders
                .into_iter()
                .map(|f| f.trim().to_string())
                .filter(|f| !f.is_empty())
                .take(64)
                .collect(),
        },
        _ => return error(StatusCode::BAD_REQUEST, "kind must be embed or chat"),
    };
    outcome(
        classifier_control::call(&socket(&state), &request, TEST_WAIT).await,
        StatusCode::BAD_GATEWAY,
    )
}
