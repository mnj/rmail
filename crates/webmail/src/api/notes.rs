//! Notes in webmail (see `crate::notes`).

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use super::{Session, Shared, blocking, internal_error};
use crate::notes;

pub(crate) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/notes", get(list).post(create))
        .route("/api/notes/{id}", put(update).delete(remove))
}

#[derive(Deserialize)]
struct Save {
    text: String,
}

fn refused(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

async fn list(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    match blocking(move || notes::list(&state.mail_root, &session.domain, &session.localpart)).await
    {
        Ok(list) => Json(json!({ "notes": list })).into_response(),
        Err(error) => internal_error(error),
    }
}

async fn write(state: Shared, headers: HeaderMap, id: Option<String>, body: Bytes) -> Response {
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<Save>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "invalid json");
    };
    if input.text.trim().is_empty() {
        return refused(StatusCode::BAD_REQUEST, "Write something first.");
    }
    if input.text.chars().count() > notes::MAX_TEXT {
        return refused(StatusCode::BAD_REQUEST, "The note is too long.");
    }
    let result = blocking(move || {
        if let Some(id) = &id
            && !notes::list(&state.mail_root, &session.domain, &session.localpart)?
                .iter()
                .any(|n| &n.id == id)
        {
            return Ok(None);
        }
        notes::save(
            &state.mail_root,
            &session.address,
            &session.domain,
            &session.localpart,
            id.as_deref(),
            &input.text,
        )
        .map(Some)
    })
    .await;
    match result {
        Ok(Some(note)) => Json(json!({ "note": note })).into_response(),
        Ok(None) => refused(StatusCode::NOT_FOUND, "This note is gone."),
        Err(error) => internal_error(error),
    }
}

async fn create(State(state): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    write(state, headers, None, body).await
}

async fn update(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    write(state, headers, Some(id), body).await
}

async fn remove(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    match blocking(move || {
        notes::delete(&state.mail_root, &session.domain, &session.localpart, &id)
    })
    .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => refused(StatusCode::NOT_FOUND, "This note is gone."),
        Err(error) => internal_error(error),
    }
}
