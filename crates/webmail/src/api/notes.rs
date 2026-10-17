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

#[cfg(test)]
mod tests {
    use super::super::tests::{req, route, state};
    use super::super::{SESSION_COOKIE, sign_session};
    use serde_json::{Value, json};

    #[tokio::test]
    async fn notes_have_their_own_view_and_leave_the_mail_folders_alone() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        rmail_common::imap_state::init_account(&state.mail_root, "example.test", "user").unwrap();
        let cookie = Some(format!(
            "{SESSION_COOKIE}={}",
            sign_session(&state, "user@example.test")
        ));
        let call = |method: &'static str, path: String, body: Value| {
            let (state, cookie) = (state.clone(), cookie.clone());
            async move {
                let body = if body.is_null() {
                    Vec::new()
                } else {
                    body.to_string().into_bytes()
                };
                let response = route(req(method, &path, &body, cookie), &state).await;
                (
                    response.status,
                    serde_json::from_slice::<Value>(&response.body).unwrap_or_default(),
                )
            }
        };
        let (_, before) = call("GET", "/api/folders".into(), Value::Null).await;
        let (status, saved) = call(
            "POST",
            "/api/notes".into(),
            json!({"text": "Shopping\nMilk"}),
        )
        .await;
        assert_eq!(status, 200, "{saved}");
        assert_eq!(saved["note"]["title"], "Shopping");
        let (_, after) = call("GET", "/api/folders".into(), Value::Null).await;
        assert_eq!(
            before, after,
            "the Notes folder is not a mail folder: {after}"
        );
        let id = saved["note"]["id"].as_str().unwrap().to_string();
        let (status, _) = call(
            "PUT",
            format!("/api/notes/{id}"),
            json!({"text": "Shopping\nMilk\nEggs"}),
        )
        .await;
        assert_eq!(status, 200);
        let (_, list) = call("GET", "/api/notes".into(), Value::Null).await;
        assert_eq!(list["notes"].as_array().unwrap().len(), 1);
        assert_eq!(list["notes"][0]["text"], "Shopping\nMilk\nEggs");
        let (status, _) = call("DELETE", format!("/api/notes/{id}"), Value::Null).await;
        assert_eq!(status, 204);
        let (status, _) = call("PUT", format!("/api/notes/{id}"), json!({"text": "x"})).await;
        assert_eq!(status, 404);
    }
}
