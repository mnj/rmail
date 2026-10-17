//! Tasks in webmail: the to-dos (`VTODO`) of the user's calendars and
//! those shared with them, the same ones CalDAV apps (Apple Reminders,
//! Thunderbird, DAVx5 with jtx Board or Tasks.org) and ActiveSync phones
//! show. Webmail edits the title, notes, due date, priority and whether a
//! task is done; other properties (subtasks, alarms, categories, repeat
//! rules) are kept as they are.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use rmail_common::dav::recur;
use rmail_common::dav::store::{self, PutError};
use rmail_common::dav::text::{self, Component, Property};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::events::{Place, is_date, places_for, set_text, text_of, time_property};
use super::{AppState, Session, Shared, blocking, internal_error};

pub(crate) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/tasks", get(list))
        .route("/api/tasks/{list}", post(create))
        .route("/api/tasks/{list}/{name}", put(update).delete(remove))
}

const MAX_SUMMARY: usize = 500;
const MAX_NOTES: usize = 20_000;

/// What webmail edits of a task.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TaskFields {
    pub summary: String,
    #[serde(default)]
    pub notes: String,
    /// Unix seconds; for a date without a time, midnight UTC of that day.
    #[serde(default)]
    pub due: Option<i64>,
    #[serde(default)]
    pub due_all_day: bool,
    /// iCalendar PRIORITY: 0 none, 1 high, 5 medium, 9 low.
    #[serde(default)]
    pub priority: u8,
    #[serde(default)]
    pub completed: bool,
}

#[derive(Serialize, Debug)]
struct Task {
    list: String,
    name: String,
    etag: String,
    #[serde(flatten)]
    fields: TaskFields,
    /// When it was marked done, Unix seconds.
    completed_at: Option<i64>,
    recurring: bool,
    editable: bool,
}

#[derive(Serialize)]
struct ListInfo {
    id: String,
    displayname: String,
    color: Option<String>,
    owner: Option<String>,
    writable: bool,
}

/// The fields of a calendar object's to-do, if it holds one.
pub(crate) fn task_fields(calendar: &Component) -> Option<TaskFields> {
    let todo = todo(calendar)?;
    let due = todo.property("DUE");
    let status = text_of(todo, "STATUS");
    Some(TaskFields {
        summary: text_of(todo, "SUMMARY"),
        notes: text_of(todo, "DESCRIPTION"),
        due: due.and_then(recur::instant),
        due_all_day: due.is_some_and(is_date),
        priority: todo
            .property("PRIORITY")
            .and_then(|p| p.value.trim().parse::<u8>().ok())
            .filter(|p| *p <= 9)
            .unwrap_or(0),
        completed: status.eq_ignore_ascii_case("COMPLETED") || todo.property("COMPLETED").is_some(),
    })
}

/// The to-do of a calendar object (its master, when it repeats).
pub(crate) fn todo(calendar: &Component) -> Option<&Component> {
    let todos = calendar.components.iter().filter(|c| c.name == "VTODO");
    todos
        .clone()
        .find(|c| c.property("RECURRENCE-ID").is_none())
        .or_else(|| todos.clone().next())
}

fn todo_mut(calendar: &mut Component) -> Option<&mut Component> {
    let index = calendar
        .components
        .iter()
        .position(|c| c.name == "VTODO" && c.property("RECURRENCE-ID").is_none())
        .or_else(|| calendar.components.iter().position(|c| c.name == "VTODO"))?;
    calendar.components.get_mut(index)
}

/// `existing` with the to-do's fields set from `fields`, or a new object.
pub(crate) fn task_text(existing: Option<&Component>, fields: &TaskFields, uid: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let mut calendar = existing.cloned().unwrap_or_else(|| {
        let mut calendar = Component::new("VCALENDAR");
        calendar.set_property("VERSION", "2.0");
        calendar.set_property("PRODID", "-//rMail//webmail//EN");
        let mut todo = Component::new("VTODO");
        todo.set_property("UID", uid);
        todo.set_property("CREATED", &recur::utc_text(now));
        calendar.components.push(todo);
        calendar
    });
    let previous = existing.and_then(task_fields);
    let Some(todo) = todo_mut(&mut calendar) else {
        return calendar.to_text();
    };
    set_text(todo, "SUMMARY", &fields.summary);
    set_text(todo, "DESCRIPTION", &fields.notes);
    let due_changed = previous
        .as_ref()
        .is_none_or(|p| (p.due, p.due_all_day) != (fields.due, fields.due_all_day));
    if due_changed {
        todo.properties.retain(|p| p.name != "DUE");
        if let Some(due) = fields.due {
            todo.properties
                .push(time_property("DUE", due, fields.due_all_day, ""));
            // A start after the due date would make the to-do invalid.
            if todo
                .property("DTSTART")
                .and_then(recur::instant)
                .is_some_and(|start| start > due)
            {
                todo.properties.retain(|p| p.name != "DTSTART");
            }
        }
    }
    todo.properties.retain(|p| p.name != "PRIORITY");
    if fields.priority > 0 {
        todo.properties.push(Property::new(
            "PRIORITY",
            &fields.priority.min(9).to_string(),
        ));
    }
    let was_done = previous.as_ref().is_some_and(|p| p.completed);
    if fields.completed && !was_done {
        todo.set_property("STATUS", "COMPLETED");
        todo.set_property("COMPLETED", &recur::utc_text(now));
        todo.set_property("PERCENT-COMPLETE", "100");
    } else if !fields.completed && was_done {
        todo.set_property("STATUS", "NEEDS-ACTION");
        todo.properties
            .retain(|p| p.name != "COMPLETED" && p.name != "PERCENT-COMPLETE");
    }
    let sequence = todo
        .property("SEQUENCE")
        .and_then(|s| s.value.trim().parse::<i64>().ok())
        .unwrap_or(0);
    if existing.is_some() {
        todo.set_property("SEQUENCE", &(sequence + 1).to_string());
    }
    todo.set_property("LAST-MODIFIED", &recur::utc_text(now));
    todo.set_property("DTSTAMP", &recur::utc_text(now));
    calendar.to_text()
}

/// Why a task cannot be saved, for the user.
pub(crate) fn check(fields: &TaskFields) -> Result<(), &'static str> {
    if fields.summary.trim().is_empty() {
        return Err("Give the task a title.");
    }
    if fields.summary.chars().count() > MAX_SUMMARY || fields.notes.chars().count() > MAX_NOTES {
        return Err("The task is too long.");
    }
    if fields.priority > 9 {
        return Err("Unknown priority.");
    }
    Ok(())
}

fn tasks_in(place: &Place) -> anyhow::Result<Vec<Task>> {
    let mut out = Vec::new();
    for object in store::objects(&place.conn, &place.collection)? {
        if object.component.as_deref() != Some("VTODO") {
            continue;
        }
        let Ok(calendar) = text::parse(&object.data) else {
            continue;
        };
        let (Some(fields), Some(todo)) = (task_fields(&calendar), todo(&calendar)) else {
            continue;
        };
        out.push(Task {
            list: place.id.clone(),
            name: object.name.clone(),
            etag: object.etag.clone(),
            completed_at: todo.property("COMPLETED").and_then(recur::instant),
            recurring: todo.property("RRULE").is_some(),
            editable: place.writable,
            fields,
        });
    }
    Ok(out)
}

fn refused(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

async fn list(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let result = blocking(move || {
        let places = places_for(&state, &session, "VTODO")?;
        let mut tasks = Vec::new();
        for place in &places {
            tasks.extend(tasks_in(place)?);
        }
        Ok(json!({
            "lists": places.iter().map(|place| ListInfo {
                id: place.id.clone(),
                displayname: place.displayname.clone(),
                color: place.color.clone(),
                owner: place.shared.then(|| place.owner.address.clone()),
                writable: place.writable,
            }).collect::<Vec<_>>(),
            "tasks": tasks,
        }))
    })
    .await;
    match result {
        Ok(listing) => Json(listing).into_response(),
        Err(error) => internal_error(error),
    }
}

#[derive(Deserialize)]
struct Save {
    #[serde(flatten)]
    fields: TaskFields,
    #[serde(default)]
    etag: Option<String>,
}

type Saved = Result<String, (StatusCode, &'static str)>;

/// Store `fields` in `list` as a new task or over `name` when it is still
/// at `etag`.
pub(crate) fn save(
    state: &AppState,
    session: &Session,
    list: &str,
    name: Option<&str>,
    fields: &TaskFields,
    etag: Option<String>,
    uid: Option<String>,
) -> anyhow::Result<Saved> {
    if let Err(message) = check(fields) {
        return Ok(Err((StatusCode::BAD_REQUEST, message)));
    }
    let Some(place) = places_for(state, session, "VTODO")?
        .into_iter()
        .find(|p| p.id == list)
    else {
        return Ok(Err((StatusCode::NOT_FOUND, "No such task list.")));
    };
    if !place.writable {
        return Ok(Err((
            StatusCode::FORBIDDEN,
            "This list is shared with you read-only.",
        )));
    }
    let uid = uid.unwrap_or_else(super::contacts::uuid);
    let name = name.map_or_else(|| format!("{uid}.ics"), str::to_string);
    let stored = store::put_with(&place.conn, &place.collection, &name, &mut |current| {
        match (current, &etag) {
            (None, None) => {}
            (Some(object), Some(etag)) if &object.etag == etag => {}
            _ => return Err(PutError::PreconditionFailed),
        }
        let existing = current.and_then(|object| text::parse(&object.data).ok());
        if existing.as_ref().is_some_and(|c| todo(c).is_none()) {
            return Err(PutError::InvalidData("not a task".into()));
        }
        Ok(store::Prepared {
            data: task_text(existing.as_ref(), fields, &uid),
            schedule_tag: store::ScheduleTag::Keep,
        })
    })?;
    Ok(match stored {
        Ok(_) => Ok(name),
        Err(PutError::PreconditionFailed) => Err((
            StatusCode::CONFLICT,
            "This task was changed elsewhere. Reload and try again.",
        )),
        Err(_) => Err((StatusCode::BAD_REQUEST, "The task could not be saved.")),
    })
}

/// Delete a task (when still at `etag`, if given).
pub(crate) fn delete(
    state: &AppState,
    session: &Session,
    list: &str,
    name: &str,
    etag: Option<String>,
) -> anyhow::Result<Result<(), (StatusCode, &'static str)>> {
    let Some(place) = places_for(state, session, "VTODO")?
        .into_iter()
        .find(|p| p.id == list)
    else {
        return Ok(Err((StatusCode::NOT_FOUND, "No such task list.")));
    };
    if !place.writable {
        return Ok(Err((
            StatusCode::FORBIDDEN,
            "This list is shared with you read-only.",
        )));
    }
    Ok(
        match store::delete(&place.conn, &place.collection, name, &|current| {
            etag.as_ref()
                .is_none_or(|etag| current.is_some_and(|object| &object.etag == etag))
        })? {
            store::Deleted::Deleted(_) => Ok(()),
            store::Deleted::NotFound => Err((StatusCode::NOT_FOUND, "The task is gone.")),
            store::Deleted::PreconditionFailed => Err((
                StatusCode::CONFLICT,
                "This task was changed elsewhere. Reload and try again.",
            )),
        },
    )
}

async fn write(
    state: Shared,
    headers: HeaderMap,
    list: String,
    name: Option<String>,
    body: Bytes,
) -> Response {
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<Save>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "invalid json");
    };
    let result = blocking(move || {
        save(
            &state,
            &session,
            &list,
            name.as_deref(),
            &input.fields,
            input.etag,
            None,
        )
    })
    .await;
    match result {
        Ok(Ok(name)) => Json(json!({ "name": name })).into_response(),
        Ok(Err((status, message))) => refused(status, message),
        Err(error) => internal_error(error),
    }
}

async fn create(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(list): Path<String>,
    body: Bytes,
) -> Response {
    write(state, headers, list, None, body).await
}

async fn update(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((list, name)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    write(state, headers, list, Some(name), body).await
}

#[derive(Deserialize)]
struct Remove {
    etag: Option<String>,
}

async fn remove(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path((list, name)): Path<(String, String)>,
    Query(query): Query<Remove>,
) -> Response {
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    match blocking(move || delete(&state, &session, &list, &name, query.etag)).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err((status, message))) => refused(status, message),
        Err(error) => internal_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{req, route, state};
    use super::super::{SESSION_COOKIE, sign_session};
    use super::*;
    use serde_json::Value;

    #[test]
    fn task_text_keeps_what_webmail_does_not_edit() {
        let existing = text::parse(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTODO\r\nUID:t1\r\nSUMMARY:Old\r\nDTSTART:20261030T120000Z\r\nCATEGORIES:home\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nEND:VALARM\r\nEND:VTODO\r\nEND:VCALENDAR\r\n",
        )
        .unwrap();
        let fields = TaskFields {
            summary: "Buy milk; bread".into(),
            due: Some(1_792_540_800), // 2026-10-21
            due_all_day: true,
            priority: 1,
            completed: true,
            ..TaskFields::default()
        };
        let data = task_text(Some(&existing), &fields, "t1");
        assert!(data.contains(r"SUMMARY:Buy milk\; bread"));
        assert!(data.contains("DUE;VALUE=DATE:20261021"));
        assert!(!data.contains("DTSTART"), "a start after the due date goes");
        assert!(data.contains("CATEGORIES:home") && data.contains("BEGIN:VALARM"));
        assert!(data.contains("STATUS:COMPLETED") && data.contains("PERCENT-COMPLETE:100"));
        let parsed = text::parse(&data).unwrap();
        assert_eq!(task_fields(&parsed), Some(fields.clone()));
        let reopened = task_text(
            Some(&parsed),
            &TaskFields {
                completed: false,
                ..fields
            },
            "t1",
        );
        assert!(reopened.contains("STATUS:NEEDS-ACTION") && !reopened.contains("COMPLETED:"));
    }

    #[tokio::test]
    async fn tasks_are_listed_added_done_and_deleted() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
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
        let (status, listing) = call("GET", "/api/tasks".into(), Value::Null).await;
        assert_eq!(status, 200);
        let list = listing["lists"][0]["id"].as_str().unwrap().to_string();
        assert_eq!(list, "own:default", "the default calendar takes tasks");
        let (status, saved) = call(
            "POST",
            format!("/api/tasks/{list}"),
            json!({"summary": "File taxes", "priority": 5}),
        )
        .await;
        assert_eq!(status, 200, "{saved}");
        let (status, _) = call(
            "POST",
            format!("/api/tasks/{list}"),
            json!({"summary": " "}),
        )
        .await;
        assert_eq!(status, 400, "a title is needed");
        let (_, listing) = call("GET", "/api/tasks".into(), Value::Null).await;
        let task = listing["tasks"][0].clone();
        assert_eq!(
            (
                task["summary"].as_str(),
                task["priority"].as_u64(),
                task["completed"].as_bool()
            ),
            (Some("File taxes"), Some(5), Some(false))
        );
        let path = format!("/api/tasks/{list}/{}", task["name"].as_str().unwrap());
        let mut done = task.clone();
        done["completed"] = json!(true);
        let (status, _) = call("PUT", path.clone(), done.clone()).await;
        assert_eq!(status, 200);
        let (status, _) = call("PUT", path.clone(), done).await;
        assert_eq!(status, 409, "the old version's etag no longer matches");
        let (_, listing) = call("GET", "/api/tasks".into(), Value::Null).await;
        let task = listing["tasks"][0].clone();
        assert_eq!(task["completed"], true);
        assert!(task["completed_at"].as_i64().is_some());
        let etag = task["etag"].as_str().unwrap();
        let (status, _) = call(
            "DELETE",
            format!("{path}?etag={}", etag.replace('"', "%22")),
            Value::Null,
        )
        .await;
        assert_eq!(status, 204);
        let (_, listing) = call("GET", "/api/tasks".into(), Value::Null).await;
        assert!(listing["tasks"].as_array().unwrap().is_empty());
    }
}
