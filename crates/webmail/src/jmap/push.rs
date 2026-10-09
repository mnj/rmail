//! Push over an event source (RFC 8620 section 7.3).
//!
//! The stream checks the user's accounts every few seconds and sends a
//! StateChange when one moved. An account has one state for all its types,
//! so every requested type is reported with it. Streams end after half an
//! hour; clients reconnect, which also picks up changed grants.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Extension;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use futures_util::stream;
use rmail_common::http::Peer;
use rmail_common::jmap::store;
use serde_json::{Map, Value, json};

use super::{Account, User, accounts, authenticate, blocking};
use crate::api::AppState;

const POLL: Duration = Duration::from_secs(3);
const MAX_LIFETIME: Duration = Duration::from_secs(30 * 60);
const TYPES: &[&str] = &["Mailbox", "Email", "Thread", "Identity", "EmailSubmission"];

/// Each account's state string, after bringing the account up to date.
fn states(state: &AppState, user: &User) -> anyhow::Result<HashMap<String, (Account, String)>> {
    let mut out = HashMap::new();
    for account in accounts(state, user)? {
        store::sync_account(&state.mail_root, &account.domain, &account.localpart)?;
        let conn = store::open(&state.mail_root, &account.domain, &account.localpart)?;
        let seq = store::state(&conn)?;
        out.insert(account.id.clone(), (account.clone(), account.state(seq)));
    }
    Ok(out)
}

struct Stream {
    state: Arc<AppState>,
    user: User,
    types: Vec<String>,
    close_after_state: bool,
    ping: Option<Duration>,
    known: HashMap<String, String>,
    started: Instant,
    last_event: Instant,
    done: bool,
}

pub(crate) async fn event_source(
    app: State<Arc<AppState>>,
    Extension(peer): Extension<Peer>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let state = app.0;
    let user = match authenticate(&state, &headers, &peer).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let types = match params.get("types").map(String::as_str) {
        None | Some("*") | Some("") => TYPES.iter().map(|t| t.to_string()).collect(),
        Some(list) => list
            .split(',')
            .map(str::trim)
            .filter(|t| TYPES.contains(t))
            .map(str::to_string)
            .collect(),
    };
    let ping = params
        .get("ping")
        .and_then(|ping| ping.parse::<u64>().ok())
        .filter(|ping| *ping > 0)
        .map(|ping| Duration::from_secs(ping.clamp(5, 300)));
    let task_state = state.clone();
    let task_user = user.clone();
    let initial = blocking(move || states(&task_state, &task_user)).await;
    let known = match initial {
        Ok(states) => states
            .into_iter()
            .map(|(id, (_, state))| (id, state))
            .collect(),
        Err(error) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                error.to_string(),
            )
                .into_response();
        }
    };
    let stream = Stream {
        state,
        user,
        types,
        close_after_state: params.get("closeafter").map(String::as_str) == Some("state"),
        ping,
        known,
        started: Instant::now(),
        last_event: Instant::now(),
        done: false,
    };
    let events = stream::unfold(stream, |mut stream| async move {
        loop {
            if stream.done || stream.started.elapsed() > MAX_LIFETIME {
                return None;
            }
            tokio::time::sleep(POLL).await;
            let task_state = stream.state.clone();
            let task_user = stream.user.clone();
            let Ok(current) = blocking(move || states(&task_state, &task_user)).await else {
                continue;
            };
            let mut changed = Map::new();
            for (id, (account, state)) in &current {
                if stream.known.get(id) == Some(state) {
                    continue;
                }
                let mut types = Map::new();
                for kind in &stream.types {
                    let personal_only = matches!(kind.as_str(), "Identity" | "EmailSubmission");
                    if personal_only && !account.is_personal() {
                        continue;
                    }
                    types.insert(kind.clone(), Value::String(state.clone()));
                }
                changed.insert(id.clone(), Value::Object(types));
            }
            stream.known = current
                .into_iter()
                .map(|(id, (_, state))| (id, state))
                .collect();
            if !changed.is_empty() {
                stream.last_event = Instant::now();
                stream.done = stream.close_after_state;
                let event = Event::default()
                    .event("state")
                    .data(json!({"@type": "StateChange", "changed": changed}).to_string());
                return Some((Ok::<_, Infallible>(event), stream));
            }
            if let Some(ping) = stream.ping
                && stream.last_event.elapsed() >= ping
            {
                stream.last_event = Instant::now();
                let event = Event::default()
                    .event("ping")
                    .data(json!({"interval": ping.as_secs()}).to_string());
                return Some((Ok(event), stream));
            }
        }
    });
    Sse::new(events).into_response()
}
