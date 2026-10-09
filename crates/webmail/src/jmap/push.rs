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
/// Polls that may fail in a row before the stream ends.
const MAX_FAILURES: u32 = 5;
const TYPES: &[&str] = &[
    "Mailbox",
    "Email",
    "EmailDelivery",
    "Thread",
    "Identity",
    "EmailSubmission",
    "VacationResponse",
];

/// An account's state now.
struct Snapshot {
    account: Account,
    seq: u64,
    state: String,
}

/// Each account's state, after bringing the account up to date.
fn states(state: &AppState, user: &User) -> anyhow::Result<HashMap<String, Snapshot>> {
    let mut out = HashMap::new();
    for account in accounts(state, user)? {
        store::sync_account(&state.mail_root, &account.domain, &account.localpart)?;
        let conn = store::open(&state.mail_root, &account.domain, &account.localpart)?;
        let seq = store::state(&conn)?;
        out.insert(
            account.id.clone(),
            Snapshot {
                state: account.state(seq),
                account,
                seq,
            },
        );
    }
    Ok(out)
}

/// Whether emails were created in `account` since `since` (the
/// EmailDelivery push type, RFC 8621 section 1.5).
fn delivered_since(state: &AppState, account: &Account, since: u64) -> bool {
    store::open(&state.mail_root, &account.domain, &account.localpart)
        .ok()
        .and_then(|conn| store::changes(&conn, "Email", since, None).ok())
        .and_then(Result::ok)
        .is_some_and(|changes| !changes.created.is_empty())
}

struct Stream {
    state: Arc<AppState>,
    user: User,
    types: Vec<String>,
    close_after_state: bool,
    ping: Option<Duration>,
    /// The state string and sequence last reported per account.
    known: HashMap<String, (String, u64)>,
    started: Instant,
    last_event: Instant,
    done: bool,
    /// Polls that failed in a row.
    failures: u32,
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
        Err(response) => return *response,
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
            .map(|(id, snapshot)| (id, (snapshot.state, snapshot.seq)))
            .collect(),
        Err(error) => return super::internal_response(format!("{error:#}")),
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
        failures: 0,
    };
    let events = stream::unfold(stream, |mut stream| async move {
        loop {
            if stream.done || stream.started.elapsed() > MAX_LIFETIME {
                return None;
            }
            match stream.state.shutdown.clone() {
                Some(mut shutdown) => {
                    if *shutdown.borrow() {
                        return None;
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(POLL) => {}
                        _ = shutdown.changed() => return None,
                    }
                }
                None => tokio::time::sleep(POLL).await,
            }
            let task_state = stream.state.clone();
            let task_user = stream.user.clone();
            let known = stream.known.clone();
            let polled = blocking(move || {
                let current = states(&task_state, &task_user)?;
                let delivered = current
                    .iter()
                    .filter(|(id, snapshot)| {
                        known.get(*id).is_some_and(|(state, seq)| {
                            *state != snapshot.state
                                && delivered_since(&task_state, &snapshot.account, *seq)
                        })
                    })
                    .map(|(id, _)| id.clone())
                    .collect::<Vec<_>>();
                Ok((current, delivered))
            })
            .await;
            let (current, delivered) = match polled {
                Ok(polled) => {
                    stream.failures = 0;
                    polled
                }
                Err(error) => {
                    webmail_log!("warn", "jmap_push_poll_failed", {
                        "user": stream.user.address,
                        "error": format!("{error:#}"),
                    });
                    // A stream that cannot see changes must not look
                    // healthy; ending it makes the client reconnect.
                    stream.failures += 1;
                    if stream.failures >= MAX_FAILURES {
                        return None;
                    }
                    continue;
                }
            };
            let mut changed = Map::new();
            for (id, snapshot) in &current {
                if stream.known.get(id).map(|(state, _)| state) == Some(&snapshot.state) {
                    continue;
                }
                let mut types = Map::new();
                for kind in &stream.types {
                    let skip = match kind.as_str() {
                        "Identity" | "EmailSubmission" | "VacationResponse" => {
                            !snapshot.account.is_personal()
                        }
                        "EmailDelivery" => !delivered.contains(id),
                        _ => false,
                    };
                    if !skip {
                        types.insert(kind.clone(), Value::String(snapshot.state.clone()));
                    }
                }
                changed.insert(id.clone(), Value::Object(types));
            }
            stream.known = current
                .into_iter()
                .map(|(id, snapshot)| (id, (snapshot.state, snapshot.seq)))
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
