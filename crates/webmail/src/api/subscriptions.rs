//! Calendar subscriptions from webmail: subscribe to a webcal/iCalendar
//! feed, refresh it, unsubscribe (see `rmail_common::dav::subscription`).
//! A task refreshes every account's subscriptions in the background.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, post};
use axum::{Json, Router};
use rmail_common::dav::store::Collection;
use rmail_common::dav::subscription;
use rmail_common::imap_state;
use serde::Deserialize;
use serde_json::json;

use super::{AppState, Session, Shared, blocking, internal_error};

/// How often the background task looks for subscriptions to refresh.
const SWEEP_EVERY: Duration = Duration::from_secs(30 * 60);

pub(crate) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/subscriptions", post(subscribe))
        .route("/api/subscriptions/{calendar}/refresh", post(refresh_now))
        .route("/api/subscriptions/{calendar}", delete(unsubscribe))
}

fn refused(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn open(
    state: &AppState,
    session: &Session,
) -> anyhow::Result<rmail_common::sqlite_pool::SqliteConnection> {
    rmail_common::jmap::store::open(&state.mail_root, &session.domain, &session.localpart)
}

/// Fetch a subscription's feed and store its events; the error, for the
/// user, when that failed (it is also recorded on the subscription).
async fn refresh(
    state: Arc<AppState>,
    domain: String,
    localpart: String,
    collection: Collection,
    url: String,
) -> Result<(usize, usize), String> {
    let fetched = match subscription::normalize_url(&url) {
        Ok(url) => subscription::fetch(&url)
            .await
            .map_err(|e| format!("{e:#}")),
        Err(error) => Err(format!("{error:#}")),
    };
    let result = blocking(move || {
        let conn = rmail_common::jmap::store::open(&state.mail_root, &domain, &localpart)?;
        let outcome = fetched.and_then(|feed| {
            let objects = subscription::objects_of(&feed).map_err(|e| format!("{e:#}"))?;
            subscription::apply(&conn, &collection, &objects).map_err(|e| format!("{e:#}"))
        });
        subscription::record(
            &conn,
            &collection,
            outcome.as_ref().err().map(String::as_str),
        )?;
        Ok(outcome)
    })
    .await;
    match result {
        Ok(outcome) => outcome,
        Err(error) => Err(format!("{error:#}")),
    }
}

#[derive(Deserialize)]
struct Subscribe {
    url: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    color: Option<String>,
}

/// Subscribe: the feed is fetched first, so a wrong address is reported
/// rather than saved.
async fn subscribe(app: State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<Subscribe>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "invalid json");
    };
    if input.name.chars().count() > 100 || input.name.contains(['\r', '\n']) {
        return refused(StatusCode::BAD_REQUEST, "The name is too long.");
    }
    let url = match subscription::normalize_url(&input.url) {
        Ok(url) => url,
        Err(error) => return refused(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };
    let feed = match subscription::fetch(&url).await {
        Ok(feed) => feed,
        Err(error) => {
            return refused(
                StatusCode::BAD_REQUEST,
                &format!("The calendar could not be fetched: {error:#}"),
            );
        }
    };
    let objects = match subscription::objects_of(&feed) {
        Ok(objects) => objects,
        Err(error) => return refused(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    };
    let result = blocking(move || {
        let conn = open(&state, &session)?;
        let collection = subscription::subscribe(&conn, &url, &input.name, input.color.as_deref())?;
        let (stored, _) = subscription::apply(&conn, &collection, &objects)?;
        subscription::record(&conn, &collection, None)?;
        Ok(json!({ "calendar": format!("own:{}", collection.name), "events": stored }))
    })
    .await;
    match result {
        Ok(body) => Json(body).into_response(),
        Err(error) => refused(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    }
}

/// The user's subscription behind a calendar id (`own:<name>`).
fn find(
    state: &AppState,
    session: &Session,
    calendar: &str,
) -> anyhow::Result<Option<subscription::Subscription>> {
    let Some(name) = calendar.strip_prefix("own:") else {
        return Ok(None);
    };
    let conn = open(state, session)?;
    Ok(subscription::subscriptions(&conn)?
        .into_iter()
        .find(|s| s.collection.name == name))
}

async fn refresh_now(
    app: State<Shared>,
    headers: HeaderMap,
    Path(calendar): Path<String>,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let (lookup_state, lookup_session) = (state.clone(), session.clone());
    let found = match blocking(move || find(&lookup_state, &lookup_session, &calendar)).await {
        Ok(Some(found)) => found,
        Ok(None) => return refused(StatusCode::NOT_FOUND, "No such subscription."),
        Err(error) => return internal_error(error),
    };
    match refresh(
        state,
        session.domain,
        session.localpart,
        found.collection,
        found.url,
    )
    .await
    {
        Ok((stored, removed)) => {
            Json(json!({ "stored": stored, "removed": removed })).into_response()
        }
        Err(error) => refused(
            StatusCode::BAD_GATEWAY,
            &format!("The calendar could not be fetched: {error}"),
        ),
    }
}

async fn unsubscribe(
    app: State<Shared>,
    headers: HeaderMap,
    Path(calendar): Path<String>,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let result = blocking(move || {
        let Some(found) = find(&state, &session, &calendar)? else {
            return Ok(false);
        };
        let conn = open(&state, &session)?;
        subscription::unsubscribe(&conn, &found.collection)?;
        Ok(true)
    })
    .await;
    match result {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => refused(StatusCode::NOT_FOUND, "No such subscription."),
        Err(error) => internal_error(error),
    }
}

/// Refresh the subscriptions that are due, for every account, every
/// [`SWEEP_EVERY`], one at a time.
pub(crate) fn spawn_refresher(state: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(SWEEP_EVERY).await;
            let root = state.mail_root.clone();
            let due = blocking(move || {
                let mut due = Vec::new();
                for (domain, localpart, _) in imap_state::list_accounts(&root)? {
                    let Ok(conn) = rmail_common::jmap::store::open(&root, &domain, &localpart)
                    else {
                        continue;
                    };
                    for found in subscription::due(&conn).unwrap_or_default() {
                        due.push((domain.clone(), localpart.clone(), found));
                    }
                }
                Ok(due)
            })
            .await
            .unwrap_or_default();
            for (domain, localpart, found) in due {
                let account = format!("{localpart}@{domain}");
                if let Err(error) = refresh(
                    state.clone(),
                    domain,
                    localpart,
                    found.collection,
                    found.url,
                )
                .await
                {
                    webmail_log!("info", "subscription_refresh_failed", { "account": account, "error": error });
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::super::tests::{req, route, state};
    use super::super::{SESSION_COOKIE, sign_session};
    use serde_json::{Value, json};

    #[tokio::test]
    async fn private_feeds_are_refused_and_subscriptions_are_read_only() {
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
        for url in [
            "http://127.0.0.1/cal.ics",
            "webcal://localhost/cal.ics",
            "file:///etc/passwd",
        ] {
            let (status, refused) =
                call("POST", "/api/subscriptions".into(), json!({"url": url})).await;
            assert_eq!(status, 400, "{url}: {refused}");
        }

        // A subscription made directly (no network in tests) is listed
        // read-only and cannot be written to.
        let conn =
            rmail_common::jmap::store::open(&state.mail_root, "example.test", "user").unwrap();
        let url =
            rmail_common::dav::subscription::normalize_url("https://example.test/h.ics").unwrap();
        let collection =
            rmail_common::dav::subscription::subscribe(&conn, &url, "Holidays", None).unwrap();
        let (_, listing) = call("GET", "/api/events?from=0&to=86400".into(), Value::Null).await;
        let holidays = listing["calendars"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["displayname"] == "Holidays")
            .unwrap()
            .clone();
        assert_eq!(holidays["writable"], false);
        assert_eq!(
            holidays["subscription"]["url"],
            "https://example.test/h.ics"
        );
        let event = json!({"summary": "x", "start": 0, "end": 3600, "timezone": "UTC"});
        let (status, _) = call(
            "POST",
            format!("/api/events/own:{}", collection.name),
            event,
        )
        .await;
        assert_eq!(status, 403);
        // CalDAV clients cannot write into it, nor make such a calendar.
        let basic = format!(
            "Basic {}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                "user@example.test:secret"
            )
        );
        let dav = |method: &'static str, path: String, body: &'static str| {
            let (state, basic) = (state.clone(), basic.clone());
            async move {
                let mut request = req(method, &path, body.as_bytes(), None);
                request
                    .headers_mut()
                    .insert(axum::http::header::AUTHORIZATION, basic.parse().unwrap());
                route(request, &state).await.status
            }
        };
        let card = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:x\r\nBEGIN:VEVENT\r\nUID:z\r\nDTSTAMP:20260101T000000Z\r\nDTSTART:20260101T000000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let put = dav(
            "PUT",
            format!("/dav/calendars/user@example.test/{}/z.ics", collection.name),
            card,
        )
        .await;
        assert_eq!(put, 403);
        let made = dav(
            "MKCALENDAR",
            "/dav/calendars/user@example.test/subscription-mine/".into(),
            "",
        )
        .await;
        assert_eq!(made, 403);
        let (status, _) = call(
            "DELETE",
            format!("/api/subscriptions/own:{}", collection.name),
            Value::Null,
        )
        .await;
        assert_eq!(status, 204);
        assert!(
            rmail_common::dav::subscription::subscriptions(&conn)
                .unwrap()
                .is_empty()
        );
    }
}
