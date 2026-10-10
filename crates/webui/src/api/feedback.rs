//! Admin API for abuse feedback (ARF) reports received from mailbox
//! providers' feedback loops: who draws complaints, and the reports
//! themselves.

use std::collections::HashMap;
use std::path::Path;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rmail_common::feedback;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Shared, blocking, outcome, parse, require_db};

/// Reports listed at most.
const MAX_LIST: usize = 500;

pub(crate) fn routes() -> Router<Shared> {
    Router::new().route("/api/feedback", get(overview).delete(delete))
}

/// `?account=` narrows the reports to one account or domain; `?days=`
/// sets the summary window (default 30).
async fn overview(
    State(state): State<Shared>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let db = match require_db(&state) {
        Ok(db) => db,
        Err(err) => return err.into_response(),
    };
    let days = params
        .get("days")
        .and_then(|days| days.parse::<i64>().ok())
        .unwrap_or(30)
        .clamp(1, 365);
    let filter = params
        .get("account")
        .map(|account| account.trim().to_string())
        .filter(|account| !account.is_empty());
    let limit = params
        .get("limit")
        .and_then(|limit| limit.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, MAX_LIST);
    outcome(
        blocking(move || overview_sync(Path::new(&db), days, filter.as_deref(), limit)).await,
        StatusCode::INTERNAL_SERVER_ERROR,
    )
}

pub(crate) fn overview_sync(
    db: &Path,
    days: i64,
    filter: Option<&str>,
    limit: usize,
) -> anyhow::Result<Value> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let since = now - days * 24 * 3600;
    let conn = rmail_common::settings::open(db)?;
    let addresses = rmail_common::settings::get(&conn, "security.feedback_addresses")?
        .and_then(|value| serde_json::from_value::<Vec<String>>(value).ok())
        .unwrap_or_default();
    let threshold = rmail_common::settings::get(&conn, "security.feedback_complaint_threshold")?
        .and_then(|value| value.as_u64())
        .unwrap_or(5);
    drop(conn);
    Ok(json!({
        "addresses": addresses,
        "threshold": threshold,
        "days": days,
        "senders": feedback::summary(db, since)?,
        "reports": feedback::list(db, filter, limit)?,
    }))
}

#[derive(Deserialize)]
struct DeleteRequest {
    id: i64,
}

async fn delete(State(state): State<Shared>, body: Bytes) -> Response {
    let db = match require_db(&state) {
        Ok(db) => db,
        Err(err) => return err.into_response(),
    };
    let input: DeleteRequest = match parse(&body) {
        Ok(input) => input,
        Err(err) => return err.into_response(),
    };
    outcome(
        blocking(move || {
            if !feedback::delete(Path::new(&db), input.id)? {
                anyhow::bail!("no feedback report {}", input.id);
            }
            Ok(json!({"result": "ok"}))
        })
        .await,
        StatusCode::NOT_FOUND,
    )
}
