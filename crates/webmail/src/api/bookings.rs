//! Booking requests for a resource with an approver: the message the
//! approver gets carries a card with Approve and Decline, which answer for
//! the resource (see `dav::schedule::answer_booking`).

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use rmail_common::dav::{itip, store, text};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{AppState, Session, Shared, blocking, internal_error};
use crate::dav::schedule::{BOOKING_HEADER, BookingAnswer, answer_booking};
use crate::jmap::User;

pub(crate) fn routes() -> Router<Shared> {
    Router::new().route("/api/bookings/answer", post(answer))
}

/// What the approver sees of a booking.
#[derive(Serialize, Debug, PartialEq)]
pub(crate) struct Booking {
    pub resource: String,
    pub uid: String,
    pub summary: String,
    pub organizer: String,
    /// Unix seconds; for an all-day event, midnights UTC.
    pub start: i64,
    pub end: i64,
    pub all_day: bool,
    /// The resource's answer: `tentative` while it waits, `accepted`,
    /// `declined`, or `gone` when the event no longer books it.
    pub status: String,
}

/// The booking header of a message: (resource, event UID).
fn booking_header(message: &[u8]) -> Option<(String, String)> {
    let head = message
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .or_else(|| message.windows(2).position(|w| w == b"\n\n"))
        .map_or(message, |end| &message[..end]);
    let head = String::from_utf8_lossy(head).replace("\r\n", "\n");
    let unfolded = head.replace("\n ", " ").replace("\n\t", " ");
    let prefix = format!("{}:", BOOKING_HEADER.to_ascii_lowercase());
    unfolded.lines().find_map(|line| {
        let value = line
            .get(..prefix.len())
            .filter(|start| start.eq_ignore_ascii_case(&prefix))
            .map(|_| line[prefix.len()..].trim())?;
        let (resource, uid) = value.split_once(' ')?;
        Some((resource.trim().to_string(), uid.trim().to_string()))
    })
}

fn user_of(address: &str) -> Option<User> {
    let (localpart, domain) = address.split_once('@')?;
    Some(User {
        address: address.to_string(),
        domain: domain.to_string(),
        localpart: localpart.to_string(),
    })
}

/// The booking a resource's calendar holds, as its approver sees it.
fn booking(state: &AppState, resource: &str, uid: &str) -> anyhow::Result<Option<Booking>> {
    let Some(user) = user_of(resource) else {
        return Ok(None);
    };
    let conn = rmail_common::jmap::store::open(&state.mail_root, &user.domain, &user.localpart)?;
    let own = rmail_common::db::calendar_addresses(&state.db_path, resource)
        .unwrap_or_else(|_| vec![resource.to_string()]);
    let Some((_, object)) = store::find_by_uid(&conn, uid)? else {
        return Ok(Some(Booking {
            resource: resource.to_string(),
            uid: uid.to_string(),
            summary: String::new(),
            organizer: String::new(),
            start: 0,
            end: 0,
            all_day: false,
            status: "gone".into(),
        }));
    };
    let calendar = text::parse(&object.data)?;
    let organizer = itip::organizer(&calendar).unwrap_or_default();
    let Some(fields) = super::events::fields_of(&calendar, Some(&organizer)) else {
        return Ok(None);
    };
    let status = super::events::master(&calendar)
        .map(super::events::attendees_of)
        .unwrap_or_default()
        .into_iter()
        .find(|a| own.iter().any(|o| o.eq_ignore_ascii_case(&a.address)))
        .map_or_else(|| "gone".to_string(), |a| a.status);
    Ok(Some(Booking {
        resource: resource.to_string(),
        uid: uid.to_string(),
        summary: fields.summary,
        organizer,
        start: fields.start,
        end: fields.end,
        all_day: fields.all_day,
        status,
    }))
}

/// The booking card of a message, for the resource's approver only.
/// Failures only lose the card.
pub(crate) fn card(state: &AppState, session: &Session, message: &[u8]) -> Option<Booking> {
    let (resource, uid) = booking_header(message)?;
    let approver = rmail_common::resources::approver_of(&state.db_path, &resource).ok()??;
    if !approver.eq_ignore_ascii_case(&session.address) {
        return None;
    }
    booking(state, &approver_resource(&resource), &uid).ok()?
}

fn approver_resource(resource: &str) -> String {
    resource.trim().to_ascii_lowercase()
}

#[derive(Deserialize)]
struct Answer {
    resource: String,
    uid: String,
    approve: bool,
}

/// Approve or decline a booking; the updated card comes back.
async fn answer(State(state): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<Answer>(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid json").into_response();
    };
    let result = blocking(
        move || -> anyhow::Result<Result<Booking, (StatusCode, &str)>> {
            let resource = approver_resource(&input.resource);
            let approver = rmail_common::resources::approver_of(&state.db_path, &resource)?;
            if !approver.is_some_and(|a| a.eq_ignore_ascii_case(&session.address)) {
                return Ok(Err((
                    StatusCode::FORBIDDEN,
                    "You don't approve bookings of this resource.",
                )));
            }
            let Some(user) = user_of(&resource) else {
                return Ok(Err((StatusCode::NOT_FOUND, "No such resource.")));
            };
            match answer_booking(&state, &user, &input.uid, input.approve)? {
                BookingAnswer::Answered => {}
                BookingAnswer::Gone => {
                    return Ok(Err((
                        StatusCode::CONFLICT,
                        "This booking is no longer there to answer.",
                    )));
                }
                BookingAnswer::Clash => {
                    return Ok(Err((
                        StatusCode::CONFLICT,
                        "It now overlaps another booking of this resource, so it can't be approved.",
                    )));
                }
            }
            Ok(booking(&state, &resource, &input.uid)?.ok_or((
                StatusCode::CONFLICT,
                "This booking is no longer there to answer.",
            )))
        },
    )
    .await;
    match result {
        Ok(Ok(card)) => Json(json!({ "booking": card })).into_response(),
        Ok(Err((status, message))) => (status, Json(json!({ "error": message }))).into_response(),
        Err(error) => internal_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_names_resource_and_event() {
        let message = b"From: room@x.test\r\nX-Rmail-Booking: room@x.test\r\n abc-1\r\nSubject: s\r\n\r\nX-Rmail-Booking: no@x.test 2\r\n";
        assert_eq!(
            booking_header(message),
            Some(("room@x.test".to_string(), "abc-1".to_string()))
        );
        assert_eq!(booking_header(b"Subject: s\r\n\r\nbody"), None);
    }
}
