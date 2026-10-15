//! Calendar invitations in mail (iMIP, RFC 6047): the reading pane shows
//! the event a message carries and lets the user answer it, as calendar
//! clients do from the schedule inbox.
//!
//! - Answering an invitation stores the event in the user's calendar with
//!   their answer and sends the reply through CalDAV scheduling
//!   (`dav::schedule`), so it reaches the organizer exactly as one made in
//!   Thunderbird or Apple Calendar would.
//! - A cancellation marks the user's copy cancelled. Neither happens on
//!   delivery: anyone can send mail, so only the user's click writes into
//!   their calendar (see `rmail_common::dav::imip`).
//! - A reply the server could not vouch for on delivery (no DMARC for the
//!   attendee's domain) can be applied to the organizer's copy here.
//! - Only invitations in the user's own folders can be answered; one in a
//!   folder shared by someone else is shown but not acted on.

use rmail_common::dav::imip;
use rmail_common::dav::itip::{self, Method, Role};
use rmail_common::dav::store::{self, Object, Prepared, PutError, ScheduleTag};
use rmail_common::dav::text::{self, Component, Property};
use rmail_common::dav::{recur, text::time_bounds};
use rmail_common::db;
use rmail_common::mime::{self, CalendarPart};
use rusqlite::Connection;
use serde::Serialize;
use std::sync::Arc;

use super::AppState;
use crate::dav::{Dav, schedule};
use crate::jmap::User;

/// Attendees listed on the card; a large meeting shows a count beyond.
const MAX_ATTENDEES: usize = 50;
const MAX_DESCRIPTION_CHARS: usize = 2_000;

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct Person {
    pub address: String,
    pub name: String,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attendee {
    pub address: String,
    pub name: String,
    /// `accepted`, `declined`, `tentative`, `needs-action` or another
    /// PARTSTAT lower-cased.
    pub status: String,
}

/// What the reading pane shows for a message with a calendar part.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct Invitation {
    /// `request`, `cancel` or `reply`.
    pub method: &'static str,
    pub summary: String,
    pub location: String,
    pub description: String,
    /// Unix seconds; the end is exclusive.
    pub start: Option<i64>,
    pub end: Option<i64>,
    pub all_day: bool,
    pub recurring: bool,
    pub organizer: Option<Person>,
    pub attendees: Vec<Attendee>,
    pub more_attendees: usize,
    /// The user's address the message names them by.
    pub you: Option<String>,
    /// The user's answer: from their calendar copy when there is one.
    pub your_status: Option<String>,
    /// For a reply: who answered and how.
    pub replier: Option<Attendee>,
    /// - `new`: an invitation not in the user's calendar yet;
    /// - `in_calendar`: in the user's calendar;
    /// - `outdated`: the calendar holds a newer version;
    /// - `cancelled`: a cancellation already applied;
    /// - `not_invited`: the message does not name the user as an attendee
    ///   (a forwarded invitation, say), or a reply about an event they do
    ///   not organize here;
    /// - `applied` / `not_applied`: a reply the organizer's copy shows or
    ///   does not show yet.
    pub state: &'static str,
    /// What the user can do: `accepted`, `tentative`, `declined` (answer),
    /// `cancel` (mark the copy cancelled), `apply` (apply a reply).
    pub actions: Vec<&'static str>,
}

fn status_of(property: &Property) -> String {
    property
        .param("PARTSTAT")
        .unwrap_or("NEEDS-ACTION")
        .to_ascii_lowercase()
}

fn person(property: &Property) -> Option<Person> {
    let address = itip::address(&property.value)?;
    let name = property
        .param("CN")
        .map(str::trim)
        .filter(|name| !name.is_empty() && !name.eq_ignore_ascii_case(&address))
        .unwrap_or_default()
        .to_string();
    Some(Person { address, name })
}

fn first_event(calendar: &Component) -> Option<&Component> {
    calendar
        .components
        .iter()
        .find(|component| component.name != "VTIMEZONE")
}

/// The master component, or the first override when there is none.
fn main_component(calendar: &Component) -> Option<&Component> {
    calendar
        .components
        .iter()
        .filter(|component| component.name != "VTIMEZONE")
        .find(|component| component.property("RECURRENCE-ID").is_none())
        .or_else(|| first_event(calendar))
}

fn sequence(calendar: &Component) -> i64 {
    main_component(calendar)
        .and_then(|component| component.property("SEQUENCE"))
        .and_then(|sequence| sequence.value.trim().parse().ok())
        .unwrap_or(0)
}

fn uid(calendar: &Component) -> Option<String> {
    first_event(calendar)
        .and_then(|component| component.property("UID"))
        .map(|uid| uid.value.trim().to_string())
}

fn text_value(component: &Component, name: &str) -> String {
    component
        .property(name)
        .map(|property| itip::unescape(&property.value).trim().to_string())
        .unwrap_or_default()
}

/// The user's answer in a calendar, under any of their addresses.
fn status_in(calendar: &Component, own: &[String]) -> Option<String> {
    main_component(calendar)?
        .properties_named("ATTENDEE")
        .find(|attendee| {
            itip::address(&attendee.value)
                .is_some_and(|address| own.iter().any(|own| own.eq_ignore_ascii_case(&address)))
        })
        .map(status_of)
}

fn cancelled(calendar: &Component) -> bool {
    main_component(calendar)
        .and_then(|component| component.property("STATUS"))
        .is_some_and(|status| status.value.trim().eq_ignore_ascii_case("CANCELLED"))
}

/// The one attendee a reply is from (RFC 5546 3.2.3).
fn replier(calendar: &Component) -> Option<&Property> {
    let mut found: Option<&Property> = None;
    for attendee in calendar
        .components
        .iter()
        .filter(|component| component.name != "VTIMEZONE")
        .flat_map(|component| component.properties_named("ATTENDEE"))
    {
        match found {
            Some(first) if itip::address(&first.value) != itip::address(&attendee.value) => {
                return None;
            }
            Some(_) => {}
            None => found = Some(attendee),
        }
    }
    found
}

/// The calendar a message carries, if it is an iTIP message.
fn message_calendar(message: &[u8]) -> Option<(Method, Component)> {
    match mime::calendar_part(message, imip::MAX_CALENDAR_BYTES) {
        CalendarPart::Found(data) => imip::scheduling_object(&data).ok()?.ok(),
        CalendarPart::Missing | CalendarPart::TooLarge => None,
    }
}

/// The card for `message`, judged against the user's calendars in `conn`;
/// `can_act` is false for a message in someone else's folder.
pub(crate) fn invitation(
    message: &[u8],
    conn: &Connection,
    own: &[String],
    can_act: bool,
) -> Option<Invitation> {
    let (method, calendar) = message_calendar(message)?;
    let event = main_component(&calendar)?;
    let (start, end) = time_bounds(&calendar);
    let all_day = event.property("DTSTART").is_some_and(|start| {
        start
            .param("VALUE")
            .is_some_and(|v| v.eq_ignore_ascii_case("DATE"))
    });
    // Exact times for the card; `time_bounds` widens floating times.
    let start = event.property("DTSTART").and_then(recur::instant).or(start);
    let end = event
        .property("DTEND")
        .and_then(recur::instant)
        .or_else(|| {
            let duration = event
                .property("DURATION")
                .and_then(|duration| text::parse_duration(&duration.value))?;
            Some(start? + duration.max(0))
        })
        .or(end);
    let attendees = event
        .properties_named("ATTENDEE")
        .filter_map(|attendee| {
            let person = person(attendee)?;
            Some(Attendee {
                address: person.address,
                name: person.name,
                status: status_of(attendee),
            })
        })
        .collect::<Vec<_>>();
    let you = itip::own_address(&calendar, own)
        .filter(|address| itip::role(&calendar, address) != Role::None)
        .map(str::to_string);
    let copy = uid(&calendar)
        .and_then(|uid| store::find_by_uid(conn, &uid).ok().flatten())
        .and_then(|(_, object)| text::parse(&object.data).ok());
    let mut actions = Vec::new();
    let mut your_status = None;
    let mut replier_card = None;
    let state = match method {
        Method::Request => {
            your_status = copy
                .as_ref()
                .and_then(|copy| status_in(copy, own))
                .or_else(|| status_in(&calendar, own));
            let invited = you
                .as_deref()
                .is_some_and(|you| itip::role(&calendar, you) == Role::Attendee);
            match &copy {
                _ if !invited => "not_invited",
                Some(copy) if sequence(copy) > sequence(&calendar) => "outdated",
                Some(copy) if cancelled(copy) => "cancelled",
                Some(_) => {
                    actions.extend(["accepted", "tentative", "declined"]);
                    "in_calendar"
                }
                None => {
                    actions.extend(["accepted", "tentative", "declined"]);
                    "new"
                }
            }
        }
        Method::Cancel => match &copy {
            Some(copy) if sequence(copy) > sequence(&calendar) => "outdated",
            Some(copy) if cancelled(copy) => "cancelled",
            Some(copy) if itip::organizer(copy) == itip::organizer(&calendar) => {
                actions.push("cancel");
                "in_calendar"
            }
            _ => "not_invited",
        },
        Method::Reply => {
            let from = replier(&calendar);
            replier_card = from.and_then(|attendee| {
                let person = person(attendee)?;
                Some(Attendee {
                    address: person.address,
                    name: person.name,
                    status: status_of(attendee),
                })
            });
            let organizes = copy.as_ref().is_some_and(|copy| {
                own.iter()
                    .any(|address| itip::role(copy, address) == Role::Organizer)
            });
            match (&copy, &replier_card) {
                (Some(copy), Some(_)) if organizes && sequence(copy) > sequence(&calendar) => {
                    "outdated"
                }
                (Some(copy), Some(replier)) if organizes => {
                    let shown = main_component(copy).is_some_and(|event| {
                        event.properties_named("ATTENDEE").any(|attendee| {
                            itip::address(&attendee.value).as_deref()
                                == Some(replier.address.as_str())
                                && status_of(attendee) == replier.status
                        })
                    });
                    if shown {
                        "applied"
                    } else {
                        actions.push("apply");
                        "not_applied"
                    }
                }
                _ => "not_invited",
            }
        }
    };
    if !can_act {
        actions.clear();
    }
    // The guest list shows the user's own answer, not the one the
    // organizer last knew of.
    let mut attendees = attendees;
    if let (Some(you), Some(status)) = (&you, &your_status) {
        for attendee in attendees
            .iter_mut()
            .filter(|attendee| attendee.address.eq_ignore_ascii_case(you))
        {
            attendee.status = status.clone();
        }
    }
    let description = text_value(event, "DESCRIPTION");
    Some(Invitation {
        method: match method {
            Method::Request => "request",
            Method::Cancel => "cancel",
            Method::Reply => "reply",
        },
        summary: text_value(event, "SUMMARY"),
        location: text_value(event, "LOCATION"),
        description: description.chars().take(MAX_DESCRIPTION_CHARS).collect(),
        start,
        end,
        all_day,
        recurring: event.property("RRULE").is_some() || event.property("RDATE").is_some(),
        organizer: event.property("ORGANIZER").and_then(person),
        more_attendees: attendees.len().saturating_sub(MAX_ATTENDEES),
        attendees: attendees.into_iter().take(MAX_ATTENDEES).collect(),
        you,
        your_status,
        replier: replier_card,
        state,
        actions,
    })
}

/// Why an action could not be taken, for the user.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    NotAnInvitation,
    NotAllowed,
    /// The calendar changed in a way that makes the action moot (a newer
    /// version, someone else's event).
    Outdated,
}

impl Refused {
    pub fn message(&self) -> &'static str {
        match self {
            Refused::NotAnInvitation => "This message has no invitation to act on.",
            Refused::NotAllowed => "This can't be done for this invitation.",
            Refused::Outdated => "Your calendar has a newer version of this event.",
        }
    }
}

/// Every component's ATTENDEE line for `me` set to `partstat`, its RSVP
/// request answered.
fn set_answer(calendar: &mut Component, me: &str, partstat: &str) {
    for component in calendar
        .components
        .iter_mut()
        .filter(|component| component.name != "VTIMEZONE")
    {
        for attendee in component
            .properties
            .iter_mut()
            .filter(|property| property.name == "ATTENDEE")
        {
            if itip::address(&attendee.value).is_some_and(|found| found.eq_ignore_ascii_case(me)) {
                attendee.set_param("PARTSTAT", Some(partstat));
                attendee.set_param("RSVP", None);
            }
        }
    }
}

/// Take `action` on the invitation in `message` for `user`.
pub(crate) fn act(
    app: Arc<AppState>,
    user: User,
    message: &[u8],
    action: &str,
) -> anyhow::Result<Result<(), Refused>> {
    let Some((method, calendar)) = message_calendar(message) else {
        return Ok(Err(Refused::NotAnInvitation));
    };
    let Some(uid) = uid(&calendar) else {
        return Ok(Err(Refused::NotAnInvitation));
    };
    let conn = rmail_common::jmap::store::open(&app.mail_root, &user.domain, &user.localpart)?;
    let own = db::calendar_addresses(&app.db_path, &user.address)?;
    let dav = Dav { user, conn, app };
    let found = store::find_by_uid(&dav.conn, &uid)?;
    match (method, action) {
        (Method::Request, "accepted" | "tentative" | "declined") => {
            let Some(me) = itip::own_address(&calendar, &own)
                .filter(|me| itip::role(&calendar, me) == Role::Attendee)
                .map(str::to_string)
            else {
                return Ok(Err(Refused::NotAllowed));
            };
            let partstat = action.to_ascii_uppercase();
            let (collection, name) = match found {
                Some((collection, object)) => (collection, object.name),
                None => (
                    store::default_calendar(&dav.conn)?,
                    format!("{}.ics", schedule::random_name()),
                ),
            };
            let mut outgoing = Vec::new();
            // Built on the copy the write transaction holds, like a
            // client's PUT, so the reply is judged against it.
            let stored = store::put_with(&dav.conn, &collection, &name, &mut |current| {
                let copy = current.and_then(|object: &Object| text::parse(&object.data).ok());
                if copy
                    .as_ref()
                    .is_some_and(|copy| sequence(copy) > sequence(&calendar))
                {
                    return Err(PutError::PreconditionFailed);
                }
                let mut answered = itip::apply_request(copy.as_ref(), &calendar);
                set_answer(&mut answered, &me, &partstat);
                let (prepared, messages) =
                    schedule::prepare_put(&dav, &dav.user, current, &answered.to_text());
                outgoing = messages;
                Ok(prepared)
            })?;
            match stored {
                Ok(_) => {
                    schedule::deliver(&dav, outgoing);
                    Ok(Ok(()))
                }
                Err(PutError::PreconditionFailed) => Ok(Err(Refused::Outdated)),
                Err(error) => anyhow::bail!("storing the event: {error:?}"),
            }
        }
        (Method::Cancel, "cancel") => {
            let Some((collection, object)) = found else {
                return Ok(Err(Refused::NotAllowed));
            };
            let stored = store::put_with(&dav.conn, &collection, &object.name, &mut |current| {
                let copy = current
                    .and_then(|object| text::parse(&object.data).ok())
                    .filter(|copy| itip::organizer(copy) == itip::organizer(&calendar))
                    .ok_or(PutError::InvalidData(String::new()))?;
                // An older cancellation than the copy (the event was
                // reinstated since) no longer applies.
                if sequence(&copy) > sequence(&calendar) {
                    return Err(PutError::PreconditionFailed);
                }
                Ok(Prepared {
                    data: itip::apply_cancel(&copy, &calendar).to_text(),
                    schedule_tag: ScheduleTag::New,
                })
            })?;
            match stored {
                Ok(_) => Ok(Ok(())),
                Err(PutError::PreconditionFailed) => Ok(Err(Refused::Outdated)),
                Err(PutError::InvalidData(_)) => Ok(Err(Refused::NotAllowed)),
                Err(error) => anyhow::bail!("storing the event: {error:?}"),
            }
        }
        (Method::Reply, "apply") => {
            let (Some((collection, object)), Some(attendee)) = (
                found,
                replier(&calendar).and_then(|attendee| itip::address(&attendee.value)),
            ) else {
                return Ok(Err(Refused::NotAllowed));
            };
            let stored = store::put_with(&dav.conn, &collection, &object.name, &mut |current| {
                let copy = current
                    .and_then(|object| text::parse(&object.data).ok())
                    .filter(|copy| {
                        own.iter()
                            .any(|address| itip::role(copy, address) == Role::Organizer)
                    })
                    .ok_or(PutError::InvalidData(String::new()))?;
                // A reply to an older version must not undo a newer answer.
                if sequence(&copy) > sequence(&calendar) {
                    return Err(PutError::PreconditionFailed);
                }
                let merged = itip::apply_reply(&copy, &calendar, &attendee)
                    .ok_or(PutError::InvalidData(String::new()))?;
                Ok(Prepared {
                    data: merged.to_text(),
                    schedule_tag: ScheduleTag::Keep,
                })
            })?;
            match stored {
                Ok(_) => Ok(Ok(())),
                Err(PutError::PreconditionFailed) => Ok(Err(Refused::Outdated)),
                Err(PutError::InvalidData(_)) => Ok(Err(Refused::NotAllowed)),
                Err(error) => anyhow::bail!("storing the event: {error:?}"),
            }
        }
        _ => Ok(Err(Refused::NotAllowed)),
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{req, route, state};
    use super::super::{SESSION_COOKIE, sign_session};
    use rmail_common::dav::store;
    use rmail_common::{db, imap_state};
    use serde_json::Value;

    const USER: &str = "user@example.test";
    const OTHER: &str = "other@example.test";

    fn mail(method: &str, event: &str) -> Vec<u8> {
        format!(
            "From: someone@example.test\r\nTo: {USER}\r\nSubject: iMIP\r\nMIME-Version: 1.0\r\n\
             Content-Type: text/calendar; method={method}; charset=utf-8\r\n\r\n\
             BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nMETHOD:{method}\r\n{event}END:VCALENDAR\r\n"
        )
        .into_bytes()
    }

    fn event(uid: &str, organizer: &str, attendee: &str, partstat: &str, extra: &str) -> String {
        format!(
            "BEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:20261001T000000Z\r\nSEQUENCE:0\r\n\
             DTSTART:20261020T090000Z\r\nDTEND:20261020T100000Z\r\nSUMMARY:Planning\\, Q4\r\n\
             LOCATION:Room 1\r\nORGANIZER;CN=Olive:mailto:{organizer}\r\n\
             ATTENDEE;PARTSTAT={partstat};RSVP=TRUE:mailto:{attendee}\r\n{extra}END:VEVENT\r\n"
        )
    }

    fn stored(root: &std::path::Path, localpart: &str, uid: &str) -> String {
        let conn = rmail_common::jmap::store::open(root, "example.test", localpart).unwrap();
        store::find_by_uid(&conn, uid).unwrap().unwrap().1.data
    }

    #[tokio::test]
    async fn invitations_are_shown_answered_cancelled_and_replies_applied() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        db::add_mailbox(&state.db_path, OTHER, Some("plain:secret"), None, None).unwrap();
        let root = state.mail_root.clone();
        let cookie = Some(format!("{SESSION_COOKIE}={}", sign_session(&state, USER)));
        let call = |method: &'static str, path: String, body: &'static str| {
            let (state, cookie) = (state.clone(), cookie.clone());
            async move {
                let response = route(req(method, &path, body.as_bytes(), cookie), &state).await;
                let json: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
                (response.status, json)
            }
        };
        let deliver = |data: Vec<u8>| {
            imap_state::deliver_message(&root, "example.test", "user", &data)
                .unwrap()
                .1
        };

        // The organizer, an account here, has the event with the user invited.
        let organizer_copy = format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n{}END:VCALENDAR\r\n",
            event("inv-1", OTHER, USER, "NEEDS-ACTION", "")
        );
        {
            let conn = rmail_common::jmap::store::open(&root, "example.test", "other").unwrap();
            let calendar = store::default_calendar(&conn).unwrap();
            store::put(&conn, &calendar, "inv.ics", &organizer_copy, &|_| true)
                .unwrap()
                .unwrap();
        }
        let uid = deliver(mail(
            "REQUEST",
            &event("inv-1", OTHER, USER, "NEEDS-ACTION", ""),
        ));
        let (status, detail) = call("GET", format!("/api/folders/INBOX/messages/{uid}"), "").await;
        assert_eq!(status, 200);
        let card = &detail["invitation"];
        assert_eq!(card["method"], "request");
        assert_eq!(card["state"], "new");
        assert_eq!(card["summary"], "Planning, Q4");
        assert_eq!(card["location"], "Room 1");
        assert_eq!(card["organizer"]["name"], "Olive");
        assert_eq!(card["you"], USER);
        assert_eq!(card["start"], 1_792_486_800);
        assert_eq!(card["end"], 1_792_490_400);
        assert_eq!(
            card["actions"],
            serde_json::json!(["accepted", "tentative", "declined"])
        );

        let path = format!("/api/folders/INBOX/messages/{uid}/invitation");
        let (status, answered) = call("POST", path.clone(), r#"{"action":"accepted"}"#).await;
        assert_eq!(status, 200, "{answered}");
        assert_eq!(answered["invitation"]["state"], "in_calendar");
        assert_eq!(answered["invitation"]["your_status"], "accepted");
        assert_eq!(answered["invitation"]["attendees"][0]["status"], "accepted");
        let copy = stored(&root, "user", "inv-1");
        assert!(copy.contains("PARTSTAT=ACCEPTED") && !copy.contains("RSVP"));
        assert!(
            stored(&root, "other", "inv-1").contains("PARTSTAT=ACCEPTED"),
            "the reply reached the organizer"
        );
        let (status, _) = call("POST", path.clone(), r#"{"action":"apply"}"#).await;
        assert_eq!(status, 409, "not a reply");

        // An older version of the invitation can no longer be answered.
        let newer =
            event("inv-1", OTHER, USER, "NEEDS-ACTION", "").replace("SEQUENCE:0", "SEQUENCE:2");
        let newer_uid = deliver(mail("REQUEST", &newer));
        call(
            "POST",
            format!("/api/folders/INBOX/messages/{newer_uid}/invitation"),
            r#"{"action":"tentative"}"#,
        )
        .await;
        let (_, detail) = call("GET", format!("/api/folders/INBOX/messages/{uid}"), "").await;
        assert_eq!(detail["invitation"]["state"], "outdated");
        assert_eq!(detail["invitation"]["actions"], serde_json::json!([]));
        let (status, _) = call("POST", path, r#"{"action":"declined"}"#).await;
        assert_eq!(status, 409);

        // A cancellation older than the calendar's copy is moot.
        let stale_cancel = deliver(mail(
            "CANCEL",
            &event("inv-1", OTHER, USER, "NEEDS-ACTION", "STATUS:CANCELLED\r\n")
                .replace("SEQUENCE:0", "SEQUENCE:1"),
        ));
        let (_, detail) = call(
            "GET",
            format!("/api/folders/INBOX/messages/{stale_cancel}"),
            "",
        )
        .await;
        assert_eq!(detail["invitation"]["state"], "outdated");
        let (status, _) = call(
            "POST",
            format!("/api/folders/INBOX/messages/{stale_cancel}/invitation"),
            r#"{"action":"cancel"}"#,
        )
        .await;
        assert_eq!(status, 409);
        assert!(!stored(&root, "user", "inv-1").contains("STATUS:CANCELLED"));

        // The organizer cancels.
        let cancel_uid = deliver(mail(
            "CANCEL",
            &event("inv-1", OTHER, USER, "NEEDS-ACTION", "STATUS:CANCELLED\r\n")
                .replace("SEQUENCE:0", "SEQUENCE:3"),
        ));
        let cancel_path = format!("/api/folders/INBOX/messages/{cancel_uid}/invitation");
        let (_, detail) = call(
            "GET",
            format!("/api/folders/INBOX/messages/{cancel_uid}"),
            "",
        )
        .await;
        assert_eq!(
            detail["invitation"]["actions"],
            serde_json::json!(["cancel"])
        );
        let (status, cancelled) = call("POST", cancel_path, r#"{"action":"cancel"}"#).await;
        assert_eq!(status, 200, "{cancelled}");
        assert_eq!(cancelled["invitation"]["state"], "cancelled");
        assert!(stored(&root, "user", "inv-1").contains("STATUS:CANCELLED"));

        // A remote guest's reply the server could not vouch for.
        let own_event = format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n{}END:VCALENDAR\r\n",
            event("own-1", USER, "guest@remote.test", "NEEDS-ACTION", "")
                .replace("SEQUENCE:0", "SEQUENCE:1")
        );
        {
            let conn = rmail_common::jmap::store::open(&root, "example.test", "user").unwrap();
            let calendar = store::default_calendar(&conn).unwrap();
            store::put(&conn, &calendar, "own.ics", &own_event, &|_| true)
                .unwrap()
                .unwrap();
        }
        // A reply to an older version is moot.
        let stale_reply = deliver(mail(
            "REPLY",
            &event("own-1", USER, "guest@remote.test", "ACCEPTED", ""),
        ));
        let (_, detail) = call(
            "GET",
            format!("/api/folders/INBOX/messages/{stale_reply}"),
            "",
        )
        .await;
        assert_eq!(detail["invitation"]["state"], "outdated");
        let (status, _) = call(
            "POST",
            format!("/api/folders/INBOX/messages/{stale_reply}/invitation"),
            r#"{"action":"apply"}"#,
        )
        .await;
        assert_eq!(status, 409);
        let reply_uid = deliver(mail(
            "REPLY",
            &event("own-1", USER, "guest@remote.test", "DECLINED", "")
                .replace("SEQUENCE:0", "SEQUENCE:1"),
        ));
        let (_, detail) = call(
            "GET",
            format!("/api/folders/INBOX/messages/{reply_uid}"),
            "",
        )
        .await;
        let card = &detail["invitation"];
        assert_eq!(card["state"], "not_applied");
        assert_eq!(card["replier"]["status"], "declined");
        assert_eq!(card["actions"], serde_json::json!(["apply"]));
        let (status, applied) = call(
            "POST",
            format!("/api/folders/INBOX/messages/{reply_uid}/invitation"),
            r#"{"action":"apply"}"#,
        )
        .await;
        assert_eq!(status, 200, "{applied}");
        assert_eq!(applied["invitation"]["state"], "applied");
        assert!(stored(&root, "user", "own-1").contains("PARTSTAT=DECLINED"));

        // Plain mail has no card.
        let plain = deliver(b"From: a@b.test\r\nSubject: hi\r\n\r\nhello".to_vec());
        let (_, detail) = call("GET", format!("/api/folders/INBOX/messages/{plain}"), "").await;
        assert!(detail.get("invitation").is_none());
    }
}
