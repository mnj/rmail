//! The calendar in webmail: the user's CalDAV calendars (and those shared
//! with them) as events in a time range, with creating, editing and
//! deleting events.
//!
//! - Events live in the store CalDAV clients sync, so they show up on the
//!   user's phone and the other way round.
//! - Saving goes through CalDAV scheduling (`dav::schedule::prepare_put`
//!   and `prepare_delete`): inviting people, moving a meeting or deleting
//!   it sends the invitations, updates and cancellations a calendar client's
//!   change would. Events in a calendar shared with write access are
//!   scheduled as its owner (RFC 6638 3.2).
//! - Recurring events are listed occurrence by occurrence; editing one
//!   edits the series. A repeat rule webmail cannot express (every other
//!   Tuesday, say) is kept as it is unless the user picks another, and so
//!   are attendees' answers, alarms and every other property webmail does
//!   not show.
//! - Writes are conditional on the ETag the user saw.

use std::path::Path;

use axum::body::Bytes;
use axum::extract::{Path as UrlPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use rmail_common::dav::itip::{self, Role};
use rmail_common::dav::recur;
use rmail_common::dav::share::{self, Access};
use rmail_common::dav::store::{self, Collection, Kind, PutError};
use rmail_common::dav::text::{self, Component, Property};
use serde::{Deserialize, Serialize};

use super::{AppState, Session, Shared, blocking, internal_error};
use crate::dav::{Dav, schedule};
use crate::jmap::User;

/// The longest range listed at once.
const MAX_RANGE: i64 = 400 * 86_400;
const MAX_TEXT_CHARS: usize = 500;
const MAX_DESCRIPTION_CHARS: usize = 10_000;
pub(crate) const MAX_ATTENDEES: usize = 100;

pub(crate) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/events", get(list))
        .route("/api/events/{calendar}", post(create))
        .route("/api/events/{calendar}/{name}", put(update).delete(remove))
        .route("/api/resources", get(resources))
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
struct CalendarInfo {
    /// `own:<name>` or `shared:<owner>:<name>`.
    id: String,
    displayname: String,
    color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    writable: bool,
    /// For a subscribed feed: where from, when last fetched and why not.
    #[serde(skip_serializing_if = "Option::is_none")]
    subscription: Option<serde_json::Value>,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attendee {
    pub address: String,
    pub name: String,
    pub status: String,
}

/// What the editor shows and saves.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct EventFields {
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub location: String,
    #[serde(default)]
    pub description: String,
    /// Unix seconds. For an all-day event, midnight UTC of the first day,
    /// and `end` midnight UTC after the last.
    pub start: i64,
    pub end: i64,
    #[serde(default)]
    pub all_day: bool,
    /// The IANA zone the times are written in; empty or unknown is UTC.
    #[serde(default)]
    pub timezone: String,
    /// `none`, `daily`, `weekly`, `monthly`, `yearly`, or `custom` for a
    /// rule webmail cannot show (kept as it is).
    #[serde(default = "no_repeat")]
    pub repeat: String,
    /// Attendee addresses (the organizer is the calendar's owner).
    #[serde(default)]
    pub attendees: Vec<String>,
}

fn no_repeat() -> String {
    "none".to_string()
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
struct Event {
    calendar: String,
    name: String,
    etag: String,
    uid: String,
    /// This occurrence; for a single event, the event's own times.
    start: i64,
    end: i64,
    /// What the editor shows: the series (its own start and end) for a
    /// recurring event.
    details: EventFields,
    organizer: Option<String>,
    attendee_details: Vec<Attendee>,
    /// The user's answer when they are invited, else empty.
    my_status: String,
    /// Whether the user organizes it (or nobody is invited), so it may be
    /// edited rather than only answered.
    editable: bool,
    cancelled: bool,
}

#[derive(Serialize)]
struct Listing {
    calendars: Vec<CalendarInfo>,
    events: Vec<Event>,
}

// ---------------------------------------------------------------------------
// Reading events

fn text_of(component: &Component, name: &str) -> String {
    component
        .property(name)
        .map(|property| itip::unescape(&property.value).trim().to_string())
        .unwrap_or_default()
}

fn is_date(property: &Property) -> bool {
    property
        .param("VALUE")
        .is_some_and(|value| value.eq_ignore_ascii_case("DATE"))
        || property.value.trim().len() == 8
}

/// The repeat choice a rule corresponds to.
fn repeat_of(component: &Component) -> String {
    let Some(rule) = component.property("RRULE") else {
        return no_repeat();
    };
    let parts: Vec<(String, String)> = rule
        .value
        .split(';')
        .filter_map(|part| part.split_once('='))
        .map(|(key, value)| {
            (
                key.trim().to_ascii_uppercase(),
                value.trim().to_ascii_uppercase(),
            )
        })
        .collect();
    match parts.as_slice() {
        [(key, freq)] if key == "FREQ" => match freq.as_str() {
            "DAILY" => "daily",
            "WEEKLY" => "weekly",
            "MONTHLY" => "monthly",
            "YEARLY" => "yearly",
            _ => "custom",
        }
        .to_string(),
        _ => "custom".to_string(),
    }
}

/// The master event (no RECURRENCE-ID), or the first one.
pub(crate) fn master(calendar: &Component) -> Option<&Component> {
    let events = || calendar.components.iter().filter(|c| c.name == "VEVENT");
    events()
        .find(|c| c.property("RECURRENCE-ID").is_none())
        .or_else(|| events().next())
}

fn master_mut(calendar: &mut Component) -> Option<&mut Component> {
    let index = calendar
        .components
        .iter()
        .position(|c| c.name == "VEVENT" && c.property("RECURRENCE-ID").is_none())
        .or_else(|| calendar.components.iter().position(|c| c.name == "VEVENT"))?;
    calendar.components.get_mut(index)
}

fn span(component: &Component) -> (i64, i64, bool) {
    let start_property = component.property("DTSTART");
    let all_day = start_property.is_some_and(is_date);
    let start = start_property.and_then(recur::instant).unwrap_or_default();
    let end = component
        .property("DTEND")
        .and_then(recur::instant)
        .or_else(|| {
            component
                .property("DURATION")
                .and_then(|d| text::parse_duration(&d.value))
                .map(|d| start + d.max(0))
        })
        .unwrap_or(if all_day { start + 86_400 } else { start });
    (start, end, all_day)
}

pub(crate) fn attendees_of(component: &Component) -> Vec<Attendee> {
    component
        .properties_named("ATTENDEE")
        .filter_map(|attendee| {
            Some(Attendee {
                address: itip::address(&attendee.value)?,
                name: attendee.param("CN").unwrap_or_default().trim().to_string(),
                status: attendee
                    .param("PARTSTAT")
                    .unwrap_or("NEEDS-ACTION")
                    .to_ascii_lowercase(),
            })
        })
        .collect()
}

/// The fields of a calendar object's master event.
pub(crate) fn fields_of(calendar: &Component, organizer: Option<&str>) -> Option<EventFields> {
    let event = master(calendar)?;
    let (start, end, all_day) = span(event);
    Some(EventFields {
        summary: text_of(event, "SUMMARY"),
        location: text_of(event, "LOCATION"),
        description: text_of(event, "DESCRIPTION"),
        start,
        end,
        all_day,
        timezone: event
            .property("DTSTART")
            .and_then(|start| start.param("TZID"))
            .unwrap_or_default()
            .to_string(),
        repeat: repeat_of(event),
        attendees: attendees_of(event)
            .into_iter()
            .map(|attendee| attendee.address)
            .filter(|address| {
                organizer.is_none_or(|organizer| !address.eq_ignore_ascii_case(organizer))
            })
            .collect(),
    })
}

// ---------------------------------------------------------------------------
// Writing events

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace(',', "\\,")
        .replace(';', "\\;")
        .replace("\r\n", "\\n")
        .replace(['\n', '\r'], "\\n")
}

fn zone(name: &str) -> Option<chrono_tz::Tz> {
    name.trim().parse::<chrono_tz::Tz>().ok()
}

/// DTSTART or DTEND for `seconds`: a date for an all-day event, local time
/// with TZID in a known zone, else UTC.
fn time_property(name: &str, seconds: i64, all_day: bool, timezone: &str) -> Property {
    use chrono::TimeZone;
    let utc = chrono::Utc
        .timestamp_opt(seconds, 0)
        .single()
        .unwrap_or_default();
    if all_day {
        let mut property = Property::new(name, &utc.format("%Y%m%d").to_string());
        property.set_param("VALUE", Some("DATE"));
        property
    } else if let Some(tz) = zone(timezone).filter(|tz| *tz != chrono_tz::UTC) {
        let mut property = Property::new(
            name,
            &utc.with_timezone(&tz).format("%Y%m%dT%H%M%S").to_string(),
        );
        property.set_param("TZID", Some(tz.name()));
        property
    } else {
        Property::new(name, &recur::utc_text(seconds))
    }
}

fn set_text(event: &mut Component, name: &str, value: &str) {
    event
        .properties
        .retain(|p| !p.name.eq_ignore_ascii_case(name));
    if !value.trim().is_empty() {
        event
            .properties
            .push(Property::new(name, &escape(value.trim())));
    }
}

fn mailto(address: &str) -> String {
    format!("mailto:{address}")
}

/// `existing` (a whole calendar object) with the master event's fields set
/// from `fields`, or a new object. `organizer` is the calendar owner's
/// address, set when there are attendees.
fn calendar_text(
    existing: Option<&Component>,
    fields: &EventFields,
    uid: &str,
    organizer: &str,
    resources: &std::collections::HashMap<String, &'static str>,
) -> String {
    let mut calendar = existing.cloned().unwrap_or_else(|| {
        let mut calendar = Component::new("VCALENDAR");
        calendar.set_property("VERSION", "2.0");
        calendar.set_property("PRODID", "-//rMail//webmail//EN");
        let mut event = Component::new("VEVENT");
        event.set_property("UID", uid);
        calendar.components.push(event);
        calendar
    });
    let previous = existing.and_then(|calendar| fields_of(calendar, Some(organizer)));
    let Some(event) = master_mut(&mut calendar) else {
        return calendar.to_text();
    };
    set_text(event, "SUMMARY", &fields.summary);
    set_text(event, "LOCATION", &fields.location);
    set_text(event, "DESCRIPTION", &fields.description);
    let times_changed = previous.as_ref().is_none_or(|previous| {
        (previous.start, previous.end, previous.all_day)
            != (fields.start, fields.end, fields.all_day)
            || (!fields.timezone.is_empty() && previous.timezone != fields.timezone)
    });
    if times_changed {
        event
            .properties
            .retain(|p| !matches!(p.name.as_str(), "DTSTART" | "DTEND" | "DURATION"));
        event.properties.push(time_property(
            "DTSTART",
            fields.start,
            fields.all_day,
            &fields.timezone,
        ));
        event.properties.push(time_property(
            "DTEND",
            fields.end,
            fields.all_day,
            &fields.timezone,
        ));
    }
    if fields.repeat != "custom" {
        event.properties.retain(|p| p.name != "RRULE");
        if fields.repeat != "none" {
            event.properties.push(Property::new(
                "RRULE",
                &format!("FREQ={}", fields.repeat.to_ascii_uppercase()),
            ));
        }
    }
    // Attendees: those kept keep their line (and answer); new ones are
    // asked to reply; the organizer is the calendar's owner.
    let wanted: Vec<String> = fields
        .attendees
        .iter()
        .map(|address| address.trim().to_ascii_lowercase())
        .filter(|address| !address.is_empty() && !address.eq_ignore_ascii_case(organizer))
        .collect();
    event.properties.retain(|p| {
        p.name != "ATTENDEE"
            || itip::address(&p.value).is_some_and(|address| {
                address.eq_ignore_ascii_case(organizer) || wanted.contains(&address)
            })
    });
    for address in &wanted {
        let present = event
            .properties_named("ATTENDEE")
            .any(|p| itip::address(&p.value).as_deref() == Some(address.as_str()));
        if !present {
            let mut attendee = Property::new("ATTENDEE", &mailto(address));
            // Rooms and equipment say what they are (they answer themselves).
            if let Some(cutype) = resources.get(address) {
                attendee.set_param("CUTYPE", Some(cutype));
            }
            attendee.set_param("PARTSTAT", Some("NEEDS-ACTION"));
            attendee.set_param("RSVP", Some("TRUE"));
            event.properties.push(attendee);
        }
    }
    if wanted.is_empty() {
        event
            .properties
            .retain(|p| p.name != "ATTENDEE" && p.name != "ORGANIZER");
    } else if event.property("ORGANIZER").is_none() {
        event
            .properties
            .push(Property::new("ORGANIZER", &mailto(organizer)));
        let mut me = Property::new("ATTENDEE", &mailto(organizer));
        me.set_param("PARTSTAT", Some("ACCEPTED"));
        event.properties.push(me);
    }
    let sequence = event
        .property("SEQUENCE")
        .and_then(|s| s.value.trim().parse::<i64>().ok())
        .unwrap_or(0);
    if existing.is_some() {
        event.set_property("SEQUENCE", &(sequence + 1).to_string());
    }
    event.set_property("DTSTAMP", &recur::utc_text(chrono::Utc::now().timestamp()));
    calendar.to_text()
}

/// Why `fields` cannot be saved, for the user.
pub(crate) fn check(fields: &EventFields) -> Result<(), &'static str> {
    if fields.summary.chars().count() > MAX_TEXT_CHARS
        || fields.location.chars().count() > MAX_TEXT_CHARS
        || fields.description.chars().count() > MAX_DESCRIPTION_CHARS
        || fields.timezone.len() > 64
    {
        return Err("A field is too long.");
    }
    if fields.summary.contains(['\r', '\n']) || fields.location.contains(['\r', '\n']) {
        return Err("The title and place are one line each.");
    }
    if fields.end < fields.start
        || fields
            .end
            .checked_sub(fields.start)
            .is_none_or(|span| span > MAX_RANGE)
    {
        return Err("The event must end after it starts, within a year.");
    }
    if fields.all_day
        && (fields.start % 86_400 != 0 || fields.end % 86_400 != 0 || fields.end == fields.start)
    {
        return Err("An all-day event starts and ends on whole days.");
    }
    if !matches!(
        fields.repeat.as_str(),
        "none" | "daily" | "weekly" | "monthly" | "yearly" | "custom"
    ) {
        return Err("Unknown repeat.");
    }
    if fields.attendees.len() > MAX_ATTENDEES
        || fields
            .attendees
            .iter()
            .any(|a| rmail_common::domain::canonicalize_mailbox_address(a.trim()).is_err())
    {
        return Err("A guest's address is not valid.");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Calendars

struct Place {
    id: String,
    displayname: String,
    color: Option<String>,
    /// The calendar's owner: the user, or who shared it.
    owner: User,
    shared: bool,
    writable: bool,
    subscription: Option<serde_json::Value>,
    conn: rmail_common::sqlite_pool::SqliteConnection,
    collection: Collection,
}

fn user_of(address: &str) -> Option<User> {
    let (localpart, domain) = address.split_once('@')?;
    Some(User {
        address: address.to_string(),
        domain: domain.to_string(),
        localpart: localpart.to_string(),
    })
}

fn open(
    mail_root: &Path,
    user: &User,
) -> anyhow::Result<rmail_common::sqlite_pool::SqliteConnection> {
    rmail_common::jmap::store::open(mail_root, &user.domain, &user.localpart)
}

fn places(state: &AppState, session: &Session) -> anyhow::Result<Vec<Place>> {
    let me = User {
        address: session.address.clone(),
        domain: session.domain.clone(),
        localpart: session.localpart.clone(),
    };
    let mut found = Vec::new();
    let conn = open(&state.mail_root, &me)?;
    let subscriptions = rmail_common::dav::subscription::subscriptions(&conn)?;
    for collection in store::collections(&conn, Kind::Calendar)? {
        if collection.inbox
            || !(collection.components.is_empty()
                || collection.components.iter().any(|c| c == "VEVENT"))
        {
            continue;
        }
        found.push(Place {
            id: format!("own:{}", collection.name),
            displayname: collection
                .displayname
                .clone()
                .unwrap_or_else(|| collection.name.clone()),
            color: collection.color.clone(),
            owner: me.clone(),
            shared: false,
            // A subscription is filled from its feed only.
            writable: !collection.managed,
            subscription: subscriptions
                .iter()
                .find(|s| s.collection.id == collection.id)
                .map(|s| serde_json::json!({ "url": s.url, "refreshed_at": s.refreshed_at, "error": s.error })),
            conn: open(&state.mail_root, &me)?,
            collection,
        });
    }
    let grants = share::shared_with(&state.db_path, &session.address)?;
    for (grant, collection) in share::with_collections(&state.mail_root, grants)? {
        if collection.kind != Kind::Calendar {
            continue;
        }
        let Some(owner) = user_of(&grant.owner) else {
            continue;
        };
        found.push(Place {
            id: format!("shared:{}:{}", grant.owner, collection.name),
            displayname: grant
                .displayname
                .clone()
                .or_else(|| collection.displayname.clone())
                .unwrap_or_else(|| collection.name.clone()),
            color: grant.color.clone().or_else(|| collection.color.clone()),
            writable: grant.access == Access::ReadWrite && !collection.managed,
            subscription: None,
            shared: true,
            conn: open(&state.mail_root, &owner)?,
            owner,
            collection,
        });
    }
    Ok(found)
}

fn events_in(place: &Place, me: &[String], from: i64, until: i64) -> anyhow::Result<Vec<Event>> {
    let mut out = Vec::new();
    for object in store::objects(&place.conn, &place.collection)? {
        if object.component.as_deref() != Some("VEVENT")
            || object.start.is_some_and(|begin| begin >= until)
            || object.end.is_some_and(|finish| finish <= from)
        {
            continue;
        }
        let Ok(calendar) = text::parse(&object.data) else {
            continue;
        };
        let organizer = itip::organizer(&calendar);
        let Some(fields) = fields_of(&calendar, organizer.as_deref()) else {
            continue;
        };
        let Some(event) = master(&calendar) else {
            continue;
        };
        let owner = [place.owner.address.clone()];
        let addresses: &[String] = if place.shared { &owner } else { me };
        let role = addresses
            .iter()
            .map(|address| itip::role(&calendar, address))
            .find(|role| *role != Role::None)
            .unwrap_or(Role::None);
        let my_status = attendees_of(event)
            .into_iter()
            .find(|a| addresses.iter().any(|m| m.eq_ignore_ascii_case(&a.address)))
            .filter(|_| role == Role::Attendee)
            .map(|a| a.status)
            .unwrap_or_default();
        let uid = text_of(event, "UID");
        for occurrence in recur::occurrences(&calendar, from, until) {
            let component = &calendar.components[occurrence.component];
            let mut shown = fields.clone();
            // An overridden occurrence shows its own text.
            if component.property("RECURRENCE-ID").is_some() {
                shown.summary = text_of(component, "SUMMARY");
                shown.location = text_of(component, "LOCATION");
            }
            out.push(Event {
                calendar: place.id.clone(),
                name: object.name.clone(),
                etag: object.etag.clone(),
                uid: uid.clone(),
                start: occurrence.start,
                end: occurrence.end,
                details: shown,
                organizer: organizer.clone(),
                attendee_details: attendees_of(component),
                my_status: my_status.clone(),
                editable: place.writable && role != Role::Attendee,
                cancelled: text_of(component, "STATUS").eq_ignore_ascii_case("CANCELLED"),
            });
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Handlers

fn refused(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

/// The rooms and equipment in the user's domain, to invite to an event.
async fn resources(app: State<Shared>, headers: HeaderMap) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    match blocking(move || rmail_common::resources::list(&state.db_path, Some(&session.domain)))
        .await
    {
        Ok(list) => Json(
            list.into_iter()
                .map(|(address, kind)| serde_json::json!({ "address": address, "kind": kind }))
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => internal_error(error),
    }
}

#[derive(Deserialize)]
struct Range {
    from: i64,
    to: i64,
}

async fn list(app: State<Shared>, headers: HeaderMap, Query(range): Query<Range>) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    if range.to <= range.from
        || range
            .to
            .checked_sub(range.from)
            .is_none_or(|span| span > MAX_RANGE)
    {
        return refused(StatusCode::BAD_REQUEST, "invalid range");
    }
    let result = blocking(move || {
        let places = places(&state, &session)?;
        let me = rmail_common::db::calendar_addresses(&state.db_path, &session.address)
            .unwrap_or_else(|_| vec![session.address.clone()]);
        let mut events = Vec::new();
        for place in &places {
            events.extend(events_in(place, &me, range.from, range.to)?);
        }
        events.sort_by_key(|event| (event.start, event.end));
        Ok(Listing {
            calendars: places
                .into_iter()
                .map(|place| CalendarInfo {
                    id: place.id,
                    displayname: place.displayname,
                    color: place.color,
                    owner: place.shared.then(|| place.owner.address.clone()),
                    writable: place.writable,
                    subscription: place.subscription,
                })
                .collect(),
            events,
        })
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
    fields: EventFields,
    #[serde(default)]
    etag: Option<String>,
}

fn uuid() -> String {
    let bytes: [u8; 16] = rand::random();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

type Outcome = Result<(), (StatusCode, &'static str)>;
/// What saving an event came to: the resource name it is stored under.
pub(crate) type Saved = Result<String, (StatusCode, &'static str)>;

fn dav_for(state: &std::sync::Arc<AppState>, session: &Session) -> anyhow::Result<Dav> {
    let user = User {
        address: session.address.clone(),
        domain: session.domain.clone(),
        localpart: session.localpart.clone(),
    };
    Ok(Dav {
        conn: open(&state.mail_root, &user)?,
        user,
        app: state.clone(),
    })
}

/// Store `fields` in `calendar` (a place id, `own:<name>` or
/// `shared:<owner>:<name>`), as a new event or over `name` when the
/// stored version is still `etag`. With `schedule`, guests hear of the
/// change as from a CalDAV client.
/// What to store: the fields, the version they replace (`etag`), whether
/// guests hear of it, and a UID for a new event (else one is made).
pub(crate) struct Change {
    pub fields: EventFields,
    pub etag: Option<String>,
    pub schedule: bool,
    pub uid: Option<String>,
}

pub(crate) fn save(
    state: &std::sync::Arc<AppState>,
    session: &Session,
    calendar: &str,
    name: Option<&str>,
    change: Change,
) -> anyhow::Result<Saved> {
    let Change {
        fields,
        etag,
        schedule,
        uid,
    } = change;
    let Some(place) = places(state, session)?
        .into_iter()
        .find(|p| p.id == calendar)
    else {
        return Ok(Err((StatusCode::NOT_FOUND, "No such calendar.")));
    };
    if !place.writable {
        return Ok(Err((
            StatusCode::FORBIDDEN,
            "This calendar is shared with you read-only.",
        )));
    }
    let dav = dav_for(state, session)?;
    let owner_addresses =
        rmail_common::db::calendar_addresses(&state.db_path, &place.owner.address)
            .unwrap_or_else(|_| vec![place.owner.address.clone()]);
    let uid = uid.unwrap_or_else(uuid);
    let resource_types: std::collections::HashMap<String, &'static str> =
        rmail_common::resources::list(&state.db_path, None)?
            .into_iter()
            .map(|(address, kind)| (address, kind.cutype()))
            .collect();
    // A client's UID names the resource only when it is safe in a URL
    // path; otherwise the event keeps its UID under a generated name.
    let name = name.map_or_else(
        || {
            let safe = !uid.is_empty()
                && uid.len() <= 200
                && uid
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
            format!("{}.ics", if safe { uid.clone() } else { uuid() })
        },
        str::to_string,
    );
    let mut outgoing = Vec::new();
    let stored = store::put_with(&place.conn, &place.collection, &name, &mut |current| {
        match (current, &etag) {
            (None, None) => {}
            (Some(object), Some(etag)) if &object.etag == etag => {}
            _ => return Err(PutError::PreconditionFailed),
        }
        let existing = current.and_then(|object| text::parse(&object.data).ok());
        // An invitation is answered, not edited, whichever of the owner's
        // addresses it was sent to.
        if existing.as_ref().is_some_and(|calendar| {
            owner_addresses
                .iter()
                .any(|address| itip::role(calendar, address) == Role::Attendee)
        }) {
            return Err(PutError::InvalidData("attendee".into()));
        }
        let data = calendar_text(
            existing.as_ref(),
            &fields,
            &uid,
            &place.owner.address,
            &resource_types,
        );
        if !schedule {
            return Ok(store::Prepared {
                data,
                schedule_tag: store::ScheduleTag::Keep,
            });
        }
        let (prepared, messages) = schedule::prepare_put(&dav, &place.owner, current, &data);
        outgoing = messages;
        Ok(prepared)
    })?;
    Ok(match stored {
        Ok(_) => {
            schedule::deliver(&dav, outgoing);
            Ok(name)
        }
        Err(PutError::PreconditionFailed) => Err((
            StatusCode::CONFLICT,
            "This event was changed elsewhere. Reload and try again.",
        )),
        Err(PutError::InvalidData(reason)) if reason == "attendee" => Err((
            StatusCode::FORBIDDEN,
            "You are invited to this event; answer it instead of editing it.",
        )),
        Err(error) => anyhow::bail!("storing the event: {error:?}"),
    })
}

async fn write(
    state: Shared,
    headers: HeaderMap,
    calendar: String,
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
    if name.is_some() && input.etag.is_none() {
        return refused(StatusCode::BAD_REQUEST, "missing etag");
    }
    if let Err(message) = check(&input.fields) {
        return refused(StatusCode::BAD_REQUEST, message);
    }
    let result = blocking(move || {
        save(
            &state,
            &session,
            &calendar,
            name.as_deref(),
            Change {
                fields: input.fields,
                etag: input.etag,
                schedule: true,
                uid: None,
            },
        )
    })
    .await;
    match result {
        Ok(Ok(_)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err((status, message))) => refused(status, message),
        Err(error) => internal_error(error),
    }
}

async fn create(
    app: State<Shared>,
    headers: HeaderMap,
    UrlPath(calendar): UrlPath<String>,
    body: Bytes,
) -> Response {
    write(app.0, headers, calendar, None, body).await
}

async fn update(
    app: State<Shared>,
    headers: HeaderMap,
    UrlPath((calendar, name)): UrlPath<(String, String)>,
    body: Bytes,
) -> Response {
    write(app.0, headers, calendar, Some(name), body).await
}

#[derive(Deserialize)]
struct Remove {
    etag: String,
}

async fn remove(
    app: State<Shared>,
    headers: HeaderMap,
    UrlPath((calendar, name)): UrlPath<(String, String)>,
    body: Bytes,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<Remove>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "missing etag");
    };
    let result =
        blocking(move || remove_event(&state, &session, &calendar, &name, Some(input.etag), true))
            .await;
    match result {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err((status, message))) => refused(status, message),
        Err(error) => internal_error(error),
    }
}

/// Delete event `name` from `calendar` (when still at `etag`, if given);
/// with `schedule`, guests hear of it.
pub(crate) fn remove_event(
    state: &std::sync::Arc<AppState>,
    session: &Session,
    calendar: &str,
    name: &str,
    etag: Option<String>,
    schedule: bool,
) -> anyhow::Result<Outcome> {
    let Some(place) = places(state, session)?
        .into_iter()
        .find(|p| p.id == calendar)
    else {
        return Ok(Err((StatusCode::NOT_FOUND, "No such calendar.")));
    };
    if !place.writable {
        return Ok(Err((
            StatusCode::FORBIDDEN,
            "This calendar is shared with you read-only.",
        )));
    }
    let precondition = |current: Option<&store::Object>| {
        current.is_some_and(|o| etag.as_ref().is_none_or(|etag| &o.etag == etag))
    };
    Ok(
        match store::delete(&place.conn, &place.collection, name, &precondition)? {
            store::Deleted::Deleted(previous) => {
                // Cancellations from the organizer, a decline from a guest.
                if schedule {
                    let dav = dav_for(state, session)?;
                    let messages = schedule::prepare_delete(&dav, &place.owner, &previous);
                    schedule::deliver(&dav, messages);
                }
                Ok(())
            }
            store::Deleted::NotFound => Err((StatusCode::NOT_FOUND, "The event is gone.")),
            store::Deleted::PreconditionFailed => Err((
                StatusCode::CONFLICT,
                "This event was changed elsewhere. Reload and try again.",
            )),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::super::tests::{req, route, state};
    use super::super::{SESSION_COOKIE, sign_session};
    use super::*;
    use rmail_common::db;
    use serde_json::{Value, json};

    const ME: &str = "user@example.test";
    /// 2026-10-20 09:00 in Copenhagen (07:00 UTC).
    const NINE: i64 = 1_792_479_600;

    fn fields() -> EventFields {
        EventFields {
            summary: "Review; Q4, budget".into(),
            location: "Room 1".into(),
            description: "Line one\nLine two".into(),
            start: NINE,
            end: NINE + 3_600,
            all_day: false,
            timezone: "Europe/Copenhagen".into(),
            repeat: "weekly".into(),
            attendees: Vec::new(),
        }
    }

    #[test]
    fn new_events_are_written_in_the_users_zone() {
        let data = calendar_text(None, &fields(), "u-1", ME, &Default::default());
        let calendar = text::parse(&data).unwrap();
        let event = master(&calendar).unwrap();
        let start = event.property("DTSTART").unwrap();
        assert_eq!(start.value, "20261020T090000");
        assert_eq!(start.param("TZID"), Some("Europe/Copenhagen"));
        assert_eq!(recur::instant(start), Some(NINE));
        assert!(data.contains(r"SUMMARY:Review\; Q4\, budget"));
        assert!(data.contains("RRULE:FREQ=WEEKLY"));
        assert!(event.property("ORGANIZER").is_none(), "nobody invited");
        assert_eq!(fields_of(&calendar, Some(ME)).unwrap(), fields());

        let all_day = EventFields {
            all_day: true,
            start: 1_792_454_400,
            end: 1_792_540_800,
            repeat: "none".into(),
            ..fields()
        };
        let data = calendar_text(None, &all_day, "u-2", ME, &Default::default());
        assert!(data.contains("DTSTART;VALUE=DATE:20261020"));
        assert!(data.contains("DTEND;VALUE=DATE:20261021"));
        assert!(check(&all_day).is_ok());
        assert!(
            check(&EventFields {
                start: 1_792_454_401,
                ..all_day
            })
            .is_err()
        );
    }

    #[test]
    fn editing_keeps_what_webmail_does_not_show() {
        let existing = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Apple//EN\r\nBEGIN:VEVENT\r\nUID:x\r\n\
            DTSTAMP:20261001T000000Z\r\nSEQUENCE:2\r\nDTSTART;TZID=Europe/Copenhagen:20261020T090000\r\n\
            DTEND;TZID=Europe/Copenhagen:20261020T100000\r\nSUMMARY:Standup\r\n\
            RRULE:FREQ=WEEKLY;INTERVAL=2;BYDAY=TU\r\nORGANIZER:mailto:user@example.test\r\n\
            ATTENDEE;PARTSTAT=ACCEPTED:mailto:user@example.test\r\n\
            ATTENDEE;CN=Bob;PARTSTAT=ACCEPTED:mailto:bob@example.test\r\n\
            ATTENDEE;PARTSTAT=DECLINED:mailto:eve@example.test\r\n\
            BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT10M\r\nDESCRIPTION:Reminder\r\nEND:VALARM\r\n\
            X-APPLE-TRAVEL-ADVISORY-BEHAVIOR:AUTOMATIC\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let calendar = text::parse(existing).unwrap();
        let mut edited = fields_of(&calendar, Some(ME)).unwrap();
        assert_eq!(edited.repeat, "custom");
        assert_eq!(edited.attendees, ["bob@example.test", "eve@example.test"]);
        edited.summary = "Standup (new room)".into();
        edited.attendees = vec!["bob@example.test".into(), "ann@example.test".into()];
        let data = calendar_text(Some(&calendar), &edited, "ignored", ME, &Default::default());
        for kept in [
            "RRULE:FREQ=WEEKLY;INTERVAL=2;BYDAY=TU",
            "BEGIN:VALARM",
            "X-APPLE-TRAVEL-ADVISORY-BEHAVIOR:AUTOMATIC",
            "CN=Bob;PARTSTAT=ACCEPTED:mailto:bob@example.test",
            "DTSTART;TZID=Europe/Copenhagen:20261020T090000",
            "SEQUENCE:3",
            "UID:x",
        ] {
            assert!(data.contains(kept), "{kept} lost:\n{data}");
        }
        assert!(!data.contains("eve@example.test"), "removed guest");
        assert!(data.contains("PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:ann@example.test"));

        edited.attendees.clear();
        edited.repeat = "none".into();
        let data = calendar_text(Some(&calendar), &edited, "ignored", ME, &Default::default());
        assert!(
            !data.contains("ORGANIZER") && !data.contains("ATTENDEE") && !data.contains("RRULE")
        );
    }

    #[tokio::test]
    async fn events_are_listed_scheduled_edited_and_deleted() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        db::add_mailbox(
            &state.db_path,
            "other@example.test",
            Some("plain:x"),
            None,
            None,
        )
        .unwrap();
        let call = |user: &'static str, method: &'static str, path: String, body: Value| {
            let state = state.clone();
            async move {
                let cookie = Some(format!("{SESSION_COOKIE}={}", sign_session(&state, user)));
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
        let range = |from: i64, to: i64| format!("/api/events?from={from}&to={to}");
        let (status, listing) =
            call(ME, "GET", range(NINE - 86_400, NINE + 86_400), Value::Null).await;
        assert_eq!(status, 200);
        assert_eq!(listing["calendars"][0]["id"], "own:default");

        let mut event = serde_json::to_value(fields()).unwrap();
        event["attendees"] = json!(["other@example.test"]);
        let (status, created) =
            call(ME, "POST", "/api/events/own:default".into(), event.clone()).await;
        assert_eq!(status, 204, "{created}");

        // Three weekly occurrences in three weeks.
        let (_, listing) = call(
            ME,
            "GET",
            range(NINE - 3_600, NINE + 21 * 86_400 - 3_600),
            Value::Null,
        )
        .await;
        let events = listing["events"].as_array().unwrap();
        assert_eq!(events.len(), 3, "{listing}");
        // Clocks go back on 25 October; the meeting stays at 09:00 local.
        assert_eq!(events[1]["start"], NINE + 7 * 86_400 + 3_600);
        assert_eq!(events[0]["editable"], true);
        assert_eq!(events[0]["details"]["summary"], "Review; Q4, budget");
        assert_eq!(events[2]["details"]["start"], NINE, "the series' own start");

        // The guest got the invitation, and may answer but not edit.
        let (_, theirs) = call(
            "other@example.test",
            "GET",
            range(NINE - 3_600, NINE + 3_600),
            Value::Null,
        )
        .await;
        let invited = &theirs["events"][0];
        assert_eq!(invited["my_status"], "needs-action");
        assert_eq!(invited["editable"], false);
        let mut change = serde_json::to_value(fields()).unwrap();
        change["etag"] = invited["etag"].clone();
        let (status, _) = call(
            "other@example.test",
            "PUT",
            format!(
                "/api/events/own:default/{}",
                invited["name"].as_str().unwrap()
            ),
            change,
        )
        .await;
        assert_eq!(status, 403);

        // Invited at an alias: still answered, not edited.
        db::add_alias(
            &state.db_path,
            "sales@example.test",
            &["other@example.test"],
        )
        .unwrap();
        let mut aliased = serde_json::to_value(EventFields {
            repeat: "none".into(),
            ..fields()
        })
        .unwrap();
        aliased["attendees"] = json!(["sales@example.test"]);
        aliased["summary"] = json!("Pricing");
        let (status, _) = call(ME, "POST", "/api/events/own:default".into(), aliased).await;
        assert_eq!(status, 204);
        let (_, theirs) = call(
            "other@example.test",
            "GET",
            range(NINE - 3_600, NINE + 3_600),
            Value::Null,
        )
        .await;
        let pricing = theirs["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["details"]["summary"] == "Pricing")
            .unwrap()
            .clone();
        assert_eq!(pricing["editable"], false);
        let mut change = pricing["details"].clone();
        change["etag"] = pricing["etag"].clone();
        let (status, _) = call(
            "other@example.test",
            "PUT",
            format!(
                "/api/events/own:default/{}",
                pricing["name"].as_str().unwrap()
            ),
            change,
        )
        .await;
        assert_eq!(status, 403, "invited at an alias");

        // The organizer moves it: the guest's copy follows.
        let mine = &events[0];
        let path = format!("/api/events/own:default/{}", mine["name"].as_str().unwrap());
        let mut moved = event.clone();
        moved["start"] = json!(NINE + 3_600);
        moved["end"] = json!(NINE + 7_200);
        moved["etag"] = mine["etag"].clone();
        let (status, body) = call(ME, "PUT", path.clone(), moved.clone()).await;
        assert_eq!(status, 204, "{body}");
        let (status, _) = call(ME, "PUT", path.clone(), moved).await;
        assert_eq!(status, 409, "an old version is not overwritten");
        let (_, theirs) = call(
            "other@example.test",
            "GET",
            range(NINE, NINE + 7_200),
            Value::Null,
        )
        .await;
        let review = theirs["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["details"]["summary"] == "Review; Q4, budget")
            .unwrap();
        assert_eq!(review["start"], NINE + 3_600);

        // Deleting it cancels it for the guest.
        let review_of = |listing: &Value| {
            listing["events"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["details"]["summary"] == "Review; Q4, budget")
                .cloned()
        };
        let (_, listing) = call(ME, "GET", range(NINE, NINE + 7_200), Value::Null).await;
        let etag = review_of(&listing).unwrap()["etag"].clone();
        let (status, _) = call(ME, "DELETE", path, json!({ "etag": etag })).await;
        assert_eq!(status, 204);
        let (_, listing) = call(ME, "GET", range(NINE, NINE + 7_200), Value::Null).await;
        assert!(review_of(&listing).is_none());
        let (_, theirs) = call(
            "other@example.test",
            "GET",
            range(NINE, NINE + 7_200),
            Value::Null,
        )
        .await;
        let review = theirs["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["details"]["summary"] == "Review; Q4, budget")
            .unwrap();
        assert_eq!(review["cancelled"], true);

        let (status, _) = call(ME, "GET", range(0, 500 * 86_400), Value::Null).await;
        assert_eq!(status, 400, "range too long");
        let (status, _) = call(ME, "GET", range(i64::MIN, i64::MAX), Value::Null).await;
        assert_eq!(status, 400, "no overflow");
    }

    #[tokio::test]
    async fn rooms_accept_free_times_and_decline_clashes() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        db::add_mailbox(
            &state.db_path,
            "room1@example.test",
            Some("plain:x"),
            None,
            None,
        )
        .unwrap();
        rmail_common::resources::set(
            &state.db_path,
            "room1@example.test",
            Some(rmail_common::resources::ResourceKind::Room),
        )
        .unwrap();
        let cookie = Some(format!("{SESSION_COOKIE}={}", sign_session(&state, ME)));
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
        let (_, rooms) = call("GET", "/api/resources".into(), Value::Null).await;
        assert_eq!(
            rooms,
            json!([{"address": "room1@example.test", "kind": "room"}])
        );
        let book = |summary: &'static str, start: i64| {
            let mut event = serde_json::to_value(EventFields {
                summary: summary.into(),
                start,
                end: start + 3_600,
                repeat: "none".into(),
                ..fields()
            })
            .unwrap();
            event["attendees"] = json!(["room1@example.test"]);
            call("POST", "/api/events/own:default".into(), event)
        };
        let room_status = |listing: &Value, summary: &str| {
            listing["events"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["details"]["summary"] == summary)
                .and_then(|e| {
                    e["attendee_details"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|a| a["address"] == "room1@example.test")
                        .map(|a| a["status"].clone())
                })
        };
        assert_eq!(book("First", NINE).await.0, 204);
        assert_eq!(book("Clash", NINE + 1_800).await.0, 204);
        assert_eq!(book("Later", NINE + 7_200).await.0, 204);
        let (_, listing) = call(
            "GET",
            format!("/api/events?from={}&to={}", NINE - 3_600, NINE + 86_400),
            Value::Null,
        )
        .await;
        assert_eq!(room_status(&listing, "First"), Some(json!("accepted")));
        assert_eq!(room_status(&listing, "Clash"), Some(json!("declined")));
        assert_eq!(room_status(&listing, "Later"), Some(json!("accepted")));
        let organizer_copy = listing["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["details"]["summary"] == "First")
            .unwrap()
            .clone();
        assert!(
            organizer_copy["attendee_details"]
                .to_string()
                .contains("room1")
        );
    }
}
