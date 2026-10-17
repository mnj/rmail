//! JMAP for Calendars (draft-ietf-jmap-calendars-32): the user's CalDAV
//! calendars as `Calendar` objects and their events as JSCalendar
//! `CalendarEvent`s (RFC 8984), in the same store CalDAV clients and
//! webmail use. The draft may still change; this follows revision 32.
//!
//! - Events are read and written through webmail's event fields (title,
//!   description, one location, start, duration, time zone, all day, a
//!   simple recurrence, attendees), so a JMAP edit keeps every other
//!   iCalendar property and overridden occurrences as they were.
//!   JSCalendar properties outside those are refused with
//!   `invalidProperties` rather than dropped.
//! - Only the user's own calendars, as for contacts. Subscriptions are
//!   read-only; invitations the user received are answered in webmail or a
//!   CalDAV client, not edited here.
//! - `sendSchedulingMessages` (default false) decides whether guests hear
//!   of a change, as CalDAV's implicit scheduling would tell them.
//! - Recurrences are not expanded in queries (`expandRecurrences` is
//!   refused); overrides are not listed (`recurrenceOverrides` is null).
//! - States are per calendar, as for contacts (`contacts::Changes`).

use base64::Engine;
use chrono::TimeZone;
use rmail_common::dav::itip;
use rmail_common::dav::store::{self, Collection, Kind, Object};
use rmail_common::dav::text;
use serde_json::{Map, Value, json};

use super::contacts::{
    apply_patch, b64, card_state_of, collection_changes, max_changes, null_if_empty, parse_state,
    since_arg,
};
use super::identity::own_account;
use super::{
    Account, Ctx, MethodError, MethodResult, fnv1a, ids_arg, project, properties_arg, set_error,
    set_error_properties, str_arg, uint_arg, utc_date,
};
use crate::api::Session;
use crate::api::events::{self, EventFields};

pub(crate) const CALENDARS: &str = "urn:ietf:params:jmap:calendars";

const CALENDAR_PROPERTIES: &[&str] = &[
    "id",
    "name",
    "description",
    "color",
    "sortOrder",
    "isSubscribed",
    "isVisible",
    "isDefault",
    "includeInAvailability",
    "defaultAlertsWithTime",
    "defaultAlertsWithoutTime",
    "timeZone",
    "shareWith",
    "myRights",
];
const EVENT_PROPERTIES: &[&str] = &[
    "id",
    "baseEventId",
    "calendarIds",
    "isDraft",
    "isOrigin",
    "useDefaultAlerts",
    "@type",
    "uid",
    "updated",
    "title",
    "description",
    "locations",
    "start",
    "duration",
    "timeZone",
    "showWithoutTime",
    "recurrenceRules",
    "recurrenceOverrides",
    "participants",
    "status",
    "freeBusyStatus",
    "privacy",
];
const DEFAULT_EVENT_PROPERTIES: &[&str] = &[
    "id",
    "baseEventId",
    "calendarIds",
    "isDraft",
    "isOrigin",
    "useDefaultAlerts",
    "@type",
    "uid",
    "updated",
    "title",
    "description",
    "locations",
    "start",
    "duration",
    "timeZone",
    "showWithoutTime",
    "recurrenceRules",
    "recurrenceOverrides",
    "participants",
    "status",
    "freeBusyStatus",
    "privacy",
];

/// The account capability (draft section 1.4.1).
pub(crate) fn account_capability() -> Value {
    json!({
        "maxCalendarsPerEvent": 1,
        "minDateTime": "1900-01-01T00:00:00Z",
        "maxDateTime": "2200-01-01T00:00:00Z",
        "maxExpandedQueryDuration": "P0D",
        "maxParticipantsPerEvent": events::MAX_ATTENDEES + 1,
        "mayCreateCalendar": true,
    })
}

fn calendar_id(collection: &Collection) -> String {
    format!("cal{}", collection.id)
}

fn parse_calendar_id(id: &str) -> Option<i64> {
    id.strip_prefix("cal")?.parse().ok()
}

fn event_id(collection: &Collection, name: &str) -> String {
    format!("ev{}-{}", collection.id, b64(name))
}

fn parse_event_id(id: &str) -> Option<(i64, String)> {
    let (calendar, name) = id.strip_prefix("ev")?.split_once('-')?;
    let name = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(name)
        .ok()?;
    Some((calendar.parse().ok()?, String::from_utf8(name).ok()?))
}

fn open(
    ctx: &mut Ctx,
    args: &Map<String, Value>,
) -> Result<(Account, rmail_common::sqlite_pool::SqliteConnection), MethodError> {
    let account = own_account(ctx, args)?;
    let conn = ctx.open(&account)?;
    Ok((account, conn))
}

/// The user's event calendars (not the schedule inbox or task lists).
fn calendars(conn: &rusqlite::Connection) -> Result<Vec<Collection>, MethodError> {
    Ok(store::collections(conn, Kind::Calendar)?
        .into_iter()
        .filter(|c| {
            !c.inbox && (c.components.is_empty() || c.components.iter().any(|k| k == "VEVENT"))
        })
        .collect())
}

fn calendar_name(collection: &Collection) -> String {
    collection
        .displayname
        .clone()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| collection.name.clone())
}

fn sort_order(collection: &Collection) -> u64 {
    collection
        .sort_order
        .as_deref()
        .and_then(|o| o.trim().parse().ok())
        .unwrap_or(0)
}

fn default_calendar(calendars: &[Collection]) -> Option<i64> {
    calendars
        .iter()
        .filter(|c| !c.managed)
        .find(|c| c.name == "default")
        .or_else(|| calendars.iter().find(|c| !c.managed))
        .map(|c| c.id)
}

fn calendar_json(collection: &Collection, default: Option<i64>) -> Map<String, Value> {
    let writable = !collection.managed;
    match json!({
        "id": calendar_id(collection),
        "name": calendar_name(collection),
        "description": collection.description,
        "color": collection.color,
        "sortOrder": sort_order(collection),
        "isSubscribed": true,
        "isVisible": true,
        "isDefault": default == Some(collection.id),
        "includeInAvailability": "all",
        "defaultAlertsWithTime": null,
        "defaultAlertsWithoutTime": null,
        "timeZone": null,
        "shareWith": null,
        "myRights": {
            "mayReadFreeBusy": true,
            "mayReadItems": true,
            "mayWriteAll": writable,
            "mayWriteOwn": writable,
            "mayUpdatePrivate": writable,
            "mayRSVP": writable,
            "mayShare": false,
            "mayDelete": writable,
        },
    }) {
        Value::Object(map) => map,
        _ => unreachable!(),
    }
}

fn calendars_state(calendars: &[Collection]) -> String {
    let entries = calendars
        .iter()
        .map(|c| {
            let digest = fnv1a(
                format!(
                    "{}\u{0}{}\u{0}{}\u{0}{}",
                    calendar_name(c),
                    c.description.as_deref().unwrap_or_default(),
                    c.color.as_deref().unwrap_or_default(),
                    sort_order(c)
                )
                .as_bytes(),
            );
            format!("{}.{digest:x}", c.id)
        })
        .collect::<Vec<_>>();
    format!("s{}", entries.join("_"))
}

fn events_state(calendars: &[Collection]) -> String {
    card_state_of(calendars.iter().map(|c| (c.id, c.sync_seq)))
}

// ---------------------------------------------------------------------------
// Calendar

pub(crate) fn calendar_get(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let (account, conn) = open(ctx, &args)?;
    let ids = ids_arg(ctx, &args, "ids")?;
    let properties = properties_arg(
        &args,
        "properties",
        CALENDAR_PROPERTIES,
        CALENDAR_PROPERTIES,
        |_| false,
    )?;
    let calendars = calendars(&conn)?;
    let default = default_calendar(&calendars);
    let mut list = Vec::new();
    let mut not_found = Vec::new();
    match ids {
        None => list.extend(
            calendars
                .iter()
                .map(|c| project(calendar_json(c, default), &properties)),
        ),
        Some(ids) => {
            for id in ids {
                match calendars
                    .iter()
                    .find(|c| Some(c.id) == parse_calendar_id(&id))
                {
                    Some(c) => list.push(project(calendar_json(c, default), &properties)),
                    None => not_found.push(id),
                }
            }
        }
    }
    Ok(vec![(
        "Calendar/get".to_string(),
        json!({ "accountId": account.id, "state": calendars_state(&calendars), "list": list, "notFound": not_found }),
    )])
}

pub(crate) fn calendar_changes(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let (account, conn) = open(ctx, &args)?;
    let since = since_arg(&args)?;
    let max = max_changes(&args)?;
    let calendars = calendars(&conn)?;
    let now = parse_state(&calendars_state(&calendars)).unwrap_or_default();
    let mut created = Vec::new();
    let mut updated = Vec::new();
    for (id, digest) in &now {
        match since.get(id) {
            None => created.push(format!("cal{id}")),
            Some(old) if old != digest => updated.push(format!("cal{id}")),
            Some(_) => {}
        }
    }
    let destroyed: Vec<String> = since
        .keys()
        .filter(|id| !now.contains_key(id))
        .map(|id| format!("cal{id}"))
        .collect();
    if max.is_some_and(|max| created.len() + updated.len() + destroyed.len() > max) {
        return Err(MethodError::new("cannotCalculateChanges"));
    }
    Ok(vec![(
        "Calendar/changes".to_string(),
        json!({
            "accountId": account.id,
            "oldState": str_arg(&args, "sinceState")?,
            "newState": calendars_state(&calendars),
            "hasMoreChanges": false,
            "created": created,
            "updated": updated,
            "destroyed": destroyed,
            "updatedProperties": null,
        }),
    )])
}

fn apply_calendar(
    conn: &rusqlite::Connection,
    collection: &Collection,
    patch: &Map<String, Value>,
) -> Result<(), Value> {
    // Every key is checked before anything is written: an update succeeds
    // or fails as a whole (RFC 8620 5.3).
    let mut writes: Vec<(store::Setting, Option<String>)> = Vec::new();
    for (key, value) in patch {
        let invalid = |description: &str| {
            set_error_properties("invalidProperties", description, &[key.as_str()])
        };
        match key.as_str() {
            "name" => match value.as_str().map(str::trim) {
                Some(name) if !name.is_empty() && name.len() <= 255 => {
                    writes.push((store::Setting::DisplayName, Some(name.to_string())))
                }
                _ => return Err(invalid("a name of 1 to 255 octets is required")),
            },
            "description" => match value {
                Value::Null => writes.push((store::Setting::Description, None)),
                Value::String(text) if text.len() <= 10_000 => {
                    writes.push((store::Setting::Description, Some(text.clone())))
                }
                _ => return Err(invalid("must be a string or null")),
            },
            "color" => match value {
                Value::Null => writes.push((store::Setting::Color, None)),
                Value::String(color)
                    if color.len() <= 64 && !color.contains(['<', '>', '\r', '\n']) =>
                {
                    writes.push((store::Setting::Color, Some(color.clone())))
                }
                _ => return Err(invalid("must be a CSS color or null")),
            },
            "sortOrder" => match value.as_u64() {
                Some(order) => writes.push((store::Setting::SortOrder, Some(order.to_string()))),
                None => return Err(invalid("must be an unsigned integer")),
            },
            // Shown and kept by the client.
            "isSubscribed" | "isVisible" if value.is_boolean() => {}
            "includeInAvailability" if value.as_str() == Some("all") => {}
            "timeZone" | "shareWith" | "defaultAlertsWithTime" | "defaultAlertsWithoutTime"
                if value.is_null() => {}
            "id" | "isDefault" | "myRights" => return Err(invalid("set by the server")),
            _ => return Err(invalid("not supported here")),
        }
    }
    for (setting, value) in writes {
        store::set_property(conn, collection, setting, value.as_deref())
            .map_err(|error| set_error("serverFail", format!("{error:#}")))?;
    }
    Ok(())
}

fn find_calendar(conn: &rusqlite::Connection, id: &str) -> Result<Option<Collection>, MethodError> {
    Ok(match parse_calendar_id(id) {
        Some(id) => calendars(conn)?.into_iter().find(|c| c.id == id),
        None => None,
    })
}

pub(crate) fn calendar_set(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let (account, conn) = open(ctx, &args)?;
    let old_state = calendars_state(&calendars(&conn)?);
    if let Some(expected) = str_arg(&args, "ifInState")?
        && expected != old_state
    {
        return Err(MethodError::new("stateMismatch"));
    }
    let mut created = Map::new();
    let mut not_created = Map::new();
    for (creation_id, object) in args
        .get("create")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
    {
        let Some(object) = object.as_object() else {
            not_created.insert(creation_id, set_error("invalidProperties", "not an object"));
            continue;
        };
        if !object.contains_key("name") {
            not_created.insert(
                creation_id,
                set_error_properties("invalidProperties", "name is required", &["name"]),
            );
            continue;
        }
        let name = format!("{:032x}", rand::random::<u128>());
        let collection = store::create(&conn, Kind::Calendar, &name, None, &["VEVENT"])?;
        match apply_calendar(&conn, &collection, object) {
            Ok(()) => {
                let id = calendar_id(&collection);
                ctx.created_ids.insert(creation_id.clone(), id.clone());
                created.insert(creation_id, json!({ "id": id, "isDefault": false, "myRights": calendar_json(&collection, None)["myRights"] }));
            }
            Err(error) => {
                store::delete_collection(&conn, &collection)?;
                not_created.insert(creation_id, error);
            }
        }
    }
    let mut updated = Map::new();
    let mut not_updated = Map::new();
    for (id, patch) in args
        .get("update")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
    {
        let id = ctx.resolve_id(&id).unwrap_or(id);
        let Some(collection) = find_calendar(&conn, &id)? else {
            not_updated.insert(id, set_error("notFound", "no such calendar"));
            continue;
        };
        if collection.managed {
            not_updated.insert(
                id,
                set_error("forbidden", "this calendar is filled from a subscription"),
            );
            continue;
        }
        let Some(patch) = patch.as_object() else {
            not_updated.insert(id, set_error("invalidPatch", "not an object"));
            continue;
        };
        match apply_calendar(&conn, &collection, patch) {
            Ok(()) => {
                updated.insert(id, Value::Null);
            }
            Err(error) => {
                not_updated.insert(id, error);
            }
        }
    }
    let remove_events = super::bool_arg(&args, "onDestroyRemoveEvents")?;
    let mut destroyed = Vec::new();
    let mut not_destroyed = Map::new();
    for id in ids_arg(ctx, &args, "destroy")?.unwrap_or_default() {
        let Some(collection) = find_calendar(&conn, &id)? else {
            not_destroyed.insert(id, set_error("notFound", "no such calendar"));
            continue;
        };
        if !remove_events && !store::objects(&conn, &collection)?.is_empty() {
            not_destroyed.insert(
                id,
                set_error("calendarHasEvent", "the calendar still has events"),
            );
            continue;
        }
        // A subscription goes with its calendar.
        if collection.managed {
            rmail_common::dav::subscription::unsubscribe(&conn, &collection)?;
        } else {
            store::delete_collection(&conn, &collection)?;
        }
        destroyed.push(id);
    }
    Ok(vec![(
        "Calendar/set".to_string(),
        json!({
            "accountId": account.id,
            "oldState": old_state,
            "newState": calendars_state(&calendars(&conn)?),
            "created": null_if_empty(created),
            "updated": null_if_empty(updated),
            "destroyed": if destroyed.is_empty() { Value::Null } else { json!(destroyed) },
            "notCreated": null_if_empty(not_created),
            "notUpdated": null_if_empty(not_updated),
            "notDestroyed": null_if_empty(not_destroyed),
        }),
    )])
}

// ---------------------------------------------------------------------------
// iCalendar <-> JSCalendar

fn zone(name: &str) -> Option<chrono_tz::Tz> {
    name.parse().ok()
}

/// An ISO 8601 duration (RFC 8984 1.4.6) for `seconds`.
fn duration_text(seconds: i64) -> String {
    let seconds = seconds.max(0);
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    let (hours, minutes, secs) = (rest / 3600, rest % 3600 / 60, rest % 60);
    let mut out = String::from("P");
    if days > 0 {
        out.push_str(&format!("{days}D"));
    }
    if rest > 0 {
        out.push('T');
        if hours > 0 {
            out.push_str(&format!("{hours}H"));
        }
        if minutes > 0 {
            out.push_str(&format!("{minutes}M"));
        }
        if secs > 0 {
            out.push_str(&format!("{secs}S"));
        }
    }
    if out == "P" { "PT0S".to_string() } else { out }
}

const FREQUENCIES: &[(&str, &str)] = &[
    ("daily", "daily"),
    ("weekly", "weekly"),
    ("monthly", "monthly"),
    ("yearly", "yearly"),
];

/// The JSCalendar recurrence rule of an RRULE webmail cannot edit: its
/// frequency and the parts JSCalendar names the same way.
fn custom_rule(event: &text::Component) -> Value {
    let Some(rule) = event.property("RRULE") else {
        return Value::Null;
    };
    let mut out = Map::new();
    out.insert("@type".into(), json!("RecurrenceRule"));
    for part in rule.value.split(';') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim().to_ascii_uppercase().as_str() {
            "FREQ" => {
                out.insert("frequency".into(), json!(value.to_ascii_lowercase()));
            }
            "INTERVAL" => {
                if let Ok(n) = value.parse::<u64>() {
                    out.insert("interval".into(), json!(n));
                }
            }
            "COUNT" => {
                if let Ok(n) = value.parse::<u64>() {
                    out.insert("count".into(), json!(n));
                }
            }
            "BYDAY" => {
                let days: Vec<Value> = value
                    .split(',')
                    .filter_map(|day| {
                        let day = day.trim();
                        let (nth, name) = day.split_at(day.len().saturating_sub(2));
                        let mut object =
                            json!({ "@type": "NDay", "day": name.to_ascii_lowercase() });
                        if let Ok(n) = nth.parse::<i64>() {
                            object["nthOfPeriod"] = json!(n);
                        }
                        (!name.is_empty()).then_some(object)
                    })
                    .collect();
                out.insert("byDay".into(), json!(days));
            }
            _ => {}
        }
    }
    json!([out])
}

/// The JSCalendar event for a stored calendar object (its master event).
fn event_json(
    collection: &Collection,
    object: &Object,
    owner: &str,
    zone_out: Option<chrono_tz::Tz>,
) -> Option<Map<String, Value>> {
    let calendar = text::parse(&object.data).ok()?;
    let master = events::master(&calendar)?;
    let fields = events::fields_of(&calendar, Some(owner))?;
    let mut out = Map::new();
    out.insert("id".into(), json!(event_id(collection, &object.name)));
    out.insert("baseEventId".into(), Value::Null);
    out.insert(
        "calendarIds".into(),
        json!({ calendar_id(collection): true }),
    );
    out.insert("isDraft".into(), json!(false));
    out.insert(
        "isOrigin".into(),
        json!(itip::organizer(&calendar).is_none_or(|o| o.eq_ignore_ascii_case(owner))),
    );
    out.insert("useDefaultAlerts".into(), json!(false));
    out.insert("@type".into(), json!("Event"));
    out.insert("uid".into(), json!(object.uid.clone().unwrap_or_default()));
    out.insert("updated".into(), json!(utc_date(object.modified)));
    out.insert("title".into(), json!(fields.summary));
    out.insert("description".into(), json!(fields.description));
    out.insert(
        "locations".into(),
        if fields.location.is_empty() {
            Value::Null
        } else {
            json!({ "l1": { "@type": "Location", "name": fields.location } })
        },
    );
    if fields.all_day {
        let day = chrono::DateTime::from_timestamp(fields.start, 0)?
            .format("%Y-%m-%dT00:00:00")
            .to_string();
        out.insert("start".into(), json!(day));
        out.insert("timeZone".into(), Value::Null);
        out.insert("showWithoutTime".into(), json!(true));
        out.insert(
            "duration".into(),
            json!(format!(
                "P{}D",
                ((fields.end - fields.start) / 86_400).max(1)
            )),
        );
    } else {
        let tz = zone(&fields.timezone).unwrap_or(chrono_tz::UTC);
        let local = tz.timestamp_opt(fields.start, 0).single()?.naive_local();
        out.insert(
            "start".into(),
            json!(local.format("%Y-%m-%dT%H:%M:%S").to_string()),
        );
        out.insert(
            "timeZone".into(),
            json!(if fields.timezone.is_empty() {
                "Etc/UTC".to_string()
            } else {
                tz.name().to_string()
            }),
        );
        out.insert("showWithoutTime".into(), json!(false));
        out.insert(
            "duration".into(),
            json!(duration_text(fields.end - fields.start)),
        );
    }
    out.insert(
        "recurrenceRules".into(),
        match FREQUENCIES
            .iter()
            .find(|(repeat, _)| *repeat == fields.repeat)
        {
            Some((_, frequency)) => json!([{ "@type": "RecurrenceRule", "frequency": frequency }]),
            None if fields.repeat == "custom" => custom_rule(master),
            None => Value::Null,
        },
    );
    out.insert("recurrenceOverrides".into(), Value::Null);
    let attendees = events::attendees_of(master);
    if attendees.is_empty() {
        out.insert("participants".into(), Value::Null);
    } else {
        let organizer = itip::organizer(&calendar).unwrap_or_else(|| owner.to_string());
        let mut participants = Map::new();
        participants.insert(
            "p0".into(),
            json!({ "@type": "Participant", "calendarAddress": format!("mailto:{organizer}"), "email": organizer, "roles": { "owner": true }, "sendTo": { "imip": format!("mailto:{organizer}") } }),
        );
        for (index, attendee) in attendees
            .iter()
            .filter(|a| !a.address.eq_ignore_ascii_case(&organizer))
            .enumerate()
        {
            let mut person = json!({
                "@type": "Participant",
                "calendarAddress": format!("mailto:{}", attendee.address),
                "email": attendee.address,
                "roles": { "attendee": true },
                "participationStatus": attendee.status,
                "sendTo": { "imip": format!("mailto:{}", attendee.address) },
            });
            if !attendee.name.is_empty() {
                person["name"] = json!(attendee.name);
            }
            participants.insert(format!("p{}", index + 1), person);
        }
        out.insert("participants".into(), Value::Object(participants));
    }
    out.insert(
        "status".into(),
        json!(
            master
                .property("STATUS")
                .map(|s| s.value.to_ascii_lowercase())
                .unwrap_or_else(|| "confirmed".into())
        ),
    );
    out.insert(
        "freeBusyStatus".into(),
        json!(if master
            .property("TRANSP")
            .is_some_and(|t| t.value.eq_ignore_ascii_case("TRANSPARENT"))
        {
            "free"
        } else {
            "busy"
        }),
    );
    out.insert("privacy".into(), json!("public"));
    let utc = |seconds: i64| -> Value {
        match zone_out {
            Some(tz) => json!(
                tz.timestamp_opt(seconds, 0)
                    .single()
                    .map(|t| t.naive_local().format("%Y-%m-%dT%H:%M:%S").to_string())
            ),
            None => json!(utc_date(seconds)),
        }
    };
    out.insert("utcStart".into(), utc(fields.start));
    out.insert("utcEnd".into(), utc(fields.end));
    Some(out)
}

/// Where a JSCalendar event cannot be stored as webmail's event fields.
struct Unsupported(Vec<String>);

/// Webmail's fields for a JSCalendar event (`before`: the event as stored,
/// for an update; a recurrence it cannot show is kept when unchanged).
fn fields_from(
    event: &Map<String, Value>,
    before: Option<&Map<String, Value>>,
) -> Result<EventFields, Unsupported> {
    let mut bad = Vec::new();
    let unchanged = |key: &str| before.is_some_and(|b| b.get(key) == event.get(key));
    for (key, value) in event {
        let fine = match key.as_str() {
            "id" | "baseEventId" | "calendarIds" | "@type" | "uid" | "updated" | "created"
            | "sequence" | "prodId" | "method" | "title" | "description" | "start" | "duration"
            | "timeZone" | "showWithoutTime" | "participants" | "locations" | "recurrenceRules"
            | "isOrigin" | "utcStart" | "utcEnd" | "replyTo" => true,
            "isDraft" | "useDefaultAlerts" | "mayInviteSelf" | "mayInviteOthers"
            | "hideAttendees" => value.as_bool() != Some(true),
            "descriptionContentType" => value.as_str().is_none_or(|t| t == "text/plain"),
            "status" => value.as_str().is_none_or(|s| s == "confirmed") || unchanged(key),
            "freeBusyStatus" => value.as_str().is_none_or(|s| s == "busy") || unchanged(key),
            "privacy" => value.as_str().is_none_or(|s| s == "public"),
            "recurrenceOverrides"
            | "excludedRecurrenceRules"
            | "alerts"
            | "keywords"
            | "links"
            | "virtualLocations"
            | "relatedTo"
            | "categories" => {
                value.is_null()
                    || value.as_object().is_some_and(Map::is_empty)
                    || value.as_array().is_some_and(Vec::is_empty)
            }
            "locale" | "color" | "priority" => value.is_null() || unchanged(key),
            _ => false,
        };
        if !fine {
            bad.push(key.clone());
        }
    }
    let text = |key: &str| {
        event
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let all_day = event
        .get("showWithoutTime")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let start_text = text("start");
    let local = chrono::NaiveDateTime::parse_from_str(&start_text, "%Y-%m-%dT%H:%M:%S");
    let duration = event
        .get("duration")
        .and_then(Value::as_str)
        .map(text::parse_duration)
        .unwrap_or(Some(if all_day { 86_400 } else { 0 }));
    let timezone = event
        .get("timeZone")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let (start, end) = match (local, duration) {
        (Ok(local), Some(duration)) if duration >= 0 => {
            let start = if all_day {
                Some(
                    local
                        .date()
                        .and_hms_opt(0, 0, 0)
                        .unwrap()
                        .and_utc()
                        .timestamp(),
                )
            } else if timezone.is_empty() || timezone == "Etc/UTC" || timezone == "UTC" {
                Some(local.and_utc().timestamp())
            } else {
                zone(&timezone)
                    .and_then(|tz| tz.from_local_datetime(&local).earliest())
                    .map(|t| t.timestamp())
            };
            match start {
                Some(start) => (start, start + duration),
                None => {
                    bad.push("timeZone".into());
                    (0, 0)
                }
            }
        }
        (Err(_), _) => {
            bad.push("start".into());
            (0, 0)
        }
        _ => {
            bad.push("duration".into());
            (0, 0)
        }
    };
    let location = match event.get("locations") {
        None | Some(Value::Null) => String::new(),
        Some(Value::Object(map)) if map.len() <= 1 => map
            .values()
            .next()
            .and_then(|l| l.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        _ => {
            bad.push("locations".into());
            String::new()
        }
    };
    let repeat = match event.get("recurrenceRules") {
        None | Some(Value::Null) => "none".to_string(),
        _ if unchanged("recurrenceRules")
            && before.is_some_and(|b| {
                !FREQUENCIES.iter().any(|(_, f)| {
                    b.get("recurrenceRules")
                        == Some(&json!([{ "@type": "RecurrenceRule", "frequency": f }]))
                })
            }) =>
        {
            "custom".to_string()
        }
        Some(Value::Array(rules)) if rules.len() == 1 => {
            let rule = rules[0].as_object();
            let simple = rule.is_some_and(|r| {
                r.keys().all(|k| {
                    k == "@type" || k == "frequency" || (k == "interval" && r[k] == json!(1))
                })
            });
            match rule
                .and_then(|r| r.get("frequency"))
                .and_then(Value::as_str)
            {
                Some(f) if simple && FREQUENCIES.iter().any(|(_, known)| *known == f) => {
                    f.to_string()
                }
                _ => {
                    bad.push("recurrenceRules".into());
                    "none".into()
                }
            }
        }
        Some(Value::Array(rules)) if rules.is_empty() => "none".to_string(),
        _ => {
            bad.push("recurrenceRules".into());
            "none".into()
        }
    };
    let mut attendees = Vec::new();
    if let Some(participants) = event.get("participants").and_then(Value::as_object) {
        for participant in participants.values() {
            let roles = participant.get("roles").and_then(Value::as_object);
            let owner = roles.is_some_and(|r| r.get("owner") == Some(&Value::Bool(true)));
            if owner {
                continue;
            }
            let address = participant
                .get("sendTo")
                .and_then(|s| s.get("imip"))
                .or_else(|| participant.get("calendarAddress"))
                .and_then(Value::as_str)
                .map(|a| a.trim_start_matches("mailto:").to_string())
                .or_else(|| {
                    participant
                        .get("email")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                });
            match address {
                Some(address) if address.contains('@') => attendees.push(address),
                _ => bad.push("participants".into()),
            }
        }
    } else if event.get("participants").is_some_and(|p| !p.is_null()) {
        bad.push("participants".into());
    }
    if bad.is_empty() {
        Ok(EventFields {
            summary: text("title"),
            location,
            description: text("description"),
            start,
            end,
            all_day,
            timezone: if all_day || timezone == "Etc/UTC" {
                String::new()
            } else {
                timezone
            },
            repeat,
            attendees,
        })
    } else {
        bad.sort();
        bad.dedup();
        Err(Unsupported(bad))
    }
}

// ---------------------------------------------------------------------------
// CalendarEvent

fn session_of(account: &Account) -> Session {
    Session {
        address: account.owner.clone(),
        domain: account.domain.clone(),
        localpart: account.localpart.clone(),
    }
}

fn all_events(
    conn: &rusqlite::Connection,
    calendars: &[Collection],
) -> Result<Vec<(Collection, Object)>, MethodError> {
    let mut out = Vec::new();
    for calendar in calendars {
        for object in store::objects(conn, calendar)? {
            if object.component.as_deref() == Some("VEVENT") {
                out.push((calendar.clone(), object));
            }
        }
    }
    Ok(out)
}

fn find_event(
    conn: &rusqlite::Connection,
    calendars: &[Collection],
    id: &str,
) -> Result<Option<(Collection, Object)>, MethodError> {
    let Some((calendar, name)) = parse_event_id(id) else {
        return Ok(None);
    };
    let Some(collection) = calendars.iter().find(|c| c.id == calendar) else {
        return Ok(None);
    };
    Ok(store::object(conn, collection, &name)?.map(|object| (collection.clone(), object)))
}

pub(crate) fn event_get(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let (account, conn) = open(ctx, &args)?;
    let ids = ids_arg(ctx, &args, "ids")?;
    let properties = properties_arg(
        &args,
        "properties",
        &[EVENT_PROPERTIES, &["utcStart", "utcEnd"]].concat(),
        DEFAULT_EVENT_PROPERTIES,
        |_| true,
    )?;
    let zone_out = match str_arg(&args, "timeZone")? {
        None | Some("Etc/UTC") | Some("UTC") => None,
        Some(name) => Some(zone(name).ok_or_else(|| MethodError::invalid("unknown timeZone"))?),
    };
    let calendars = calendars(&conn)?;
    let owner = account.owner.clone();
    let mut list = Vec::new();
    let mut not_found = Vec::new();
    let found: Vec<Lookup> = match ids {
        None => all_events(&conn, &calendars)?
            .into_iter()
            .map(|e| (Some(e), None))
            .collect(),
        Some(ids) => ids
            .into_iter()
            .map(|id| Ok((find_event(&conn, &calendars, &id)?, Some(id))))
            .collect::<Result<_, MethodError>>()?,
    };
    for (event, id) in found {
        match event.and_then(|(c, o)| event_json(&c, &o, &owner, zone_out)) {
            Some(event) => list.push(project(event, &properties)),
            None => not_found.extend(id),
        }
    }
    Ok(vec![(
        "CalendarEvent/get".to_string(),
        json!({ "accountId": account.id, "state": events_state(&calendars), "list": list, "notFound": not_found }),
    )])
}

pub(crate) fn event_changes(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let (account, conn) = open(ctx, &args)?;
    let since = since_arg(&args)?;
    let max = max_changes(&args)?;
    let calendars = calendars(&conn)?;
    let changes = collection_changes(&conn, &calendars, &since, max, event_id)?;
    Ok(vec![(
        "CalendarEvent/changes".to_string(),
        json!({
            "accountId": account.id,
            "oldState": str_arg(&args, "sinceState")?,
            "newState": changes.new_state,
            "hasMoreChanges": changes.has_more,
            "created": changes.created,
            "updated": changes.updated,
            "destroyed": changes.destroyed,
        }),
    )])
}

fn single_calendar(event: &Map<String, Value>, ctx: &Ctx) -> Option<i64> {
    let ids = event.get("calendarIds")?.as_object()?;
    let mut chosen = ids.iter().filter(|(_, on)| **on == Value::Bool(true));
    let (id, _) = chosen.next()?;
    if chosen.next().is_some() {
        return None;
    }
    parse_calendar_id(&ctx.resolve_id(id).unwrap_or_else(|| id.clone()))
}

fn unsupported(properties: &[String]) -> Value {
    let names = properties.iter().map(String::as_str).collect::<Vec<_>>();
    set_error_properties("invalidProperties", "not supported here", &names)
}

/// A refusal from the event store, as a SetError.
fn refusal(status: axum::http::StatusCode, message: &str) -> Value {
    let kind = match status.as_u16() {
        403 => "forbidden",
        404 => "notFound",
        409 => "stateMismatch",
        _ => "invalidProperties",
    };
    set_error(kind, message)
}

pub(crate) fn event_set(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let (account, conn) = open(ctx, &args)?;
    let old_state = events_state(&calendars(&conn)?);
    if let Some(expected) = str_arg(&args, "ifInState")?
        && expected != old_state
    {
        return Err(MethodError::new("stateMismatch"));
    }
    let schedule = super::bool_arg(&args, "sendSchedulingMessages")?;
    let session = session_of(&account);
    let state = ctx.app.clone();
    let mut created = Map::new();
    let mut not_created = Map::new();
    for (creation_id, object) in args
        .get("create")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
    {
        let calendars = calendars(&conn)?;
        let Some(event) = object.as_object() else {
            not_created.insert(creation_id, set_error("invalidProperties", "not an object"));
            continue;
        };
        let Some(calendar) =
            single_calendar(event, ctx).and_then(|id| calendars.iter().find(|c| c.id == id))
        else {
            not_created.insert(
                creation_id,
                set_error_properties(
                    "invalidProperties",
                    "name exactly one of the account's calendars",
                    &["calendarIds"],
                ),
            );
            continue;
        };
        let fields = match fields_from(event, None) {
            Ok(fields) => fields,
            Err(Unsupported(properties)) => {
                not_created.insert(creation_id, unsupported(&properties));
                continue;
            }
        };
        if let Err(message) = events::check(&fields) {
            not_created.insert(creation_id, set_error("invalidProperties", message));
            continue;
        }
        let uid = event
            .get("uid")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|u| !u.is_empty() && u.len() <= 255 && !u.contains(['\r', '\n']))
            .map(str::to_string);
        let place = format!("own:{}", calendar.name);
        match events::save(
            &state,
            &session,
            &place,
            None,
            events::Change {
                fields,
                etag: None,
                schedule,
                uid,
            },
        )? {
            Ok(name) => {
                let id = event_id(calendar, &name);
                ctx.created_ids.insert(creation_id.clone(), id.clone());
                let uid = store::object(&conn, calendar, &name)?
                    .and_then(|o| o.uid)
                    .unwrap_or_default();
                created.insert(creation_id, json!({ "id": id, "uid": uid }));
            }
            Err((status, message)) => {
                not_created.insert(creation_id, refusal(status, message));
            }
        }
    }
    let mut updated = Map::new();
    let mut not_updated = Map::new();
    for (id, patch) in args
        .get("update")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
    {
        let id = ctx.resolve_id(&id).unwrap_or(id);
        let calendars = calendars(&conn)?;
        let Some((calendar, object)) = find_event(&conn, &calendars, &id)? else {
            not_updated.insert(id, set_error("notFound", "no such event"));
            continue;
        };
        let (Some(patch), Some(before)) = (
            patch.as_object(),
            event_json(&calendar, &object, &account.owner, None),
        ) else {
            not_updated.insert(id, set_error("invalidPatch", "not an object"));
            continue;
        };
        let mut event = before.clone();
        if let Err(path) = apply_patch(&mut event, patch) {
            not_updated.insert(
                id,
                set_error_properties("invalidPatch", "no such path", &[path.as_str()]),
            );
            continue;
        }
        let fixed: Vec<&str> = ["id", "uid", "calendarIds"]
            .into_iter()
            .filter(|key| event.get(*key) != before.get(*key))
            .collect();
        if !fixed.is_empty() {
            not_updated.insert(
                id,
                set_error_properties(
                    "invalidProperties",
                    "cannot be changed (an event stays in its calendar)",
                    &fixed,
                ),
            );
            continue;
        }
        let fields = match fields_from(&event, Some(&before)) {
            Ok(fields) => fields,
            Err(Unsupported(properties)) => {
                not_updated.insert(id, unsupported(&properties));
                continue;
            }
        };
        if let Err(message) = events::check(&fields) {
            not_updated.insert(id, set_error("invalidProperties", message));
            continue;
        }
        let place = format!("own:{}", calendar.name);
        match events::save(
            &state,
            &session,
            &place,
            Some(&object.name),
            events::Change {
                fields,
                etag: Some(object.etag.clone()),
                schedule,
                uid: None,
            },
        )? {
            Ok(_) => {
                updated.insert(id, Value::Null);
            }
            Err((status, message)) => {
                not_updated.insert(id, refusal(status, message));
            }
        }
    }
    let mut destroyed = Vec::new();
    let mut not_destroyed = Map::new();
    for id in ids_arg(ctx, &args, "destroy")?.unwrap_or_default() {
        let calendars = calendars(&conn)?;
        let Some((calendar, object)) = find_event(&conn, &calendars, &id)? else {
            not_destroyed.insert(id, set_error("notFound", "no such event"));
            continue;
        };
        let place = format!("own:{}", calendar.name);
        match events::remove_event(&state, &session, &place, &object.name, None, schedule)? {
            Ok(()) => destroyed.push(id),
            Err((status, message)) => {
                not_destroyed.insert(id, refusal(status, message));
            }
        }
    }
    ctx.touched(&account);
    Ok(vec![(
        "CalendarEvent/set".to_string(),
        json!({
            "accountId": account.id,
            "oldState": old_state,
            "newState": events_state(&calendars(&conn)?),
            "created": null_if_empty(created),
            "updated": null_if_empty(updated),
            "destroyed": if destroyed.is_empty() { Value::Null } else { json!(destroyed) },
            "notCreated": null_if_empty(not_created),
            "notUpdated": null_if_empty(not_updated),
            "notDestroyed": null_if_empty(not_destroyed),
        }),
    )])
}

/// An event looked up (if found), and the id it was asked for.
type Lookup = (Option<(Collection, Object)>, Option<String>);

struct Row {
    id: String,
    calendar: String,
    uid: String,
    modified: i64,
    fields: EventFields,
    /// Where the event and all its occurrences fall (an open end for a
    /// recurrence without one).
    span: (Option<i64>, Option<i64>),
}

fn contains(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

fn matches(filter: &Map<String, Value>, row: &Row) -> Result<bool, MethodError> {
    if let Some(operator) = filter.get("operator") {
        let conditions = filter
            .get("conditions")
            .and_then(Value::as_array)
            .ok_or_else(|| MethodError::new("invalidArguments"))?;
        let mut results = Vec::new();
        for condition in conditions {
            results.push(matches(
                condition
                    .as_object()
                    .ok_or_else(|| MethodError::new("invalidArguments"))?,
                row,
            )?);
        }
        return match operator.as_str() {
            Some("AND") => Ok(results.iter().all(|r| *r)),
            Some("OR") => Ok(results.iter().any(|r| *r)),
            Some("NOT") => Ok(!results.iter().any(|r| *r)),
            _ => Err(MethodError::new("unsupportedFilter")),
        };
    }
    let f = &row.fields;
    for (key, value) in filter {
        let text = value
            .as_str()
            .ok_or_else(|| MethodError::new("unsupportedFilter"))?;
        let instant = || {
            super::parse_utc_date(text)
                .ok_or_else(|| MethodError::invalid(format!("{key} must be a UTCDateTime")))
        };
        let ok = match key.as_str() {
            "inCalendar" => row.calendar == text,
            "uid" => row.uid == text,
            "after" => {
                let at = instant()?;
                row.span.1.is_none_or(|end| end > at)
            }
            "before" => {
                let at = instant()?;
                row.span.0.unwrap_or(f.start) < at
            }
            "title" => contains(&f.summary, text),
            "description" => contains(&f.description, text),
            "location" => contains(&f.location, text),
            "participant" => f.attendees.iter().any(|a| contains(a, text)),
            "text" => {
                contains(&f.summary, text)
                    || contains(&f.description, text)
                    || contains(&f.location, text)
                    || f.attendees.iter().any(|a| contains(a, text))
            }
            _ => return Err(MethodError::new("unsupportedFilter")),
        };
        if !ok {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn event_query(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let (account, conn) = open(ctx, &args)?;
    if super::bool_arg(&args, "expandRecurrences")? {
        return Err(MethodError::with(
            "cannotCalculateOccurrences",
            "recurring events are not expanded here",
        ));
    }
    let calendars = calendars(&conn)?;
    let mut rows = Vec::new();
    for (calendar, object) in all_events(&conn, &calendars)? {
        let Some(fields) = text::parse(&object.data)
            .ok()
            .and_then(|c| events::fields_of(&c, Some(&account.owner)))
        else {
            continue;
        };
        rows.push(Row {
            id: event_id(&calendar, &object.name),
            calendar: calendar_id(&calendar),
            uid: object.uid.clone().unwrap_or_default(),
            modified: object.modified,
            fields,
            span: (object.start, object.end),
        });
    }
    if let Some(filter) = args.get("filter").filter(|f| !f.is_null()) {
        let filter = filter
            .as_object()
            .ok_or_else(|| MethodError::invalid("filter must be an object"))?;
        let mut kept = Vec::new();
        for row in rows {
            if matches(filter, &row)? {
                kept.push(row);
            }
        }
        rows = kept;
    }
    let mut keys = Vec::new();
    for comparator in args
        .get("sort")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let ascending = comparator
            .get("isAscending")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        match comparator.get("property").and_then(Value::as_str) {
            Some(p @ ("start" | "uid" | "updated" | "title")) => {
                keys.push((p.to_string(), ascending))
            }
            _ => return Err(MethodError::new("unsupportedSort")),
        }
    }
    if keys.is_empty() {
        keys.push(("start".to_string(), true));
    }
    rows.sort_by(|a, b| {
        for (key, ascending) in &keys {
            let order = match key.as_str() {
                "start" => a.fields.start.cmp(&b.fields.start),
                "uid" => a.uid.cmp(&b.uid),
                "updated" => a.modified.cmp(&b.modified),
                _ => a
                    .fields
                    .summary
                    .to_lowercase()
                    .cmp(&b.fields.summary.to_lowercase()),
            };
            let order = if *ascending { order } else { order.reverse() };
            if order.is_ne() {
                return order;
            }
        }
        a.id.cmp(&b.id)
    });
    let ids: Vec<String> = rows.into_iter().map(|row| row.id).collect();
    let total = ids.len();
    let mut position = match args.get("position").and_then(Value::as_i64) {
        Some(p) if p < 0 => total.saturating_sub(p.unsigned_abs() as usize),
        Some(p) => (p as usize).min(total),
        None => 0,
    };
    if let Some(anchor) = str_arg(&args, "anchor")? {
        let index = ids
            .iter()
            .position(|id| id == anchor)
            .ok_or_else(|| MethodError::new("anchorNotFound"))?;
        let offset = args
            .get("anchorOffset")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        position = (index as i64 + offset).clamp(0, total as i64) as usize;
    }
    let limit = uint_arg(&args, "limit")?.map(|limit| limit as usize);
    let page: Vec<String> = ids
        .iter()
        .skip(position)
        .take(limit.unwrap_or(usize::MAX))
        .cloned()
        .collect();
    let mut response = json!({
        "accountId": account.id,
        "queryState": events_state(&calendars),
        "canCalculateChanges": false,
        "position": position,
        "ids": page,
    });
    if super::bool_arg(&args, "calculateTotal")? {
        response["total"] = json!(total);
    }
    Ok(vec![("CalendarEvent/query".to_string(), response)])
}

// ---------------------------------------------------------------------------
// ParticipantIdentity

pub(crate) fn identity_get(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let account = own_account(ctx, &args)?;
    let ids = ids_arg(ctx, &args, "ids")?;
    let addresses = rmail_common::db::calendar_addresses(&ctx.app.db_path, &account.owner)
        .unwrap_or_else(|_| vec![account.owner.clone()]);
    let all: Vec<Value> = addresses
        .iter()
        .enumerate()
        .map(|(index, address)| json!({ "id": format!("pi{index}"), "name": "", "calendarAddress": format!("mailto:{address}"), "isDefault": index == 0 }))
        .collect();
    let (list, not_found): (Vec<Value>, Vec<String>) = match ids {
        None => (all, Vec::new()),
        Some(ids) => {
            let mut list = Vec::new();
            let mut missing = Vec::new();
            for id in ids {
                match all.iter().find(|i| i["id"] == json!(id)) {
                    Some(identity) => list.push(identity.clone()),
                    None => missing.push(id),
                }
            }
            (list, missing)
        }
    };
    let state = format!("{:x}", fnv1a(addresses.join(",").as_bytes()));
    Ok(vec![(
        "ParticipantIdentity/get".to_string(),
        json!({ "accountId": account.id, "state": state, "list": list, "notFound": not_found }),
    )])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn durations_and_ids_round_trip() {
        assert_eq!(duration_text(3600), "PT1H");
        assert_eq!(duration_text(86_400 + 5400), "P1DT1H30M");
        assert_eq!(duration_text(0), "PT0S");
        assert_eq!(text::parse_duration("P1DT1H30M"), Some(86_400 + 5400));
        assert_eq!(
            parse_event_id(&format!("ev4-{}", b64("a-b.ics"))),
            Some((4, "a-b.ics".to_string()))
        );
        assert_eq!(parse_calendar_id("cal9"), Some(9));
        let state = BTreeMap::from([(1, "2".to_string())]);
        assert_eq!(
            parse_state(&card_state_of([(1, 2)].into_iter())).unwrap(),
            state
        );
    }
}
