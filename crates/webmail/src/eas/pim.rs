//! Contacts and calendars over ActiveSync: the account's CardDAV address
//! books and CalDAV event calendars as folders, synced both ways through
//! webmail's contact and event fields (so other vCard and iCalendar
//! properties are kept), and invitations a phone can answer.
//!
//! - Folder ids are `ab<n>` (address books) and `cal<n>` (calendars).
//! - An item's ServerId is its resource name, or a digest of it when the
//!   name is too long or unusual for ActiveSync's 64 characters.
//! - Changes are found by ETag against what the device was sent.
//! - Event times go out in UTC with a UTC time zone; recurrences that
//!   webmail can edit (daily, weekly, monthly, yearly) both ways, others
//!   shown as near as ActiveSync allows and kept unless changed.

use std::collections::BTreeMap;

use base64::Engine;
use rmail_common::dav::store::{self, Collection, Kind, Object};
use rmail_common::dav::{itip, recur, text};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use super::commands::Account;
use super::state::{self, Items};
use super::wbxml::Element;
use crate::api::Session;
use crate::api::contacts::{self, Entry, Fields, PostalAddress};
use crate::api::events::{self, EventFields};
use crate::api::tasks;

pub(super) const CONTACTS_PREFIX: &str = "ab";
pub(super) const CALENDAR_PREFIX: &str = "cal";
pub(super) const TASKS_PREFIX: &str = "task";

pub(super) fn is_pim(id: &str) -> bool {
    class_of(id).is_some()
}

/// What a PIM folder holds; a calendar that takes both events and to-dos
/// is a calendar folder and a tasks folder, as on Exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Contacts,
    Events,
    Tasks,
}

fn class_of(id: &str) -> Option<Class> {
    if id.starts_with(TASKS_PREFIX) {
        Some(Class::Tasks)
    } else if id.starts_with(CALENDAR_PREFIX) {
        Some(Class::Events)
    } else if id.starts_with(CONTACTS_PREFIX) {
        Some(Class::Contacts)
    } else {
        None
    }
}

fn conn(account: &Account) -> anyhow::Result<rmail_common::sqlite_pool::SqliteConnection> {
    rmail_common::jmap::store::open(
        &account.state.mail_root,
        &account.user.domain,
        &account.user.localpart,
    )
}

fn calendars_for(conn: &Connection, component: &str) -> anyhow::Result<Vec<Collection>> {
    Ok(store::collections(conn, Kind::Calendar)?
        .into_iter()
        .filter(|c| {
            !c.inbox && (c.components.is_empty() || c.components.iter().any(|k| k == component))
        })
        .collect())
}

/// The address books and calendars as folders: id -> (parent, name, type).
pub(super) fn folders(account: &Account) -> anyhow::Result<state::FolderList> {
    let conn = conn(account)?;
    let mut out = BTreeMap::new();
    let name = |c: &Collection| {
        c.displayname
            .clone()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| c.name.clone())
    };
    for book in store::collections(&conn, Kind::AddressBook)? {
        let kind = if book.name == "default" { 9 } else { 14 };
        out.insert(
            format!("{CONTACTS_PREFIX}{}", book.id),
            ("0".to_string(), name(&book), kind),
        );
    }
    for calendar in calendars_for(&conn, "VEVENT")? {
        let kind = if calendar.name == "default" { 8 } else { 13 };
        out.insert(
            format!("{CALENDAR_PREFIX}{}", calendar.id),
            ("0".to_string(), name(&calendar), kind),
        );
    }
    for list in calendars_for(&conn, "VTODO")? {
        let (kind, title) = if list.name == "default" {
            (7, "Tasks".to_string())
        } else {
            (15, name(&list))
        };
        out.insert(
            format!("{TASKS_PREFIX}{}", list.id),
            ("0".to_string(), title, kind),
        );
    }
    Ok(out)
}

fn collection_of(conn: &Connection, id: &str) -> anyhow::Result<Option<Collection>> {
    let (kind, number) = if let Some(n) = id.strip_prefix(TASKS_PREFIX) {
        (Kind::Calendar, n)
    } else if let Some(n) = id.strip_prefix(CALENDAR_PREFIX) {
        (Kind::Calendar, n)
    } else if let Some(n) = id.strip_prefix(CONTACTS_PREFIX) {
        (Kind::AddressBook, n)
    } else {
        return Ok(None);
    };
    let Ok(number) = number.parse::<i64>() else {
        return Ok(None);
    };
    Ok(store::collection_by_id(conn, number)?.filter(|c| c.kind == kind && !c.inbox))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// An item's ServerId (at most 64 characters).
fn item_id(name: &str) -> String {
    if name.len() <= 60
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
    {
        name.to_string()
    } else {
        let digest = Sha256::digest(name.as_bytes());
        format!("h{}", hex(&digest[..20]))
    }
}

fn objects(
    conn: &Connection,
    collection: &Collection,
    class: Class,
) -> anyhow::Result<Vec<Object>> {
    Ok(store::objects(conn, collection)?
        .into_iter()
        .filter(|o| match class {
            Class::Contacts => true,
            Class::Events => o.component.as_deref() == Some("VEVENT"),
            Class::Tasks => o.component.as_deref() == Some("VTODO"),
        })
        .collect())
}

fn find(
    conn: &Connection,
    collection: &Collection,
    class: Class,
    id: &str,
) -> anyhow::Result<Option<Object>> {
    Ok(objects(conn, collection, class)?
        .into_iter()
        .find(|o| item_id(&o.name) == id))
}

// ---------------------------------------------------------------------------
// Contacts

const PHONE_SLOTS: &[(&str, &[&str])] = &[
    ("Contacts:MobilePhoneNumber", &["cell", "mobile"]),
    ("Contacts:BusinessPhoneNumber", &["work"]),
    ("Contacts:Business2PhoneNumber", &["work"]),
    ("Contacts:HomePhoneNumber", &["home", ""]),
    ("Contacts:Home2PhoneNumber", &["home", ""]),
    ("Contacts:BusinessFaxNumber", &["fax"]),
    ("Contacts:PagerNumber", &["pager"]),
    ("Contacts:CarPhoneNumber", &["car"]),
];

fn address_tags(kind: &str) -> [&'static str; 5] {
    match kind {
        "work" => [
            "Contacts:BusinessStreet",
            "Contacts:BusinessCity",
            "Contacts:BusinessState",
            "Contacts:BusinessPostalCode",
            "Contacts:BusinessCountry",
        ],
        "home" => [
            "Contacts:HomeStreet",
            "Contacts:HomeCity",
            "Contacts:HomeState",
            "Contacts:HomePostalCode",
            "Contacts:HomeCountry",
        ],
        _ => [
            "Contacts:OtherStreet",
            "Contacts:OtherCity",
            "Contacts:OtherState",
            "Contacts:OtherPostalCode",
            "Contacts:OtherCountry",
        ],
    }
}

/// Which ActiveSync phone field each phone goes in (phones that fit
/// none are not sent): (field, index into `phones`).
fn phone_slots(phones: &[Entry]) -> Vec<(&'static str, usize)> {
    let mut used: Vec<(&'static str, usize)> = Vec::new();
    for (index, phone) in phones.iter().enumerate() {
        let free = |tag: &&str| !used.iter().any(|(t, _)| t == tag);
        let slot = PHONE_SLOTS
            .iter()
            .find(|(tag, kinds)| free(tag) && kinds.contains(&phone.kind.as_str()))
            .or_else(|| {
                PHONE_SLOTS.iter().find(|(tag, _)| {
                    free(tag)
                        && (*tag == "Contacts:Home2PhoneNumber"
                            || *tag == "Contacts:Business2PhoneNumber")
                })
            })
            .map(|(tag, _)| *tag);
        if let Some(slot) = slot {
            used.push((slot, index));
        }
    }
    used
}

/// Which ActiveSync address (work, home, other) each address goes in:
/// (kind, index into `addresses`).
fn address_slots(addresses: &[PostalAddress]) -> Vec<(&'static str, usize)> {
    let mut used: Vec<(&'static str, usize)> = Vec::new();
    for (index, address) in addresses.iter().enumerate() {
        let free = |kind: &str| !used.iter().any(|(k, _)| *k == kind);
        let kind = match address.kind.as_str() {
            "work" if free("work") => "work",
            "home" if free("home") => "home",
            _ if free("other") => "other",
            _ => continue,
        };
        used.push((kind, index));
    }
    used
}

/// Whether a contact has emails, phones or addresses a device is not sent.
fn has_unsent(object: &Object) -> bool {
    let Ok(card) = text::parse(&object.data) else {
        return false;
    };
    let fields = contacts::fields_of(&card);
    fields.emails.len() > 3
        || phone_slots(&fields.phones).len() < fields.phones.len()
        || address_slots(&fields.addresses).len() < fields.addresses.len()
}

fn contact_data(tag: &str, object: &Object) -> anyhow::Result<Element> {
    let card = text::parse(&object.data).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let fields = contacts::fields_of(&card);
    let mut data = Element::new(tag);
    let mut put = |name: &str, value: &str| {
        if !value.trim().is_empty() {
            data.push(Element::text(name, value.trim()));
        }
    };
    let file_as = if !fields.family.is_empty() && !fields.given.is_empty() {
        format!("{}, {}", fields.family, fields.given)
    } else {
        fields.full_name.clone()
    };
    put("Contacts:FileAs", &file_as);
    put("Contacts:FirstName", &fields.given);
    put("Contacts:LastName", &fields.family);
    put("Contacts:CompanyName", &fields.org);
    put("Contacts:JobTitle", &fields.title);
    for (index, email) in fields.emails.iter().take(3).enumerate() {
        put(
            [
                "Contacts:Email1Address",
                "Contacts:Email2Address",
                "Contacts:Email3Address",
            ][index],
            &email.value,
        );
    }
    for (slot, index) in phone_slots(&fields.phones) {
        put(slot, &fields.phones[index].value);
    }
    for (kind, index) in address_slots(&fields.addresses) {
        let address = &fields.addresses[index];
        let tags = address_tags(kind);
        for (tag, value) in tags.iter().zip([
            &address.street,
            &address.city,
            &address.region,
            &address.postcode,
            &address.country,
        ]) {
            put(tag, value);
        }
    }
    if fields.birthday.len() == 10 && !fields.birthday.starts_with("--") {
        put(
            "Contacts:Birthday",
            &format!("{}T00:00:00.000Z", fields.birthday),
        );
    }
    if !fields.note.is_empty() {
        data.push(
            Element::new("AirSyncBase:Body")
                .with(Element::text("AirSyncBase:Type", "1"))
                .with(Element::text(
                    "AirSyncBase:EstimatedDataSize",
                    fields.note.len().to_string(),
                ))
                .with(Element::text(
                    "AirSyncBase:Data",
                    fields.note.replace('\n', "\r\n"),
                )),
        );
    }
    Ok(data)
}

/// The fields a device's contact sets. A change replaces what the device
/// was sent (ActiveSync clients send every property); what it could not
/// be sent (`previous` beyond its fields) is kept, and kinds it has no
/// field for stay as they were.
fn contact_fields(data: &Element, previous: Option<&Fields>) -> Fields {
    let value = |tag: &str| data.value(tag).unwrap_or_default().trim().to_string();
    let mut fields = Fields {
        given: value("Contacts:FirstName"),
        family: value("Contacts:LastName"),
        org: value("Contacts:CompanyName"),
        title: value("Contacts:JobTitle"),
        ..Fields::default()
    };
    let file_as = value("Contacts:FileAs");
    fields.full_name = if fields.given.is_empty() && fields.family.is_empty() {
        file_as
    } else {
        String::new()
    };
    for (index, tag) in [
        "Contacts:Email1Address",
        "Contacts:Email2Address",
        "Contacts:Email3Address",
    ]
    .into_iter()
    .enumerate()
    {
        let raw = value(tag);
        let address = rmail_common::jmap::address::parse(&raw)
            .into_iter()
            .next()
            .map(|a| a.email)
            .unwrap_or(raw);
        if !address.is_empty() {
            let kind = previous
                .and_then(|p| p.emails.get(index))
                .filter(|e| e.value.eq_ignore_ascii_case(&address))
                .map(|e| e.kind.clone())
                .unwrap_or_default();
            fields.emails.push(Entry {
                kind,
                value: address,
            });
        }
    }
    let empty = Fields::default();
    let previous = previous.unwrap_or(&empty);
    let sent_phones = phone_slots(&previous.phones);
    for (tag, kinds) in PHONE_SLOTS {
        let number = value(tag);
        if !number.is_empty() {
            let kind = sent_phones
                .iter()
                .find(|(t, _)| t == tag)
                .map(|(_, i)| &previous.phones[*i])
                .filter(|p| p.value == number)
                .map_or_else(|| kinds[0].to_string(), |p| p.kind.clone());
            fields.phones.push(Entry {
                kind,
                value: number,
            });
        }
    }
    let sent_addresses = address_slots(&previous.addresses);
    for kind in ["work", "home", "other"] {
        let tags = address_tags(kind);
        let part = |i: usize| value(tags[i]);
        let address = PostalAddress {
            kind: sent_addresses.iter().find(|(k, _)| *k == kind).map_or_else(
                || kind.to_string(),
                |(_, i)| previous.addresses[*i].kind.clone(),
            ),
            street: part(0),
            city: part(1),
            region: part(2),
            postcode: part(3),
            country: part(4),
        };
        if [
            &address.street,
            &address.city,
            &address.region,
            &address.postcode,
            &address.country,
        ]
        .iter()
        .any(|p| !p.is_empty())
        {
            fields.addresses.push(address);
        }
    }
    let birthday = value("Contacts:Birthday");
    if birthday.len() >= 10 {
        fields.birthday = birthday[..10].to_string();
    } else if previous.birthday.starts_with("--") {
        // A birthday without a year is not sent.
        fields.birthday = previous.birthday.clone();
    }
    // What the device was not sent.
    fields
        .emails
        .extend(previous.emails.iter().skip(3).cloned());
    fields.phones.extend(
        (0..previous.phones.len())
            .filter(|i| !sent_phones.iter().any(|(_, s)| s == i))
            .map(|i| previous.phones[i].clone()),
    );
    fields.addresses.extend(
        (0..previous.addresses.len())
            .filter(|i| !sent_addresses.iter().any(|(_, s)| s == i))
            .map(|i| previous.addresses[i].clone()),
    );
    fields.note = data
        .child("AirSyncBase:Body")
        .and_then(|b| b.value("AirSyncBase:Data"))
        .unwrap_or_default()
        .replace("\r\n", "\n");
    contacts::tidy(fields)
}

// ---------------------------------------------------------------------------
// Calendar

/// A TIME_ZONE_INFORMATION blob for UTC (MS-ASDTYPE 2.6.4): times are
/// sent in UTC.
fn utc_zone() -> String {
    base64::engine::general_purpose::STANDARD.encode([0u8; 172])
}

/// The UTC offsets (seconds, local = UTC + offset) of a device's
/// TIME_ZONE_INFORMATION blob: standard time, then daylight time.
fn zone_offsets(zone: &str) -> Vec<i64> {
    let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(zone.trim()) else {
        return Vec::new();
    };
    if blob.len() < 172 {
        return Vec::new();
    }
    let at = |i: usize| {
        i64::from(i32::from_le_bytes([
            blob[i],
            blob[i + 1],
            blob[i + 2],
            blob[i + 3],
        ]))
    };
    // Bias, then StandardName (64), StandardDate (16), StandardBias,
    // DaylightName (64), DaylightDate (16), DaylightBias; UTC = local + bias.
    let bias = at(0);
    vec![-(bias + at(84)) * 60, -(bias + at(168)) * 60]
}

fn compact(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0)
        .unwrap_or_default()
        .format("%Y%m%dT%H%M%SZ")
        .to_string()
}

fn email_time(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%S.000Z")
        .to_string()
}

fn parse_time(text: &str) -> Option<i64> {
    let text = text.trim();
    chrono::NaiveDateTime::parse_from_str(text, "%Y%m%dT%H%M%SZ")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S%.fZ"))
        .ok()
        .map(|t| t.and_utc().timestamp())
}

fn attendee_status(status: &str) -> &'static str {
    match status {
        "accepted" => "3",
        "tentative" => "2",
        "declined" => "4",
        "needs-action" => "5",
        _ => "0",
    }
}

/// The ActiveSync recurrence of an event's rule, as near as it goes.
fn recurrence(event: &text::Component, start: i64) -> Option<Element> {
    let rule = event.property("RRULE")?;
    let mut parts: BTreeMap<String, String> = BTreeMap::new();
    for part in rule.value.split(';') {
        if let Some((key, value)) = part.split_once('=') {
            parts.insert(
                key.trim().to_ascii_uppercase(),
                value.trim().to_ascii_uppercase(),
            );
        }
    }
    let start = chrono::DateTime::from_timestamp(start, 0)?;
    use chrono::Datelike;
    let kind = match parts.get("FREQ")?.as_str() {
        "DAILY" => "0",
        "WEEKLY" => "1",
        "MONTHLY" => "2",
        "YEARLY" => "5",
        _ => return None,
    };
    let mut out = Element::new("Calendar:Recurrence").with(Element::text("Calendar:Type", kind));
    if let Some(interval) = parts.get("INTERVAL") {
        out.push(Element::text("Calendar:Interval", interval.clone()));
    } else {
        out.push(Element::text("Calendar:Interval", "1"));
    }
    if let Some(count) = parts.get("COUNT") {
        out.push(Element::text("Calendar:Occurrences", count.clone()));
    } else if let Some(until) = parts.get("UNTIL") {
        let until = if until.len() == 8 {
            format!("{until}T000000Z")
        } else {
            until.clone()
        };
        out.push(Element::text("Calendar:Until", until));
    }
    let day_bit = |day: &str| match day {
        "SU" => 1,
        "MO" => 2,
        "TU" => 4,
        "WE" => 8,
        "TH" => 16,
        "FR" => 32,
        "SA" => 64,
        _ => 0,
    };
    match kind {
        "1" => {
            let mask = match parts.get("BYDAY") {
                Some(days) => days
                    .split(',')
                    .map(|d| {
                        day_bit(d.trim_start_matches(|c: char| c == '-' || c.is_ascii_digit()))
                    })
                    .sum(),
                None => 1 << start.weekday().num_days_from_sunday(),
            };
            out.push(Element::text("Calendar:DayOfWeek", mask.to_string()));
        }
        "2" => out.push(Element::text(
            "Calendar:DayOfMonth",
            start.day().to_string(),
        )),
        "5" => {
            out.push(Element::text(
                "Calendar:DayOfMonth",
                start.day().to_string(),
            ));
            out.push(Element::text(
                "Calendar:MonthOfYear",
                start.month().to_string(),
            ));
        }
        _ => {}
    }
    Some(out)
}

fn event_data(tag: &str, object: &Object, me: &[String]) -> anyhow::Result<Element> {
    let calendar = text::parse(&object.data).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let master = events::master(&calendar).ok_or_else(|| anyhow::anyhow!("no event"))?;
    let organizer = itip::organizer(&calendar);
    let fields = events::fields_of(&calendar, organizer.as_deref())
        .ok_or_else(|| anyhow::anyhow!("no event"))?;
    let attendees = events::attendees_of(master);
    let mine = |address: &str| me.iter().any(|m| m.eq_ignore_ascii_case(address));
    let mut data = Element::new(tag)
        .with(Element::text("Calendar:TimeZone", utc_zone()))
        .with(Element::text(
            "Calendar:AllDayEvent",
            if fields.all_day { "1" } else { "0" },
        ))
        .with(Element::text("Calendar:DtStamp", compact(object.modified)))
        .with(Element::text("Calendar:StartTime", compact(fields.start)))
        .with(Element::text("Calendar:EndTime", compact(fields.end)))
        .with(Element::text("Calendar:Subject", fields.summary.clone()))
        .with(Element::text(
            "Calendar:UID",
            object.uid.clone().unwrap_or_default(),
        ));
    if !fields.location.is_empty() {
        data.push(Element::text("Calendar:Location", fields.location.clone()));
    }
    if !fields.description.is_empty() {
        data.push(
            Element::new("AirSyncBase:Body")
                .with(Element::text("AirSyncBase:Type", "1"))
                .with(Element::text(
                    "AirSyncBase:EstimatedDataSize",
                    fields.description.len().to_string(),
                ))
                .with(Element::text(
                    "AirSyncBase:Data",
                    fields.description.replace('\n', "\r\n"),
                )),
        );
    }
    data.push(Element::text("Calendar:Sensitivity", "0"));
    data.push(Element::text("Calendar:BusyStatus", "2"));
    if attendees.is_empty() {
        data.push(Element::text("Calendar:MeetingStatus", "0"));
    } else {
        let organizing = organizer.as_deref().is_none_or(mine);
        data.push(Element::text(
            "Calendar:MeetingStatus",
            if organizing { "1" } else { "3" },
        ));
        if let Some(organizer) = &organizer {
            data.push(Element::text("Calendar:OrganizerEmail", organizer.clone()));
            data.push(Element::text("Calendar:OrganizerName", organizer.clone()));
        }
        let mut list = Element::new("Calendar:Attendees");
        for attendee in &attendees {
            let element = Element::new("Calendar:Attendee")
                .with(Element::text("Calendar:Email", attendee.address.clone()))
                .with(Element::text(
                    "Calendar:Name",
                    if attendee.name.is_empty() {
                        attendee.address.clone()
                    } else {
                        attendee.name.clone()
                    },
                ))
                .with(Element::text(
                    "Calendar:AttendeeStatus",
                    attendee_status(&attendee.status),
                ))
                .with(Element::text("Calendar:AttendeeType", "1"));
            list.push(element);
        }
        data.push(list);
        if !organizing && let Some(own) = attendees.iter().find(|a| mine(&a.address)) {
            data.push(Element::text(
                "Calendar:ResponseType",
                attendee_status(&own.status),
            ));
        }
        data.push(Element::text("Calendar:ResponseRequested", "1"));
    }
    if let Some(rule) = recurrence(master, fields.start) {
        data.push(rule);
    }
    Ok(data)
}

/// The event fields a device's event sets.
fn event_fields(data: &Element, previous: Option<&EventFields>) -> Option<EventFields> {
    let start = parse_time(&data.value("Calendar:StartTime")?)?;
    let end = data
        .value("Calendar:EndTime")
        .and_then(|e| parse_time(&e))
        .unwrap_or(start + 3600);
    let all_day = data.value("Calendar:AllDayEvent").as_deref() == Some("1");
    let repeat = match data.child("Calendar:Recurrence") {
        None => "none".to_string(),
        // A rule webmail cannot write stays as it was.
        Some(_) if previous.is_some_and(|p| p.repeat == "custom") => "custom".to_string(),
        Some(rule) => {
            let single_day = rule
                .value("Calendar:DayOfWeek")
                .and_then(|d| d.parse::<u32>().ok())
                .is_none_or(|d| d.count_ones() <= 1);
            let simple = rule.value("Calendar:Interval").is_none_or(|i| i == "1")
                && rule.child("Calendar:Until").is_none()
                && rule.child("Calendar:Occurrences").is_none()
                && single_day;
            match rule.value("Calendar:Type").as_deref() {
                Some("0") if simple => "daily".to_string(),
                Some("1") if simple => "weekly".to_string(),
                Some("2") if simple => "monthly".to_string(),
                Some("5") if simple => "yearly".to_string(),
                _ => return None,
            }
        }
    };
    // Phones often leave attendees out of a change; they stay as they were.
    let attendees = match data.child("Calendar:Attendees") {
        Some(list) => list
            .children_named("Calendar:Attendee")
            .filter_map(|a| a.value("Calendar:Email"))
            .filter(|e| e.contains('@'))
            .collect(),
        None => previous.map(|p| p.attendees.clone()).unwrap_or_default(),
    };
    // All-day times are the device's local midnights in UTC: the date is
    // taken in its zone (standard or daylight time, whichever makes a
    // midnight), else from the nearest UTC midnight.
    let offsets = data
        .value("Calendar:TimeZone")
        .map(|zone| zone_offsets(&zone))
        .unwrap_or_default();
    let midnight = |t: i64| {
        offsets
            .iter()
            .map(|offset| t + offset)
            .find(|local| local.rem_euclid(86_400) == 0)
            .unwrap_or_else(|| (t + 43_200).div_euclid(86_400) * 86_400)
    };
    Some(EventFields {
        summary: data
            .value("Calendar:Subject")
            .unwrap_or_default()
            .replace(['\r', '\n'], " "),
        location: data
            .value("Calendar:Location")
            .unwrap_or_default()
            .replace(['\r', '\n'], " "),
        description: data
            .child("AirSyncBase:Body")
            .and_then(|b| b.value("AirSyncBase:Data"))
            .unwrap_or_default()
            .replace("\r\n", "\n"),
        start: if all_day { midnight(start) } else { start },
        end: if all_day {
            midnight(end).max(midnight(start) + 86_400)
        } else {
            end
        },
        all_day,
        timezone: previous.map(|p| p.timezone.clone()).unwrap_or_default(),
        repeat,
        attendees,
    })
}

// ---------------------------------------------------------------------------
// Tasks

/// ActiveSync's importance (0 low, 1 normal, 2 high) for an iCalendar
/// PRIORITY.
fn importance(priority: u8) -> &'static str {
    match priority {
        1..=4 => "2",
        6..=9 => "0",
        _ => "1",
    }
}

fn task_data(tag: &str, object: &Object) -> anyhow::Result<Element> {
    let calendar = text::parse(&object.data).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let fields = tasks::task_fields(&calendar).ok_or_else(|| anyhow::anyhow!("no task"))?;
    let todo = tasks::todo(&calendar).ok_or_else(|| anyhow::anyhow!("no task"))?;
    let mut data = Element::new(tag);
    if !fields.notes.is_empty() {
        data.push(
            Element::new("AirSyncBase:Body")
                .with(Element::text("AirSyncBase:Type", "1"))
                .with(Element::text(
                    "AirSyncBase:EstimatedDataSize",
                    fields.notes.len().to_string(),
                ))
                .with(Element::text(
                    "AirSyncBase:Data",
                    fields.notes.replace('\n', "\r\n"),
                )),
        );
    }
    data.push(Element::text("Tasks:Subject", fields.summary.clone()));
    data.push(Element::text(
        "Tasks:Importance",
        importance(fields.priority),
    ));
    if let Some(start) = todo.property("DTSTART").and_then(recur::instant) {
        data.push(Element::text("Tasks:UtcStartDate", email_time(start)));
        data.push(Element::text("Tasks:StartDate", email_time(start)));
    }
    if let Some(due) = fields.due {
        data.push(Element::text("Tasks:UtcDueDate", email_time(due)));
        data.push(Element::text("Tasks:DueDate", email_time(due)));
    }
    data.push(Element::text(
        "Tasks:Complete",
        if fields.completed { "1" } else { "0" },
    ));
    if fields.completed {
        let done = todo
            .property("COMPLETED")
            .and_then(recur::instant)
            .unwrap_or(object.modified);
        data.push(Element::text("Tasks:DateCompleted", email_time(done)));
    }
    data.push(Element::text("Tasks:Sensitivity", "0"));
    data.push(Element::text("Tasks:ReminderSet", "0"));
    Ok(data)
}

/// The task fields a device's task sets; what it has no field for (the
/// time of a date-only due date, a priority between the three levels) is
/// kept from `previous`.
fn task_fields_from(data: &Element, previous: Option<&tasks::TaskFields>) -> tasks::TaskFields {
    let value = |tag: &str| data.value(tag).unwrap_or_default().trim().to_string();
    // DueDate is the device's local time written as if UTC: a midnight
    // there is a date without a time.
    let local_due = data.value("Tasks:DueDate").and_then(|d| parse_time(&d));
    let utc_due = data
        .value("Tasks:UtcDueDate")
        .and_then(|d| parse_time(&d))
        .or(local_due);
    let (due, due_all_day) = match (local_due, utc_due) {
        (Some(local), _) if local.rem_euclid(86_400) == 0 => (Some(local), true),
        (_, Some(utc)) => (Some(utc), false),
        _ => (None, false),
    };
    let previous_priority = previous.map_or(0, |p| p.priority);
    // An importance the device leaves out stays as it was (MS-ASTASK).
    let priority = match data.value("Tasks:Importance").as_deref() {
        None => previous_priority,
        Some("2") if importance(previous_priority) == "2" => previous_priority,
        Some("2") => 1,
        Some("0") if importance(previous_priority) == "0" => previous_priority,
        Some("0") => 9,
        _ if importance(previous_priority) == "1" => previous_priority,
        _ => 0,
    };
    tasks::TaskFields {
        summary: value("Tasks:Subject").replace(['\r', '\n'], " "),
        notes: data
            .child("AirSyncBase:Body")
            .and_then(|b| b.value("AirSyncBase:Data"))
            .unwrap_or_default()
            .replace("\r\n", "\n"),
        due,
        due_all_day,
        priority,
        completed: value("Tasks:Complete") == "1",
    }
}

fn store_task(
    account: &Account,
    conn: &Connection,
    collection: &Collection,
    existing: Option<&Object>,
    new_uid: &str,
    data: &Element,
) -> anyhow::Result<Option<String>> {
    let previous = existing
        .and_then(|o| text::parse(&o.data).ok())
        .and_then(|c| tasks::task_fields(&c));
    let fields = task_fields_from(data, previous.as_ref());
    let (name, uid) = match existing {
        Some(object) => (Some(object.name.clone()), None),
        None => {
            // A repeated Add (a retried Sync) finds what it stored.
            let name = format!("{new_uid}.ics");
            if store::object(conn, collection, &name)?.is_some() {
                return Ok(Some(name));
            }
            (None, Some(new_uid.to_string()))
        }
    };
    let saved = tasks::save(
        &account.state,
        &session(account),
        &format!("own:{}", collection.name),
        name.as_deref(),
        &fields,
        existing.map(|o| o.etag.clone()),
        uid,
    )?;
    Ok(saved.ok())
}

// ---------------------------------------------------------------------------
// Sync

fn session(account: &Account) -> Session {
    Session {
        address: account.user.address.clone(),
        domain: account.user.domain.clone(),
        localpart: account.user.localpart.clone(),
    }
}

fn item_data(class: Class, object: &Object, me: &[String]) -> anyhow::Result<Element> {
    match class {
        Class::Contacts => contact_data("AirSync:ApplicationData", object),
        Class::Events => event_data("AirSync:ApplicationData", object, me),
        Class::Tasks => task_data("AirSync:ApplicationData", object),
    }
}

/// Apply a device's Add or Change; returns the stored resource name.
fn store_item(
    account: &Account,
    conn: &Connection,
    collection: &Collection,
    class: Class,
    existing: Option<&Object>,
    new_uid: &str,
    data: &Element,
) -> anyhow::Result<Option<String>> {
    if collection.managed {
        return Ok(None);
    }
    if class == Class::Tasks {
        return store_task(account, conn, collection, existing, new_uid, data);
    }
    if class == Class::Contacts {
        let previous = existing
            .and_then(|o| text::parse(&o.data).ok())
            .map(|card| contacts::fields_of(&card));
        let fields = contact_fields(data, previous.as_ref());
        if contacts::check(&fields).is_err() || !contacts::valid_birthday(&fields.birthday) {
            return Ok(None);
        }
        let (name, uid, etag) = match existing {
            Some(object) => (
                object.name.clone(),
                object.uid.clone().unwrap_or_default(),
                Some(object.etag.clone()),
            ),
            None => {
                let name = format!("{new_uid}.vcf");
                // A repeated Add (a retried Sync) finds what it stored.
                if store::object(conn, collection, &name)?.is_some() {
                    return Ok(Some(name));
                }
                (name, new_uid.to_string(), None)
            }
        };
        let text = contacts::card_text(existing.map(|o| o.data.as_str()), &fields, &uid);
        let stored = store::put(
            conn,
            collection,
            &name,
            &text,
            &|current| match (&etag, current) {
                (None, None) => true,
                (Some(etag), Some(current)) => &current.etag == etag,
                _ => false,
            },
        )?;
        return Ok(stored.ok().map(|_| name));
    }
    let previous = existing
        .and_then(|o| text::parse(&o.data).ok())
        .and_then(|c| events::fields_of(&c, Some(&account.user.address)));
    let Some(fields) = event_fields(data, previous.as_ref()) else {
        return Ok(None);
    };
    if events::check(&fields).is_err() {
        return Ok(None);
    }
    let uid = match existing {
        Some(_) => None,
        None => {
            let uid = data
                .value("Calendar:UID")
                .filter(|u| !u.trim().is_empty())
                .unwrap_or_else(|| new_uid.to_string());
            // A repeated Add (a retried Sync) finds what it stored.
            if let Some((found, object)) = store::find_by_uid(conn, &uid)?
                && found.id == collection.id
            {
                return Ok(Some(object.name));
            }
            Some(uid)
        }
    };
    let saved = events::save(
        &account.state,
        &session(account),
        &format!("own:{}", collection.name),
        existing.map(|o| o.name.as_str()),
        events::Change {
            fields,
            etag: existing.map(|o| o.etag.clone()),
            schedule: true,
            uid,
        },
    )?;
    Ok(saved.ok())
}

pub(super) fn sync_collection(
    account: &Account,
    db: &Connection,
    request: &Element,
    window: Option<usize>,
) -> anyhow::Result<Element> {
    let id = request.value("AirSync:CollectionId").unwrap_or_default();
    let key: i64 = request
        .value("AirSync:SyncKey")
        .and_then(|k| k.parse().ok())
        .unwrap_or(-1);
    let mut response = Element::new("AirSync:Collection");
    let status = |code: &str| Element::text("AirSync:Status", code);
    let conn = conn(account)?;
    let (Some(collection), Some(class)) = (collection_of(&conn, &id)?, class_of(&id)) else {
        return Ok(response
            .with(Element::text("AirSync:CollectionId", id))
            .with(status("8")));
    };
    if key == 0 {
        state::save_items(db, &account.device, &id, 1, &Items::new(), None)?;
        return Ok(response
            .with(Element::text("AirSync:SyncKey", "1"))
            .with(Element::text("AirSync:CollectionId", id))
            .with(status("1")));
    }
    let Some(known) = state::items_state(db, &account.device, &id)? else {
        return Ok(response
            .with(Element::text("AirSync:SyncKey", "0"))
            .with(Element::text("AirSync:CollectionId", id))
            .with(status("3")));
    };
    let mut base = if key == known.0 {
        known.1.clone()
    } else if key == known.2 {
        known.3.clone()
    } else {
        return Ok(response
            .with(Element::text("AirSync:SyncKey", "0"))
            .with(Element::text("AirSync:CollectionId", id))
            .with(status("3")));
    };
    let me = rmail_common::db::calendar_addresses(&account.state.db_path, &account.user.address)
        .unwrap_or_else(|_| vec![account.user.address.clone()]);
    let mut responses = Element::new("AirSync:Responses");
    if let Some(commands) = request.child("AirSync:Commands") {
        for command in &commands.children {
            let server_id = command.value("AirSync:ServerId").unwrap_or_default();
            match command.name {
                "Add" => {
                    let client = command.value("AirSync:ClientId").unwrap_or_default();
                    // Named after the device's ClientId, so a retried Sync
                    // does not add it twice.
                    let new_uid = if client.is_empty() {
                        contacts::uuid()
                    } else {
                        let digest = Sha256::digest(format!("{}\0{id}\0{client}", account.device));
                        format!("eas-{}", hex(&digest[..16]))
                    };
                    let stored = match command.child("AirSync:ApplicationData") {
                        Some(data) => {
                            store_item(account, &conn, &collection, class, None, &new_uid, data)?
                        }
                        None => None,
                    };
                    let mut answer =
                        Element::new("AirSync:Add").with(Element::text("AirSync:ClientId", client));
                    match stored
                        .and_then(|name| store::object(&conn, &collection, &name).ok().flatten())
                    {
                        Some(object) => {
                            let item = item_id(&object.name);
                            base.insert(item.clone(), object.etag.clone());
                            answer.push(Element::text("AirSync:ServerId", item));
                            answer.push(status("1"));
                        }
                        None => answer.push(status("6")),
                    }
                    responses.push(answer);
                }
                // A retried Sync's changes were made by the first attempt;
                // the device gets the stored version back.
                "Change" if key != known.0 => {}
                "Change" => {
                    let existing = find(&conn, &collection, class, &server_id)?;
                    // When a contact had more than the device was sent, the
                    // merged version goes back to it.
                    let echo =
                        class == Class::Contacts && existing.as_ref().is_some_and(has_unsent);
                    let stored = match (&existing, command.child("AirSync:ApplicationData")) {
                        (Some(object), Some(data)) => {
                            store_item(account, &conn, &collection, class, Some(object), "", data)?
                        }
                        _ => None,
                    };
                    match stored
                        .and_then(|name| store::object(&conn, &collection, &name).ok().flatten())
                    {
                        Some(object) => {
                            if !echo {
                                base.insert(server_id, object.etag.clone());
                            }
                        }
                        None => responses.push(
                            Element::new("AirSync:Change")
                                .with(Element::text("AirSync:ServerId", server_id))
                                .with(status(if existing.is_some() { "6" } else { "8" })),
                        ),
                    }
                }
                "Delete" => {
                    if let Some(object) = find(&conn, &collection, class, &server_id)?
                        && !collection.managed
                    {
                        if class == Class::Events {
                            events::remove_event(
                                &account.state,
                                &session(account),
                                &format!("own:{}", collection.name),
                                &object.name,
                                None,
                                true,
                            )?
                            .ok();
                        } else {
                            store::delete(&conn, &collection, &object.name, &|_| true)?;
                        }
                    }
                    base.remove(&server_id);
                }
                "Fetch" => match find(&conn, &collection, class, &server_id)? {
                    Some(object) => responses.push(
                        Element::new("AirSync:Fetch")
                            .with(Element::text("AirSync:ServerId", server_id))
                            .with(status("1"))
                            .with(item_data(class, &object, &me)?),
                    ),
                    None => responses.push(
                        Element::new("AirSync:Fetch")
                            .with(Element::text("AirSync:ServerId", server_id))
                            .with(status("8")),
                    ),
                },
                _ => {}
            }
        }
    }
    let now: Vec<Object> = objects(&conn, &collection, class)?;
    let current: Items = now
        .iter()
        .map(|o| (item_id(&o.name), o.etag.clone()))
        .collect();
    let limit = request
        .value("AirSync:WindowSize")
        .and_then(|w| w.parse::<usize>().ok())
        .or(window)
        .unwrap_or(100)
        .clamp(1, 512);
    let mut commands = Element::new("AirSync:Commands");
    let mut next = base.clone();
    let mut sent = 0;
    let mut more = false;
    if request.value("AirSync:GetChanges").is_none_or(|v| v != "0") {
        for gone in base
            .keys()
            .filter(|id| !current.contains_key(*id))
            .cloned()
            .collect::<Vec<_>>()
        {
            if sent >= limit {
                more = true;
                break;
            }
            commands.push(
                Element::new("AirSync:Delete")
                    .with(Element::text("AirSync:ServerId", gone.clone())),
            );
            next.remove(&gone);
            sent += 1;
        }
        for object in &now {
            let item = item_id(&object.name);
            let tag = match base.get(&item) {
                None => "AirSync:Add",
                Some(etag) if etag != &object.etag => "AirSync:Change",
                Some(_) => continue,
            };
            if sent >= limit {
                more = true;
                break;
            }
            let Ok(data) = item_data(class, object, &me) else {
                continue;
            };
            commands.push(
                Element::new(tag)
                    .with(Element::text("AirSync:ServerId", item.clone()))
                    .with(data),
            );
            next.insert(item, object.etag.clone());
            sent += 1;
        }
    }
    let new_key = if key == known.0 { known.0 + 1 } else { known.0 };
    state::save_items(db, &account.device, &id, new_key, &next, Some((key, &base)))?;
    response.push(Element::text("AirSync:SyncKey", new_key.to_string()));
    response.push(Element::text("AirSync:CollectionId", id));
    response.push(status("1"));
    if more {
        response.push(Element::new("AirSync:MoreAvailable"));
    }
    if !commands.children.is_empty() {
        response.push(commands);
    }
    if !responses.children.is_empty() {
        response.push(responses);
    }
    Ok(response)
}

/// Changes waiting for a device in a contacts or calendar folder.
pub(super) fn pending(account: &Account, db: &Connection, id: &str) -> anyhow::Result<usize> {
    let conn = conn(account)?;
    let (Some(collection), Some(class)) = (collection_of(&conn, id)?, class_of(id)) else {
        return Ok(0);
    };
    let Some(known) = state::items_state(db, &account.device, id)? else {
        return Ok(1);
    };
    let current: Items = objects(&conn, &collection, class)?
        .iter()
        .map(|o| (item_id(&o.name), o.etag.clone()))
        .collect();
    let changed = current
        .iter()
        .filter(|(id, etag)| known.1.get(*id) != Some(etag))
        .count();
    let gone = known
        .1
        .keys()
        .filter(|id| !current.contains_key(*id))
        .count();
    Ok(changed + gone)
}

// ---------------------------------------------------------------------------
// Invitations

/// Outlook's "GlobalObjId" for an iCalendar UID (the vCal-Uid form,
/// MS-ASEMAIL 2.2.2.42), which phones match invitations to events by.
fn global_object_id(uid: &str) -> String {
    let mut data = b"vCal-Uid".to_vec();
    data.extend(1u32.to_le_bytes());
    data.extend(uid.as_bytes());
    data.push(0);
    let mut out = vec![
        0x04, 0x00, 0x00, 0x00, 0x82, 0x00, 0xE0, 0x00, 0x74, 0xC5, 0xB7, 0x10, 0x1A, 0x82, 0xE0,
        0x08,
    ];
    out.extend([0u8; 4]); // instance date
    out.extend([0u8; 8]); // creation time
    out.extend([0u8; 8]);
    out.extend((data.len() as u32).to_le_bytes());
    out.extend(data);
    base64::engine::general_purpose::STANDARD.encode(out)
}

/// For a message carrying an invitation, cancellation or answer: its
/// MessageClass and the MeetingRequest element phones show it with.
pub(super) fn meeting(raw: &[u8]) -> Option<(&'static str, Option<Element>)> {
    let rmail_common::mime::CalendarPart::Found(data) =
        rmail_common::mime::calendar_part(raw, rmail_common::dav::imip::MAX_CALENDAR_BYTES)
    else {
        return None;
    };
    let (method, calendar) = rmail_common::dav::imip::scheduling_object(&data)
        .ok()?
        .ok()?;
    let class = match method {
        itip::Method::Request => "IPM.Schedule.Meeting.Request",
        itip::Method::Cancel => "IPM.Schedule.Meeting.Canceled",
        itip::Method::Reply => {
            let status = calendar
                .components
                .iter()
                .flat_map(|c| c.properties_named("ATTENDEE"))
                .find_map(|a| a.param("PARTSTAT").map(str::to_ascii_uppercase));
            return Some((
                match status.as_deref() {
                    Some("ACCEPTED") => "IPM.Schedule.Meeting.Resp.Pos",
                    Some("TENTATIVE") => "IPM.Schedule.Meeting.Resp.Tent",
                    _ => "IPM.Schedule.Meeting.Resp.Neg",
                },
                None,
            ));
        }
        _ => return None,
    };
    let master = events::master(&calendar)?;
    let fields = events::fields_of(&calendar, None)?;
    let uid = master
        .property("UID")
        .map(|u| u.value.clone())
        .unwrap_or_default();
    let mut request = Element::new("Email:MeetingRequest")
        .with(Element::text(
            "Email:AllDayEvent",
            if fields.all_day { "1" } else { "0" },
        ))
        .with(Element::text("Email:StartTime", email_time(fields.start)))
        .with(Element::text(
            "Email:DtStamp",
            email_time(chrono::Utc::now().timestamp()),
        ))
        .with(Element::text("Email:EndTime", email_time(fields.end)))
        .with(Element::text("Email:InstanceType", "0"));
    if !fields.location.is_empty() {
        request.push(Element::text("Email:Location", fields.location.clone()));
    }
    if let Some(organizer) = itip::organizer(&calendar) {
        request.push(Element::text("Email:Organizer", organizer));
    }
    request.push(Element::text(
        "Email:ResponseRequested",
        if method == itip::Method::Request {
            "1"
        } else {
            "0"
        },
    ));
    request.push(Element::text("Email:Sensitivity", "0"));
    request.push(Element::text("Email:BusyStatus", "2"));
    request.push(Element::text("Email:TimeZone", utc_zone()));
    request.push(Element::text("Email:GlobalObjId", global_object_id(&uid)));
    Some((class, Some(request)))
}

/// MeetingResponse: answer invitations from their message (or from the
/// event in a calendar folder), as webmail's invitation card does.
pub(super) fn meeting_response(
    account: &Account,
    db: &Connection,
    request: Option<&Element>,
) -> anyhow::Result<Element> {
    let mut response = Element::new("MeetingResponse:MeetingResponse");
    for item in request
        .map(|r| {
            r.children_named("MeetingResponse:Request")
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
    {
        let request_id = item.value("MeetingResponse:RequestId").unwrap_or_default();
        let collection = item
            .value("MeetingResponse:CollectionId")
            .unwrap_or_default();
        let action = match item.value("MeetingResponse:UserResponse").as_deref() {
            Some("1") => "accepted",
            Some("2") => "tentative",
            Some("3") => "declined",
            _ => "",
        };
        let mut result = Element::new("MeetingResponse:Result").with(Element::text(
            "MeetingResponse:RequestId",
            request_id.clone(),
        ));
        let message: Option<Vec<u8>> = if is_pim(&collection) {
            // From the calendar: the stored event, as an invitation.
            let conn = conn(account)?;
            match collection_of(&conn, &collection)? {
                Some(calendar) => {
                    find(&conn, &calendar, Class::Events, &request_id)?.map(|object| {
                        let body = object.data.replacen(
                            "BEGIN:VCALENDAR\r\n",
                            "BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\n",
                            1,
                        );
                        format!(
                        "Content-Type: text/calendar; method=REQUEST; charset=utf-8\r\n\r\n{body}"
                    )
                    .into_bytes()
                    })
                }
                None => None,
            }
        } else {
            let folder = state::folder_name(db, &collection)?;
            let uid = request_id
                .split_once(':')
                .and_then(|(_, uid)| uid.parse::<u64>().ok());
            match (folder, uid) {
                (Some(folder), Some(uid)) => account
                    .messages(&folder)?
                    .1
                    .into_iter()
                    .find(|m| m.uid == uid)
                    .and_then(|m| std::fs::read(&m.path).ok()),
                _ => None,
            }
        };
        let answered = match (message, action) {
            (Some(message), action) if !action.is_empty() => {
                let uid = rmail_common::mime::calendar_part(
                    &message,
                    rmail_common::dav::imip::MAX_CALENDAR_BYTES,
                );
                let uid = match uid {
                    rmail_common::mime::CalendarPart::Found(data) => {
                        rmail_common::dav::imip::scheduling_object(&data)
                            .ok()
                            .and_then(|r| r.ok())
                            .and_then(|(_, c)| {
                                events::master(&c)
                                    .and_then(|m| m.property("UID").map(|u| u.value.clone()))
                            })
                    }
                    _ => None,
                };
                let outcome = crate::api::invitations::act(
                    account.state.clone(),
                    account.user.clone(),
                    &message,
                    action,
                    None,
                )?;
                outcome.ok().and(uid)
            }
            _ => None,
        };
        match answered {
            Some(uid) => {
                result.push(Element::text("MeetingResponse:Status", "1"));
                if action != "declined" {
                    let conn = conn(account)?;
                    if let Some((calendar, object)) = store::find_by_uid(&conn, &uid)? {
                        let _ = calendar;
                        result.push(Element::text(
                            "MeetingResponse:CalendarId",
                            item_id(&object.name),
                        ));
                    }
                }
            }
            None => result.push(Element::text("MeetingResponse:Status", "2")),
        }
        response.push(result);
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_fit_activesync() {
        assert_eq!(item_id("abc-123.ics"), "abc-123.ics");
        let long = item_id(&"x".repeat(100));
        assert!(long.len() <= 64 && long.starts_with('h'));
        assert_eq!(item_id("a b/c.ics"), item_id("a b/c.ics"));
        assert_eq!(parse_time("20261022T120000Z"), Some(1_792_670_400));
        assert_eq!(compact(1_792_670_400), "20261022T120000Z");
        let goid = base64::engine::general_purpose::STANDARD
            .decode(global_object_id("u1"))
            .unwrap();
        assert!(goid.windows(8).any(|w| w == b"vCal-Uid"));
    }
}
