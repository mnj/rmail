//! Scheduling messages (iTIP, RFC 5546) for CalDAV implicit scheduling
//! (RFC 6638): what a change to an event sends, and how a received message
//! changes the recipient's copy.
//!
//! - The organizer's changes send `REQUEST` to the attendees (only to new
//!   ones when nothing significant changed) and `CANCEL` to removed ones,
//!   or to everyone when the event is deleted or cancelled.
//! - An attendee's changed participation status sends `REPLY` to the
//!   organizer; deleting the event declines it.
//! - Attendees whose `SCHEDULE-AGENT` is not `SERVER` are left to the
//!   client.
//! - Each attendee gets only the instances they are invited to (RFC 6638
//!   3.2): the series with the overrides that list them, the occurrences
//!   overridden without them excluded, or only their overrides when the
//!   series does not list them. Significant changes are judged on that
//!   view, so a change to an instance someone is not invited to does not
//!   reach them, and someone dropped from one instance gets a `CANCEL` for
//!   that instance alone.
//! - An answer for one occurrence of the series gets an override of its
//!   own in the organizer's copy.

use std::collections::{BTreeMap, BTreeSet};

use super::text::{Component, Property};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Request,
    Cancel,
    Reply,
    /// An attendee proposes other times (RFC 5546 3.2.7).
    Counter,
    /// The organizer turns a proposal down (RFC 5546 3.2.8).
    DeclineCounter,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Request => "REQUEST",
            Method::Cancel => "CANCEL",
            Method::Reply => "REPLY",
            Method::Counter => "COUNTER",
            Method::DeclineCounter => "DECLINECOUNTER",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "REQUEST" => Some(Method::Request),
            "CANCEL" => Some(Method::Cancel),
            "REPLY" => Some(Method::Reply),
            "COUNTER" => Some(Method::Counter),
            "DECLINECOUNTER" => Some(Method::DeclineCounter),
            _ => None,
        }
    }
}

/// A scheduling message for some recipients (bare email addresses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub method: Method,
    pub recipients: Vec<String>,
    /// A VCALENDAR with `METHOD`.
    pub calendar: Component,
}

/// The email address of a calendar user address (`mailto:`), lower-cased.
pub fn address(value: &str) -> Option<String> {
    let value = value.trim();
    let rest = value
        .get(..7)
        .filter(|scheme| scheme.eq_ignore_ascii_case("mailto:"))
        .map(|_| &value[7..])?;
    let rest = rest.trim();
    (rest.contains('@') && !rest.contains(['<', '>', ' ', ',', '\r', '\n']))
        .then(|| rest.to_ascii_lowercase())
}

fn is_user(property: &Property, user: &str) -> bool {
    address(&property.value).is_some_and(|found| found.eq_ignore_ascii_case(user))
}

/// The components that carry scheduling: events and to-dos.
fn scheduled(calendar: &Component) -> impl Iterator<Item = &Component> {
    calendar
        .components
        .iter()
        .filter(|component| component.name != "VTIMEZONE")
}

fn scheduled_mut(calendar: &mut Component) -> impl Iterator<Item = &mut Component> {
    calendar
        .components
        .iter_mut()
        .filter(|component| component.name != "VTIMEZONE")
}

/// The organizer's address, from the first component that names one.
pub fn organizer(calendar: &Component) -> Option<String> {
    scheduled(calendar)
        .find_map(|component| component.property("ORGANIZER"))
        .and_then(|organizer| address(&organizer.value))
}

/// Whether the server does the scheduling for this calendar user
/// (`SCHEDULE-AGENT`, RFC 6638 7.1).
fn server_schedules(property: &Property) -> bool {
    property
        .param("SCHEDULE-AGENT")
        .is_none_or(|agent| agent.eq_ignore_ascii_case("SERVER"))
}

/// What the account is to an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Organizer,
    Attendee,
    /// Not a scheduling object (no organizer, or not involving the user).
    None,
}

/// Which of an account's addresses (its own first, then its aliases) a
/// calendar involves it under; the account's own when none does.
pub fn own_address<'a>(calendar: &Component, addresses: &'a [String]) -> Option<&'a str> {
    addresses
        .iter()
        .find(|address| role(calendar, address) != Role::None)
        .or(addresses.first())
        .map(String::as_str)
}

pub fn role(calendar: &Component, user: &str) -> Role {
    let Some(organizer) = organizer(calendar) else {
        return Role::None;
    };
    if organizer.eq_ignore_ascii_case(user) {
        // An organizer with no one else invited is just an event.
        if attendees(calendar, user).is_empty() {
            Role::None
        } else {
            Role::Organizer
        }
    } else if scheduled(calendar)
        .flat_map(|component| component.properties_named("ATTENDEE"))
        .any(|attendee| is_user(attendee, user))
    {
        Role::Attendee
    } else {
        Role::None
    }
}

/// The attendees the server schedules for, without the organizer.
fn attendees(calendar: &Component, organizer: &str) -> BTreeSet<String> {
    scheduled(calendar)
        .flat_map(|component| component.properties_named("ATTENDEE"))
        .filter(|attendee| server_schedules(attendee))
        .filter_map(|attendee| address(&attendee.value))
        .filter(|found| !found.eq_ignore_ascii_case(organizer))
        .collect()
}

fn force_send(calendar: &Component, organizer: &str) -> BTreeSet<String> {
    scheduled(calendar)
        .flat_map(|component| component.properties_named("ATTENDEE"))
        .filter(|attendee| {
            attendee
                .param("SCHEDULE-FORCE-SEND")
                .is_some_and(|force| force.eq_ignore_ascii_case("REQUEST"))
        })
        .filter_map(|attendee| address(&attendee.value))
        .filter(|found| !found.eq_ignore_ascii_case(organizer))
        .collect()
}

/// Parameters only the server or the scheduling exchange set.
const SCHEDULING_PARAMS: &[&str] = &["SCHEDULE-STATUS", "SCHEDULE-FORCE-SEND"];

/// The event as the organizer's significant content: what attendees see,
/// without alarms, time stamps, client-private properties or the attendee
/// list (RFC 6638 3.2.8). Added attendees are invited on their own and
/// removed ones get a cancellation, so the others are not told again.
fn significant(calendar: &Component) -> Vec<Vec<String>> {
    scheduled(calendar)
        .map(|component| {
            let mut lines = component
                .properties
                .iter()
                .filter(|property| {
                    !matches!(
                        property.name.as_str(),
                        "DTSTAMP" | "LAST-MODIFIED" | "CREATED" | "ATTENDEE"
                    ) && !property.name.starts_with("X-")
                })
                .map(|property| {
                    let mut property = property.clone();
                    if property.name == "ORGANIZER" {
                        property.value = address(&property.value).unwrap_or(property.value);
                        for param in SCHEDULING_PARAMS {
                            property.set_param(param, None);
                        }
                    }
                    property.params.sort();
                    format!("{}{:?}:{}", property.name, property.params, property.value)
                })
                .collect::<Vec<_>>();
            lines.sort();
            lines
        })
        .collect()
}

/// A copy of `calendar` to send: `METHOD` set, alarms and the server's
/// scheduling parameters removed.
fn outgoing(calendar: &Component, method: Method) -> Component {
    let mut copy = calendar.clone();
    copy.properties.retain(|property| property.name != "METHOD");
    copy.properties
        .insert(0, Property::new("METHOD", method.as_str()));
    for component in scheduled_mut(&mut copy) {
        component.components.retain(|sub| sub.name != "VALARM");
        for property in &mut component.properties {
            if matches!(property.name.as_str(), "ATTENDEE" | "ORGANIZER") {
                for param in SCHEDULING_PARAMS {
                    property.set_param(param, None);
                }
            }
        }
    }
    copy
}

fn is_cancelled(calendar: &Component) -> bool {
    scheduled(calendar)
        .filter(|component| component.property("RECURRENCE-ID").is_none())
        .any(|component| {
            component
                .property("STATUS")
                .is_some_and(|status| status.value.trim().eq_ignore_ascii_case("CANCELLED"))
        })
}

fn cancel_of(calendar: &Component) -> Component {
    let mut cancel = outgoing(calendar, Method::Cancel);
    for component in scheduled_mut(&mut cancel) {
        component.set_property("STATUS", "CANCELLED");
    }
    cancel
}

/// The series: the component without a `RECURRENCE-ID`.
fn master(calendar: &Component) -> Option<&Component> {
    scheduled(calendar).find(|component| recurrence_key(component).is_none())
}

fn listed(component: &Component, user: &str) -> bool {
    component
        .properties_named("ATTENDEE")
        .any(|attendee| is_user(attendee, user))
}

/// Whether `user` is invited to the occurrence `key` (`None`: the series):
/// its override lists them, or it has none and the series does.
fn invited_at(calendar: &Component, user: &str, key: Option<&str>) -> bool {
    let instance = key.and_then(|key| {
        scheduled(calendar).find(|component| recurrence_key(component).as_deref() == Some(key))
    });
    match instance {
        Some(instance) => listed(instance, user),
        None => master(calendar).is_some_and(|master| listed(master, user)),
    }
}

/// The overrides' `RECURRENCE-ID`s, by value.
fn recurrence_ids(calendar: &Component) -> BTreeMap<String, Property> {
    scheduled(calendar)
        .filter_map(|component| {
            let id = component.property("RECURRENCE-ID")?;
            Some((id.value.trim().to_string(), id.clone()))
        })
        .collect()
}

/// Whether an `EXDATE` of `component` already names `value`.
fn excludes(component: &Component, value: &str) -> bool {
    component
        .properties_named("EXDATE")
        .flat_map(|exdate| exdate.value.split(','))
        .any(|found| found.trim() == value)
}

/// The part of the event `user` is invited to (RFC 6638 3.2), time
/// zones kept: the series and the overrides that list them, with the
/// occurrences overridden without them (and those in `without`) excluded
/// from the series; or, when the series does not list them, only the
/// overrides that do. `None` when they are invited to nothing.
pub fn attendee_view(
    calendar: &Component,
    user: &str,
    without: &BTreeMap<String, Property>,
) -> Option<Component> {
    let in_series = master(calendar).is_some_and(|master| listed(master, user));
    let mut view = calendar.clone();
    view.components.clear();
    let mut excluded = without.clone();
    for component in &calendar.components {
        if component.name == "VTIMEZONE" {
            view.components.push(component.clone());
            continue;
        }
        match component.property("RECURRENCE-ID") {
            None if in_series => view.components.push(component.clone()),
            None => {}
            Some(id) => {
                let key = id.value.trim().to_string();
                if listed(component, user) && !without.contains_key(&key) {
                    view.components.push(component.clone());
                } else {
                    excluded.insert(key, id.clone());
                }
            }
        }
    }
    if in_series
        && let Some(series) =
            scheduled_mut(&mut view).find(|component| component.property("RECURRENCE-ID").is_none())
    {
        for (key, id) in excluded {
            if !excludes(series, &key) {
                let mut exdate = id;
                exdate.name = "EXDATE".to_string();
                exdate.value = key;
                series.properties.push(exdate);
            }
        }
    }
    let invited = scheduled(&view).next().is_some();
    invited.then_some(view)
}

/// The occurrences `keys` of the event, to cancel: their overrides, or for
/// plain occurrences of the series a copy of it moved to that occurrence.
fn instances(calendar: &Component, keys: &BTreeMap<String, Property>) -> Component {
    let mut out = calendar.clone();
    out.components
        .retain(|component| component.name == "VTIMEZONE");
    for (key, id) in keys {
        let found = scheduled(calendar)
            .find(|component| recurrence_key(component).as_deref() == Some(key.as_str()));
        if let Some(found) = found {
            out.components.push(found.clone());
            continue;
        }
        if let Some(series) = master(calendar) {
            out.components.push(occurrence(series, id));
        }
    }
    out
}

/// Whether the series of `calendar` has an occurrence starting at `id`
/// (a `RECURRENCE-ID`), its exclusions and expansion limit applied.
fn is_occurrence(calendar: &Component, id: &Property) -> bool {
    let Some(at) = super::recur::instant(id) else {
        return false;
    };
    let Some(series) = calendar.components.iter().position(|component| {
        component.name != "VTIMEZONE" && component.property("RECURRENCE-ID").is_none()
    }) else {
        return false;
    };
    super::recur::occurrences(calendar, at, at + 1)
        .iter()
        .any(|found| found.component == series && found.start == at)
}

/// An override for the occurrence `id` of `series`, as the series has it:
/// its start moved there, its length kept.
fn occurrence(series: &Component, id: &Property) -> Component {
    let mut instance = series.clone();
    let length = series.property("DURATION").is_none().then(|| {
        let start = series.property("DTSTART").and_then(super::recur::instant)?;
        let end = series.property("DTEND").and_then(super::recur::instant)?;
        Some((end - start).max(0))
    });
    instance.properties.retain(|property| {
        !matches!(
            property.name.as_str(),
            "RRULE" | "RDATE" | "EXDATE" | "EXRULE" | "DTSTART" | "DTEND"
        )
    });
    let mut start = id.clone();
    start.name = "DTSTART".to_string();
    let all_day = start
        .param("VALUE")
        .is_some_and(|value| value.eq_ignore_ascii_case("DATE"))
        || start.value.trim().len() == 8;
    instance.properties.push(start);
    instance.properties.push(id.clone());
    if let Some(Some(seconds)) = length {
        let duration = if all_day {
            format!("P{}D", seconds / 86_400)
        } else {
            format!("PT{seconds}S")
        };
        instance
            .properties
            .push(Property::new("DURATION", &duration));
    }
    instance
}

/// Messages being gathered: recipients who get the same calendar share one
/// message.
#[derive(Default)]
struct Outbox(Vec<Message>);

impl Outbox {
    fn add(&mut self, method: Method, calendar: Component, recipient: &str) {
        if let Some(found) = self
            .0
            .iter_mut()
            .find(|message| message.method == method && message.calendar == calendar)
        {
            found.recipients.push(recipient.to_string());
            return;
        }
        self.0.push(Message {
            method,
            recipients: vec![recipient.to_string()],
            calendar,
        });
    }

    fn cancel(&mut self, view: &Component, recipient: &str) {
        self.add(Method::Cancel, cancel_of(view), recipient);
    }

    fn request(&mut self, view: &Component, recipient: &str) {
        self.add(Method::Request, outgoing(view, Method::Request), recipient);
    }

    /// Cancellations first: someone dropped from the series hears so
    /// before they get the instances they keep.
    fn messages(self) -> Vec<Message> {
        let (mut cancels, requests): (Vec<_>, Vec<_>) = self
            .0
            .into_iter()
            .partition(|message| message.method == Method::Cancel);
        cancels.extend(requests);
        cancels
    }
}

/// The messages an organizer's change sends: `previous` and `current` are
/// the stored versions before and after (`None` for created or deleted).
/// Each attendee's messages carry only the instances they are invited to.
pub fn organizer_messages(
    previous: Option<&Component>,
    current: Option<&Component>,
    user: &str,
) -> Vec<Message> {
    let none = BTreeMap::new();
    let previous = previous.filter(|calendar| role(calendar, user) == Role::Organizer);
    let before = previous
        .map(|calendar| attendees(calendar, user))
        .unwrap_or_default();
    let mut outbox = Outbox::default();
    let Some(current) = current.filter(|calendar| role(calendar, user) == Role::Organizer) else {
        // Deleted, or no longer organized here: cancel for everyone.
        if let Some(previous) = previous
            && !is_cancelled(previous)
        {
            for attendee in &before {
                if let Some(view) = attendee_view(previous, attendee, &none) {
                    outbox.cancel(&view, attendee);
                }
            }
        }
        return outbox.messages();
    };
    let now = attendees(current, user);
    if is_cancelled(current) {
        let already = previous.is_some_and(is_cancelled);
        let recipients = if already {
            now.difference(&before).cloned().collect::<Vec<_>>()
        } else {
            now.union(&before).cloned().collect()
        };
        for attendee in &recipients {
            let view = attendee_view(current, attendee, &none)
                .or_else(|| previous.and_then(|previous| attendee_view(previous, attendee, &none)));
            if let Some(view) = view {
                outbox.cancel(&view, attendee);
            }
        }
        return outbox.messages();
    }
    let forced = force_send(current, user);
    let everyone = now
        .iter()
        .chain(&before)
        .chain(&forced)
        .collect::<BTreeSet<_>>();
    for attendee in everyone {
        let old = previous
            .filter(|_| before.contains(attendee))
            .and_then(|previous| attendee_view(previous, attendee, &none));
        let new = (now.contains(attendee) || forced.contains(attendee))
            .then(|| attendee_view(current, attendee, &none))
            .flatten();
        let (previous, old, new) = match (previous, old, new) {
            (_, None, None) => continue,
            (_, Some(old), None) => {
                outbox.cancel(&old, attendee);
                continue;
            }
            (Some(previous), Some(old), Some(new)) => (previous, old, new),
            (_, _, Some(new)) => {
                outbox.request(&new, attendee);
                continue;
            }
        };
        if invited_at(previous, attendee, None) && !invited_at(current, attendee, None) {
            // Dropped from the series but kept in some instances: the
            // series is cancelled, then those instances sent anew.
            outbox.cancel(&old, attendee);
            outbox.request(&new, attendee);
            continue;
        }
        let mut ids = recurrence_ids(previous);
        ids.extend(recurrence_ids(current));
        let removed = ids
            .into_iter()
            .filter(|(key, _)| {
                invited_at(previous, attendee, Some(key))
                    && !invited_at(current, attendee, Some(key))
            })
            .collect::<BTreeMap<_, _>>();
        if !removed.is_empty() {
            outbox.cancel(&instances(previous, &removed), attendee);
        }
        // What they keep of the old version, against what they get now:
        // only a significant difference is sent again.
        let kept = attendee_view(previous, attendee, &removed);
        if forced.contains(attendee)
            || kept.is_none_or(|kept| significant(&kept) != significant(&new))
        {
            outbox.request(&new, attendee);
        }
    }
    outbox.messages()
}

fn recurrence_key(component: &Component) -> Option<String> {
    component
        .property("RECURRENCE-ID")
        .map(|id| id.value.trim().to_string())
}

fn partstat(component: &Component, user: &str) -> Option<String> {
    component
        .properties_named("ATTENDEE")
        .find(|attendee| is_user(attendee, user))
        .map(|attendee| {
            attendee
                .param("PARTSTAT")
                .unwrap_or("NEEDS-ACTION")
                .to_ascii_uppercase()
        })
}

/// A reply from `user` with the given components, each cut down to the
/// organizer and the user's own attendee line.
fn reply_of(calendar: &Component, keep: &[usize], user: &str, organizer: String) -> Message {
    let mut reply = outgoing(calendar, Method::Reply);
    let mut index = 0;
    reply.components.retain(|component| {
        let kept = component.name == "VTIMEZONE" || keep.contains(&index);
        index += 1;
        kept
    });
    for component in scheduled_mut(&mut reply) {
        component
            .properties
            .retain(|property| property.name != "ATTENDEE" || is_user(property, user));
    }
    Message {
        method: Method::Reply,
        recipients: vec![organizer],
        calendar: reply,
    }
}

/// The reply an attendee's change sends, if their participation changed:
/// `current` is `None` when they deleted the event, which declines it.
pub fn attendee_reply(
    previous: Option<&Component>,
    current: Option<&Component>,
    user: &str,
) -> Option<Message> {
    let calendar = current.or(previous)?;
    if role(calendar, user) != Role::Attendee {
        return None;
    }
    let organizer_property = scheduled(calendar).find_map(|c| c.property("ORGANIZER"))?;
    if !server_schedules(organizer_property) {
        return None;
    }
    let organizer = address(&organizer_property.value)?;
    let Some(current) = current else {
        // Deleted: decline, unless the organizer had cancelled it.
        let previous = previous?;
        if is_cancelled(previous) {
            return None;
        }
        let mut declined = previous.clone();
        for component in scheduled_mut(&mut declined) {
            for attendee in &mut component.properties {
                if attendee.name == "ATTENDEE" && is_user(attendee, user) {
                    attendee.set_param("PARTSTAT", Some("DECLINED"));
                }
            }
        }
        let keep = (0..declined.components.len()).collect::<Vec<_>>();
        return Some(reply_of(&declined, &keep, user, organizer));
    };
    let before = |key: &Option<String>| -> String {
        let previous_partstat = previous.and_then(|previous| {
            let same = scheduled(previous).find(|c| &recurrence_key(c) == key);
            // A new override starts from the series' status.
            let master = scheduled(previous).find(|c| recurrence_key(c).is_none());
            same.or(master).and_then(|c| partstat(c, user))
        });
        previous_partstat.unwrap_or_else(|| "NEEDS-ACTION".to_string())
    };
    let changed = current
        .components
        .iter()
        .enumerate()
        .filter(|(_, component)| component.name != "VTIMEZONE")
        .filter(|(_, component)| {
            partstat(component, user).is_some_and(|now| now != before(&recurrence_key(component)))
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if changed.is_empty() {
        return None;
    }
    Some(reply_of(current, &changed, user, organizer))
}

/// Record the scheduling status of a delivery (RFC 6638 3.2.9) on the
/// stored copy: on attendees for the organizer, on the organizer for an
/// attendee. `statuses` maps addresses to codes such as `1.2`.
pub fn set_statuses(calendar: &mut Component, property: &str, statuses: &[(String, String)]) {
    for component in scheduled_mut(calendar) {
        for found in &mut component.properties {
            if found.name != property {
                continue;
            }
            if let Some(address) = address(&found.value)
                && let Some((_, code)) = statuses.iter().find(|(to, _)| *to == address)
            {
                found.set_param("SCHEDULE-STATUS", Some(code));
            }
        }
    }
}

/// Remove what clients may not store: `SCHEDULE-FORCE-SEND` is a one-off
/// request (RFC 6638 7.2).
pub fn strip_force_send(calendar: &mut Component) -> bool {
    let mut changed = false;
    for component in scheduled_mut(calendar) {
        for property in &mut component.properties {
            if property.param("SCHEDULE-FORCE-SEND").is_some() {
                property.set_param("SCHEDULE-FORCE-SEND", None);
                changed = true;
            }
        }
    }
    changed
}

// ---------------------------------------------------------------------------
// Receiving

/// The recipient's copy after a `REQUEST`: the organizer's version, with
/// the recipient's alarms kept. A request with only some instances updates
/// those in a copy of the series (RFC 5546 3.2.2); otherwise it replaces
/// the copy, as it holds everything the recipient is invited to.
pub fn apply_request(existing: Option<&Component>, message: &Component) -> Component {
    let copy = request_copy(existing, message);
    let Some(existing) = existing.filter(|existing| {
        master(&copy).is_none()
            && master(existing).is_some_and(|series| {
                series
                    .property("STATUS")
                    .is_none_or(|status| !status.value.trim().eq_ignore_ascii_case("CANCELLED"))
            })
    }) else {
        return copy;
    };
    let mut merged = existing.clone();
    for component in copy.components {
        let slot = if component.name == "VTIMEZONE" {
            let tzid = component.property("TZID").map(|tzid| tzid.value.trim());
            merged.components.iter().position(|found| {
                found.name == "VTIMEZONE" && found.property("TZID").map(|t| t.value.trim()) == tzid
            })
        } else {
            let key = recurrence_key(&component);
            merged
                .components
                .iter()
                .position(|found| found.name != "VTIMEZONE" && recurrence_key(found) == key)
        };
        match slot {
            Some(at) => merged.components[at] = component,
            None => merged.components.push(component),
        }
    }
    merged
}

fn request_copy(existing: Option<&Component>, message: &Component) -> Component {
    let mut copy = message.clone();
    copy.properties.retain(|property| property.name != "METHOD");
    for component in scheduled_mut(&mut copy) {
        if component.components.iter().any(|sub| sub.name == "VALARM") {
            continue;
        }
        let key = recurrence_key(component);
        let alarms = existing
            .into_iter()
            .flat_map(scheduled)
            .find(|old| recurrence_key(old) == key)
            .map(|old| {
                old.components
                    .iter()
                    .filter(|sub| sub.name == "VALARM")
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        component.components.extend(alarms);
    }
    copy
}

/// The recipient's copy after a `CANCEL`: the whole event, or the named
/// occurrences, marked cancelled.
pub fn apply_cancel(existing: &Component, message: &Component) -> Component {
    let mut copy = existing.clone();
    let keys = scheduled(message).map(recurrence_key).collect::<Vec<_>>();
    if keys.iter().any(Option::is_none) {
        for component in scheduled_mut(&mut copy) {
            component.set_property("STATUS", "CANCELLED");
        }
        return copy;
    }
    for message_component in scheduled(message) {
        let Some(id) = message_component.property("RECURRENCE-ID") else {
            continue;
        };
        let key = recurrence_key(message_component);
        if let Some(found) = scheduled_mut(&mut copy).find(|c| recurrence_key(c) == key) {
            found.set_property("STATUS", "CANCELLED");
        } else if let Some(master) = scheduled_mut(&mut copy).find(|c| recurrence_key(c).is_none())
        {
            // One occurrence of the series is off.
            let mut exdate = id.clone();
            exdate.name = "EXDATE".to_string();
            master.properties.push(exdate);
        }
    }
    copy
}

/// The organizer's copy after `attendee`'s `REPLY`, or `None` when the
/// reply does not concern an invited attendee.
pub fn apply_reply(existing: &Component, message: &Component, attendee: &str) -> Option<Component> {
    let mut copy = existing.clone();
    let mut changed = false;
    for reply in scheduled(message) {
        let Some(answer) = reply
            .properties_named("ATTENDEE")
            .find(|property| is_user(property, attendee))
        else {
            continue;
        };
        let key = recurrence_key(reply);
        let overridden = scheduled(&copy).any(|c| recurrence_key(c) == key);
        if !overridden
            && let (Some(id), Some(series)) = (reply.property("RECURRENCE-ID"), master(&copy))
            && listed(series, attendee)
            && !excludes(series, id.value.trim())
            && is_occurrence(&copy, id)
        {
            // An answer for one occurrence of the series: it gets an
            // override of its own to hold it (RFC 6638 3.2). Only a real
            // occurrence: a reply cannot add dates to the event.
            let instance = occurrence(series, id);
            copy.components.push(instance);
        }
        let Some(target) = scheduled_mut(&mut copy).find(|c| recurrence_key(c) == key) else {
            continue;
        };
        for property in &mut target.properties {
            if property.name == "ATTENDEE" && is_user(property, attendee) {
                property.set_param(
                    "PARTSTAT",
                    answer.param("PARTSTAT").or(Some("NEEDS-ACTION")),
                );
                property.set_param("SCHEDULE-STATUS", Some("2.0"));
                changed = true;
            }
        }
    }
    changed.then_some(copy)
}

/// The master event (no RECURRENCE-ID), or the first one.
fn master_of(calendar: &Component) -> Option<&Component> {
    scheduled(calendar)
        .find(|c| c.property("RECURRENCE-ID").is_none())
        .or_else(|| scheduled(calendar).next())
}

/// A proposal from attendee `user` to hold the event at `start`..`end`
/// instead (RFC 5546 3.2.7): the master event with the new times, the
/// organizer and the user's own attendee line, and an optional comment.
/// `None` when the user is not an attendee.
pub fn counter(
    calendar: &Component,
    user: &str,
    start: Property,
    end: Property,
    comment: Option<&str>,
) -> Option<Message> {
    if role(calendar, user) != Role::Attendee {
        return None;
    }
    let organizer = organizer(calendar)?;
    let mut proposal = outgoing(calendar, Method::Counter);
    let master_index = proposal
        .components
        .iter()
        .position(|c| c.name != "VTIMEZONE" && c.property("RECURRENCE-ID").is_none())?;
    let mut index = 0;
    proposal.components.retain(|component| {
        let kept = component.name == "VTIMEZONE" || index == master_index;
        index += 1;
        kept
    });
    let event = proposal
        .components
        .iter_mut()
        .find(|c| c.name != "VTIMEZONE")?;
    event.properties.retain(|property| {
        !matches!(
            property.name.as_str(),
            "DTSTART" | "DTEND" | "DURATION" | "COMMENT"
        ) && (property.name != "ATTENDEE" || is_user(property, user))
    });
    event.properties.push(start);
    event.properties.push(end);
    if let Some(comment) = comment.map(str::trim).filter(|c| !c.is_empty()) {
        event.properties.push(Property::new(
            "COMMENT",
            &comment
                .replace('\\', "\\\\")
                .replace(';', "\\;")
                .replace(',', "\\,")
                .replace(['\r', '\n'], " "),
        ));
    }
    Some(Message {
        method: Method::Counter,
        recipients: vec![organizer],
        calendar: proposal,
    })
}

/// The organizer's "no" to a proposal (RFC 5546 3.2.8), to its sender.
pub fn decline_counter(proposal: &Component) -> Option<Message> {
    let event = master_of(proposal)?;
    let attendee = event
        .properties_named("ATTENDEE")
        .find_map(|a| address(&a.value))?;
    let mut decline = Component::new("VCALENDAR");
    decline.set_property("VERSION", "2.0");
    decline.set_property("PRODID", "-//rMail//EN");
    decline
        .properties
        .insert(0, Property::new("METHOD", Method::DeclineCounter.as_str()));
    let mut component = Component::new("VEVENT");
    for name in ["UID", "SEQUENCE", "ORGANIZER", "ATTENDEE", "RECURRENCE-ID"] {
        for property in event.properties_named(name) {
            component.properties.push(property.clone());
        }
    }
    component.set_property(
        "DTSTAMP",
        &super::recur::utc_text(chrono::Utc::now().timestamp()),
    );
    decline.components.push(component);
    Some(Message {
        method: Method::DeclineCounter,
        recipients: vec![attendee],
        calendar: decline,
    })
}

/// The organizer's copy with a proposal's times taken: the master event
/// moves to them (a change every attendee then hears of).
pub fn apply_counter(existing: &Component, proposal: &Component) -> Option<Component> {
    let proposed = master_of(proposal)?;
    let start = proposed.property("DTSTART")?.clone();
    let end = proposed.property("DTEND").cloned();
    let mut copy = existing.clone();
    let event = copy
        .components
        .iter_mut()
        .find(|c| c.name != "VTIMEZONE" && c.property("RECURRENCE-ID").is_none())?;
    event
        .properties
        .retain(|p| !matches!(p.name.as_str(), "DTSTART" | "DTEND" | "DURATION"));
    event.properties.push(start);
    if let Some(end) = end {
        event.properties.push(end);
    }
    let sequence = event
        .property("SEQUENCE")
        .and_then(|s| s.value.trim().parse::<i64>().ok())
        .unwrap_or(0);
    event.set_property("SEQUENCE", &(sequence + 1).to_string());
    // The time zones a proposal's times use come along.
    for zone in proposal.components.iter().filter(|c| c.name == "VTIMEZONE") {
        let tzid = zone.property("TZID").map(|t| t.value.clone());
        if !copy
            .components
            .iter()
            .any(|c| c.name == "VTIMEZONE" && c.property("TZID").map(|t| t.value.clone()) == tzid)
        {
            copy.components.insert(0, zone.clone());
        }
    }
    Some(copy)
}

/// A short text for an invitation email: what, when, who.
pub fn summary_text(calendar: &Component) -> (String, String) {
    let first = scheduled(calendar).next();
    let summary = first
        .and_then(|component| component.property("SUMMARY"))
        .map(|summary| unescape(&summary.value))
        .filter(|summary| !summary.trim().is_empty())
        .unwrap_or_else(|| "(no title)".to_string());
    let mut lines = Vec::new();
    if let Some(component) = first {
        if let Some(start) = component.property("DTSTART") {
            let zone = start
                .param("TZID")
                .unwrap_or(if start.value.ends_with('Z') {
                    "UTC"
                } else {
                    ""
                });
            lines.push(format!("When: {} {zone}", readable_time(&start.value)));
        }
        if let Some(location) = component.property("LOCATION") {
            lines.push(format!("Where: {}", unescape(&location.value)));
        }
        if let Some(organizer) = component.property("ORGANIZER") {
            let email = address(&organizer.value).unwrap_or_default();
            let name = organizer
                .param("CN")
                .filter(|name| !name.trim().is_empty() && !name.eq_ignore_ascii_case(&email));
            lines.push(match name {
                Some(name) => format!("Organizer: {name} <{email}>"),
                None => format!("Organizer: {email}"),
            });
        }
        if let Some(description) = component.property("DESCRIPTION") {
            lines.push(String::new());
            lines.push(unescape(&description.value));
        }
    }
    (summary, lines.join("\n"))
}

fn readable_time(value: &str) -> String {
    let value = value.trim().trim_end_matches('Z');
    if let Ok(time) = chrono::NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%S") {
        return time.format("%Y-%m-%d %H:%M").to_string();
    }
    chrono::NaiveDate::parse_from_str(value, "%Y%m%d")
        .map(|date| date.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|_| value.to_string())
}

/// An iCalendar TEXT value as plain text (RFC 5545 3.3.11).
pub fn unescape(value: &str) -> String {
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n' | 'N') => out.push('\n'),
                Some(other) => out.push(other),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::text;
    use super::*;

    const ORGANIZER: &str = "alice@example.test";

    fn event(attendees: &[(&str, &str)], summary: &str, extra: &str) -> Component {
        let lines = attendees
            .iter()
            .map(|(who, status)| format!("ATTENDEE;PARTSTAT={status};RSVP=TRUE:mailto:{who}\r\n"))
            .collect::<String>();
        text::parse(&format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:m1\r\n\
             DTSTAMP:20261001T000000Z\r\nDTSTART:20261012T090000Z\r\nDURATION:PT1H\r\n\
             SUMMARY:{summary}\r\nORGANIZER;CN=Alice:mailto:{ORGANIZER}\r\n\
             ATTENDEE;PARTSTAT=ACCEPTED:mailto:{ORGANIZER}\r\n{lines}{extra}\
             BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT10M\r\nEND:VALARM\r\n\
             END:VEVENT\r\nEND:VCALENDAR\r\n"
        ))
        .unwrap()
    }

    #[test]
    fn proposals_of_other_times() {
        let calendar = event(
            &[
                ("bob@example.test", "ACCEPTED"),
                ("carol@example.test", "NEEDS-ACTION"),
            ],
            "Plan",
            "",
        );
        let start = Property::new("DTSTART", "20261013T100000Z");
        let end = Property::new("DTEND", "20261013T110000Z");
        assert!(
            counter(&calendar, ORGANIZER, start.clone(), end.clone(), None).is_none(),
            "not an attendee"
        );
        let proposal = counter(
            &calendar,
            "bob@example.test",
            start,
            end,
            Some("Tuesday, please"),
        )
        .unwrap();
        assert_eq!(proposal.method, Method::Counter);
        assert_eq!(proposal.recipients, [ORGANIZER]);
        let text = proposal.calendar.to_text();
        assert!(text.contains("METHOD:COUNTER") && text.contains("DTSTART:20261013T100000Z"));
        assert!(
            text.contains("bob@example.test") && !text.contains("carol@example.test"),
            "{text}"
        );
        assert!(text.contains("COMMENT:Tuesday\\, please"));

        let decline = decline_counter(&proposal.calendar).unwrap();
        assert_eq!(decline.method, Method::DeclineCounter);
        assert_eq!(decline.recipients, ["bob@example.test"]);
        assert!(decline.calendar.to_text().contains("METHOD:DECLINECOUNTER"));

        let moved = apply_counter(&calendar, &proposal.calendar).unwrap();
        let master = master_of(&moved).unwrap();
        assert_eq!(
            master.property("DTSTART").unwrap().value,
            "20261013T100000Z"
        );
        assert_eq!(master.property("SEQUENCE").unwrap().value, "1");
        assert!(
            moved.to_text().contains("carol@example.test"),
            "everyone stays invited"
        );
    }

    #[test]
    fn roles_and_addresses() {
        let calendar = event(&[("bob@example.test", "NEEDS-ACTION")], "Plan", "");
        assert_eq!(role(&calendar, ORGANIZER), Role::Organizer);
        assert_eq!(role(&calendar, "BOB@example.test"), Role::Attendee);
        assert_eq!(role(&calendar, "carol@example.test"), Role::None);
        assert_eq!(role(&event(&[], "Solo", ""), ORGANIZER), Role::None);
        assert_eq!(
            address("MAILTO:Bob@Example.test"),
            Some("bob@example.test".into())
        );
        assert_eq!(address("urn:uuid:1"), None);

        let carol = [
            "carol@example.test".to_string(),
            "bob@example.test".to_string(),
        ];
        assert_eq!(own_address(&calendar, &carol), Some("bob@example.test"));
        let dave = ["dave@example.test".to_string()];
        assert_eq!(own_address(&calendar, &dave), Some("dave@example.test"));
        assert_eq!(own_address(&calendar, &[]), None);
    }

    #[test]
    fn organizer_changes_invite_update_and_cancel() {
        let bob = ("bob@example.test", "NEEDS-ACTION");
        let carol = ("carol@example.test", "NEEDS-ACTION");
        let first = event(&[bob], "Plan", "");
        let sent = organizer_messages(None, Some(&first), ORGANIZER);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].method, Method::Request);
        assert_eq!(sent[0].recipients, vec!["bob@example.test"]);
        let text = sent[0].calendar.to_text();
        assert!(text.contains("METHOD:REQUEST") && !text.contains("VALARM"));

        // Bob's answer merged in and a new alarm: nothing to send.
        let answered = event(
            &[("bob@example.test", "ACCEPTED")],
            "Plan",
            "X-MOZ-GENERATION:2\r\n",
        );
        assert!(organizer_messages(Some(&first), Some(&answered), ORGANIZER).is_empty());
        // Adding Carol invites only her.
        let more = event(&[("bob@example.test", "ACCEPTED"), carol], "Plan", "");
        let sent = organizer_messages(Some(&answered), Some(&more), ORGANIZER);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].recipients, vec!["carol@example.test"]);
        // A new time goes to everyone; removing Bob cancels for him.
        let moved = event(&[carol], "Plan (moved)", "");
        let sent = organizer_messages(Some(&more), Some(&moved), ORGANIZER);
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].method, Method::Cancel);
        assert_eq!(sent[0].recipients, vec!["bob@example.test"]);
        assert!(sent[0].calendar.to_text().contains("STATUS:CANCELLED"));
        assert_eq!(sent[1].method, Method::Request);
        assert_eq!(sent[1].recipients, vec!["carol@example.test"]);
        // Deleting cancels for everyone; so does marking it cancelled.
        let sent = organizer_messages(Some(&moved), None, ORGANIZER);
        assert_eq!(
            (sent[0].method, sent[0].recipients.len()),
            (Method::Cancel, 1)
        );
        let cancelled = event(&[carol], "Plan (moved)", "STATUS:CANCELLED\r\n");
        let sent = organizer_messages(Some(&moved), Some(&cancelled), ORGANIZER);
        assert_eq!(sent[0].method, Method::Cancel);
        assert!(organizer_messages(Some(&cancelled), None, ORGANIZER).is_empty());
        // Attendees the client schedules are left alone.
        let client = text::parse(&first.to_text().replace(
            "ATTENDEE;PARTSTAT=NEEDS-ACTION",
            "ATTENDEE;SCHEDULE-AGENT=CLIENT",
        ))
        .unwrap();
        assert!(organizer_messages(None, Some(&client), ORGANIZER).is_empty());
    }

    #[test]
    fn attendee_answers_reply_to_the_organizer() {
        let bob = "bob@example.test";
        let invited = event(
            &[
                (bob, "NEEDS-ACTION"),
                ("carol@example.test", "NEEDS-ACTION"),
            ],
            "Plan",
            "",
        );
        assert!(attendee_reply(None, Some(&invited), bob).is_none());
        assert!(attendee_reply(Some(&invited), Some(&invited), bob).is_none());
        let accepted = event(
            &[(bob, "ACCEPTED"), ("carol@example.test", "NEEDS-ACTION")],
            "Plan",
            "",
        );
        let reply = attendee_reply(Some(&invited), Some(&accepted), bob).unwrap();
        assert_eq!(reply.method, Method::Reply);
        assert_eq!(reply.recipients, vec![ORGANIZER]);
        let text = reply.calendar.to_text();
        assert!(text.contains("METHOD:REPLY"));
        assert!(text.contains("PARTSTAT=ACCEPTED;RSVP=TRUE:mailto:bob@example.test"));
        assert!(!text.contains("carol") && !text.contains("VALARM"));
        // Accepting an emailed invitation into the calendar replies too.
        assert!(attendee_reply(None, Some(&accepted), bob).is_some());
        let reply = attendee_reply(Some(&accepted), None, bob).unwrap();
        assert!(reply.calendar.to_text().contains("PARTSTAT=DECLINED"));
        let cancelled = event(&[(bob, "ACCEPTED")], "Plan", "STATUS:CANCELLED\r\n");
        assert!(attendee_reply(Some(&cancelled), None, bob).is_none());
    }

    #[test]
    fn received_messages_update_the_copies() {
        let bob = "bob@example.test";
        let invited = event(&[(bob, "NEEDS-ACTION")], "Plan", "");
        let request = organizer_messages(None, Some(&invited), ORGANIZER).remove(0);
        let copy = apply_request(None, &request.calendar);
        assert!(copy.property("METHOD").is_none());
        // Bob's alarm survives an update.
        let mine = event(&[(bob, "ACCEPTED")], "Plan", "");
        let updated = apply_request(Some(&mine), &request.calendar);
        assert!(updated.to_text().contains("TRIGGER:-PT10M"));

        let cancel = organizer_messages(Some(&invited), None, ORGANIZER).remove(0);
        let cancelled = apply_cancel(&copy, &cancel.calendar);
        assert!(cancelled.to_text().contains("STATUS:CANCELLED"));

        let accepted = event(&[(bob, "ACCEPTED")], "Plan", "");
        let reply = attendee_reply(Some(&invited), Some(&accepted), bob).unwrap();
        let merged = apply_reply(&invited, &reply.calendar, bob).unwrap();
        let text = merged.to_text();
        assert!(text.contains("PARTSTAT=ACCEPTED"), "{text}");
        assert!(text.contains("SCHEDULE-STATUS=2.0"));
        assert!(apply_reply(&invited, &reply.calendar, "mallory@example.test").is_none());

        let mut stored = invited.clone();
        set_statuses(
            &mut stored,
            "ATTENDEE",
            &[(bob.to_string(), "1.2".to_string())],
        );
        assert!(stored.to_text().contains("SCHEDULE-STATUS=1.2"));
        let (summary, body) = summary_text(&invited);
        assert_eq!(summary, "Plan");
        assert!(body.contains("When: 2026-10-12 09:00 UTC"));
        assert!(body.contains("Organizer: Alice <alice@example.test>"));
    }

    #[test]
    fn cancelling_one_occurrence_excludes_it() {
        let series = text::parse(
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:s\r\nDTSTART:20261012T090000Z\r\n\
             RRULE:FREQ=DAILY\r\nORGANIZER:mailto:alice@example.test\r\n\
             ATTENDEE:mailto:bob@example.test\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        )
        .unwrap();
        let cancel = text::parse(
            "BEGIN:VCALENDAR\r\nMETHOD:CANCEL\r\nBEGIN:VEVENT\r\nUID:s\r\n\
             RECURRENCE-ID:20261014T090000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        )
        .unwrap();
        let copy = apply_cancel(&series, &cancel);
        assert!(copy.to_text().contains("EXDATE:20261014T090000Z"));
        assert!(!copy.to_text().contains("CANCELLED"));
    }

    const BOB: &str = "bob@example.test";
    const CAROL: &str = "carol@example.test";
    const DAY2: &str = "20261013T090000Z";
    const DAY3: &str = "20261014T090000Z";
    const DAY4: &str = "20261015T090000Z";

    /// A daily series with time zone, its attendees, and overrides as
    /// (recurrence id, summary, attendees).
    fn series(attendees: &[&str], overrides: &[(&str, &str, &[&str])]) -> Component {
        let lines = |who: &[&str]| {
            who.iter()
                .map(|who| format!("ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:{who}\r\n"))
                .collect::<String>()
        };
        let overrides = overrides
            .iter()
            .map(|(id, summary, who)| {
                format!(
                    "BEGIN:VEVENT\r\nUID:s\r\nRECURRENCE-ID:{id}\r\nDTSTART:{id}\r\n\
                     DURATION:PT1H\r\nSUMMARY:{summary}\r\nORGANIZER:mailto:{ORGANIZER}\r\n\
                     ATTENDEE;PARTSTAT=ACCEPTED:mailto:{ORGANIZER}\r\n{}END:VEVENT\r\n",
                    lines(who)
                )
            })
            .collect::<String>();
        text::parse(&format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n\
             BEGIN:VTIMEZONE\r\nTZID:Europe/Copenhagen\r\nBEGIN:STANDARD\r\n\
             DTSTART:19701025T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\n\
             END:STANDARD\r\nEND:VTIMEZONE\r\n\
             BEGIN:VEVENT\r\nUID:s\r\nDTSTART:20261012T090000Z\r\nDURATION:PT1H\r\n\
             RRULE:FREQ=DAILY;COUNT=5\r\nSUMMARY:Standup\r\nORGANIZER:mailto:{ORGANIZER}\r\n\
             ATTENDEE;PARTSTAT=ACCEPTED:mailto:{ORGANIZER}\r\n{}END:VEVENT\r\n{overrides}\
             END:VCALENDAR\r\n",
            lines(attendees)
        ))
        .unwrap()
    }

    fn sent_to<'a>(messages: &'a [Message], who: &str) -> Vec<&'a Message> {
        messages
            .iter()
            .filter(|message| message.recipients.iter().any(|to| to == who))
            .collect()
    }

    fn events(calendar: &Component) -> usize {
        scheduled(calendar).count()
    }

    #[test]
    fn attendees_get_only_their_instances() {
        // Bob is in the series but not on day 4; Carol only on day 3.
        let first = series(
            &[BOB],
            &[(DAY3, "Standup", &[BOB, CAROL]), (DAY4, "Standup", &[])],
        );
        let sent = organizer_messages(None, Some(&first), ORGANIZER);
        assert_eq!(sent.len(), 2, "{sent:?}");
        let bob = sent_to(&sent, BOB)[0].calendar.to_text();
        assert!(bob.contains("RRULE:") && bob.contains(&format!("EXDATE:{DAY4}")));
        assert!(bob.contains(&format!("RECURRENCE-ID:{DAY3}")));
        assert!(!bob.contains(&format!("RECURRENCE-ID:{DAY4}")));
        let carol = &sent_to(&sent, CAROL)[0].calendar;
        assert_eq!(events(carol), 1);
        let text = carol.to_text();
        assert!(text.contains(&format!("RECURRENCE-ID:{DAY3}")) && !text.contains("RRULE"));
        assert!(text.contains("BEGIN:VTIMEZONE"), "time zones are kept");

        // A change to an instance neither is invited to reaches no one.
        let moved = series(
            &[BOB],
            &[(DAY3, "Standup", &[BOB, CAROL]), (DAY4, "Retro", &[])],
        );
        assert!(organizer_messages(Some(&first), Some(&moved), ORGANIZER).is_empty());
        // A change to day 3 reaches both, each with their own view.
        let renamed = series(
            &[BOB],
            &[(DAY3, "Planning", &[BOB, CAROL]), (DAY4, "Standup", &[])],
        );
        let sent = organizer_messages(Some(&first), Some(&renamed), ORGANIZER);
        assert_eq!(sent.len(), 2);
        assert!(sent.iter().all(|message| message.method == Method::Request));
        assert_eq!(events(&sent_to(&sent, CAROL)[0].calendar), 1);

        // Bob dropped from day 3: a cancellation of that instance alone.
        let without_bob = series(
            &[BOB],
            &[(DAY3, "Standup", &[CAROL]), (DAY4, "Standup", &[])],
        );
        let sent = organizer_messages(Some(&first), Some(&without_bob), ORGANIZER);
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(
            (sent[0].method, sent[0].recipients.clone()),
            (Method::Cancel, vec![BOB.to_string()])
        );
        assert_eq!(events(&sent[0].calendar), 1);
        let text = sent[0].calendar.to_text();
        assert!(text.contains(&format!("RECURRENCE-ID:{DAY3}")) && !text.contains("RRULE"));
        // Carol dropped from her only instance: cancelled for her.
        let without_carol = series(&[BOB], &[(DAY3, "Standup", &[BOB]), (DAY4, "Standup", &[])]);
        let sent = organizer_messages(Some(&first), Some(&without_carol), ORGANIZER);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].method, Method::Cancel);
        assert_eq!(sent[0].recipients, vec![CAROL]);
    }

    #[test]
    fn instances_added_and_overridden_without_an_attendee() {
        let plain = series(&[BOB], &[]);
        // Day 2 moved without Bob: he gets that occurrence cancelled, made
        // from the series.
        let moved = series(&[BOB], &[(DAY2, "Elsewhere", &[])]);
        let sent = organizer_messages(Some(&plain), Some(&moved), ORGANIZER);
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(sent[0].method, Method::Cancel);
        let text = sent[0].calendar.to_text();
        assert!(text.contains(&format!("RECURRENCE-ID:{DAY2}")));
        assert!(text.contains(&format!("DTSTART:{DAY2}")) && !text.contains("RRULE"));
        let copy = apply_cancel(&apply_request(None, &plain), &sent[0].calendar);
        assert!(copy.to_text().contains(&format!("EXDATE:{DAY2}")));

        // Carol added to one instance: invited to that one only.
        let with_carol = series(&[BOB], &[(DAY3, "Standup", &[BOB, CAROL])]);
        let sent = organizer_messages(Some(&plain), Some(&with_carol), ORGANIZER);
        let carol = sent_to(&sent, CAROL);
        assert_eq!(carol.len(), 1);
        assert_eq!(carol[0].method, Method::Request);
        assert_eq!(events(&carol[0].calendar), 1);
        // Bob's view gained the override, so he is updated too.
        assert_eq!(sent_to(&sent, BOB).len(), 1);
        // Forcing a send reaches an attendee even without a change.
        let forced = text::parse(&with_carol.to_text().replace(
            "ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:carol",
            "ATTENDEE;SCHEDULE-FORCE-SEND=REQUEST:mailto:carol",
        ))
        .unwrap();
        let sent = organizer_messages(Some(&with_carol), Some(&forced), ORGANIZER);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].recipients, vec![CAROL]);
        assert!(!sent[0].calendar.to_text().contains("SCHEDULE-FORCE-SEND"));

        // Bob dropped from the series but kept on day 3: the series is
        // cancelled, then day 3 sent on its own.
        let only_day3 = series(&[], &[(DAY3, "Standup", &[BOB, CAROL])]);
        let sent = organizer_messages(Some(&with_carol), Some(&only_day3), ORGANIZER);
        let bob = sent_to(&sent, BOB);
        assert_eq!(bob.len(), 2, "{sent:?}");
        assert_eq!(bob[0].method, Method::Cancel);
        assert_eq!(bob[1].method, Method::Request);
        assert_eq!(events(&bob[1].calendar), 1);
        // Applied in order, Bob's copy holds day 3 alone.
        let copy = apply_request(None, &outgoing(&with_carol, Method::Request));
        let copy = apply_cancel(&copy, &bob[0].calendar);
        let copy = apply_request(Some(&copy), &bob[1].calendar);
        assert_eq!(events(&copy), 1);
        assert!(!copy.to_text().contains("CANCELLED"));
    }

    #[test]
    fn an_answer_for_one_occurrence_gets_its_own_override() {
        let organized = text::parse(
            &series(&[BOB], &[])
                .to_text()
                .replace("DURATION:PT1H", "DTEND:20261012T100000Z"),
        )
        .unwrap();
        // Bob declines day 3 only, in his copy.
        let mine = apply_request(None, &outgoing(&organized, Method::Request));
        let mut declined = mine.clone();
        let mut day3 = occurrence(
            master(&mine).unwrap(),
            &Property::new("RECURRENCE-ID", DAY3),
        );
        for attendee in &mut day3.properties {
            if attendee.name == "ATTENDEE" && is_user(attendee, BOB) {
                attendee.set_param("PARTSTAT", Some("DECLINED"));
            }
        }
        declined.components.push(day3);
        let reply = attendee_reply(Some(&mine), Some(&declined), BOB).unwrap();
        assert_eq!(events(&reply.calendar), 1);
        let merged = apply_reply(&organized, &reply.calendar, BOB).unwrap();
        assert_eq!(events(&merged), 2);
        let text = merged.to_text();
        assert!(text.contains(&format!("RECURRENCE-ID:{DAY3}")));
        assert!(text.contains("DURATION:PT3600S"), "{text}");
        assert_eq!(text.matches("PARTSTAT=DECLINED").count(), 1);
        // Not for an occurrence that was taken out, nor from a stranger.
        let excluded = text::parse(
            &organized
                .to_text()
                .replace("RRULE:", &format!("EXDATE:{DAY3}\r\nRRULE:")),
        )
        .unwrap();
        assert!(apply_reply(&excluded, &reply.calendar, BOB).is_none());
        assert!(apply_reply(&organized, &reply.calendar, CAROL).is_none());
        // Nor for a date the series does not have: between occurrences,
        // or after its last one.
        for fake in ["20261014T100000Z", "20261020T090000Z"] {
            let invented = text::parse(&reply.calendar.to_text().replace(DAY3, fake)).unwrap();
            assert!(apply_reply(&organized, &invented, BOB).is_none(), "{fake}");
        }
    }

    #[test]
    fn a_request_for_some_instances_updates_a_copy_of_the_series() {
        let copy = apply_request(None, &series(&[BOB], &[]));
        let only = |calendar: Component| attendee_view(&calendar, BOB, &BTreeMap::new()).unwrap();
        let update = only(series(&[], &[(DAY3, "Moved", &[BOB])]));
        let merged = apply_request(Some(&copy), &update);
        assert_eq!(events(&merged), 2);
        let text = merged.to_text();
        assert!(text.contains("RRULE:") && text.contains("SUMMARY:Moved"));
        assert_eq!(text.matches("BEGIN:VTIMEZONE").count(), 1);
        // The same instance again replaces it.
        let again = apply_request(
            Some(&merged),
            &only(series(&[], &[(DAY3, "Again", &[BOB])])),
        );
        assert_eq!(events(&again), 2);
        assert!(!again.to_text().contains("SUMMARY:Moved"));
        // A cancelled series has nothing to merge into.
        let cancelled = apply_cancel(&copy, &cancel_of(&copy));
        assert_eq!(events(&apply_request(Some(&cancelled), &update)), 1);
    }
}
