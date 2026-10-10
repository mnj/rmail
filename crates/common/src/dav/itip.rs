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
//!   client. Every attendee gets the whole event, overrides included.

use std::collections::BTreeSet;

use super::text::{Component, Property};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Request,
    Cancel,
    Reply,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Request => "REQUEST",
            Method::Cancel => "CANCEL",
            Method::Reply => "REPLY",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "REQUEST" => Some(Method::Request),
            "CANCEL" => Some(Method::Cancel),
            "REPLY" => Some(Method::Reply),
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

fn cancel_of(calendar: &Component, recipients: Vec<String>) -> Message {
    let mut cancel = outgoing(calendar, Method::Cancel);
    for component in scheduled_mut(&mut cancel) {
        component.set_property("STATUS", "CANCELLED");
    }
    Message {
        method: Method::Cancel,
        recipients,
        calendar: cancel,
    }
}

/// The messages an organizer's change sends: `previous` and `current` are
/// the stored versions before and after (`None` for created or deleted).
pub fn organizer_messages(
    previous: Option<&Component>,
    current: Option<&Component>,
    user: &str,
) -> Vec<Message> {
    let before = previous
        .filter(|calendar| role(calendar, user) == Role::Organizer)
        .map(|calendar| attendees(calendar, user))
        .unwrap_or_default();
    let mut messages = Vec::new();
    let Some(current) = current.filter(|calendar| role(calendar, user) == Role::Organizer) else {
        // Deleted, or no longer organized here: cancel for everyone.
        if let Some(previous) = previous
            && !before.is_empty()
            && !is_cancelled(previous)
        {
            messages.push(cancel_of(previous, before.into_iter().collect()));
        }
        return messages;
    };
    let now = attendees(current, user);
    if is_cancelled(current) {
        let already = previous.is_some_and(is_cancelled);
        let recipients = if already {
            now.difference(&before).cloned().collect::<Vec<_>>()
        } else {
            now.union(&before).cloned().collect()
        };
        if !recipients.is_empty() {
            messages.push(cancel_of(current, recipients));
        }
        return messages;
    }
    let changed = previous.is_none_or(|previous| significant(previous) != significant(current));
    let mut invited = if changed {
        now.clone()
    } else {
        now.difference(&before).cloned().collect()
    };
    invited.extend(force_send(current, user));
    if !invited.is_empty() {
        messages.push(Message {
            method: Method::Request,
            recipients: invited.into_iter().collect(),
            calendar: outgoing(current, Method::Request),
        });
    }
    let removed = before.difference(&now).cloned().collect::<Vec<_>>();
    if let Some(previous) = previous
        && !removed.is_empty()
    {
        messages.push(cancel_of(previous, removed));
    }
    messages
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
/// the recipient's alarms kept.
pub fn apply_request(existing: Option<&Component>, message: &Component) -> Component {
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
fn unescape(value: &str) -> String {
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
        assert_eq!(sent[0].recipients, vec!["carol@example.test"]);
        assert_eq!(sent[1].method, Method::Cancel);
        assert_eq!(sent[1].recipients, vec!["bob@example.test"]);
        assert!(sent[1].calendar.to_text().contains("STATUS:CANCELLED"));
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
}
