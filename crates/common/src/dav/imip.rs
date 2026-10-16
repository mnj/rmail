//! Scheduling messages received by email (iMIP, RFC 6047): an invitation,
//! cancellation or reply delivered to an account is also put in its
//! CalDAV schedule inbox, so calendar clients offer it like one from an
//! account here.
//!
//! - Anyone can send mail, so a received `REQUEST` or `CANCEL` is never
//!   applied to the account's calendars: the client shows it, and the
//!   user's answer is scheduled as usual. Writing invitations straight
//!   into calendars would let any sender fill them.
//! - A `REPLY` updates the account's own copy at once, but only when the
//!   account organizes the event, the replying attendee is invited to it,
//!   and the delivery vouches for the attendee's domain (DMARC passed for
//!   the `From` domain) or address (sent by that account here). Otherwise
//!   it only goes to the inbox.
//! - A `COUNTER` (an attendee proposing other times) and a `DECLINECOUNTER`
//!   are only kept for the organizer and the attendee to act on.
//! - Only messages addressed to the account are kept: it must be an
//!   attendee of a `REQUEST` or `CANCEL` and the organizer of a `REPLY`,
//!   under its own address or an alias that delivers only to it
//!   (`db::calendar_addresses`).

use std::path::Path;

use anyhow::Result;
use rusqlite::Connection;

use super::itip::{self, Method, Role};
use super::store::{self, Prepared, PutError, ScheduleTag};
use super::text::{self, Component};
use crate::mime::{self, CalendarPart};

/// The largest calendar part looked at.
pub const MAX_CALENDAR_BYTES: usize = 1024 * 1024;

/// Who the delivery vouches the message comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verified {
    Nobody,
    /// DMARC passed for this `From` domain.
    Domain(String),
    /// Submitted by this account, whose address the `From` header names.
    Address(String),
}

impl Verified {
    fn vouches_for(&self, address: &str) -> bool {
        match self {
            Verified::Nobody => false,
            Verified::Address(sender) => same_address(sender, address),
            Verified::Domain(domain) => address
                .rsplit_once('@')
                .is_some_and(|(_, found)| same_domain(found, domain)),
        }
    }
}

fn same_domain(a: &str, b: &str) -> bool {
    let canonical = |domain: &str| {
        crate::domain::canonicalize_domain(domain).unwrap_or_else(|_| domain.to_ascii_lowercase())
    };
    canonical(a) == canonical(b)
}

fn same_address(a: &str, b: &str) -> bool {
    let canonical = |address: &str| {
        crate::domain::canonicalize_mailbox_address(address)
            .unwrap_or_else(|_| address.to_ascii_lowercase())
    };
    canonical(a).eq_ignore_ascii_case(&canonical(b))
}

/// What became of a received message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// No calendar part.
    None,
    /// A calendar part that is not kept, and why.
    Skipped(&'static str),
    /// Put in the schedule inbox; `applied` when a reply also updated the
    /// organizer's copy, else `why` not.
    Deposited {
        method: Method,
        applied: bool,
        why: Option<&'static str>,
    },
}

/// Look for an iTIP message in mail delivered to an account and keep it in
/// the account's schedule inbox (see the module documentation).
/// `addresses` are the account's calendar addresses, its own first. The
/// account's state is only opened when there is something to keep.
pub fn receive(
    mail_root: &Path,
    domain: &str,
    localpart: &str,
    addresses: &[String],
    message: &[u8],
    verified: &Verified,
) -> Result<Outcome> {
    if !mentions_calendar(message) {
        return Ok(Outcome::None);
    }
    let (method, calendar, account) = match scheduling_message(message, addresses)? {
        Ok(found) => found,
        Err(outcome) => return Ok(outcome),
    };
    let conn = crate::jmap::store::open(mail_root, domain, localpart)?;
    deposit(&conn, &account, method, &calendar, verified)
}

/// Cheaply rule out mail without a calendar part before parsing it.
fn mentions_calendar(message: &[u8]) -> bool {
    const NEEDLE: &[u8] = b"text/calendar";
    message
        .windows(NEEDLE.len())
        .any(|window| window.eq_ignore_ascii_case(NEEDLE))
}

/// The iTIP message in `message` and the address it reaches the account
/// at, if it is one for the account.
fn scheduling_message(
    message: &[u8],
    addresses: &[String],
) -> Result<std::result::Result<(Method, Component, String), Outcome>> {
    let data = match mime::calendar_part(message, MAX_CALENDAR_BYTES) {
        CalendarPart::Missing => return Ok(Err(Outcome::None)),
        CalendarPart::TooLarge => return Ok(Err(Outcome::Skipped("calendar part too large"))),
        CalendarPart::Found(data) => data,
    };
    let (method, calendar) = match scheduling_object(&data)? {
        Ok(found) => found,
        Err(why) => return Ok(Err(Outcome::Skipped(why))),
    };
    let Some(organizer) = itip::organizer(&calendar) else {
        return Ok(Err(Outcome::Skipped("no organizer")));
    };
    let Some(account) = itip::own_address(&calendar, addresses) else {
        return Ok(Err(Outcome::Skipped("not addressed to the account")));
    };
    let addressed = match method {
        Method::Request | Method::Cancel | Method::DeclineCounter => {
            !same_address(&organizer, account) && itip::role(&calendar, account) == Role::Attendee
        }
        // A proposal of other times is for the organizer, who decides.
        Method::Reply | Method::Counter => itip::role(&calendar, account) == Role::Organizer,
    };
    if !addressed {
        return Ok(Err(Outcome::Skipped("not addressed to the account")));
    }
    Ok(Ok((method, calendar, account.to_string())))
}

/// An iTIP message as a calendar: a `REQUEST`, `REPLY` or `CANCEL` about one
/// event or to-do (one UID, as a calendar object holds; RFC 4791 4.1), or
/// why not. Unreadable calendar data is an error.
pub fn scheduling_object(
    data: &str,
) -> Result<std::result::Result<(Method, Component), &'static str>> {
    let calendar = text::parse(data)?;
    if calendar.name != "VCALENDAR" {
        return Ok(Err("not a calendar"));
    }
    let Some(method) = calendar
        .property("METHOD")
        .and_then(|method| Method::parse(&method.value))
    else {
        return Ok(Err("not a REQUEST, REPLY or CANCEL"));
    };
    let parts = calendar
        .components
        .iter()
        .filter(|component| component.name != "VTIMEZONE")
        .collect::<Vec<_>>();
    let uid = |component: &Component| {
        component
            .property("UID")
            .map(|uid| uid.value.trim().to_string())
            .filter(|uid| !uid.is_empty())
    };
    let one_object = parts.first().is_some_and(|first| {
        matches!(first.name.as_str(), "VEVENT" | "VTODO")
            && uid(first).is_some()
            && parts
                .iter()
                .all(|part| part.name == first.name && uid(part) == uid(first))
    });
    if !one_object {
        return Ok(Err("not one event or to-do"));
    }
    Ok(Ok((method, calendar)))
}

/// Put the message in the inbox and apply a vouched-for reply.
fn deposit(
    conn: &Connection,
    account: &str,
    method: Method,
    calendar: &Component,
    verified: &Verified,
) -> Result<Outcome> {
    store::inbox_add(conn, &calendar.to_text())?;
    let (applied, why) = if method == Method::Reply {
        match apply_reply(conn, account, calendar, verified)? {
            Ok(()) => (true, None),
            Err(why) => (false, Some(why)),
        }
    } else {
        (false, Some("invitations from email are left to the client"))
    };
    Ok(Outcome::Deposited {
        method,
        applied,
        why,
    })
}

fn apply_reply(
    conn: &Connection,
    account: &str,
    reply: &Component,
    verified: &Verified,
) -> Result<std::result::Result<(), &'static str>> {
    // A reply is one attendee's answer (RFC 5546 3.2.3).
    let mut attendees = reply
        .components
        .iter()
        .filter(|component| component.name != "VTIMEZONE")
        .flat_map(|component| component.properties_named("ATTENDEE"))
        .filter_map(|attendee| itip::address(&attendee.value))
        .collect::<Vec<_>>();
    attendees.sort();
    attendees.dedup();
    let [attendee] = attendees.as_slice() else {
        return Ok(Err("not one attendee"));
    };
    if !verified.vouches_for(attendee) {
        return Ok(Err("sender not verified for the attendee"));
    }
    let Some(uid) = reply
        .components
        .iter()
        .find(|component| component.name != "VTIMEZONE")
        .and_then(|component| component.property("UID"))
        .map(|uid| uid.value.trim().to_string())
    else {
        return Ok(Err("no UID"));
    };
    let Some((collection, object)) = store::find_by_uid(conn, &uid)? else {
        return Ok(Err("no copy of the event"));
    };
    // Applied to the version the write transaction holds, like replies
    // from accounts here.
    let stored = store::put_with(conn, &collection, &object.name, &mut |current| {
        let copy = current
            .and_then(|object| text::parse(&object.data).ok())
            .filter(|copy| itip::role(copy, account) == Role::Organizer)
            .ok_or(PutError::PreconditionFailed)?;
        let merged =
            itip::apply_reply(&copy, reply, attendee).ok_or(PutError::PreconditionFailed)?;
        Ok(Prepared {
            data: merged.to_text(),
            schedule_tag: ScheduleTag::Keep,
        })
    })?;
    match stored {
        Ok(_) => Ok(Ok(())),
        Err(PutError::PreconditionFailed) => Ok(Err(
            "not the organizer's copy, or the attendee is not invited",
        )),
        Err(error) => anyhow::bail!("storing the event: {error:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORGANIZER: &str = "user@example.test";
    const ATTENDEE: &str = "guest@remote.test";
    /// An alias that delivers only to the account.
    const ALIAS: &str = "sales@example.test";

    fn account(td: &tempfile::TempDir) -> crate::sqlite_pool::SqliteConnection {
        crate::jmap::store::open(td.path(), "example.test", "user").unwrap()
    }

    fn calendar(method: &str, organizer: &str, attendee: &str, partstat: &str) -> String {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//remote//EN\r\nMETHOD:{method}\r\n\
             BEGIN:VEVENT\r\nUID:ext-1\r\nDTSTAMP:20261001T000000Z\r\n\
             DTSTART:20261012T090000Z\r\nDURATION:PT1H\r\nSUMMARY:Review\r\n\
             ORGANIZER:mailto:{organizer}\r\nATTENDEE;PARTSTAT={partstat}:mailto:{attendee}\r\n\
             END:VEVENT\r\nEND:VCALENDAR\r\n"
        )
    }

    fn mail(calendar: &str) -> Vec<u8> {
        use base64::Engine;
        format!(
            "From: someone@remote.test\r\nTo: {ORGANIZER}\r\nSubject: iMIP\r\n\
             MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=b\r\n\r\n\
             --b\r\nContent-Type: text/plain\r\n\r\nSee the invitation.\r\n\
             --b\r\nContent-Type: text/calendar; method=X; charset=utf-8\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n{}\r\n--b--\r\n",
            base64::engine::general_purpose::STANDARD.encode(calendar)
        )
        .into_bytes()
    }

    fn receive_as(td: &tempfile::TempDir, message: &[u8], verified: &Verified) -> Outcome {
        receive(
            td.path(),
            "example.test",
            "user",
            &[ORGANIZER.to_string(), ALIAS.to_string()],
            message,
            verified,
        )
        .unwrap()
    }

    fn inbox_size(conn: &Connection) -> usize {
        store::objects(conn, &store::inbox(conn).unwrap())
            .unwrap()
            .len()
    }

    /// The organizer's own event with the remote attendee invited.
    fn organize(conn: &Connection) {
        let event = calendar("REQUEST", ORGANIZER, ATTENDEE, "NEEDS-ACTION")
            .replace("METHOD:REQUEST\r\n", "");
        let calendar = store::default_calendar(conn).unwrap();
        store::put(conn, &calendar, "ext.ics", &event, &|_| true)
            .unwrap()
            .unwrap();
    }

    fn stored_event(conn: &Connection) -> String {
        let calendar = store::default_calendar(conn).unwrap();
        store::object(conn, &calendar, "ext.ics")
            .unwrap()
            .unwrap()
            .data
    }

    #[test]
    fn invitations_and_replies_reach_the_account_at_its_alias() {
        let td = tempfile::tempdir().unwrap();
        let invite = calendar("REQUEST", ATTENDEE, ALIAS, "NEEDS-ACTION");
        assert!(matches!(
            receive_as(&td, &mail(&invite), &Verified::Nobody),
            Outcome::Deposited {
                method: Method::Request,
                ..
            }
        ));

        // The account's own event, organized under the alias.
        let conn = account(&td);
        let event =
            calendar("REQUEST", ALIAS, ATTENDEE, "NEEDS-ACTION").replace("METHOD:REQUEST\r\n", "");
        let collection = store::default_calendar(&conn).unwrap();
        store::put(&conn, &collection, "ext.ics", &event, &|_| true)
            .unwrap()
            .unwrap();
        let reply = calendar("REPLY", ALIAS, ATTENDEE, "ACCEPTED");
        let outcome = receive_as(&td, &mail(&reply), &Verified::Domain("remote.test".into()));
        assert_eq!(
            outcome,
            Outcome::Deposited {
                method: Method::Reply,
                applied: true,
                why: None
            }
        );
        assert!(stored_event(&conn).contains("PARTSTAT=ACCEPTED"));
    }

    #[test]
    fn invitations_go_to_the_inbox_only() {
        let td = tempfile::tempdir().unwrap();
        let invite = calendar("REQUEST", ATTENDEE, ORGANIZER, "NEEDS-ACTION");
        let outcome = receive_as(&td, &mail(&invite), &Verified::Domain("remote.test".into()));
        assert_eq!(
            outcome,
            Outcome::Deposited {
                method: Method::Request,
                applied: false,
                why: Some("invitations from email are left to the client"),
            }
        );
        let conn = account(&td);
        assert_eq!(inbox_size(&conn), 1);
        assert!(store::find_by_uid(&conn, "ext-1").unwrap().is_none());
        // Not addressed to the account, not iTIP, or no calendar at all.
        let elsewhere = calendar("REQUEST", ATTENDEE, "carol@example.test", "NEEDS-ACTION");
        assert_eq!(
            receive_as(&td, &mail(&elsewhere), &Verified::Nobody),
            Outcome::Skipped("not addressed to the account")
        );
        let publish = invite.replace("METHOD:REQUEST", "METHOD:PUBLISH");
        assert!(matches!(
            receive_as(&td, &mail(&publish), &Verified::Nobody),
            Outcome::Skipped(_)
        ));
        let plain = b"From: a@remote.test\r\nSubject: hi\r\n\r\ntext/calendar is a type\r\n";
        assert_eq!(receive_as(&td, plain, &Verified::Nobody), Outcome::None);
        assert_eq!(inbox_size(&conn), 1);
        // Broken calendar data is an error for the caller to log.
        assert!(
            receive(
                td.path(),
                "example.test",
                "user",
                &[ORGANIZER.to_string()],
                &mail("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\n"),
                &Verified::Nobody,
            )
            .is_err()
        );
    }

    #[test]
    fn verified_replies_update_the_organizers_copy() {
        let td = tempfile::tempdir().unwrap();
        let conn = account(&td);
        organize(&conn);
        let reply = mail(&calendar("REPLY", ORGANIZER, ATTENDEE, "ACCEPTED"));

        // Unverified, or verified for another domain: inbox only.
        for verified in [
            Verified::Nobody,
            Verified::Domain("elsewhere.test".into()),
            Verified::Address("other@remote.test".into()),
        ] {
            let outcome = receive_as(&td, &reply, &verified);
            assert!(matches!(outcome, Outcome::Deposited { applied: false, .. }));
        }
        assert!(stored_event(&conn).contains("PARTSTAT=NEEDS-ACTION"));
        assert_eq!(inbox_size(&conn), 3);

        // Someone not invited cannot answer, even from a verified domain.
        let stranger = mail(&calendar(
            "REPLY",
            ORGANIZER,
            "mallory@remote.test",
            "ACCEPTED",
        ));
        let outcome = receive_as(&td, &stranger, &Verified::Domain("remote.test".into()));
        assert!(matches!(outcome, Outcome::Deposited { applied: false, .. }));
        assert!(!stored_event(&conn).contains("mallory"));

        // DMARC passed for the attendee's domain: applied.
        let outcome = receive_as(&td, &reply, &Verified::Domain("REMOTE.test".into()));
        assert_eq!(
            outcome,
            Outcome::Deposited {
                method: Method::Reply,
                applied: true,
                why: None
            }
        );
        let data = stored_event(&conn);
        assert!(
            data.contains("PARTSTAT=ACCEPTED;SCHEDULE-STATUS=2.0"),
            "{data}"
        );

        // A reply about someone else's event is not the account's to take.
        let foreign = mail(
            &calendar("REPLY", "carol@example.test", ATTENDEE, "DECLINED")
                .replace("UID:ext-1", "UID:ext-2"),
        );
        assert_eq!(
            receive_as(&td, &foreign, &Verified::Domain("remote.test".into())),
            Outcome::Skipped("not addressed to the account")
        );
    }

    #[test]
    fn oversized_calendar_parts_are_skipped() {
        let td = tempfile::tempdir().unwrap();
        let invite = calendar("REQUEST", ATTENDEE, ORGANIZER, "NEEDS-ACTION").replace(
            "SUMMARY:Review",
            &format!("SUMMARY:{}", "x".repeat(MAX_CALENDAR_BYTES)),
        );
        assert_eq!(
            receive_as(&td, &mail(&invite), &Verified::Nobody),
            Outcome::Skipped("calendar part too large")
        );
    }
}
