//! CalDAV scheduling (RFC 6638): the server sends the invitations,
//! updates, cancellations and replies that changes to events imply, and
//! answers free-busy queries posted to the outbox.
//!
//! - Recipients with an account in the sender's domain get the message in
//!   their schedule inbox and their calendar copy updated at once.
//! - Everyone else gets an iMIP email (RFC 6047) through this server's
//!   submission service, with its checks and limits; replies from them
//!   come back by email, where smtpd puts them in the organizer's schedule
//!   inbox and applies those it can vouch for (`dav::imip`).
//! - Each attendee gets only the instances they are invited to
//!   (`itip::attendee_view`).
//! - Accounts in other domains on this server are reached by email too, so
//!   one domain cannot write into another's calendars or read its
//!   free-busy times, unless an administrator shares that domain's
//!   free-busy times with the whole server (`directory::freebusy_shared`).
//! - The stored copy records each recipient's `SCHEDULE-STATUS`.
//! - A change in a calendar shared with read-write access is scheduled as
//!   the calendar's owner (RFC 6638 3.2), whoever makes it: the owner is
//!   the organizer or attendee the event names, so messages come from the
//!   owner's address. Granting read-write access thus lets the sharee
//!   invite and answer in the owner's name for that calendar's events, as
//!   a delegate. Recipients still apply a message only when it comes from
//!   their copy's organizer.
//! - An account is also the calendar user of its aliases that deliver only
//!   to it (`db::calendar_addresses`): an event naming the alias is
//!   scheduled under the alias, and email for it is sent from the alias.

use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use rmail_common::dav::itip::{self, Message, Method, Role};
use rmail_common::dav::store::{self, Object, Prepared, ScheduleTag};
use rmail_common::dav::{recur, text};
use rmail_common::db;

use super::xml::{self, ROOT_NAMESPACES};
use super::{Dav, Target, status, xml_response};
use crate::jmap::User;

/// The most recipients one change schedules for; the rest are refused.
const MAX_RECIPIENTS: usize = 100;

/// The longest free-busy query, in seconds.
const MAX_FREEBUSY_RANGE: i64 = 400 * 86_400;

/// Where a recipient's scheduling messages go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Route {
    /// An account in the sender's domain: straight into its calendars.
    Local(User),
    /// By email.
    Email,
    /// Not deliverable, with the `SCHEDULE-STATUS` code.
    Refused(&'static str),
}

impl Route {
    fn status(&self) -> &'static str {
        match self {
            Route::Local(_) => "1.2",
            Route::Email => "1.1",
            Route::Refused(code) => code,
        }
    }
}

/// A message and where each of its recipients gets it.
pub(crate) struct Outgoing {
    /// The calendar user it is from: the owner of the calendar changed.
    sender: User,
    /// The address it is from: the sender's own or one of its aliases.
    from: String,
    message: Message,
    routes: Vec<(String, Route)>,
}

/// The calendar addresses of `user`, its own first.
pub(super) fn addresses(dav: &Dav, user: &User) -> Vec<String> {
    db::calendar_addresses(&dav.app.db_path, &user.address)
        .unwrap_or_else(|_| vec![user.address.clone()])
}

/// The address of `addresses` an event involves the user under, now or
/// before the change.
fn acting_address<'a>(
    addresses: &'a [String],
    calendar: &text::Component,
    previous: Option<&text::Component>,
) -> &'a str {
    let involved = |calendar: &text::Component| {
        itip::own_address(calendar, addresses)
            .filter(|address| itip::role(calendar, address) != Role::None)
    };
    involved(calendar)
        .or_else(|| previous.and_then(involved))
        .or(addresses.first().map(String::as_str))
        .unwrap_or_default()
}

fn same_domain(user: &User, domain: &str) -> bool {
    user.domain.eq_ignore_ascii_case(domain)
}

/// The account in `sender`'s domain an address reaches, directly or as an
/// alias with one target.
fn local_account(dav: &Dav, sender: &User, address: &str) -> Option<User> {
    account_here(dav, address).filter(|user| same_domain(sender, &user.domain))
}

/// The account `address` (or its single-target alias) reaches on this
/// server, in any domain.
fn account_here(dav: &Dav, address: &str) -> Option<User> {
    let canonical = rmail_common::domain::canonicalize_mailbox_address(address).ok()?;
    let target = if db::mailbox_exists(&dav.app.db_path, &canonical).ok()? {
        canonical
    } else {
        match db::get_alias_targets(&dav.app.db_path, &canonical).ok()?? {
            targets if targets.len() == 1 => {
                let target =
                    rmail_common::domain::canonicalize_mailbox_address(&targets[0]).ok()?;
                db::mailbox_exists(&dav.app.db_path, &target)
                    .ok()?
                    .then_some(target)?
            }
            _ => return None,
        }
    };
    let (localpart, domain) = target.rsplit_once('@')?;
    Some(User {
        address: target.clone(),
        domain: domain.to_string(),
        localpart: localpart.to_string(),
    })
}

/// An account whose free-busy times `sender` may see: in its domain, or
/// in a domain that shares them with the whole server.
fn freebusy_account(dav: &Dav, sender: &User, address: &str) -> anyhow::Result<Option<User>> {
    let Some(user) = account_here(dav, address) else {
        return Ok(None);
    };
    if same_domain(sender, &user.domain)
        || rmail_common::directory::freebusy_shared(&dav.app.db_path, &user.domain)?
    {
        return Ok(Some(user));
    }
    Ok(None)
}

fn route(dav: &Dav, sender: &User, address: &str) -> Route {
    if let Some(user) = local_account(dav, sender, address) {
        return Route::Local(user);
    }
    if dav.app.submission.is_some() {
        Route::Email
    } else {
        // Sending is off on this server.
        Route::Refused("5.1")
    }
}

/// Send scheduling messages (a proposal, a declined proposal) as `owner`,
/// from whichever of its addresses the event names.
pub(crate) fn send(dav: &Dav, owner: &User, from: &str, messages: Vec<Message>) {
    let own = addresses(dav, owner);
    deliver(dav, plan(dav, owner, from, &own, messages));
}

fn plan(
    dav: &Dav,
    sender: &User,
    from: &str,
    own: &[String],
    messages: Vec<Message>,
) -> Vec<Outgoing> {
    let mut budget = MAX_RECIPIENTS;
    messages
        .into_iter()
        .map(|message| {
            let routes = message
                .recipients
                .iter()
                .filter(|recipient| !own.iter().any(|own| own.eq_ignore_ascii_case(recipient)))
                .map(|recipient| {
                    let route = if budget == 0 {
                        Route::Refused("5.1")
                    } else if matches!(message.method, Method::Counter | Method::DeclineCounter) {
                        // Proposals go by email even inside the domain: the
                        // person deciding sees them in their mail (webmail
                        // shows them as a card), and delivery also files
                        // them in the schedule inbox for calendar apps.
                        budget -= 1;
                        if dav.app.submission.is_some() {
                            Route::Email
                        } else {
                            Route::Refused("5.1")
                        }
                    } else {
                        budget -= 1;
                        route(dav, sender, recipient)
                    };
                    (recipient.clone(), route)
                })
                .collect();
            Outgoing {
                sender: sender.clone(),
                from: from.to_string(),
                message,
                routes,
            }
        })
        .collect()
}

/// What a PUT of calendar data stores and which messages it sends as
/// `owner`, the calendar's owner, given the version it replaces (inside
/// the write transaction).
pub(crate) fn prepare_put(
    dav: &Dav,
    owner: &User,
    current: Option<&Object>,
    data: &str,
) -> (Prepared, Vec<Outgoing>) {
    let unchanged = |schedule_tag| Prepared {
        data: data.to_string(),
        schedule_tag,
    };
    // Invalid data is refused by the store.
    let Ok(mut calendar) = text::parse(data) else {
        return (unchanged(ScheduleTag::None), Vec::new());
    };
    let previous = current.and_then(|object| text::parse(&object.data).ok());
    let own = addresses(dav, owner);
    let user = acting_address(&own, &calendar, previous.as_ref());
    let role_now = itip::role(&calendar, user);
    let role_before = previous
        .as_ref()
        .map_or(Role::None, |previous| itip::role(previous, user));
    if role_now == Role::None && role_before == Role::None {
        return (unchanged(ScheduleTag::None), Vec::new());
    }
    let mut changed = itip::strip_force_send(&mut calendar);
    let (messages, property) = if role_now == Role::Organizer || role_before == Role::Organizer {
        (
            itip::organizer_messages(previous.as_ref(), Some(&calendar), user),
            "ATTENDEE",
        )
    } else {
        (
            itip::attendee_reply(previous.as_ref(), Some(&calendar), user)
                .into_iter()
                .collect(),
            "ORGANIZER",
        )
    };
    let outgoing = plan(dav, owner, user, &own, messages);
    let statuses = outgoing
        .iter()
        .flat_map(|outgoing| &outgoing.routes)
        .map(|(to, route)| (to.clone(), route.status().to_string()))
        .collect::<Vec<_>>();
    if !statuses.is_empty() {
        itip::set_statuses(&mut calendar, property, &statuses);
        changed = true;
    }
    let tag = if role_now == Role::None {
        ScheduleTag::None
    } else {
        ScheduleTag::New
    };
    let prepared = if changed {
        Prepared {
            data: calendar.to_text(),
            schedule_tag: tag,
        }
    } else {
        unchanged(tag)
    };
    (prepared, outgoing)
}

/// The messages deleting an event sends: cancellations from the organizer,
/// a decline from an attendee; `owner` is the calendar's owner.
pub(crate) fn prepare_delete(dav: &Dav, owner: &User, previous: &Object) -> Vec<Outgoing> {
    let Ok(previous) = text::parse(&previous.data) else {
        return Vec::new();
    };
    let own = addresses(dav, owner);
    let user = acting_address(&own, &previous, None);
    let messages = match itip::role(&previous, user) {
        Role::Organizer => itip::organizer_messages(Some(&previous), None, user),
        Role::Attendee => itip::attendee_reply(Some(&previous), None, user)
            .into_iter()
            .collect(),
        Role::None => Vec::new(),
    };
    plan(dav, owner, user, &own, messages)
}

/// Send what a stored change implies. Failures are logged: the change is
/// stored either way.
pub(crate) fn deliver(dav: &Dav, outgoing: Vec<Outgoing>) {
    for Outgoing {
        sender,
        from,
        message,
        routes,
    } in outgoing
    {
        let mut by_email = Vec::new();
        for (recipient, route) in routes {
            match route {
                Route::Local(account) => {
                    if let Err(error) = deliver_local(dav, &from, &account, &message) {
                        webmail_log!("warn", "scheduling_delivery_failed", {
                            "recipient": account.address,
                            "error": format!("{error:#}")
                        });
                    }
                }
                Route::Email => by_email.push(recipient),
                Route::Refused(_) => {}
            }
        }
        if !by_email.is_empty()
            && let Err(error) = send_email(dav, &sender, &from, &message, &by_email)
        {
            webmail_log!("warn", "scheduling_mail_failed", {
                "sender": sender.address,
                "error": format!("{error:#}")
            });
        }
    }
}

fn uid_of(calendar: &text::Component) -> Option<String> {
    calendar
        .components
        .iter()
        .filter(|component| component.name != "VTIMEZONE")
        .find_map(|component| component.property("UID"))
        .map(|uid| uid.value.trim().to_string())
}

/// Put a message in `account`'s inbox and apply it to their copy of the
/// event (RFC 6638 4.1).
/// One lock per resource account, held from storing an invitation to
/// answering it, so two bookings arriving together are judged one after the
/// other (each would otherwise count the other, still unanswered, as busy).
fn resource_lock(address: &str) -> std::sync::Arc<std::sync::Mutex<()>> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};
    static LOCKS: OnceLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> = OnceLock::new();
    LOCKS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(address.to_ascii_lowercase())
        .or_default()
        .clone()
}

pub(super) fn deliver_local(
    dav: &Dav,
    sender: &str,
    account: &User,
    message: &Message,
) -> anyhow::Result<()> {
    // A room or piece of equipment answers for itself.
    let resource = message.method == Method::Request
        && match rmail_common::resources::kind_of(&dav.app.db_path, &account.address) {
            Ok(kind) => kind.is_some(),
            Err(error) => {
                webmail_log!("warn", "resource_lookup_failed", { "account": account.address, "error": format!("{error:#}") });
                false
            }
        };
    let lock = resource.then(|| resource_lock(&account.address));
    let _held = lock
        .as_ref()
        .map(|lock| lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner()));
    let conn =
        rmail_common::jmap::store::open(&dav.app.mail_root, &account.domain, &account.localpart)?;
    store::inbox_add(&conn, &message.calendar.to_text())?;
    let Some(uid) = uid_of(&message.calendar) else {
        return Ok(());
    };
    let recipient = addresses(dav, account);
    // The lookup only picks where the copy is; the message is applied to
    // the version the write transaction holds, so concurrent replies or
    // the recipient's own edits are not lost.
    let (collection, name) = match store::find_by_uid(&conn, &uid)? {
        Some((collection, object)) => (collection, object.name),
        None if message.method == Method::Request => (
            store::default_calendar(&conn)?,
            format!("{}.ics", random_name()),
        ),
        None => return Ok(()),
    };
    let stored = store::put_with(&conn, &collection, &name, &mut |current| {
        let copy = current.and_then(|object| text::parse(&object.data).ok());
        apply(message, copy.as_ref(), sender, &recipient).ok_or(store::PutError::PreconditionFailed)
    })?;
    match stored {
        Ok(_) => {
            // The invitation is stored whatever becomes of the answer.
            if resource && let Err(error) = answer_as_resource(dav, account, &collection, &name) {
                webmail_log!("warn", "resource_answer_failed", { "account": account.address, "error": format!("{error:#}") });
            }
            Ok(())
        }
        // Nothing for this account to change.
        Err(store::PutError::PreconditionFailed) => Ok(()),
        Err(error) => anyhow::bail!("storing the event: {error:?}"),
    }
}

/// How far ahead a resource looks for clashes with a repeating booking.
const RESOURCE_HORIZON: i64 = 400 * 86_400;

/// A resource's answer to an invitation now in its calendar: accepted when
/// every occurrence (within [`RESOURCE_HORIZON`]) is free, declined when one
/// overlaps another booking. The reply goes out like anyone's.
fn answer_as_resource(
    dav: &Dav,
    resource: &User,
    collection: &store::Collection,
    name: &str,
) -> anyhow::Result<()> {
    let resource_dav = Dav {
        user: resource.clone(),
        conn: rmail_common::jmap::store::open(
            &dav.app.mail_root,
            &resource.domain,
            &resource.localpart,
        )?,
        app: dav.app.clone(),
    };
    let Some(object) = store::object(&resource_dav.conn, collection, name)? else {
        return Ok(());
    };
    let calendar = text::parse(&object.data)?;
    let own = addresses(&resource_dav, resource);
    let Some(me) = own
        .iter()
        .find(|address| itip::role(&calendar, address) == Role::Attendee)
        .cloned()
    else {
        return Ok(());
    };
    let now = chrono::Utc::now().timestamp();
    let (from, until) = (now - 86_400, now + RESOURCE_HORIZON);
    let wanted = recur::occurrences(&calendar, from, until);
    let taken = busy_except(
        &resource_dav,
        resource,
        from,
        until,
        uid_of(&calendar).as_deref(),
    )?;
    let clash = wanted.iter().any(|occurrence| {
        taken
            .iter()
            .any(|(begin, finish, _)| occurrence.start < *finish && *begin < occurrence.end)
    });
    let partstat = if clash { "DECLINED" } else { "ACCEPTED" };
    let mut outgoing = Vec::new();
    let stored = store::put_with(&resource_dav.conn, collection, name, &mut |current| {
        let Some(mut copy) = current.and_then(|object| text::parse(&object.data).ok()) else {
            return Err(store::PutError::PreconditionFailed);
        };
        for component in copy.components.iter_mut().filter(|c| c.name != "VTIMEZONE") {
            for attendee in component
                .properties
                .iter_mut()
                .filter(|property| property.name == "ATTENDEE")
            {
                if itip::address(&attendee.value)
                    .is_some_and(|found| found.eq_ignore_ascii_case(&me))
                {
                    attendee.set_param("PARTSTAT", Some(partstat));
                    attendee.set_param("RSVP", None);
                }
            }
        }
        let (prepared, messages) = prepare_put(&resource_dav, resource, current, &copy.to_text());
        outgoing = messages;
        Ok(prepared)
    })?;
    if stored.is_ok() {
        webmail_log!("info", "resource_answered", { "resource": resource.address, "answer": partstat });
        deliver(&resource_dav, outgoing);
    }
    Ok(())
}

/// The recipient's copy after a message from `sender`, or `None` when the
/// message does not change it: only the event's organizer changes an
/// existing copy, and a reply only reaches the organizer's own copy.
fn apply(
    message: &Message,
    copy: Option<&text::Component>,
    sender: &str,
    recipient: &[String],
) -> Option<Prepared> {
    let organized_by_sender = |copy: &text::Component| {
        itip::organizer(copy).is_some_and(|organizer| organizer.eq_ignore_ascii_case(sender))
    };
    let (calendar, schedule_tag) = match (message.method, copy) {
        (Method::Request, None) => (
            itip::apply_request(None, &message.calendar),
            ScheduleTag::New,
        ),
        (Method::Request, Some(copy)) if organized_by_sender(copy) => (
            itip::apply_request(Some(copy), &message.calendar),
            ScheduleTag::New,
        ),
        (Method::Cancel, Some(copy)) if organized_by_sender(copy) => (
            itip::apply_cancel(copy, &message.calendar),
            ScheduleTag::New,
        ),
        (Method::Reply, Some(copy))
            if recipient
                .iter()
                .any(|address| itip::role(copy, address) == Role::Organizer) =>
        {
            (
                itip::apply_reply(copy, &message.calendar, sender)?,
                ScheduleTag::Keep,
            )
        }
        _ => return None,
    };
    Some(Prepared {
        data: calendar.to_text(),
        schedule_tag,
    })
}

pub(crate) fn random_name() -> String {
    (0..16)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect()
}

/// An iMIP email (RFC 6047) with the message as a `text/calendar` part.
fn send_email(
    dav: &Dav,
    account: &User,
    sender: &str,
    message: &Message,
    recipients: &[String],
) -> anyhow::Result<()> {
    let Some(submission) = dav.app.submission else {
        anyhow::bail!("sending is off");
    };
    let (summary, details) = itip::summary_text(&message.calendar);
    let (subject, intro) = match message.method {
        Method::Request => (
            format!("Invitation: {summary}"),
            format!("{sender} invites you to \"{summary}\"."),
        ),
        Method::Cancel => (
            format!("Cancelled: {summary}"),
            format!("{sender} cancelled \"{summary}\"."),
        ),
        Method::Counter => (
            format!("New time proposed: {summary}"),
            format!("{sender} proposes another time for \"{summary}\"."),
        ),
        Method::DeclineCounter => (
            format!("Proposal declined: {summary}"),
            format!("{sender} keeps the time of \"{summary}\"."),
        ),
        Method::Reply => {
            let answer = message
                .calendar
                .components
                .iter()
                .flat_map(|component| component.properties_named("ATTENDEE"))
                .find_map(|attendee| attendee.param("PARTSTAT"))
                .unwrap_or("NEEDS-ACTION")
                .to_ascii_uppercase();
            let (word, verb) = match answer.as_str() {
                "ACCEPTED" => ("Accepted", "accepted"),
                "DECLINED" => ("Declined", "declined"),
                "TENTATIVE" => ("Tentative", "tentatively accepted"),
                _ => ("Reply", "replied to"),
            };
            (
                format!("{word}: {summary}"),
                format!("{sender} {verb} \"{summary}\"."),
            )
        }
    };
    let outgoing = rmail_common::compose::Outgoing {
        from: sender.to_string(),
        to: recipients.to_vec(),
        cc: Vec::new(),
        bcc: Vec::new(),
        subject,
        text: format!("{intro}\n\n{details}\n"),
        in_reply_to: None,
        references: None,
        attachments: Vec::new(),
        calendar: Some(rmail_common::compose::CalendarPart {
            method: message.method.as_str().to_string(),
            data: message.calendar.to_text(),
        }),
        ..Default::default()
    };
    let built = rmail_common::compose::build(&outgoing, false, None)?;
    tokio::runtime::Handle::current().block_on(crate::submit::submit_as(
        submission,
        &dav.app.mail_root,
        &account.address,
        sender,
        recipients,
        &built.bytes,
    ))
}

// ---------------------------------------------------------------------------
// Free-busy (RFC 6638 5)

/// POST to the outbox: a `VFREEBUSY` request for some attendees.
pub(crate) fn post(
    dav: &Dav,
    target: Target,
    headers: &HeaderMap,
    body: &[u8],
) -> anyhow::Result<Response> {
    if !matches!(target, Target::Outbox) {
        return Ok(status(StatusCode::METHOD_NOT_ALLOWED));
    }
    let is_calendar = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .trim()
                .to_ascii_lowercase()
                .starts_with("text/calendar")
        });
    let invalid = || {
        xml_response(
            StatusCode::BAD_REQUEST,
            xml::error("<c:valid-calendar-data/>"),
        )
    };
    if !is_calendar || body.len() > super::MAX_RESOURCE_SIZE {
        return Ok(invalid());
    }
    let Some(request) = std::str::from_utf8(body)
        .ok()
        .and_then(|data| text::parse(data).ok())
    else {
        return Ok(invalid());
    };
    let method = request
        .property("METHOD")
        .and_then(|m| Method::parse(&m.value));
    let Some(query) = request
        .components
        .iter()
        .find(|component| component.name == "VFREEBUSY")
        .filter(|_| method == Some(Method::Request))
    else {
        // Only free-busy queries are posted; events are scheduled by PUT.
        return Ok(xml_response(
            StatusCode::FORBIDDEN,
            xml::error("<c:valid-scheduling-message/>"),
        ));
    };
    let organizer = query.property("ORGANIZER");
    let own = addresses(dav, &dav.user);
    if organizer
        .and_then(|organizer| itip::address(&organizer.value))
        .is_none_or(|address| !own.iter().any(|own| own.eq_ignore_ascii_case(&address)))
    {
        return Ok(xml_response(
            StatusCode::FORBIDDEN,
            xml::error("<c:organizer-allowed/>"),
        ));
    }
    let (Some(start), Some(end)) = (
        query.property("DTSTART").and_then(recur::instant),
        query.property("DTEND").and_then(recur::instant),
    ) else {
        return Ok(invalid());
    };
    if end <= start || end - start > MAX_FREEBUSY_RANGE {
        return Ok(invalid());
    }
    let mut responses = String::new();
    for attendee in query.properties_named("ATTENDEE").take(MAX_RECIPIENTS) {
        let (status, data) = match itip::address(&attendee.value) {
            None => ("3.7;Invalid calendar user", None),
            Some(address) => match freebusy_account(dav, &dav.user, &address)? {
                Some(account) => (
                    "2.0;Success",
                    Some(freebusy_reply(dav, &account, query, attendee, start, end)?),
                ),
                None => ("5.3;No scheduling support for user", None),
            },
        };
        responses.push_str(&format!(
            "<c:response><c:recipient>{}</c:recipient><c:request-status>{status}</c:request-status>{}</c:response>",
            xml::href(&attendee.value),
            data.map(|data| format!("<c:calendar-data>{}</c:calendar-data>", xml::escape(&data)))
                .unwrap_or_default()
        ));
    }
    Ok(xml_response(
        StatusCode::OK,
        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<c:schedule-response {ROOT_NAMESPACES}>{responses}</c:schedule-response>"
        ),
    ))
}

/// Busy periods of `account` between `start` and `end`: opaque, not
/// cancelled, not declined events; tentative ones apart.
fn busy(dav: &Dav, account: &User, start: i64, end: i64) -> anyhow::Result<Vec<(i64, i64, bool)>> {
    busy_except(dav, account, start, end, None)
}

/// [`busy`], leaving out the event with UID `skip` (the one being answered).
fn busy_except(
    dav: &Dav,
    account: &User,
    start: i64,
    end: i64,
    skip: Option<&str>,
) -> anyhow::Result<Vec<(i64, i64, bool)>> {
    let conn = if account.address == dav.user.address {
        None
    } else {
        Some(rmail_common::jmap::store::open(
            &dav.app.mail_root,
            &account.domain,
            &account.localpart,
        )?)
    };
    let conn = conn.as_deref().unwrap_or(&dav.conn);
    let own = addresses(dav, account);
    let mut periods = Vec::new();
    for collection in store::collections(conn, store::Kind::Calendar)? {
        for object in store::objects(conn, &collection)? {
            if object.component.as_deref() != Some("VEVENT")
                || object.start.is_some_and(|begin| begin >= end)
                || object.end.is_some_and(|finish| finish <= start)
            {
                continue;
            }
            if skip.is_some() && object.uid.as_deref() == skip {
                continue;
            }
            let Ok(calendar) = text::parse(&object.data) else {
                continue;
            };
            for occurrence in recur::occurrences(&calendar, start, end) {
                let event = &calendar.components[occurrence.component];
                let value = |name: &str| {
                    event
                        .property(name)
                        .map(|property| property.value.trim().to_ascii_uppercase())
                };
                let declined = event
                    .properties_named("ATTENDEE")
                    .filter(|attendee| {
                        itip::address(&attendee.value).is_some_and(|address| {
                            own.iter().any(|own| own.eq_ignore_ascii_case(&address))
                        })
                    })
                    .any(|attendee| {
                        attendee
                            .param("PARTSTAT")
                            .is_some_and(|partstat| partstat.eq_ignore_ascii_case("DECLINED"))
                    });
                if value("TRANSP").as_deref() == Some("TRANSPARENT")
                    || value("STATUS").as_deref() == Some("CANCELLED")
                    || declined
                    || occurrence.end <= occurrence.start
                {
                    continue;
                }
                let tentative = value("STATUS").as_deref() == Some("TENTATIVE");
                periods.push((
                    occurrence.start.max(start),
                    occurrence.end.min(end),
                    tentative,
                ));
            }
        }
    }
    Ok(merge(periods))
}

/// Overlapping periods of the same kind joined, sorted by start.
fn merge(mut periods: Vec<(i64, i64, bool)>) -> Vec<(i64, i64, bool)> {
    periods.sort();
    let mut merged: Vec<(i64, i64, bool)> = Vec::new();
    for tentative in [false, true] {
        let mut last: Option<(i64, i64)> = None;
        for &(begin, finish, _) in periods.iter().filter(|p| p.2 == tentative) {
            match &mut last {
                Some((_, until)) if begin <= *until => *until = (*until).max(finish),
                _ => {
                    if let Some((a, b)) = last.take() {
                        merged.push((a, b, tentative));
                    }
                    last = Some((begin, finish));
                }
            }
        }
        if let Some((a, b)) = last {
            merged.push((a, b, tentative));
        }
    }
    merged.sort();
    merged
}

fn freebusy_reply(
    dav: &Dav,
    account: &User,
    query: &text::Component,
    attendee: &text::Property,
    start: i64,
    end: i64,
) -> anyhow::Result<String> {
    let mut reply = text::Component::new("VFREEBUSY");
    if let Some(uid) = query.property("UID") {
        reply.properties.push(uid.clone());
    }
    reply.set_property("DTSTAMP", &recur::utc_text(chrono::Utc::now().timestamp()));
    reply.set_property("DTSTART", &recur::utc_text(start));
    reply.set_property("DTEND", &recur::utc_text(end));
    if let Some(organizer) = query.property("ORGANIZER") {
        reply.properties.push(organizer.clone());
    }
    reply.properties.push(attendee.clone());
    for (begin, finish, tentative) in busy(dav, account, start, end)? {
        let mut line = text::Property::new(
            "FREEBUSY",
            &format!("{}/{}", recur::utc_text(begin), recur::utc_text(finish)),
        );
        line.set_param(
            "FBTYPE",
            Some(if tentative { "BUSY-TENTATIVE" } else { "BUSY" }),
        );
        reply.properties.push(line);
    }
    let mut calendar = text::Component::new("VCALENDAR");
    calendar.set_property("VERSION", "2.0");
    calendar.set_property("PRODID", "-//rMail//CalDAV//EN");
    calendar.set_property("METHOD", "REPLY");
    calendar.components.push(reply);
    Ok(calendar.to_text())
}
