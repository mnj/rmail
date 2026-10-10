//! CalDAV (RFC 4791) and CardDAV (RFC 6352) for the accounts' calendars
//! and contacts, served by webmail under `/dav/`.
//!
//! - Clients sign in as for JMAP: HTTP Basic or an OAuth Bearer token.
//! - `/.well-known/caldav` and `/.well-known/carddav` (RFC 6764) lead to
//!   `/dav/`, where `current-user-principal` names
//!   `/dav/principals/<address>/`; its home sets are
//!   `/dav/calendars/<address>/` and `/dav/addressbooks/<address>/`.
//! - Each account has a calendar and an address book from the start and
//!   can create more (MKCALENDAR, extended MKCOL).
//! - Changes are tracked per collection for `sync-collection` (RFC 6578)
//!   and `getctag`; see `rmail_common::dav::store`.
//! - Scheduling (RFC 6638) is done by the server: see `schedule`. Each
//!   calendar home has `inbox/` and `outbox/`.
//! - Collections other accounts share with the user (see
//!   `rmail_common::dav::share`) appear in the user's home as
//!   `<owner>~<name>/`, read-only or read-write as granted; see `sharing`.
//!   Clients discover them like the user's own, as every client lists the
//!   home's members, and `current-user-privilege-set` tells them whether
//!   they may write.

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::{Extension, Router};
use rmail_common::dav::share::{self, Access};
use rmail_common::dav::store::{self, Collection, Kind, Object, PutError};
use rmail_common::db;
use rmail_common::http::Peer;
use rmail_common::sqlite_pool::SqliteConnection;
use rusqlite::Connection;

use crate::api::AppState;
use crate::jmap::{self, User};

mod props;
mod report;
mod schedule;
mod sharing;
mod xml;

#[cfg(test)]
mod tests;

/// The largest calendar object or vCard accepted (RFC 4791 max-resource-size).
pub(crate) const MAX_RESOURCE_SIZE: usize = 5 * 1024 * 1024;

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/.well-known/caldav", any(well_known))
        .route("/.well-known/carddav", any(well_known))
        .route("/", any(server_root))
        .route("/dav", any(handle))
        .route("/dav/", any(handle))
        .route("/dav/{*path}", any(handle))
}

/// RFC 6764 section 5: the well-known URIs redirect to the context path.
async fn well_known() -> Response {
    let mut response = StatusCode::MOVED_PERMANENTLY.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static("/dav/"));
    response
}

// ---------------------------------------------------------------------------
// Paths

fn percent_decode(segment: &str) -> Option<String> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = std::str::from_utf8(bytes.get(index + 1..index + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn percent_encode(segment: &str) -> String {
    segment
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-._~@+".contains(&byte) {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// The path segments after `/dav/`, decoded.
fn segments(path: &str) -> Option<Vec<String>> {
    let rest = path.strip_prefix("/dav")?;
    rest.split('/')
        .filter(|segment| !segment.is_empty())
        .map(percent_decode)
        .collect()
}

/// Accept an href from a request body (absolute URL or path) as segments.
pub(crate) fn href_segments(href: &str) -> Option<Vec<String>> {
    let path = match href.find("://") {
        Some(index) => {
            let after = &href[index + 3..];
            &after[after.find('/')?..]
        }
        None => href,
    };
    segments(path)
}

pub(crate) fn principal_href(user: &User) -> String {
    format!("/dav/principals/{}/", percent_encode(&user.address))
}

pub(crate) fn home_href(user: &User, kind: Kind) -> String {
    format!(
        "/dav/{}/{}/",
        home_segment(kind),
        percent_encode(&user.address)
    )
}

fn home_segment(kind: Kind) -> &'static str {
    match kind {
        Kind::Calendar => "calendars",
        Kind::AddressBook => "addressbooks",
    }
}

/// The URL segment binding a shared collection into the grantee's home:
/// `<owner>~<name>`. The user's own collections cannot have an `@` in
/// their name, so the two never meet.
pub(crate) fn binding_segment(owner: &str, name: &str) -> String {
    format!("{owner}~{name}")
}

/// The owner and collection name a binding segment names.
fn parse_binding(segment: &str) -> Option<(&str, &str)> {
    let at = segment.find('@')?;
    // Domains have no `~`; the first one after the `@` ends the owner.
    let tilde = at + segment[at..].find('~')?;
    let (owner, name) = (&segment[..tilde], &segment[tilde + 1..]);
    (at > 0 && tilde > at + 1 && !name.is_empty()).then_some((owner, name))
}

/// The URL of one of the user's own collections.
pub(crate) fn own_collection_href(user: &User, collection: &Collection) -> String {
    format!(
        "{}{}/",
        home_href(user, collection.kind),
        percent_encode(&collection.name)
    )
}

/// A collection's URL as `user` reaches it: in their home, as their own
/// or bound there by a share.
pub(crate) fn collection_href(user: &User, place: &Place) -> String {
    match &place.share {
        None => own_collection_href(user, &place.collection),
        Some(share) => format!(
            "{}{}/",
            home_href(user, place.collection.kind),
            percent_encode(&binding_segment(
                &share.owner.address,
                &place.collection.name
            ))
        ),
    }
}

pub(crate) fn outbox_href(user: &User) -> String {
    format!("{}outbox/", home_href(user, Kind::Calendar))
}

pub(crate) fn object_href(user: &User, place: &Place, name: &str) -> String {
    format!("{}{}", collection_href(user, place), percent_encode(name))
}

/// A collection another account shares with the user.
pub(crate) struct Share {
    pub owner: User,
    /// The owner's state database, which holds the collection.
    pub conn: Rc<SqliteConnection>,
    pub grant: share::Grant,
}

/// A collection as a request reaches it: the user's own, or another
/// account's shared with them.
#[derive(Clone)]
pub(crate) struct Place {
    pub collection: Collection,
    pub share: Option<Rc<Share>>,
}

impl Place {
    pub fn own(collection: Collection) -> Self {
        Self {
            collection,
            share: None,
        }
    }

    /// Whether the user may change the collection and its objects.
    pub fn writable(&self) -> bool {
        self.share
            .as_ref()
            .is_none_or(|share| share.grant.access == Access::ReadWrite)
    }

    /// The account whose collection it is. Scheduling acts as this
    /// calendar user (RFC 6638 3.2: as the owner of the calendar), even
    /// when a sharee makes the change.
    pub fn owner<'a>(&'a self, dav: &'a Dav) -> &'a User {
        self.share.as_ref().map_or(&dav.user, |share| &share.owner)
    }
}

/// What a request path names.
pub(crate) enum Target {
    Root,
    Principals,
    Principal,
    /// The principal of an account that shares a collection with the user.
    Sharer(User),
    Home(Kind),
    /// A calendar, address book or the schedule inbox.
    Collection(Place),
    /// The schedule outbox (RFC 6638 2.1), for free-busy queries.
    Outbox,
    /// A collection that does not exist yet (for MKCALENDAR/MKCOL).
    NewCollection(Kind, String),
    /// An object, which may not exist yet (for PUT).
    Object(Place, Option<Box<Object>>, String),
    NotFound,
}

pub(crate) struct Dav {
    pub user: User,
    pub conn: SqliteConnection,
    pub app: Arc<AppState>,
}

impl Dav {
    /// The database holding a collection and its objects.
    pub fn conn_of<'a>(&'a self, place: &'a Place) -> &'a Connection {
        match &place.share {
            Some(share) => &share.conn,
            None => &self.conn,
        }
    }

    /// The account at `address`, if there is one.
    fn account(&self, address: &str) -> anyhow::Result<Option<User>> {
        let Ok(address) = rmail_common::domain::canonicalize_mailbox_address(address) else {
            return Ok(None);
        };
        let Some((localpart, domain)) = address.split_once('@') else {
            return Ok(None);
        };
        // Grants go with a removed account; checking anyway keeps a stale
        // one from creating storage for a name that is gone.
        if !db::mailbox_exists(&self.app.db_path, &address)? {
            return Ok(None);
        }
        Ok(Some(User {
            localpart: localpart.to_string(),
            domain: domain.to_string(),
            address: address.clone(),
        }))
    }

    /// The collections shared with the user: of `kind` (or both), and of
    /// `owner` (or every owner). Grants on collections deleted since are
    /// skipped; each owner's database is opened once.
    pub fn shared(&self, kind: Option<Kind>, owner: Option<&str>) -> anyhow::Result<Vec<Place>> {
        let mut grants = share::shared_with(&self.app.db_path, &self.user.address)?;
        if let Some(owner) = owner {
            grants.retain(|grant| grant.owner.eq_ignore_ascii_case(owner));
        }
        let mut owners = HashMap::<String, Option<(User, Rc<SqliteConnection>)>>::new();
        let mut found = Vec::new();
        for grant in grants {
            if !owners.contains_key(&grant.owner) {
                let opened = match self.account(&grant.owner)? {
                    Some(user) => {
                        let conn = rmail_common::jmap::store::open(
                            &self.app.mail_root,
                            &user.domain,
                            &user.localpart,
                        )?;
                        Some((user, Rc::new(conn)))
                    }
                    None => None,
                };
                owners.insert(grant.owner.clone(), opened);
            }
            let Some(Some((user, conn))) = owners.get(&grant.owner) else {
                continue;
            };
            let Some(collection) = store::collection_by_id(conn, grant.collection_id)? else {
                continue;
            };
            if kind.is_some_and(|kind| kind != collection.kind) {
                continue;
            }
            found.push(Place {
                collection,
                share: Some(Rc::new(Share {
                    owner: user.clone(),
                    conn: conn.clone(),
                    grant,
                })),
            });
        }
        Ok(found)
    }

    /// The collection a segment of the user's home names: their own, the
    /// schedule inbox, or a shared one's binding.
    fn place(&self, kind: Kind, name: &str) -> anyhow::Result<Option<Place>> {
        if name.contains('@') {
            let Some((owner, name)) = parse_binding(name) else {
                return Ok(None);
            };
            return Ok(self
                .shared(Some(kind), Some(owner))?
                .into_iter()
                .find(|place| place.collection.name == name));
        }
        if kind == Kind::Calendar && name == "inbox" {
            return Ok(Some(Place::own(store::inbox(&self.conn)?)));
        }
        Ok(store::collection(&self.conn, kind, name)?.map(Place::own))
    }

    pub fn resolve(&self, segments: &[String]) -> anyhow::Result<Target> {
        let own = |address: &String| address.eq_ignore_ascii_case(&self.user.address);
        let kind = |segment: &str| match segment {
            "calendars" => Some(Kind::Calendar),
            "addressbooks" => Some(Kind::AddressBook),
            _ => None,
        };
        Ok(match segments {
            [] => Target::Root,
            [first] if first == "principals" => Target::Principals,
            [first, user] if first == "principals" && own(user) => Target::Principal,
            [first, user] if first == "principals" => {
                // Another account's principal is visible only to accounts
                // it shares with, as the owner of what they see.
                match self.shared(None, Some(user))?.into_iter().next() {
                    Some(place) => Target::Sharer(place.owner(self).clone()),
                    None => Target::NotFound,
                }
            }
            [home, user] if kind(home).is_some() && own(user) => {
                Target::Home(kind(home).unwrap_or(Kind::Calendar))
            }
            [home, user, name] if home == "calendars" && own(user) && name == "outbox" => {
                Target::Outbox
            }
            [home, user, name] if kind(home).is_some() && own(user) => {
                let kind = kind(home).unwrap_or(Kind::Calendar);
                match self.place(kind, name)? {
                    Some(place) => Target::Collection(place),
                    // Names with `@` are for shares, never new collections.
                    None if name.contains('@') => Target::NotFound,
                    None => Target::NewCollection(kind, name.clone()),
                }
            }
            [home, user, name, object] if kind(home).is_some() && own(user) => {
                let kind = kind(home).unwrap_or(Kind::Calendar);
                match self.place(kind, name)? {
                    Some(place) => {
                        let found = store::object(self.conn_of(&place), &place.collection, object)?;
                        Target::Object(place, found.map(Box::new), object.clone())
                    }
                    None => Target::NotFound,
                }
            }
            _ => Target::NotFound,
        })
    }
}

// ---------------------------------------------------------------------------
// Requests

fn status(code: StatusCode) -> Response {
    code.into_response()
}

pub(crate) fn xml_response(code: StatusCode, body: String) -> Response {
    let mut response = (code, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    response
}

/// 403 for a write the user's access does not allow (RFC 3744 7.1.1),
/// naming the resource and the privilege it needs.
pub(crate) fn need_privilege(href: &str, privilege: &str) -> Response {
    xml_response(
        StatusCode::FORBIDDEN,
        xml::error(&format!(
            "<d:need-privileges><d:resource>{}<d:privilege><d:{privilege}/></d:privilege></d:resource></d:need-privileges>",
            xml::href(href)
        )),
    )
}

fn options() -> Response {
    let mut response = StatusCode::OK.into_response();
    let headers = response.headers_mut();
    headers.insert(
        "dav",
        HeaderValue::from_static(
            "1, 3, calendar-access, calendar-auto-schedule, addressbook, \
             extended-mkcol, calendarserver-sharing",
        ),
    );
    headers.insert(
        header::ALLOW,
        HeaderValue::from_static(
            "OPTIONS, GET, HEAD, POST, PUT, DELETE, PROPFIND, PROPPATCH, MKCALENDAR, MKCOL, REPORT",
        ),
    );
    response
}

/// The server root serves the webmail app, but DAV clients given only the
/// host name start there: their requests get the DAV root.
async fn server_root(
    app: State<Arc<AppState>>,
    peer: Extension<Peer>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if matches!(method, Method::GET | Method::HEAD) {
        return crate::assets::spa(&app.0.static_dir, "/");
    }
    if !matches!(method.as_str(), "PROPFIND" | "REPORT" | "OPTIONS") {
        return status(StatusCode::METHOD_NOT_ALLOWED);
    }
    handle(app, peer, method, Uri::from_static("/dav/"), headers, body).await
}

async fn handle(
    app: State<Arc<AppState>>,
    Extension(peer): Extension<Peer>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let state = app.0;
    // Clients probe with OPTIONS before signing in.
    if method == Method::OPTIONS {
        return options();
    }
    // Writes from a browser on another site never reach authentication.
    if !matches!(method, Method::GET | Method::HEAD) && jmap::from_another_site(&headers) {
        return jmap::cross_site_refusal();
    }
    let user = match jmap::authenticate(&state, &headers, &peer).await {
        Ok(user) => user,
        Err(response) => return *response,
    };
    let Some(segments) = segments(uri.path()) else {
        return status(StatusCode::NOT_FOUND);
    };
    let app = state.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let state = app;
        let conn =
            rmail_common::jmap::store::open(&state.mail_root, &user.domain, &user.localpart)?;
        let dav = Dav {
            user,
            conn,
            app: state,
        };
        let target = dav.resolve(&segments)?;
        Ok::<_, anyhow::Error>(dispatch(&dav, &method, &headers, &body, target))
    })
    .await;
    match outcome {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => jmap::internal_response(format!("{error:#}")),
        Err(error) => jmap::internal_response(error),
    }
}

fn dispatch(
    dav: &Dav,
    method: &Method,
    headers: &HeaderMap,
    body: &[u8],
    target: Target,
) -> Response {
    let depth = headers
        .get("depth")
        .and_then(|value| value.to_str().ok())
        .map(str::trim);
    let result = match method.as_str() {
        "PROPFIND" => props::propfind(dav, target, depth, body),
        "PROPPATCH" => props::proppatch(dav, target, body),
        "REPORT" => report::report(dav, target, depth, body),
        "MKCALENDAR" => make_collection(dav, target, Some(Kind::Calendar), body),
        "MKCOL" => make_collection(dav, target, None, body),
        "GET" | "HEAD" => Ok(get(target, method == Method::HEAD)),
        "PUT" => put(dav, target, headers, body),
        "DELETE" => delete(dav, target, headers),
        "POST" if matches!(target, Target::Collection(_)) => sharing::post(dav, target, body),
        "POST" => schedule::post(dav, target, headers, body),
        _ => Ok(status(StatusCode::METHOD_NOT_ALLOWED)),
    };
    result.unwrap_or_else(|error| jmap::internal_response(format!("{error:#}")))
}

fn content_type(kind: Kind) -> &'static str {
    match kind {
        Kind::Calendar => "text/calendar; charset=utf-8",
        Kind::AddressBook => "text/vcard; charset=utf-8",
    }
}

fn with_etag(mut response: Response, etag: &str) -> Response {
    if let Ok(value) = HeaderValue::from_str(etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

fn get(target: Target, head: bool) -> Response {
    let Target::Object(place, Some(object), _) = target else {
        return match target {
            Target::NotFound | Target::NewCollection(..) | Target::Object(_, None, _) => {
                status(StatusCode::NOT_FOUND)
            }
            _ => status(StatusCode::METHOD_NOT_ALLOWED),
        };
    };
    let body = if head {
        String::new()
    } else {
        object.data.clone()
    };
    let mut response = with_etag((StatusCode::OK, body).into_response(), &object.etag);
    with_schedule_tag(&mut response, object.schedule_tag.as_deref());
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type(place.collection.kind)),
    );
    if head && let Ok(length) = HeaderValue::from_str(&object.data.len().to_string()) {
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, length);
    }
    response
}

fn with_schedule_tag(response: &mut Response, tag: Option<&str>) {
    if let Some(value) = tag.and_then(|tag| HeaderValue::from_str(tag).ok()) {
        response.headers_mut().insert("schedule-tag", value);
    }
}

/// `If-Match`/`If-None-Match` against the current ETag (RFC 9110 13.1) and
/// `If-Schedule-Tag-Match` against its schedule tag (RFC 6638 8.3).
fn preconditions_fail(headers: &HeaderMap, current: Option<&Object>) -> bool {
    let text = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    let matches = |list: &str, tag: Option<&str>| {
        list.split(',')
            .map(str::trim)
            .any(|wanted| wanted == "*" && current.is_some() || Some(wanted) == tag)
    };
    let etag = current.map(|object| object.etag.as_str());
    if let Some(list) = text("if-match")
        && !matches(list, etag)
    {
        return true;
    }
    if let Some(list) = text("if-none-match")
        && matches(list, etag)
    {
        return true;
    }
    if let Some(list) = text("if-schedule-tag-match") {
        let tag = current.and_then(|object| object.schedule_tag.as_deref());
        if tag.is_none() || !matches(list, tag) {
            return true;
        }
    }
    false
}

fn put(dav: &Dav, target: Target, headers: &HeaderMap, body: &[u8]) -> anyhow::Result<Response> {
    let Target::Object(place, existing, name) = target else {
        return Ok(status(match target {
            Target::NotFound => StatusCode::CONFLICT,
            _ => StatusCode::METHOD_NOT_ALLOWED,
        }));
    };
    let collection = &place.collection;
    if collection.inbox {
        // Only the server delivers to the inbox (RFC 6638 2.2).
        return Ok(status(StatusCode::FORBIDDEN));
    }
    if !place.writable() {
        // Changing an object needs write-content on it, adding one bind on
        // the collection (RFC 3744 3.3, 3.9).
        return Ok(match existing {
            Some(_) => need_privilege(&object_href(&dav.user, &place, &name), "write-content"),
            None => need_privilege(&collection_href(&dav.user, &place), "bind"),
        });
    }
    let prefix = match collection.kind {
        Kind::Calendar => "c",
        Kind::AddressBook => "card",
    };
    if body.len() > MAX_RESOURCE_SIZE {
        return Ok(xml_response(
            StatusCode::FORBIDDEN,
            xml::error(&format!("<{prefix}:max-resource-size/>")),
        ));
    }
    let valid = match collection.kind {
        Kind::Calendar => "c:valid-calendar-data",
        Kind::AddressBook => "card:valid-address-data",
    };
    let Ok(text) = std::str::from_utf8(body) else {
        return Ok(xml_response(
            StatusCode::FORBIDDEN,
            xml::error(&format!("<{valid}/>")),
        ));
    };
    let conn = dav.conn_of(&place);
    // The preconditions are checked against the object as it is inside the
    // store's write transaction, so concurrent writers cannot both pass;
    // scheduling compares against that same version.
    let mut outgoing = Vec::new();
    let mut prepare = |current: Option<&Object>| {
        if preconditions_fail(headers, current) {
            return Err(PutError::PreconditionFailed);
        }
        if collection.kind != Kind::Calendar {
            return Ok(store::Prepared {
                data: text.to_string(),
                schedule_tag: store::ScheduleTag::None,
            });
        }
        let (prepared, messages) = schedule::prepare_put(dav, place.owner(dav), current, text);
        outgoing = messages;
        Ok(prepared)
    };
    match store::put_with(conn, collection, &name, &mut prepare)? {
        Ok(stored) => {
            schedule::deliver(dav, outgoing);
            let mut response = status(if stored.created {
                StatusCode::CREATED
            } else {
                StatusCode::NO_CONTENT
            });
            with_schedule_tag(&mut response, stored.schedule_tag.as_deref());
            // An ETag only when the object is stored as sent (RFC 4791
            // 5.3.4); scheduling may have added statuses.
            let as_sent = store::object(conn, collection, &name)?
                .is_some_and(|object| object.etag == stored.etag && object.data == text);
            Ok(if as_sent {
                with_etag(response, &stored.etag)
            } else {
                response
            })
        }
        Err(PutError::InvalidData(_)) => Ok(xml_response(
            StatusCode::FORBIDDEN,
            xml::error(&format!("<{valid}/>")),
        )),
        Err(PutError::UnsupportedComponent) => Ok(xml_response(
            StatusCode::FORBIDDEN,
            xml::error("<c:supported-calendar-component/>"),
        )),
        Err(PutError::PreconditionFailed) => Ok(status(StatusCode::PRECONDITION_FAILED)),
        Err(PutError::UidConflict(other)) => Ok(xml_response(
            StatusCode::FORBIDDEN,
            xml::error(&format!(
                "<{prefix}:no-uid-conflict>{}</{prefix}:no-uid-conflict>",
                xml::href(&object_href(&dav.user, &place, &other))
            )),
        )),
    }
}

fn delete(dav: &Dav, target: Target, headers: &HeaderMap) -> anyhow::Result<Response> {
    match target {
        Target::Object(place, Some(_), _) if !place.writable() => Ok(need_privilege(
            &collection_href(&dav.user, &place),
            "unbind",
        )),
        Target::Object(place, Some(_), name) => {
            let collection = &place.collection;
            let precondition = |current: Option<&Object>| !preconditions_fail(headers, current);
            Ok(status(
                match store::delete(dav.conn_of(&place), collection, &name, &precondition)? {
                    store::Deleted::Deleted(previous) => {
                        // RFC 6638 8.1: `Schedule-Reply: F` deletes quietly.
                        let quiet = headers
                            .get("schedule-reply")
                            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"F"));
                        if collection.kind == Kind::Calendar && !collection.inbox && !quiet {
                            let messages =
                                schedule::prepare_delete(dav, place.owner(dav), &previous);
                            schedule::deliver(dav, messages);
                        }
                        StatusCode::NO_CONTENT
                    }
                    store::Deleted::NotFound => StatusCode::NOT_FOUND,
                    store::Deleted::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
                },
            ))
        }
        Target::Collection(place) if place.collection.inbox => Ok(status(StatusCode::FORBIDDEN)),
        Target::Collection(Place {
            collection,
            share: Some(share),
        }) => {
            // A sharee deleting a shared collection only leaves it; the
            // owner's collection stays (as with CalendarServer sharing).
            share::delete(
                &dav.app.db_path,
                &share.owner.address,
                collection.id,
                &dav.user.address,
            )?;
            Ok(status(StatusCode::NO_CONTENT))
        }
        Target::Collection(Place { collection, .. }) => {
            store::delete_collection(&dav.conn, &collection)?;
            share::forget_collection(&dav.app.db_path, &dav.user.address, collection.id)?;
            Ok(status(StatusCode::NO_CONTENT))
        }
        Target::Object(_, None, _) | Target::NotFound | Target::NewCollection(..) => {
            Ok(status(StatusCode::NOT_FOUND))
        }
        _ => Ok(status(StatusCode::FORBIDDEN)),
    }
}

/// MKCALENDAR (RFC 4791 5.3.1) and extended MKCOL (RFC 5689): create a
/// collection in a home, applying the properties of the body.
fn make_collection(
    dav: &Dav,
    target: Target,
    forced: Option<Kind>,
    body: &[u8],
) -> anyhow::Result<Response> {
    let (home_kind, name) = match target {
        Target::NewCollection(kind, name) => (kind, name),
        Target::Collection(_) => return Ok(status(StatusCode::METHOD_NOT_ALLOWED)),
        _ => return Ok(status(StatusCode::FORBIDDEN)),
    };
    let Ok(document) = xml::parse(body) else {
        return Ok(status(StatusCode::BAD_REQUEST));
    };
    let prop = document.as_ref().and_then(|document| {
        let root = document.root_element();
        xml::child(root, xml::DAV, "set").and_then(|set| xml::child(set, xml::DAV, "prop"))
    });
    // The resource type an extended MKCOL asks for, else the home's kind.
    let requested = prop
        .and_then(|prop| xml::child(prop, xml::DAV, "resourcetype"))
        .map(|types| {
            if xml::child(types, xml::CALDAV, "calendar").is_some() {
                Some(Kind::Calendar)
            } else if xml::child(types, xml::CARDDAV, "addressbook").is_some() {
                Some(Kind::AddressBook)
            } else {
                None
            }
        });
    let kind = forced.or(requested.flatten()).unwrap_or(home_kind);
    if kind != home_kind || matches!(requested, Some(None)) {
        // Calendars live in the calendar home, address books in theirs;
        // plain collections are not offered.
        return Ok(xml_response(
            StatusCode::FORBIDDEN,
            xml::error("<d:valid-resourcetype/>"),
        ));
    }
    // `inbox` and `outbox` are the scheduling collections; names with an
    // `@` are kept for shared collections (see `binding_segment`).
    if !store::valid_name(&name)
        || name.contains('@')
        || kind == Kind::Calendar && matches!(name.as_str(), "inbox" | "outbox")
    {
        return Ok(status(StatusCode::FORBIDDEN));
    }
    let components = prop
        .and_then(|prop| xml::child(prop, xml::CALDAV, "supported-calendar-component-set"))
        .map(|set| {
            xml::children(set, xml::CALDAV, "comp")
                .filter_map(|comp| comp.attribute("name"))
                .map(str::to_ascii_uppercase)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| match kind {
            Kind::Calendar => vec!["VEVENT".to_string(), "VTODO".to_string()],
            Kind::AddressBook => Vec::new(),
        });
    let components = components.iter().map(String::as_str).collect::<Vec<_>>();
    let collection = store::create(&dav.conn, kind, &name, None, &components)?;
    if let Some(prop) = prop {
        for element in prop.children().filter(|node| node.is_element()) {
            if let Some(setting) = props::setting(element) {
                let value = element.text().map(str::to_string);
                store::set_property(&dav.conn, &collection, setting, value.as_deref())?;
            }
        }
    }
    let mut response = status(StatusCode::CREATED);
    if let Ok(location) = HeaderValue::from_str(&own_collection_href(&dav.user, &collection)) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    Ok(response)
}

#[cfg(test)]
mod path_tests {
    use super::*;

    #[test]
    fn binding_segments_name_the_owner_and_collection() {
        let segment = binding_segment("team+cal@example.test", "work~2026");
        assert_eq!(segment, "team+cal@example.test~work~2026");
        assert_eq!(
            parse_binding(&segment),
            Some(("team+cal@example.test", "work~2026"))
        );
        assert_eq!(parse_binding("default"), None);
        assert_eq!(parse_binding("a@example.test"), None);
        assert_eq!(parse_binding("a@example.test~"), None);
        assert_eq!(parse_binding("@~x"), None);
        assert_eq!(parse_binding("a@~x"), None);
    }
}
