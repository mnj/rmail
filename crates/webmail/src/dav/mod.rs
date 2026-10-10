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
//! - Sharing is not offered.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::{Extension, Router};
use rmail_common::dav::store::{self, Collection, Kind, Object, PutError};
use rmail_common::http::Peer;
use rmail_common::sqlite_pool::SqliteConnection;

use crate::api::AppState;
use crate::jmap::{self, User};

mod props;
mod report;
mod schedule;
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

pub(crate) fn collection_href(user: &User, collection: &Collection) -> String {
    format!(
        "{}{}/",
        home_href(user, collection.kind),
        percent_encode(&collection.name)
    )
}

pub(crate) fn outbox_href(user: &User) -> String {
    format!("{}outbox/", home_href(user, Kind::Calendar))
}

pub(crate) fn object_href(user: &User, collection: &Collection, name: &str) -> String {
    format!(
        "{}{}",
        collection_href(user, collection),
        percent_encode(name)
    )
}

/// What a request path names.
pub(crate) enum Target {
    Root,
    Principals,
    Principal,
    Home(Kind),
    /// A calendar, address book or the schedule inbox.
    Collection(Collection),
    /// The schedule outbox (RFC 6638 2.1), for free-busy queries.
    Outbox,
    /// A collection that does not exist yet (for MKCALENDAR/MKCOL).
    NewCollection(Kind, String),
    /// An object, which may not exist yet (for PUT).
    Object(Collection, Option<Box<Object>>, String),
    NotFound,
}

pub(crate) struct Dav {
    pub user: User,
    pub conn: SqliteConnection,
    pub app: Arc<AppState>,
}

impl Dav {
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
            [home, user] if kind(home).is_some() && own(user) => {
                Target::Home(kind(home).unwrap_or(Kind::Calendar))
            }
            [home, user, name] if home == "calendars" && own(user) && name == "inbox" => {
                Target::Collection(store::inbox(&self.conn)?)
            }
            [home, user, name] if home == "calendars" && own(user) && name == "outbox" => {
                Target::Outbox
            }
            [home, user, name] if kind(home).is_some() && own(user) => {
                let kind = kind(home).unwrap_or(Kind::Calendar);
                match store::collection(&self.conn, kind, name)? {
                    Some(collection) => Target::Collection(collection),
                    None => Target::NewCollection(kind, name.clone()),
                }
            }
            [home, user, name, object] if kind(home).is_some() && own(user) => {
                let kind = kind(home).unwrap_or(Kind::Calendar);
                let collection = if kind == Kind::Calendar && name == "inbox" {
                    Some(store::inbox(&self.conn)?)
                } else {
                    store::collection(&self.conn, kind, name)?
                };
                match collection {
                    Some(collection) => {
                        let found = store::object(&self.conn, &collection, object)?;
                        Target::Object(collection, found.map(Box::new), object.clone())
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

fn options() -> Response {
    let mut response = StatusCode::OK.into_response();
    let headers = response.headers_mut();
    headers.insert(
        "dav",
        HeaderValue::from_static(
            "1, 3, calendar-access, calendar-auto-schedule, addressbook, extended-mkcol",
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
    let Target::Object(collection, Some(object), _) = target else {
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
        HeaderValue::from_static(content_type(collection.kind)),
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
    let Target::Object(collection, _, name) = target else {
        return Ok(status(match target {
            Target::NotFound => StatusCode::CONFLICT,
            _ => StatusCode::METHOD_NOT_ALLOWED,
        }));
    };
    if collection.inbox {
        // Only the server delivers to the inbox (RFC 6638 2.2).
        return Ok(status(StatusCode::FORBIDDEN));
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
        let (prepared, messages) = schedule::prepare_put(dav, current, text);
        outgoing = messages;
        Ok(prepared)
    };
    match store::put_with(&dav.conn, &collection, &name, &mut prepare)? {
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
            let as_sent = store::object(&dav.conn, &collection, &name)?
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
                xml::href(&object_href(&dav.user, &collection, &other))
            )),
        )),
    }
}

fn delete(dav: &Dav, target: Target, headers: &HeaderMap) -> anyhow::Result<Response> {
    match target {
        Target::Object(collection, Some(_), name) => {
            let precondition = |current: Option<&Object>| !preconditions_fail(headers, current);
            Ok(status(
                match store::delete(&dav.conn, &collection, &name, &precondition)? {
                    store::Deleted::Deleted(previous) => {
                        // RFC 6638 8.1: `Schedule-Reply: F` deletes quietly.
                        let quiet = headers
                            .get("schedule-reply")
                            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"F"));
                        if collection.kind == Kind::Calendar && !collection.inbox && !quiet {
                            let messages = schedule::prepare_delete(dav, &previous);
                            schedule::deliver(dav, messages);
                        }
                        StatusCode::NO_CONTENT
                    }
                    store::Deleted::NotFound => StatusCode::NOT_FOUND,
                    store::Deleted::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
                },
            ))
        }
        Target::Collection(collection) if collection.inbox => Ok(status(StatusCode::FORBIDDEN)),
        Target::Collection(collection) => {
            store::delete_collection(&dav.conn, &collection)?;
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
    if !store::valid_name(&name)
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
    if let Ok(location) = HeaderValue::from_str(&collection_href(&dav.user, &collection)) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    Ok(response)
}
