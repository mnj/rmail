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
//! - Scheduling (RFC 6638) and sharing are not offered.

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
    Collection(Collection),
    /// A collection that does not exist yet (for MKCALENDAR/MKCOL).
    NewCollection(Kind, String),
    /// An object, which may not exist yet (for PUT).
    Object(Collection, Option<Object>, String),
    NotFound,
}

pub(crate) struct Dav {
    pub user: User,
    pub conn: SqliteConnection,
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
            [home, user, name] if kind(home).is_some() && own(user) => {
                let kind = kind(home).unwrap_or(Kind::Calendar);
                match store::collection(&self.conn, kind, name)? {
                    Some(collection) => Target::Collection(collection),
                    None => Target::NewCollection(kind, name.clone()),
                }
            }
            [home, user, name, object] if kind(home).is_some() && own(user) => {
                let kind = kind(home).unwrap_or(Kind::Calendar);
                match store::collection(&self.conn, kind, name)? {
                    Some(collection) => {
                        let found = store::object(&self.conn, &collection, object)?;
                        Target::Object(collection, found, object.clone())
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
        HeaderValue::from_static("1, 3, calendar-access, addressbook, extended-mkcol"),
    );
    headers.insert(
        header::ALLOW,
        HeaderValue::from_static(
            "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCALENDAR, MKCOL, REPORT",
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
    let outcome = tokio::task::spawn_blocking(move || {
        let conn =
            rmail_common::jmap::store::open(&state.mail_root, &user.domain, &user.localpart)?;
        let dav = Dav { user, conn };
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

/// `If-Match`/`If-None-Match` against the current ETag (RFC 9110 13.1).
fn preconditions_fail(headers: &HeaderMap, current: Option<&str>) -> bool {
    let text = |name: header::HeaderName| headers.get(name).and_then(|value| value.to_str().ok());
    let matches = |list: &str| {
        list.split(',')
            .map(str::trim)
            .any(|tag| tag == "*" && current.is_some() || Some(tag) == current)
    };
    if let Some(list) = text(header::IF_MATCH)
        && !matches(list)
    {
        return true;
    }
    if let Some(list) = text(header::IF_NONE_MATCH)
        && matches(list)
    {
        return true;
    }
    false
}

fn put(dav: &Dav, target: Target, headers: &HeaderMap, body: &[u8]) -> anyhow::Result<Response> {
    let Target::Object(collection, existing, name) = target else {
        return Ok(status(match target {
            Target::NotFound => StatusCode::CONFLICT,
            _ => StatusCode::METHOD_NOT_ALLOWED,
        }));
    };
    if preconditions_fail(
        headers,
        existing.as_ref().map(|object| object.etag.as_str()),
    ) {
        return Ok(status(StatusCode::PRECONDITION_FAILED));
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
    match store::put(&dav.conn, &collection, &name, text)? {
        Ok((etag, created)) => Ok(with_etag(
            status(if created {
                StatusCode::CREATED
            } else {
                StatusCode::NO_CONTENT
            }),
            &etag,
        )),
        Err(PutError::InvalidData(_)) => Ok(xml_response(
            StatusCode::FORBIDDEN,
            xml::error(&format!("<{valid}/>")),
        )),
        Err(PutError::UnsupportedComponent) => Ok(xml_response(
            StatusCode::FORBIDDEN,
            xml::error("<c:supported-calendar-component/>"),
        )),
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
        Target::Object(collection, Some(object), name) => {
            if preconditions_fail(headers, Some(&object.etag)) {
                return Ok(status(StatusCode::PRECONDITION_FAILED));
            }
            store::delete(&dav.conn, &collection, &name)?;
            Ok(status(StatusCode::NO_CONTENT))
        }
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
    if !store::valid_name(&name) {
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
