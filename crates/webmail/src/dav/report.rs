//! REPORT: calendar-query and calendar-multiget (RFC 4791 7.8, 7.9),
//! addressbook-query and addressbook-multiget (RFC 6352 8.6, 8.7), and
//! sync-collection (RFC 6578).

use axum::http::StatusCode;
use axum::response::Response;
use rmail_common::dav::store::{self, Change, Collection, Kind, Object};
use rmail_common::dav::text::{self, Component, Property};

use super::props::{self, Resource, Wanted};
use super::xml::{self, CALDAV, CARDDAV, DAV};
use super::{Dav, Target, href_segments, object_href, xml_response};

pub(crate) fn report(
    dav: &Dav,
    target: Target,
    depth: Option<&str>,
    body: &[u8],
) -> anyhow::Result<Response> {
    let Ok(Some(document)) = xml::parse(body) else {
        return Ok(super::status(StatusCode::BAD_REQUEST));
    };
    let root = document.root_element();
    let wanted = props::wanted(Some(root));
    if xml::is(root, CALDAV, "calendar-multiget") || xml::is(root, CARDDAV, "addressbook-multiget")
    {
        return multiget(dav, root, &wanted);
    }
    let query = if xml::is(root, CALDAV, "calendar-query") {
        Some(Kind::Calendar)
    } else if xml::is(root, CARDDAV, "addressbook-query") {
        Some(Kind::AddressBook)
    } else {
        None
    };
    if let Some(kind) = query {
        // A query runs over a collection (Depth 1) or one object (Depth 0).
        let (collection, objects) = match target {
            Target::Collection(collection) if collection.kind == kind => {
                let objects = if depth == Some("0") {
                    Vec::new()
                } else {
                    store::objects(&dav.conn, &collection)?
                };
                (collection, objects)
            }
            Target::Object(collection, Some(object), _) if collection.kind == kind => {
                (collection, vec![*object])
            }
            Target::NotFound | Target::Object(_, None, _) | Target::NewCollection(..) => {
                return Ok(super::status(StatusCode::NOT_FOUND));
            }
            _ => return Ok(super::status(StatusCode::FORBIDDEN)),
        };
        let filter = match kind {
            Kind::Calendar => xml::child(root, CALDAV, "filter"),
            Kind::AddressBook => xml::child(root, CARDDAV, "filter"),
        };
        let limit = xml::child(root, CARDDAV, "limit")
            .and_then(|limit| xml::child(limit, CARDDAV, "nresults"))
            .and_then(|count| count.text())
            .and_then(|count| count.trim().parse::<usize>().ok());
        let mut responses = Vec::new();
        for object in &objects {
            let Ok(parsed) = text::parse(&object.data) else {
                continue;
            };
            let matched = match (kind, filter) {
                (_, None) => true,
                (Kind::Calendar, Some(filter)) => calendar_filter(filter, &parsed, object),
                (Kind::AddressBook, Some(filter)) => card_filter(filter, &parsed),
            };
            if matched {
                if limit.is_some_and(|limit| responses.len() >= limit) {
                    break;
                }
                responses.push(props::describe(
                    dav,
                    &Resource::Object(&collection, object),
                    &wanted,
                ));
            }
        }
        return Ok(xml_response(
            StatusCode::MULTI_STATUS,
            xml::multistatus(&responses, None),
        ));
    }
    if xml::is(root, DAV, "sync-collection") {
        let Target::Collection(collection) = target else {
            return Ok(super::status(StatusCode::FORBIDDEN));
        };
        return sync(dav, root, &collection, &wanted);
    }
    Ok(xml_response(
        StatusCode::FORBIDDEN,
        xml::error("<d:supported-report/>"),
    ))
}

fn multiget(dav: &Dav, root: roxmltree::Node<'_, '_>, wanted: &Wanted) -> anyhow::Result<Response> {
    let mut responses = Vec::new();
    for href in xml::children(root, DAV, "href") {
        let text = href.text().unwrap_or_default().trim().to_string();
        let found = match href_segments(&text) {
            Some(segments) => match dav.resolve(&segments)? {
                Target::Object(collection, Some(object), _) => Some((collection, object)),
                _ => None,
            },
            None => None,
        };
        match found {
            Some((collection, object)) => responses.push(props::describe(
                dav,
                &Resource::Object(&collection, &object),
                wanted,
            )),
            None => {
                let mut missing = xml::Response::new(&text);
                missing.status = Some(404);
                responses.push(missing);
            }
        }
    }
    Ok(xml_response(
        StatusCode::MULTI_STATUS,
        xml::multistatus(&responses, None),
    ))
}

fn sync(
    dav: &Dav,
    root: roxmltree::Node<'_, '_>,
    collection: &Collection,
    wanted: &Wanted,
) -> anyhow::Result<Response> {
    let token = xml::child(root, DAV, "sync-token")
        .and_then(|token| token.text())
        .map(str::trim)
        .unwrap_or_default();
    let since = if token.is_empty() {
        Some(0)
    } else {
        store::parse_sync_token(collection, token)
    };
    let invalid = || xml_response(StatusCode::FORBIDDEN, xml::error("<d:valid-sync-token/>"));
    let Some(since) = since else {
        return Ok(invalid());
    };
    let Some(changes) = store::changes_since(&dav.conn, collection, since)? else {
        return Ok(invalid());
    };
    let mut responses = Vec::new();
    for change in changes {
        match change {
            Change::Changed(object) => responses.push(props::describe(
                dav,
                &Resource::Object(collection, &object),
                wanted,
            )),
            Change::Deleted(name) => {
                let mut gone = xml::Response::new(&object_href(&dav.user, collection, &name));
                gone.status = Some(404);
                responses.push(gone);
            }
        }
    }
    Ok(xml_response(
        StatusCode::MULTI_STATUS,
        xml::multistatus(&responses, Some(&collection.sync_token())),
    ))
}

// ---------------------------------------------------------------------------
// Filters

/// `text-match` (RFC 4791 9.7.5, RFC 6352 10.5.4): case-insensitive unless
/// the collation is `i;octet`; `contains` unless a CardDAV `match-type`
/// says otherwise.
fn text_match(node: roxmltree::Node<'_, '_>, value: &str) -> bool {
    let needle = node.text().unwrap_or_default();
    let exact = node.attribute("collation") == Some("i;octet");
    let (needle, value) = if exact {
        (needle.to_string(), value.to_string())
    } else {
        (needle.to_lowercase(), value.to_lowercase())
    };
    let matched = match node.attribute("match-type").unwrap_or("contains") {
        "equals" => value == needle,
        "starts-with" => value.starts_with(&needle),
        "ends-with" => value.ends_with(&needle),
        _ => value.contains(&needle),
    };
    let negate = node.attribute("negate-condition") == Some("yes");
    matched != negate
}

fn parse_time(value: Option<&str>) -> Option<i64> {
    let value = value?.trim().trim_end_matches('Z');
    chrono::NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%S")
        .ok()
        .map(|time| time.and_utc().timestamp())
}

/// Whether the object's span overlaps `time-range` (RFC 4791 9.9).
fn in_range(range: roxmltree::Node<'_, '_>, object: &Object) -> bool {
    let start = parse_time(range.attribute("start")).unwrap_or(i64::MIN);
    let end = parse_time(range.attribute("end")).unwrap_or(i64::MAX);
    let begins_before_end = object.start.is_none_or(|begin| begin < end);
    let ends_after_start = object
        .end
        .is_none_or(|finish| finish > start || object.start == Some(finish) && finish >= start);
    begins_before_end && ends_after_start
}

/// A calendar `prop-filter` against the properties of one component.
fn calendar_prop_filter(filter: roxmltree::Node<'_, '_>, component: &Component) -> bool {
    let name = filter.attribute("name").unwrap_or_default();
    let properties = component.properties_named(name).collect::<Vec<&Property>>();
    if xml::child(filter, CALDAV, "is-not-defined").is_some() {
        return properties.is_empty();
    }
    if properties.is_empty() {
        return false;
    }
    let text_ok = xml::child(filter, CALDAV, "text-match")
        .is_none_or(|matcher| properties.iter().any(|p| text_match(matcher, &p.value)));
    let params_ok = xml::children(filter, CALDAV, "param-filter").all(|param| {
        let name = param.attribute("name").unwrap_or_default();
        let values = properties
            .iter()
            .filter_map(|p| p.param(name))
            .collect::<Vec<_>>();
        if xml::child(param, CALDAV, "is-not-defined").is_some() {
            values.is_empty()
        } else {
            !values.is_empty()
                && xml::child(param, CALDAV, "text-match")
                    .is_none_or(|matcher| values.iter().any(|value| text_match(matcher, value)))
        }
    });
    text_ok && params_ok
}

/// A `comp-filter` against `component`, whose name already matched.
/// `top` is true for the object's main components (VEVENT, VTODO), whose
/// time span comes from the stored bounds.
fn comp_filter(
    filter: roxmltree::Node<'_, '_>,
    component: &Component,
    object: &Object,
    top: bool,
) -> bool {
    if let Some(range) = xml::child(filter, CALDAV, "time-range")
        && top
        && !in_range(range, object)
    {
        return false;
    }
    if !xml::children(filter, CALDAV, "prop-filter")
        .all(|prop| calendar_prop_filter(prop, component))
    {
        return false;
    }
    xml::children(filter, CALDAV, "comp-filter").all(|child| {
        let name = child.attribute("name").unwrap_or_default();
        let mut matching = component
            .components
            .iter()
            .filter(|sub| sub.name.eq_ignore_ascii_case(name));
        if xml::child(child, CALDAV, "is-not-defined").is_some() {
            matching.next().is_none()
        } else {
            let main = component.name == "VCALENDAR";
            matching.any(|sub| comp_filter(child, sub, object, main))
        }
    })
}

fn calendar_filter(filter: roxmltree::Node<'_, '_>, calendar: &Component, object: &Object) -> bool {
    xml::children(filter, CALDAV, "comp-filter").all(|top| {
        top.attribute("name")
            .is_some_and(|name| name.eq_ignore_ascii_case(&calendar.name))
            && comp_filter(top, calendar, object, false)
    })
}

/// An address book `filter` (RFC 6352 10.5): `anyof` (default) or `allof`
/// over its `prop-filter`s.
fn card_filter(filter: roxmltree::Node<'_, '_>, card: &Component) -> bool {
    let all = filter.attribute("test") == Some("allof");
    let mut results =
        xml::children(filter, CARDDAV, "prop-filter").map(|prop| card_prop_filter(prop, card));
    if all {
        results.all(|matched| matched)
    } else {
        // No prop-filter at all matches everything.
        let results = results.collect::<Vec<_>>();
        results.is_empty() || results.into_iter().any(|matched| matched)
    }
}

fn card_prop_filter(filter: roxmltree::Node<'_, '_>, card: &Component) -> bool {
    let name = filter.attribute("name").unwrap_or_default();
    let properties = card.properties_named(name).collect::<Vec<&Property>>();
    if xml::child(filter, CARDDAV, "is-not-defined").is_some() {
        return properties.is_empty();
    }
    if properties.is_empty() {
        return false;
    }
    let all = filter.attribute("test") == Some("allof");
    let mut tests = Vec::new();
    for matcher in xml::children(filter, CARDDAV, "text-match") {
        tests.push(properties.iter().any(|p| text_match(matcher, &p.value)));
    }
    for param in xml::children(filter, CARDDAV, "param-filter") {
        let param_name = param.attribute("name").unwrap_or_default();
        let values = properties
            .iter()
            .filter_map(|p| p.param(param_name))
            .collect::<Vec<_>>();
        tests.push(if xml::child(param, CARDDAV, "is-not-defined").is_some() {
            values.is_empty()
        } else {
            !values.is_empty()
                && xml::child(param, CARDDAV, "text-match")
                    .is_none_or(|matcher| values.iter().any(|value| text_match(matcher, value)))
        });
    }
    if tests.is_empty() {
        return true;
    }
    if all {
        tests.into_iter().all(|ok| ok)
    } else {
        tests.into_iter().any(|ok| ok)
    }
}
