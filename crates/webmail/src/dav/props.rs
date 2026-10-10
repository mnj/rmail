//! PROPFIND and PROPPATCH (RFC 4918 9.1, 9.2) and the properties of each
//! resource.

use axum::http::StatusCode;
use axum::response::Response;
use rmail_common::dav::store::{self, Collection, Kind, Object, Setting};

use super::xml::{self, APPLE, CALDAV, CALSERVER, CARDDAV, DAV, Name};
use super::{
    Dav, MAX_RESOURCE_SIZE, Target, collection_href, home_href, object_href, outbox_href,
    principal_href, xml_response,
};

/// What PROPFIND `allprop` reports (RFC 4918 9.1: the live properties of
/// RFC 4918; CalDAV/CardDAV data is never included).
const ALLPROP: &[(&str, &str)] = &[
    (DAV, "resourcetype"),
    (DAV, "displayname"),
    (DAV, "getetag"),
    (DAV, "getcontenttype"),
    (DAV, "getcontentlength"),
    (DAV, "getlastmodified"),
];

/// A resource being described.
pub(crate) enum Resource<'a> {
    Root,
    Principals,
    Principal,
    Home(Kind),
    Collection(&'a Collection),
    Outbox,
    Object(&'a Collection, &'a Object),
}

impl Resource<'_> {
    pub fn href(&self, dav: &Dav) -> String {
        match self {
            Resource::Root => "/dav/".to_string(),
            Resource::Principals => "/dav/principals/".to_string(),
            Resource::Principal => principal_href(&dav.user),
            Resource::Home(kind) => home_href(&dav.user, *kind),
            Resource::Collection(collection) => collection_href(&dav.user, collection),
            Resource::Outbox => outbox_href(&dav.user),
            Resource::Object(collection, object) => {
                object_href(&dav.user, collection, &object.name)
            }
        }
    }
}

fn hrefs(list: &[String]) -> String {
    list.iter().map(|href| xml::href(href)).collect()
}

fn privileges() -> String {
    [
        "read",
        "write",
        "write-properties",
        "write-content",
        "bind",
        "unbind",
        "read-current-user-privilege-set",
    ]
    .iter()
    .map(|privilege| format!("<d:privilege><d:{privilege}/></d:privilege>"))
    .collect()
}

fn http_date(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .unwrap_or_default()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

/// The value of property `name` on `resource` as inner XML (`Some("")`
/// for an empty element), or `None` when the resource has no such
/// property.
pub(crate) fn value(dav: &Dav, resource: &Resource<'_>, name: &Name) -> Option<String> {
    let (ns, local) = (name.0.as_str(), name.1.as_str());
    let principal = principal_href(&dav.user);
    // Properties every resource has.
    match (ns, local) {
        (DAV, "current-user-principal") => return Some(xml::href(&principal)),
        (DAV, "current-user-privilege-set") => return Some(privileges()),
        (DAV, "principal-collection-set") => return Some(xml::href("/dav/principals/")),
        _ => {}
    }
    match resource {
        Resource::Root | Resource::Principals => match (ns, local) {
            (DAV, "resourcetype") => Some("<d:collection/>".to_string()),
            (DAV, "displayname") => Some("rMail".to_string()),
            _ => None,
        },
        Resource::Principal => match (ns, local) {
            (DAV, "resourcetype") => Some("<d:principal/>".to_string()),
            (DAV, "displayname") => Some(xml::escape(&dav.user.address)),
            (DAV, "principal-URL") => Some(xml::href(&principal)),
            (CALDAV, "calendar-home-set") => Some(xml::href(&home_href(&dav.user, Kind::Calendar))),
            (CARDDAV, "addressbook-home-set") => {
                Some(xml::href(&home_href(&dav.user, Kind::AddressBook)))
            }
            (CALDAV, "calendar-user-address-set") => {
                Some(hrefs(&[format!("mailto:{}", dav.user.address), principal]))
            }
            (CALDAV, "calendar-user-type") => Some("INDIVIDUAL".to_string()),
            (CALDAV, "schedule-inbox-URL") => Some(xml::href(&format!(
                "{}inbox/",
                home_href(&dav.user, Kind::Calendar)
            ))),
            (CALDAV, "schedule-outbox-URL") => Some(xml::href(&outbox_href(&dav.user))),
            _ => None,
        },
        Resource::Outbox => match (ns, local) {
            (DAV, "resourcetype") => Some("<d:collection/><c:schedule-outbox/>".to_string()),
            (DAV, "displayname") => Some("Outbox".to_string()),
            (DAV, "owner") => Some(xml::href(&principal)),
            _ => None,
        },
        Resource::Home(_) => match (ns, local) {
            (DAV, "resourcetype") => Some("<d:collection/>".to_string()),
            (DAV, "owner") => Some(xml::href(&principal)),
            _ => None,
        },
        Resource::Collection(collection) => {
            let calendar = collection.kind == Kind::Calendar;
            match (ns, local) {
                (DAV, "resourcetype") if collection.inbox => {
                    Some("<d:collection/><c:schedule-inbox/>".to_string())
                }
                (CALDAV, "schedule-default-calendar-URL") if collection.inbox => {
                    let default = store::default_calendar(&dav.conn).ok()?;
                    Some(xml::href(&collection_href(&dav.user, &default)))
                }
                (CALDAV, "schedule-calendar-transp") if calendar && !collection.inbox => {
                    Some("<c:opaque/>".to_string())
                }
                (DAV, "resourcetype") => Some(if calendar {
                    "<d:collection/><c:calendar/>".to_string()
                } else {
                    "<d:collection/><card:addressbook/>".to_string()
                }),
                (DAV, "displayname") => collection.displayname.as_deref().map(xml::escape),
                (DAV, "owner") => Some(xml::href(&principal)),
                (DAV, "sync-token") => Some(xml::escape(&collection.sync_token())),
                (CALSERVER, "getctag") => Some(collection.sync_seq.to_string()),
                (DAV, "supported-report-set") => {
                    let reports = if calendar {
                        ["sync-collection", "c:calendar-query", "c:calendar-multiget"]
                    } else {
                        [
                            "sync-collection",
                            "card:addressbook-query",
                            "card:addressbook-multiget",
                        ]
                    };
                    Some(
                        reports
                            .iter()
                            .map(|report| {
                                let report = if report.contains(':') {
                                    report.to_string()
                                } else {
                                    format!("d:{report}")
                                };
                                format!(
                                    "<d:supported-report><d:report><{report}/></d:report></d:supported-report>"
                                )
                            })
                            .collect(),
                    )
                }
                (CALDAV, "calendar-description") if calendar => {
                    collection.description.as_deref().map(xml::escape)
                }
                (CARDDAV, "addressbook-description") if !calendar => {
                    collection.description.as_deref().map(xml::escape)
                }
                (CALDAV, "calendar-timezone") if calendar => {
                    collection.timezone.as_deref().map(xml::escape)
                }
                (APPLE, "calendar-color") if calendar => {
                    collection.color.as_deref().map(xml::escape)
                }
                (APPLE, "calendar-order") if calendar => {
                    collection.sort_order.as_deref().map(xml::escape)
                }
                (CALDAV, "supported-calendar-component-set") if calendar => Some(
                    collection
                        .components
                        .iter()
                        .map(|component| format!("<c:comp name=\"{}\"/>", xml::escape(component)))
                        .collect(),
                ),
                (CALDAV, "supported-calendar-data") if calendar => Some(
                    "<c:calendar-data content-type=\"text/calendar\" version=\"2.0\"/>".to_string(),
                ),
                (CARDDAV, "supported-address-data") if !calendar => Some(
                    "<card:address-data-type content-type=\"text/vcard\" version=\"3.0\"/>\
                     <card:address-data-type content-type=\"text/vcard\" version=\"4.0\"/>"
                        .to_string(),
                ),
                (CALDAV, "max-resource-size") if calendar => Some(MAX_RESOURCE_SIZE.to_string()),
                (CARDDAV, "max-resource-size") if !calendar => Some(MAX_RESOURCE_SIZE.to_string()),
                _ => None,
            }
        }
        Resource::Object(collection, object) => match (ns, local) {
            (DAV, "resourcetype") => Some(String::new()),
            (DAV, "getetag") => Some(xml::escape(&object.etag)),
            (DAV, "getcontenttype") => Some(
                match collection.kind {
                    Kind::Calendar => "text/calendar; charset=utf-8",
                    Kind::AddressBook => "text/vcard; charset=utf-8",
                }
                .to_string(),
            ),
            (DAV, "getcontentlength") => Some(object.data.len().to_string()),
            (DAV, "getlastmodified") => Some(http_date(object.modified)),
            (CALDAV, "calendar-data") if collection.kind == Kind::Calendar => {
                Some(xml::escape(&object.data))
            }
            (CALDAV, "schedule-tag") => object.schedule_tag.as_deref().map(xml::escape),
            (CARDDAV, "address-data") if collection.kind == Kind::AddressBook => {
                Some(xml::escape(&object.data))
            }
            _ => None,
        },
    }
}

/// What a PROPFIND or REPORT asks for.
pub(crate) enum Wanted {
    All,
    Names,
    Props(Vec<Name>),
}

/// A response for `resource` with the wanted properties.
pub(crate) fn describe(dav: &Dav, resource: &Resource<'_>, wanted: &Wanted) -> xml::Response {
    let mut response = xml::Response::new(&resource.href(dav));
    match wanted {
        Wanted::Props(names) => {
            for name in names {
                match value(dav, resource, name) {
                    Some(inner) => response.add(200, xml::element(name, Some(&inner))),
                    None => response.add(404, xml::element(name, None)),
                }
            }
        }
        Wanted::All | Wanted::Names => {
            for (ns, local) in ALLPROP {
                let name = xml::name(ns, local);
                if let Some(inner) = value(dav, resource, &name) {
                    let inner = matches!(wanted, Wanted::All).then_some(inner);
                    response.add(200, xml::element(&name, inner.as_deref()));
                }
            }
        }
    }
    response
}

/// The `prop`/`allprop`/`propname` of a PROPFIND or REPORT body element.
pub(crate) fn wanted(node: Option<roxmltree::Node<'_, '_>>) -> Wanted {
    let Some(node) = node else {
        return Wanted::All;
    };
    if xml::child(node, DAV, "propname").is_some() {
        return Wanted::Names;
    }
    match xml::child(node, DAV, "prop") {
        Some(prop) => Wanted::Props(xml::names(prop)),
        None => Wanted::All,
    }
}

pub(crate) fn propfind(
    dav: &Dav,
    target: Target,
    depth: Option<&str>,
    body: &[u8],
) -> anyhow::Result<Response> {
    let Ok(document) = xml::parse(body) else {
        return Ok(super::status(StatusCode::BAD_REQUEST));
    };
    let wanted = wanted(document.as_ref().map(|document| document.root_element()));
    let depth = match depth {
        // A missing Depth means infinity (RFC 4918 9.1), but clients that
        // leave it out during discovery want the children; give them those.
        None => 1,
        Some("infinity") => {
            // RFC 4918 9.1: a server may refuse infinite depth.
            return Ok(xml_response(
                StatusCode::FORBIDDEN,
                xml::error("<d:propfind-finite-depth/>"),
            ));
        }
        Some("0") => 0,
        Some("1") => 1,
        Some(_) => return Ok(super::status(StatusCode::BAD_REQUEST)),
    };
    let mut responses = Vec::new();
    match &target {
        Target::Root => {
            responses.push(describe(dav, &Resource::Root, &wanted));
            if depth == 1 {
                responses.push(describe(dav, &Resource::Principals, &wanted));
                responses.push(describe(dav, &Resource::Home(Kind::Calendar), &wanted));
                responses.push(describe(dav, &Resource::Home(Kind::AddressBook), &wanted));
            }
        }
        Target::Principals => {
            responses.push(describe(dav, &Resource::Principals, &wanted));
            if depth == 1 {
                responses.push(describe(dav, &Resource::Principal, &wanted));
            }
        }
        Target::Principal => responses.push(describe(dav, &Resource::Principal, &wanted)),
        Target::Outbox => responses.push(describe(dav, &Resource::Outbox, &wanted)),
        Target::Home(kind) => {
            responses.push(describe(dav, &Resource::Home(*kind), &wanted));
            if depth == 1 {
                for collection in store::collections(&dav.conn, *kind)? {
                    responses.push(describe(dav, &Resource::Collection(&collection), &wanted));
                }
                if *kind == Kind::Calendar {
                    let inbox = store::inbox(&dav.conn)?;
                    responses.push(describe(dav, &Resource::Collection(&inbox), &wanted));
                    responses.push(describe(dav, &Resource::Outbox, &wanted));
                }
            }
        }
        Target::Collection(collection) => {
            responses.push(describe(dav, &Resource::Collection(collection), &wanted));
            if depth == 1 {
                for object in store::objects(&dav.conn, collection)? {
                    responses.push(describe(
                        dav,
                        &Resource::Object(collection, &object),
                        &wanted,
                    ));
                }
            }
        }
        Target::Object(collection, Some(object), _) => {
            responses.push(describe(
                dav,
                &Resource::Object(collection, object),
                &wanted,
            ));
        }
        Target::Object(_, None, _) | Target::NewCollection(..) | Target::NotFound => {
            return Ok(super::status(StatusCode::NOT_FOUND));
        }
    }
    Ok(xml_response(
        StatusCode::MULTI_STATUS,
        xml::multistatus(&responses, None),
    ))
}

/// The collection setting a property element changes, if any.
pub(crate) fn setting(element: roxmltree::Node<'_, '_>) -> Option<Setting> {
    let ns = element.tag_name().namespace()?;
    Some(match (ns, element.tag_name().name()) {
        (DAV, "displayname") => Setting::DisplayName,
        (CALDAV, "calendar-description") | (CARDDAV, "addressbook-description") => {
            Setting::Description
        }
        (APPLE, "calendar-color") => Setting::Color,
        (APPLE, "calendar-order") => Setting::SortOrder,
        (CALDAV, "calendar-timezone") => Setting::Timezone,
        _ => return None,
    })
}

/// PROPPATCH: all changes or none (RFC 4918 9.2).
pub(crate) fn proppatch(dav: &Dav, target: Target, body: &[u8]) -> anyhow::Result<Response> {
    let Target::Collection(collection) = target else {
        return Ok(super::status(match target {
            Target::NotFound | Target::NewCollection(..) | Target::Object(_, None, _) => {
                StatusCode::NOT_FOUND
            }
            _ => StatusCode::FORBIDDEN,
        }));
    };
    if collection.inbox {
        return Ok(super::status(StatusCode::FORBIDDEN));
    }
    let Ok(Some(document)) = xml::parse(body) else {
        return Ok(super::status(StatusCode::BAD_REQUEST));
    };
    let root = document.root_element();
    if !xml::is(root, DAV, "propertyupdate") {
        return Ok(super::status(StatusCode::BAD_REQUEST));
    }
    // (name, setting, value) in document order; set and remove interleave.
    let mut changes = Vec::new();
    let mut refused = Vec::new();
    for operation in root.children().filter(|node| node.is_element()) {
        let remove = xml::is(operation, DAV, "remove");
        if !remove && !xml::is(operation, DAV, "set") {
            continue;
        }
        let Some(prop) = xml::child(operation, DAV, "prop") else {
            continue;
        };
        for element in prop.children().filter(|node| node.is_element()) {
            let name = xml::name(
                element.tag_name().namespace().unwrap_or_default(),
                element.tag_name().name(),
            );
            match setting(element) {
                Some(setting) => {
                    let value = if remove {
                        None
                    } else {
                        Some(element.text().unwrap_or_default().to_string())
                    };
                    changes.push((name, setting, value));
                }
                None => refused.push(name),
            }
        }
    }
    let mut response = xml::Response::new(&collection_href(&dav.user, &collection));
    if refused.is_empty() {
        for (name, setting, value) in &changes {
            store::set_property(&dav.conn, &collection, *setting, value.as_deref())?;
            response.add(200, xml::element(name, None));
        }
    } else {
        for name in refused {
            response.add(403, xml::element(&name, None));
        }
        for (name, _, _) in changes {
            response.add(424, xml::element(&name, None));
        }
    }
    Ok(xml_response(
        StatusCode::MULTI_STATUS,
        xml::multistatus(&[response], None),
    ))
}
