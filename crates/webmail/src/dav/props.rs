//! PROPFIND and PROPPATCH (RFC 4918 9.1, 9.2) and the properties of each
//! resource.

use axum::http::StatusCode;
use axum::response::Response;
use rmail_common::dav::share::{self, Access};
use rmail_common::dav::store::{self, Kind, Object, Setting};

use super::xml::{self, APPLE, CALDAV, CALSERVER, CARDDAV, DAV, Name};
use super::{
    Dav, MAX_RESOURCE_SIZE, Place, Target, collection_href, home_href, object_href, outbox_href,
    own_collection_href, principal_href, xml_response,
};
use crate::jmap::User;

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
    /// Another account's principal, seen by an account it shares with.
    Sharer(&'a User),
    Home(Kind),
    Collection(&'a Place),
    Outbox,
    Object(&'a Place, &'a Object),
}

impl Resource<'_> {
    pub fn href(&self, dav: &Dav) -> String {
        match self {
            Resource::Root => "/dav/".to_string(),
            Resource::Principals => "/dav/principals/".to_string(),
            Resource::Principal => principal_href(&dav.user),
            Resource::Sharer(user) => principal_href(user),
            Resource::Home(kind) => home_href(&dav.user, *kind),
            Resource::Collection(place) => collection_href(&dav.user, place),
            Resource::Outbox => outbox_href(&dav.user),
            Resource::Object(place, object) => object_href(&dav.user, place, &object.name),
        }
    }

    /// The collection the resource is or is in, if any.
    fn place(&self) -> Option<&Place> {
        match self {
            Resource::Collection(place) | Resource::Object(place, _) => Some(place),
            _ => None,
        }
    }
}

fn hrefs(list: &[String]) -> String {
    list.iter().map(|href| xml::href(href)).collect()
}

/// The user's privileges (RFC 3744 5.4): every one on their own
/// resources, reading only on another account's principal and in a
/// read-only share. Clients read this to show a collection as read-only.
fn privileges(resource: &Resource<'_>) -> String {
    let writable = match resource {
        Resource::Sharer(_) => false,
        resource => resource.place().is_none_or(Place::writable),
    };
    let list: &[&str] = if writable {
        &[
            "read",
            "write",
            "write-properties",
            "write-content",
            "bind",
            "unbind",
            "read-current-user-privilege-set",
        ]
    } else {
        &["read", "read-current-user-privilege-set"]
    };
    list.iter()
        .map(|privilege| format!("<d:privilege><d:{privilege}/></d:privilege>"))
        .collect()
}

/// A CalendarServer sharing `access` element.
fn access_element(access: Access) -> &'static str {
    match access {
        Access::Read => "<cs:access><cs:read/></cs:access>",
        Access::ReadWrite => "<cs:access><cs:read-write/></cs:access>",
    }
}

fn invite_user(address: &str, access: Access) -> String {
    format!(
        "<cs:user>{}<cs:common-name>{}</cs:common-name><cs:invite-accepted/>{}</cs:user>",
        xml::href(&format!("mailto:{address}")),
        xml::escape(address),
        access_element(access)
    )
}

/// CalendarServer's `invite` property: who a collection is shared with.
/// The owner sees every sharee; a sharee sees the owner and themselves.
/// Grants take effect at once, so every invitation shows as accepted.
fn invite(dav: &Dav, place: &Place) -> Option<String> {
    match &place.share {
        Some(share) => Some(format!(
            "<cs:organizer>{}<cs:common-name>{}</cs:common-name></cs:organizer>{}",
            xml::href(&format!("mailto:{}", share.owner.address)),
            xml::escape(&share.owner.address),
            invite_user(&dav.user.address, share.grant.access)
        )),
        None => Some(
            share::grants_on(&dav.app.db_path, &dav.user.address, place.collection.id)
                .ok()?
                .iter()
                .map(|grant| invite_user(&grant.grantee, grant.access))
                .collect(),
        ),
    }
}

/// A shared collection's name for the sharee: their own, else the owner's
/// with the owner's address, so it is told apart from their own.
fn shared_name(place: &Place) -> Option<String> {
    let share = place.share.as_ref()?;
    Some(share.grant.displayname.clone().unwrap_or_else(|| {
        let name = place
            .collection
            .displayname
            .as_deref()
            .unwrap_or(&place.collection.name);
        format!("{name} ({})", share.owner.address)
    }))
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
        (DAV, "current-user-privilege-set") => return Some(privileges(resource)),
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
        // Enough for clients to name who shares a collection.
        Resource::Sharer(user) => match (ns, local) {
            (DAV, "resourcetype") => Some("<d:principal/>".to_string()),
            (DAV, "displayname") => Some(xml::escape(&user.address)),
            (DAV, "principal-URL") => Some(xml::href(&principal_href(user))),
            (CALDAV, "calendar-user-address-set") => {
                Some(xml::href(&format!("mailto:{}", user.address)))
            }
            (CALDAV, "calendar-user-type") => Some("INDIVIDUAL".to_string()),
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
        Resource::Collection(place) => {
            let collection = &place.collection;
            let calendar = collection.kind == Kind::Calendar;
            let personal = |value: Option<&String>, own: &Option<String>| {
                value.or(own.as_ref()).map(|value| xml::escape(value))
            };
            let grant = place.share.as_ref().map(|share| &share.grant);
            match (ns, local) {
                (DAV, "resourcetype") if collection.inbox => {
                    Some("<d:collection/><c:schedule-inbox/>".to_string())
                }
                (CALDAV, "schedule-default-calendar-URL") if collection.inbox => {
                    let default = store::default_calendar(&dav.conn).ok()?;
                    Some(xml::href(&own_collection_href(&dav.user, &default)))
                }
                (CALDAV, "schedule-calendar-transp") if calendar && !collection.inbox => {
                    Some("<c:opaque/>".to_string())
                }
                (DAV, "resourcetype") => {
                    let mut types = if calendar {
                        "<d:collection/><c:calendar/>".to_string()
                    } else {
                        "<d:collection/><card:addressbook/>".to_string()
                    };
                    // CalendarServer marks shared collections for both
                    // sides; Apple clients show the sharing state by it.
                    if place.share.is_some() {
                        types.push_str("<cs:shared/>");
                    } else if invite(dav, place).is_some_and(|users| !users.is_empty()) {
                        types.push_str("<cs:shared-owner/>");
                    }
                    Some(types)
                }
                (DAV, "displayname") if place.share.is_some() => {
                    shared_name(place).map(|name| xml::escape(&name))
                }
                (DAV, "displayname") => collection.displayname.as_deref().map(xml::escape),
                (DAV, "owner") => Some(xml::href(&principal_href(place.owner(dav)))),
                (CALSERVER, "invite") if !collection.inbox => invite(dav, place),
                (CALSERVER, "allowed-sharing-modes")
                    if !collection.inbox && place.share.is_none() =>
                {
                    Some("<cs:can-be-shared/>".to_string())
                }
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
                (APPLE, "calendar-color") if calendar => personal(
                    grant.and_then(|grant| grant.color.as_ref()),
                    &collection.color,
                ),
                (APPLE, "calendar-order") if calendar => personal(
                    grant.and_then(|grant| grant.sort_order.as_ref()),
                    &collection.sort_order,
                ),
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
        Resource::Object(Place { collection, .. }, object) => match (ns, local) {
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
        Target::Sharer(user) => responses.push(describe(dav, &Resource::Sharer(user), &wanted)),
        Target::Outbox => responses.push(describe(dav, &Resource::Outbox, &wanted)),
        Target::Home(kind) => {
            responses.push(describe(dav, &Resource::Home(*kind), &wanted));
            if depth == 1 {
                let own = store::collections(&dav.conn, *kind)?
                    .into_iter()
                    .map(Place::own);
                // Shared collections are members of the home too, so
                // clients find them as they find the user's own.
                for place in own.chain(dav.shared(Some(*kind), None)?) {
                    responses.push(describe(dav, &Resource::Collection(&place), &wanted));
                }
                if *kind == Kind::Calendar {
                    let inbox = Place::own(store::inbox(&dav.conn)?);
                    responses.push(describe(dav, &Resource::Collection(&inbox), &wanted));
                    responses.push(describe(dav, &Resource::Outbox, &wanted));
                }
            }
        }
        Target::Collection(place) => {
            responses.push(describe(dav, &Resource::Collection(place), &wanted));
            if depth == 1 {
                for object in store::objects(dav.conn_of(place), &place.collection)? {
                    responses.push(describe(dav, &Resource::Object(place, &object), &wanted));
                }
            }
        }
        Target::Object(place, Some(object), _) => {
            responses.push(describe(dav, &Resource::Object(place, object), &wanted));
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

/// PROPPATCH: all changes or none (RFC 4918 9.2). In a shared collection
/// the name, color and order are the sharee's own (see
/// `rmail_common::dav::share`); the description and time zone are the
/// owner's and need read-write access.
pub(crate) fn proppatch(dav: &Dav, target: Target, body: &[u8]) -> anyhow::Result<Response> {
    let Target::Collection(place) = target else {
        return Ok(super::status(match target {
            Target::NotFound | Target::NewCollection(..) | Target::Object(_, None, _) => {
                StatusCode::NOT_FOUND
            }
            _ => StatusCode::FORBIDDEN,
        }));
    };
    let collection = &place.collection;
    if collection.inbox {
        return Ok(super::status(StatusCode::FORBIDDEN));
    }
    let personal = |setting: Setting| place.share.is_some() && share::is_personal(setting);
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
                Some(setting) if personal(setting) || place.writable() => {
                    let value = if remove {
                        None
                    } else {
                        Some(element.text().unwrap_or_default().to_string())
                    };
                    changes.push((name, setting, value));
                }
                _ => refused.push(name),
            }
        }
    }
    let mut response = xml::Response::new(&collection_href(&dav.user, &place));
    if refused.is_empty() {
        for (name, setting, value) in &changes {
            match &place.share {
                Some(share) if personal(*setting) => {
                    share::set_personal(
                        &dav.app.db_path,
                        &share.grant,
                        *setting,
                        value.as_deref(),
                    )?;
                }
                _ => store::set_property(
                    dav.conn_of(&place),
                    collection,
                    *setting,
                    value.as_deref(),
                )?,
            }
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
