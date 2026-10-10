//! Sharing a collection from a client, as CalendarServer does (its
//! `calendarserver-sharing` extension, which Apple Calendar uses): a POST
//! of `CS:share` to one of the user's own collections sets or removes
//! sharees. Each sharee is an account on this server, named by a `mailto:`
//! URI or its principal URL, and gets read (`CS:read`) or read-write
//! (`CS:read-write`) access at once: there are no invitations to accept,
//! so `CS:invite` lists every sharee as accepted.
//!
//! Clients without sharing (Thunderbird, DAVx5) see what is shared with
//! them all the same; webmail, the admin console and `rmail_ctl` manage
//! the grants too.

use axum::http::StatusCode;
use axum::response::Response;
use rmail_common::dav::share::{self, Access};

use super::xml::{self, CALSERVER, DAV};
use super::{Dav, Place, Target, href_segments, status, xml_response};

/// The most sharees one request may change.
const MAX_SHAREES: usize = 100;

/// POST to a collection: a `CS:share` request.
pub(crate) fn post(dav: &Dav, target: Target, body: &[u8]) -> anyhow::Result<Response> {
    let Target::Collection(place) = target else {
        return Ok(status(StatusCode::METHOD_NOT_ALLOWED));
    };
    let Place {
        collection,
        share: None,
    } = place
    else {
        // Only the owner shares a collection.
        return Ok(status(StatusCode::FORBIDDEN));
    };
    if collection.inbox {
        return Ok(status(StatusCode::FORBIDDEN));
    }
    // Sharing is the only thing posted to a collection (scheduling posts
    // go to the outbox).
    let Some(document) = xml::parse(body).ok().flatten() else {
        return Ok(status(StatusCode::METHOD_NOT_ALLOWED));
    };
    let root = document.root_element();
    if !xml::is(root, CALSERVER, "share") {
        return Ok(status(StatusCode::METHOD_NOT_ALLOWED));
    }
    let mut changes = Vec::new();
    for operation in root.children().filter(|node| node.is_element()) {
        let set = xml::is(operation, CALSERVER, "set");
        if !set && !xml::is(operation, CALSERVER, "remove") {
            continue;
        }
        let Some(href) = xml::child(operation, DAV, "href").and_then(|href| href.text()) else {
            return Ok(status(StatusCode::BAD_REQUEST));
        };
        let access = if !set {
            None
        } else if xml::child(operation, CALSERVER, "read-write").is_some() {
            Some(Access::ReadWrite)
        } else {
            Some(Access::Read)
        };
        changes.push((href.trim().to_string(), access));
    }
    if changes.len() > MAX_SHAREES {
        return Ok(status(StatusCode::FORBIDDEN));
    }
    // Each sharee is changed on its own; those that fail are reported in a
    // multistatus, as CalendarServer does.
    let mut refused = Vec::new();
    for (href, access) in changes {
        let applied = match sharee(&href) {
            Some(address) => share::set_access(
                &dav.app.db_path,
                &dav.user.address,
                collection.id,
                &address,
                access,
            )
            .is_ok(),
            None => false,
        };
        if !applied {
            let mut response = xml::Response::new(&href);
            response.status = Some(403);
            refused.push(response);
        }
    }
    Ok(if refused.is_empty() {
        status(StatusCode::OK)
    } else {
        xml_response(StatusCode::MULTI_STATUS, xml::multistatus(&refused, None))
    })
}

/// The account address a sharee href names: `mailto:` or a principal URL.
fn sharee(href: &str) -> Option<String> {
    if let Some(address) = href
        .get(..7)
        .filter(|scheme| scheme.eq_ignore_ascii_case("mailto:"))
        .map(|_| &href[7..])
    {
        return Some(address.trim().to_string());
    }
    match href_segments(href)?.as_slice() {
        [first, address] if first == "principals" => Some(address.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sharees_are_named_by_mailto_or_principal() {
        assert_eq!(
            sharee("mailto:a@example.test").as_deref(),
            Some("a@example.test")
        );
        assert_eq!(
            sharee("MAILTO:a@example.test").as_deref(),
            Some("a@example.test")
        );
        assert_eq!(
            sharee("/dav/principals/a%40example.test/").as_deref(),
            Some("a@example.test")
        );
        assert_eq!(
            sharee("https://mail.example.test/dav/principals/a@example.test/").as_deref(),
            Some("a@example.test")
        );
        assert_eq!(sharee("/dav/calendars/a@example.test/"), None);
        assert_eq!(sharee("urn:uuid:1234"), None);
    }
}
