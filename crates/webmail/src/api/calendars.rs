//! Sharing calendars and address books from webmail. Webmail shows no
//! calendars itself, but most CalDAV/CardDAV clients (Thunderbird, DAVx5)
//! cannot share, so the user's collections are listed here with whom each
//! is shared, as for folders (see `rmail_common::dav::share`).

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use rmail_common::dav::share::{self, Access};
use rmail_common::dav::store::{Collection, Kind};
use serde::{Deserialize, Serialize};

use super::{Session, Shared, blocking, internal_error};

pub(crate) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/calendars", get(list))
        .route("/api/calendars/{kind}/{name}/sharing", put(change))
}

/// Webmail's names for the access levels, as for folders.
fn access_name(access: Access) -> &'static str {
    match access {
        Access::Read => "read",
        Access::ReadWrite => "edit",
    }
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Calendar => "calendar",
        Kind::AddressBook => "addressbook",
    }
}

fn display_name(collection: &Collection) -> String {
    collection
        .displayname
        .clone()
        .unwrap_or_else(|| collection.name.clone())
}

#[derive(Serialize)]
struct SharedTo {
    address: String,
    access: &'static str,
}

#[derive(Serialize)]
struct OwnCollection {
    kind: &'static str,
    /// The URL segment, which names it in requests.
    name: String,
    displayname: String,
    grants: Vec<SharedTo>,
}

#[derive(Serialize)]
struct SharedCollection {
    kind: &'static str,
    owner: String,
    displayname: String,
    access: &'static str,
}

#[derive(Serialize)]
struct Listing {
    own: Vec<OwnCollection>,
    shared: Vec<SharedCollection>,
}

/// The user's calendars and address books with their grants, and those
/// other accounts share with the user.
async fn list(app: State<Shared>, headers: HeaderMap) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let result = blocking(move || {
        let grants = share::granted_by(&state.db_path, &session.address)?;
        let mut own = Vec::new();
        for kind in [Kind::Calendar, Kind::AddressBook] {
            for collection in share::own_collections(&state.mail_root, &session.address, kind)? {
                own.push(OwnCollection {
                    kind: kind_name(kind),
                    displayname: display_name(&collection),
                    grants: grants
                        .iter()
                        .filter(|grant| grant.collection_id == collection.id)
                        .map(|grant| SharedTo {
                            address: grant.grantee.clone(),
                            access: access_name(grant.access),
                        })
                        .collect(),
                    name: collection.name,
                });
            }
        }
        let received = share::shared_with(&state.db_path, &session.address)?;
        let shared = share::with_collections(&state.mail_root, received)?
            .into_iter()
            .map(|(grant, collection)| SharedCollection {
                kind: kind_name(collection.kind),
                displayname: grant
                    .displayname
                    .clone()
                    .unwrap_or_else(|| display_name(&collection)),
                owner: grant.owner,
                access: access_name(grant.access),
            })
            .collect();
        Ok(Listing { own, shared })
    })
    .await;
    match result {
        Ok(listing) => Json(listing).into_response(),
        Err(error) => internal_error(error),
    }
}

#[derive(Deserialize)]
struct SharingChange {
    address: String,
    /// `read`, `edit` or `none` (stop sharing).
    access: String,
}

/// Share one of the user's calendars or address books with another
/// account, change its access or stop sharing it.
async fn change(
    app: State<Shared>,
    headers: HeaderMap,
    Path((kind, name)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let kind = match kind.as_str() {
        "calendar" => Kind::Calendar,
        "addressbook" => Kind::AddressBook,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<SharingChange>(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid json").into_response();
    };
    let access = match input.access.as_str() {
        "none" => None,
        "read" => Some(Access::Read),
        "edit" => Some(Access::ReadWrite),
        _ => return (StatusCode::BAD_REQUEST, "unknown access").into_response(),
    };
    let result = blocking(move || {
        let Some(collection) = share::own_collections(&state.mail_root, &session.address, kind)?
            .into_iter()
            .find(|collection| collection.name == name)
        else {
            return Ok(Err(StatusCode::NOT_FOUND.into_response()));
        };
        Ok(
            match share::set_access(
                &state.db_path,
                &session.address,
                collection.id,
                input.address.trim(),
                access,
            ) {
                Ok(()) => Ok(()),
                Err(error) => {
                    Err((StatusCode::UNPROCESSABLE_ENTITY, format!("{error:#}")).into_response())
                }
            },
        )
    })
    .await;
    match result {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(response)) => response,
        Err(error) => internal_error(error),
    }
}
