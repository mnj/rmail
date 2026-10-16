//! Contacts in webmail: the user's CardDAV address books (and those shared
//! with them) as JSON, with adding, editing and deleting.
//!
//! - Contacts are vCards in the same store CardDAV clients sync
//!   (`rmail_common::dav::store`), so a change here reaches the user's phone
//!   and the other way round.
//! - Editing replaces only the lines of the fields webmail shows (name,
//!   addresses, phones, organization, title, birthday, note); every other
//!   line, such as a photo, labels grouped with a field (`item1.X-ABLabel`)
//!   or a client's own extensions, is kept as it was. The parser used for
//!   reading drops property groups, so cards are edited line by line rather
//!   than re-serialized.
//! - Writes are conditional on the ETag the user saw, so a change made in
//!   another client meanwhile is not overwritten.
//! - Address books shared with the user read-only are listed but cannot be
//!   changed.

use std::path::Path;

use axum::body::Bytes;
use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use rmail_common::dav::itip::unescape;
use rmail_common::dav::share::{self, Access};
use rmail_common::dav::store::{self, Collection, Kind, PutError};
use rmail_common::dav::text::{self, Component, Property};
use serde::{Deserialize, Serialize};

use super::{AppState, Session, Shared, blocking, internal_error};

const MAX_FIELD_CHARS: usize = 300;
const MAX_NOTE_CHARS: usize = 10_000;
const MAX_ENTRIES: usize = 20;
const BIRTHDAY_FORMAT: &str = "Write the birthday as YYYY-MM-DD.";

pub(crate) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/addressbook", get(list))
        .route("/api/addressbook/{book}", post(create))
        .route("/api/addressbook/{book}/{name}", put(update).delete(remove))
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Entry {
    /// `work`, `home`, `cell`... or empty.
    #[serde(default)]
    pub kind: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PostalAddress {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub street: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub postcode: String,
    #[serde(default)]
    pub country: String,
}

/// The fields webmail edits.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Fields {
    #[serde(default)]
    pub full_name: String,
    #[serde(default)]
    pub given: String,
    #[serde(default)]
    pub family: String,
    #[serde(default)]
    pub emails: Vec<Entry>,
    #[serde(default)]
    pub phones: Vec<Entry>,
    #[serde(default)]
    pub org: String,
    #[serde(default)]
    pub title: String,
    /// `YYYY-MM-DD`, or `--MM-DD` without a year.
    #[serde(default)]
    pub birthday: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub addresses: Vec<PostalAddress>,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct Contact {
    pub book: String,
    /// The resource name in its address book.
    pub name: String,
    pub etag: String,
    #[serde(flatten)]
    pub fields: Fields,
    pub has_photo: bool,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
struct Book {
    /// `own:<name>`, or `shared:<owner>:<name>` for one shared with the
    /// user; one path segment either way.
    id: String,
    displayname: String,
    /// Who shared it, for one that is not the user's.
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    writable: bool,
}

#[derive(Serialize)]
struct Listing {
    books: Vec<Book>,
    contacts: Vec<Contact>,
}

// ---------------------------------------------------------------------------
// Reading vCards

/// A structured value (`N`, `ADR`) split on unescaped semicolons.
fn components(value: &str) -> Vec<String> {
    let mut parts = vec![String::new()];
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(next) = chars.next() {
                    parts.last_mut().unwrap().push('\\');
                    parts.last_mut().unwrap().push(next);
                }
            }
            ';' => parts.push(String::new()),
            c => parts.last_mut().unwrap().push(c),
        }
    }
    parts
        .iter()
        .map(|part| unescape(part).trim().to_string())
        .collect()
}

/// The kind of an EMAIL, TEL or ADR from its TYPE parameter(s): the first
/// one that says where (`work`, `home`, `cell`...), not `internet`,
/// `voice` or `pref`.
fn kind_of(property: &Property) -> String {
    property
        .params
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("TYPE"))
        .flat_map(|(_, value)| value.split(','))
        .map(|kind| kind.trim().to_ascii_lowercase())
        .find(|kind| !matches!(kind.as_str(), "internet" | "voice" | "pref" | "x400" | ""))
        .unwrap_or_default()
}

fn text_of(card: &Component, name: &str) -> String {
    card.property(name)
        .map(|property| unescape(&property.value).trim().to_string())
        .unwrap_or_default()
}

pub(crate) fn fields_of(card: &Component) -> Fields {
    let n = card
        .property("N")
        .map(|n| components(&n.value))
        .unwrap_or_default();
    let part = |index: usize| n.get(index).cloned().unwrap_or_default();
    let entries = |name: &str, strip: &str| {
        card.properties_named(name)
            .map(|property| Entry {
                kind: kind_of(property),
                value: unescape(&property.value)
                    .trim()
                    .trim_start_matches(strip)
                    .to_string(),
            })
            .filter(|entry| !entry.value.is_empty())
            .collect::<Vec<_>>()
    };
    let birthday = text_of(card, "BDAY");
    Fields {
        full_name: text_of(card, "FN"),
        family: part(0),
        given: part(1),
        emails: entries("EMAIL", "mailto:"),
        phones: entries("TEL", "tel:"),
        org: card
            .property("ORG")
            .and_then(|org| components(&org.value).into_iter().find(|p| !p.is_empty()))
            .unwrap_or_default(),
        title: text_of(card, "TITLE"),
        birthday: readable_date(&birthday),
        note: text_of(card, "NOTE"),
        addresses: card
            .properties_named("ADR")
            .map(|adr| {
                let parts = components(&adr.value);
                let at = |index: usize| parts.get(index).cloned().unwrap_or_default();
                PostalAddress {
                    kind: kind_of(adr),
                    street: at(2),
                    city: at(3),
                    region: at(4),
                    postcode: at(5),
                    country: at(6),
                }
            })
            .collect(),
    }
}

/// `19850412` and `1985-04-12` as `1985-04-12`; `--0412` as `--04-12`.
fn readable_date(value: &str) -> String {
    let value = value.split('T').next().unwrap_or_default().trim();
    let digits: String = value.chars().filter(char::is_ascii_digit).collect();
    match (value.starts_with("--"), digits.len()) {
        (true, 4) => format!("--{}-{}", &digits[..2], &digits[2..]),
        (false, 8) => format!("{}-{}-{}", &digits[..4], &digits[4..6], &digits[6..]),
        _ => value.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Writing vCards

/// A vCard TEXT value.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace(',', "\\,")
        .replace(';', "\\;")
        .replace("\r\n", "\\n")
        .replace(['\n', '\r'], "\\n")
}

/// A content line folded at 75 octets (RFC 6350 3.2).
fn fold(line: &str) -> String {
    let mut out = String::new();
    let mut width = 0;
    for c in line.chars() {
        if width + c.len_utf8() > 75 {
            out.push_str("\r\n ");
            width = 1;
        }
        out.push(c);
        width += c.len_utf8();
    }
    out.push_str("\r\n");
    out
}

/// A card's lines with continuations joined.
fn unfold(data: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for line in data.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        match (line.strip_prefix([' ', '\t']), lines.last_mut()) {
            (Some(rest), Some(last)) => last.push_str(rest),
            _ if line.is_empty() => {}
            _ => lines.push(line.to_string()),
        }
    }
    lines
}

/// The property name of a content line, without any group.
fn line_name(line: &str) -> String {
    let end = line.find([':', ';']).unwrap_or(line.len());
    let name = &line[..end];
    name.rsplit('.').next().unwrap_or(name).to_ascii_uppercase()
}

/// The properties webmail owns; their lines are rewritten on every save.
const MANAGED: &[&str] = &[
    "FN", "N", "EMAIL", "TEL", "ORG", "TITLE", "NOTE", "BDAY", "ADR",
];

fn type_param(kind: &str) -> String {
    let kind: String = kind
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    if kind.is_empty() {
        String::new()
    } else {
        format!(";TYPE={}", kind.to_ascii_lowercase())
    }
}

fn display_name(fields: &Fields) -> String {
    let full = fields.full_name.trim();
    if !full.is_empty() {
        return full.to_string();
    }
    let joined = [fields.given.trim(), fields.family.trim()]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if !joined.is_empty() {
        return joined;
    }
    if !fields.org.trim().is_empty() {
        return fields.org.trim().to_string();
    }
    fields
        .emails
        .first()
        .map(|email| email.value.trim().to_string())
        .unwrap_or_default()
}

/// The lines for `fields`, in vCard order.
fn field_lines(fields: &Fields) -> Vec<String> {
    let mut lines = vec![
        format!("FN:{}", escape(&display_name(fields))),
        format!(
            "N:{};{};;;",
            escape(fields.family.trim()),
            escape(fields.given.trim())
        ),
    ];
    for email in &fields.emails {
        lines.push(format!(
            "EMAIL{}:{}",
            type_param(&email.kind),
            escape(email.value.trim())
        ));
    }
    for phone in &fields.phones {
        lines.push(format!(
            "TEL{}:{}",
            type_param(&phone.kind),
            escape(phone.value.trim())
        ));
    }
    if !fields.org.trim().is_empty() {
        lines.push(format!("ORG:{}", escape(fields.org.trim())));
    }
    if !fields.title.trim().is_empty() {
        lines.push(format!("TITLE:{}", escape(fields.title.trim())));
    }
    if !fields.birthday.trim().is_empty() {
        lines.push(format!("BDAY:{}", fields.birthday.trim()));
    }
    for address in &fields.addresses {
        lines.push(format!(
            "ADR{}:;;{};{};{};{};{}",
            type_param(&address.kind),
            escape(address.street.trim()),
            escape(address.city.trim()),
            escape(address.region.trim()),
            escape(address.postcode.trim()),
            escape(address.country.trim()),
        ));
    }
    if !fields.note.trim().is_empty() {
        lines.push(format!("NOTE:{}", escape(fields.note.trim())));
    }
    lines
}

/// `existing` with webmail's fields replaced by `fields`, or a new card.
pub(crate) fn card_text(existing: Option<&str>, fields: &Fields, uid: &str) -> String {
    // A birthday left as it was keeps its line, whatever format another
    // client wrote it in.
    let same_birthday =
        existing.is_some_and(|data| birthday_of(data).as_deref() == Some(fields.birthday.as_str()));
    let kept: Vec<String> = match existing {
        Some(data) => unfold(data)
            .into_iter()
            .filter(|line| {
                let name = line_name(line);
                (same_birthday && name == "BDAY")
                    || (!MANAGED.contains(&name.as_str()) && name != "END" && name != "BEGIN")
            })
            .collect(),
        None => vec!["VERSION:3.0".to_string(), format!("UID:{}", escape(uid))],
    };
    let mut lines = field_lines(fields);
    if same_birthday {
        lines.retain(|line| line_name(line) != "BDAY");
    }
    let mut out = fold("BEGIN:VCARD");
    for line in kept.iter().chain(lines.iter()) {
        out.push_str(&fold(line));
    }
    out.push_str(&fold("END:VCARD"));
    out
}

/// The birthday on a card as webmail shows it.
fn birthday_of(data: &str) -> Option<String> {
    text::parse(data).ok().map(|card| fields_of(&card).birthday)
}

/// Whether a birthday is one webmail writes: `YYYY-MM-DD` or `--MM-DD`.
fn valid_birthday(birthday: &str) -> bool {
    let birthday = birthday.trim();
    let shape = birthday.is_empty()
        || (birthday.len() == 10
            && birthday.as_bytes()[4] == b'-'
            && birthday.as_bytes()[7] == b'-')
        || (birthday.len() == 7 && birthday.starts_with("--") && birthday.as_bytes()[4] == b'-');
    shape && birthday.chars().all(|c| c.is_ascii_digit() || c == '-')
}

/// Why `fields` cannot be saved, for the user. The birthday's format is
/// checked when it is saved, against the card it replaces.
fn check(fields: &Fields) -> Result<(), &'static str> {
    if display_name(fields).is_empty() {
        return Err("Give the contact a name or an email address.");
    }
    let single = [
        &fields.full_name,
        &fields.given,
        &fields.family,
        &fields.org,
        &fields.title,
        &fields.birthday,
    ];
    let entries = fields.emails.iter().chain(&fields.phones);
    if single
        .iter()
        .any(|value| value.chars().count() > MAX_FIELD_CHARS || value.contains(['\r', '\n']))
        || fields.emails.len() > MAX_ENTRIES
        || fields.phones.len() > MAX_ENTRIES
        || fields.addresses.len() > MAX_ENTRIES
        || fields.note.chars().count() > MAX_NOTE_CHARS
    {
        return Err("A field is too long.");
    }
    for entry in entries {
        if entry.value.chars().count() > MAX_FIELD_CHARS
            || entry.kind.chars().count() > 30
            || entry.value.contains(['\r', '\n'])
        {
            return Err("A field is too long.");
        }
    }
    for address in &fields.addresses {
        let parts = [
            &address.kind,
            &address.street,
            &address.city,
            &address.region,
            &address.postcode,
            &address.country,
        ];
        if parts
            .iter()
            .any(|part| part.chars().count() > MAX_FIELD_CHARS)
            || address.kind.contains(['\r', '\n'])
        {
            return Err("A field is too long.");
        }
    }
    if fields
        .emails
        .iter()
        .any(|email| !email.value.trim().is_empty() && !email.value.contains('@'))
    {
        return Err("An email address is not valid.");
    }
    Ok(())
}

/// The fields without empty entries.
fn tidy(mut fields: Fields) -> Fields {
    fields.emails.retain(|entry| !entry.value.trim().is_empty());
    fields.phones.retain(|entry| !entry.value.trim().is_empty());
    fields.addresses.retain(|address| {
        [
            &address.street,
            &address.city,
            &address.region,
            &address.postcode,
            &address.country,
        ]
        .iter()
        .any(|part| !part.trim().is_empty())
    });
    fields
}

// ---------------------------------------------------------------------------
// Address books

/// One address book the user can see: where it is and whether they may
/// change it.
struct Place {
    id: String,
    displayname: String,
    owner: Option<String>,
    writable: bool,
    conn: rmail_common::sqlite_pool::SqliteConnection,
    collection: Collection,
}

fn display(collection: &Collection) -> String {
    collection
        .displayname
        .clone()
        .unwrap_or_else(|| collection.name.clone())
}

fn open_account(
    mail_root: &Path,
    address: &str,
) -> anyhow::Result<rmail_common::sqlite_pool::SqliteConnection> {
    let (local, domain) = address
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("invalid address"))?;
    rmail_common::jmap::store::open(mail_root, domain, local)
}

fn places(state: &AppState, session: &Session) -> anyhow::Result<Vec<Place>> {
    let mut found = Vec::new();
    let conn = open_account(&state.mail_root, &session.address)?;
    for collection in store::collections(&conn, Kind::AddressBook)? {
        found.push(Place {
            id: format!("own:{}", collection.name),
            displayname: display(&collection),
            owner: None,
            // The directory is kept by the server.
            writable: !collection.managed,
            conn: open_account(&state.mail_root, &session.address)?,
            collection,
        });
    }
    let grants = share::shared_with(&state.db_path, &session.address)?;
    for (grant, collection) in share::with_collections(&state.mail_root, grants)? {
        if collection.kind != Kind::AddressBook {
            continue;
        }
        found.push(Place {
            id: format!("shared:{}:{}", grant.owner, collection.name),
            displayname: grant
                .displayname
                .clone()
                .unwrap_or_else(|| display(&collection)),
            writable: grant.access == Access::ReadWrite && !collection.managed,
            conn: open_account(&state.mail_root, &grant.owner)?,
            owner: Some(grant.owner),
            collection,
        });
    }
    Ok(found)
}

fn contacts_in(place: &Place) -> anyhow::Result<Vec<Contact>> {
    let mut out = Vec::new();
    for object in store::objects(&place.conn, &place.collection)? {
        let Ok(card) = text::parse(&object.data) else {
            continue;
        };
        if card.name != "VCARD" {
            continue;
        }
        out.push(Contact {
            book: place.id.clone(),
            name: object.name.clone(),
            etag: object.etag.clone(),
            fields: fields_of(&card),
            has_photo: card.property("PHOTO").is_some(),
        });
    }
    Ok(out)
}

fn contact(place: &Place, name: &str) -> anyhow::Result<Option<Contact>> {
    let Some(object) = store::object(&place.conn, &place.collection, name)? else {
        return Ok(None);
    };
    let card = text::parse(&object.data)?;
    Ok(Some(Contact {
        book: place.id.clone(),
        name: object.name,
        etag: object.etag,
        fields: fields_of(&card),
        has_photo: card.property("PHOTO").is_some(),
    }))
}

// ---------------------------------------------------------------------------
// Handlers

fn refused(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

async fn list(app: State<Shared>, headers: HeaderMap) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let result = blocking(move || {
        let places = places(&state, &session)?;
        let mut contacts = Vec::new();
        for place in &places {
            contacts.extend(contacts_in(place)?);
        }
        contacts.sort_by_key(|contact| display_name(&contact.fields).to_lowercase());
        Ok(Listing {
            books: places
                .into_iter()
                .map(|place| Book {
                    id: place.id,
                    displayname: place.displayname,
                    owner: place.owner,
                    writable: place.writable,
                })
                .collect(),
            contacts,
        })
    })
    .await;
    match result {
        Ok(listing) => Json(listing).into_response(),
        Err(error) => internal_error(error),
    }
}

#[derive(Deserialize)]
struct Save {
    #[serde(flatten)]
    fields: Fields,
    /// The version the user edited (updates).
    #[serde(default)]
    etag: Option<String>,
}

enum Outcome {
    Saved(Box<Contact>),
    Refused(StatusCode, &'static str),
}

/// Store a card in `book`, creating `name` or replacing the version with
/// `etag`, in one write transaction.
fn save(
    state: &AppState,
    session: &Session,
    book: &str,
    name: Option<&str>,
    input: Save,
) -> anyhow::Result<Outcome> {
    let Some(place) = places(state, session)?
        .into_iter()
        .find(|place| place.id == book)
    else {
        return Ok(Outcome::Refused(
            StatusCode::NOT_FOUND,
            "No such address book.",
        ));
    };
    if !place.writable {
        return Ok(Outcome::Refused(
            StatusCode::FORBIDDEN,
            "This address book is shared with you read-only.",
        ));
    }
    let fields = tidy(input.fields);
    let uid = uuid();
    let name = match name {
        Some(name) => name.to_string(),
        None => format!("{uid}.vcf"),
    };
    let creating = input.etag.is_none();
    let etag = input.etag.clone();
    let stored = store::put_with(&place.conn, &place.collection, &name, &mut |current| {
        match (current, &etag) {
            (None, None) => {}
            (Some(object), Some(etag)) if &object.etag == etag => {}
            _ => return Err(PutError::PreconditionFailed),
        }
        let previous = current.and_then(|object| birthday_of(&object.data));
        if previous.as_deref() != Some(fields.birthday.as_str())
            && !valid_birthday(&fields.birthday)
        {
            return Err(PutError::InvalidData(BIRTHDAY_FORMAT.to_string()));
        }
        Ok(store::Prepared {
            data: card_text(current.map(|object| object.data.as_str()), &fields, &uid),
            schedule_tag: store::ScheduleTag::None,
        })
    })?;
    match stored {
        Ok(_) => Ok(contact(&place, &name)?
            .map(|contact| Outcome::Saved(Box::new(contact)))
            .unwrap_or(Outcome::Refused(
                StatusCode::NOT_FOUND,
                "The contact is gone.",
            ))),
        Err(PutError::InvalidData(message)) if message == BIRTHDAY_FORMAT => {
            Ok(Outcome::Refused(StatusCode::BAD_REQUEST, BIRTHDAY_FORMAT))
        }
        Err(PutError::PreconditionFailed) if creating => Ok(Outcome::Refused(
            StatusCode::CONFLICT,
            "A contact with this name exists.",
        )),
        Err(PutError::PreconditionFailed) => Ok(Outcome::Refused(
            StatusCode::CONFLICT,
            "This contact was changed elsewhere. Reload and try again.",
        )),
        Err(error) => anyhow::bail!("storing the contact: {error:?}"),
    }
}

fn uuid() -> String {
    let bytes: [u8; 16] = rand::random();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

async fn write(
    state: Shared,
    headers: HeaderMap,
    book: String,
    name: Option<String>,
    body: Bytes,
) -> Response {
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<Save>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "invalid json");
    };
    if name.is_some() && input.etag.is_none() {
        return refused(StatusCode::BAD_REQUEST, "missing etag");
    }
    if let Err(message) = check(&input.fields) {
        return refused(StatusCode::BAD_REQUEST, message);
    }
    match blocking(move || save(&state, &session, &book, name.as_deref(), input)).await {
        Ok(Outcome::Saved(contact)) => Json(*contact).into_response(),
        Ok(Outcome::Refused(status, message)) => refused(status, message),
        Err(error) => internal_error(error),
    }
}

async fn create(
    app: State<Shared>,
    headers: HeaderMap,
    UrlPath(book): UrlPath<String>,
    body: Bytes,
) -> Response {
    write(app.0, headers, book, None, body).await
}

async fn update(
    app: State<Shared>,
    headers: HeaderMap,
    UrlPath((book, name)): UrlPath<(String, String)>,
    body: Bytes,
) -> Response {
    write(app.0, headers, book, Some(name), body).await
}

#[derive(Deserialize)]
struct Remove {
    etag: String,
}

async fn remove(
    app: State<Shared>,
    headers: HeaderMap,
    UrlPath((book, name)): UrlPath<(String, String)>,
    body: Bytes,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<Remove>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "missing etag");
    };
    let result = blocking(move || {
        let Some(place) = places(&state, &session)?
            .into_iter()
            .find(|place| place.id == book)
        else {
            return Ok(Err((StatusCode::NOT_FOUND, "No such address book.")));
        };
        if !place.writable {
            return Ok(Err((
                StatusCode::FORBIDDEN,
                "This address book is shared with you read-only.",
            )));
        }
        let etag = input.etag;
        let precondition =
            |current: Option<&store::Object>| current.is_some_and(|object| object.etag == etag);
        Ok(
            match store::delete(&place.conn, &place.collection, &name, &precondition)? {
                store::Deleted::Deleted(_) => Ok(()),
                store::Deleted::NotFound => Err((StatusCode::NOT_FOUND, "The contact is gone.")),
                store::Deleted::PreconditionFailed => Err((
                    StatusCode::CONFLICT,
                    "This contact was changed elsewhere. Reload and try again.",
                )),
            },
        )
    })
    .await;
    match result {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err((status, message))) => refused(status, message),
        Err(error) => internal_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{req, route, state};
    use super::super::{SESSION_COOKIE, sign_session};
    use super::*;
    use rmail_common::db;
    use serde_json::{Value, json};

    const APPLE: &str = "BEGIN:VCARD\r\nVERSION:3.0\r\nPRODID:-//Apple Inc.//iOS 18//EN\r\nUID:apple-1\r\n\
        N:Holm;Søren;;;\r\nFN:Søren Holm\r\nORG:Nordlys ApS;\r\n\
        item1.EMAIL;type=INTERNET;type=pref:soren@nordlys.test\r\nitem1.X-ABLabel:_$!<Work>!$_\r\n\
        TEL;type=CELL;type=VOICE;type=pref:+45 12 34 56 78\r\nBDAY:1985-04-12\r\n\
        ADR;type=HOME:;;Strandvej 1\\, 2. th;Aarhus;;8000;Denmark\r\n\
        NOTE:Likes coffee\\; black.\\nCall after 10.\r\nPHOTO;ENCODING=b;TYPE=JPEG:/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2w\r\n \
        BDAQkJCQwLDBgNDRgyIRwhMjIy\r\nX-SOCIALPROFILE;type=twitter:https://x.test/soren\r\nEND:VCARD\r\n";

    #[test]
    fn cards_are_read_from_either_vcard_version() {
        let fields = fields_of(&text::parse(APPLE).unwrap());
        assert_eq!(fields.full_name, "Søren Holm");
        assert_eq!(
            (fields.given.as_str(), fields.family.as_str()),
            ("Søren", "Holm")
        );
        assert_eq!(fields.org, "Nordlys ApS");
        assert_eq!(
            fields.emails,
            [Entry {
                kind: String::new(),
                value: "soren@nordlys.test".into()
            }]
        );
        assert_eq!(fields.phones[0].kind, "cell");
        assert_eq!(fields.birthday, "1985-04-12");
        assert_eq!(fields.note, "Likes coffee; black.\nCall after 10.");
        assert_eq!(fields.addresses[0].street, "Strandvej 1, 2. th");
        assert_eq!(fields.addresses[0].city, "Aarhus");
        assert_eq!(fields.addresses[0].country, "Denmark");

        let v4 = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:x\r\nFN:Ann\r\nEMAIL;TYPE=\"work,pref\":mailto:ann@example.test\r\nBDAY:--0412\r\nEND:VCARD\r\n";
        let fields = fields_of(&text::parse(v4).unwrap());
        assert_eq!(
            fields.emails[0],
            Entry {
                kind: "work".into(),
                value: "ann@example.test".into()
            }
        );
        assert_eq!(fields.birthday, "--04-12");
    }

    #[test]
    fn editing_keeps_every_line_webmail_does_not_show() {
        let mut fields = fields_of(&text::parse(APPLE).unwrap());
        fields.phones[0].value = "+45 87 65 43 21".into();
        fields.note = "Tea now, \"strong\"".into();
        let edited = card_text(Some(APPLE), &fields, "ignored");
        for kept in [
            "UID:apple-1",
            "PRODID:-//Apple Inc.//iOS 18//EN",
            "item1.X-ABLabel:_$!<Work>!$_",
            "X-SOCIALPROFILE;type=twitter:https://x.test/soren",
        ] {
            assert!(edited.contains(kept), "{kept} lost:\n{edited}");
        }
        assert_eq!(
            unfold(&edited)
                .iter()
                .filter(|l| l.starts_with("PHOTO"))
                .count(),
            1
        );
        assert!(
            unfold(&edited)
                .iter()
                .any(|line| line.ends_with("BDAQkJCQwLDBgNDRgyIRwhMjIy"))
        );
        assert!(!edited.contains("+45 12 34 56 78"));
        assert_eq!(edited.matches("BEGIN:VCARD").count(), 1);
        assert!(edited.lines().all(|line| line.len() <= 76), "folded");
        let reread = fields_of(&text::parse(&edited).unwrap());
        assert_eq!(reread, fields, "round trip");

        let new = card_text(
            None,
            &Fields {
                emails: vec![Entry {
                    kind: "work".into(),
                    value: "a@b.test".into(),
                }],
                ..Fields::default()
            },
            "u-1",
        );
        assert!(
            new.contains("VERSION:3.0") && new.contains("UID:u-1") && new.contains("FN:a@b.test")
        );
        assert!(new.contains("EMAIL;TYPE=work:a@b.test"));
    }

    #[test]
    fn a_birthday_left_alone_keeps_its_own_format() {
        let card = APPLE.replace("BDAY:1985-04-12", "BDAY;VALUE=text:circa 1985");
        let mut fields = fields_of(&text::parse(&card).unwrap());
        assert_eq!(fields.birthday, "circa 1985");
        fields.title = "Lead".into();
        let edited = card_text(Some(&card), &fields, "x");
        assert!(edited.contains("BDAY;VALUE=text:circa 1985"));
        assert_eq!(edited.matches("BDAY").count(), 1);
        fields.birthday = "1985-04-12".into();
        let edited = card_text(Some(&card), &fields, "x");
        assert!(edited.contains("BDAY:1985-04-12") && !edited.contains("circa"));
    }

    #[test]
    fn invalid_contacts_are_refused() {
        assert!(check(&Fields::default()).is_err(), "no name");
        let named = Fields {
            full_name: "Ann".into(),
            ..Fields::default()
        };
        assert!(check(&named).is_ok());
        assert!(
            check(&Fields {
                given: "a\nb".into(),
                ..named.clone()
            })
            .is_err()
        );
        assert!(!valid_birthday("12/04/1985") && valid_birthday("--04-12") && valid_birthday(""));
        assert!(
            check(&Fields {
                emails: vec![Entry {
                    kind: String::new(),
                    value: "nope".into()
                }],
                ..named.clone()
            })
            .is_err()
        );
        assert!(
            check(&Fields {
                note: "x".repeat(MAX_NOTE_CHARS + 1),
                ..named
            })
            .is_err()
        );
    }

    #[tokio::test]
    async fn contacts_are_listed_added_edited_and_deleted() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        let cookie = Some(format!(
            "{SESSION_COOKIE}={}",
            sign_session(&state, "user@example.test")
        ));
        let call = |method: &'static str, path: String, body: Value| {
            let (state, cookie) = (state.clone(), cookie.clone());
            async move {
                let body = if body.is_null() {
                    Vec::new()
                } else {
                    body.to_string().into_bytes()
                };
                let response = route(req(method, &path, &body, cookie), &state).await;
                (
                    response.status,
                    serde_json::from_slice::<Value>(&response.body).unwrap_or_default(),
                )
            }
        };
        let (status, listing) = call("GET", "/api/addressbook".into(), Value::Null).await;
        assert_eq!(status, 200);
        assert_eq!(listing["books"][0]["id"], "own:default");
        assert_eq!(listing["contacts"], json!([]));

        let (status, created) = call(
            "POST",
            "/api/addressbook/own:default".into(),
            json!({"given": "Ann", "family": "Lee", "emails": [{"kind": "work", "value": "ann@example.test"}, {"value": ""}]}),
        )
        .await;
        assert_eq!(status, 200, "{created}");
        assert_eq!(created["full_name"], "Ann Lee");
        assert_eq!(
            created["emails"].as_array().unwrap().len(),
            1,
            "empty entries dropped"
        );
        let name = created["name"].as_str().unwrap().to_string();
        let etag = created["etag"].as_str().unwrap().to_string();

        // Compose suggestions read the same address book.
        let suggested = rmail_common::compose_store::suggestions(
            &state.mail_root,
            "example.test",
            "user",
            "ann",
            5,
        )
        .unwrap();
        assert!(
            format!("{suggested:?}").contains("ann@example.test"),
            "the new contact is suggested"
        );

        let path = format!("/api/addressbook/own:default/{name}");
        let (status, updated) = call(
            "PUT",
            path.clone(),
            json!({"full_name": "Ann Lee", "title": "CTO", "etag": etag}),
        )
        .await;
        assert_eq!(status, 200, "{updated}");
        assert_eq!(updated["title"], "CTO");
        let (status, _) = call(
            "PUT",
            path.clone(),
            json!({"full_name": "Stale", "etag": etag}),
        )
        .await;
        assert_eq!(status, 409, "an old version is not overwritten");
        let (status, _) = call(
            "PUT",
            path.clone(),
            json!({"full_name": "Ann Lee", "birthday": "soon", "etag": updated["etag"]}),
        )
        .await;
        assert_eq!(status, 400, "a new birthday must be a date");
        let (status, _) = call("PUT", path.clone(), json!({"full_name": "No etag"})).await;
        assert_eq!(status, 400);
        let (status, _) = call("DELETE", path.clone(), json!({"etag": etag})).await;
        assert_eq!(status, 409);
        let (status, _) = call("DELETE", path.clone(), json!({"etag": updated["etag"]})).await;
        assert_eq!(status, 204);
        let (_, listing) = call("GET", "/api/addressbook".into(), Value::Null).await;
        assert_eq!(listing["contacts"], json!([]));

        // A book shared read-only is listed but cannot be changed.
        db::add_mailbox(
            &state.db_path,
            "boss@example.test",
            Some("plain:x"),
            None,
            None,
        )
        .unwrap();
        let boss = open_account(&state.mail_root, "boss@example.test").unwrap();
        let book = store::collections(&boss, Kind::AddressBook)
            .unwrap()
            .remove(0);
        store::put(&boss, &book, "c.vcf", APPLE, &|_| true)
            .unwrap()
            .unwrap();
        share::set_access(
            &state.db_path,
            "boss@example.test",
            book.id,
            "user@example.test",
            Some(Access::Read),
        )
        .unwrap();
        let (_, listing) = call("GET", "/api/addressbook".into(), Value::Null).await;
        let shared = listing["books"]
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["owner"] == "boss@example.test")
            .unwrap();
        assert_eq!(shared["writable"], false);
        assert_eq!(listing["contacts"][0]["full_name"], "Søren Holm");
        assert_eq!(listing["contacts"][0]["has_photo"], true);
        let (status, _) = call(
            "POST",
            format!("/api/addressbook/{}", shared["id"].as_str().unwrap()),
            json!({"full_name": "Nope"}),
        )
        .await;
        assert_eq!(status, 403);
    }

    #[tokio::test]
    async fn the_directory_is_listed_read_only() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        rmail_common::imap_state::init_account(&state.mail_root, "example.test", "user").unwrap();
        rmail_common::directory::set_enabled(&state.db_path, "example.test", true).unwrap();
        rmail_common::directory::sync_all(&state.db_path, &state.mail_root).unwrap();
        let cookie = Some(format!(
            "{SESSION_COOKIE}={}",
            sign_session(&state, "user@example.test")
        ));
        let response = route(req("GET", "/api/addressbook", b"", cookie.clone()), &state).await;
        let listing: Value = serde_json::from_slice(&response.body).unwrap();
        let book = listing["books"]
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["id"] == "own:directory")
            .unwrap()
            .clone();
        assert_eq!(book["writable"], false);
        assert!(
            listing["contacts"]
                .to_string()
                .contains("user@example.test")
        );
        let body = json!({"full_name": "Nope"}).to_string();
        let refused = route(
            req(
                "POST",
                "/api/addressbook/own:directory",
                body.as_bytes(),
                cookie,
            ),
            &state,
        )
        .await;
        assert_eq!(refused.status, 403);
    }
}
