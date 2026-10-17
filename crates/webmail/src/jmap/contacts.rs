//! JMAP for Contacts (RFC 9610): the user's CardDAV address books as
//! `AddressBook` objects and their vCards as JSContact `ContactCard`s
//! (RFC 9553), in the same store CardDAV clients and webmail use.
//!
//! - Cards are read and written through webmail's contact fields (name,
//!   emails, phones, organization, title, birthday, note, addresses), so
//!   a JMAP edit keeps every other vCard line (a photo, a client's own
//!   properties) as it was. Properties outside those fields are refused
//!   with `invalidProperties` rather than dropped.
//! - Only the user's own account has contacts; mail shared by others does
//!   not bring their address books. The directory (`rmail_common::
//!   directory`) is read-only.
//! - A card lives in one address book (`maxAddressBooksPerCard` 1), and
//!   its id names that book, so moving a card is refused.
//! - States list each address book with its sync sequence (cards) or a
//!   digest of its properties (books), so `/changes` is exact and works
//!   per book; a book removed since makes `ContactCard/changes` answer
//!   `cannotCalculateChanges`. Push does not report these types.

use std::collections::BTreeMap;

use base64::Engine;
use rmail_common::dav::store::{self, Collection, Kind, Object};
use rmail_common::dav::text::{self, Component};
use serde_json::{Map, Value, json};

use super::identity::own_account;
use super::{
    Account, Ctx, MethodError, MethodResult, fnv1a, ids_arg, project, properties_arg, set_error,
    set_error_properties, str_arg, uint_arg, utc_date,
};
use crate::api::contacts::{self as webmail, Entry, Fields, PostalAddress};

pub(crate) const CONTACTS: &str = "urn:ietf:params:jmap:contacts";

const BOOK_PROPERTIES: &[&str] = &[
    "id",
    "name",
    "description",
    "sortOrder",
    "isDefault",
    "isSubscribed",
    "shareWith",
    "myRights",
];
const CARD_PROPERTIES: &[&str] = &[
    "id",
    "addressBookIds",
    "@type",
    "version",
    "uid",
    "kind",
    "updated",
    "name",
    "emails",
    "phones",
    "organizations",
    "titles",
    "anniversaries",
    "notes",
    "addresses",
];
/// Card properties a client may send that carry nothing to store.
const IGNORED: &[&str] = &[
    "@type", "version", "id", "updated", "created", "prodId", "language",
];

/// The account capability (RFC 9610 1.3.1).
pub(crate) fn account_capability() -> Value {
    json!({ "maxAddressBooksPerCard": 1, "mayCreateAddressBook": true })
}

pub(crate) fn b64(text: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(text)
}

fn book_id(collection: &Collection) -> String {
    format!("b{}", collection.id)
}

fn card_id(collection: &Collection, name: &str) -> String {
    format!("c{}-{}", collection.id, b64(name))
}

fn parse_book_id(id: &str) -> Option<i64> {
    id.strip_prefix('b')?.parse().ok()
}

fn parse_card_id(id: &str) -> Option<(i64, String)> {
    let (book, name) = id.strip_prefix('c')?.split_once('-')?;
    let name = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(name)
        .ok()?;
    Some((book.parse().ok()?, String::from_utf8(name).ok()?))
}

/// The user's account and its store.
fn open(
    ctx: &mut Ctx,
    args: &Map<String, Value>,
) -> Result<(Account, rmail_common::sqlite_pool::SqliteConnection), MethodError> {
    let account = own_account(ctx, args)?;
    let conn = ctx.open(&account)?;
    Ok((account, conn))
}

fn books(conn: &rusqlite::Connection) -> Result<Vec<Collection>, MethodError> {
    Ok(store::collections(conn, Kind::AddressBook)?)
}

fn sort_order(collection: &Collection) -> u64 {
    collection
        .sort_order
        .as_deref()
        .and_then(|order| order.trim().parse().ok())
        .unwrap_or(0)
}

fn book_name(collection: &Collection) -> String {
    collection
        .displayname
        .clone()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| collection.name.clone())
}

fn default_book(books: &[Collection]) -> Option<&Collection> {
    books
        .iter()
        .filter(|book| !book.managed)
        .find(|book| book.name == "default")
        .or_else(|| books.iter().find(|book| !book.managed))
}

fn book_json(collection: &Collection, default: Option<i64>) -> Map<String, Value> {
    let writable = !collection.managed;
    match json!({
        "id": book_id(collection),
        "name": book_name(collection),
        "description": collection.description,
        "sortOrder": sort_order(collection),
        "isDefault": default == Some(collection.id),
        "isSubscribed": true,
        "shareWith": null,
        "myRights": {
            "mayRead": true,
            "mayWrite": writable,
            "mayShare": false,
            "mayDelete": writable,
        },
    }) {
        Value::Object(map) => map,
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// States

/// `AddressBook` state: each book with a digest of what it shows.
fn book_state(books: &[Collection]) -> String {
    let entries = books
        .iter()
        .map(|book| {
            let digest = fnv1a(
                format!(
                    "{}\u{0}{}\u{0}{}",
                    book_name(book),
                    book.description.as_deref().unwrap_or_default(),
                    sort_order(book)
                )
                .as_bytes(),
            );
            format!("{}.{digest:x}", book.id)
        })
        .collect::<Vec<_>>();
    format!("s{}", entries.join("_"))
}

/// `ContactCard` state: each book with its sync sequence.
fn card_state(books: &[Collection]) -> String {
    card_state_of(books.iter().map(|book| (book.id, book.sync_seq)))
}

pub(crate) fn card_state_of(entries: impl Iterator<Item = (i64, i64)>) -> String {
    let entries = entries
        .map(|(id, seq)| format!("{id}.{seq}"))
        .collect::<Vec<_>>();
    format!("s{}", entries.join("_"))
}

pub(crate) fn parse_state(state: &str) -> Option<BTreeMap<i64, String>> {
    let rest = state.strip_prefix('s')?;
    if rest.is_empty() {
        return Some(BTreeMap::new());
    }
    rest.split('_')
        .map(|entry| {
            let (id, value) = entry.split_once('.')?;
            Some((id.parse().ok()?, value.to_string()))
        })
        .collect()
}

pub(crate) fn since_arg(args: &Map<String, Value>) -> Result<BTreeMap<i64, String>, MethodError> {
    let since = str_arg(args, "sinceState")?
        .ok_or_else(|| MethodError::invalid("sinceState is required"))?;
    parse_state(since).ok_or_else(|| MethodError::new("cannotCalculateChanges"))
}

pub(crate) fn max_changes(args: &Map<String, Value>) -> Result<Option<usize>, MethodError> {
    match uint_arg(args, "maxChanges")? {
        Some(0) => Err(MethodError::invalid("maxChanges must be positive")),
        max => Ok(max.map(|max| max as usize)),
    }
}

pub(crate) fn null_if_empty(map: Map<String, Value>) -> Value {
    if map.is_empty() {
        Value::Null
    } else {
        Value::Object(map)
    }
}

// ---------------------------------------------------------------------------
// AddressBook

pub(crate) fn book_get(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let (account, conn) = open(ctx, &args)?;
    let ids = ids_arg(ctx, &args, "ids")?;
    let properties = properties_arg(
        &args,
        "properties",
        BOOK_PROPERTIES,
        BOOK_PROPERTIES,
        |_| false,
    )?;
    let books = books(&conn)?;
    let default = default_book(&books).map(|book| book.id);
    let mut list = Vec::new();
    let mut not_found = Vec::new();
    match ids {
        None => {
            for book in &books {
                list.push(project(book_json(book, default), &properties));
            }
        }
        Some(ids) => {
            for id in ids {
                match books
                    .iter()
                    .find(|book| Some(book.id) == parse_book_id(&id))
                {
                    Some(book) => list.push(project(book_json(book, default), &properties)),
                    None => not_found.push(id),
                }
            }
        }
    }
    Ok(vec![(
        "AddressBook/get".to_string(),
        json!({
            "accountId": account.id,
            "state": book_state(&books),
            "list": list,
            "notFound": not_found,
        }),
    )])
}

pub(crate) fn book_changes(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let (account, conn) = open(ctx, &args)?;
    let since = since_arg(&args)?;
    let max = max_changes(&args)?;
    let books = books(&conn)?;
    let now = parse_state(&book_state(&books)).unwrap_or_default();
    let mut created = Vec::new();
    let mut updated = Vec::new();
    for (id, digest) in &now {
        match since.get(id) {
            None => created.push(format!("b{id}")),
            Some(old) if old != digest => updated.push(format!("b{id}")),
            Some(_) => {}
        }
    }
    let destroyed = since
        .keys()
        .filter(|id| !now.contains_key(id))
        .map(|id| format!("b{id}"))
        .collect::<Vec<_>>();
    if max.is_some_and(|max| created.len() + updated.len() + destroyed.len() > max) {
        // Books are few; a client asking for fewer starts over.
        return Err(MethodError::new("cannotCalculateChanges"));
    }
    Ok(vec![(
        "AddressBook/changes".to_string(),
        json!({
            "accountId": account.id,
            "oldState": str_arg(&args, "sinceState")?,
            "newState": book_state(&books),
            "hasMoreChanges": false,
            "created": created,
            "updated": updated,
            "destroyed": destroyed,
            "updatedProperties": null,
        }),
    )])
}

/// Apply an AddressBook create or update to `collection`.
fn apply_book(
    conn: &rusqlite::Connection,
    collection: &Collection,
    patch: &Map<String, Value>,
) -> Result<(), Value> {
    for (key, value) in patch {
        let invalid = |description: &str| {
            set_error_properties("invalidProperties", description, &[key.as_str()])
        };
        let result = match key.as_str() {
            "name" => match value.as_str().map(str::trim) {
                Some(name) if !name.is_empty() && name.chars().count() <= 255 => {
                    store::set_property(conn, collection, store::Setting::DisplayName, Some(name))
                }
                _ => return Err(invalid("a name of 1 to 255 characters is required")),
            },
            "description" => match value {
                Value::Null => {
                    store::set_property(conn, collection, store::Setting::Description, None)
                }
                Value::String(text) if text.chars().count() <= 10_000 => {
                    store::set_property(conn, collection, store::Setting::Description, Some(text))
                }
                _ => return Err(invalid("must be a string or null")),
            },
            "sortOrder" => match value.as_u64() {
                Some(order) => store::set_property(
                    conn,
                    collection,
                    store::Setting::SortOrder,
                    Some(&order.to_string()),
                ),
                None => return Err(invalid("must be an unsigned integer")),
            },
            // Every book is shown; subscribing is the client's to remember.
            "isSubscribed" if value.is_boolean() => Ok(()),
            "shareWith" if value.is_null() => Ok(()),
            "id" | "isDefault" | "myRights" => {
                return Err(invalid("set by the server"));
            }
            _ => return Err(invalid("not a property that can be set")),
        };
        result.map_err(|error| set_error("serverFail", format!("{error:#}")))?;
    }
    Ok(())
}

pub(crate) fn book_set(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let (account, conn) = open(ctx, &args)?;
    let old_state = book_state(&books(&conn)?);
    if let Some(expected) = str_arg(&args, "ifInState")?
        && expected != old_state
    {
        return Err(MethodError::new("stateMismatch"));
    }
    let mut created = Map::new();
    let mut not_created = Map::new();
    for (creation_id, object) in args
        .get("create")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
    {
        let Some(object) = object.as_object() else {
            not_created.insert(creation_id, set_error("invalidProperties", "not an object"));
            continue;
        };
        if !object.contains_key("name") {
            not_created.insert(
                creation_id,
                set_error_properties("invalidProperties", "name is required", &["name"]),
            );
            continue;
        }
        let collection = store::create(&conn, Kind::AddressBook, &webmail::uuid(), None, &[])?;
        match apply_book(&conn, &collection, object) {
            Ok(()) => {
                let id = book_id(&collection);
                ctx.created_ids.insert(creation_id.clone(), id.clone());
                created.insert(
                    creation_id,
                    json!({
                        "id": id,
                        "isDefault": false,
                        "myRights": {"mayRead": true, "mayWrite": true, "mayShare": false, "mayDelete": true},
                    }),
                );
            }
            Err(error) => {
                store::delete_collection(&conn, &collection)?;
                not_created.insert(creation_id, error);
            }
        }
    }
    let mut updated = Map::new();
    let mut not_updated = Map::new();
    for (id, patch) in args
        .get("update")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
    {
        let id = ctx.resolve_id(&id).unwrap_or(id);
        let found = parse_book_id(&id)
            .map(|book| store::collection_by_id(&conn, book))
            .transpose()?
            .flatten()
            .filter(|book| book.kind == Kind::AddressBook);
        let Some(collection) = found else {
            not_updated.insert(id, set_error("notFound", "no such address book"));
            continue;
        };
        if collection.managed {
            not_updated.insert(
                id,
                set_error("forbidden", "this address book is kept by the server"),
            );
            continue;
        }
        let Some(patch) = patch.as_object() else {
            not_updated.insert(id, set_error("invalidPatch", "not an object"));
            continue;
        };
        match apply_book(&conn, &collection, patch) {
            Ok(()) => {
                updated.insert(id, Value::Null);
            }
            Err(error) => {
                not_updated.insert(id, error);
            }
        }
    }
    let remove_contents = super::bool_arg(&args, "onDestroyRemoveContents")?;
    let mut destroyed = Vec::new();
    let mut not_destroyed = Map::new();
    for id in ids_arg(ctx, &args, "destroy")?.unwrap_or_default() {
        let found = parse_book_id(&id)
            .map(|book| store::collection_by_id(&conn, book))
            .transpose()?
            .flatten()
            .filter(|book| book.kind == Kind::AddressBook);
        let Some(collection) = found else {
            not_destroyed.insert(id, set_error("notFound", "no such address book"));
            continue;
        };
        if collection.managed {
            not_destroyed.insert(
                id,
                set_error("forbidden", "this address book is kept by the server"),
            );
            continue;
        }
        if !remove_contents && !store::objects(&conn, &collection)?.is_empty() {
            not_destroyed.insert(
                id,
                set_error("addressBookHasContents", "the address book still has cards"),
            );
            continue;
        }
        store::delete_collection(&conn, &collection)?;
        destroyed.push(id);
    }
    Ok(vec![(
        "AddressBook/set".to_string(),
        json!({
            "accountId": account.id,
            "oldState": old_state,
            "newState": book_state(&books(&conn)?),
            "created": null_if_empty(created),
            "updated": null_if_empty(updated),
            "destroyed": if destroyed.is_empty() { Value::Null } else { json!(destroyed) },
            "notCreated": null_if_empty(not_created),
            "notUpdated": null_if_empty(not_updated),
            "notDestroyed": null_if_empty(not_destroyed),
        }),
    )])
}

// ---------------------------------------------------------------------------
// vCard <-> JSContact

fn kind_of_card(card: &Component) -> String {
    card.property("KIND")
        .or_else(|| card.property("X-ADDRESSBOOKSERVER-KIND"))
        .map(|kind| kind.value.trim().to_ascii_lowercase())
        .filter(|kind| {
            [
                "individual",
                "group",
                "org",
                "location",
                "device",
                "application",
            ]
            .contains(&kind.as_str())
        })
        .unwrap_or_else(|| "individual".to_string())
}

/// `contexts` (and a `label` for anything else) from a webmail kind.
fn contexts_of(kind: &str, object: &mut Map<String, Value>) {
    match kind {
        "" => {}
        "work" => {
            object.insert("contexts".into(), json!({"work": true}));
        }
        "home" => {
            object.insert("contexts".into(), json!({"private": true}));
        }
        other => {
            object.insert("label".into(), json!(other));
        }
    }
}

const PHONE_FEATURES: &[(&str, &str)] = &[
    ("cell", "mobile"),
    ("fax", "fax"),
    ("pager", "pager"),
    ("text", "text"),
    ("video", "video"),
    ("textphone", "textphone"),
];

fn entries_json(entries: &[Entry], prefix: &str, value_key: &str, phone: bool) -> Option<Value> {
    if entries.is_empty() {
        return None;
    }
    let mut map = Map::new();
    for (index, entry) in entries.iter().enumerate() {
        let mut object = Map::new();
        object.insert(value_key.into(), json!(entry.value));
        match PHONE_FEATURES
            .iter()
            .find(|(kind, _)| phone && *kind == entry.kind)
        {
            Some((_, feature)) => {
                object.insert("features".into(), json!({ *feature: true }));
            }
            None => contexts_of(&entry.kind, &mut object),
        }
        map.insert(format!("{prefix}{}", index + 1), Value::Object(object));
    }
    Some(Value::Object(map))
}

fn partial_date(birthday: &str) -> Option<Value> {
    let (year, rest) = match birthday.strip_prefix("--") {
        Some(rest) => (None, rest),
        None => {
            let (year, rest) = birthday.split_once('-')?;
            (Some(year.parse::<u32>().ok()?), rest)
        }
    };
    let (month, day) = rest.split_once('-')?;
    let mut date = json!({"@type": "PartialDate", "month": month.parse::<u32>().ok()?, "day": day.parse::<u32>().ok()?});
    if let Some(year) = year {
        date["year"] = json!(year);
    }
    Some(date)
}

/// The JSContact card for a stored vCard.
fn card_json(collection: &Collection, object: &Object) -> Option<Map<String, Value>> {
    let card = text::parse(&object.data).ok()?;
    let fields = webmail::fields_of(&card);
    let mut out = Map::new();
    out.insert("id".into(), json!(card_id(collection, &object.name)));
    out.insert(
        "addressBookIds".into(),
        json!({ book_id(collection): true }),
    );
    out.insert("@type".into(), json!("Card"));
    out.insert("version".into(), json!("1.0"));
    out.insert("uid".into(), json!(object.uid.clone().unwrap_or_default()));
    out.insert("kind".into(), json!(kind_of_card(&card)));
    out.insert("updated".into(), json!(utc_date(object.modified)));
    let mut name = Map::new();
    if !fields.full_name.is_empty() {
        name.insert("full".into(), json!(fields.full_name));
    }
    let components = [("given", &fields.given), ("surname", &fields.family)]
        .into_iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(kind, value)| json!({"kind": kind, "value": value}))
        .collect::<Vec<_>>();
    if !components.is_empty() {
        name.insert("components".into(), json!(components));
    }
    if !name.is_empty() {
        out.insert("name".into(), Value::Object(name));
    }
    if let Some(emails) = entries_json(&fields.emails, "e", "address", false) {
        out.insert("emails".into(), emails);
    }
    if let Some(phones) = entries_json(&fields.phones, "p", "number", true) {
        out.insert("phones".into(), phones);
    }
    if !fields.org.is_empty() {
        out.insert("organizations".into(), json!({"o1": {"name": fields.org}}));
    }
    if !fields.title.is_empty() {
        out.insert(
            "titles".into(),
            json!({"t1": {"name": fields.title, "kind": "title"}}),
        );
    }
    if let Some(date) = partial_date(&fields.birthday) {
        out.insert(
            "anniversaries".into(),
            json!({"k1": {"kind": "birth", "date": date}}),
        );
    }
    if !fields.note.is_empty() {
        out.insert("notes".into(), json!({"n1": {"note": fields.note}}));
    }
    if !fields.addresses.is_empty() {
        let mut map = Map::new();
        for (index, address) in fields.addresses.iter().enumerate() {
            let components = [
                ("name", &address.street),
                ("locality", &address.city),
                ("region", &address.region),
                ("postcode", &address.postcode),
                ("country", &address.country),
            ]
            .into_iter()
            .filter(|(_, value)| !value.is_empty())
            .map(|(kind, value)| json!({"kind": kind, "value": value}))
            .collect::<Vec<_>>();
            let mut object = Map::new();
            object.insert("components".into(), json!(components));
            contexts_of(&address.kind, &mut object);
            map.insert(format!("a{}", index + 1), Value::Object(object));
        }
        out.insert("addresses".into(), Value::Object(map));
    }
    Some(out)
}

/// Where a JSContact card cannot be stored as webmail's fields.
struct Unsupported(Vec<String>);

fn string_at<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

/// Entries of a JSContact map (`emails`, `phones`...) in id order.
fn map_entries<'a>(
    card: &'a Map<String, Value>,
    key: &str,
    bad: &mut Vec<String>,
) -> Vec<&'a Map<String, Value>> {
    match card.get(key) {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Object(map)) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            // e2 before e10.
            entries.sort_by_key(|(id, _)| {
                let digits: String = id.chars().filter(char::is_ascii_digit).collect();
                (digits.parse::<u64>().unwrap_or(u64::MAX), id.to_string())
            });
            entries
                .into_iter()
                .filter_map(|(_, value)| {
                    let object = value.as_object();
                    if object.is_none() {
                        bad.push(key.to_string());
                    }
                    object
                })
                .collect()
        }
        Some(_) => {
            bad.push(key.to_string());
            Vec::new()
        }
    }
}

/// A webmail kind from `contexts`, `features` and `label`.
fn kind_from(object: &Map<String, Value>) -> String {
    let flag = |key: &str, name: &str| {
        object
            .get(key)
            .and_then(Value::as_object)
            .is_some_and(|map| map.get(name) == Some(&Value::Bool(true)))
    };
    if let Some((kind, _)) = PHONE_FEATURES
        .iter()
        .find(|(_, feature)| flag("features", feature))
    {
        return kind.to_string();
    }
    if flag("contexts", "work") {
        return "work".to_string();
    }
    if flag("contexts", "private") {
        return "home".to_string();
    }
    string_at(object, "label")
        .map(|label| label.trim().to_ascii_lowercase())
        .unwrap_or_default()
}

fn fields_from(card: &Map<String, Value>) -> Result<Fields, Unsupported> {
    let mut bad = Vec::new();
    for key in card.keys() {
        if !CARD_PROPERTIES.contains(&key.as_str()) && !IGNORED.contains(&key.as_str()) {
            bad.push(key.clone());
        }
    }
    let mut fields = Fields::default();
    match card.get("name") {
        None | Some(Value::Null) => {}
        Some(Value::Object(name)) => {
            fields.full_name = string_at(name, "full").unwrap_or_default().to_string();
            for component in name
                .get("components")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let value = component.get("value").and_then(Value::as_str);
                match (component.get("kind").and_then(Value::as_str), value) {
                    (Some("given"), Some(value)) => fields.given = value.to_string(),
                    (Some("surname"), Some(value)) => fields.family = value.to_string(),
                    (Some("separator"), _) => {}
                    _ => bad.push("name/components".to_string()),
                }
            }
        }
        Some(_) => bad.push("name".to_string()),
    }
    fields.emails = map_entries(card, "emails", &mut bad)
        .into_iter()
        .map(|email| Entry {
            kind: kind_from(email),
            value: string_at(email, "address").unwrap_or_default().to_string(),
        })
        .collect();
    fields.phones = map_entries(card, "phones", &mut bad)
        .into_iter()
        .map(|phone| Entry {
            kind: kind_from(phone),
            value: string_at(phone, "number").unwrap_or_default().to_string(),
        })
        .collect();
    let organizations = map_entries(card, "organizations", &mut bad);
    if organizations.len() > 1 {
        bad.push("organizations".to_string());
    }
    fields.org = organizations
        .first()
        .and_then(|org| string_at(org, "name"))
        .unwrap_or_default()
        .to_string();
    let titles = map_entries(card, "titles", &mut bad);
    if titles.len() > 1 {
        bad.push("titles".to_string());
    }
    fields.title = titles
        .first()
        .and_then(|title| string_at(title, "name"))
        .unwrap_or_default()
        .to_string();
    let anniversaries = map_entries(card, "anniversaries", &mut bad);
    for anniversary in &anniversaries {
        if string_at(anniversary, "kind") != Some("birth") || anniversaries.len() > 1 {
            bad.push("anniversaries".to_string());
            continue;
        }
        let date = anniversary.get("date");
        let number = |key: &str| date.and_then(|d| d.get(key)).and_then(Value::as_u64);
        fields.birthday = match (number("year"), number("month"), number("day")) {
            (Some(year), Some(month), Some(day)) => format!("{year:04}-{month:02}-{day:02}"),
            (None, Some(month), Some(day)) => format!("--{month:02}-{day:02}"),
            _ => match date.and_then(|d| d.get("utc")).and_then(Value::as_str) {
                Some(utc) if utc.len() >= 10 => utc[..10].to_string(),
                _ => {
                    bad.push("anniversaries".to_string());
                    String::new()
                }
            },
        };
    }
    fields.note = map_entries(card, "notes", &mut bad)
        .into_iter()
        .filter_map(|note| string_at(note, "note"))
        .collect::<Vec<_>>()
        .join("\n\n");
    for address in map_entries(card, "addresses", &mut bad) {
        let mut postal = PostalAddress {
            kind: kind_from(address),
            ..PostalAddress::default()
        };
        for component in address
            .get("components")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let value = component
                .get("value")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let slot = match component.get("kind").and_then(Value::as_str) {
                Some(
                    "name" | "number" | "direction" | "building" | "floor" | "apartment" | "room",
                ) => &mut postal.street,
                Some("locality" | "district" | "subdistrict") => &mut postal.city,
                Some("region") => &mut postal.region,
                Some("postcode") => &mut postal.postcode,
                Some("country") => &mut postal.country,
                Some("separator") => continue,
                _ => {
                    bad.push("addresses".to_string());
                    continue;
                }
            };
            if !slot.is_empty() {
                slot.push(' ');
            }
            slot.push_str(&value);
        }
        fields.addresses.push(postal);
    }
    match string_at(card, "kind") {
        None | Some("individual") => {}
        Some(_) => bad.push("kind".to_string()),
    }
    if bad.is_empty() {
        Ok(fields)
    } else {
        bad.sort();
        bad.dedup();
        Err(Unsupported(bad))
    }
}

/// Apply a JMAP PatchObject (RFC 8620 5.3) to `object`.
pub(crate) fn apply_patch(
    object: &mut Map<String, Value>,
    patch: &Map<String, Value>,
) -> Result<(), String> {
    for (path, value) in patch {
        let parts = path
            .split('/')
            .map(|part| part.replace("~1", "/").replace("~0", "~"))
            .collect::<Vec<_>>();
        let (last, parents) = parts.split_last().ok_or_else(|| path.clone())?;
        let mut target = &mut *object;
        for part in parents {
            target = target
                .get_mut(part)
                .and_then(Value::as_object_mut)
                .ok_or_else(|| path.clone())?;
        }
        if value.is_null() {
            target.remove(last);
        } else {
            target.insert(last.clone(), value.clone());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ContactCard

/// Every card of the user's address books.
fn all_cards(
    conn: &rusqlite::Connection,
    books: &[Collection],
) -> Result<Vec<(Collection, Object)>, MethodError> {
    let mut out = Vec::new();
    for book in books {
        for object in store::objects(conn, book)? {
            out.push((book.clone(), object));
        }
    }
    Ok(out)
}

fn find_card(
    conn: &rusqlite::Connection,
    books: &[Collection],
    id: &str,
) -> Result<Option<(Collection, Object)>, MethodError> {
    let Some((book, name)) = parse_card_id(id) else {
        return Ok(None);
    };
    let Some(collection) = books.iter().find(|b| b.id == book) else {
        return Ok(None);
    };
    Ok(store::object(conn, collection, &name)?.map(|object| (collection.clone(), object)))
}

pub(crate) fn card_get(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let (account, conn) = open(ctx, &args)?;
    let ids = ids_arg(ctx, &args, "ids")?;
    let properties = properties_arg(
        &args,
        "properties",
        CARD_PROPERTIES,
        CARD_PROPERTIES,
        |_| true,
    )?;
    let books = books(&conn)?;
    let mut list = Vec::new();
    let mut not_found = Vec::new();
    match ids {
        None => {
            for (book, object) in all_cards(&conn, &books)? {
                if let Some(card) = card_json(&book, &object) {
                    list.push(project(card, &properties));
                }
            }
        }
        Some(ids) => {
            for id in ids {
                match find_card(&conn, &books, &id)?
                    .and_then(|(book, object)| card_json(&book, &object))
                {
                    Some(card) => list.push(project(card, &properties)),
                    None => not_found.push(id),
                }
            }
        }
    }
    Ok(vec![(
        "ContactCard/get".to_string(),
        json!({
            "accountId": account.id,
            "state": card_state(&books),
            "list": list,
            "notFound": not_found,
        }),
    )])
}

/// What changed in a set of collections since a state.
pub(crate) struct Changes {
    pub created: Vec<String>,
    pub updated: Vec<String>,
    pub destroyed: Vec<String>,
    pub new_state: String,
    pub has_more: bool,
}

/// Object changes across `collections` since the per-collection state
/// `since` (see [`card_state_of`]), at most `max`. `id` names an object.
pub(crate) fn collection_changes(
    conn: &rusqlite::Connection,
    collections: &[Collection],
    since: &BTreeMap<i64, String>,
    max: Option<usize>,
    id: impl Fn(&Collection, &str) -> String,
) -> Result<Changes, MethodError> {
    if since
        .keys()
        .any(|known| !collections.iter().any(|collection| collection.id == *known))
    {
        return Err(MethodError::new("cannotCalculateChanges"));
    }
    let mut created = Vec::new();
    let mut updated = Vec::new();
    let mut destroyed = Vec::new();
    let mut reached: Vec<(i64, i64)> = Vec::new();
    let mut has_more = false;
    for collection in collections {
        let from = match since.get(&collection.id) {
            Some(seq) => seq
                .parse::<i64>()
                .map_err(|_| MethodError::new("cannotCalculateChanges"))?,
            None => 0,
        };
        let mut at = from;
        if !has_more {
            let changes = store::object_changes(conn, collection, from)?
                .ok_or_else(|| MethodError::new("cannotCalculateChanges"))?;
            // Changes come oldest first; only the last one per object counts.
            let mut last: BTreeMap<String, &store::ObjectChange> = BTreeMap::new();
            let mut order = Vec::new();
            for change in &changes {
                if !last.contains_key(&change.name) {
                    order.push(change.name.clone());
                }
                last.insert(change.name.clone(), change);
            }
            let mut ordered = order.iter().map(|name| last[name]).collect::<Vec<_>>();
            ordered.sort_by_key(|change| change.modseq);
            for change in ordered {
                let total = created.len() + updated.len() + destroyed.len();
                if max.is_some_and(|max| total >= max) {
                    has_more = true;
                    break;
                }
                let object = id(collection, &change.name);
                let new = change.created_seq > from;
                match (change.deleted, new) {
                    (true, true) => {}
                    (true, false) => destroyed.push(object),
                    (false, true) => created.push(object),
                    (false, false) => updated.push(object),
                }
                at = change.modseq;
            }
            if !has_more {
                at = collection.sync_seq;
            }
        }
        reached.push((collection.id, at));
    }
    Ok(Changes {
        created,
        updated,
        destroyed,
        new_state: card_state_of(reached.into_iter()),
        has_more,
    })
}

pub(crate) fn card_changes(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let (account, conn) = open(ctx, &args)?;
    let since = since_arg(&args)?;
    let max = max_changes(&args)?;
    let books = books(&conn)?;
    let changes = collection_changes(&conn, &books, &since, max, card_id)?;
    Ok(vec![(
        "ContactCard/changes".to_string(),
        json!({
            "accountId": account.id,
            "oldState": str_arg(&args, "sinceState")?,
            "newState": changes.new_state,
            "hasMoreChanges": changes.has_more,
            "created": changes.created,
            "updated": changes.updated,
            "destroyed": changes.destroyed,
        }),
    )])
}

/// A card's text for `fields`, or why it cannot be saved.
fn checked(fields: Fields) -> Result<Fields, Value> {
    let fields = webmail::tidy(fields);
    webmail::check(&fields).map_err(|error| set_error("invalidProperties", error))?;
    Ok(fields)
}

fn single_book(card: &Map<String, Value>, ctx: &Ctx) -> Option<i64> {
    let ids = card.get("addressBookIds")?.as_object()?;
    let mut chosen = ids.iter().filter(|(_, on)| **on == Value::Bool(true));
    let (id, _) = chosen.next()?;
    if chosen.next().is_some() {
        return None;
    }
    parse_book_id(&ctx.resolve_id(id).unwrap_or_else(|| id.clone()))
}

pub(crate) fn card_set(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let (account, conn) = open(ctx, &args)?;
    let old_state = card_state(&books(&conn)?);
    if let Some(expected) = str_arg(&args, "ifInState")?
        && expected != old_state
    {
        return Err(MethodError::new("stateMismatch"));
    }
    let mut created = Map::new();
    let mut not_created = Map::new();
    for (creation_id, object) in args
        .get("create")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
    {
        let books = books(&conn)?;
        let Some(card) = object.as_object() else {
            not_created.insert(creation_id, set_error("invalidProperties", "not an object"));
            continue;
        };
        let Some(book) = single_book(card, ctx).and_then(|id| books.iter().find(|b| b.id == id))
        else {
            not_created.insert(
                creation_id,
                set_error_properties(
                    "invalidProperties",
                    "name exactly one of the account's address books",
                    &["addressBookIds"],
                ),
            );
            continue;
        };
        if book.managed {
            not_created.insert(
                creation_id,
                set_error("forbidden", "this address book is kept by the server"),
            );
            continue;
        }
        let fields = match fields_from(card) {
            Ok(fields) => fields,
            Err(Unsupported(properties)) => {
                let names = properties.iter().map(String::as_str).collect::<Vec<_>>();
                not_created.insert(
                    creation_id,
                    set_error_properties("invalidProperties", "not supported here", &names),
                );
                continue;
            }
        };
        if !webmail::valid_birthday(&fields.birthday) {
            not_created.insert(
                creation_id,
                set_error_properties(
                    "invalidProperties",
                    webmail::BIRTHDAY_FORMAT,
                    &["anniversaries"],
                ),
            );
            continue;
        }
        let fields = match checked(fields) {
            Ok(fields) => fields,
            Err(error) => {
                not_created.insert(creation_id, error);
                continue;
            }
        };
        let uid = match string_at(card, "uid").map(str::trim) {
            Some(uid) if !uid.is_empty() && uid.len() <= 255 && !uid.contains(['\r', '\n']) => {
                uid.to_string()
            }
            Some(_) => {
                not_created.insert(
                    creation_id,
                    set_error_properties("invalidProperties", "not a usable uid", &["uid"]),
                );
                continue;
            }
            None => format!("urn:uuid:{}", webmail::uuid()),
        };
        let name = format!("{}.vcf", webmail::uuid());
        let data = webmail::card_text(None, &fields, &uid);
        match store::put(&conn, book, &name, &data, &|current| current.is_none())? {
            Ok(_) => {
                let id = card_id(book, &name);
                ctx.created_ids.insert(creation_id.clone(), id.clone());
                created.insert(creation_id, json!({"id": id, "uid": uid}));
            }
            Err(store::PutError::UidConflict(_)) => {
                not_created.insert(
                    creation_id,
                    set_error_properties(
                        "invalidProperties",
                        "the address book has a card with this uid",
                        &["uid"],
                    ),
                );
            }
            Err(error) => {
                not_created.insert(
                    creation_id,
                    set_error("invalidProperties", format!("{error:?}")),
                );
            }
        }
    }
    let mut updated = Map::new();
    let mut not_updated = Map::new();
    for (id, patch) in args
        .get("update")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
    {
        let id = ctx.resolve_id(&id).unwrap_or(id);
        let books = books(&conn)?;
        let Some((book, object)) = find_card(&conn, &books, &id)? else {
            not_updated.insert(id, set_error("notFound", "no such card"));
            continue;
        };
        if book.managed {
            not_updated.insert(
                id,
                set_error("forbidden", "this address book is kept by the server"),
            );
            continue;
        }
        let (Some(patch), Some(mut card)) = (patch.as_object(), card_json(&book, &object)) else {
            not_updated.insert(id, set_error("invalidPatch", "not an object"));
            continue;
        };
        let before = card.clone();
        if let Err(path) = apply_patch(&mut card, patch) {
            not_updated.insert(
                id,
                set_error_properties("invalidPatch", "no such path", &[path.as_str()]),
            );
            continue;
        }
        let fixed = ["id", "uid", "addressBookIds", "kind"]
            .into_iter()
            .filter(|key| card.get(*key) != before.get(*key))
            .collect::<Vec<_>>();
        if !fixed.is_empty() {
            not_updated.insert(
                id,
                set_error_properties(
                    "invalidProperties",
                    "cannot be changed (a card stays in its address book)",
                    &fixed,
                ),
            );
            continue;
        }
        let mut fields = match fields_from(&card) {
            Ok(fields) => fields,
            Err(Unsupported(properties)) => {
                let names = properties.iter().map(String::as_str).collect::<Vec<_>>();
                not_updated.insert(
                    id,
                    set_error_properties("invalidProperties", "not supported here", &names),
                );
                continue;
            }
        };
        // A birthday JSContact could not show (a year alone, say) stays as
        // stored unless the patch sets one.
        let touches_birthday = patch
            .keys()
            .any(|key| key == "anniversaries" || key.starts_with("anniversaries/"));
        if !touches_birthday && !before.contains_key("anniversaries") {
            fields.birthday = webmail::birthday_of(&object.data).unwrap_or_default();
        }
        let kept_birthday =
            webmail::birthday_of(&object.data).as_deref() == Some(fields.birthday.as_str());
        if !kept_birthday && !webmail::valid_birthday(&fields.birthday) {
            not_updated.insert(
                id,
                set_error_properties(
                    "invalidProperties",
                    webmail::BIRTHDAY_FORMAT,
                    &["anniversaries"],
                ),
            );
            continue;
        }
        let fields = match checked(fields) {
            Ok(fields) => fields,
            Err(error) => {
                not_updated.insert(id, error);
                continue;
            }
        };
        let current = text::parse(&object.data)
            .ok()
            .map(|card| webmail::fields_of(&card));
        if current.as_ref() == Some(&fields) {
            updated.insert(id, Value::Null);
            continue;
        }
        let uid = object.uid.clone().unwrap_or_default();
        let data = webmail::card_text(Some(&object.data), &fields, &uid);
        let etag = object.etag.clone();
        match store::put(&conn, &book, &object.name, &data, &|current| {
            current.is_some_and(|current| current.etag == etag)
        })? {
            Ok(_) => {
                updated.insert(id, Value::Null);
            }
            Err(error) => {
                not_updated.insert(id, set_error("invalidProperties", format!("{error:?}")));
            }
        }
    }
    let mut destroyed = Vec::new();
    let mut not_destroyed = Map::new();
    for id in ids_arg(ctx, &args, "destroy")?.unwrap_or_default() {
        let books = books(&conn)?;
        let Some((book, object)) = find_card(&conn, &books, &id)? else {
            not_destroyed.insert(id, set_error("notFound", "no such card"));
            continue;
        };
        if book.managed {
            not_destroyed.insert(
                id,
                set_error("forbidden", "this address book is kept by the server"),
            );
            continue;
        }
        match store::delete(&conn, &book, &object.name, &|_| true)? {
            store::Deleted::Deleted(_) => destroyed.push(id),
            _ => {
                not_destroyed.insert(id, set_error("notFound", "no such card"));
            }
        }
    }
    Ok(vec![(
        "ContactCard/set".to_string(),
        json!({
            "accountId": account.id,
            "oldState": old_state,
            "newState": card_state(&books(&conn)?),
            "created": null_if_empty(created),
            "updated": null_if_empty(updated),
            "destroyed": if destroyed.is_empty() { Value::Null } else { json!(destroyed) },
            "notCreated": null_if_empty(not_created),
            "notUpdated": null_if_empty(not_updated),
            "notDestroyed": null_if_empty(not_destroyed),
        }),
    )])
}

// ---------------------------------------------------------------------------
// ContactCard/query

struct Row {
    id: String,
    book: String,
    uid: String,
    modified: i64,
    fields: Fields,
}

fn contains(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

fn matches(filter: &Map<String, Value>, row: &Row) -> Result<bool, MethodError> {
    if let Some(operator) = filter.get("operator") {
        let conditions = filter
            .get("conditions")
            .and_then(Value::as_array)
            .ok_or_else(|| MethodError::new("invalidArguments"))?;
        let mut results = Vec::new();
        for condition in conditions {
            let condition = condition
                .as_object()
                .ok_or_else(|| MethodError::new("invalidArguments"))?;
            results.push(matches(condition, row)?);
        }
        return match operator.as_str() {
            Some("AND") => Ok(results.iter().all(|r| *r)),
            Some("OR") => Ok(results.iter().any(|r| *r)),
            Some("NOT") => Ok(!results.iter().any(|r| *r)),
            _ => Err(MethodError::new("unsupportedFilter")),
        };
    }
    let fields = &row.fields;
    let name = format!("{} {} {}", fields.full_name, fields.given, fields.family);
    for (key, value) in filter {
        let text = value
            .as_str()
            .ok_or_else(|| MethodError::new("unsupportedFilter"))?;
        let ok = match key.as_str() {
            "inAddressBook" => row.book == text,
            "uid" => row.uid == text,
            "name" => contains(&name, text),
            "name/given" => contains(&fields.given, text),
            "name/surname" => contains(&fields.family, text),
            "email" => fields.emails.iter().any(|e| contains(&e.value, text)),
            "phone" => fields.phones.iter().any(|p| contains(&p.value, text)),
            "organization" => contains(&fields.org, text),
            "note" => contains(&fields.note, text),
            "text" => {
                contains(&name, text)
                    || fields.emails.iter().any(|e| contains(&e.value, text))
                    || fields.phones.iter().any(|p| contains(&p.value, text))
                    || contains(&fields.org, text)
                    || contains(&fields.title, text)
                    || contains(&fields.note, text)
            }
            _ => return Err(MethodError::new("unsupportedFilter")),
        };
        if !ok {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn card_query(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let (account, conn) = open(ctx, &args)?;
    let books = books(&conn)?;
    let mut rows = Vec::new();
    for (book, object) in all_cards(&conn, &books)? {
        let Ok(card) = text::parse(&object.data) else {
            continue;
        };
        rows.push(Row {
            id: card_id(&book, &object.name),
            book: book_id(&book),
            uid: object.uid.clone().unwrap_or_default(),
            modified: object.modified,
            fields: webmail::fields_of(&card),
        });
    }
    if let Some(filter) = args.get("filter").filter(|f| !f.is_null()) {
        let filter = filter
            .as_object()
            .ok_or_else(|| MethodError::invalid("filter must be an object"))?;
        let mut kept = Vec::new();
        for row in rows {
            if matches(filter, &row)? {
                kept.push(row);
            }
        }
        rows = kept;
    }
    let sort = args
        .get("sort")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut keys = Vec::new();
    for comparator in &sort {
        let property = comparator.get("property").and_then(Value::as_str);
        let ascending = comparator
            .get("isAscending")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        match property {
            Some(p @ ("updated" | "name/given" | "name/surname")) => keys.push((p, ascending)),
            _ => return Err(MethodError::new("unsupportedSort")),
        }
    }
    rows.sort_by(|a, b| {
        for (key, ascending) in &keys {
            let order = match *key {
                "updated" => a.modified.cmp(&b.modified),
                "name/given" => a
                    .fields
                    .given
                    .to_lowercase()
                    .cmp(&b.fields.given.to_lowercase()),
                _ => a
                    .fields
                    .family
                    .to_lowercase()
                    .cmp(&b.fields.family.to_lowercase()),
            };
            let order = if *ascending { order } else { order.reverse() };
            if order.is_ne() {
                return order;
            }
        }
        a.id.cmp(&b.id)
    });
    let ids = rows.into_iter().map(|row| row.id).collect::<Vec<_>>();
    let total = ids.len();
    let mut position = match args.get("position").and_then(Value::as_i64) {
        Some(p) if p < 0 => total.saturating_sub(p.unsigned_abs() as usize),
        Some(p) => (p as usize).min(total),
        None => 0,
    };
    if let Some(anchor) = str_arg(&args, "anchor")? {
        let index = ids
            .iter()
            .position(|id| id == anchor)
            .ok_or_else(|| MethodError::new("anchorNotFound"))?;
        let offset = args
            .get("anchorOffset")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        position = (index as i64 + offset).clamp(0, total as i64) as usize;
    }
    let limit = uint_arg(&args, "limit")?.map(|limit| limit as usize);
    let page = ids
        .iter()
        .skip(position)
        .take(limit.unwrap_or(usize::MAX))
        .cloned()
        .collect::<Vec<_>>();
    let mut response = json!({
        "accountId": account.id,
        "queryState": card_state(&books),
        "canCalculateChanges": false,
        "position": position,
        "ids": page,
    });
    if super::bool_arg(&args, "calculateTotal")? {
        response["total"] = json!(total);
    }
    Ok(vec![("ContactCard/query".to_string(), response)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_states_round_trip() {
        assert_eq!(
            parse_card_id("c12-YWJjLnZjZg"),
            Some((12, "abc.vcf".to_string()))
        );
        assert_eq!(
            parse_card_id(&format!("c3-{}", b64("x-y_z.vcf"))),
            Some((3, "x-y_z.vcf".to_string()))
        );
        assert_eq!(parse_book_id("b7"), Some(7));
        let state = card_state_of([(1, 5), (4, 9)].into_iter());
        assert_eq!(
            parse_state(&state).unwrap(),
            BTreeMap::from([(1, "5".to_string()), (4, "9".to_string())])
        );
        assert_eq!(parse_state("s").unwrap(), BTreeMap::new());
        assert!(parse_state("x").is_none());
    }

    #[test]
    fn patches_follow_paths() {
        let mut card =
            json!({"emails": {"e1": {"address": "a@x.test"}}, "notes": {"n1": {"note": "hi"}}})
                .as_object()
                .unwrap()
                .clone();
        let patch = json!({"emails/e1/address": "b@x.test", "notes": null, "phones": {"p1": {"number": "1"}}});
        apply_patch(&mut card, patch.as_object().unwrap()).unwrap();
        assert_eq!(card["emails"]["e1"]["address"], "b@x.test");
        assert!(!card.contains_key("notes"));
        assert_eq!(card["phones"]["p1"]["number"], "1");
        let bad = json!({"titles/t1/name": "x"});
        assert!(apply_patch(&mut card, bad.as_object().unwrap()).is_err());
    }
}
