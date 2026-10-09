//! Email objects (RFC 8621 section 4).
//!
//! An Email is every stored copy with one EMAILID: copies in several
//! mailboxes make one Email whose `mailboxIds` names them all. Keywords are
//! the IMAP flags; a keyword set on any copy counts, and changing keywords
//! changes every copy.

use std::collections::{HashMap, HashSet};

use rmail_common::acl::Rights;
use rmail_common::imap_state;
use rmail_common::jmap::{
    address,
    mime::{self, BodyPart, HeaderForm, HeaderProperty},
    store::{self, EmailRow},
};
use serde_json::{Map, Value, json};

use super::blob;
use super::mailbox::{self, View};
use super::{
    Account, Ctx, MAX_OBJECTS_IN_SET, MethodError, MethodResult, bool_arg, changes_response,
    check_if_in_state, current_state, flag_to_keyword, ids_arg, keyword_to_flag, set_error,
    set_error_properties, str_arg, uint_arg, utc_date, valid_keyword,
};

pub(crate) const PROPERTIES: &[&str] = &[
    "id",
    "blobId",
    "threadId",
    "mailboxIds",
    "keywords",
    "size",
    "receivedAt",
    "headers",
    "messageId",
    "inReplyTo",
    "references",
    "sender",
    "from",
    "to",
    "cc",
    "bcc",
    "replyTo",
    "subject",
    "sentAt",
    "hasAttachment",
    "preview",
    "bodyStructure",
    "bodyValues",
    "textBody",
    "htmlBody",
    "attachments",
];

const DEFAULT_PROPERTIES: &[&str] = &[
    "id",
    "blobId",
    "threadId",
    "mailboxIds",
    "keywords",
    "size",
    "receivedAt",
    "messageId",
    "inReplyTo",
    "references",
    "sender",
    "from",
    "to",
    "cc",
    "bcc",
    "replyTo",
    "subject",
    "sentAt",
    "hasAttachment",
    "preview",
    "bodyValues",
    "textBody",
    "htmlBody",
    "attachments",
];

/// Properties answered from the index without reading the message.
const INDEXED: &[&str] = &[
    "id",
    "blobId",
    "threadId",
    "mailboxIds",
    "keywords",
    "size",
    "receivedAt",
    "hasAttachment",
    "preview",
];

const BODY_PROPERTIES: &[&str] = &[
    "partId",
    "blobId",
    "size",
    "headers",
    "name",
    "type",
    "charset",
    "disposition",
    "cid",
    "language",
    "location",
    "subParts",
];

const DEFAULT_BODY_PROPERTIES: &[&str] = &[
    "partId",
    "blobId",
    "size",
    "name",
    "type",
    "charset",
    "disposition",
    "cid",
    "language",
    "location",
];

fn is_header_property(property: &str) -> bool {
    HeaderProperty::parse(property).is_some()
}

/// The emails of `account` the user may read, with only their readable
/// copies (all of them in the user's own account).
pub(crate) fn visible_emails(
    ctx: &Ctx,
    account: &Account,
    ids: Option<&[String]>,
) -> Result<Vec<EmailRow>, MethodError> {
    let conn = ctx.open(account)?;
    let mut rows = store::emails(
        &conn,
        &ctx.app.mail_root,
        &account.domain,
        &account.localpart,
        ids,
    )?;
    if account.shared.is_some() {
        for row in &mut rows {
            row.copies.retain(|copy| account.reads(&copy.mailbox_id));
        }
        rows.retain(|row| !row.copies.is_empty());
    }
    Ok(rows)
}

pub(crate) fn keywords_json(row: &EmailRow) -> Value {
    let mut keywords = Map::new();
    for flag in row.flags() {
        if let Some(keyword) = flag_to_keyword(&flag) {
            keywords.insert(keyword, Value::Bool(true));
        }
    }
    Value::Object(keywords)
}

fn mailbox_ids_json(row: &EmailRow) -> Value {
    let mut ids = Map::new();
    for copy in &row.copies {
        ids.insert(copy.mailbox_id.clone(), Value::Bool(true));
    }
    Value::Object(ids)
}

/// The blob id of a part of the message with blob id `message_blob`.
pub(crate) fn part_blob_id(message_blob: &str, part_id: &str) -> String {
    format!("{message_blob}_{part_id}")
}

/// Options for rendering body parts and values.
pub(crate) struct BodyOptions {
    pub properties: Vec<String>,
    pub fetch_text: bool,
    pub fetch_html: bool,
    pub fetch_all: bool,
    pub max_bytes: Option<usize>,
}

impl BodyOptions {
    pub fn from_args(args: &Map<String, Value>) -> Result<Self, MethodError> {
        Ok(Self {
            properties: super::properties_arg(
                args,
                "bodyProperties",
                BODY_PROPERTIES,
                DEFAULT_BODY_PROPERTIES,
                is_header_property,
            )?,
            fetch_text: bool_arg(args, "fetchTextBodyValues")?,
            fetch_html: bool_arg(args, "fetchHTMLBodyValues")?,
            fetch_all: bool_arg(args, "fetchAllBodyValues")?,
            max_bytes: uint_arg(args, "maxBodyValueBytes")?
                .filter(|max| *max > 0)
                .map(|max| max as usize),
        })
    }
}

fn cid_value(cid: &str) -> String {
    cid.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_string()
}

fn part_json(part: &BodyPart, blob_prefix: &str, properties: &[String]) -> Value {
    let mut object = Map::new();
    for property in properties {
        let value = match property.as_str() {
            "partId" => json!(part.part_id),
            "blobId" => json!(
                part.part_id
                    .as_deref()
                    .map(|id| part_blob_id(blob_prefix, id))
            ),
            "size" => json!(part.size),
            "headers" => mime::headers_json(&part.headers),
            "name" => json!(part.name),
            "type" => json!(part.content_type),
            "charset" => json!(part.charset),
            "disposition" => json!(part.disposition),
            "cid" => json!(part.cid.as_deref().map(cid_value)),
            "language" => json!(part.language),
            "location" => json!(part.location),
            "subParts" => {
                if part.is_multipart() {
                    Value::Array(
                        part.sub_parts
                            .iter()
                            .map(|child| part_json(child, blob_prefix, properties))
                            .collect(),
                    )
                } else {
                    Value::Null
                }
            }
            other => match HeaderProperty::parse(other) {
                Some(header) => {
                    mime::header_property(&part.headers, &header.name, header.form, header.all)
                }
                None => continue,
            },
        };
        object.insert(property.clone(), value);
    }
    Value::Object(object)
}

fn body_value(part: &BodyPart, data: &[u8], max_bytes: Option<usize>) -> Value {
    let mut text = part.text(data);
    let mut truncated = false;
    if let Some(max) = max_bytes
        && text.len() > max
    {
        let mut end = max;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        truncated = true;
    }
    json!({"value": text, "isEncodingProblem": false, "isTruncated": truncated})
}

/// The properties of an Email that come from parsing the message.
pub(crate) fn parsed_properties(
    data: &[u8],
    blob_id: &str,
    properties: &[String],
    body: &BodyOptions,
    object: &mut Map<String, Value>,
) {
    let root = mime::parse(data);
    let lists = mime::body_lists(&root);
    let last =
        |name: &str, form: HeaderForm| mime::header_property(&root.headers, name, form, false);
    let parts_json = |ids: &[String]| {
        Value::Array(
            ids.iter()
                .filter_map(|id| root.find(id))
                .map(|part| part_json(part, blob_id, &body.properties))
                .collect(),
        )
    };
    for property in properties {
        let value = match property.as_str() {
            "headers" => mime::headers_json(&root.headers),
            "messageId" => last("Message-ID", HeaderForm::MessageIds),
            "inReplyTo" => last("In-Reply-To", HeaderForm::MessageIds),
            "references" => last("References", HeaderForm::MessageIds),
            "sender" => last("Sender", HeaderForm::Addresses),
            "from" => last("From", HeaderForm::Addresses),
            "to" => last("To", HeaderForm::Addresses),
            "cc" => last("Cc", HeaderForm::Addresses),
            "bcc" => last("Bcc", HeaderForm::Addresses),
            "replyTo" => last("Reply-To", HeaderForm::Addresses),
            "subject" => last("Subject", HeaderForm::Text),
            "sentAt" => last("Date", HeaderForm::Date),
            "hasAttachment" => json!(mime::has_attachment(&root, &lists)),
            "preview" => json!(mime::preview(data, &root, &lists, store::PREVIEW_CHARS)),
            "bodyStructure" => part_json(&root, blob_id, &{
                let mut properties = body.properties.clone();
                if !properties.iter().any(|p| p == "subParts") {
                    properties.push("subParts".to_string());
                }
                properties
            }),
            "textBody" => parts_json(&lists.text),
            "htmlBody" => parts_json(&lists.html),
            "attachments" => parts_json(&lists.attachments),
            "bodyValues" => {
                let mut wanted: Vec<&String> = Vec::new();
                if body.fetch_all {
                    for part in root.leaves() {
                        if part.content_type.starts_with("text/") {
                            wanted.extend(part.part_id.as_ref());
                        }
                    }
                } else {
                    if body.fetch_text {
                        wanted.extend(lists.text.iter());
                    }
                    if body.fetch_html {
                        wanted.extend(lists.html.iter());
                    }
                }
                let mut values = Map::new();
                for id in wanted {
                    if let Some(part) = root.find(id)
                        && part.content_type.starts_with("text/")
                    {
                        values.insert(id.clone(), body_value(part, data, body.max_bytes));
                    }
                }
                Value::Object(values)
            }
            other => match HeaderProperty::parse(other) {
                Some(header) => {
                    mime::header_property(&root.headers, &header.name, header.form, header.all)
                }
                None => continue,
            },
        };
        object.insert(property.clone(), value);
    }
}

pub(crate) fn get(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let account = ctx.account(&args)?;
    let ids = ids_arg(ctx, &args, "ids")?;
    let properties = super::properties_arg(
        &args,
        "properties",
        PROPERTIES,
        DEFAULT_PROPERTIES,
        is_header_property,
    )?;
    let body = BodyOptions::from_args(&args)?;
    let state = current_state(ctx, &account)?;
    let rows = visible_emails(ctx, &account, ids.as_deref())?;
    let ids = match ids {
        Some(ids) => ids,
        None => {
            if rows.len() > super::MAX_OBJECTS_IN_GET {
                return Err(MethodError::new("requestTooLarge"));
            }
            rows.iter().map(|row| row.email_id.clone()).collect()
        }
    };
    let by_id = rows
        .iter()
        .map(|row| (row.email_id.as_str(), row))
        .collect::<HashMap<_, _>>();
    let needs_message = properties
        .iter()
        .any(|property| !INDEXED.contains(&property.as_str()));
    let mut list = Vec::new();
    let mut not_found = Vec::new();
    for id in ids {
        let Some(row) = by_id.get(id.as_str()) else {
            not_found.push(id);
            continue;
        };
        let mut object = Map::new();
        for property in &properties {
            let value = match property.as_str() {
                "id" => json!(row.email_id),
                "blobId" => json!(row.email_id),
                "threadId" => json!(row.thread_id),
                "mailboxIds" => mailbox_ids_json(row),
                "keywords" => keywords_json(row),
                "size" => json!(row.size),
                "receivedAt" => json!(utc_date(row.received_at)),
                "hasAttachment" => json!(row.has_attachment),
                "preview" => json!(row.preview),
                _ => continue,
            };
            object.insert(property.clone(), value);
        }
        object.insert("id".to_string(), json!(row.email_id));
        if needs_message {
            let data = row
                .copies
                .iter()
                .find_map(|copy| std::fs::read(&copy.path).ok());
            let Some(data) = data else {
                not_found.push(id);
                continue;
            };
            let remaining = properties
                .iter()
                .filter(|property| !INDEXED.contains(&property.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            parsed_properties(&data, &row.email_id, &remaining, &body, &mut object);
        }
        list.push(Value::Object(object));
    }
    Ok(vec![(
        "Email/get".to_string(),
        json!({"accountId": account.id, "state": state, "list": list, "notFound": not_found}),
    )])
}

pub(crate) fn changes(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let (_, response, _) =
        changes_response(ctx, &args, "Email", |account, conn, root, changes| {
            if account.shared.is_none() {
                return Ok(());
            }
            // An email the user cannot read is left out, or reported destroyed
            // when it was moved out of the shared mailboxes.
            let ids = changes
                .created
                .iter()
                .chain(&changes.updated)
                .cloned()
                .collect::<Vec<_>>();
            let visible =
                store::emails(conn, root, &account.domain, &account.localpart, Some(&ids))?
                    .into_iter()
                    .filter(|row| {
                        row.copies
                            .iter()
                            .any(|copy| account.reads(&copy.mailbox_id))
                    })
                    .map(|row| row.email_id)
                    .collect::<HashSet<_>>();
            changes.created.retain(|id| visible.contains(id));
            let (kept, hidden): (Vec<_>, Vec<_>) = changes
                .updated
                .drain(..)
                .partition(|id| visible.contains(id));
            changes.updated = kept;
            changes.destroyed.extend(hidden);
            Ok(())
        })?;
    Ok(vec![("Email/changes".to_string(), response)])
}

// ---------------------------------------------------------------------------
// Building messages (Email/set create)

fn folded_join(items: &[String]) -> String {
    items.join(",\r\n ")
}

fn addresses_value(value: &Value) -> Result<Vec<address::EmailAddress>, String> {
    let items = value.as_array().ok_or("addresses must be a list")?;
    items
        .iter()
        .map(|item| {
            let email = item
                .get("email")
                .and_then(Value::as_str)
                .filter(|email| !email.is_empty() && !email.contains(['\r', '\n', '<', '>']))
                .ok_or("an address needs an email")?;
            let name = match item.get("name") {
                None | Some(Value::Null) => None,
                Some(Value::String(name)) => Some(name.replace(['\r', '\n'], " ")),
                Some(_) => return Err("a name must be a string"),
            };
            Ok(address::EmailAddress {
                name,
                email: email.to_string(),
            })
        })
        .collect::<Result<_, _>>()
        .map_err(str::to_string)
}

fn format_addresses(value: &Value) -> Result<String, String> {
    Ok(folded_join(
        &addresses_value(value)?
            .iter()
            .map(address::format)
            .collect::<Vec<_>>(),
    ))
}

fn format_message_ids(value: &Value) -> Result<String, String> {
    let items = value.as_array().ok_or("message ids must be a list")?;
    let ids = items
        .iter()
        .map(|item| {
            item.as_str()
                .filter(|id| !id.is_empty() && !id.contains(['<', '>', ' ', '\r', '\n']))
                .map(|id| format!("<{id}>"))
                .ok_or("invalid message id")
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ids.join(" "))
}

fn format_date(value: &Value) -> Result<String, String> {
    let text = value.as_str().ok_or("a date must be a string")?;
    chrono::DateTime::parse_from_rfc3339(text)
        .map(|date| date.to_rfc2822())
        .map_err(|_| "invalid date".to_string())
}

/// A `header:Name[:asForm]` value to set, formatted for the wire.
fn format_header(header: &HeaderProperty, value: &Value) -> Result<Option<String>, String> {
    if header.all {
        return Err("`:all` cannot be set".to_string());
    }
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(match header.form {
        HeaderForm::Raw => {
            let raw = value.as_str().ok_or("raw values are strings")?;
            raw.trim_start().to_string()
        }
        HeaderForm::Text => mime::encode_text(value.as_str().ok_or("text values are strings")?),
        HeaderForm::Addresses => format_addresses(value)?,
        HeaderForm::GroupedAddresses => {
            let groups = value.as_array().ok_or("groups must be a list")?;
            let mut out = Vec::new();
            for group in groups {
                let addresses = format_addresses(group.get("addresses").unwrap_or(&Value::Null))?;
                match group.get("name").and_then(Value::as_str) {
                    Some(name) => {
                        out.push(format!("{}: {addresses};", address::encode_phrase(name)))
                    }
                    None => out.push(addresses),
                }
            }
            folded_join(&out)
        }
        HeaderForm::MessageIds => format_message_ids(value)?,
        HeaderForm::Date => format_date(value)?,
        HeaderForm::Urls => {
            let urls = value.as_array().ok_or("urls must be a list")?;
            urls.iter()
                .map(|url| {
                    url.as_str()
                        .map(|url| format!("<{url}>"))
                        .ok_or("invalid url")
                })
                .collect::<Result<Vec<_>, _>>()?
                .join(", ")
        }
    }))
}

fn base64_lines(data: &[u8]) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(data);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 76 * 2 + 2);
    for chunk in encoded.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push_str("\r\n");
    }
    out
}

/// Parameter `name=value`, RFC 2231 encoded when not plain ASCII.
fn parameter(name: &str, value: &str) -> String {
    if value.is_ascii() && !value.contains(['"', '\\', '\r', '\n']) {
        format!("{name}=\"{value}\"")
    } else {
        let encoded = value
            .bytes()
            .map(|byte| {
                if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                    (byte as char).to_string()
                } else {
                    format!("%{byte:02X}")
                }
            })
            .collect::<String>();
        format!("{name}*=utf-8''{encoded}")
    }
}

fn new_boundary() -> String {
    format!("=_rmail_{:032x}", rand::random::<u128>())
}

/// Builds MIME parts from `EmailBodyPart` creation objects.
struct Builder<'a> {
    body_values: &'a Map<String, Value>,
    blobs: &'a dyn Fn(&str) -> Option<Vec<u8>>,
}

impl Builder<'_> {
    fn part(&self, part: &Value, depth: usize) -> Result<String, String> {
        if depth > 10 {
            return Err("body structure too deep".to_string());
        }
        let object = part.as_object().ok_or("a body part must be an object")?;
        let content_type = object
            .get("type")
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase);
        let mut headers: Vec<String> = Vec::new();
        for (key, value) in object {
            if let Some(header) = HeaderProperty::parse(key) {
                let lower = header.name.to_ascii_lowercase();
                if lower.starts_with("content-") {
                    return Err(format!("{key} cannot be set on a body part"));
                }
                if let Some(text) = format_header(&header, value)? {
                    headers.push(format!("{}: {text}", header.name));
                }
            }
        }
        if let Some(Value::Array(sub_parts)) = object.get("subParts") {
            let content_type = content_type.unwrap_or_else(|| "multipart/mixed".to_string());
            if !content_type.starts_with("multipart/") {
                return Err("subParts need a multipart type".to_string());
            }
            let boundary = new_boundary();
            let mut out = format!(
                "Content-Type: {content_type}; boundary=\"{boundary}\"\r\n{}\r\n",
                headers
                    .iter()
                    .map(|h| format!("{h}\r\n"))
                    .collect::<String>()
            );
            for child in sub_parts {
                out.push_str(&format!("--{boundary}\r\n"));
                out.push_str(&self.part(child, depth + 1)?);
                out.push_str("\r\n");
            }
            out.push_str(&format!("--{boundary}--\r\n"));
            return Ok(out);
        }
        let (data, default_type) = match (object.get("partId"), object.get("blobId")) {
            (Some(Value::String(part_id)), None) => {
                let value = self
                    .body_values
                    .get(part_id)
                    .and_then(|value| value.get("value"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("no body value {part_id}"))?;
                (
                    value
                        .replace("\r\n", "\n")
                        .replace('\n', "\r\n")
                        .into_bytes(),
                    "text/plain",
                )
            }
            (None, Some(Value::String(blob_id))) => (
                (self.blobs)(blob_id).ok_or_else(|| format!("blob {blob_id} not found"))?,
                "application/octet-stream",
            ),
            _ => return Err("a body part needs a partId or a blobId".to_string()),
        };
        let content_type = content_type.unwrap_or_else(|| default_type.to_string());
        if content_type.starts_with("multipart/") {
            return Err("a multipart part needs subParts".to_string());
        }
        let is_text = content_type.starts_with("text/");
        let mut type_line = format!("Content-Type: {content_type}");
        if is_text {
            let charset = object
                .get("charset")
                .and_then(Value::as_str)
                .unwrap_or("utf-8");
            type_line.push_str(&format!("; charset={charset}"));
        }
        let name = object.get("name").and_then(Value::as_str);
        if let Some(name) = name {
            type_line.push_str(&format!("; {}", parameter("name", name)));
        }
        let mut out = format!("{type_line}\r\n");
        let disposition = object.get("disposition").and_then(Value::as_str);
        match (disposition, name) {
            (Some(disposition), Some(name)) => out.push_str(&format!(
                "Content-Disposition: {disposition}; {}\r\n",
                parameter("filename", name)
            )),
            (Some(disposition), None) => {
                out.push_str(&format!("Content-Disposition: {disposition}\r\n"))
            }
            (None, Some(name)) if !is_text => out.push_str(&format!(
                "Content-Disposition: attachment; {}\r\n",
                parameter("filename", name)
            )),
            _ => {}
        }
        if let Some(cid) = object.get("cid").and_then(Value::as_str) {
            out.push_str(&format!("Content-ID: <{}>\r\n", cid_value(cid)));
        }
        if let Some(language) = object.get("language").and_then(Value::as_array) {
            let tags = language
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            if !tags.is_empty() {
                out.push_str(&format!("Content-Language: {}\r\n", tags.join(", ")));
            }
        }
        if let Some(location) = object.get("location").and_then(Value::as_str) {
            out.push_str(&format!("Content-Location: {location}\r\n"));
        }
        for header in &headers {
            out.push_str(&format!("{header}\r\n"));
        }
        let plain_text = is_text
            && data.is_ascii()
            && data
                .split(|byte| *byte == b'\n')
                .all(|line| line.len() <= 998);
        if plain_text {
            out.push_str("Content-Transfer-Encoding: 7bit\r\n\r\n");
            out.push_str(std::str::from_utf8(&data).unwrap_or_default());
            if !data.ends_with(b"\r\n") {
                out.push_str("\r\n");
            }
        } else if is_text {
            out.push_str("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
            out.push_str(&rmail_common::compose::quoted_printable(
                &String::from_utf8_lossy(&data),
            ));
            out.push_str("\r\n");
        } else {
            out.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
            out.push_str(&base64_lines(&data));
        }
        Ok(out)
    }
}

/// Build a message from an Email creation object; returns it and the
/// keywords and mailbox ids it asked for.
pub(crate) fn build_message(
    object: &Map<String, Value>,
    domain: &str,
    blobs: &dyn Fn(&str) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, Value> {
    let invalid = |property: &str, description: &str| {
        set_error_properties("invalidProperties", description, &[property])
    };
    let empty = Map::new();
    let body_values = match object.get("bodyValues") {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(values)) => values,
        Some(_) => return Err(invalid("bodyValues", "must be an object")),
    };
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut set_header = |name: &str, value: String| {
        headers.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
        headers.push((name.to_string(), value));
    };
    for (property, name) in [
        ("from", "From"),
        ("sender", "Sender"),
        ("to", "To"),
        ("cc", "Cc"),
        ("bcc", "Bcc"),
        ("replyTo", "Reply-To"),
    ] {
        if let Some(value) = object.get(property).filter(|value| !value.is_null()) {
            set_header(
                name,
                format_addresses(value).map_err(|error| invalid(property, &error))?,
            );
        }
    }
    if let Some(value) = object.get("subject").filter(|value| !value.is_null()) {
        let subject = value
            .as_str()
            .ok_or_else(|| invalid("subject", "must be a string"))?;
        set_header("Subject", mime::encode_text(subject));
    }
    let date = match object.get("sentAt").filter(|value| !value.is_null()) {
        Some(value) => format_date(value).map_err(|error| invalid("sentAt", &error))?,
        None => chrono::Utc::now().to_rfc2822(),
    };
    set_header("Date", date);
    let message_id = match object.get("messageId").filter(|value| !value.is_null()) {
        Some(value) => format_message_ids(value).map_err(|error| invalid("messageId", &error))?,
        None => format!("<{:032x}@{domain}>", rand::random::<u128>()),
    };
    set_header("Message-ID", message_id);
    for (property, name) in [("inReplyTo", "In-Reply-To"), ("references", "References")] {
        if let Some(value) = object.get(property).filter(|value| !value.is_null()) {
            set_header(
                name,
                format_message_ids(value).map_err(|error| invalid(property, &error))?,
            );
        }
    }
    for (key, value) in object {
        if let Some(header) = HeaderProperty::parse(key) {
            if header.name.to_ascii_lowercase().starts_with("content-") {
                return Err(invalid(key, "set Content-* fields on body parts"));
            }
            if let Some(text) =
                format_header(&header, value).map_err(|error| invalid(key, &error))?
            {
                set_header(&header.name, text);
            }
        }
    }
    set_header("MIME-Version", "1.0".to_string());

    let builder = Builder { body_values, blobs };
    let body = if let Some(structure) = object.get("bodyStructure").filter(|value| !value.is_null())
    {
        for conflicting in ["textBody", "htmlBody", "attachments"] {
            if object
                .get(conflicting)
                .is_some_and(|value| !value.is_null())
            {
                return Err(invalid(
                    conflicting,
                    "cannot be combined with bodyStructure",
                ));
            }
        }
        builder
            .part(structure, 0)
            .map_err(|error| invalid("bodyStructure", &error))?
    } else {
        let single = |property: &str, wanted: &str| -> Result<Option<Value>, Value> {
            match object.get(property) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::Array(parts)) if parts.len() <= 1 => {
                    let Some(part) = parts.first() else {
                        return Ok(None);
                    };
                    let mut part = part.clone();
                    let kind = part.get("type").and_then(Value::as_str).unwrap_or(wanted);
                    if kind != wanted {
                        return Err(invalid(property, &format!("must be {wanted}")));
                    }
                    part["type"] = json!(wanted);
                    Ok(Some(part))
                }
                Some(_) => Err(invalid(property, "must hold at most one part")),
            }
        };
        let text = single("textBody", "text/plain")?;
        let html = single("htmlBody", "text/html")?;
        let attachments = match object.get("attachments") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(parts)) => parts.clone(),
            Some(_) => return Err(invalid("attachments", "must be a list")),
        };
        let content = match (text, html) {
            (Some(text), Some(html)) => {
                Some(json!({"type": "multipart/alternative", "subParts": [text, html]}))
            }
            (Some(part), None) | (None, Some(part)) => Some(part),
            (None, None) => None,
        };
        let structure = match (content, attachments.is_empty()) {
            (Some(content), true) => content,
            (Some(content), false) => {
                let mut parts = vec![content];
                parts.extend(attachments);
                json!({"type": "multipart/mixed", "subParts": parts})
            }
            (None, false) => json!({"type": "multipart/mixed", "subParts": attachments}),
            (None, true) => {
                json!({"type": "text/plain", "partId": "empty"})
            }
        };
        let mut values = body_values.clone();
        values.entry("empty").or_insert(json!({"value": ""}));
        let builder = Builder {
            body_values: &values,
            blobs,
        };
        builder
            .part(&structure, 0)
            .map_err(|error| invalid("textBody", &error))?
    };
    let mut message = String::new();
    for (name, value) in headers {
        message.push_str(&format!("{name}: {value}\r\n"));
    }
    message.push_str(&body);
    Ok(message.into_bytes())
}

// ---------------------------------------------------------------------------
// Email/set, Email/import, Email/copy

/// Turn `keywords` into IMAP flags, or the error.
fn flags_from_keywords(value: &Value) -> Result<Vec<String>, Value> {
    let object = value.as_object().ok_or_else(|| {
        set_error_properties(
            "invalidProperties",
            "keywords must be an object",
            &["keywords"],
        )
    })?;
    let mut flags = Vec::new();
    for (keyword, set) in object {
        if set != &Value::Bool(true) || !valid_keyword(keyword) {
            return Err(set_error_properties(
                "invalidProperties",
                "invalid keyword",
                &["keywords"],
            ));
        }
        flags.push(keyword_to_flag(keyword));
    }
    Ok(flags)
}

/// The mailboxes named by `mailboxIds`, as views, checked for the right to
/// add messages.
fn target_mailboxes(ctx: &Ctx, views: &[View], value: &Value) -> Result<Vec<View>, Value> {
    let invalid =
        |description: &str| set_error_properties("invalidProperties", description, &["mailboxIds"]);
    let object = value
        .as_object()
        .ok_or_else(|| invalid("mailboxIds must be an object"))?;
    let mut targets = Vec::new();
    for (id, set) in object {
        if set != &Value::Bool(true) {
            return Err(invalid("mailboxIds values must be true"));
        }
        let id = ctx
            .resolve_id(id)
            .ok_or_else(|| invalid("unknown mailbox"))?;
        let view = views
            .iter()
            .find(|view| view.row.mailbox_id == id)
            .ok_or_else(|| invalid("unknown mailbox"))?;
        targets.push(view.clone());
    }
    if targets.is_empty() {
        return Err(invalid("an email must be in at least one mailbox"));
    }
    Ok(targets)
}

fn storage_error(error: anyhow::Error) -> Value {
    if error
        .downcast_ref::<imap_state::StorageQuotaExceeded>()
        .is_some()
    {
        set_error("overQuota", "the account's storage quota is exceeded")
    } else {
        super::server_fail(format!("{error:#}"))
    }
}

/// Store `data` in each mailbox; returns the new EMAILID.
fn store_message(
    ctx: &Ctx,
    account: &Account,
    targets: &[View],
    data: &[u8],
    flags: &[String],
    received_at: Option<i64>,
) -> Result<String, Value> {
    for target in targets {
        if !target.rights.contains(Rights::INSERT) {
            return Err(set_error(
                "forbidden",
                "no permission to add to this mailbox",
            ));
        }
    }
    // Keywords the rights do not allow are dropped, as IMAP APPEND does.
    let first = &targets[0];
    let flags = flags
        .iter()
        .filter(|flag| account.shared.is_none() || permitted_flag(first.rights, flag))
        .cloned()
        .collect::<Vec<_>>();
    let root = ctx.mail_root();
    let (_, uid) = imap_state::append_message_with_internal_date(
        &root,
        &account.domain,
        &account.localpart,
        &first.row.name,
        data,
        flags,
        received_at.map(|at| (at, 0)),
    )
    .map_err(storage_error)?;
    for other in &targets[1..] {
        imap_state::copy_message_by_uid(
            &root,
            &account.domain,
            &account.localpart,
            &first.row.name,
            uid,
            &other.row.name,
        )
        .map_err(storage_error)?;
    }
    let conn = ctx
        .open(account)
        .map_err(|error| super::server_fail(format!("{error:?}")))?;
    store::email_id_at(&conn, &first.row.name, uid)
        .map_err(|error| super::server_fail(error.to_string()))?
        .ok_or_else(|| super::server_fail("the stored message has no id"))
}

/// Which flags `rights` allow setting (RFC 4314 section 4).
fn permitted_flag(rights: Rights, flag: &str) -> bool {
    if flag.eq_ignore_ascii_case("\\Seen") {
        rights.contains(Rights::SEEN)
    } else if flag.eq_ignore_ascii_case("\\Deleted") {
        rights.contains(Rights::DELETE_MESSAGES)
    } else {
        rights.contains(Rights::WRITE)
    }
}

/// `{id, blobId, threadId, size}` for created emails, after indexing them.
fn created_json(
    ctx: &mut Ctx,
    account: &Account,
    ids: &HashMap<String, String>,
) -> Result<Map<String, Value>, MethodError> {
    ctx.touched(account);
    let account = ctx.account_by_id(&account.id)?;
    let wanted = ids.values().cloned().collect::<Vec<_>>();
    let rows = visible_emails(ctx, &account, Some(&wanted))?;
    let mut out = Map::new();
    for (creation_id, id) in ids {
        if let Some(row) = rows.iter().find(|row| &row.email_id == id) {
            out.insert(
                creation_id.clone(),
                json!({"id": row.email_id, "blobId": row.email_id, "threadId": row.thread_id, "size": row.size}),
            );
        }
    }
    Ok(out)
}

fn null_if_empty(map: Map<String, Value>) -> Value {
    if map.is_empty() {
        Value::Null
    } else {
        Value::Object(map)
    }
}

/// Apply one update patch to an email.
fn update_email(
    ctx: &Ctx,
    account: &Account,
    views: &[View],
    row: &EmailRow,
    patch: &Map<String, Value>,
) -> Result<(), Value> {
    let invalid = |property: &str, description: &str| {
        set_error_properties("invalidProperties", description, &[property])
    };
    // Keywords: whole replacement or per-keyword patches.
    let current = row
        .flags()
        .into_iter()
        .filter(|flag| flag_to_keyword(flag).is_some())
        .collect::<Vec<_>>();
    let mut keywords: Option<Vec<String>> = None;
    let mut mailboxes: Option<HashSet<String>> = None;
    let current_mailboxes = row
        .copies
        .iter()
        .map(|copy| copy.mailbox_id.clone())
        .collect::<HashSet<_>>();
    for (key, value) in patch {
        if key == "keywords" {
            keywords = Some(flags_from_keywords(value)?);
        } else if let Some(keyword) = key.strip_prefix("keywords/") {
            if !valid_keyword(keyword) {
                return Err(invalid("keywords", "invalid keyword"));
            }
            let flag = keyword_to_flag(keyword);
            let list = keywords.get_or_insert_with(|| current.clone());
            list.retain(|existing| !existing.eq_ignore_ascii_case(&flag));
            match value {
                Value::Bool(true) => list.push(flag),
                Value::Null => {}
                _ => return Err(invalid("keywords", "a keyword patch is true or null")),
            }
        } else if key == "mailboxIds" {
            mailboxes = Some(
                target_mailboxes(ctx, views, value)?
                    .into_iter()
                    .map(|view| view.row.mailbox_id)
                    .collect(),
            );
        } else if let Some(id) = key.strip_prefix("mailboxIds/") {
            let id = ctx
                .resolve_id(id)
                .ok_or_else(|| invalid("mailboxIds", "unknown mailbox"))?;
            if !views.iter().any(|view| view.row.mailbox_id == id) {
                return Err(invalid("mailboxIds", "unknown mailbox"));
            }
            let set = mailboxes.get_or_insert_with(|| current_mailboxes.clone());
            match value {
                Value::Bool(true) => {
                    set.insert(id);
                }
                Value::Null => {
                    set.remove(&id);
                }
                _ => return Err(invalid("mailboxIds", "a mailbox patch is true or null")),
            }
        } else {
            return Err(invalid(key, "the property cannot be changed"));
        }
    }
    let rights_of = |mailbox_id: &str| {
        views
            .iter()
            .find(|view| view.row.mailbox_id == mailbox_id)
            .map(|view| view.rights)
            .unwrap_or(Rights::NONE)
    };
    let root = ctx.mail_root();
    if let Some(keywords) = &keywords {
        // Group the copies by folder for one batch per folder.
        let mut batches: HashMap<&str, Vec<(u64, Vec<String>)>> = HashMap::new();
        for copy in &row.copies {
            let rights = rights_of(&copy.mailbox_id);
            let mut flags = copy
                .flags
                .iter()
                .filter(|flag| flag_to_keyword(flag).is_none())
                .cloned()
                .collect::<Vec<_>>();
            flags.extend(keywords.iter().cloned());
            // Only flags the rights allow may change.
            let changed = |flag: &String| {
                let had = copy.flags.iter().any(|f| f.eq_ignore_ascii_case(flag));
                let has = flags.iter().any(|f| f.eq_ignore_ascii_case(flag));
                had != has
            };
            let touched = copy.flags.iter().chain(&flags).filter(|flag| changed(flag));
            for flag in touched {
                if !permitted_flag(rights, flag) {
                    return Err(set_error(
                        "forbidden",
                        "no permission to change these keywords",
                    ));
                }
            }
            batches
                .entry(&copy.folder)
                .or_default()
                .push((copy.uid, flags));
        }
        for (folder, updates) in batches {
            imap_state::set_uid_flags_batch(
                &root,
                &account.domain,
                &account.localpart,
                folder,
                &updates,
            )
            .map_err(storage_error)?;
        }
    }
    if let Some(mailboxes) = mailboxes {
        if mailboxes.is_empty() {
            return Err(invalid(
                "mailboxIds",
                "an email must be in at least one mailbox",
            ));
        }
        let source = &row.copies[0];
        for id in mailboxes.difference(&current_mailboxes) {
            let view = views
                .iter()
                .find(|view| &view.row.mailbox_id == id)
                .ok_or_else(|| invalid("mailboxIds", "unknown mailbox"))?;
            if !view.rights.contains(Rights::INSERT) {
                return Err(set_error(
                    "forbidden",
                    "no permission to add to this mailbox",
                ));
            }
            imap_state::copy_message_by_uid(
                &root,
                &account.domain,
                &account.localpart,
                &source.folder,
                source.uid,
                &view.row.name,
            )
            .map_err(storage_error)?;
        }
        for copy in &row.copies {
            if mailboxes.contains(&copy.mailbox_id) {
                continue;
            }
            if !rights_of(&copy.mailbox_id).contains(Rights::DELETE_MESSAGES.union(Rights::EXPUNGE))
            {
                return Err(set_error(
                    "forbidden",
                    "no permission to remove from this mailbox",
                ));
            }
            imap_state::delete_messages_by_uid(
                &root,
                &account.domain,
                &account.localpart,
                &copy.folder,
                &[copy.uid],
            )
            .map_err(storage_error)?;
        }
    }
    Ok(())
}

fn destroy_email(
    ctx: &Ctx,
    account: &Account,
    views: &[View],
    row: &EmailRow,
) -> Result<(), Value> {
    for copy in &row.copies {
        let rights = views
            .iter()
            .find(|view| view.row.mailbox_id == copy.mailbox_id)
            .map(|view| view.rights)
            .unwrap_or(Rights::NONE);
        if !rights.contains(Rights::DELETE_MESSAGES.union(Rights::EXPUNGE)) {
            return Err(set_error("forbidden", "no permission to remove this email"));
        }
    }
    let root = ctx.mail_root();
    for copy in &row.copies {
        imap_state::delete_messages_by_uid(
            &root,
            &account.domain,
            &account.localpart,
            &copy.folder,
            &[copy.uid],
        )
        .map_err(storage_error)?;
    }
    Ok(())
}

/// The `Email/set` work, also used by EmailSubmission and Email/copy's
/// implicit calls.
pub(crate) fn set_inner(
    ctx: &mut Ctx,
    account: &Account,
    create: Map<String, Value>,
    update: Map<String, Value>,
    destroy: Vec<String>,
    old_state: String,
) -> Result<Value, MethodError> {
    if create.len() + update.len() + destroy.len() > MAX_OBJECTS_IN_SET {
        return Err(MethodError::new("requestTooLarge"));
    }
    let views = mailbox::views(ctx, account)?;
    let mut created_ids = HashMap::new();
    let mut not_created = Map::new();
    for (creation_id, object) in create {
        let Some(object) = object.as_object() else {
            not_created.insert(creation_id, set_error("invalidProperties", "not an object"));
            continue;
        };
        for server_set in [
            "id",
            "blobId",
            "threadId",
            "size",
            "hasAttachment",
            "preview",
        ] {
            if object.contains_key(server_set) {
                not_created.insert(
                    creation_id.clone(),
                    set_error_properties("invalidProperties", "server-set property", &[server_set]),
                );
            }
        }
        if not_created.contains_key(&creation_id) {
            continue;
        }
        let outcome = (|| {
            let targets = target_mailboxes(
                ctx,
                &views,
                object.get("mailboxIds").unwrap_or(&Value::Null),
            )?;
            let flags = match object.get("keywords") {
                None | Some(Value::Null) => Vec::new(),
                Some(value) => flags_from_keywords(value)?,
            };
            let received_at = match object.get("receivedAt") {
                None | Some(Value::Null) => None,
                Some(value) => Some(value.as_str().and_then(super::parse_utc_date).ok_or_else(
                    || set_error_properties("invalidProperties", "invalid date", &["receivedAt"]),
                )?),
            };
            let blobs = |blob_id: &str| blob::blob_bytes(ctx, account, blob_id).ok().flatten();
            let data = build_message(object, &ctx.user.domain, &blobs)?;
            store_message(ctx, account, &targets, &data, &flags, received_at)
        })();
        match outcome {
            Ok(id) => {
                ctx.created_ids.insert(creation_id.clone(), id.clone());
                created_ids.insert(creation_id, id);
            }
            Err(error) => {
                not_created.insert(creation_id, error);
            }
        }
    }
    let created = created_json(ctx, account, &created_ids)?;
    let account = &ctx.account_by_id(&account.id)?;

    let mut updated = Map::new();
    let mut not_updated = Map::new();
    let update_ids = update
        .keys()
        .map(|id| ctx.resolve_id(id).unwrap_or_else(|| id.clone()))
        .collect::<Vec<_>>();
    let rows = visible_emails(ctx, account, Some(&update_ids))?;
    for (id, patch) in update {
        let id = ctx.resolve_id(&id).unwrap_or(id);
        let Some(row) = rows.iter().find(|row| row.email_id == id) else {
            not_updated.insert(id, set_error("notFound", "no such email"));
            continue;
        };
        let Some(patch) = patch.as_object() else {
            not_updated.insert(id, set_error("invalidPatch", "not an object"));
            continue;
        };
        match update_email(ctx, account, &views, row, patch) {
            Ok(()) => {
                updated.insert(id, Value::Null);
            }
            Err(error) => {
                not_updated.insert(id, error);
            }
        }
    }

    let mut destroyed = Vec::new();
    let mut not_destroyed = Map::new();
    let rows = visible_emails(ctx, account, Some(&destroy))?;
    for id in destroy {
        let Some(row) = rows.iter().find(|row| row.email_id == id) else {
            not_destroyed.insert(id, set_error("notFound", "no such email"));
            continue;
        };
        match destroy_email(ctx, account, &views, row) {
            Ok(()) => destroyed.push(id),
            Err(error) => {
                not_destroyed.insert(id, error);
            }
        }
    }
    ctx.touched(account);
    let account = ctx.account_by_id(&account.id)?;
    let new_state = current_state(ctx, &account)?;
    Ok(json!({
        "accountId": account.id,
        "oldState": old_state,
        "newState": new_state,
        "created": null_if_empty(created),
        "updated": null_if_empty(updated),
        "destroyed": if destroyed.is_empty() { Value::Null } else { json!(destroyed) },
        "notCreated": null_if_empty(not_created),
        "notUpdated": null_if_empty(not_updated),
        "notDestroyed": null_if_empty(not_destroyed),
    }))
}

pub(crate) fn set(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let account = ctx.account(&args)?;
    let old_state = check_if_in_state(ctx, &account, &args)?;
    let create = args
        .get("create")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let update = args
        .get("update")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let destroy = ids_arg(ctx, &args, "destroy")?.unwrap_or_default();
    let response = set_inner(ctx, &account, create, update, destroy, old_state)?;
    Ok(vec![("Email/set".to_string(), response)])
}

pub(crate) fn import(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let account = ctx.account(&args)?;
    let old_state = check_if_in_state(ctx, &account, &args)?;
    let emails = args
        .get("emails")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| MethodError::invalid("emails is required"))?;
    if emails.len() > MAX_OBJECTS_IN_SET {
        return Err(MethodError::new("requestTooLarge"));
    }
    let views = mailbox::views(ctx, &account)?;
    let mut created_ids = HashMap::new();
    let mut not_created = Map::new();
    for (creation_id, object) in emails {
        let outcome = (|| {
            let object = object
                .as_object()
                .ok_or_else(|| set_error("invalidProperties", "not an object"))?;
            let blob_id = object
                .get("blobId")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    set_error_properties("invalidProperties", "blobId is required", &["blobId"])
                })?;
            let blob_id = ctx
                .resolve_id(blob_id)
                .unwrap_or_else(|| blob_id.to_string());
            let data = blob::blob_bytes(ctx, &account, &blob_id)
                .map_err(|error| super::server_fail(format!("{error:?}")))?
                .ok_or_else(|| set_error("blobNotFound", "no such blob"))?;
            let targets = target_mailboxes(
                ctx,
                &views,
                object.get("mailboxIds").unwrap_or(&Value::Null),
            )?;
            let flags = match object.get("keywords") {
                None | Some(Value::Null) => Vec::new(),
                Some(value) => flags_from_keywords(value)?,
            };
            let received_at = object
                .get("receivedAt")
                .and_then(Value::as_str)
                .and_then(super::parse_utc_date);
            store_message(ctx, &account, &targets, &data, &flags, received_at)
        })();
        match outcome {
            Ok(id) => {
                ctx.created_ids.insert(creation_id.clone(), id.clone());
                created_ids.insert(creation_id, id);
            }
            Err(error) => {
                not_created.insert(creation_id, error);
            }
        }
    }
    let created = created_json(ctx, &account, &created_ids)?;
    let new_state = current_state(ctx, &account)?;
    Ok(vec![(
        "Email/import".to_string(),
        json!({
            "accountId": account.id,
            "oldState": old_state,
            "newState": new_state,
            "created": null_if_empty(created),
            "notCreated": null_if_empty(not_created),
        }),
    )])
}

pub(crate) fn copy(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let from_id = str_arg(&args, "fromAccountId")?
        .ok_or_else(|| MethodError::invalid("fromAccountId is required"))?
        .to_string();
    let from = ctx.account_by_id(&from_id)?;
    let account = ctx.account(&args)?;
    if from.id == account.id {
        return Err(MethodError::invalid(
            "fromAccountId and accountId must differ",
        ));
    }
    if let Some(expected) = str_arg(&args, "ifFromInState")?
        && expected != current_state(ctx, &from)?
    {
        return Err(MethodError::new("stateMismatch"));
    }
    let old_state = check_if_in_state(ctx, &account, &args)?;
    let create = args
        .get("create")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| MethodError::invalid("create is required"))?;
    if create.len() > MAX_OBJECTS_IN_SET {
        return Err(MethodError::new("requestTooLarge"));
    }
    let views = mailbox::views(ctx, &account)?;
    let mut created_ids = HashMap::new();
    let mut copied_from = Vec::new();
    let mut not_created = Map::new();
    for (creation_id, object) in create {
        let outcome = (|| {
            let object = object
                .as_object()
                .ok_or_else(|| set_error("invalidProperties", "not an object"))?;
            let source_id = object.get("id").and_then(Value::as_str).ok_or_else(|| {
                set_error_properties("invalidProperties", "id is required", &["id"])
            })?;
            let source = visible_emails(ctx, &from, Some(&[source_id.to_string()]))
                .map_err(|error| super::server_fail(format!("{error:?}")))?
                .into_iter()
                .next()
                .ok_or_else(|| set_error("notFound", "no such email"))?;
            let data = source
                .copies
                .iter()
                .find_map(|copy| std::fs::read(&copy.path).ok())
                .ok_or_else(|| set_error("notFound", "the email's message is gone"))?;
            let targets = target_mailboxes(
                ctx,
                &views,
                object.get("mailboxIds").unwrap_or(&Value::Null),
            )?;
            let flags = match object.get("keywords") {
                None | Some(Value::Null) => source
                    .flags()
                    .into_iter()
                    .filter(|flag| flag_to_keyword(flag).is_some())
                    .collect(),
                Some(value) => flags_from_keywords(value)?,
            };
            let received_at = object
                .get("receivedAt")
                .and_then(Value::as_str)
                .and_then(super::parse_utc_date)
                .or(Some(source.received_at));
            let id = store_message(ctx, &account, &targets, &data, &flags, received_at)?;
            Ok::<_, Value>((id, source.email_id))
        })();
        match outcome {
            Ok((id, source_id)) => {
                ctx.created_ids.insert(creation_id.clone(), id.clone());
                created_ids.insert(creation_id, id);
                copied_from.push(source_id);
            }
            Err(error) => {
                not_created.insert(creation_id, error);
            }
        }
    }
    let created = created_json(ctx, &account, &created_ids)?;
    let new_state = current_state(ctx, &account)?;
    let mut responses = vec![(
        "Email/copy".to_string(),
        json!({
            "fromAccountId": from.id,
            "accountId": account.id,
            "oldState": old_state,
            "newState": new_state,
            "created": null_if_empty(created),
            "notCreated": null_if_empty(not_created),
        }),
    )];
    if bool_arg(&args, "onSuccessDestroyOriginal")? && !copied_from.is_empty() {
        let from_state = current_state(ctx, &from)?;
        if let Some(expected) = str_arg(&args, "destroyFromIfInState")?
            && expected != from_state
        {
            responses.push(("error".to_string(), json!({"type": "stateMismatch"})));
        } else {
            let response = set_inner(ctx, &from, Map::new(), Map::new(), copied_from, from_state)?;
            responses.push(("Email/set".to_string(), response));
        }
    }
    Ok(responses)
}

pub(crate) fn parse(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let account = ctx.account(&args)?;
    let blob_ids = ids_arg(ctx, &args, "blobIds")?
        .ok_or_else(|| MethodError::invalid("blobIds is required"))?;
    let defaults = [
        "messageId",
        "inReplyTo",
        "references",
        "sender",
        "from",
        "to",
        "cc",
        "bcc",
        "replyTo",
        "subject",
        "sentAt",
        "hasAttachment",
        "preview",
        "bodyValues",
        "textBody",
        "htmlBody",
        "attachments",
    ];
    let properties = super::properties_arg(
        &args,
        "properties",
        PROPERTIES,
        &defaults,
        is_header_property,
    )?;
    let body = BodyOptions::from_args(&args)?;
    let mut parsed = Map::new();
    let mut not_parsable = Vec::new();
    let mut not_found = Vec::new();
    for blob_id in blob_ids {
        let Some(data) = blob::blob_bytes(ctx, &account, &blob_id)? else {
            not_found.push(blob_id);
            continue;
        };
        if !data
            .windows(2)
            .any(|pair| pair == b"\n\n" || pair == b":\x20")
        {
            not_parsable.push(blob_id);
            continue;
        }
        let mut object = Map::new();
        for property in &properties {
            match property.as_str() {
                "id" | "threadId" | "mailboxIds" | "keywords" | "receivedAt" => {
                    object.insert(property.clone(), Value::Null);
                }
                "blobId" => {
                    object.insert(property.clone(), json!(blob_id));
                }
                "size" => {
                    object.insert(property.clone(), json!(data.len()));
                }
                _ => {}
            }
        }
        let rest = properties
            .iter()
            .filter(|property| {
                ![
                    "id",
                    "threadId",
                    "mailboxIds",
                    "keywords",
                    "receivedAt",
                    "blobId",
                    "size",
                ]
                .contains(&property.as_str())
            })
            .cloned()
            .collect::<Vec<_>>();
        parsed_properties(&data, &blob_id, &rest, &body, &mut object);
        parsed.insert(blob_id, Value::Object(object));
    }
    Ok(vec![(
        "Email/parse".to_string(),
        json!({
            "accountId": account.id,
            "parsed": null_if_empty(parsed),
            "notParsable": not_parsable,
            "notFound": not_found,
        }),
    )])
}
