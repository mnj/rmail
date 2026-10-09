//! EmailSubmission objects (RFC 8621 section 7): sending a stored email
//! through this server's submission service, as webmail does.
//!
//! Mail is sent at once unless the envelope's `mailFrom` carries the RFC
//! 4865 `HOLDUNTIL`/`HOLDFOR` parameters: then it is held
//! (`rmail_common::hold`), `pending` until the outbound worker releases it,
//! and can be cancelled by setting `undoStatus` to `canceled` until then. Records are kept in the user's own
//! account for `/get`, `/changes` and `/query`.

use rmail_common::jmap::{
    mime::{self, HeaderForm},
    store,
};
use rusqlite::params;
use serde_json::{Map, Value, json};

use super::email::{self, visible_emails};
use super::identity::{identities, own_account};
use super::{
    Account, Ctx, MethodError, MethodResult, changes_response, check_if_in_state, current_state,
    ids_arg, new_id, project, properties_arg, query, set_error, set_error_properties, utc_date,
};

const PROPERTIES: &[&str] = &[
    "id",
    "identityId",
    "emailId",
    "threadId",
    "envelope",
    "sendAt",
    "undoStatus",
    "deliveryStatus",
    "dsnBlobIds",
    "mdnBlobIds",
];

struct Record {
    id: String,
    identity_id: String,
    email_id: String,
    thread_id: String,
    envelope: Value,
    send_at: i64,
    delivery_status: Value,
    /// `final`, `pending` (held) or `canceled`.
    undo_status: String,
    hold_id: Option<String>,
}

impl Record {
    fn to_json(&self) -> Map<String, Value> {
        match json!({
            "id": self.id,
            "identityId": self.identity_id,
            "emailId": self.email_id,
            "threadId": self.thread_id,
            "envelope": self.envelope,
            "sendAt": utc_date(self.send_at),
            "undoStatus": self.undo_status,
            "deliveryStatus": self.delivery_status,
            "dsnBlobIds": [],
            "mdnBlobIds": [],
        }) {
            Value::Object(map) => map,
            _ => unreachable!(),
        }
    }
}

fn records(ctx: &Ctx, account: &Account) -> Result<Vec<Record>, MethodError> {
    let conn = ctx.open(account)?;
    let mut statement = conn.prepare(
        "SELECT id, identity_id, email_id, thread_id, envelope, send_at, delivery_status,
                undo_status, hold_id
         FROM jmap_submissions ORDER BY send_at, id",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok(Record {
                id: row.get(0)?,
                identity_id: row.get(1)?,
                email_id: row.get(2)?,
                thread_id: row.get(3)?,
                envelope: serde_json::from_str(&row.get::<_, String>(4)?).unwrap_or(Value::Null),
                send_at: row.get(5)?,
                delivery_status: serde_json::from_str(&row.get::<_, String>(6)?)
                    .unwrap_or(Value::Null),
                undo_status: row.get(7)?,
                hold_id: row.get(8)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    // A held message the outbound worker released is no longer pending,
    // even if it could not update the record.
    let mut rows = rows;
    for record in &mut rows {
        if record.undo_status == "pending"
            && let Some(hold_id) = &record.hold_id
            && matches!(
                rmail_common::hold::get(&ctx.app.mail_root, hold_id),
                Ok(None)
            )
        {
            record.undo_status = "final".to_string();
        }
    }
    Ok(rows)
}

/// The release time the envelope's `mailFrom` parameters ask for (RFC 4865
/// HOLDUNTIL/HOLDFOR), checked against the FUTURERELEASE maximum.
fn release_time(envelope: Option<&Value>) -> Result<Option<i64>, Value> {
    let invalid =
        |description: &str| set_error_properties("invalidProperties", description, &["envelope"]);
    let Some(parameters) = envelope
        .and_then(|envelope| envelope.get("mailFrom"))
        .and_then(|from| from.get("parameters"))
        .and_then(Value::as_object)
    else {
        return Ok(None);
    };
    let now = chrono::Utc::now().timestamp();
    let mut release = None;
    for (name, value) in parameters {
        let value = value.as_str().unwrap_or_default();
        let at = if name.eq_ignore_ascii_case("HOLDFOR") {
            let seconds = value
                .parse::<i64>()
                .ok()
                .filter(|seconds| *seconds >= 0 && value.len() <= 9)
                .ok_or_else(|| invalid("HOLDFOR must be a number of seconds"))?;
            now + seconds
        } else if name.eq_ignore_ascii_case("HOLDUNTIL") {
            chrono::DateTime::parse_from_rfc3339(value)
                .map_err(|_| invalid("HOLDUNTIL must be a date-time"))?
                .timestamp()
        } else {
            return Err(invalid("unsupported mailFrom parameter"));
        };
        if release.replace(at).is_some() {
            return Err(invalid("give HOLDFOR or HOLDUNTIL, not both"));
        }
    }
    if let Some(at) = release
        && at - now > rmail_common::hold::MAX_HOLD_SECONDS
    {
        return Err(invalid("the release time is beyond maxDelayedSend"));
    }
    Ok(release.filter(|at| *at > now))
}

pub(crate) fn get(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let account = own_account(ctx, &args)?;
    let ids = ids_arg(ctx, &args, "ids")?;
    let properties = properties_arg(&args, "properties", PROPERTIES, PROPERTIES, |_| false)?;
    let records = records(ctx, &account)?;
    let state = current_state(ctx, &account)?;
    let mut list = Vec::new();
    let mut not_found = Vec::new();
    match ids {
        None => {
            for record in &records {
                list.push(project(record.to_json(), &properties));
            }
        }
        Some(ids) => {
            for id in ids {
                match records.iter().find(|record| record.id == id) {
                    Some(record) => list.push(project(record.to_json(), &properties)),
                    None => not_found.push(id),
                }
            }
        }
    }
    Ok(vec![(
        "EmailSubmission/get".to_string(),
        json!({"accountId": account.id, "state": state, "list": list, "notFound": not_found}),
    )])
}

pub(crate) fn changes(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    own_account(ctx, &args)?;
    let (_, response, _) = changes_response(ctx, &args, "EmailSubmission", |_, _, _, _| Ok(()))?;
    Ok(vec![("EmailSubmission/changes".to_string(), response)])
}

pub(crate) fn query(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let account = own_account(ctx, &args)?;
    let records = records(ctx, &account)?;
    let filter = args
        .get("filter")
        .filter(|filter| !filter.is_null())
        .cloned();
    let mut matching = Vec::new();
    for record in &records {
        let keep = match &filter {
            None => true,
            Some(filter) => query::matches(filter, &|condition| {
                for (key, value) in condition {
                    let in_list = |id: &str| {
                        value
                            .as_array()
                            .is_some_and(|ids| ids.iter().any(|item| item.as_str() == Some(id)))
                    };
                    let ok = match key.as_str() {
                        "identityIds" => in_list(&record.identity_id),
                        "emailIds" => in_list(&record.email_id),
                        "threadIds" => in_list(&record.thread_id),
                        "undoStatus" => value.as_str() == Some(record.undo_status.as_str()),
                        "before" => value
                            .as_str()
                            .and_then(super::parse_utc_date)
                            .is_some_and(|before| record.send_at < before),
                        "after" => value
                            .as_str()
                            .and_then(super::parse_utc_date)
                            .is_some_and(|after| record.send_at >= after),
                        _ => return Err(MethodError::new("unsupportedFilter")),
                    };
                    if !ok {
                        return Ok(false);
                    }
                }
                Ok(true)
            })?,
        };
        if keep {
            matching.push(record);
        }
    }
    let mut comparators = Vec::new();
    if let Some(sort) = args.get("sort").and_then(Value::as_array) {
        for comparator in sort {
            let property = comparator.get("property").and_then(Value::as_str);
            if !matches!(property, Some("emailId" | "threadId" | "sentAt")) {
                return Err(MethodError::new("unsupportedSort"));
            }
            let ascending = comparator
                .get("isAscending")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            comparators.push((property.unwrap_or_default().to_string(), ascending));
        }
    }
    // Each key in turn; a descending key reverses its own comparison only.
    matching.sort_by(|a, b| {
        for (property, ascending) in &comparators {
            let order = match property.as_str() {
                "emailId" => a.email_id.cmp(&b.email_id),
                "threadId" => a.thread_id.cmp(&b.thread_id),
                _ => a.send_at.cmp(&b.send_at),
            };
            let order = if *ascending { order } else { order.reverse() };
            if order.is_ne() {
                return order;
            }
        }
        std::cmp::Ordering::Equal
    });
    let ids = matching.iter().map(|record| record.id.clone()).collect();
    let mut response = query::page(ids, &args)?;
    response["accountId"] = json!(account.id);
    response["queryState"] = json!(current_state(ctx, &account)?);
    Ok(vec![("EmailSubmission/query".to_string(), response)])
}

/// The message without its Bcc fields, which recipients must not see.
fn without_bcc(data: &[u8]) -> Vec<u8> {
    let (head_end, separator) = match data.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(index) => (index + 2, 2),
        None => match data.windows(2).position(|w| w == b"\n\n") {
            Some(index) => (index + 1, 1),
            None => (data.len(), 0),
        },
    };
    let head = &data[..head_end];
    let mut out = Vec::with_capacity(data.len());
    let mut skipping = false;
    for line in head.split_inclusive(|byte| *byte == b'\n') {
        let continuation = line
            .first()
            .is_some_and(|byte| *byte == b' ' || *byte == b'\t');
        if !continuation {
            skipping = line.len() >= 4 && line[..4].eq_ignore_ascii_case(b"bcc:");
        }
        if !skipping {
            out.extend_from_slice(line);
        }
    }
    let _ = separator;
    out.extend_from_slice(&data[head_end..]);
    out
}

fn envelope_addresses(value: &Value) -> Option<Vec<String>> {
    value.as_array().map(|items| {
        items
            .iter()
            .filter_map(|item| item.get("email").and_then(Value::as_str))
            .map(str::to_string)
            .collect()
    })
}

/// Send one submission; returns its record.
fn submit(ctx: &mut Ctx, account: &Account, object: &Map<String, Value>) -> Result<Record, Value> {
    let Some(submission_address) = ctx.app.submission else {
        return Err(set_error(
            "forbiddenToSend",
            "sending is not configured on this server",
        ));
    };
    let identity_id = object
        .get("identityId")
        .and_then(Value::as_str)
        .and_then(|id| ctx.resolve_id(id))
        .ok_or_else(|| {
            set_error_properties(
                "invalidProperties",
                "identityId is required",
                &["identityId"],
            )
        })?;
    let identity = identities(ctx, account)
        .map_err(|error| super::server_fail(format!("{error:?}")))?
        .into_iter()
        .find(|identity| identity.id == identity_id)
        .ok_or_else(|| {
            set_error_properties("invalidProperties", "unknown identity", &["identityId"])
        })?;
    let email_id = object
        .get("emailId")
        .and_then(Value::as_str)
        .and_then(|id| ctx.resolve_id(id))
        .ok_or_else(|| {
            set_error_properties("invalidProperties", "emailId is required", &["emailId"])
        })?;
    let row = visible_emails(ctx, account, Some(std::slice::from_ref(&email_id)))
        .map_err(|error| super::server_fail(format!("{error:?}")))?
        .into_iter()
        .next()
        .ok_or_else(|| set_error("invalidEmail", "no such email"))?;
    let data = row
        .copies
        .iter()
        .find_map(|copy| std::fs::read(&copy.path).ok())
        .ok_or_else(|| set_error("invalidEmail", "the email's message is gone"))?;
    let root = mime::parse(&data);
    let addresses = |name: &str| {
        mime::header_property(&root.headers, name, HeaderForm::Addresses, true)
            .as_array()
            .map(|lists| {
                lists
                    .iter()
                    .filter_map(Value::as_array)
                    .flatten()
                    .filter_map(|address| address.get("email").and_then(Value::as_str))
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    let (mail_from, recipients) = match object.get("envelope").filter(|value| !value.is_null()) {
        Some(envelope) => {
            let mail_from = envelope
                .get("mailFrom")
                .and_then(|from| from.get("email"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    set_error_properties(
                        "invalidProperties",
                        "envelope needs mailFrom",
                        &["envelope"],
                    )
                })?
                .to_string();
            let recipients = envelope
                .get("rcptTo")
                .and_then(envelope_addresses)
                .ok_or_else(|| {
                    set_error_properties(
                        "invalidProperties",
                        "envelope needs rcptTo",
                        &["envelope"],
                    )
                })?;
            (mail_from, recipients)
        }
        None => {
            let mut recipients = Vec::new();
            for name in ["To", "Cc", "Bcc"] {
                for address in addresses(name) {
                    if !recipients
                        .iter()
                        .any(|known: &String| known.eq_ignore_ascii_case(&address))
                    {
                        recipients.push(address);
                    }
                }
            }
            (identity.email.clone(), recipients)
        }
    };
    if recipients.is_empty() {
        return Err(set_error("noRecipients", "the email has no recipients"));
    }
    if !mail_from.eq_ignore_ascii_case(&identity.email) {
        return Err(set_error(
            "forbiddenMailFrom",
            "the envelope sender must be the identity's address",
        ));
    }
    if addresses("From")
        .iter()
        .any(|from| !from.eq_ignore_ascii_case(&identity.email))
    {
        return Err(set_error(
            "forbiddenFrom",
            "the From address must be the identity's address",
        ));
    }
    let release_at = release_time(object.get("envelope"))?;
    let message = without_bcc(&data);
    let mail_root = ctx.mail_root();
    let user = ctx.user.address.clone();
    let id = new_id("S");
    let envelope = json!({
        "mailFrom": {
            "email": mail_from,
            "parameters": object
                .get("envelope")
                .and_then(|envelope| envelope.get("mailFrom"))
                .and_then(|from| from.get("parameters"))
                .cloned()
                .unwrap_or(Value::Null),
        },
        "rcptTo": recipients
            .iter()
            .map(|email| json!({"email": email, "parameters": null}))
            .collect::<Vec<_>>(),
    });
    if let Some(release_at) = release_at {
        // Held: the outbound worker submits it as this user at release.
        for address in std::iter::once(&mail_from).chain(&recipients) {
            if address.contains(['\r', '\n', '<', '>', ' ']) || !address.contains('@') {
                return Err(set_error(
                    "invalidRecipients",
                    format!("invalid address {address:?}"),
                ));
            }
        }
        if rmail_common::hold::count_for(&mail_root, &user).map_err(super::server_fail)?
            >= rmail_common::hold::MAX_HELD_PER_USER
        {
            return Err(set_error("forbiddenToSend", "too many scheduled messages"));
        }
        let held = rmail_common::hold::hold(
            &mail_root,
            rmail_common::hold::Held {
                id: String::new(),
                user,
                mail_from,
                recipients,
                release_at,
                submission_id: Some(id.clone()),
                last_error: None,
            },
            &message,
        )
        .map_err(super::server_fail)?;
        return Ok(Record {
            id,
            identity_id,
            email_id,
            thread_id: row.thread_id,
            envelope,
            send_at: release_at,
            delivery_status: Value::Null,
            undo_status: "pending".to_string(),
            hold_id: Some(held.id),
        });
    }
    let sent = tokio::runtime::Handle::current().block_on(crate::submit::submit_as(
        submission_address,
        &mail_root,
        &user,
        &mail_from,
        &recipients,
        &message,
    ));
    if let Err(error) = sent {
        let text = format!("{error:#}");
        return Err(if text.contains("recipients refused") {
            set_error("invalidRecipients", text)
        } else if error.downcast_ref::<crate::submit::Refused>().is_some() {
            set_error("forbiddenToSend", text)
        } else {
            super::server_fail(text)
        });
    }
    let mut delivery_status = Map::new();
    for recipient in &recipients {
        delivery_status.insert(
            recipient.clone(),
            json!({"smtpReply": "250 2.0.0 Queued", "delivered": "queued", "displayed": "unknown"}),
        );
    }
    Ok(Record {
        id,
        identity_id,
        email_id,
        thread_id: row.thread_id,
        envelope,
        send_at: chrono::Utc::now().timestamp(),
        delivery_status: Value::Object(delivery_status),
        undo_status: "final".to_string(),
        hold_id: None,
    })
}

fn record_submission(ctx: &Ctx, account: &Account, record: &Record) -> Result<(), MethodError> {
    let conn = ctx.open(account)?;
    conn.execute(
        "INSERT INTO jmap_submissions(id, identity_id, email_id, thread_id, envelope, send_at,
             delivery_status, undo_status, hold_id)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            record.id,
            record.identity_id,
            record.email_id,
            record.thread_id,
            record.envelope.to_string(),
            record.send_at,
            record.delivery_status.to_string(),
            record.undo_status,
            record.hold_id,
        ],
    )?;
    store::log_change(&conn, "EmailSubmission", &record.id, true, false)?;
    Ok(())
}

pub(crate) fn set(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let account = own_account(ctx, &args)?;
    let old_state = check_if_in_state(ctx, &account, &args)?;
    let mut created = Map::new();
    let mut not_created = Map::new();
    // Creation id -> email id, for onSuccessUpdateEmail/DestroyEmail.
    let mut sent = Vec::new();
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
        match submit(ctx, &account, object) {
            Ok(record) => {
                if let Err(error) = record_submission(ctx, &account, &record) {
                    webmail_log!("error", "jmap_submission_not_recorded", {
                        "user": ctx.user.address,
                        "submission": record.id,
                        "error": format!("{error:?}"),
                    });
                    // A held message has not gone anywhere yet: take it back
                    // and report the failure. Mail already sent cannot be,
                    // and hiding the send would make a retrying client send
                    // it twice, so that is reported as created.
                    if let Some(hold_id) = &record.hold_id
                        && rmail_common::hold::cancel(&ctx.app.mail_root, hold_id).unwrap_or(false)
                    {
                        not_created.insert(creation_id, super::server_fail(format!("{error:?}")));
                        continue;
                    }
                }
                ctx.created_ids
                    .insert(creation_id.clone(), record.id.clone());
                sent.push((
                    creation_id.clone(),
                    record.id.clone(),
                    record.email_id.clone(),
                ));
                created.insert(
                    creation_id,
                    json!({"id": record.id, "threadId": record.thread_id, "sendAt": utc_date(record.send_at), "undoStatus": record.undo_status}),
                );
            }
            Err(error) => {
                not_created.insert(creation_id, error);
            }
        }
    }
    let mut updated = Map::new();
    let mut not_updated = Map::new();
    let existing = records(ctx, &account)?;
    for (id, patch) in args
        .get("update")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
    {
        let id = ctx.resolve_id(&id).unwrap_or(id);
        let Some(record) = existing.iter().find(|record| record.id == id) else {
            not_updated.insert(id, set_error("notFound", "no such submission"));
            continue;
        };
        let cancel = patch.as_object().is_some_and(|patch| {
            patch.len() == 1 && patch.get("undoStatus").and_then(Value::as_str) == Some("canceled")
        });
        if !cancel {
            not_updated.insert(
                id,
                set_error_properties(
                    "invalidProperties",
                    "only undoStatus can be set, to canceled",
                    &["undoStatus"],
                ),
            );
            continue;
        }
        // Cancelling works only while the message is still held. The record
        // says `canceled` before the hold goes, so a failure in between can
        // never leave a cancelled message looking sent.
        let Some(hold_id) = record
            .hold_id
            .as_deref()
            .filter(|_| record.undo_status == "pending")
        else {
            not_updated.insert(id, set_error("cannotUnsend", "the message has been sent"));
            continue;
        };
        let conn = ctx.open(&account)?;
        conn.execute(
            "UPDATE jmap_submissions SET undo_status = 'canceled' WHERE id = ?1",
            params![id],
        )?;
        if !rmail_common::hold::cancel(&ctx.app.mail_root, hold_id).unwrap_or(false) {
            // Released meanwhile: it was sent after all.
            conn.execute(
                "UPDATE jmap_submissions SET undo_status = 'final' WHERE id = ?1",
                params![id],
            )?;
            not_updated.insert(id, set_error("cannotUnsend", "the message has been sent"));
            continue;
        }
        store::log_change(&conn, "EmailSubmission", &id, false, false)?;
        updated.insert(id, Value::Null);
    }
    let mut destroyed = Vec::new();
    let mut not_destroyed = Map::new();
    {
        let conn = ctx.open(&account)?;
        for id in ids_arg(ctx, &args, "destroy")?.unwrap_or_default() {
            if conn.execute("DELETE FROM jmap_submissions WHERE id = ?1", params![id])? == 0 {
                not_destroyed.insert(id, set_error("notFound", "no such submission"));
            } else {
                store::log_change(&conn, "EmailSubmission", &id, false, true)?;
                destroyed.push(id);
            }
        }
    }
    let new_state = current_state(ctx, &account)?;
    let null_if_empty = |map: Map<String, Value>| {
        if map.is_empty() {
            Value::Null
        } else {
            Value::Object(map)
        }
    };
    let mut responses = vec![(
        "EmailSubmission/set".to_string(),
        json!({
            "accountId": account.id,
            "oldState": old_state,
            "newState": new_state,
            "created": null_if_empty(created),
            "updated": null_if_empty(updated),
            "destroyed": if destroyed.is_empty() { Value::Null } else { json!(destroyed) },
            "notCreated": null_if_empty(not_created),
            "notUpdated": null_if_empty(not_updated),
            "notDestroyed": null_if_empty(not_destroyed),
        }),
    )];
    // The implicit Email/set (RFC 8621 section 7.5): keys and ids may be
    // `#creationId` of a submission, meaning that submission's email.
    let resolve = |key: &str| -> Option<String> {
        match key.strip_prefix('#') {
            Some(creation_id) => sent
                .iter()
                .find(|(created, _, _)| created == creation_id)
                .map(|(_, _, email_id)| email_id.clone()),
            None => sent
                .iter()
                .find(|(_, submission_id, _)| submission_id == key)
                .map(|(_, _, email_id)| email_id.clone()),
        }
    };
    let mut update = Map::new();
    if let Some(patches) = args.get("onSuccessUpdateEmail").and_then(Value::as_object) {
        for (key, patch) in patches {
            if let Some(email_id) = resolve(key) {
                update.insert(email_id, patch.clone());
            }
        }
    }
    let mut destroy = Vec::new();
    if let Some(ids) = args.get("onSuccessDestroyEmail").and_then(Value::as_array) {
        for id in ids.iter().filter_map(Value::as_str) {
            if let Some(email_id) = resolve(id) {
                destroy.push(email_id);
            }
        }
    }
    if !update.is_empty() || !destroy.is_empty() {
        let state = current_state(ctx, &account)?;
        let response = email::set_inner(ctx, &account, Map::new(), update, destroy, state)?;
        responses.push(("Email/set".to_string(), response));
    }
    Ok(responses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bcc_is_removed_with_its_continuation_lines() {
        let message =
            b"From: a@x.test\r\nBcc: b@x.test,\r\n c@x.test\r\nTo: d@x.test\r\n\r\nBcc: body\r\n";
        assert_eq!(
            without_bcc(message),
            b"From: a@x.test\r\nTo: d@x.test\r\n\r\nBcc: body\r\n"
        );
    }
}
