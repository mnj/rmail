//! Identity objects (RFC 8621 section 6): the addresses the user sends as.
//!
//! Identities are stored in the user's own account. The first request
//! creates one for the account's address; more may be added for aliases
//! that deliver to the account.

use rmail_common::db;
use rmail_common::jmap::store;
use rusqlite::{OptionalExtension, params};
use serde_json::{Map, Value, json};

use super::{
    Account, Ctx, MethodError, MethodResult, changes_response, check_if_in_state, current_state,
    ids_arg, new_id, project, properties_arg, set_error, set_error_properties,
};

const PROPERTIES: &[&str] = &[
    "id",
    "name",
    "email",
    "replyTo",
    "bcc",
    "textSignature",
    "htmlSignature",
    "mayDelete",
];

#[derive(Debug, Clone)]
pub(crate) struct Identity {
    pub id: String,
    pub name: String,
    pub email: String,
    pub reply_to: Option<Value>,
    pub bcc: Option<Value>,
    pub text_signature: String,
    pub html_signature: String,
}

impl Identity {
    fn to_json(&self) -> Map<String, Value> {
        match json!({
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "replyTo": self.reply_to,
            "bcc": self.bcc,
            "textSignature": self.text_signature,
            "htmlSignature": self.html_signature,
            "mayDelete": true,
        }) {
            Value::Object(map) => map,
            _ => unreachable!(),
        }
    }
}

/// The user's own account; identities and submissions exist only there.
pub(crate) fn own_account(
    ctx: &mut Ctx,
    args: &Map<String, Value>,
) -> Result<Account, MethodError> {
    let account = ctx.account(args)?;
    if !account.is_personal() {
        return Err(MethodError::with(
            "accountNotSupportedByMethod",
            "shared accounts have no identities or submissions",
        ));
    }
    Ok(account)
}

fn parse_json(text: Option<String>) -> Option<Value> {
    text.and_then(|text| serde_json::from_str(&text).ok())
}

pub(crate) fn identities(ctx: &Ctx, account: &Account) -> Result<Vec<Identity>, MethodError> {
    let conn = ctx.open(account)?;
    let empty: bool = conn.query_row("SELECT COUNT(*) = 0 FROM jmap_identities", [], |row| {
        row.get(0)
    })?;
    if empty {
        let id = new_id("I");
        conn.execute(
            "INSERT INTO jmap_identities(id, name, email, text_signature, html_signature)
             VALUES(?1, '', ?2, '', '')",
            params![id, ctx.user.address],
        )?;
        store::log_change(&conn, "Identity", &id, true, false)?;
    }
    let mut statement = conn.prepare(
        "SELECT id, name, email, reply_to, bcc, text_signature, html_signature
         FROM jmap_identities ORDER BY email, id",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok(Identity {
                id: row.get(0)?,
                name: row.get(1)?,
                email: row.get(2)?,
                reply_to: parse_json(row.get(3)?),
                bcc: parse_json(row.get(4)?),
                text_signature: row.get(5)?,
                html_signature: row.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub(crate) fn get(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let account = own_account(ctx, &args)?;
    let ids = ids_arg(ctx, &args, "ids")?;
    let properties = properties_arg(&args, "properties", PROPERTIES, PROPERTIES, |_| false)?;
    let identities = identities(ctx, &account)?;
    let state = current_state(ctx, &account)?;
    let mut list = Vec::new();
    let mut not_found = Vec::new();
    match ids {
        None => {
            for identity in &identities {
                list.push(project(identity.to_json(), &properties));
            }
        }
        Some(ids) => {
            for id in ids {
                match identities.iter().find(|identity| identity.id == id) {
                    Some(identity) => list.push(project(identity.to_json(), &properties)),
                    None => not_found.push(id),
                }
            }
        }
    }
    Ok(vec![(
        "Identity/get".to_string(),
        json!({"accountId": account.id, "state": state, "list": list, "notFound": not_found}),
    )])
}

pub(crate) fn changes(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    own_account(ctx, &args)?;
    let (_, response, _) = changes_response(ctx, &args, "Identity", |_, _, _, _| Ok(()))?;
    Ok(vec![("Identity/changes".to_string(), response)])
}

/// Whether the user may send as `email`: their own address, or an alias
/// that delivers to them.
fn may_send_as(ctx: &Ctx, email: &str) -> bool {
    let Ok(email) = rmail_common::domain::canonicalize_mailbox_address(email) else {
        return false;
    };
    if email.eq_ignore_ascii_case(&ctx.user.address) {
        return true;
    }
    db::get_alias_targets(&ctx.app.db_path, &email)
        .ok()
        .flatten()
        .is_some_and(|targets| {
            targets
                .iter()
                .any(|target| target.eq_ignore_ascii_case(&ctx.user.address))
        })
}

fn address_list(value: &Value, property: &str) -> Result<Option<String>, Value> {
    match value {
        Value::Null => Ok(None),
        Value::Array(items)
            if items
                .iter()
                .all(|item| item.get("email").and_then(Value::as_str).is_some()) =>
        {
            Ok(Some(value.to_string()))
        }
        _ => Err(set_error_properties(
            "invalidProperties",
            "must be a list of addresses",
            &[property],
        )),
    }
}

fn apply(
    identity: &mut (String, Option<String>, Option<String>, String, String),
    object: &Map<String, Value>,
    creating: bool,
) -> Result<(), Value> {
    for (key, value) in object {
        let text = || {
            value.as_str().map(str::to_string).ok_or_else(|| {
                set_error_properties("invalidProperties", "must be a string", &[key.as_str()])
            })
        };
        match key.as_str() {
            "name" => identity.0 = text()?,
            "replyTo" => identity.1 = address_list(value, "replyTo")?,
            "bcc" => identity.2 = address_list(value, "bcc")?,
            "textSignature" => identity.3 = text()?,
            "htmlSignature" => identity.4 = text()?,
            "email" if creating => {}
            "id" | "mayDelete" | "email" => {
                return Err(set_error_properties(
                    "invalidProperties",
                    "the property cannot be changed",
                    &[key.as_str()],
                ));
            }
            other => {
                return Err(set_error_properties(
                    "invalidProperties",
                    "unknown property",
                    &[other],
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn set(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let account = own_account(ctx, &args)?;
    identities(ctx, &account)?;
    let old_state = check_if_in_state(ctx, &account, &args)?;
    let conn = ctx.open(&account)?;
    let mut created = Map::new();
    let mut not_created = Map::new();
    for (creation_id, object) in args
        .get("create")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
    {
        let outcome = (|| {
            let object = object
                .as_object()
                .ok_or_else(|| set_error("invalidProperties", "not an object"))?;
            let email = object.get("email").and_then(Value::as_str).ok_or_else(|| {
                set_error_properties("invalidProperties", "email is required", &["email"])
            })?;
            if !may_send_as(ctx, email) {
                return Err(set_error(
                    "forbiddenFrom",
                    "you may not send as this address",
                ));
            }
            let mut fields = (String::new(), None, None, String::new(), String::new());
            apply(&mut fields, object, true)?;
            let id = new_id("I");
            conn.execute(
                "INSERT INTO jmap_identities(id, name, email, reply_to, bcc, text_signature, html_signature)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![id, fields.0, email.to_ascii_lowercase(), fields.1, fields.2, fields.3, fields.4],
            )
            .map_err(|error| super::server_fail(error.to_string()))?;
            store::log_change(&conn, "Identity", &id, true, false)
                .map_err(|error| super::server_fail(error.to_string()))?;
            Ok(id)
        })();
        match outcome {
            Ok(id) => {
                ctx.created_ids.insert(creation_id.clone(), id.clone());
                created.insert(creation_id, json!({"id": id, "mayDelete": true}));
            }
            Err(error) => {
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
        let outcome = (|| {
            let patch = patch
                .as_object()
                .ok_or_else(|| set_error("invalidPatch", "not an object"))?;
            let mut fields = conn
                .query_row(
                    "SELECT name, reply_to, bcc, text_signature, html_signature
                     FROM jmap_identities WHERE id = ?1",
                    params![id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()
                .map_err(|error| super::server_fail(error.to_string()))?
                .ok_or_else(|| set_error("notFound", "no such identity"))?;
            apply(&mut fields, patch, false)?;
            conn.execute(
                "UPDATE jmap_identities SET name = ?2, reply_to = ?3, bcc = ?4,
                     text_signature = ?5, html_signature = ?6 WHERE id = ?1",
                params![id, fields.0, fields.1, fields.2, fields.3, fields.4],
            )
            .map_err(|error| super::server_fail(error.to_string()))?;
            store::log_change(&conn, "Identity", &id, false, false)
                .map_err(|error| super::server_fail(error.to_string()))?;
            Ok(())
        })();
        match outcome {
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
    for id in ids_arg(ctx, &args, "destroy")?.unwrap_or_default() {
        let removed = conn.execute("DELETE FROM jmap_identities WHERE id = ?1", params![id])?;
        if removed == 0 {
            not_destroyed.insert(id, set_error("notFound", "no such identity"));
        } else {
            store::log_change(&conn, "Identity", &id, false, true)?;
            destroyed.push(id);
        }
    }
    drop(conn);
    let new_state = current_state(ctx, &account)?;
    let null_if_empty = |map: Map<String, Value>| {
        if map.is_empty() {
            Value::Null
        } else {
            Value::Object(map)
        }
    };
    Ok(vec![(
        "Identity/set".to_string(),
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
    )])
}
