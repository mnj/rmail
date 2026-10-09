//! VacationResponse (RFC 8621 section 8): one object, `singleton`, per
//! account. Delivery answers with it next to the account's own Sieve script
//! (`rmail_smtpd`), with Sieve vacation's rules for whom to answer.

use rmail_common::db::{self, VacationResponse};
use rmail_common::jmap::store;
use serde_json::{Map, Value, json};

use super::identity::own_account;
use super::{
    Ctx, MethodResult, check_if_in_state, current_state, ids_arg, parse_utc_date, project,
    properties_arg, set_error, set_error_properties, utc_date,
};

const SINGLETON: &str = "singleton";
const PROPERTIES: &[&str] = &[
    "id",
    "isEnabled",
    "fromDate",
    "toDate",
    "subject",
    "textBody",
    "htmlBody",
];

fn to_json(response: &VacationResponse) -> Map<String, Value> {
    match json!({
        "id": SINGLETON,
        "isEnabled": response.enabled,
        "fromDate": response.from_date.map(utc_date),
        "toDate": response.to_date.map(utc_date),
        "subject": response.subject,
        "textBody": response.text_body,
        "htmlBody": response.html_body,
    }) {
        Value::Object(map) => map,
        _ => unreachable!(),
    }
}

pub(crate) fn get(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let account = own_account(ctx, &args)?;
    let ids = ids_arg(ctx, &args, "ids")?;
    let properties = properties_arg(&args, "properties", PROPERTIES, PROPERTIES, |_| false)?;
    let response = db::get_vacation_response(&ctx.app.db_path, &account.owner)?;
    let state = current_state(ctx, &account)?;
    let mut list = Vec::new();
    let mut not_found = Vec::new();
    for id in ids.unwrap_or_else(|| vec![SINGLETON.to_string()]) {
        if id == SINGLETON {
            list.push(project(to_json(&response), &properties));
        } else {
            not_found.push(id);
        }
    }
    Ok(vec![(
        "VacationResponse/get".to_string(),
        json!({"accountId": account.id, "state": state, "list": list, "notFound": not_found}),
    )])
}

fn apply(response: &mut VacationResponse, patch: &Map<String, Value>) -> Result<(), Value> {
    for (key, value) in patch {
        let invalid = |description: &str| {
            set_error_properties("invalidProperties", description, &[key.as_str()])
        };
        let text = || match value {
            Value::Null => Ok(None),
            Value::String(text) => Ok(Some(text.clone())),
            _ => Err(invalid("must be a string or null")),
        };
        let date = || match value {
            Value::Null => Ok(None),
            Value::String(text) => parse_utc_date(text)
                .map(Some)
                .ok_or_else(|| invalid("must be a UTCDate or null")),
            _ => Err(invalid("must be a UTCDate or null")),
        };
        match key.as_str() {
            "isEnabled" => {
                response.enabled = value
                    .as_bool()
                    .ok_or_else(|| invalid("must be a boolean"))?
            }
            "fromDate" => response.from_date = date()?,
            "toDate" => response.to_date = date()?,
            "subject" => {
                response.subject = text()?.map(|subject| subject.replace(['\r', '\n'], " "))
            }
            "textBody" => response.text_body = text()?,
            "htmlBody" => response.html_body = text()?,
            "id" if value.as_str() == Some(SINGLETON) => {}
            _ => return Err(invalid("the property cannot be set")),
        }
    }
    Ok(())
}

pub(crate) fn set(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let account = own_account(ctx, &args)?;
    let old_state = check_if_in_state(ctx, &account, &args)?;
    let mut not_created = Map::new();
    if let Some(create) = args.get("create").and_then(Value::as_object) {
        for creation_id in create.keys() {
            not_created.insert(
                creation_id.clone(),
                set_error("singleton", "the vacation response always exists"),
            );
        }
    }
    let mut not_destroyed = Map::new();
    for id in ids_arg(ctx, &args, "destroy")?.unwrap_or_default() {
        not_destroyed.insert(
            id,
            set_error("singleton", "the vacation response cannot be destroyed"),
        );
    }
    let mut updated = Map::new();
    let mut not_updated = Map::new();
    for (id, patch) in args
        .get("update")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
    {
        if id != SINGLETON {
            not_updated.insert(id, set_error("notFound", "the only id is singleton"));
            continue;
        }
        let Some(patch) = patch.as_object() else {
            not_updated.insert(id, set_error("invalidPatch", "not an object"));
            continue;
        };
        let mut response = db::get_vacation_response(&ctx.app.db_path, &account.owner)?;
        match apply(&mut response, patch) {
            Ok(()) => {
                // The change is logged first: if saving then fails, clients
                // only fetch an unchanged object, while the other order
                // could leave a saved change no client hears about.
                let conn = ctx.open(&account)?;
                store::log_change(&conn, "VacationResponse", SINGLETON, false, false)?;
                db::set_vacation_response(&ctx.app.db_path, &account.owner, &response)?;
                updated.insert(id, Value::Null);
            }
            Err(error) => {
                not_updated.insert(id, error);
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
    Ok(vec![(
        "VacationResponse/set".to_string(),
        json!({
            "accountId": account.id,
            "oldState": old_state,
            "newState": new_state,
            "created": Value::Null,
            "updated": null_if_empty(updated),
            "destroyed": Value::Null,
            "notCreated": null_if_empty(not_created),
            "notUpdated": null_if_empty(not_updated),
            "notDestroyed": null_if_empty(not_destroyed),
        }),
    )])
}
