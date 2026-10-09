//! Thread objects (RFC 8621 section 3).

use std::collections::HashSet;

use rmail_common::jmap::store;
use serde_json::{Map, Value, json};

use super::email::visible_emails;
use super::{Ctx, MethodResult, changes_response, current_state, ids_arg, project, properties_arg};

pub(crate) fn get(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let account = ctx.account(&args)?;
    let ids = ids_arg(ctx, &args, "ids")?;
    let properties = properties_arg(
        &args,
        "properties",
        &["id", "emailIds"],
        &["id", "emailIds"],
        |_| false,
    )?;
    let state = current_state(ctx, &account)?;
    let ids = match ids {
        Some(ids) => ids,
        None => {
            let mut threads = visible_emails(ctx, &account, None)?
                .into_iter()
                .map(|row| row.thread_id)
                .collect::<Vec<_>>();
            threads.sort();
            threads.dedup();
            threads
        }
    };
    let conn = ctx.open(&account)?;
    let threads = store::threads(&conn, &ids)?;
    // In a shared account a thread holds only the emails the user can read.
    let visible = if account.shared.is_some() {
        let members = threads.values().flatten().cloned().collect::<Vec<_>>();
        Some(
            visible_emails(ctx, &account, Some(&members))?
                .into_iter()
                .map(|row| row.email_id)
                .collect::<HashSet<_>>(),
        )
    } else {
        None
    };
    let mut list = Vec::new();
    let mut not_found = Vec::new();
    for id in ids {
        let emails = threads
            .get(&id)
            .map(|emails| {
                emails
                    .iter()
                    .filter(|email| {
                        visible
                            .as_ref()
                            .is_none_or(|visible| visible.contains(*email))
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if emails.is_empty() {
            not_found.push(id);
            continue;
        }
        let mut object = Map::new();
        object.insert("id".to_string(), json!(id));
        object.insert("emailIds".to_string(), json!(emails));
        list.push(project(object, &properties));
    }
    Ok(vec![(
        "Thread/get".to_string(),
        json!({"accountId": account.id, "state": state, "list": list, "notFound": not_found}),
    )])
}

pub(crate) fn changes(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let (_, response, _) =
        changes_response(ctx, &args, "Thread", |account, conn, root, changes| {
            if account.shared.is_none() {
                return Ok(());
            }
            let ids = changes
                .created
                .iter()
                .chain(&changes.updated)
                .cloned()
                .collect::<Vec<_>>();
            let members = store::threads(conn, &ids)?;
            let all = members.values().flatten().cloned().collect::<Vec<_>>();
            let readable =
                store::emails(conn, root, &account.domain, &account.localpart, Some(&all))?
                    .into_iter()
                    .filter(|row| {
                        row.copies
                            .iter()
                            .any(|copy| account.reads(&copy.mailbox_id))
                    })
                    .map(|row| row.thread_id)
                    .collect::<HashSet<_>>();
            changes.created.retain(|id| readable.contains(id));
            let (kept, hidden): (Vec<_>, Vec<_>) = changes
                .updated
                .drain(..)
                .partition(|id| readable.contains(id));
            changes.updated = kept;
            changes.destroyed.extend(hidden);
            Ok(())
        })?;
    Ok(vec![("Thread/changes".to_string(), response)])
}
