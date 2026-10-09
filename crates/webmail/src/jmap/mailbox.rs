//! Mailbox objects (RFC 8621 section 2): the account's IMAP folders, or the
//! shared ones in a shared account.

use std::collections::HashMap;

use rmail_common::acl::{self, Rights};
use rmail_common::imap_state;
use rmail_common::jmap::store::{self, MailboxRow};
use serde_json::{Map, Value, json};

use super::query;
use super::{
    Account, Ctx, MAX_OBJECTS_IN_SET, MethodError, MethodResult, bool_arg, changes_response,
    check_if_in_state, current_state, ids_arg, project, properties_arg, set_error,
    set_error_properties,
};

const PROPERTIES: &[&str] = &[
    "id",
    "name",
    "parentId",
    "role",
    "sortOrder",
    "totalEmails",
    "unreadEmails",
    "totalThreads",
    "unreadThreads",
    "myRights",
    "isSubscribed",
];

const COUNT_PROPERTIES: &[&str] = &[
    "totalEmails",
    "unreadEmails",
    "totalThreads",
    "unreadThreads",
];

/// The JMAP role of an IMAP special-use attribute (RFC 8621 section 2,
/// the IANA "IMAP Mailbox Name Attributes" registry).
fn role(row: &MailboxRow) -> Option<&'static str> {
    if row.name.eq_ignore_ascii_case("INBOX") {
        return Some("inbox");
    }
    Some(
        match row.special_use.as_deref()?.to_ascii_lowercase().as_str() {
            "\\sent" => "sent",
            "\\drafts" => "drafts",
            "\\trash" => "trash",
            "\\junk" => "junk",
            "\\archive" => "archive",
            "\\all" => "all",
            "\\flagged" => "flagged",
            "\\important" => "important",
            _ => return None,
        },
    )
}

fn special_use_for(role: &str) -> Option<&'static str> {
    Some(match role {
        "sent" => "\\Sent",
        "drafts" => "\\Drafts",
        "trash" => "\\Trash",
        "junk" => "\\Junk",
        "archive" => "\\Archive",
        _ => return None,
    })
}

fn sort_order(role: Option<&str>) -> u32 {
    match role {
        Some("inbox") => 1,
        Some("drafts") => 2,
        Some("sent") => 3,
        Some("archive") => 4,
        Some("junk") => 5,
        Some("trash") => 6,
        _ => 10,
    }
}

/// A mailbox in the user's view of an account.
#[derive(Debug, Clone)]
pub(crate) struct View {
    pub row: MailboxRow,
    pub parent_id: Option<String>,
    /// The name relative to the parent.
    pub name: String,
    pub rights: Rights,
}

impl View {
    pub fn role(&self) -> Option<&'static str> {
        role(&self.row)
    }

    fn to_json(&self, account: &Account) -> Map<String, Value> {
        let rights = self.rights;
        let inbox = self.role() == Some("inbox");
        let json = json!({
            "id": self.row.mailbox_id,
            "name": self.name,
            "parentId": self.parent_id,
            "role": self.role(),
            "sortOrder": sort_order(self.role()),
            "totalEmails": self.row.total_emails,
            "unreadEmails": self.row.unread_emails,
            "totalThreads": self.row.total_threads,
            "unreadThreads": self.row.unread_threads,
            "myRights": {
                "mayReadItems": rights.contains(Rights::READ),
                "mayAddItems": rights.contains(Rights::INSERT),
                "mayRemoveItems": rights.contains(Rights::DELETE_MESSAGES.union(Rights::EXPUNGE)),
                "maySetSeen": rights.contains(Rights::SEEN),
                "maySetKeywords": rights.contains(Rights::WRITE),
                "mayCreateChild": rights.contains(Rights::CREATE),
                "mayRename": rights.contains(Rights::DELETE_MAILBOX) && !inbox,
                "mayDelete": rights.contains(Rights::DELETE_MAILBOX) && !inbox,
                "maySubmit": account.is_personal(),
            },
            "isSubscribed": self.row.subscribed,
        });
        match json {
            Value::Object(map) => map,
            _ => unreachable!(),
        }
    }
}

/// The mailboxes of `account` the user may list, with their tree.
pub(crate) fn views(ctx: &Ctx, account: &Account) -> Result<Vec<View>, MethodError> {
    let conn = ctx.open(account)?;
    let rows = store::mailboxes(&conn)?
        .into_iter()
        .filter(|row| account.lists(&row.mailbox_id))
        .map(|mut row| {
            // Subscriptions are the owner's; a grantee's shared mailboxes
            // are always subscribed.
            row.subscribed |= !account.is_personal();
            row
        })
        .collect::<Vec<_>>();
    let by_name = rows
        .iter()
        .map(|row| (row.name.clone(), row.mailbox_id.clone()))
        .collect::<HashMap<_, _>>();
    Ok(rows
        .iter()
        .map(|row| {
            // The nearest listed ancestor is the parent.
            let mut parent = None;
            let mut prefix = row.name.as_str();
            while let Some((head, _)) = prefix.rsplit_once('/') {
                if let Some(id) = by_name.get(head) {
                    parent = Some((head.to_string(), id.clone()));
                    break;
                }
                prefix = head;
            }
            let name = match &parent {
                Some((parent_name, _)) => row.name[parent_name.len() + 1..].to_string(),
                None => row.name.clone(),
            };
            View {
                rights: account.rights(&row.mailbox_id),
                parent_id: parent.map(|(_, id)| id),
                name,
                row: row.clone(),
            }
        })
        .collect())
}

pub(crate) fn get(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let account = ctx.account(&args)?;
    let ids = ids_arg(ctx, &args, "ids")?;
    let properties = properties_arg(&args, "properties", PROPERTIES, PROPERTIES, |_| false)?;
    let views = views(ctx, &account)?;
    let state = current_state(ctx, &account)?;
    let mut list = Vec::new();
    let mut not_found = Vec::new();
    match ids {
        None => {
            for view in &views {
                list.push(project(view.to_json(&account), &properties));
            }
        }
        Some(ids) => {
            for id in ids {
                match views.iter().find(|view| view.row.mailbox_id == id) {
                    Some(view) => list.push(project(view.to_json(&account), &properties)),
                    None => not_found.push(id),
                }
            }
        }
    }
    Ok(vec![(
        "Mailbox/get".to_string(),
        json!({"accountId": account.id, "state": state, "list": list, "notFound": not_found}),
    )])
}

pub(crate) fn changes(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let (_, mut response, counts_only) =
        changes_response(ctx, &args, "Mailbox", |account, _, _, changes| {
            if account.shared.is_some() {
                changes.created.retain(|id| account.lists(id));
                let (kept, hidden): (Vec<_>, Vec<_>) =
                    changes.updated.drain(..).partition(|id| account.lists(id));
                changes.updated = kept;
                changes.destroyed.extend(hidden);
            }
            Ok(())
        })?;
    response["updatedProperties"] = if counts_only {
        json!(COUNT_PROPERTIES)
    } else {
        Value::Null
    };
    Ok(vec![("Mailbox/changes".to_string(), response)])
}

fn matches_condition(view: &View, condition: &Map<String, Value>) -> Result<bool, MethodError> {
    for (key, value) in condition {
        let ok = match key.as_str() {
            "parentId" => match value {
                Value::Null => view.parent_id.is_none(),
                Value::String(id) => view.parent_id.as_deref() == Some(id),
                _ => return Err(MethodError::new("unsupportedFilter")),
            },
            "name" => {
                let needle = value
                    .as_str()
                    .ok_or_else(|| MethodError::new("unsupportedFilter"))?;
                view.name.to_lowercase().contains(&needle.to_lowercase())
            }
            "role" => match value {
                Value::Null => view.role().is_none(),
                Value::String(role) => view.role() == Some(role.as_str()),
                _ => return Err(MethodError::new("unsupportedFilter")),
            },
            "hasAnyRole" => {
                value
                    .as_bool()
                    .ok_or_else(|| MethodError::new("unsupportedFilter"))?
                    == view.role().is_some()
            }
            "isSubscribed" => {
                value
                    .as_bool()
                    .ok_or_else(|| MethodError::new("unsupportedFilter"))?
                    == view.row.subscribed
            }
            _ => return Err(MethodError::new("unsupportedFilter")),
        };
        if !ok {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn query(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let account = ctx.account(&args)?;
    let views = views(ctx, &account)?;
    let filter = args.get("filter").filter(|filter| !filter.is_null());
    let mut matching = Vec::new();
    for view in &views {
        let keep = match filter {
            None => true,
            Some(filter) => {
                query::matches(filter, &|condition| matches_condition(view, condition))?
            }
        };
        if keep {
            matching.push(view);
        }
    }
    if bool_arg(&args, "filterAsTree")? && filter.is_some() {
        // A mailbox whose parent does not match is left out too.
        let kept = matching
            .iter()
            .map(|view| view.row.mailbox_id.clone())
            .collect::<std::collections::HashSet<_>>();
        matching.retain(|view| {
            let mut parent = view.parent_id.clone();
            while let Some(id) = parent {
                if !kept.contains(&id) {
                    return false;
                }
                parent = views
                    .iter()
                    .find(|candidate| candidate.row.mailbox_id == id)
                    .and_then(|candidate| candidate.parent_id.clone());
            }
            true
        });
    }
    let mut sort_keys: Vec<(String, bool)> = Vec::new();
    if let Some(sort) = args.get("sort").filter(|sort| !sort.is_null()) {
        for comparator in sort
            .as_array()
            .ok_or_else(|| MethodError::invalid("sort must be a list"))?
        {
            let property = comparator
                .get("property")
                .and_then(Value::as_str)
                .ok_or_else(|| MethodError::invalid("a comparator needs a property"))?;
            if !["sortOrder", "name"].contains(&property) {
                return Err(MethodError::new("unsupportedSort"));
            }
            let ascending = comparator
                .get("isAscending")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            sort_keys.push((property.to_string(), ascending));
        }
    }
    let compare = |a: &&View, b: &&View| {
        for (property, ascending) in &sort_keys {
            let order = match property.as_str() {
                "sortOrder" => sort_order(a.role()).cmp(&sort_order(b.role())),
                _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            };
            let order = if *ascending { order } else { order.reverse() };
            if order.is_ne() {
                return order;
            }
        }
        a.row.name.cmp(&b.row.name)
    };
    matching.sort_by(compare);
    if bool_arg(&args, "sortAsTree")? {
        // Each parent comes before its children, siblings in sort order.
        let mut ordered = Vec::new();
        fn visit<'a>(parent: Option<&str>, all: &[&'a View], out: &mut Vec<&'a View>) {
            for view in all
                .iter()
                .filter(|view| view.parent_id.as_deref() == parent)
            {
                out.push(view);
                visit(Some(&view.row.mailbox_id), all, out);
            }
        }
        let ids = matching
            .iter()
            .map(|view| view.row.mailbox_id.as_str())
            .collect::<Vec<_>>();
        let roots = matching
            .iter()
            .filter(|view| {
                view.parent_id
                    .as_deref()
                    .is_none_or(|parent| !ids.contains(&parent))
            })
            .copied()
            .collect::<Vec<_>>();
        for root in roots {
            ordered.push(root);
            visit(Some(&root.row.mailbox_id), &matching, &mut ordered);
        }
        matching = ordered;
    }
    let ids = matching
        .iter()
        .map(|view| view.row.mailbox_id.clone())
        .collect::<Vec<_>>();
    let state = current_state(ctx, &account)?;
    let mut response = query::page(ids, &args)?;
    response["accountId"] = json!(account.id);
    response["queryState"] = json!(state);
    Ok(vec![("Mailbox/query".to_string(), response)])
}

// ---------------------------------------------------------------------------
// Mailbox/set

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= 255
        && !name.contains('/')
        && !name.chars().any(char::is_control)
        && name.trim() == name
}

struct Setter<'a> {
    ctx: &'a mut Ctx,
    account: Account,
}

impl Setter<'_> {
    fn views(&self) -> Result<Vec<View>, MethodError> {
        views(self.ctx, &self.account)
    }

    fn full_name(&self, parent_id: Option<&str>, name: &str) -> Result<String, Value> {
        match parent_id {
            None => Ok(name.to_string()),
            Some(id) => {
                let id = self.ctx.resolve_id(id).ok_or_else(|| {
                    set_error_properties("invalidProperties", "unknown parent", &["parentId"])
                })?;
                let views = self
                    .views()
                    .map_err(|error| set_error("serverFail", format!("{error:?}")))?;
                let parent = views
                    .iter()
                    .find(|view| view.row.mailbox_id == id)
                    .ok_or_else(|| {
                        set_error_properties("invalidProperties", "unknown parent", &["parentId"])
                    })?;
                Ok(format!("{}/{name}", parent.row.name))
            }
        }
    }

    fn create(&mut self, object: &Map<String, Value>) -> Result<Value, Value> {
        for key in object.keys() {
            if !["name", "parentId", "role", "sortOrder", "isSubscribed"].contains(&key.as_str()) {
                return Err(set_error_properties(
                    "invalidProperties",
                    "the property cannot be set",
                    &[key.as_str()],
                ));
            }
        }
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| valid_name(name))
            .ok_or_else(|| set_error_properties("invalidProperties", "invalid name", &["name"]))?;
        let parent_id = match object.get("parentId") {
            None | Some(Value::Null) => None,
            Some(Value::String(id)) => Some(id.as_str()),
            Some(_) => {
                return Err(set_error_properties(
                    "invalidProperties",
                    "parentId must be an id",
                    &["parentId"],
                ));
            }
        };
        let special_use = match object.get("role") {
            None | Some(Value::Null) => None,
            Some(Value::String(role)) => Some(special_use_for(role).ok_or_else(|| {
                set_error_properties("invalidProperties", "unsupported role", &["role"])
            })?),
            Some(_) => {
                return Err(set_error_properties(
                    "invalidProperties",
                    "invalid role",
                    &["role"],
                ));
            }
        };
        let full = self.full_name(parent_id, name)?;
        if full.eq_ignore_ascii_case("INBOX")
            || full.starts_with(crate::api::OTHER_USERS.trim_end_matches('/'))
        {
            return Err(set_error_properties(
                "invalidProperties",
                "reserved name",
                &["name"],
            ));
        }
        if let Some(shared) = &self.account.shared {
            // A grantee needs `k` on the parent; shared accounts have no
            // top-level mailboxes of their own.
            let parent = parent_id
                .and_then(|id| self.ctx.resolve_id(id))
                .ok_or_else(|| {
                    set_error("forbidden", "mailboxes are created inside a shared one")
                })?;
            if !shared
                .get(&parent)
                .is_some_and(|rights| rights.contains(Rights::CREATE))
            {
                return Err(set_error(
                    "forbidden",
                    "no permission to create mailboxes here",
                ));
            }
        }
        let views = self
            .views()
            .map_err(|error| set_error("serverFail", format!("{error:?}")))?;
        let conn = self
            .ctx
            .open(&self.account)
            .map_err(|error| set_error("serverFail", format!("{error:?}")))?;
        let exists = store::mailboxes(&conn)
            .map_err(|error| set_error("serverFail", error.to_string()))?
            .iter()
            .any(|row| row.name.eq_ignore_ascii_case(&full));
        drop(conn);
        let _ = views;
        if exists {
            return Err(set_error_properties(
                "invalidProperties",
                "a mailbox with this name exists",
                &["name"],
            ));
        }
        let root = self.ctx.mail_root();
        imap_state::create_folder_with_special_use(
            &root,
            &self.account.domain,
            &self.account.localpart,
            &full,
            special_use,
        )
        .map_err(|error| set_error("serverFail", error.to_string()))?;
        let subscribe = object
            .get("isSubscribed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || !self.account.is_personal();
        if self.account.is_personal() {
            imap_state::set_subscription(
                &root,
                &self.account.domain,
                &self.account.localpart,
                &full,
                subscribe,
            )
            .map_err(|error| set_error("serverFail", error.to_string()))?;
        }
        let folder =
            imap_state::find_folder(&root, &self.account.domain, &self.account.localpart, &full)
                .map_err(|error| set_error("serverFail", error.to_string()))?
                .ok_or_else(|| set_error("serverFail", "the new mailbox vanished"))?;
        if self.account.shared.is_some() {
            self.inherit_grants(&full, &folder.mailbox_id)
                .map_err(|error| set_error("serverFail", error.to_string()))?;
            // The user now sees the new mailbox with the parent's rights.
            if let Some(parent) = parent_id.and_then(|id| self.ctx.resolve_id(id)) {
                let rights = self.account.rights(&parent);
                if let Some(shared) = &mut self.account.shared {
                    shared.insert(folder.mailbox_id.clone(), rights);
                }
                if let Some(account) = self
                    .ctx
                    .accounts
                    .iter_mut()
                    .find(|account| account.id == self.account.id)
                {
                    account.shared = self.account.shared.clone();
                }
            }
        }
        let rights = self.account.rights(&folder.mailbox_id);
        Ok(json!({
            "id": folder.mailbox_id,
            "sortOrder": sort_order(None),
            "totalEmails": 0,
            "unreadEmails": 0,
            "totalThreads": 0,
            "unreadThreads": 0,
            "isSubscribed": subscribe,
            "myRights": View {
                row: MailboxRow {
                    mailbox_id: String::new(),
                    name: full.clone(),
                    special_use: special_use.map(str::to_string),
                    subscribed: subscribe,
                    total_emails: 0,
                    unread_emails: 0,
                    total_threads: 0,
                    unread_threads: 0,
                },
                parent_id: None,
                name: String::new(),
                rights,
            }
            .to_json(&self.account)["myRights"],
        }))
    }

    fn inherit_grants(&self, full: &str, mailbox_id: &str) -> anyhow::Result<()> {
        let Some((parent, _)) = full.rsplit_once('/') else {
            return Ok(());
        };
        let root = self.ctx.mail_root();
        let Some(parent) =
            imap_state::find_folder(&root, &self.account.domain, &self.account.localpart, parent)?
        else {
            return Ok(());
        };
        let db = &self.ctx.app.db_path;
        for (grantee, rights) in acl::entries(db, &self.account.owner, &parent.mailbox_id)? {
            acl::set_rights(db, &self.account.owner, mailbox_id, &grantee, rights)?;
        }
        Ok(())
    }

    fn update(&mut self, id: &str, patch: &Map<String, Value>) -> Result<(), Value> {
        let views = self
            .views()
            .map_err(|error| set_error("serverFail", format!("{error:?}")))?;
        let view = views
            .iter()
            .find(|view| view.row.mailbox_id == id)
            .ok_or_else(|| set_error("notFound", "no such mailbox"))?;
        let mut new_name = view.name.clone();
        let mut new_parent = view.parent_id.clone();
        let mut subscribe = None;
        for (key, value) in patch {
            match key.as_str() {
                "name" => {
                    new_name = value
                        .as_str()
                        .filter(|name| valid_name(name))
                        .ok_or_else(|| {
                            set_error_properties("invalidProperties", "invalid name", &["name"])
                        })?
                        .to_string();
                }
                "parentId" => {
                    new_parent = match value {
                        Value::Null => None,
                        Value::String(parent) => {
                            Some(self.ctx.resolve_id(parent).ok_or_else(|| {
                                set_error_properties(
                                    "invalidProperties",
                                    "unknown parent",
                                    &["parentId"],
                                )
                            })?)
                        }
                        _ => {
                            return Err(set_error_properties(
                                "invalidProperties",
                                "parentId must be an id",
                                &["parentId"],
                            ));
                        }
                    };
                }
                "isSubscribed" => {
                    subscribe = Some(value.as_bool().ok_or_else(|| {
                        set_error_properties(
                            "invalidProperties",
                            "must be a boolean",
                            &["isSubscribed"],
                        )
                    })?);
                }
                "role" => {
                    if value.as_str() != view.role() {
                        return Err(set_error_properties(
                            "invalidProperties",
                            "roles cannot be changed",
                            &["role"],
                        ));
                    }
                }
                // Mailboxes are ordered by role; the order is not stored.
                "sortOrder" if value.is_u64() => {}
                other => {
                    return Err(set_error_properties(
                        "invalidProperties",
                        "the property cannot be set",
                        &[other],
                    ));
                }
            }
        }
        let root = self.ctx.mail_root();
        if new_name != view.name || new_parent != view.parent_id {
            if view.role() == Some("inbox") {
                return Err(set_error("forbidden", "the inbox cannot be renamed"));
            }
            if !view.rights.contains(Rights::DELETE_MAILBOX) {
                return Err(set_error(
                    "forbidden",
                    "no permission to rename this mailbox",
                ));
            }
            if new_parent.as_deref() == Some(id) {
                return Err(set_error_properties(
                    "invalidProperties",
                    "a mailbox cannot be its own parent",
                    &["parentId"],
                ));
            }
            let full = self.full_name(new_parent.as_deref(), &new_name)?;
            if full.starts_with(&format!("{}/", view.row.name)) {
                return Err(set_error_properties(
                    "invalidProperties",
                    "a mailbox cannot move below itself",
                    &["parentId"],
                ));
            }
            match &new_parent {
                Some(parent) if !self.account.rights(parent).contains(Rights::CREATE) => {
                    return Err(set_error(
                        "forbidden",
                        "no permission to create mailboxes there",
                    ));
                }
                None if self.account.shared.is_some() => {
                    return Err(set_error(
                        "forbidden",
                        "shared mailboxes stay inside a shared one",
                    ));
                }
                _ => {}
            }
            if views
                .iter()
                .any(|other| other.row.name.eq_ignore_ascii_case(&full))
            {
                return Err(set_error_properties(
                    "invalidProperties",
                    "a mailbox with this name exists",
                    &["name"],
                ));
            }
            imap_state::rename_folder(
                &root,
                &self.account.domain,
                &self.account.localpart,
                &view.row.name,
                &full,
            )
            .map_err(|error| set_error("serverFail", error.to_string()))?;
        }
        if let Some(subscribe) = subscribe
            && !self.account.is_personal()
        {
            if !subscribe {
                return Err(set_error_properties(
                    "invalidProperties",
                    "shared mailboxes are always subscribed",
                    &["isSubscribed"],
                ));
            }
        } else if let Some(subscribe) = subscribe {
            let name =
                imap_state::list_folders(&root, &self.account.domain, &self.account.localpart)
                    .map_err(|error| set_error("serverFail", error.to_string()))?
                    .into_iter()
                    .find(|folder| folder.mailbox_id == id)
                    .map(|folder| folder.name)
                    .ok_or_else(|| set_error("notFound", "no such mailbox"))?;
            imap_state::set_subscription(
                &root,
                &self.account.domain,
                &self.account.localpart,
                &name,
                subscribe,
            )
            .map_err(|error| set_error("serverFail", error.to_string()))?;
        }
        Ok(())
    }

    fn destroy(&mut self, id: &str, remove_emails: bool) -> Result<(), Value> {
        let conn = self
            .ctx
            .open(&self.account)
            .map_err(|error| set_error("serverFail", format!("{error:?}")))?;
        let rows =
            store::mailboxes(&conn).map_err(|error| set_error("serverFail", error.to_string()))?;
        drop(conn);
        let row = rows
            .iter()
            .find(|row| row.mailbox_id == id && self.account.lists(id))
            .ok_or_else(|| set_error("notFound", "no such mailbox"))?;
        if role(row) == Some("inbox") {
            return Err(set_error("forbidden", "the inbox cannot be destroyed"));
        }
        if !self.account.rights(id).contains(Rights::DELETE_MAILBOX) {
            return Err(set_error(
                "forbidden",
                "no permission to destroy this mailbox",
            ));
        }
        let prefix = format!("{}/", row.name);
        if rows.iter().any(|other| other.name.starts_with(&prefix)) {
            return Err(set_error(
                "mailboxHasChild",
                "the mailbox has child mailboxes",
            ));
        }
        if row.total_emails > 0 && !remove_emails {
            return Err(set_error("mailboxHasEmail", "the mailbox is not empty"));
        }
        if row.total_emails > 0
            && !self
                .account
                .rights(id)
                .contains(Rights::DELETE_MESSAGES.union(Rights::EXPUNGE))
        {
            return Err(set_error(
                "forbidden",
                "no permission to remove the mailbox's emails",
            ));
        }
        imap_state::delete_folder(
            &self.ctx.mail_root(),
            &self.account.domain,
            &self.account.localpart,
            &row.name,
        )
        .map_err(|error| set_error("serverFail", error.to_string()))?;
        acl::forget_mailbox(&self.ctx.app.db_path, &self.account.owner, id)
            .map_err(|error| set_error("serverFail", error.to_string()))?;
        Ok(())
    }
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
    if create.len() + update.len() + destroy.len() > MAX_OBJECTS_IN_SET {
        return Err(MethodError::new("requestTooLarge"));
    }
    let remove_emails = bool_arg(&args, "onDestroyRemoveEmails")?;
    let mut setter = Setter {
        ctx,
        account: account.clone(),
    };
    let mut created = Map::new();
    let mut not_created = Map::new();
    // Parents before children: a creation may name another one's id.
    let mut pending = create.into_iter().collect::<Vec<_>>();
    while !pending.is_empty() {
        let before = pending.len();
        let mut waiting = Vec::new();
        for (creation_id, object) in pending {
            let parent_pending = object
                .get("parentId")
                .and_then(Value::as_str)
                .and_then(|id| id.strip_prefix('#'))
                .is_some_and(|parent| !setter.ctx.created_ids.contains_key(parent));
            if parent_pending && before > 1 {
                waiting.push((creation_id, object));
                continue;
            }
            let Some(object) = object.as_object() else {
                not_created.insert(creation_id, set_error("invalidProperties", "not an object"));
                continue;
            };
            match setter.create(object) {
                Ok(result) => {
                    if let Some(id) = result.get("id").and_then(Value::as_str) {
                        setter
                            .ctx
                            .created_ids
                            .insert(creation_id.clone(), id.to_string());
                    }
                    created.insert(creation_id, result);
                }
                Err(error) => {
                    not_created.insert(creation_id, error);
                }
            }
        }
        if waiting.len() == before {
            for (creation_id, _) in waiting {
                not_created.insert(
                    creation_id,
                    set_error_properties("invalidProperties", "unknown parent", &["parentId"]),
                );
            }
            break;
        }
        pending = waiting;
    }
    let mut updated = Map::new();
    let mut not_updated = Map::new();
    for (id, patch) in update {
        let id = setter.ctx.resolve_id(&id).unwrap_or(id);
        let Some(patch) = patch.as_object() else {
            not_updated.insert(id, set_error("invalidPatch", "not an object"));
            continue;
        };
        match setter.update(&id, patch) {
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
    // Children before parents, so a whole subtree can go in one call.
    let names = views(setter.ctx, &setter.account)?
        .into_iter()
        .map(|view| (view.row.mailbox_id.clone(), view.row.name.clone()))
        .collect::<HashMap<_, _>>();
    let mut destroy = destroy;
    destroy.sort_by_key(|id| {
        std::cmp::Reverse(names.get(id).map_or(0, |name| name.matches('/').count()))
    });
    for id in destroy {
        match setter.destroy(&id, remove_emails) {
            Ok(()) => destroyed.push(id),
            Err(error) => {
                not_destroyed.insert(id, error);
            }
        }
    }
    let ctx = setter.ctx;
    ctx.touched(&account);
    let account = ctx.account_by_id(&account.id)?;
    let new_state = current_state(ctx, &account)?;
    let null_if_empty = |map: Map<String, Value>| {
        if map.is_empty() {
            Value::Null
        } else {
            Value::Object(map)
        }
    };
    Ok(vec![(
        "Mailbox/set".to_string(),
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
