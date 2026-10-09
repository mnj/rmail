use std::path::Path;

use rmail_common::acl::Rights;

use crate::{
    mailbox, parser,
    response::{Response, Status, StatusLine},
    shared,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operation {
    Create,
    Delete,
    Rename,
    Subscribe,
    Unsubscribe,
}

impl Operation {
    fn command(self) -> &'static str {
        match self {
            Self::Create => "CREATE",
            Self::Delete => "DELETE",
            Self::Rename => "RENAME",
            Self::Subscribe => "SUBSCRIBE",
            Self::Unsubscribe => "UNSUBSCRIBE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SelectionEffect {
    None,
    Deleted(String),
    Renamed { source: String, destination: String },
}

impl SelectionEffect {
    pub(crate) fn renamed_selection(&self, selected: &str) -> Option<String> {
        let Self::Renamed {
            source,
            destination,
        } = self
        else {
            return None;
        };
        if selected.eq_ignore_ascii_case(source) {
            return Some(destination.clone());
        }
        let prefix = format!("{source}/");
        selected
            .get(..prefix.len())
            .filter(|candidate| candidate.eq_ignore_ascii_case(&prefix))
            .map(|_| format!("{destination}/{}", &selected[prefix.len()..]))
    }
}

pub(crate) struct Outcome {
    pub(crate) response: Response,
    pub(crate) selection_effect: SelectionEffect,
}

impl Outcome {
    fn response(response: Response) -> Self {
        Self {
            response,
            selection_effect: SelectionEffect::None,
        }
    }
}

pub(crate) fn handle(
    operation: Operation,
    tag: &str,
    raw_args: &str,
    mail_root: &Path,
    db_path: Option<&Path>,
    address: &str,
    utf8_accept: bool,
    imap4rev2: bool,
) -> Outcome {
    let command = operation.command();
    let mut special_uses = Vec::new();
    let parsed = match operation {
        Operation::Rename => parser::parse_rename_arguments(raw_args)
            .map(|(source, destination)| vec![source, destination]),
        Operation::Create => parser::parse_create_arguments(raw_args).map(|(mailbox, uses)| {
            special_uses = uses;
            vec![mailbox]
        }),
        _ => parser::parse_mailbox_argument(raw_args).map(|mailbox| vec![mailbox]),
    };
    // CREATE-SPECIAL-USE (RFC 6154 §3): one real folder has one use.
    if special_uses.len() > 1
        || special_uses.iter().any(|requested| {
            !rmail_common::imap_state::CREATABLE_SPECIAL_USES
                .iter()
                .any(|known| known.eq_ignore_ascii_case(requested))
        })
    {
        return Outcome::response(
            Response::new().status(
                StatusLine::tagged(tag, Status::No, "Unsupported special-use attribute")
                    .with_code("USEATTR"),
            ),
        );
    }
    let wire_names = match parsed {
        Ok(names) => names,
        Err(_) => return Outcome::response(bad(tag, format!("Invalid {command} arguments"))),
    };
    let names = match wire_names
        .iter()
        .map(|name| mailbox::decode_wire_mailbox_name(name, utf8_accept))
        .collect::<anyhow::Result<Vec<_>>>()
    {
        Ok(names) => names,
        Err(_) => return Outcome::response(bad(tag, "Invalid mailbox name")),
    };
    if operation == Operation::Subscribe || operation == Operation::Unsubscribe {
        // Subscriptions are the user's own list of names, shared or not.
        let (local, domain) = match mailbox::address_parts(address) {
            Ok(parts) => parts,
            Err(error) => return Outcome::response(storage_failure(tag, command, error, None)),
        };
        return match rmail_common::maildir::set_mailbox_subscription(
            mail_root,
            &domain,
            &local,
            &names[0],
            operation == Operation::Subscribe,
        ) {
            Ok(()) => Outcome::response(completed(tag, command)),
            Err(error) => Outcome::response(storage_failure(tag, command, error, None)),
        };
    }
    let targets = match names
        .iter()
        .map(|name| shared::resolve(mail_root, db_path, address, name))
        .collect::<anyhow::Result<Vec<_>>>()
    {
        Ok(targets) => targets,
        Err(error) => return Outcome::response(storage_failure(tag, command, error, None)),
    };
    if let Some(refusal) = check_rights(
        operation,
        tag,
        mail_root,
        db_path,
        address,
        &names,
        &targets,
        !special_uses.is_empty(),
    ) {
        return Outcome::response(refusal);
    }
    let target = &targets[0];
    let (domain, local) = (&target.domain, &target.local);
    // Remembered before DELETE so the grants on it can be dropped.
    let deleted_id = match operation {
        Operation::Delete => {
            rmail_common::imap_state::find_folder(mail_root, domain, local, &target.mailbox)
                .ok()
                .flatten()
                .map(|folder| folder.mailbox_id)
        }
        _ => None,
    };

    let result = match operation {
        Operation::Create => match special_uses.first() {
            Some(special_use) => rmail_common::imap_state::create_folder_with_special_use(
                mail_root,
                domain,
                local,
                &target.mailbox,
                Some(special_use),
            ),
            None => {
                rmail_common::maildir::create_mailbox(mail_root, domain, local, &target.mailbox)
                    .and_then(|()| inherit_acl(mail_root, db_path, target))
            }
        },
        Operation::Delete => {
            rmail_common::maildir::delete_mailbox(mail_root, domain, local, &target.mailbox)
        }
        Operation::Rename => rmail_common::maildir::rename_mailbox(
            mail_root,
            domain,
            local,
            &target.mailbox,
            &targets[1].mailbox,
        ),
        Operation::Subscribe | Operation::Unsubscribe => unreachable!("handled above"),
    };
    if result.is_ok()
        && let (Some(db_path), Some(mailbox_id)) = (db_path, &deleted_id)
    {
        let owner = format!("{local}@{domain}");
        if let Err(error) = rmail_common::acl::forget_mailbox(db_path, &owner, mailbox_id) {
            rmail_common::structured_log!("warn", "imapd", "acl_cleanup_failed", { "owner": owner, "mailbox_id": mailbox_id, "error": error.to_string() });
        }
    }

    match result {
        Ok(()) => Outcome {
            response: match operation {
                Operation::Create => created(tag, mail_root, domain, local, &target.mailbox),
                Operation::Rename if imap4rev2 => renamed(
                    tag,
                    mail_root,
                    domain,
                    local,
                    (&target.mailbox, &targets[1].mailbox),
                    target
                        .owner
                        .as_deref()
                        .map(|owner| shared::shared_name(owner, "")),
                    utf8_accept,
                ),
                _ => completed(tag, command),
            },
            selection_effect: match operation {
                Operation::Delete => SelectionEffect::Deleted(names[0].clone()),
                Operation::Rename => SelectionEffect::Renamed {
                    source: names[0].clone(),
                    destination: names[1].clone(),
                },
                _ => SelectionEffect::None,
            },
        },
        Err(error) => {
            let message = error.to_string();
            let code = match operation {
                Operation::Create if message.contains("already exists") => Some("ALREADYEXISTS"),
                Operation::Delete if message.contains("does not exist") => Some("NONEXISTENT"),
                _ => None,
            };
            Outcome::response(storage_failure(tag, command, error, code))
        }
    }
}

/// Refuse CREATE, DELETE and RENAME the rights do not allow (RFC 4314
/// section 4): CREATE needs `k` on the parent, DELETE `x`, RENAME `x` on the
/// source and `k` on the new parent. A RENAME stays within one account, and
/// the user's own mailboxes cannot take names in the shared namespace.
#[allow(clippy::too_many_arguments)]
fn check_rights(
    operation: Operation,
    tag: &str,
    mail_root: &Path,
    db_path: Option<&Path>,
    address: &str,
    names: &[String],
    targets: &[shared::Target],
    special_use: bool,
) -> Option<Response> {
    let refuse = |code: &str, text: &str| {
        Some(Response::new().status(StatusLine::tagged(tag, Status::No, text).with_code(code)))
    };
    let missing = |target: &shared::Target| {
        target.is_shared() && (target.mailbox_id.is_none() || !target.visible())
    };
    let may_create = |target: &shared::Target| {
        shared::may_create(mail_root, db_path, address, target).unwrap_or(false)
    };
    let new_name = match operation {
        Operation::Create => Some(0),
        Operation::Rename => Some(1),
        _ => None,
    };
    if let Some(index) = new_name {
        let target = &targets[index];
        if (!target.is_shared() && shared::is_shared_name(&names[index]))
            || (target.is_shared() && target.mailbox.is_empty())
        {
            return refuse("CANNOT", "Names under \"Other Users\" are reserved");
        }
        if target.is_shared() {
            if target.mailbox_id.is_some() && target.visible() {
                return refuse("ALREADYEXISTS", "Mailbox already exists");
            }
            if special_use || !may_create(target) {
                return refuse("NOPERM", "Permission denied");
            }
        }
    }
    if matches!(operation, Operation::Delete | Operation::Rename) {
        let source = &targets[0];
        if missing(source) {
            return refuse("NONEXISTENT", "Mailbox does not exist");
        }
        if !source.rights.contains(Rights::DELETE_MAILBOX) {
            return refuse("NOPERM", "Permission denied");
        }
    }
    if operation == Operation::Rename && targets[0].owner != targets[1].owner {
        return refuse("CANNOT", "Cannot rename a mailbox into another account");
    }
    None
}

/// A mailbox created inside a shared mailbox gets its parent's grants, so
/// the user who created it (and everyone else the parent is shared with)
/// can still reach it.
fn inherit_acl(
    mail_root: &Path,
    db_path: Option<&Path>,
    target: &shared::Target,
) -> anyhow::Result<()> {
    let (Some(db_path), Some(owner)) = (db_path, &target.owner) else {
        return Ok(());
    };
    let Some((parent, _)) = target.mailbox.rsplit_once('/') else {
        return Ok(());
    };
    let find = |name: &str| {
        rmail_common::imap_state::find_folder(mail_root, &target.domain, &target.local, name)
    };
    let (Some(parent), Some(child)) = (find(parent)?, find(&target.mailbox)?) else {
        return Ok(());
    };
    for (grantee, rights) in rmail_common::acl::entries(db_path, owner, &parent.mailbox_id)? {
        rmail_common::acl::set_rights(db_path, owner, &child.mailbox_id, &grantee, rights)?;
    }
    Ok(())
}

fn completed(tag: &str, command: &str) -> Response {
    Response::new().status(StatusLine::tagged(
        tag,
        Status::Ok,
        format!("{command} completed"),
    ))
}

/// RFC 8474 §4.1: a successful CREATE reports the new MAILBOXID.
fn created(tag: &str, mail_root: &Path, domain: &str, local: &str, name: &str) -> Response {
    let line = StatusLine::tagged(tag, Status::Ok, "CREATE completed");
    let mailbox_id = rmail_common::maildir::normalize_mailbox_name(name)
        .ok()
        .and_then(|name| {
            rmail_common::imap_state::list_folders(mail_root, domain, local)
                .ok()?
                .into_iter()
                .find(|folder| folder.name == name)
        })
        .map(|folder| folder.mailbox_id);
    Response::new().status(match mailbox_id {
        Some(id) => line.with_code(format!("MAILBOXID ({id})")),
        None => line,
    })
}

/// RFC 9051 §7.3.1: after RENAME, an IMAP4rev2 session gets a LIST response
/// with the `OLDNAME` extended data item for the renamed mailbox and each
/// renamed inferior, so it can move cached state without a full LIST.
fn renamed(
    tag: &str,
    mail_root: &Path,
    domain: &str,
    local: &str,
    (source, destination): (&str, &str),
    shared_prefix: Option<String>,
    utf8_accept: bool,
) -> Response {
    let mut response = Response::new();
    let normalized = rmail_common::maildir::normalize_mailbox_name(source).and_then(|source| {
        Ok((
            source,
            rmail_common::maildir::normalize_mailbox_name(destination)?,
        ))
    });
    let folders = rmail_common::imap_state::list_folders(mail_root, domain, local);
    if let (Ok((source, destination)), Ok(folders)) = (normalized, folders) {
        let prefix = format!("{destination}/");
        for folder in &folders {
            // In another account only the renamed mailbox is reported: its
            // children may not be visible to the user.
            if shared_prefix.is_some() && folder.name != destination {
                continue;
            }
            let old_name = if folder.name == destination {
                source.clone()
            } else if let Some(suffix) = folder.name.strip_prefix(&prefix) {
                format!("{source}/{suffix}")
            } else {
                continue;
            };
            let child_prefix = format!("{}/", folder.name);
            let children = if folders
                .iter()
                .any(|candidate| candidate.name.starts_with(&child_prefix))
            {
                "\\HasChildren"
            } else {
                "\\HasNoChildren"
            };
            let prefix = shared_prefix.as_deref().unwrap_or("");
            response = response.data(format!(
                "LIST ({children}) \"/\" {} (\"OLDNAME\" ({}))",
                mailbox::quote_wire_mailbox_name(&format!("{prefix}{}", folder.name), utf8_accept),
                mailbox::quote_wire_mailbox_name(&format!("{prefix}{old_name}"), utf8_accept)
            ));
        }
    }
    response.status(StatusLine::tagged(tag, Status::Ok, "RENAME completed"))
}

fn bad(tag: &str, text: impl Into<String>) -> Response {
    Response::new().status(StatusLine::tagged(tag, Status::Bad, text))
}

fn storage_failure(
    tag: &str,
    command: &str,
    error: impl std::fmt::Display,
    code: Option<&str>,
) -> Response {
    let mut line = StatusLine::tagged(tag, Status::No, format!("{command} failed: {error}"));
    if let Some(code) = code {
        line = line.with_code(code);
    }
    Response::new().status(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_delete_and_rename_return_selection_effects_and_codes() {
        let temp = tempfile::tempdir().unwrap();
        let address = "user@example.test";
        let create = handle(
            Operation::Create,
            "A1",
            "Projects",
            temp.path(),
            None,
            address,
            false,
            false,
        );
        let mailbox_id =
            rmail_common::imap_state::list_folders(temp.path(), "example.test", "user")
                .unwrap()
                .into_iter()
                .find(|folder| folder.name == "Projects")
                .unwrap()
                .mailbox_id;
        assert_eq!(
            create.response.encode(),
            format!("A1 OK [MAILBOXID ({mailbox_id})] CREATE completed\r\n")
        );
        assert_eq!(create.selection_effect, SelectionEffect::None);

        let duplicate = handle(
            Operation::Create,
            "A2",
            "Projects",
            temp.path(),
            None,
            address,
            false,
            false,
        )
        .response
        .encode();
        assert!(duplicate.starts_with("A2 NO [ALREADYEXISTS] CREATE failed:"));

        let rename = handle(
            Operation::Rename,
            "A3",
            "Projects Renamed",
            temp.path(),
            None,
            address,
            false,
            false,
        );
        assert_eq!(
            rename.selection_effect,
            SelectionEffect::Renamed {
                source: "Projects".to_string(),
                destination: "Renamed".to_string(),
            }
        );
        assert_eq!(rename.response.encode(), "A3 OK RENAME completed\r\n");

        let delete = handle(
            Operation::Delete,
            "A4",
            "Renamed",
            temp.path(),
            None,
            address,
            false,
            false,
        );
        assert_eq!(
            delete.selection_effect,
            SelectionEffect::Deleted("Renamed".to_string())
        );
        assert_eq!(delete.response.encode(), "A4 OK DELETE completed\r\n");
    }

    #[test]
    fn malformed_arguments_fail_before_storage_changes() {
        let temp = tempfile::tempdir().unwrap();
        let outcome = handle(
            Operation::Rename,
            "A1",
            "OnlyOneName",
            temp.path(),
            None,
            "user@example.test",
            false,
            false,
        );
        assert_eq!(
            outcome.response.encode(),
            "A1 BAD Invalid RENAME arguments\r\n"
        );
        assert_eq!(outcome.selection_effect, SelectionEffect::None);
    }

    #[test]
    fn hierarchy_rename_remaps_selected_descendants() {
        let effect = SelectionEffect::Renamed {
            source: "Projects".to_string(),
            destination: "Archive/Projects".to_string(),
        };
        assert_eq!(
            effect.renamed_selection("Projects/Client/2026"),
            Some("Archive/Projects/Client/2026".to_string())
        );
        assert_eq!(effect.renamed_selection("Projects-Old"), None);
    }
}
