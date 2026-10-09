//! RFC 4314 ACL commands: SETACL, DELETEACL, GETACL, LISTRIGHTS, MYRIGHTS.
//!
//! Identifiers are account addresses on this server. The owner of a mailbox
//! always holds every right and cannot be changed; `anyone` and negative
//! rights (`-identifier`) are not supported. See `rmail_common::acl`.

use std::path::Path;

use rmail_common::acl::{self, Rights};

use crate::parser::{self, Command};
use crate::response::{Response, Status, StatusLine};
use crate::{mailbox, shared};

/// LISTRIGHTS: nothing is required of a grantee, every right may be given
/// on its own, plus the obsolete `c` and `d` (RFC 4314 section 2.1.1).
const OPTIONAL_RIGHTS: &str = "l r s w i p k x t e a c d";

pub(crate) fn handle(
    tag: &str,
    command: &Command,
    args: &str,
    mail_root: &Path,
    db_path: Option<&Path>,
    address: &str,
    utf8_accept: bool,
) -> Response {
    let name = command_name(command);
    let Ok(arguments) = parser::parse_imap_args(args) else {
        return bad(tag, name);
    };
    let Some(arguments) = arguments
        .iter()
        .map(parser::ImapArg::as_text)
        .collect::<Option<Vec<_>>>()
    else {
        return bad(tag, name);
    };
    let expected = match command {
        Command::SetAcl => 3,
        Command::DeleteAcl | Command::ListRights => 2,
        _ => 1,
    };
    if arguments.len() != expected {
        return bad(tag, name);
    }
    let Ok(mailbox_name) = mailbox::decode_wire_mailbox_name(arguments[0], utf8_accept) else {
        return Response::new().status(StatusLine::tagged(
            tag,
            Status::Bad,
            "Invalid mailbox name",
        ));
    };
    // Parse rights before touching storage: an unknown right is BAD
    // (RFC 4314 section 3.1).
    let modification = match command {
        Command::SetAcl => match parse_modification(arguments[2]) {
            Ok(modification) => Some(modification),
            Err(error) => {
                return Response::new().status(StatusLine::tagged(
                    tag,
                    Status::Bad,
                    format!("Invalid rights: {error}"),
                ));
            }
        },
        _ => None,
    };
    let Some(db_path) = db_path else {
        return no(tag, "UNAVAILABLE", "Sharing needs the account database");
    };
    let (target, mailbox_id) = match find(mail_root, db_path, address, &mailbox_name) {
        Ok(Some(found)) => found,
        Ok(None) => return no(tag, "NONEXISTENT", "Mailbox does not exist"),
        Err(error) => return no(tag, "UNAVAILABLE", &format!("{name} failed: {error}")),
    };
    let quoted = mailbox::quote_wire_mailbox_name(&mailbox_name, utf8_accept);
    let owner = format!("{}@{}", target.local, target.domain);
    if matches!(command, Command::MyRights) {
        return Response::new()
            .data(format!(
                "MYRIGHTS {quoted} {}",
                astring(&target.rights.to_string())
            ))
            .status(completed(tag, name));
    }
    if !target.rights.contains(Rights::ADMIN) {
        return no(tag, "NOPERM", "Permission denied");
    }
    let result = match command {
        Command::GetAcl => acl::entries(db_path, &owner, &mailbox_id).map(|entries| {
            let mut data = format!("ACL {quoted} {} {}", astring(&owner), Rights::ALL);
            for (grantee, rights) in entries {
                data.push_str(&format!(
                    " {} {}",
                    astring(&grantee),
                    astring(&rights.to_string())
                ));
            }
            Response::new().data(data)
        }),
        Command::ListRights => {
            let identifier = arguments[1];
            let data = if same_account(identifier, &owner) {
                format!(
                    "LISTRIGHTS {quoted} {} {}",
                    astring(identifier),
                    Rights::ALL
                )
            } else {
                format!(
                    "LISTRIGHTS {quoted} {} \"\" {OPTIONAL_RIGHTS}",
                    astring(identifier)
                )
            };
            Ok(Response::new().data(data))
        }
        Command::SetAcl | Command::DeleteAcl => {
            let identifier = arguments[1];
            if let Some(refusal) = check_identifier(tag, identifier, &owner) {
                return refusal;
            }
            let rights = match modification {
                Some(Modification::Replace(rights)) => Ok(rights),
                Some(Modification::Add(rights)) => {
                    acl::rights_of(db_path, &owner, &mailbox_id, identifier)
                        .map(|current| current.union(rights))
                }
                Some(Modification::Remove(rights)) => {
                    acl::rights_of(db_path, &owner, &mailbox_id, identifier)
                        .map(|current| current.without(rights))
                }
                None => Ok(Rights::NONE),
            };
            rights
                .and_then(|rights| {
                    acl::set_rights(db_path, &owner, &mailbox_id, identifier, rights)
                })
                .map(|()| Response::new())
        }
        _ => unreachable!("dispatch only routes ACL commands here"),
    };
    match result {
        Ok(response) => response.status(completed(tag, name)),
        Err(error) => no(tag, "CANNOT", &format!("{name} failed: {error}")),
    }
}

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::SetAcl => "SETACL",
        Command::DeleteAcl => "DELETEACL",
        Command::GetAcl => "GETACL",
        Command::ListRights => "LISTRIGHTS",
        _ => "MYRIGHTS",
    }
}

enum Modification {
    Replace(Rights),
    Add(Rights),
    Remove(Rights),
}

fn parse_modification(text: &str) -> anyhow::Result<Modification> {
    Ok(if let Some(rights) = text.strip_prefix('+') {
        Modification::Add(Rights::parse(rights)?)
    } else if let Some(rights) = text.strip_prefix('-') {
        Modification::Remove(Rights::parse(rights)?)
    } else {
        Modification::Replace(Rights::parse(text)?)
    })
}

/// The mailbox and its MAILBOXID, or `None` when it does not exist or the
/// user may not know it does.
fn find(
    mail_root: &Path,
    db_path: &Path,
    address: &str,
    name: &str,
) -> anyhow::Result<Option<(shared::Target, String)>> {
    let target = shared::resolve(mail_root, Some(db_path), address, name)?;
    if !target.visible() {
        return Ok(None);
    }
    let mailbox_id = match &target.mailbox_id {
        Some(id) => Some(id.clone()),
        None if !target.is_shared() => rmail_common::imap_state::find_folder(
            mail_root,
            &target.domain,
            &target.local,
            &target.mailbox,
        )?
        .map(|folder| folder.mailbox_id),
        None => None,
    };
    Ok(mailbox_id.map(|id| (target, id)))
}

fn same_account(identifier: &str, owner: &str) -> bool {
    rmail_common::domain::canonicalize_mailbox_address(identifier)
        .is_ok_and(|identifier| identifier == owner)
}

fn check_identifier(tag: &str, identifier: &str, owner: &str) -> Option<Response> {
    if identifier.starts_with('-') {
        return Some(no(tag, "CANNOT", "Negative rights are not supported"));
    }
    if identifier.eq_ignore_ascii_case("anyone") {
        return Some(no(
            tag,
            "CANNOT",
            "Mailboxes are shared with named accounts only",
        ));
    }
    if same_account(identifier, owner) {
        return Some(no(tag, "CANNOT", "The owner always has every right"));
    }
    None
}

/// An identifier or rights string as an IMAP astring.
fn astring(value: &str) -> String {
    let atom = !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !b"(){%*\"\\]".contains(&byte));
    if atom {
        value.to_string()
    } else {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

fn completed(tag: &str, name: &str) -> StatusLine {
    StatusLine::tagged(tag, Status::Ok, format!("{name} completed"))
}

fn no(tag: &str, code: &str, text: &str) -> Response {
    Response::new().status(StatusLine::tagged(tag, Status::No, text).with_code(code))
}

fn bad(tag: &str, name: &str) -> Response {
    Response::new().status(StatusLine::tagged(
        tag,
        Status::Bad,
        format!("Invalid {name} arguments"),
    ))
}
