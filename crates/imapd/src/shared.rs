//! Shared mailboxes (RFC 4314 ACL, RFC 2342 "Other Users" namespace).
//!
//! Mailboxes other accounts share with the user appear as
//! `Other Users/<owner address>/<mailbox>`. [`resolve`] turns any mailbox
//! name a client sends into the account that stores it, the name there and
//! the rights the user holds; commands then work on that account's storage.
//! A shared mailbox the user may neither list nor read resolves exactly like
//! one that does not exist, so its existence is not revealed (RFC 4314
//! section 6).

use std::path::Path;

use anyhow::Result;
use rmail_common::acl::{self, Rights};
use rmail_common::imap_state::{self, FolderSummary};

use crate::mailbox;

/// The prefix of the other users' namespace, without its trailing `/`.
pub(crate) const OTHER_USERS: &str = "Other Users";

/// A mailbox name resolved to its storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub(crate) domain: String,
    pub(crate) local: String,
    /// The mailbox name in the owner's account.
    pub(crate) mailbox: String,
    /// The owner's address when the mailbox is shared with the user; `None`
    /// for the user's own mailboxes.
    pub(crate) owner: Option<String>,
    /// The MAILBOXID of a shared mailbox the user can see.
    pub(crate) mailbox_id: Option<String>,
    /// The user's rights: every right on their own mailboxes, none on a
    /// shared mailbox that does not exist or is hidden.
    pub(crate) rights: Rights,
}

impl Target {
    pub(crate) fn is_shared(&self) -> bool {
        self.owner.is_some()
    }

    /// The user may know the mailbox exists (RFC 4314 section 6).
    pub(crate) fn visible(&self) -> bool {
        !self.is_shared() || self.rights.intersects(Rights::LOOKUP.union(Rights::READ))
    }
}

/// Split `Other Users/<owner>/<rest>` into the owner and the rest, which is
/// empty for the owner's own node.
pub(crate) fn split_shared_name(name: &str) -> Option<(&str, &str)> {
    let rest = name.strip_prefix(OTHER_USERS)?.strip_prefix('/')?;
    Some(rest.split_once('/').unwrap_or((rest, "")))
}

/// The name a shared mailbox has in the user's view.
pub(crate) fn shared_name(owner: &str, mailbox: &str) -> String {
    format!("{OTHER_USERS}/{owner}/{mailbox}")
}

/// Whether `name` is in the other users' namespace.
pub(crate) fn is_shared_name(name: &str) -> bool {
    name == OTHER_USERS || split_shared_name(name).is_some()
}

/// Resolve `name` for the authenticated `address`. Names outside the other
/// users' namespace are the user's own mailboxes and need no database.
pub(crate) fn resolve(
    mail_root: &Path,
    db_path: Option<&Path>,
    address: &str,
    name: &str,
) -> Result<Target> {
    let Some((owner, rest)) = split_shared_name(name) else {
        let (local, domain) = mailbox::address_parts(address)?;
        return Ok(Target {
            domain,
            local,
            mailbox: name.to_string(),
            owner: None,
            mailbox_id: None,
            rights: Rights::ALL,
        });
    };
    let owner = rmail_common::domain::canonicalize_mailbox_address(owner)
        .unwrap_or_else(|_| owner.to_string());
    let (local, domain) = mailbox::address_parts(&owner).unwrap_or_default();
    let mut target = Target {
        domain,
        local,
        mailbox: rest.to_string(),
        owner: Some(owner.clone()),
        mailbox_id: None,
        rights: Rights::NONE,
    };
    let Some(db_path) = db_path else {
        return Ok(target);
    };
    if rest.is_empty() {
        return Ok(target);
    }
    if let Some(shared) = acl::find_shared(mail_root, db_path, address, &owner, rest)? {
        target.mailbox = shared.folder.name;
        target.mailbox_id = Some(shared.folder.mailbox_id);
        target.rights = shared.rights;
    }
    Ok(target)
}

/// The rights needed to create `name`, which are the CREATE right on its
/// parent in the owner's account (RFC 4314 section 4). Top-level mailboxes
/// of another account cannot be created.
pub(crate) fn may_create(
    mail_root: &Path,
    db_path: Option<&Path>,
    address: &str,
    target: &Target,
) -> Result<bool> {
    let Some(owner) = &target.owner else {
        return Ok(true);
    };
    let Some((parent, _)) = target.mailbox.rsplit_once('/') else {
        return Ok(false);
    };
    let parent = resolve(mail_root, db_path, address, &shared_name(owner, parent))?;
    Ok(parent.rights.contains(Rights::CREATE))
}

/// A shared mailbox the user can list, with its summary renamed to the
/// user's view of it.
pub(crate) struct Listed {
    pub(crate) summary: FolderSummary,
    pub(crate) target: Target,
}

/// Every shared mailbox the user may list (the `l` right), sorted by name.
pub(crate) fn listable(
    mail_root: &Path,
    db_path: Option<&Path>,
    address: &str,
) -> Result<Vec<Listed>> {
    let Some(db_path) = db_path else {
        return Ok(Vec::new());
    };
    let mut listed = Vec::new();
    for shared in acl::shared_mailboxes(mail_root, db_path, address)? {
        if !shared.rights.contains(Rights::LOOKUP) {
            continue;
        }
        let Some(mut summary) = imap_state::folder_summary(
            mail_root,
            &shared.domain,
            &shared.localpart,
            &shared.folder.name,
        )?
        else {
            continue;
        };
        summary.folder.name = shared_name(&shared.owner, &shared.folder.name);
        // Special-use attributes describe the owner's mailboxes, not the
        // user's (RFC 6154 section 1).
        summary.folder.special_use = None;
        let target = Target {
            domain: shared.domain,
            local: shared.localpart,
            mailbox: shared.folder.name,
            owner: Some(shared.owner),
            mailbox_id: Some(shared.folder.mailbox_id),
            rights: shared.rights,
        };
        listed.push(Listed { summary, target });
    }
    listed.sort_by(|left, right| left.summary.folder.name.cmp(&right.summary.folder.name));
    Ok(listed)
}

/// The `\Noselect` nodes above the listed shared mailboxes: the namespace
/// root and one per owner.
pub(crate) fn hierarchy_nodes(listed: &[Listed]) -> Vec<String> {
    let mut nodes = Vec::new();
    if listed.is_empty() {
        return nodes;
    }
    nodes.push(OTHER_USERS.to_string());
    for entry in listed {
        if let Some(owner) = &entry.target.owner {
            let node = format!("{OTHER_USERS}/{owner}");
            if !nodes.contains(&node) {
                nodes.push(node);
            }
        }
    }
    nodes
}

/// Keep only the flags the rights allow to be set (RFC 4314 section 4):
/// `s` for \Seen, `t` for \Deleted, `w` for the rest.
pub(crate) fn permitted_flag(rights: Rights, flag: &str) -> bool {
    if flag.eq_ignore_ascii_case("\\Seen") {
        rights.contains(Rights::SEEN)
    } else if flag.eq_ignore_ascii_case("\\Deleted") {
        rights.contains(Rights::DELETE_MESSAGES)
    } else {
        rights.contains(Rights::WRITE)
    }
}

/// Whether the rights allow changing any flag at all.
pub(crate) fn may_change_flags(rights: Rights) -> bool {
    rights.intersects(
        Rights::SEEN
            .union(Rights::WRITE)
            .union(Rights::DELETE_MESSAGES),
    )
}

/// PERMANENTFLAGS for a mailbox opened with `rights`.
pub(crate) fn permanent_flags(rights: Rights) -> String {
    let mut flags = Vec::new();
    if rights.contains(Rights::SEEN) {
        flags.push("\\Seen");
    }
    if rights.contains(Rights::WRITE) {
        flags.extend(["\\Answered", "\\Flagged"]);
    }
    if rights.contains(Rights::DELETE_MESSAGES) {
        flags.push("\\Deleted");
    }
    if rights.contains(Rights::WRITE) {
        flags.extend(["\\Draft", "\\*"]);
    }
    flags.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_names_split_into_owner_and_mailbox() {
        assert_eq!(
            split_shared_name("Other Users/bob@example.test/Projects/Q1"),
            Some(("bob@example.test", "Projects/Q1"))
        );
        assert_eq!(
            split_shared_name("Other Users/bob@example.test"),
            Some(("bob@example.test", ""))
        );
        assert_eq!(split_shared_name("Other Users"), None);
        assert_eq!(split_shared_name("Other UsersX/a"), None);
        assert!(is_shared_name("Other Users"));
        assert!(!is_shared_name("INBOX"));
    }

    #[test]
    fn flags_follow_rights() {
        let rights = Rights::parse("lrs").unwrap();
        assert!(permitted_flag(rights, "\\Seen"));
        assert!(!permitted_flag(rights, "\\Deleted"));
        assert!(!permitted_flag(rights, "$Label"));
        assert_eq!(permanent_flags(rights), "\\Seen");
        assert_eq!(
            permanent_flags(Rights::ALL),
            "\\Seen \\Answered \\Flagged \\Deleted \\Draft \\*"
        );
        assert!(!may_change_flags(Rights::parse("lr").unwrap()));
    }
}
