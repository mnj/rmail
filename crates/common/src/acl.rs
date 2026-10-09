//! Mailbox sharing (RFC 4314 access control lists), stored in the
//! `mailbox_acl` table. A row grants `grantee` some rights on one mailbox of
//! `owner`, keyed by the mailbox's MAILBOXID so the grant follows a RENAME
//! and is not inherited by a later mailbox of the same name. The owner
//! always holds every right and has no row.
//!
//! Grantees are accounts on this server; RFC 4314's `anyone` and negative
//! rights are not supported, so a mailbox is never visible to an account
//! its owner did not name.

use std::fmt;
use std::path::Path;

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};

/// RFC 4314 rights, in the order they are listed.
const LETTERS: &[(char, u16)] = &[
    ('l', 1 << 0),
    ('r', 1 << 1),
    ('s', 1 << 2),
    ('w', 1 << 3),
    ('i', 1 << 4),
    ('p', 1 << 5),
    ('k', 1 << 6),
    ('x', 1 << 7),
    ('t', 1 << 8),
    ('e', 1 << 9),
    ('a', 1 << 10),
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rights(u16);

impl Rights {
    pub const NONE: Rights = Rights(0);
    pub const ALL: Rights = Rights((1 << 11) - 1);
    /// List the mailbox (LIST, LSUB).
    pub const LOOKUP: Rights = Rights(1 << 0);
    /// SELECT, EXAMINE, STATUS, FETCH, SEARCH, and COPY from the mailbox.
    pub const READ: Rights = Rights(1 << 1);
    /// Set or clear \Seen.
    pub const SEEN: Rights = Rights(1 << 2);
    /// Set or clear flags other than \Seen and \Deleted.
    pub const WRITE: Rights = Rights(1 << 3);
    /// APPEND and COPY into the mailbox.
    pub const INSERT: Rights = Rights(1 << 4);
    /// Send mail to the mailbox; recorded but not used by rMail.
    pub const POST: Rights = Rights(1 << 5);
    /// CREATE a child mailbox, or RENAME into one.
    pub const CREATE: Rights = Rights(1 << 6);
    /// DELETE or RENAME the mailbox.
    pub const DELETE_MAILBOX: Rights = Rights(1 << 7);
    /// Set or clear \Deleted.
    pub const DELETE_MESSAGES: Rights = Rights(1 << 8);
    /// EXPUNGE.
    pub const EXPUNGE: Rights = Rights(1 << 9);
    /// Read and change the ACL.
    pub const ADMIN: Rights = Rights(1 << 10);

    /// Parse a rights string. The obsolete RFC 2086 rights stand for their
    /// RFC 4314 groups: `c` for `k`, `d` for `xte` (section 2.1.1). Any
    /// other unknown letter is an error.
    pub fn parse(text: &str) -> Result<Self> {
        let mut bits = 0;
        for letter in text.chars() {
            bits |= match letter {
                'c' => Self::CREATE.0,
                'd' => Self::DELETE_MAILBOX.0 | Self::DELETE_MESSAGES.0 | Self::EXPUNGE.0,
                letter => LETTERS
                    .iter()
                    .find(|(candidate, _)| *candidate == letter)
                    .map(|(_, bit)| *bit)
                    .with_context(|| format!("unknown right {letter:?}"))?,
            };
        }
        Ok(Self(bits))
    }

    pub fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn intersects(self, other: Rights) -> bool {
        self.0 & other.0 != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    pub fn without(self, other: Rights) -> Rights {
        Rights(self.0 & !other.0)
    }
}

impl fmt::Display for Rights {
    /// The rights as RFC 4314 letters, with `c` and `d` added when a member
    /// of their group is present, as section 2.1.1 requires.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (letter, bit) in LETTERS {
            if self.0 & bit != 0 {
                write!(formatter, "{letter}")?;
            }
        }
        if self.contains(Self::CREATE) {
            write!(formatter, "c")?;
        }
        if self.intersects(Rights(
            Self::DELETE_MAILBOX.0 | Self::DELETE_MESSAGES.0 | Self::EXPUNGE.0,
        )) {
            write!(formatter, "d")?;
        }
        Ok(())
    }
}

/// A mailbox shared with an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub owner: String,
    pub mailbox_id: String,
    pub rights: Rights,
}

fn open(db_path: &Path) -> Result<Connection> {
    let conn = Connection::open(db_path)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(conn)
}

fn canonical(address: &str) -> Result<String> {
    crate::domain::canonicalize_mailbox_address(address)
}

/// Grant `grantee` exactly `rights` on the owner's mailbox; empty rights
/// remove the grant. The grantee must be another account on this server.
pub fn set_rights(
    db_path: &Path,
    owner: &str,
    mailbox_id: &str,
    grantee: &str,
    rights: Rights,
) -> Result<()> {
    let owner = canonical(owner)?;
    let grantee = canonical(grantee).context("the identifier must be an account address")?;
    if grantee == owner {
        bail!("the owner always has every right");
    }
    if rights.is_empty() {
        delete_rights(db_path, &owner, mailbox_id, &grantee)?;
        return Ok(());
    }
    if !crate::db::mailbox_exists(db_path, &grantee)? {
        bail!("no account {grantee} on this server");
    }
    open(db_path)?.execute(
        "INSERT OR REPLACE INTO mailbox_acl (owner, mailbox_id, grantee, rights)
         VALUES (?1, ?2, ?3, ?4)",
        params![owner, mailbox_id, grantee, rights.0],
    )?;
    Ok(())
}

/// Remove the grant for `grantee`; whether there was one.
pub fn delete_rights(db_path: &Path, owner: &str, mailbox_id: &str, grantee: &str) -> Result<bool> {
    Ok(open(db_path)?.execute(
        "DELETE FROM mailbox_acl WHERE owner = ?1 AND mailbox_id = ?2 AND grantee = ?3",
        params![canonical(owner)?, mailbox_id, canonical(grantee)?],
    )? > 0)
}

/// The rights `account` holds on the owner's mailbox.
pub fn rights_of(db_path: &Path, owner: &str, mailbox_id: &str, account: &str) -> Result<Rights> {
    let owner = canonical(owner)?;
    let account = canonical(account)?;
    if owner == account {
        return Ok(Rights::ALL);
    }
    let bits = open(db_path)?
        .query_row(
            "SELECT rights FROM mailbox_acl WHERE owner = ?1 AND mailbox_id = ?2 AND grantee = ?3",
            params![owner, mailbox_id, account],
            |row| row.get::<_, u16>(0),
        )
        .optional()?;
    Ok(Rights(bits.unwrap_or(0) & Rights::ALL.0))
}

/// Every grant on the owner's mailbox, by grantee.
pub fn entries(db_path: &Path, owner: &str, mailbox_id: &str) -> Result<Vec<(String, Rights)>> {
    let conn = open(db_path)?;
    let mut statement = conn.prepare(
        "SELECT grantee, rights FROM mailbox_acl WHERE owner = ?1 AND mailbox_id = ?2
         ORDER BY grantee",
    )?;
    let rows = statement
        .query_map(params![canonical(owner)?, mailbox_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                Rights(row.get::<_, u16>(1)? & Rights::ALL.0),
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Every grant on the server, as (owner, mailbox ID, grantee, rights).
pub fn all_grants(db_path: &Path) -> Result<Vec<(String, String, String, Rights)>> {
    let conn = open(db_path)?;
    let mut statement = conn.prepare(
        "SELECT owner, mailbox_id, grantee, rights FROM mailbox_acl
         ORDER BY owner, mailbox_id, grantee",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                Rights(row.get::<_, u16>(3)? & Rights::ALL.0),
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Every grant `owner` has made, as (mailbox ID, grantee, rights).
pub fn granted_by(db_path: &Path, owner: &str) -> Result<Vec<(String, String, Rights)>> {
    let conn = open(db_path)?;
    let mut statement = conn.prepare(
        "SELECT mailbox_id, grantee, rights FROM mailbox_acl WHERE owner = ?1
         ORDER BY mailbox_id, grantee",
    )?;
    let rows = statement
        .query_map(params![canonical(owner)?], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                Rights(row.get::<_, u16>(2)? & Rights::ALL.0),
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Every mailbox other accounts share with `account`.
pub fn shared_with(db_path: &Path, account: &str) -> Result<Vec<Share>> {
    let conn = open(db_path)?;
    let mut statement = conn.prepare(
        "SELECT owner, mailbox_id, rights FROM mailbox_acl WHERE grantee = ?1
         ORDER BY owner, mailbox_id",
    )?;
    let rows = statement
        .query_map(params![canonical(account)?], |row| {
            Ok(Share {
                owner: row.get(0)?,
                mailbox_id: row.get(1)?,
                rights: Rights(row.get::<_, u16>(2)? & Rights::ALL.0),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// A mailbox of another account that is shared with a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedMailbox {
    pub owner: String,
    pub domain: String,
    pub localpart: String,
    pub folder: crate::imap_state::Folder,
    pub rights: Rights,
}

fn owner_parts(owner: &str) -> Option<(String, String)> {
    let (local, domain) = owner.split_once('@')?;
    (!local.is_empty() && !domain.is_empty() && !owner.contains('/'))
        .then(|| (local.to_string(), domain.to_string()))
}

/// Every mailbox shared with `account`, whatever the rights, ordered by
/// owner and name. Only owners with a grant to the account are read, so no
/// storage is opened (or created) for other names.
pub fn shared_mailboxes(
    mail_root: &Path,
    db_path: &Path,
    account: &str,
) -> Result<Vec<SharedMailbox>> {
    let mut by_owner = std::collections::BTreeMap::<String, Vec<Share>>::new();
    for share in shared_with(db_path, account)? {
        by_owner.entry(share.owner.clone()).or_default().push(share);
    }
    let mut found = Vec::new();
    for (owner, shares) in by_owner {
        let Some((localpart, domain)) = owner_parts(&owner) else {
            continue;
        };
        for folder in crate::imap_state::list_folders(mail_root, &domain, &localpart)? {
            if let Some(share) = shares
                .iter()
                .find(|share| share.mailbox_id == folder.mailbox_id)
            {
                found.push(SharedMailbox {
                    owner: owner.clone(),
                    domain: domain.clone(),
                    localpart: localpart.clone(),
                    folder,
                    rights: share.rights,
                });
            }
        }
    }
    Ok(found)
}

/// The owner's mailbox `name` if it is shared with `account`.
pub fn find_shared(
    mail_root: &Path,
    db_path: &Path,
    account: &str,
    owner: &str,
    name: &str,
) -> Result<Option<SharedMailbox>> {
    let Ok(owner) = canonical(owner) else {
        return Ok(None);
    };
    let shares = shared_with(db_path, account)?
        .into_iter()
        .filter(|share| share.owner == owner)
        .collect::<Vec<_>>();
    let Some((localpart, domain)) = owner_parts(&owner).filter(|_| !shares.is_empty()) else {
        return Ok(None);
    };
    let Some(folder) = crate::imap_state::find_folder(mail_root, &domain, &localpart, name)? else {
        return Ok(None);
    };
    Ok(shares
        .iter()
        .find(|share| share.mailbox_id == folder.mailbox_id)
        .map(|share| SharedMailbox {
            owner: owner.clone(),
            domain,
            localpart,
            rights: share.rights,
            folder,
        }))
}

/// Drop the grants on a deleted mailbox.
pub fn forget_mailbox(db_path: &Path, owner: &str, mailbox_id: &str) -> Result<()> {
    open(db_path)?.execute(
        "DELETE FROM mailbox_acl WHERE owner = ?1 AND mailbox_id = ?2",
        params![canonical(owner)?, mailbox_id],
    )?;
    Ok(())
}

/// Drop every grant made by or to a removed account.
pub fn forget_account(db_path: &Path, address: &str) -> Result<()> {
    let address = canonical(address)?;
    open(db_path)?.execute(
        "DELETE FROM mailbox_acl WHERE owner = ?1 OR grantee = ?1",
        params![address],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rmail.db");
        crate::db::init_db(&path).unwrap();
        for address in ["owner@example.test", "friend@example.test"] {
            crate::db::add_mailbox(&path, address, Some("plain:x"), None, None).unwrap();
        }
        (dir, path)
    }

    #[test]
    fn rights_parse_obsolete_letters_and_print_them_back() {
        assert_eq!(Rights::parse("c").unwrap(), Rights::CREATE);
        assert_eq!(Rights::parse("d").unwrap(), Rights::parse("xte").unwrap());
        assert_eq!(Rights::parse("lrs").unwrap().to_string(), "lrs");
        assert_eq!(Rights::parse("lrt").unwrap().to_string(), "lrtd");
        assert_eq!(Rights::ALL.to_string(), "lrswipkxteacd");
        assert!(Rights::parse("lr9").is_err());
        assert!(Rights::parse("L").is_err());
    }

    #[test]
    fn grants_are_per_mailbox_and_only_to_accounts() {
        let (_dir, db) = db();
        let rights = Rights::parse("lrs").unwrap();
        set_rights(
            &db,
            "owner@example.test",
            "F1",
            "friend@Example.TEST",
            rights,
        )
        .unwrap();
        assert_eq!(
            rights_of(&db, "owner@example.test", "F1", "friend@example.test").unwrap(),
            rights
        );
        assert_eq!(
            rights_of(&db, "owner@example.test", "F2", "friend@example.test").unwrap(),
            Rights::NONE
        );
        assert_eq!(
            rights_of(&db, "owner@example.test", "F2", "owner@example.test").unwrap(),
            Rights::ALL
        );
        assert_eq!(
            shared_with(&db, "friend@example.test").unwrap(),
            vec![Share {
                owner: "owner@example.test".into(),
                mailbox_id: "F1".into(),
                rights,
            }]
        );
        assert!(
            set_rights(
                &db,
                "owner@example.test",
                "F1",
                "nobody@example.test",
                rights
            )
            .is_err()
        );
        assert!(
            set_rights(
                &db,
                "owner@example.test",
                "F1",
                "owner@example.test",
                rights
            )
            .is_err()
        );
        assert!(set_rights(&db, "owner@example.test", "F1", "anyone", rights).is_err());
        // Empty rights remove the grant.
        set_rights(
            &db,
            "owner@example.test",
            "F1",
            "friend@example.test",
            Rights::NONE,
        )
        .unwrap();
        assert!(entries(&db, "owner@example.test", "F1").unwrap().is_empty());
        set_rights(
            &db,
            "owner@example.test",
            "F1",
            "friend@example.test",
            rights,
        )
        .unwrap();
        forget_account(&db, "friend@example.test").unwrap();
        assert!(shared_with(&db, "friend@example.test").unwrap().is_empty());
    }
}
