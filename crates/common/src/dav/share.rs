//! Calendar and address book sharing, stored in the central `dav_shares`
//! table. A row grants `grantee` read or read-write access to one
//! collection of `owner`, keyed by the collection's id in the owner's state
//! database: ids are never reused, so a grant does not pass to a later
//! collection of the same name. The owner always has full access and has
//! no row.
//!
//! As for mailboxes (see `acl`), grantees are accounts on this server and
//! there is no "anyone": a collection is never visible to an account its
//! owner did not name. A grant takes effect at once; there is no
//! invitation to accept, and a grantee who deletes the shared collection
//! from their home only drops the grant.
//!
//! The row also holds the grantee's own name, color and order for the
//! collection, so each sharee can label it without changing the owner's.

use std::path::Path;

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};

use super::store::{self, Collection, Kind, Setting};

/// What a grantee may do with a shared collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Read the collection and its objects.
    Read,
    /// Also add, change and delete objects, and change the collection's
    /// description and time zone.
    ReadWrite,
}

impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Access::Read => "read",
            Access::ReadWrite => "read-write",
        }
    }

    pub fn parse(text: &str) -> Option<Access> {
        match text {
            "read" => Some(Access::Read),
            "read-write" => Some(Access::ReadWrite),
            _ => None,
        }
    }
}

/// One grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub owner: String,
    pub collection_id: i64,
    pub grantee: String,
    pub access: Access,
    /// The grantee's own name for the collection.
    pub displayname: Option<String>,
    /// The grantee's own color for a calendar.
    pub color: Option<String>,
    /// The grantee's own position for a calendar.
    pub sort_order: Option<String>,
}

const COLUMNS: &str = "owner, collection_id, grantee, access, displayname, color, sort_order";

fn row_to_grant(row: &rusqlite::Row<'_>) -> rusqlite::Result<Grant> {
    let access: String = row.get(3)?;
    Ok(Grant {
        owner: row.get(0)?,
        collection_id: row.get(1)?,
        grantee: row.get(2)?,
        // Anything unexpected is read as the lesser access.
        access: Access::parse(&access).unwrap_or(Access::Read),
        displayname: row.get(4)?,
        color: row.get(5)?,
        sort_order: row.get(6)?,
    })
}

fn open(db_path: &Path) -> Result<Connection> {
    let conn = Connection::open(db_path)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(conn)
}

fn canonical(address: &str) -> Result<String> {
    crate::domain::canonicalize_mailbox_address(address)
}

fn select(db_path: &Path, filter: &str, values: &[&dyn rusqlite::ToSql]) -> Result<Vec<Grant>> {
    let conn = open(db_path)?;
    let mut statement = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM dav_shares {filter} ORDER BY owner, collection_id, grantee"
    ))?;
    Ok(statement
        .query_map(values, row_to_grant)?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Give `grantee` `access` to the owner's collection, or with `None` stop
/// sharing it. The grantee must be another account on this server. A
/// change of access keeps the grantee's own name and color.
pub fn set_access(
    db_path: &Path,
    owner: &str,
    collection_id: i64,
    grantee: &str,
    access: Option<Access>,
) -> Result<()> {
    let owner = canonical(owner)?;
    let grantee = canonical(grantee).context("the sharee must be an account address")?;
    if grantee == owner {
        bail!("the owner always has full access");
    }
    let Some(access) = access else {
        delete(db_path, &owner, collection_id, &grantee)?;
        return Ok(());
    };
    if !crate::db::mailbox_exists(db_path, &grantee)? {
        bail!("no account {grantee} on this server");
    }
    open(db_path)?.execute(
        "INSERT INTO dav_shares (owner, collection_id, grantee, access) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(owner, collection_id, grantee) DO UPDATE SET access = excluded.access",
        params![owner, collection_id, grantee, access.as_str()],
    )?;
    Ok(())
}

/// Remove the grant for `grantee`; whether there was one.
pub fn delete(db_path: &Path, owner: &str, collection_id: i64, grantee: &str) -> Result<bool> {
    Ok(open(db_path)?.execute(
        "DELETE FROM dav_shares WHERE owner = ?1 AND collection_id = ?2 AND grantee = ?3",
        params![canonical(owner)?, collection_id, canonical(grantee)?],
    )? > 0)
}

/// The grant `account` holds on the owner's collection, if any.
pub fn grant(
    db_path: &Path,
    owner: &str,
    collection_id: i64,
    account: &str,
) -> Result<Option<Grant>> {
    Ok(open(db_path)?
        .query_row(
            &format!(
                "SELECT {COLUMNS} FROM dav_shares
                 WHERE owner = ?1 AND collection_id = ?2 AND grantee = ?3"
            ),
            params![canonical(owner)?, collection_id, canonical(account)?],
            row_to_grant,
        )
        .optional()?)
}

/// Every grant on the owner's collection, by grantee.
pub fn grants_on(db_path: &Path, owner: &str, collection_id: i64) -> Result<Vec<Grant>> {
    select(
        db_path,
        "WHERE owner = ?1 AND collection_id = ?2",
        &[&canonical(owner)?, &collection_id],
    )
}

/// Every grant `owner` has made.
pub fn granted_by(db_path: &Path, owner: &str) -> Result<Vec<Grant>> {
    select(db_path, "WHERE owner = ?1", &[&canonical(owner)?])
}

/// Every collection other accounts share with `account`.
pub fn shared_with(db_path: &Path, account: &str) -> Result<Vec<Grant>> {
    select(db_path, "WHERE grantee = ?1", &[&canonical(account)?])
}

/// Every grant on the server.
pub fn all_grants(db_path: &Path) -> Result<Vec<Grant>> {
    select(db_path, "", &[])
}

/// Set the grantee's own name, color or order for a shared collection;
/// whether the grant exists. Other settings belong to the owner.
pub fn set_personal(
    db_path: &Path,
    grant: &Grant,
    setting: Setting,
    value: Option<&str>,
) -> Result<bool> {
    let column = match setting {
        Setting::DisplayName => "displayname",
        Setting::Color => "color",
        Setting::SortOrder => "sort_order",
        Setting::Description | Setting::Timezone => bail!("not a personal setting"),
    };
    Ok(open(db_path)?.execute(
        &format!(
            "UPDATE dav_shares SET {column} = ?4
             WHERE owner = ?1 AND collection_id = ?2 AND grantee = ?3"
        ),
        params![grant.owner, grant.collection_id, grant.grantee, value],
    )? > 0)
}

/// Whether a setting is the grantee's own (see [`set_personal`]).
pub fn is_personal(setting: Setting) -> bool {
    matches!(
        setting,
        Setting::DisplayName | Setting::Color | Setting::SortOrder
    )
}

fn owner_parts(owner: &str) -> Option<(&str, &str)> {
    let (local, domain) = owner.split_once('@')?;
    (!local.is_empty() && !domain.is_empty() && !owner.contains('/')).then_some((local, domain))
}

/// The grants with the collections they name, for listings; grants on
/// collections deleted since are left out. Only owners with a grant are
/// opened, so no storage is created for other names.
pub fn with_collections(mail_root: &Path, grants: Vec<Grant>) -> Result<Vec<(Grant, Collection)>> {
    let mut found = Vec::new();
    let mut owners = std::collections::HashMap::new();
    for grant in grants {
        if !owners.contains_key(&grant.owner) {
            let conn = match owner_parts(&grant.owner) {
                Some((local, domain)) => Some(crate::jmap::store::open(mail_root, domain, local)?),
                None => None,
            };
            owners.insert(grant.owner.clone(), conn);
        }
        let Some(Some(conn)) = owners.get(&grant.owner) else {
            continue;
        };
        if let Some(collection) = store::collection_by_id(conn, grant.collection_id)? {
            found.push((grant, collection));
        }
    }
    Ok(found)
}

/// The account's own collections of `kind` (see `store::collections`).
pub fn own_collections(mail_root: &Path, account: &str, kind: Kind) -> Result<Vec<Collection>> {
    let account = canonical(account)?;
    let (local, domain) = owner_parts(&account).context("invalid address")?;
    let conn = crate::jmap::store::open(mail_root, domain, local)?;
    store::collections(&conn, kind)
}

/// Drop the grants on a deleted collection.
pub fn forget_collection(db_path: &Path, owner: &str, collection_id: i64) -> Result<()> {
    open(db_path)?.execute(
        "DELETE FROM dav_shares WHERE owner = ?1 AND collection_id = ?2",
        params![canonical(owner)?, collection_id],
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
    fn grants_are_per_collection_and_only_to_accounts() {
        let (_dir, db) = db();
        let owner = "owner@example.test";
        set_access(&db, owner, 7, "friend@Example.TEST", Some(Access::Read)).unwrap();
        let found = grant(&db, owner, 7, "friend@example.test")
            .unwrap()
            .unwrap();
        assert_eq!(found.access, Access::Read);
        assert_eq!(found.grantee, "friend@example.test");
        assert!(
            grant(&db, owner, 8, "friend@example.test")
                .unwrap()
                .is_none()
        );
        assert!(set_access(&db, owner, 7, "nobody@example.test", Some(Access::Read)).is_err());
        assert!(set_access(&db, owner, 7, owner, Some(Access::Read)).is_err());
        assert!(set_access(&db, owner, 7, "anyone", Some(Access::Read)).is_err());

        // The grantee's own name survives a change of access.
        assert!(set_personal(&db, &found, Setting::DisplayName, Some("Team")).unwrap());
        assert!(set_personal(&db, &found, Setting::Timezone, Some("x")).is_err());
        set_access(
            &db,
            owner,
            7,
            "friend@example.test",
            Some(Access::ReadWrite),
        )
        .unwrap();
        let changed = &shared_with(&db, "friend@example.test").unwrap()[0];
        assert_eq!(changed.access, Access::ReadWrite);
        assert_eq!(changed.displayname.as_deref(), Some("Team"));
        assert_eq!(granted_by(&db, owner).unwrap().len(), 1);
        assert_eq!(all_grants(&db).unwrap().len(), 1);

        set_access(&db, owner, 7, "friend@example.test", None).unwrap();
        assert!(grants_on(&db, owner, 7).unwrap().is_empty());
        set_access(&db, owner, 7, "friend@example.test", Some(Access::Read)).unwrap();
        forget_collection(&db, owner, 7).unwrap();
        assert!(shared_with(&db, "friend@example.test").unwrap().is_empty());

        // Removing an account drops the grants made by and to it.
        set_access(&db, owner, 9, "friend@example.test", Some(Access::Read)).unwrap();
        crate::db::remove_mailbox(&db, "friend@example.test").unwrap();
        assert!(granted_by(&db, owner).unwrap().is_empty());
    }
}
