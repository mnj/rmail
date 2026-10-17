//! Resource accounts: rooms and equipment people book by inviting them.
//!
//! A resource is an ordinary mailbox marked as one. When someone in its
//! domain invites it (CalDAV scheduling, or webmail's calendar), the server
//! answers for it: accepted when its calendar is free for every occurrence,
//! declined when one clashes with another booking. Invitations from other
//! domains arrive by email and wait in its inbox for a person.
//!
//! A resource may have an approver: a booking that fits is then held as
//! tentative, and the approver (a local mailbox) gets a booking request to
//! approve or decline in webmail. Clashes are still declined at once.

use std::path::Path;

use anyhow::{Result, bail};
use rusqlite::{OptionalExtension, params};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourceKind {
    Room,
    Equipment,
}

impl ResourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceKind::Room => "room",
            ResourceKind::Equipment => "equipment",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "room" => Some(ResourceKind::Room),
            "equipment" => Some(ResourceKind::Equipment),
            _ => None,
        }
    }

    /// The iCalendar `CUTYPE` of an attendee of this kind (RFC 5545 3.2.3).
    pub fn cutype(self) -> &'static str {
        match self {
            ResourceKind::Room => "ROOM",
            ResourceKind::Equipment => "RESOURCE",
        }
    }
}

pub(crate) const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS resources (
        address TEXT PRIMARY KEY,
        kind TEXT NOT NULL
    );
";

/// The table, with the approver column added to older databases.
pub(crate) fn ensure_schema(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(SCHEMA)?;
    let has_approver = conn
        .prepare("PRAGMA table_info(resources)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .iter()
        .any(|column| column == "approver");
    if !has_approver {
        conn.execute("ALTER TABLE resources ADD COLUMN approver TEXT", [])?;
    }
    Ok(())
}

fn open(db: &Path) -> Result<crate::sqlite_pool::SqliteConnection> {
    let conn = crate::sqlite_pool::connection(db)?;
    ensure_schema(&conn)?;
    Ok(conn)
}

fn key(address: &str) -> Result<String> {
    Ok(crate::domain::canonicalize_mailbox_address(address)?.to_ascii_lowercase())
}

/// Mark a mailbox as a resource, or with `None` as a person again.
pub fn set(db: &Path, address: &str, kind: Option<ResourceKind>) -> Result<()> {
    let address = key(address)?;
    if kind.is_some() && !crate::db::mailbox_exists(db, &address)? {
        bail!("no mailbox {address}");
    }
    let conn = open(db)?;
    match kind {
        Some(kind) => conn.execute(
            "INSERT INTO resources (address, kind) VALUES (?1, ?2)
             ON CONFLICT(address) DO UPDATE SET kind = excluded.kind",
            params![address, kind.as_str()],
        )?,
        None => conn.execute("DELETE FROM resources WHERE address = ?1", params![address])?,
    };
    Ok(())
}

pub fn kind_of(db: &Path, address: &str) -> Result<Option<ResourceKind>> {
    let Ok(address) = key(address) else {
        return Ok(None);
    };
    let conn = open(db)?;
    let kind: Option<String> = conn
        .query_row(
            "SELECT kind FROM resources WHERE address = ?1",
            params![address],
            |row| row.get(0),
        )
        .optional()?;
    Ok(kind.as_deref().and_then(ResourceKind::parse))
}

/// Give a resource an approver (a local mailbox), or with `None` let it
/// answer bookings itself again.
pub fn set_approver(db: &Path, address: &str, approver: Option<&str>) -> Result<()> {
    let address = key(address)?;
    if kind_of(db, &address)?.is_none() {
        bail!("{address} is not a room or equipment");
    }
    let approver = match approver {
        Some(approver) => {
            let approver = key(approver)?;
            if approver == address {
                bail!("a resource cannot approve its own bookings");
            }
            if !crate::db::mailbox_exists(db, &approver)? {
                bail!("no mailbox {approver}");
            }
            Some(approver)
        }
        None => None,
    };
    open(db)?.execute(
        "UPDATE resources SET approver = ?2 WHERE address = ?1",
        params![address, approver],
    )?;
    Ok(())
}

/// Who approves a resource's bookings, if anyone.
pub fn approver_of(db: &Path, address: &str) -> Result<Option<String>> {
    let Ok(address) = key(address) else {
        return Ok(None);
    };
    Ok(open(db)?
        .query_row(
            "SELECT approver FROM resources WHERE address = ?1",
            params![address],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten())
}

/// Every resource with an approver: (resource, approver).
pub fn approvers(db: &Path) -> Result<Vec<(String, String)>> {
    let conn = open(db)?;
    let mut stmt = conn.prepare(
        "SELECT address, approver FROM resources WHERE approver IS NOT NULL ORDER BY address",
    )?;
    let rows = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Every resource, or those of one domain, by address.
pub fn list(db: &Path, domain: Option<&str>) -> Result<Vec<(String, ResourceKind)>> {
    let conn = open(db)?;
    let mut stmt = conn.prepare("SELECT address, kind FROM resources ORDER BY address")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (address, kind) = row?;
        let in_domain = domain.is_none_or(|domain| {
            address
                .rsplit_once('@')
                .is_some_and(|(_, d)| d.eq_ignore_ascii_case(domain))
        });
        if let (true, Some(kind)) = (in_domain, ResourceKind::parse(&kind)) {
            out.push((address, kind));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resources_are_marked_listed_and_unmarked() {
        let td = tempfile::tempdir().unwrap();
        let db = td.path().join("accounts.sqlite");
        crate::db::init_db(&db).unwrap();
        crate::db::add_mailbox(&db, "room1@example.test", None, None, None).unwrap();
        crate::db::add_mailbox(&db, "beamer@other.test", None, None, None).unwrap();
        assert!(set(&db, "nobody@example.test", Some(ResourceKind::Room)).is_err());
        set(&db, "Room1@Example.test", Some(ResourceKind::Room)).unwrap();
        set(&db, "beamer@other.test", Some(ResourceKind::Equipment)).unwrap();
        assert_eq!(
            kind_of(&db, "ROOM1@example.test").unwrap(),
            Some(ResourceKind::Room)
        );
        assert_eq!(
            list(&db, Some("example.test")).unwrap(),
            [("room1@example.test".to_string(), ResourceKind::Room)]
        );
        assert_eq!(list(&db, None).unwrap().len(), 2);
        set(&db, "room1@example.test", None).unwrap();
        assert_eq!(kind_of(&db, "room1@example.test").unwrap(), None);
        crate::db::remove_mailbox(&db, "beamer@other.test").unwrap();
        assert!(
            list(&db, None).unwrap().is_empty(),
            "deleting the mailbox unmarks it"
        );
        assert_eq!(ResourceKind::Equipment.cutype(), "RESOURCE");
    }

    #[test]
    fn approvers_are_local_mailboxes_and_go_with_them() {
        let td = tempfile::tempdir().unwrap();
        let db = td.path().join("accounts.sqlite");
        crate::db::init_db(&db).unwrap();
        crate::db::add_mailbox(&db, "room1@example.test", None, None, None).unwrap();
        crate::db::add_mailbox(&db, "facilities@example.test", None, None, None).unwrap();
        assert!(
            set_approver(&db, "room1@example.test", Some("facilities@example.test")).is_err(),
            "not a resource yet"
        );
        set(&db, "room1@example.test", Some(ResourceKind::Room)).unwrap();
        assert!(set_approver(&db, "room1@example.test", Some("nobody@example.test")).is_err());
        assert!(set_approver(&db, "room1@example.test", Some("room1@example.test")).is_err());
        set_approver(&db, "Room1@example.test", Some("Facilities@example.test")).unwrap();
        assert_eq!(
            approver_of(&db, "room1@example.test").unwrap().as_deref(),
            Some("facilities@example.test")
        );
        assert_eq!(approvers(&db).unwrap().len(), 1);
        crate::db::remove_mailbox(&db, "facilities@example.test").unwrap();
        assert_eq!(
            approver_of(&db, "room1@example.test").unwrap(),
            None,
            "a deleted approver is cleared"
        );
        assert_eq!(
            kind_of(&db, "room1@example.test").unwrap(),
            Some(ResourceKind::Room)
        );
    }
}
