//! Retention: per-domain limits on how long mail is kept, applied by a
//! periodic sweep (webmail runs it hourly).
//!
//! - Trash and Junk are emptied of messages that have been there longer
//!   than their limit (by when they were moved there).
//! - An optional limit for all mail deletes anything older (by when it was
//!   received), in every folder.
//! - Accounts on legal hold (`imap_state::set_legal_hold`) are skipped,
//!   and nothing in them can be deleted by anyone meanwhile.

use std::path::Path;

use anyhow::{Result, bail};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::imap_state;

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS retention_policies (
        domain TEXT PRIMARY KEY,
        trash_days INTEGER,
        junk_days INTEGER,
        max_age_days INTEGER
    );
";

/// The longest limit accepted (100 years).
pub const MAX_DAYS: u32 = 36_500;

/// A domain's limits, in days; `None` keeps mail there for good.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub trash_days: Option<u32>,
    #[serde(default)]
    pub junk_days: Option<u32>,
    #[serde(default)]
    pub max_age_days: Option<u32>,
}

impl Policy {
    fn is_empty(&self) -> bool {
        self.trash_days.is_none() && self.junk_days.is_none() && self.max_age_days.is_none()
    }
}

fn open(db: &Path) -> Result<crate::sqlite_pool::SqliteConnection> {
    let conn = crate::sqlite_pool::connection(db)?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

fn check(days: Option<u32>) -> Result<Option<u32>> {
    match days {
        Some(0) => bail!("a limit must be at least one day"),
        Some(days) if days > MAX_DAYS => bail!("a limit can be at most {MAX_DAYS} days"),
        other => Ok(other),
    }
}

/// Set a domain's policy; an empty one removes it.
pub fn set(db: &Path, domain: &str, policy: &Policy) -> Result<()> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || domain.contains(['/', '\\', '@']) {
        bail!("invalid domain");
    }
    let (trash, junk, max_age) = (
        check(policy.trash_days)?,
        check(policy.junk_days)?,
        check(policy.max_age_days)?,
    );
    let conn = open(db)?;
    if policy.is_empty() {
        conn.execute(
            "DELETE FROM retention_policies WHERE domain = ?1",
            params![domain],
        )?;
    } else {
        conn.execute(
            "INSERT INTO retention_policies (domain, trash_days, junk_days, max_age_days)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(domain) DO UPDATE SET trash_days = excluded.trash_days,
                 junk_days = excluded.junk_days, max_age_days = excluded.max_age_days",
            params![domain, trash, junk, max_age],
        )?;
    }
    Ok(())
}

pub fn get(db: &Path, domain: &str) -> Result<Policy> {
    Ok(open(db)?
        .query_row(
            "SELECT trash_days, junk_days, max_age_days FROM retention_policies WHERE domain = ?1",
            params![domain.to_ascii_lowercase()],
            |row| {
                Ok(Policy {
                    trash_days: row.get(0)?,
                    junk_days: row.get(1)?,
                    max_age_days: row.get(2)?,
                })
            },
        )
        .optional()?
        .unwrap_or_default())
}

/// Every domain with a policy.
pub fn list(db: &Path) -> Result<Vec<(String, Policy)>> {
    let conn = open(db)?;
    let mut stmt = conn.prepare(
        "SELECT domain, trash_days, junk_days, max_age_days FROM retention_policies ORDER BY domain",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                Policy {
                    trash_days: row.get(1)?,
                    junk_days: row.get(2)?,
                    max_age_days: row.get(3)?,
                },
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// What a sweep did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    pub deleted: usize,
    /// Accounts left alone because they are on legal hold.
    pub held: usize,
    pub errors: Vec<String>,
}

/// Apply every domain's policy to its accounts, at `now` (Unix seconds).
pub fn sweep(db: &Path, mail_root: &Path, now: i64) -> Result<Report> {
    let policies: std::collections::HashMap<String, Policy> = list(db)?.into_iter().collect();
    let mut report = Report::default();
    if policies.is_empty() {
        return Ok(report);
    }
    for mailbox in crate::db::list_mailboxes(db)? {
        let Some((local, domain)) = mailbox.address.rsplit_once('@') else {
            continue;
        };
        let Some(policy) = policies.get(&domain.to_ascii_lowercase()) else {
            continue;
        };
        match sweep_account(mail_root, domain, local, policy, now) {
            Ok(None) => report.held += 1,
            Ok(Some(deleted)) => report.deleted += deleted,
            Err(error) => report
                .errors
                .push(format!("{}: {error:#}", mailbox.address)),
        }
    }
    Ok(report)
}

/// One account's sweep: how many messages went, or `None` when on hold.
fn sweep_account(
    mail_root: &Path,
    domain: &str,
    local: &str,
    policy: &Policy,
    now: i64,
) -> Result<Option<usize>> {
    if !imap_state::account_maildir(mail_root, domain, local).exists() {
        return Ok(Some(0));
    }
    if imap_state::legal_hold(mail_root, domain, local)? {
        return Ok(None);
    }
    let cutoff = |days: u32| now - i64::from(days) * 86_400;
    let mut deleted = 0;
    for folder in imap_state::list_folders(mail_root, domain, local)? {
        let special = folder.special_use.as_deref();
        let in_folder_limit = match special {
            Some("\\Trash") => policy.trash_days,
            Some("\\Junk") => policy.junk_days,
            _ => None,
        };
        if in_folder_limit.is_none() && policy.max_age_days.is_none() {
            continue;
        }
        let (_, messages) = imap_state::load_folder(mail_root, domain, local, &folder.name)?;
        let expired: Vec<u64> = messages
            .iter()
            .filter(|message| {
                // When it came into this folder; older rows have no save date.
                let arrived = if message.save_date > 0 {
                    message.save_date
                } else {
                    message.internaldate
                };
                in_folder_limit.is_some_and(|days| arrived < cutoff(days))
                    || policy
                        .max_age_days
                        .is_some_and(|days| message.internaldate < cutoff(days))
            })
            .map(|message| message.uid)
            .collect();
        if !expired.is_empty() {
            deleted += imap_state::delete_messages_by_uid(
                mail_root,
                domain,
                local,
                &folder.name,
                &expired,
            )?
            .len();
        }
    }
    Ok(Some(deleted))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweeps_trash_junk_and_old_mail_but_not_held_accounts() {
        let td = tempfile::tempdir().unwrap();
        let (db, root) = (td.path().join("accounts.sqlite"), td.path().join("mail"));
        crate::db::init_db(&db).unwrap();
        let now = chrono::Utc::now().timestamp();
        for local in ["user", "held"] {
            crate::db::add_mailbox(&db, &format!("{local}@example.test"), None, None, None)
                .unwrap();
            imap_state::init_account(&root, "example.test", local).unwrap();
            imap_state::deliver_message(&root, "example.test", local, b"Subject: keep\r\n\r\nx")
                .unwrap();
            let (_, binned) = imap_state::deliver_message(
                &root,
                "example.test",
                local,
                b"Subject: binned\r\n\r\nx",
            )
            .unwrap();
            imap_state::move_message_by_uid(&root, "example.test", local, "INBOX", binned, "Trash")
                .unwrap();
            imap_state::append_message_with_internal_date(
                &root,
                "example.test",
                local,
                "Archive",
                b"Subject: ancient\r\n\r\nx",
                Vec::new(),
                Some((now - 400 * 86_400, 0)),
            )
            .unwrap();
        }
        imap_state::set_legal_hold(&root, "example.test", "held", true).unwrap();

        assert!(
            set(
                &db,
                "example.test",
                &Policy {
                    trash_days: Some(0),
                    ..Policy::default()
                }
            )
            .is_err()
        );
        let policy = Policy {
            trash_days: Some(30),
            junk_days: Some(30),
            max_age_days: Some(365),
        };
        set(&db, "Example.test", &policy).unwrap();
        assert_eq!(get(&db, "example.test").unwrap(), policy);

        // Today only the 400-day-old message is past its limit.
        let report = sweep(&db, &root, now).unwrap();
        assert_eq!((report.deleted, report.held), (1, 1), "{report:?}");
        // Forty days on, Trash's has been there past 30 days too.
        let report = sweep(&db, &root, now + 40 * 86_400).unwrap();
        assert_eq!((report.deleted, report.held), (1, 1), "{report:?}");
        let count = |local: &str, folder: &str| {
            imap_state::load_folder(&root, "example.test", local, folder)
                .unwrap()
                .1
                .len()
        };
        assert_eq!(
            (
                count("user", "INBOX"),
                count("user", "Trash"),
                count("user", "Archive")
            ),
            (1, 0, 0)
        );
        assert_eq!(
            (count("held", "Trash"), count("held", "Archive")),
            (1, 1),
            "held mail stays"
        );

        // On hold, nothing can be deleted by hand either, but moving works.
        let (_, trash) = imap_state::load_folder(&root, "example.test", "held", "Trash").unwrap();
        let refused = imap_state::delete_messages_by_uid(
            &root,
            "example.test",
            "held",
            "Trash",
            &[trash[0].uid],
        )
        .unwrap_err();
        assert!(refused.downcast_ref::<imap_state::LegalHold>().is_some());
        assert!(imap_state::delete_folder(&root, "example.test", "held", "Archive").is_err());
        imap_state::move_message_by_uid(
            &root,
            "example.test",
            "held",
            "Trash",
            trash[0].uid,
            "INBOX",
        )
        .unwrap();
        imap_state::set_legal_hold(&root, "example.test", "held", false).unwrap();
        assert_eq!(
            sweep(&db, &root, now + 40 * 86_400).unwrap().deleted,
            1,
            "the ancient one, once released"
        );

        set(&db, "example.test", &Policy::default()).unwrap();
        assert!(list(&db).unwrap().is_empty(), "an empty policy is removed");
    }
}
