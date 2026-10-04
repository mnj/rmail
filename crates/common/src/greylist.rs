//! Greylisting: the first delivery attempt from an unknown (client network,
//! sender, recipient) triple is deferred; a retry after the minimum delay is
//! accepted and the triple is remembered.
//!
//! State lives in memory and is snapshotted to SQLite only when it changed,
//! on an interval (see [`spawn_persistence`]), so busy servers do not write
//! to disk per message. A crash loses at most one interval of new triples.

use anyhow::Result;
use moka::sync::Cache;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How long an idle triple is remembered.
const TTL: Duration = Duration::from_secs(36 * 24 * 3600);
const MAX_ENTRIES: u64 = 200_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GreylistDecision {
    Accept,
    /// Retry no sooner than this many seconds from now.
    Defer {
        retry_after_secs: u64,
    },
}

/// One remembered triple, as persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GreylistRecord {
    pub key: String,
    pub first_seen: u64,
    pub last_seen: u64,
}

struct Entry {
    first_seen: u64,
    last_seen: AtomicU64,
}

pub struct Greylist {
    seen: Cache<String, Arc<Entry>>,
    dirty: AtomicBool,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Greylist {
    pub fn new(max_entries: u64, ttl: Duration) -> Self {
        Self {
            seen: Cache::builder()
                .max_capacity(max_entries)
                .time_to_idle(ttl)
                .build(),
            dirty: AtomicBool::new(false),
        }
    }

    /// Record an attempt and decide. Accepted triples stay remembered and keep
    /// being refreshed by traffic, so established senders are not delayed again.
    pub fn check(
        &self,
        ip: IpAddr,
        mail_from: &str,
        rcpt: &str,
        min_delay: Duration,
    ) -> GreylistDecision {
        self.check_at(ip, mail_from, rcpt, min_delay, unix_now())
    }

    fn check_at(
        &self,
        ip: IpAddr,
        mail_from: &str,
        rcpt: &str,
        min_delay: Duration,
        now: u64,
    ) -> GreylistDecision {
        let key = triple_key(ip, mail_from, rcpt);
        let mut created = false;
        let entry = self.seen.get_with(key, || {
            created = true;
            Arc::new(Entry {
                first_seen: now,
                last_seen: AtomicU64::new(now),
            })
        });
        if created {
            self.dirty.store(true, Ordering::Release);
        } else if entry.last_seen.fetch_max(now, Ordering::AcqRel) < now {
            // Only the persisted last_seen moved; coalesced into the next snapshot.
            self.dirty.store(true, Ordering::Release);
        }
        let elapsed = now.saturating_sub(entry.first_seen);
        if elapsed >= min_delay.as_secs() {
            GreylistDecision::Accept
        } else {
            GreylistDecision::Defer {
                retry_after_secs: (min_delay.as_secs() - elapsed).max(1),
            }
        }
    }

    /// Everything currently remembered, for persisting.
    pub fn snapshot(&self) -> Vec<GreylistRecord> {
        self.seen
            .iter()
            .map(|(key, entry)| GreylistRecord {
                key: (*key).clone(),
                first_seen: entry.first_seen,
                last_seen: entry.last_seen.load(Ordering::Acquire),
            })
            .collect()
    }

    /// Restore persisted records, dropping those idle for longer than the TTL.
    pub fn restore(&self, records: Vec<GreylistRecord>) {
        self.restore_at(records, unix_now());
    }

    fn restore_at(&self, records: Vec<GreylistRecord>, now: u64) {
        for record in records {
            if now.saturating_sub(record.last_seen) > TTL.as_secs() {
                continue;
            }
            self.seen.insert(
                record.key,
                Arc::new(Entry {
                    first_seen: record.first_seen,
                    last_seen: AtomicU64::new(record.last_seen),
                }),
            );
        }
    }

    /// True once if anything changed since the last call.
    fn take_dirty(&self) -> bool {
        self.dirty.swap(false, Ordering::AcqRel)
    }

    fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Release);
    }
}

/// Process-wide store shared by all SMTP sessions.
pub fn global() -> &'static Greylist {
    static GREYLIST: OnceLock<Greylist> = OnceLock::new();
    GREYLIST.get_or_init(|| Greylist::new(MAX_ENTRIES, TTL))
}

/// Write the store to SQLite if it changed. Returns whether a write happened.
pub fn persist_if_dirty(grey: &Greylist, db_path: &std::path::Path) -> Result<bool> {
    if !grey.take_dirty() {
        return Ok(false);
    }
    if let Err(error) = crate::db::save_greylist(db_path, &grey.snapshot()) {
        grey.mark_dirty(); // retry on the next tick
        return Err(error);
    }
    Ok(true)
}

/// Load persisted state into the global store and start the periodic
/// snapshot task. Abort the returned handle on shutdown, then call
/// [`flush`] for a final write.
pub fn spawn_persistence(
    db_path: PathBuf,
    interval: Duration,
) -> Result<tokio::task::JoinHandle<()>> {
    let grey = global();
    grey.restore(crate::db::load_greylist(&db_path)?);
    Ok(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await; // first tick is immediate
        loop {
            ticker.tick().await;
            let path = db_path.clone();
            let result =
                tokio::task::spawn_blocking(move || persist_if_dirty(global(), &path)).await;
            match result {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => eprintln!("greylist persist failed: {error}"),
                Err(error) => eprintln!("greylist persist task failed: {error}"),
            }
        }
    }))
}

/// Final synchronous write, for shutdown.
pub fn flush(db_path: &std::path::Path) -> Result<bool> {
    persist_if_dirty(global(), db_path)
}

/// Clients retrying from another address in the same /24 (IPv6: /64) share
/// a triple, since large senders rotate outbound hosts.
fn triple_key(ip: IpAddr, mail_from: &str, rcpt: &str) -> String {
    let network = match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    };
    format!(
        "{network}|{}|{}",
        mail_from.to_ascii_lowercase(),
        rcpt.to_ascii_lowercase()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    const T: u64 = 1_700_000_000;

    #[test]
    fn first_attempt_is_deferred_and_retry_after_delay_accepted() {
        let grey = Greylist::new(100, TTL);
        let delay = Duration::from_secs(300);
        assert_eq!(
            grey.check_at(ip("192.0.2.1"), "a@x.test", "b@y.test", delay, T),
            GreylistDecision::Defer {
                retry_after_secs: 300
            }
        );
        assert_eq!(
            grey.check_at(ip("192.0.2.1"), "a@x.test", "b@y.test", delay, T + 100),
            GreylistDecision::Defer {
                retry_after_secs: 200
            }
        );
        assert_eq!(
            grey.check_at(ip("192.0.2.1"), "a@x.test", "b@y.test", delay, T + 300),
            GreylistDecision::Accept
        );
    }

    #[test]
    fn same_slash_24_and_case_share_a_triple() {
        assert_eq!(
            triple_key(ip("192.0.2.1"), "A@x.test", "b@y.test"),
            triple_key(ip("192.0.2.200"), "a@X.test", "B@y.test")
        );
        assert_ne!(
            triple_key(ip("192.0.2.1"), "a@x.test", "b@y.test"),
            triple_key(ip("192.0.3.1"), "a@x.test", "b@y.test")
        );
    }

    #[test]
    fn different_recipients_are_tracked_separately() {
        let grey = Greylist::new(100, TTL);
        let delay = Duration::from_secs(300);
        grey.check_at(ip("192.0.2.1"), "a@x.test", "b@y.test", delay, T);
        assert!(matches!(
            grey.check_at(ip("192.0.2.1"), "a@x.test", "c@y.test", delay, T + 400),
            GreylistDecision::Defer { .. }
        ));
    }

    #[test]
    fn snapshot_restores_into_a_fresh_store() {
        let grey = Greylist::new(100, TTL);
        let delay = Duration::from_secs(300);
        grey.check_at(ip("192.0.2.1"), "a@x.test", "b@y.test", delay, T);

        let fresh = Greylist::new(100, TTL);
        fresh.restore_at(grey.snapshot(), T + 10);
        assert_eq!(
            fresh.check_at(ip("192.0.2.1"), "a@x.test", "b@y.test", delay, T + 301),
            GreylistDecision::Accept
        );
    }

    #[test]
    fn restore_drops_expired_records() {
        let grey = Greylist::new(100, TTL);
        grey.restore_at(
            vec![GreylistRecord {
                key: triple_key(ip("192.0.2.1"), "a@x.test", "b@y.test"),
                first_seen: T,
                last_seen: T,
            }],
            T + TTL.as_secs() + 1,
        );
        assert!(grey.snapshot().is_empty());
    }

    #[test]
    fn dirty_flag_coalesces_writes() {
        let grey = Greylist::new(100, TTL);
        assert!(!grey.take_dirty());
        grey.check_at(ip("192.0.2.1"), "a@x.test", "b@y.test", Duration::ZERO, T);
        assert!(grey.take_dirty());
        assert!(!grey.take_dirty());
        // A repeat within the same second changes nothing worth writing.
        grey.check_at(ip("192.0.2.1"), "a@x.test", "b@y.test", Duration::ZERO, T);
        assert!(!grey.take_dirty());
        grey.check_at(
            ip("192.0.2.1"),
            "a@x.test",
            "b@y.test",
            Duration::ZERO,
            T + 5,
        );
        assert!(grey.take_dirty());
    }

    #[test]
    fn persists_through_sqlite_only_when_dirty() {
        let td = tempfile::tempdir().unwrap();
        let db = td.path().join("rmail.db");
        crate::db::init_db(&db).unwrap();
        let grey = Greylist::new(100, TTL);
        assert!(!persist_if_dirty(&grey, &db).unwrap());
        grey.check_at(ip("192.0.2.1"), "a@x.test", "b@y.test", Duration::ZERO, T);
        assert!(persist_if_dirty(&grey, &db).unwrap());
        assert!(!persist_if_dirty(&grey, &db).unwrap());

        let loaded = crate::db::load_greylist(&db).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].first_seen, T);

        // Saving replaces the table, so expired/evicted triples do not linger.
        let empty = Greylist::new(100, TTL);
        empty.mark_dirty();
        assert!(persist_if_dirty(&empty, &db).unwrap());
        assert!(crate::db::load_greylist(&db).unwrap().is_empty());
    }
}
