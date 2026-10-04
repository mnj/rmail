//! Greylisting: the first delivery attempt from an unknown (client network,
//! sender, recipient) triple is deferred; a retry after the minimum delay is
//! accepted and the triple is remembered. State is in memory, so a restart
//! only costs senders one more retry.

use moka::sync::Cache;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GreylistDecision {
    Accept,
    /// Retry no sooner than this many seconds from now.
    Defer {
        retry_after_secs: u64,
    },
}

pub struct Greylist {
    /// Triple -> time of the first attempt.
    seen: Cache<String, Instant>,
}

impl Greylist {
    pub fn new(max_entries: u64, ttl: Duration) -> Self {
        Self {
            seen: Cache::builder()
                .max_capacity(max_entries)
                .time_to_idle(ttl)
                .build(),
        }
    }

    /// Record an attempt and decide. Accepted triples stay in the cache and
    /// keep being refreshed by traffic, so established senders are not delayed again.
    pub fn check(
        &self,
        ip: IpAddr,
        mail_from: &str,
        rcpt: &str,
        min_delay: Duration,
    ) -> GreylistDecision {
        let key = triple_key(ip, mail_from, rcpt);
        let now = Instant::now();
        let first = self.seen.get_with(key, || now);
        let elapsed = now.saturating_duration_since(first);
        if elapsed >= min_delay {
            GreylistDecision::Accept
        } else {
            GreylistDecision::Defer {
                retry_after_secs: (min_delay - elapsed).as_secs().max(1),
            }
        }
    }
}

/// Process-wide store shared by all SMTP sessions.
pub fn global() -> &'static Greylist {
    static GREYLIST: OnceLock<Greylist> = OnceLock::new();
    GREYLIST.get_or_init(|| Greylist::new(200_000, Duration::from_secs(36 * 24 * 3600)))
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

    #[test]
    fn first_attempt_is_deferred_and_retry_after_delay_accepted() {
        let grey = Greylist::new(100, Duration::from_secs(60));
        let delay = Duration::from_millis(50);
        assert!(matches!(
            grey.check(ip("192.0.2.1"), "a@x.test", "b@y.test", delay),
            GreylistDecision::Defer { .. }
        ));
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(
            grey.check(ip("192.0.2.1"), "a@x.test", "b@y.test", delay),
            GreylistDecision::Accept
        );
    }

    #[test]
    fn immediate_retry_is_still_deferred() {
        let grey = Greylist::new(100, Duration::from_secs(60));
        let delay = Duration::from_secs(300);
        grey.check(ip("192.0.2.1"), "a@x.test", "b@y.test", delay);
        assert!(matches!(
            grey.check(ip("192.0.2.1"), "a@x.test", "b@y.test", delay),
            GreylistDecision::Defer { retry_after_secs } if retry_after_secs >= 1
        ));
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
        let grey = Greylist::new(100, Duration::from_secs(60));
        let delay = Duration::from_secs(300);
        grey.check(ip("192.0.2.1"), "a@x.test", "b@y.test", delay);
        assert!(matches!(
            grey.check(ip("192.0.2.1"), "a@x.test", "c@y.test", delay),
            GreylistDecision::Defer { .. }
        ));
    }
}
