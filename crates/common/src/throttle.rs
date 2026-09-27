//! Per-client authentication failure throttling shared by every daemon that
//! accepts passwords.
//!
//! Failures are counted inside a sliding window; reaching the limit locks the
//! client out for a fixed period. IPv6 clients are grouped by their /64 prefix
//! because a single host usually controls a whole /64. Idle entries are pruned
//! so the table cannot grow without bound.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const PRUNE_THRESHOLD: usize = 4096;

#[derive(Debug, Clone, Copy)]
pub struct ThrottlePolicy {
    pub max_failures: u32,
    pub window: Duration,
    pub lockout: Duration,
}

impl Default for ThrottlePolicy {
    fn default() -> Self {
        Self {
            max_failures: 5,
            window: Duration::from_secs(10 * 60),
            lockout: Duration::from_secs(30 * 60),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    failures: u32,
    window_start: Instant,
    locked_until: Option<Instant>,
}

#[derive(Debug)]
pub struct AuthThrottle {
    policy: ThrottlePolicy,
    entries: Mutex<HashMap<IpAddr, Entry>>,
}

impl Default for AuthThrottle {
    fn default() -> Self {
        Self::new(ThrottlePolicy::default())
    }
}

impl AuthThrottle {
    pub fn new(policy: ThrottlePolicy) -> Self {
        Self {
            policy,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Remaining lockout for the client, if any.
    pub fn blocked_for(&self, ip: IpAddr) -> Option<Duration> {
        self.blocked_for_at(ip, Instant::now())
    }

    pub fn record_failure(&self, ip: IpAddr) {
        self.record_failure_at(ip, Instant::now());
    }

    pub fn reset(&self, ip: IpAddr) {
        self.lock().remove(&throttle_key(ip));
    }

    pub fn tracked_clients(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, Entry>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn blocked_for_at(&self, ip: IpAddr, now: Instant) -> Option<Duration> {
        let entries = self.lock();
        let until = entries.get(&throttle_key(ip))?.locked_until?;
        (until > now).then(|| until - now)
    }

    fn record_failure_at(&self, ip: IpAddr, now: Instant) {
        let mut entries = self.lock();
        if entries.len() >= PRUNE_THRESHOLD {
            let policy = self.policy;
            entries.retain(|_, entry| !is_idle(entry, &policy, now));
        }
        let entry = entries.entry(throttle_key(ip)).or_insert(Entry {
            failures: 0,
            window_start: now,
            locked_until: None,
        });
        if entry.locked_until.is_some_and(|until| until > now) {
            return;
        }
        if now.duration_since(entry.window_start) > self.policy.window {
            entry.failures = 0;
            entry.window_start = now;
            entry.locked_until = None;
        }
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= self.policy.max_failures {
            entry.locked_until = Some(now + self.policy.lockout);
            entry.failures = 0;
            entry.window_start = now;
        }
    }
}

fn is_idle(entry: &Entry, policy: &ThrottlePolicy, now: Instant) -> bool {
    let locked = entry.locked_until.is_some_and(|until| until > now);
    !locked && now.duration_since(entry.window_start) > policy.window
}

fn throttle_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            let mut segments = v6.segments();
            segments[4..].fill(0);
            IpAddr::V6(segments.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ThrottlePolicy {
        ThrottlePolicy {
            max_failures: 3,
            window: Duration::from_secs(60),
            lockout: Duration::from_secs(300),
        }
    }

    #[test]
    fn locks_after_failures_inside_window() {
        let throttle = AuthThrottle::new(policy());
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let now = Instant::now();
        for _ in 0..3 {
            assert!(throttle.blocked_for_at(ip, now).is_none());
            throttle.record_failure_at(ip, now);
        }
        assert!(throttle.blocked_for_at(ip, now).is_some());
        assert!(
            throttle
                .blocked_for_at(ip, now + Duration::from_secs(301))
                .is_none()
        );
    }

    #[test]
    fn failures_outside_window_do_not_accumulate() {
        let throttle = AuthThrottle::new(policy());
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let start = Instant::now();
        for step in 0..10u64 {
            throttle.record_failure_at(ip, start + Duration::from_secs(step * 61));
        }
        assert!(
            throttle
                .blocked_for_at(ip, start + Duration::from_secs(10 * 61))
                .is_none()
        );
    }

    #[test]
    fn ipv6_clients_share_their_64_prefix() {
        let throttle = AuthThrottle::new(policy());
        let now = Instant::now();
        for host in 1..=3 {
            let ip: IpAddr = format!("2001:db8:1:2::{host}").parse().unwrap();
            throttle.record_failure_at(ip, now);
        }
        let sibling: IpAddr = "2001:db8:1:2:ffff::1".parse().unwrap();
        assert!(throttle.blocked_for_at(sibling, now).is_some());
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert!(throttle.blocked_for_at(other, now).is_none());
    }

    #[test]
    fn idle_entries_are_pruned() {
        let throttle = AuthThrottle::new(policy());
        let start = Instant::now();
        for i in 0..PRUNE_THRESHOLD as u32 {
            throttle.record_failure_at(IpAddr::V4(i.into()), start);
        }
        assert_eq!(throttle.tracked_clients(), PRUNE_THRESHOLD);
        throttle.record_failure_at(
            "198.51.100.1".parse().unwrap(),
            start + Duration::from_secs(120),
        );
        assert_eq!(throttle.tracked_clients(), 1);
    }

    #[test]
    fn reset_clears_client() {
        let throttle = AuthThrottle::new(policy());
        let ip: IpAddr = "192.0.2.9".parse().unwrap();
        for _ in 0..3 {
            throttle.record_failure_at(ip, Instant::now());
        }
        throttle.reset(ip);
        assert!(throttle.blocked_for(ip).is_none());
    }
}
