//! Per-client and per-user rate limits.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;

static SUBMISSION_MESSAGES: Lazy<Mutex<HashMap<String, VecDeque<Instant>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
// Longer-window caps that catch a compromised account sending steadily below
// the per-minute limit: per user over a day, per sending domain over an hour.
static SUBMISSION_DAILY: Lazy<Mutex<HashMap<String, VecDeque<Instant>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static SUBMISSION_DOMAIN_HOURLY: Lazy<Mutex<HashMap<String, VecDeque<Instant>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
const DAY: Duration = Duration::from_secs(24 * 3600);
const HOUR: Duration = Duration::from_secs(3600);

static CONNECTION_ATTEMPTS: Lazy<Mutex<HashMap<IpAddr, VecDeque<Instant>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// In-process brute-force protection keyed by client address (IPv6 by /64).
static AUTH_THROTTLE: Lazy<rmail_common::throttle::AuthThrottle> =
    Lazy::new(rmail_common::throttle::AuthThrottle::default);

/// Remaining authentication lockout for the client, if any.
pub(crate) fn auth_block_remaining(ip: IpAddr) -> Option<Duration> {
    AUTH_THROTTLE.blocked_for(ip)
}

/// Record a failed authentication; repeated failures lock the client out.
pub(crate) fn record_auth_failure(ip: IpAddr) {
    rmail_common::metrics::inc_auth_failures();
    AUTH_THROTTLE.record_failure(ip);
}

/// Clear recorded failures after a successful authentication.
pub(crate) fn reset_auth_failures(ip: IpAddr) {
    AUTH_THROTTLE.reset(ip);
}

pub(crate) fn submission_quota_available(user: &str, limit: usize) -> bool {
    let now = Instant::now();
    let mut all = SUBMISSION_MESSAGES.lock().unwrap();
    let messages = all.entry(user.to_ascii_lowercase()).or_default();
    while messages
        .front()
        .is_some_and(|seen| now.duration_since(*seen) >= Duration::from_secs(60))
    {
        messages.pop_front();
    }
    messages.len() < limit.max(1)
}

pub(crate) fn record_submission_message(user: &str) {
    let now = Instant::now();
    let user = user.to_ascii_lowercase();
    SUBMISSION_MESSAGES
        .lock()
        .unwrap()
        .entry(user.clone())
        .or_default()
        .push_back(now);
    SUBMISSION_DAILY
        .lock()
        .unwrap()
        .entry(user.clone())
        .or_default()
        .push_back(now);
    if let Some((_, domain)) = user.rsplit_once('@') {
        SUBMISSION_DOMAIN_HOURLY
            .lock()
            .unwrap()
            .entry(domain.to_string())
            .or_default()
            .push_back(now);
    }
}

/// Which long-window submission cap, if any, a sender has reached.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SenderLimit {
    UserDaily,
    DomainHourly,
}

/// Per-user daily and per-domain hourly caps; a limit of 0 disables that cap.
pub(crate) fn sender_limit_reached(
    user: &str,
    daily_per_user: usize,
    hourly_per_domain: usize,
) -> Option<SenderLimit> {
    sender_limit_reached_at(user, daily_per_user, hourly_per_domain, Instant::now())
}

fn sender_limit_reached_at(
    user: &str,
    daily_per_user: usize,
    hourly_per_domain: usize,
    now: Instant,
) -> Option<SenderLimit> {
    let user = user.to_ascii_lowercase();
    if daily_per_user > 0 && window_count(&SUBMISSION_DAILY, &user, DAY, now) >= daily_per_user {
        return Some(SenderLimit::UserDaily);
    }
    if hourly_per_domain > 0
        && let Some((_, domain)) = user.rsplit_once('@')
        && window_count(&SUBMISSION_DOMAIN_HOURLY, domain, HOUR, now) >= hourly_per_domain
    {
        return Some(SenderLimit::DomainHourly);
    }
    None
}

/// Entries inside `window` for `key`, dropping expired ones (and the key when empty).
fn window_count(
    map: &Mutex<HashMap<String, VecDeque<Instant>>>,
    key: &str,
    window: Duration,
    now: Instant,
) -> usize {
    let mut all = map.lock().unwrap();
    let Some(entries) = all.get_mut(key) else {
        return 0;
    };
    while entries
        .front()
        .is_some_and(|seen| now.saturating_duration_since(*seen) >= window)
    {
        entries.pop_front();
    }
    let count = entries.len();
    if count == 0 {
        all.remove(key);
    }
    count
}

/// Sliding one-minute connection rate limit per client address.
pub(crate) fn accept_connection_from(ip: IpAddr, limit: usize) -> bool {
    const MAX_TRACKED_SOURCE_IPS: usize = 10_000;
    let now = Instant::now();
    let mut all = CONNECTION_ATTEMPTS.lock().unwrap();
    all.retain(|_, attempts| {
        while attempts
            .front()
            .is_some_and(|seen| now.duration_since(*seen) >= Duration::from_secs(60))
        {
            attempts.pop_front();
        }
        !attempts.is_empty()
    });
    if !all.contains_key(&ip)
        && all.len() >= MAX_TRACKED_SOURCE_IPS
        && let Some(oldest) = all
            .iter()
            .min_by_key(|(_, attempts)| attempts.back().copied())
            .map(|(address, _)| *address)
    {
        all.remove(&oldest);
    }
    let attempts = all.entry(ip).or_default();
    if attempts.len() >= limit.max(1) {
        return false;
    }
    attempts.push_back(now);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daily_user_and_hourly_domain_caps_apply_and_expire() {
        let (a, b) = ("cap-a@capdomain.test", "cap-b@capdomain.test");
        assert_eq!(sender_limit_reached(a, 2, 3), None);
        record_submission_message(a);
        record_submission_message(a);
        assert_eq!(sender_limit_reached(a, 2, 3), Some(SenderLimit::UserDaily));
        // Another user of the domain is not hit by a's daily cap, but the
        // domain hourly total (2 so far) counts everyone.
        assert_eq!(sender_limit_reached(b, 2, 3), None);
        record_submission_message(b);
        assert_eq!(
            sender_limit_reached(b, 2, 3),
            Some(SenderLimit::DomainHourly)
        );
        // 0 disables a cap.
        assert_eq!(sender_limit_reached(b, 0, 0), None);

        // After an hour the domain cap clears; the daily cap persists for a.
        let later = Instant::now() + HOUR + Duration::from_secs(1);
        assert_eq!(sender_limit_reached_at(b, 2, 3, later), None);
        assert_eq!(
            sender_limit_reached_at(a, 2, 3, later),
            Some(SenderLimit::UserDaily)
        );
        let next_day = Instant::now() + DAY + Duration::from_secs(1);
        assert_eq!(sender_limit_reached_at(a, 2, 3, next_day), None);
    }
}
