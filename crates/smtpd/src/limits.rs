//! Per-client and per-user rate limits.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;

static SUBMISSION_MESSAGES: Lazy<Mutex<HashMap<String, VecDeque<Instant>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
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
    SUBMISSION_MESSAGES
        .lock()
        .unwrap()
        .entry(user.to_ascii_lowercase())
        .or_default()
        .push_back(Instant::now());
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
