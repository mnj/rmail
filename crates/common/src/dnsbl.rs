//! DNS blocklist (DNSBL/RBL) lookups for inbound client addresses (RFC 5782).
//!
//! Lookups fail open: a timeout or resolver error counts as "not listed", so a
//! broken or rate-limiting blocklist never blocks mail.

use moka::future::Cache;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::OnceLock;
use std::time::Duration;
use tokio::task::JoinSet;

const CACHE_TTL: Duration = Duration::from_secs(600);
const CACHE_ENTRIES: u64 = 50_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    pub zone: String,
    /// The 127.0.0.x answer, which many lists use to encode the reason.
    pub code: Ipv4Addr,
}

/// `4.3.2.1.zone` for 1.2.3.4; reversed nibbles for IPv6 (RFC 5782 section 2.4).
pub fn query_name(ip: IpAddr, zone: &str) -> String {
    let zone = zone.trim().trim_matches('.');
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.{zone}", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut name = String::with_capacity(64 + zone.len() + 1);
            for byte in v6.octets().iter().rev() {
                name.push_str(&format!("{:x}.{:x}.", byte & 0x0f, byte >> 4));
            }
            name.push_str(zone);
            name
        }
    }
}

/// Interpret an answer set. Only 127.0.0.0/8 answers mean "listed"; the
/// 127.255.255.0/24 range is how e.g. Spamhaus reports refused or over-quota
/// queries, which must not be treated as a listing.
pub fn listed_code(answers: &[IpAddr]) -> Option<Ipv4Addr> {
    answers.iter().find_map(|answer| match answer {
        IpAddr::V4(v4) if v4.octets()[0] == 127 && v4.octets()[1..3] != [255, 255] => Some(*v4),
        _ => None,
    })
}

/// Ranges that are never listed and not worth a DNS query.
fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique local
        }
    }
}

fn cache() -> &'static Cache<(IpAddr, String), Option<Listing>> {
    static CACHE: OnceLock<Cache<(IpAddr, String), Option<Listing>>> = OnceLock::new();
    CACHE.get_or_init(|| {
        Cache::builder()
            .max_capacity(CACHE_ENTRIES)
            .time_to_live(CACHE_TTL)
            .build()
    })
}

/// Pre-seed the result cache so session tests need no DNS.
#[cfg(any(test, feature = "test-support"))]
pub async fn seed_cache(ip: IpAddr, zone: &str, listing: Option<Listing>) {
    cache().insert((ip, zone.to_string()), listing).await;
}

/// First listing found across `zones`, querying them concurrently.
pub async fn check(ip: IpAddr, zones: &[String], timeout: Duration) -> Option<Listing> {
    if is_local(ip) || zones.is_empty() {
        return None;
    }
    let mut lookups = JoinSet::new();
    for zone in zones.iter().filter(|zone| !zone.trim().is_empty()) {
        let zone = zone.trim().trim_matches('.').to_ascii_lowercase();
        lookups.spawn(async move {
            // Failures are not cached (try_get_with only stores Ok), so the
            // next attempt retries; the failed attempt itself fails open.
            cache()
                .try_get_with((ip, zone.clone()), lookup_zone(ip, &zone, timeout))
                .await
                .unwrap_or(None)
        });
    }
    while let Some(result) = lookups.join_next().await {
        if let Ok(Some(listing)) = result {
            lookups.abort_all();
            return Some(listing);
        }
    }
    None
}

fn is_no_records(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<mail_auth::hickory_resolver::net::NetError>()
        .is_some_and(|error| error.is_no_records_found())
}

/// `Err` means the lookup failed (timeout or resolver error) and must not be
/// cached; NXDOMAIN-style "no records" is a clean `Ok(None)`.
async fn lookup_zone(ip: IpAddr, zone: &str, timeout: Duration) -> Result<Option<Listing>, ()> {
    let name = query_name(ip, zone);
    let answers =
        match tokio::time::timeout(timeout, crate::mail_auth::lookup_ip_addrs(&name)).await {
            Ok(Ok(answers)) => answers,
            Ok(Err(error)) if is_no_records(&error) => return Ok(None),
            _ => return Err(()),
        };
    Ok(listed_code(&answers).map(|code| Listing {
        zone: zone.to_string(),
        code,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_query_name_reverses_octets() {
        assert_eq!(
            query_name("192.0.2.99".parse().unwrap(), "zen.example."),
            "99.2.0.192.zen.example"
        );
    }

    #[test]
    fn ipv6_query_name_uses_reversed_nibbles() {
        assert_eq!(
            query_name("2001:db8::1".parse().unwrap(), "bl.example"),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.bl.example"
        );
    }

    #[test]
    fn only_loopback_range_answers_are_listings() {
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        assert_eq!(
            listed_code(&[ip("127.0.0.2")]),
            Some(Ipv4Addr::new(127, 0, 0, 2))
        );
        assert_eq!(listed_code(&[ip("127.255.255.254")]), None);
        assert_eq!(listed_code(&[ip("192.0.2.1")]), None);
        assert_eq!(listed_code(&[]), None);
        assert_eq!(
            listed_code(&[ip("127.255.255.252"), ip("127.0.0.4")]),
            Some(Ipv4Addr::new(127, 0, 0, 4))
        );
    }

    #[tokio::test]
    async fn local_addresses_and_empty_zone_lists_skip_dns() {
        let zones = vec!["bl.example".to_string()];
        let t = Duration::from_millis(50);
        assert_eq!(check("127.0.0.1".parse().unwrap(), &zones, t).await, None);
        assert_eq!(check("10.1.2.3".parse().unwrap(), &zones, t).await, None);
        assert_eq!(check("203.0.113.9".parse().unwrap(), &[], t).await, None);
    }
}
