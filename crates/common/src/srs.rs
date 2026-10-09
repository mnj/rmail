//! Sender Rewriting Scheme for mail rMail forwards to other servers.
//!
//! A forwarded message keeps its original envelope sender, so the next hop's
//! SPF check fails: the sender's domain never authorized this server. SRS
//! rewrites the sender into an address at `security.srs_domain` that encodes
//! the original one, and bounces to that address are verified and sent back:
//!
//! - `user@example.org` becomes `SRS0=HHHHHHHH=TT=example.org=user@srs.domain`.
//! - An address that is already SRS0 (from another forwarder) becomes
//!   `SRS1=HHHHHHHH=forwarder.example==HHHHHHHH=TT=example.org=user@srs.domain`,
//!   which reverses to the SRS0 address at that forwarder.
//!
//! `HHHHHHHH` is a keyed hash and `TT` a day stamp, both base32 so they survive
//! case changes. Only rMail reverses its own addresses, so the hash need not
//! match other implementations.

use anyhow::{Result, bail};
use hmac::{Hmac, Mac};
use sha2::Sha256;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/// Bounces to rewritten addresses are accepted for this many days.
const MAX_AGE_DAYS: u64 = 21;
/// 8 base32 characters (40 bits): a valid hash lets anyone relay through
/// the SRS domain, so it must resist guessing over many RCPT attempts.
const HASH_LEN: usize = 8;

fn day_stamp(day: u64) -> String {
    let day = day % 1024;
    [day >> 5, day & 31]
        .iter()
        .map(|value| BASE32[*value as usize] as char)
        .collect()
}

fn decode_stamp(stamp: &str) -> Option<u64> {
    let mut value = 0u64;
    for byte in stamp.bytes() {
        let digit = BASE32
            .iter()
            .position(|candidate| *candidate == byte.to_ascii_uppercase())?;
        value = value * 32 + digit as u64;
    }
    (stamp.len() == 2).then_some(value)
}

fn hash(secret: &[u8], parts: &[&str]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part.to_ascii_lowercase().as_bytes());
        mac.update(b"\0");
    }
    let digest = mac.finalize().into_bytes();
    digest
        .iter()
        .take(HASH_LEN)
        .map(|byte| BASE32[(byte % 32) as usize] as char)
        .collect()
}

fn days_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() / 86_400)
        .unwrap_or(0)
}

/// Whether `local` (the part before `@`) is an SRS address.
pub fn is_srs(local: &str) -> bool {
    let prefix = local.get(..5).unwrap_or("");
    prefix.eq_ignore_ascii_case("SRS0=") || prefix.eq_ignore_ascii_case("SRS1=")
}

/// The rewritten envelope sender for forwarding mail from `sender`.
pub fn forward(sender: &str, srs_domain: &str, secret: &[u8]) -> Result<String> {
    forward_on(sender, srs_domain, secret, days_now())
}

fn forward_on(sender: &str, srs_domain: &str, secret: &[u8], day: u64) -> Result<String> {
    let Some((local, domain)) = sender.rsplit_once('@') else {
        bail!("not an address: {sender}");
    };
    if domain.eq_ignore_ascii_case(srs_domain) && is_srs(local) {
        // Already ours: forwarding it again keeps the address.
        return Ok(sender.to_string());
    }
    if local
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("SRS0="))
    {
        // SRS1 keeps the first forwarder's SRS0 address reachable.
        let rest = &local[4..];
        let hash = hash(secret, &[domain, rest]);
        return Ok(format!("SRS1={hash}={domain}={rest}@{srs_domain}"));
    }
    if local
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("SRS1="))
    {
        // Re-forwarding an SRS1 address: keep its original forwarder.
        let Some((_, rest)) = local[5..].split_once('=') else {
            bail!("malformed SRS1 address: {sender}");
        };
        let Some((forwarder, rest)) = rest.split_once('=') else {
            bail!("malformed SRS1 address: {sender}");
        };
        let hash = hash(secret, &[forwarder, rest]);
        return Ok(format!("SRS1={hash}={forwarder}={rest}@{srs_domain}"));
    }
    let stamp = day_stamp(day);
    let hash = hash(secret, &[&stamp, domain, local]);
    Ok(format!("SRS0={hash}={stamp}={domain}={local}@{srs_domain}"))
}

/// The address a bounce to the SRS address `local@<srs domain>` returns to,
/// after checking its hash and age.
pub fn reverse(local: &str, secret: &[u8]) -> Result<String> {
    reverse_on(local, secret, days_now())
}

fn reverse_on(local: &str, secret: &[u8], day: u64) -> Result<String> {
    let prefix = local.get(..5).unwrap_or("").to_ascii_uppercase();
    let body = local.get(5..).unwrap_or("");
    match prefix.as_str() {
        "SRS0=" => {
            let mut fields = body.splitn(4, '=');
            let (Some(given), Some(stamp), Some(domain), Some(original)) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                bail!("malformed SRS0 address");
            };
            if !given.eq_ignore_ascii_case(&hash(secret, &[stamp, domain, original])) {
                bail!("SRS0 hash does not match");
            }
            let stamped =
                decode_stamp(stamp).ok_or_else(|| anyhow::anyhow!("bad SRS0 time stamp"))?;
            let age = (day % 1024 + 1024 - stamped) % 1024;
            if age > MAX_AGE_DAYS {
                bail!("SRS0 address expired");
            }
            if domain.is_empty() || original.is_empty() {
                bail!("malformed SRS0 address");
            }
            Ok(format!("{original}@{domain}"))
        }
        "SRS1=" => {
            let mut fields = body.splitn(3, '=');
            let (Some(given), Some(forwarder), Some(rest)) =
                (fields.next(), fields.next(), fields.next())
            else {
                bail!("malformed SRS1 address");
            };
            if !given.eq_ignore_ascii_case(&hash(secret, &[forwarder, rest])) {
                bail!("SRS1 hash does not match");
            }
            if forwarder.is_empty() || !rest.starts_with('=') {
                bail!("malformed SRS1 address");
            }
            Ok(format!("SRS0{rest}@{forwarder}"))
        }
        _ => bail!("not an SRS address"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"test-key";

    #[test]
    fn srs0_round_trips_and_checks_hash_and_age() {
        let rewritten = forward_on("Alice@Example.org", "fwd.example", KEY, 20_000).unwrap();
        let (local, domain) = rewritten.rsplit_once('@').unwrap();
        assert_eq!(domain, "fwd.example");
        assert!(local.starts_with("SRS0="), "{rewritten}");
        assert!(local.ends_with("=Example.org=Alice"), "{rewritten}");
        assert_eq!(reverse_on(local, KEY, 20_000).unwrap(), "Alice@Example.org");
        // Survives a downcased local part.
        assert_eq!(
            reverse_on(&local.to_ascii_lowercase(), KEY, 20_005).unwrap(),
            "alice@example.org"
        );
        assert!(reverse_on(local, KEY, 20_000 + MAX_AGE_DAYS + 1).is_err());
        assert!(reverse_on(local, b"other-key", 20_000).is_err());
        let forged = local.replacen("Alice", "Mallory", 1);
        assert!(reverse_on(&forged, KEY, 20_000).is_err());
        // Day stamps wrap every 1024 days.
        let wrapped = forward_on("a@b.example", "fwd.example", KEY, 1023).unwrap();
        let local = wrapped.rsplit_once('@').unwrap().0;
        assert_eq!(reverse_on(local, KEY, 1024 + 3).unwrap(), "a@b.example");
    }

    #[test]
    fn srs1_points_back_at_the_first_forwarder() {
        let first = "SRS0=ABCD=XY=example.org=alice@first.example";
        let rewritten = forward_on(first, "fwd.example", KEY, 1).unwrap();
        assert!(rewritten.starts_with("SRS1="), "{rewritten}");
        let local = rewritten.rsplit_once('@').unwrap().0;
        assert_eq!(reverse_on(local, KEY, 1).unwrap(), first);
        // Forwarding our own SRS address again leaves it alone.
        assert_eq!(
            forward_on(&rewritten, "fwd.example", KEY, 2).unwrap(),
            rewritten
        );
        assert!(is_srs(local) && !is_srs("alice"));
    }
}
