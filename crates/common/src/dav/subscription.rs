//! Calendar subscriptions: read-only calendars filled from an iCalendar
//! feed on the web (webcal), such as public holidays or a team's published
//! calendar, and refreshed now and then.
//!
//! - A subscription is an ordinary calendar collection in the user's store
//!   (so CalDAV clients see it too) with a row in `dav_subscriptions`; the
//!   DAV server and webmail refuse writes to it.
//! - The feed URL comes from the user, so fetching it is guarded against
//!   reaching this server's own network (SSRF): only http(s), every address
//!   the name resolves to must be public, the connection goes to the address
//!   that was checked (no second lookup to rebind), and each redirect is
//!   checked the same way. Size, time and event count are capped.
//! - Each refresh replaces the calendar's contents with the feed's events,
//!   one object per UID; unchanged events keep their ETags, so clients only
//!   fetch what changed.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};

use super::store::{self, Collection, Kind};
use super::text::{self, Component};

/// The largest feed read.
pub const MAX_FEED_BYTES: usize = 5 * 1024 * 1024;
/// Events kept from one feed.
pub const MAX_EVENTS: usize = 5_000;
/// How often a subscription is fetched again.
pub const REFRESH_SECONDS: i64 = 6 * 3600;
/// Subscriptions per account.
pub const MAX_SUBSCRIPTIONS: usize = 20;
/// Subscription calendars' names start with this; CalDAV treats them as
/// read-only and does not let clients create collections named so.
pub const NAME_PREFIX: &str = "subscription-";
const TIMEOUT: Duration = Duration::from_secs(20);
const MAX_REDIRECTS: usize = 3;

pub(crate) const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS dav_subscriptions(
        collection_id INTEGER PRIMARY KEY,
        url TEXT NOT NULL,
        refreshed_at INTEGER,
        error TEXT
    );
";

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    pub collection: Collection,
    pub url: String,
    pub refreshed_at: Option<i64>,
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// URLs and addresses

/// A feed URL as fetched: `webcal://` becomes `https://`; only http(s),
/// without credentials in the URL.
pub fn normalize_url(input: &str) -> Result<reqwest::Url> {
    let input = input.trim();
    let input = match input.get(..9) {
        Some(scheme) if scheme.eq_ignore_ascii_case("webcal://") => {
            format!("https://{}", &input[9..])
        }
        _ => match input.get(..10) {
            Some(scheme) if scheme.eq_ignore_ascii_case("webcals://") => {
                format!("https://{}", &input[10..])
            }
            _ => input.to_string(),
        },
    };
    let url = reqwest::Url::parse(&input).context("not a web address")?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("only http, https and webcal addresses can be subscribed to");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("addresses with a user name or password are not supported");
    }
    if url.host_str().is_none_or(str::is_empty) || input.len() > 2_000 {
        bail!("not a web address");
    }
    Ok(url)
}

/// An address on the public internet: not this host, a private network,
/// link-local, multicast, documentation or reserved space.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || a == 0
                || (a == 100 && (b & 0xc0) == 64)
                || (a == 192 && b == 0 && c == 0)
                || (a == 198 && (b & 0xfe) == 18)
                || a >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            // Global unicast (2000::/3), less documentation (2001:db8::/32).
            (first & 0xe000) == 0x2000 && !(first == 0x2001 && v6.segments()[1] == 0x0db8)
        }
    }
}

/// The public address to connect to for `url`, or why there is none.
async fn public_address(url: &reqwest::Url) -> Result<SocketAddr> {
    let host = url.host_str().context("no host")?;
    let port = url.port_or_known_default().context("no port")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let addresses: Vec<SocketAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => tokio::net::lookup_host((host, port))
            .await
            .with_context(|| format!("{host} could not be found"))?
            .collect(),
    };
    if addresses.is_empty() {
        bail!("{host} could not be found");
    }
    // Every address must be public, or a name could point both ways.
    if addresses.iter().any(|address| !is_public(address.ip())) {
        bail!("{host} is not on the public internet");
    }
    Ok(addresses[0])
}

/// Fetch a feed: public addresses only, redirects checked one by one, all
/// of it (lookups, redirects and the body) within [`TIMEOUT`].
pub async fn fetch(url: &reqwest::Url) -> Result<String> {
    match tokio::time::timeout(TIMEOUT, fetch_unbounded(url)).await {
        Ok(result) => result,
        Err(_) => bail!("the calendar's server took too long"),
    }
}

async fn fetch_unbounded(url: &reqwest::Url) -> Result<String> {
    let mut url = url.clone();
    for _ in 0..=MAX_REDIRECTS {
        let address = public_address(&url).await?;
        let host = url.host_str().context("no host")?.to_string();
        let client = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .resolve(&host, address)
            .user_agent(concat!("rMail-calendar/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let mut response = client
            .get(url.clone())
            .header("Accept", "text/calendar, */*;q=0.5")
            .send()
            .await
            .with_context(|| format!("{host} did not answer"))?;
        let status = response.status();
        if status.is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .context("a redirect without a location")?;
            url = normalize_url(url.join(location)?.as_str())?;
            continue;
        }
        if !status.is_success() {
            bail!("the calendar's server answered {status}");
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > MAX_FEED_BYTES {
                bail!(
                    "the calendar is larger than {} MB",
                    MAX_FEED_BYTES / (1024 * 1024)
                );
            }
            body.extend_from_slice(&chunk);
        }
        return String::from_utf8(body).context("the calendar is not text");
    }
    bail!("too many redirects")
}

// ---------------------------------------------------------------------------
// Feeds into objects

/// The feed's events, one calendar object per UID (with the time zones it
/// uses), keyed by a resource name derived from the UID.
pub fn objects_of(feed: &str) -> Result<BTreeMap<String, String>> {
    let calendar = text::parse(feed).context("not an iCalendar file")?;
    if calendar.name != "VCALENDAR" {
        bail!("not an iCalendar file");
    }
    let zones: Vec<&Component> = calendar
        .components
        .iter()
        .filter(|c| c.name == "VTIMEZONE")
        .collect();
    let mut by_uid: BTreeMap<String, Vec<&Component>> = BTreeMap::new();
    for component in calendar.components.iter().filter(|c| c.name == "VEVENT") {
        let Some(uid) = component
            .property("UID")
            .map(|uid| uid.value.trim().to_string())
        else {
            continue;
        };
        if uid.is_empty() || uid.len() > 500 {
            continue;
        }
        if !by_uid.contains_key(&uid) && by_uid.len() >= MAX_EVENTS {
            continue;
        }
        by_uid.entry(uid).or_default().push(component);
    }
    let mut objects = BTreeMap::new();
    for (uid, events) in by_uid {
        let mut object = Component::new("VCALENDAR");
        object.set_property("VERSION", "2.0");
        object.set_property("PRODID", "-//rMail//subscription//EN");
        let used: Vec<&str> = events
            .iter()
            .flat_map(|event| event.properties.iter())
            .filter_map(|property| property.param("TZID"))
            .collect();
        for zone in &zones {
            if zone
                .property("TZID")
                .is_some_and(|tzid| used.contains(&tzid.value.trim()))
            {
                object.components.push((*zone).clone());
            }
        }
        object.components.extend(events.into_iter().cloned());
        objects.insert(resource_name(&uid), object.to_text());
    }
    Ok(objects)
}

/// A resource name for a UID: stable, so refreshes update in place.
fn resource_name(uid: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(uid.as_bytes());
    let hex: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!("{hex}.ics")
}

// ---------------------------------------------------------------------------
// Storage

fn ensure(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA)?;
    Ok(())
}

/// Whether a collection is a subscription (read-only).
pub fn is_subscription(conn: &Connection, collection_id: i64) -> Result<bool> {
    ensure(conn)?;
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM dav_subscriptions WHERE collection_id = ?1)",
        params![collection_id],
        |row| row.get(0),
    )?)
}

pub fn subscriptions(conn: &Connection) -> Result<Vec<Subscription>> {
    ensure(conn)?;
    let mut stmt =
        conn.prepare("SELECT collection_id, url, refreshed_at, error FROM dav_subscriptions")?;
    let rows: Vec<(i64, String, Option<i64>, Option<String>)> = stmt
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut out = Vec::new();
    for (id, url, refreshed_at, error) in rows {
        if let Some(collection) = store::collection_by_id(conn, id)? {
            out.push(Subscription {
                collection,
                url,
                refreshed_at,
                error,
            });
        }
    }
    Ok(out)
}

/// A new, empty subscription calendar for `url` (fill it with [`refresh`]).
pub fn subscribe(
    conn: &Connection,
    url: &reqwest::Url,
    displayname: &str,
    color: Option<&str>,
) -> Result<Collection> {
    ensure(conn)?;
    if subscriptions(conn)?.len() >= MAX_SUBSCRIPTIONS {
        bail!("at most {MAX_SUBSCRIPTIONS} subscriptions");
    }
    if subscriptions(conn)?.iter().any(|s| s.url == url.as_str()) {
        bail!("you are already subscribed to this calendar");
    }
    let name = format!(
        "{NAME_PREFIX}{}",
        (0..6)
            .map(|_| format!("{:02x}", rand::random::<u8>()))
            .collect::<String>()
    );
    let displayname = displayname.trim();
    let displayname = if displayname.is_empty() {
        url.host_str().unwrap_or("Subscription")
    } else {
        displayname
    };
    let collection =
        store::create_managed(conn, Kind::Calendar, &name, Some(displayname), &["VEVENT"])?;
    if let Some(color) = color.filter(|c| c.len() <= 9 && c.starts_with('#')) {
        store::set_property(conn, &collection, store::Setting::Color, Some(color))?;
    }
    conn.execute(
        "INSERT INTO dav_subscriptions (collection_id, url) VALUES (?1, ?2)",
        params![collection.id, url.as_str()],
    )?;
    Ok(collection)
}

/// Drop the subscription row of a collection deleted some other way.
pub fn forget(conn: &Connection, collection_id: i64) -> Result<()> {
    ensure(conn)?;
    conn.execute(
        "DELETE FROM dav_subscriptions WHERE collection_id = ?1",
        params![collection_id],
    )?;
    Ok(())
}

pub fn unsubscribe(conn: &Connection, collection: &Collection) -> Result<()> {
    ensure(conn)?;
    conn.execute(
        "DELETE FROM dav_subscriptions WHERE collection_id = ?1",
        params![collection.id],
    )?;
    store::delete_collection(conn, collection)
}

/// Replace the calendar's events with `objects`; unchanged ones are left
/// alone. Returns how many were stored and removed.
pub fn apply(
    conn: &Connection,
    collection: &Collection,
    objects: &BTreeMap<String, String>,
) -> Result<(usize, usize)> {
    let current = store::objects(conn, collection)?;
    let mut removed = 0;
    for object in &current {
        if !objects.contains_key(&object.name) {
            let name = object.name.clone();
            if matches!(
                store::delete(conn, collection, &name, &|_| true)?,
                store::Deleted::Deleted(_)
            ) {
                removed += 1;
            }
        }
    }
    let mut stored = 0;
    for (name, data) in objects {
        if current
            .iter()
            .any(|object| &object.name == name && &object.data == data)
        {
            continue;
        }
        if store::put(conn, collection, name, data, &|_| true)?.is_ok() {
            stored += 1;
        }
    }
    Ok((stored, removed))
}

pub fn record(conn: &Connection, collection: &Collection, error: Option<&str>) -> Result<()> {
    ensure(conn)?;
    conn.execute(
        "UPDATE dav_subscriptions SET refreshed_at = ?2, error = ?3 WHERE collection_id = ?1",
        params![collection.id, now(), error],
    )?;
    Ok(())
}

/// Subscriptions not fetched for [`REFRESH_SECONDS`] (or never).
pub fn due(conn: &Connection) -> Result<Vec<Subscription>> {
    Ok(subscriptions(conn)?
        .into_iter()
        .filter(|s| {
            s.refreshed_at
                .is_none_or(|at| now() - at >= REFRESH_SECONDS)
        })
        .collect())
}

/// The subscription of a collection, if it is one.
pub fn subscription(conn: &Connection, collection_id: i64) -> Result<Option<Subscription>> {
    ensure(conn)?;
    let row: Option<String> = conn
        .query_row(
            "SELECT url FROM dav_subscriptions WHERE collection_id = ?1",
            params![collection_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(match row {
        Some(_) => subscriptions(conn)?
            .into_iter()
            .find(|s| s.collection.id == collection_id),
        None => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_and_addresses() {
        assert_eq!(
            normalize_url("webcal://example.test/h.ics")
                .unwrap()
                .as_str(),
            "https://example.test/h.ics"
        );
        assert_eq!(
            normalize_url(" WEBCALS://example.test/h.ics")
                .unwrap()
                .scheme(),
            "https"
        );
        assert!(normalize_url("ftp://example.test/h.ics").is_err());
        assert!(normalize_url("file:///etc/passwd").is_err());
        assert!(normalize_url("https://user:pw@example.test/h.ics").is_err());
        for private in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
        for public in ["93.184.216.34", "2606:4700::1111"] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
    }

    #[tokio::test]
    async fn private_addresses_are_not_fetched() {
        for url in [
            "http://127.0.0.1:9/x.ics",
            "http://[::1]/x.ics",
            "http://localhost/x.ics",
            "http://169.254.169.254/latest",
        ] {
            let error = fetch(&normalize_url(url).unwrap())
                .await
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("not on the public internet"),
                "{url}: {error}"
            );
        }
    }

    #[test]
    fn feeds_become_one_object_per_event_and_refresh_in_place() {
        let feed = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n\
            BEGIN:VTIMEZONE\r\nTZID:Europe/Copenhagen\r\nBEGIN:STANDARD\r\nDTSTART:19701025T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n\
            BEGIN:VEVENT\r\nUID:a\r\nDTSTAMP:20260101T000000Z\r\nDTSTART;VALUE=DATE:20261224\r\nSUMMARY:Christmas Eve\r\nEND:VEVENT\r\n\
            BEGIN:VEVENT\r\nUID:b\r\nDTSTAMP:20260101T000000Z\r\nDTSTART;TZID=Europe/Copenhagen:20261020T090000\r\nSUMMARY:Standup\r\nEND:VEVENT\r\n\
            BEGIN:VEVENT\r\nDTSTART:20261020T090000Z\r\nSUMMARY:No UID\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let objects = objects_of(feed).unwrap();
        assert_eq!(objects.len(), 2, "the event without a UID is skipped");
        let standup = objects.values().find(|o| o.contains("Standup")).unwrap();
        assert!(
            standup.contains("BEGIN:VTIMEZONE"),
            "its time zone comes along"
        );
        let christmas = objects.values().find(|o| o.contains("Christmas")).unwrap();
        assert!(!christmas.contains("VTIMEZONE"));
        assert!(objects_of("not a calendar").is_err());

        let td = tempfile::tempdir().unwrap();
        let conn = crate::jmap::store::open(td.path(), "example.test", "user").unwrap();
        let url = normalize_url("webcal://example.test/holidays.ics").unwrap();
        let collection = subscribe(&conn, &url, "Holidays", Some("#ff0000")).unwrap();
        assert!(is_subscription(&conn, collection.id).unwrap());
        assert!(
            subscribe(&conn, &url, "Again", None).is_err(),
            "no duplicates"
        );
        assert_eq!(apply(&conn, &collection, &objects).unwrap(), (2, 0));
        let etags: Vec<String> = store::objects(&conn, &collection)
            .unwrap()
            .into_iter()
            .map(|o| o.etag)
            .collect();
        assert_eq!(
            apply(&conn, &collection, &objects).unwrap(),
            (0, 0),
            "nothing changed"
        );
        assert_eq!(
            store::objects(&conn, &collection)
                .unwrap()
                .into_iter()
                .map(|o| o.etag)
                .collect::<Vec<_>>(),
            etags
        );
        let fewer: BTreeMap<String, String> = objects.into_iter().take(1).collect();
        assert_eq!(apply(&conn, &collection, &fewer).unwrap(), (0, 1));
        assert_eq!(due(&conn).unwrap().len(), 1, "never fetched");
        record(&conn, &collection, None).unwrap();
        assert!(due(&conn).unwrap().is_empty());
        unsubscribe(&conn, &collection).unwrap();
        assert!(subscriptions(&conn).unwrap().is_empty());
    }
}
