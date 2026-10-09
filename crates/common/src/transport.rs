//! Delivery routes: per-domain next hops for outbound mail, stored in the
//! `transport_routes` table. A route for `*` applies to every domain without
//! its own route, which makes it a smarthost. Domains without a route are
//! delivered to their MX hosts.

use std::path::Path;

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum RouteAction {
    /// Hand the mail to `host:port` instead of the MX hosts.
    Relay {
        host: String,
        port: u16,
        /// TLS from the first byte (usually port 465) instead of STARTTLS.
        #[serde(default)]
        implicit_tls: bool,
        /// AUTH PLAIN credentials; sent only over TLS.
        #[serde(default)]
        username: Option<String>,
        #[serde(default, skip_serializing)]
        password: Option<String>,
    },
    /// Refuse the mail with this SMTP reply (e.g. "550 5.1.2 No such domain").
    Reject { reply: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Route {
    /// A domain, or `*` for the default route.
    pub domain: String,
    #[serde(flatten)]
    pub action: RouteAction,
    /// Whether a password is stored (the password itself is never returned).
    pub has_password: bool,
}

fn open(db_path: &Path) -> Result<Connection> {
    let conn = Connection::open(db_path)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(conn)
}

fn normalize_domain(domain: &str) -> Result<String> {
    let domain = domain.trim();
    if domain == "*" {
        return Ok(domain.to_string());
    }
    crate::domain::canonicalize_domain(domain)
}

fn validate(action: &RouteAction) -> Result<()> {
    match action {
        RouteAction::Relay {
            host,
            port,
            username,
            password,
            ..
        } => {
            crate::domain::canonicalize_domain(host)
                .or_else(|_| host.parse::<std::net::IpAddr>().map(|_| host.clone()))
                .with_context(|| format!("invalid relay host {host:?}"))?;
            if *port == 0 {
                bail!("the relay port must not be 0");
            }
            if username.is_some() != password.is_some() {
                bail!("give both a username and a password, or neither");
            }
        }
        RouteAction::Reject { reply } => {
            let code = reply.get(..3).and_then(|code| code.parse::<u16>().ok());
            if !code.is_some_and(|code| (400..600).contains(&code)) || reply.contains(['\r', '\n'])
            {
                bail!(
                    "a reject reply starts with a 4xx or 5xx code, e.g. \"550 5.1.2 No such domain\""
                );
            }
        }
    }
    Ok(())
}

/// Store the route for `domain` (or `*`), replacing any earlier one. A relay
/// route given without a password keeps the stored password when the
/// username is unchanged, so editing the host does not require retyping it.
pub fn set_route(db_path: &Path, domain: &str, mut action: RouteAction) -> Result<Route> {
    let domain = normalize_domain(domain)?;
    if let RouteAction::Relay {
        username, password, ..
    } = &mut action
        && username.is_some()
        && password.is_none()
        && let Some(Route {
            action:
                RouteAction::Relay {
                    username: stored_user,
                    password: stored_password,
                    ..
                },
            ..
        }) = get_route_with_secret(db_path, &domain)?
        && stored_user == *username
    {
        *password = stored_password;
    }
    validate(&action)?;
    let conn = open(db_path)?;
    let (kind, host, port, implicit_tls, username, password, reply) = match &action {
        RouteAction::Relay {
            host,
            port,
            implicit_tls,
            username,
            password,
        } => (
            "relay",
            Some(host.clone()),
            Some(*port),
            *implicit_tls,
            username.clone(),
            password.clone(),
            None,
        ),
        RouteAction::Reject { reply } => {
            ("reject", None, None, false, None, None, Some(reply.clone()))
        }
    };
    conn.execute(
        "INSERT OR REPLACE INTO transport_routes
           (domain, kind, host, port, implicit_tls, username, password, reply, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, strftime('%s','now'))",
        params![
            domain,
            kind,
            host,
            port,
            implicit_tls,
            username,
            password,
            reply
        ],
    )?;
    get_route(db_path, &domain)?.context("stored route vanished")
}

pub fn delete_route(db_path: &Path, domain: &str) -> Result<bool> {
    let domain = normalize_domain(domain)?;
    Ok(open(db_path)?.execute(
        "DELETE FROM transport_routes WHERE domain = ?1",
        params![domain],
    )? > 0)
}

const COLUMNS: &str = "domain, kind, host, port, implicit_tls, username, password, reply";

fn row_to_route(row: &rusqlite::Row<'_>) -> rusqlite::Result<Route> {
    let kind: String = row.get(1)?;
    let password: Option<String> = row.get(6)?;
    let action = if kind == "reject" {
        RouteAction::Reject {
            reply: row.get::<_, Option<String>>(7)?.unwrap_or_default(),
        }
    } else {
        RouteAction::Relay {
            host: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
            port: row.get::<_, Option<u16>>(3)?.unwrap_or(25),
            implicit_tls: row.get(4)?,
            username: row.get(5)?,
            password: password.clone(),
        }
    };
    Ok(Route {
        domain: row.get(0)?,
        action,
        has_password: password.is_some(),
    })
}

fn get_route_with_secret(db_path: &Path, domain: &str) -> Result<Option<Route>> {
    Ok(open(db_path)?
        .query_row(
            &format!("SELECT {COLUMNS} FROM transport_routes WHERE domain = ?1"),
            params![domain],
            row_to_route,
        )
        .optional()?)
}

fn without_secret(mut route: Route) -> Route {
    if let RouteAction::Relay { password, .. } = &mut route.action {
        *password = None;
    }
    route
}

/// The route stored for exactly `domain` (or `*`), without its password.
pub fn get_route(db_path: &Path, domain: &str) -> Result<Option<Route>> {
    Ok(get_route_with_secret(db_path, &normalize_domain(domain)?)?.map(without_secret))
}

/// Every route, without passwords.
pub fn list_routes(db_path: &Path) -> Result<Vec<Route>> {
    let conn = open(db_path)?;
    let mut statement = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM transport_routes ORDER BY domain = '*' DESC, domain"
    ))?;
    let routes = statement
        .query_map([], row_to_route)?
        .map(|route| route.map(without_secret))
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(routes)
}

/// How to deliver mail for `domain`: its own route, else the `*` route,
/// else `None` (deliver to the MX hosts). Includes the relay password.
pub fn lookup(db_path: &Path, domain: &str) -> Result<Option<Route>> {
    let domain = crate::domain::canonicalize_domain(domain)?;
    if let Some(route) = get_route_with_secret(db_path, &domain)? {
        return Ok(Some(route));
    }
    get_route_with_secret(db_path, "*")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rmail.db");
        crate::db::init_db(&path).unwrap();
        (dir, path)
    }

    fn relay(host: &str, user: Option<&str>, password: Option<&str>) -> RouteAction {
        RouteAction::Relay {
            host: host.into(),
            port: 587,
            implicit_tls: false,
            username: user.map(Into::into),
            password: password.map(Into::into),
        }
    }

    #[test]
    fn domain_routes_win_over_the_default_route() {
        let (_dir, db) = db();
        assert_eq!(lookup(&db, "example.net").unwrap(), None);
        set_route(&db, "*", relay("smarthost.example", Some("u"), Some("p"))).unwrap();
        set_route(
            &db,
            "Blocked.Example",
            RouteAction::Reject {
                reply: "550 5.1.2 No such domain".into(),
            },
        )
        .unwrap();
        let fallback = lookup(&db, "example.net").unwrap().unwrap();
        assert_eq!(fallback.domain, "*");
        assert_eq!(
            fallback.action,
            relay("smarthost.example", Some("u"), Some("p"))
        );
        assert!(matches!(
            lookup(&db, "blocked.example").unwrap().unwrap().action,
            RouteAction::Reject { .. }
        ));
        // Listings never carry the password.
        let listed = list_routes(&db).unwrap();
        assert_eq!(listed[0].domain, "*");
        assert!(listed[0].has_password);
        assert_eq!(
            listed[0].action,
            relay("smarthost.example", Some("u"), None)
        );
        assert!(delete_route(&db, "*").unwrap());
        assert_eq!(lookup(&db, "example.net").unwrap(), None);
    }

    #[test]
    fn editing_a_relay_keeps_its_password_and_routes_are_validated() {
        let (_dir, db) = db();
        set_route(&db, "*", relay("old.example", Some("u"), Some("p"))).unwrap();
        set_route(&db, "*", relay("new.example", Some("u"), None)).unwrap();
        assert_eq!(
            lookup(&db, "x.example").unwrap().unwrap().action,
            relay("new.example", Some("u"), Some("p"))
        );
        // A new username needs its own password.
        assert!(set_route(&db, "*", relay("new.example", Some("v"), None)).is_err());
        assert!(set_route(&db, "*", relay("bad host", None, None)).is_err());
        assert!(
            set_route(
                &db,
                "x.example",
                RouteAction::Reject {
                    reply: "nope".into()
                }
            )
            .is_err()
        );
    }
}
