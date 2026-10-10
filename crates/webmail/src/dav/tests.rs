//! End-to-end CalDAV/CardDAV tests over the HTTP router.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, header};
use base64::Engine;
use rmail_common::http::Peer;
use rmail_common::throttle::AuthThrottle;
use rmail_common::{db, imap_state, websession};
use tower::ServiceExt;

use crate::api::{AppState, router};

const USER: &str = "user@example.test";

fn state(td: &tempfile::TempDir) -> Arc<AppState> {
    let db_path = td.path().join("accounts.sqlite");
    db::init_db(&db_path).unwrap();
    for address in [USER, "other@example.test"] {
        db::add_mailbox(&db_path, address, Some("plain:secret"), None, None).unwrap();
    }
    let mail_root = td.path().join("mail");
    imap_state::init_account(&mail_root, "example.test", "user").unwrap();
    Arc::new(AppState {
        mail_root,
        db_path,
        static_dir: td.path().join("static"),
        session_secret: b"test secret".to_vec(),
        secure_cookies: false,
        throttle: AuthThrottle::default(),
        revoked: websession::RevocationList::default(),
        submission: None,
        oauth: None,
        jmap_logins: Default::default(),
        shutdown: None,
    })
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map_or("", |(_, value)| value.as_str())
    }
}

async fn dav(
    state: &Arc<AppState>,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Reply {
    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{USER}:secret"))
    );
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "mail.example.test")
        .header(header::AUTHORIZATION, auth);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let mut request = builder.body(Body::from(body.to_string())).unwrap();
    request
        .extensions_mut()
        .insert(Peer(Some("192.0.2.1:40000".parse().unwrap())));
    let response = router(state.clone()).oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    Reply {
        status,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    }
}

const CALENDAR: &str = "/dav/calendars/user@example.test/default/";

fn event(uid: &str, summary: &str, start: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:{uid}\r\n\
         DTSTAMP:20261001T000000Z\r\nDTSTART:{start}\r\nDURATION:PT1H\r\nSUMMARY:{summary}\r\n\
         END:VEVENT\r\nEND:VCALENDAR\r\n"
    )
}

/// The text of the first non-empty element named `local` in an XML reply.
fn text_of(body: &str, local: &str) -> String {
    let document = roxmltree::Document::parse(body).unwrap();
    document
        .descendants()
        .filter(|node| node.tag_name().name() == local)
        .find_map(|node| node.text())
        .unwrap_or_default()
        .to_string()
}

#[tokio::test]
async fn clients_discover_the_principal_and_home_sets() {
    let td = tempfile::tempdir().unwrap();
    let state = state(&td);
    let redirect = dav(&state, "PROPFIND", "/.well-known/caldav", &[], "").await;
    assert_eq!(redirect.status, 301);
    assert_eq!(redirect.header("location"), "/dav/");
    let options = dav(&state, "OPTIONS", "/dav/", &[], "").await;
    assert!(options.header("dav").contains("calendar-access"));
    assert!(options.header("dav").contains("addressbook"));

    let root = dav(
        &state,
        "PROPFIND",
        "/dav/",
        &[("depth", "0")],
        r#"<d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/></d:prop></d:propfind>"#,
    )
    .await;
    assert_eq!(root.status, 207, "{}", root.body);
    assert!(
        root.body
            .contains("<d:href>/dav/principals/user@example.test/</d:href>"),
        "{}",
        root.body
    );

    let principal = dav(
        &state,
        "PROPFIND",
        "/dav/principals/user%40example.test/",
        &[("depth", "0")],
        r#"<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav" xmlns:card="urn:ietf:params:xml:ns:carddav">
           <d:prop><c:calendar-home-set/><card:addressbook-home-set/><c:calendar-user-address-set/><d:nonsense/></d:prop></d:propfind>"#,
    )
    .await;
    assert!(
        principal
            .body
            .contains("<c:calendar-home-set><d:href>/dav/calendars/user@example.test/</d:href>")
    );
    assert!(principal.body.contains(
        "<card:addressbook-home-set><d:href>/dav/addressbooks/user@example.test/</d:href>"
    ));
    assert!(principal.body.contains("mailto:user@example.test"));
    assert!(
        principal.body.contains("HTTP/1.1 404 Not Found"),
        "unknown properties are 404"
    );

    // Clients given only the host name start at the server root.
    let server_root = dav(
        &state,
        "PROPFIND",
        "/",
        &[("depth", "0")],
        r#"<d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/></d:prop></d:propfind>"#,
    )
    .await;
    assert_eq!(server_root.status, 207);
    assert!(
        server_root
            .body
            .contains("/dav/principals/user@example.test/")
    );

    // Another account's data is not there for this user.
    let other = dav(
        &state,
        "PROPFIND",
        "/dav/calendars/other@example.test/",
        &[("depth", "1")],
        "",
    )
    .await;
    assert_eq!(other.status, 404);
    let infinite = dav(&state, "PROPFIND", "/dav/", &[("depth", "infinity")], "").await;
    assert_eq!(infinite.status, 403);
    assert!(infinite.body.contains("propfind-finite-depth"));
}

#[tokio::test]
async fn events_are_stored_queried_and_synchronized() {
    let td = tempfile::tempdir().unwrap();
    let state = state(&td);
    let home = dav(
        &state,
        "PROPFIND",
        "/dav/calendars/user@example.test/",
        &[("depth", "1")],
        r#"<d:propfind xmlns:d="DAV:" xmlns:cs="http://calendarserver.org/ns/"><d:prop><d:resourcetype/><d:displayname/><cs:getctag/><d:sync-token/></d:prop></d:propfind>"#,
    )
    .await;
    assert!(
        home.body.contains(&format!("<d:href>{CALENDAR}</d:href>")),
        "{}",
        home.body
    );
    assert!(home.body.contains("<c:calendar/>"));
    assert!(
        home.body
            .contains("<d:displayname>Calendar</d:displayname>")
    );
    let initial_token = text_of(&home.body, "sync-token");
    assert!(!initial_token.is_empty());

    let created = dav(
        &state,
        "PUT",
        &format!("{CALENDAR}standup.ics"),
        &[("if-none-match", "*")],
        &event("standup", "Standup", "20261012T090000Z"),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.body);
    let etag = created.header("etag").to_string();
    assert!(etag.starts_with('"'));
    let again = dav(
        &state,
        "PUT",
        &format!("{CALENDAR}standup.ics"),
        &[("if-none-match", "*")],
        &event("standup", "x", "20261012T090000Z"),
    )
    .await;
    assert_eq!(again.status, 412);
    let fetched = dav(&state, "GET", &format!("{CALENDAR}standup.ics"), &[], "").await;
    assert_eq!(fetched.status, 200);
    assert_eq!(fetched.header("etag"), etag);
    assert!(fetched.body.contains("SUMMARY:Standup"));
    assert!(fetched.header("content-type").starts_with("text/calendar"));

    // Preconditions of RFC 4791 5.3.2.
    let duplicate = dav(
        &state,
        "PUT",
        &format!("{CALENDAR}other.ics"),
        &[],
        &event("standup", "Dup", "20261013T090000Z"),
    )
    .await;
    assert_eq!(duplicate.status, 403);
    assert!(
        duplicate.body.contains("no-uid-conflict"),
        "{}",
        duplicate.body
    );
    let invalid = dav(
        &state,
        "PUT",
        &format!("{CALENDAR}bad.ics"),
        &[],
        "not a calendar",
    )
    .await;
    assert_eq!(invalid.status, 403);
    assert!(invalid.body.contains("valid-calendar-data"));

    dav(
        &state,
        "PUT",
        &format!("{CALENDAR}review.ics"),
        &[],
        &event("review", "Review", "20261120T140000Z"),
    )
    .await;
    let query = |start: &'static str, end: &'static str| {
        format!(
            r#"<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
               <d:prop><d:getetag/><c:calendar-data/></d:prop>
               <c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="VEVENT">
               <c:time-range start="{start}" end="{end}"/></c:comp-filter></c:comp-filter></c:filter>
               </c:calendar-query>"#
        )
    };
    let october = dav(
        &state,
        "REPORT",
        CALENDAR,
        &[("depth", "1")],
        &query("20261001T000000Z", "20261101T000000Z"),
    )
    .await;
    assert_eq!(october.status, 207);
    assert!(october.body.contains("standup.ics"), "{}", october.body);
    assert!(!october.body.contains("review.ics"));
    assert!(october.body.contains("SUMMARY:Standup"));
    let multiget = dav(
        &state,
        "REPORT",
        CALENDAR,
        &[("depth", "1")],
        &format!(
            r#"<c:calendar-multiget xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
               <d:prop><d:getetag/></d:prop><d:href>{CALENDAR}review.ics</d:href><d:href>{CALENDAR}gone.ics</d:href>
               </c:calendar-multiget>"#
        ),
    )
    .await;
    assert!(multiget.body.contains("review.ics"));
    assert!(multiget.body.contains("<d:href>/dav/calendars/user@example.test/default/gone.ics</d:href><d:status>HTTP/1.1 404"), "{}", multiget.body);

    // sync-collection: changes, then a deletion, since a token.
    let sync = |token: String| {
        format!(
            r#"<d:sync-collection xmlns:d="DAV:"><d:sync-token>{token}</d:sync-token><d:sync-level>1</d:sync-level><d:prop><d:getetag/></d:prop></d:sync-collection>"#
        )
    };
    let first = dav(
        &state,
        "REPORT",
        CALENDAR,
        &[],
        &sync(initial_token.clone()),
    )
    .await;
    assert!(
        first.body.contains("standup.ics") && first.body.contains("review.ics"),
        "{}",
        first.body
    );
    let token = text_of(&first.body, "sync-token");
    let wrong = dav(
        &state,
        "DELETE",
        &format!("{CALENDAR}review.ics"),
        &[("if-match", "\"nope\"")],
        "",
    )
    .await;
    assert_eq!(wrong.status, 412);
    let deleted = dav(&state, "DELETE", &format!("{CALENDAR}review.ics"), &[], "").await;
    assert_eq!(deleted.status, 204);
    let second = dav(&state, "REPORT", CALENDAR, &[], &sync(token)).await;
    assert!(
        second
            .body
            .contains("review.ics</d:href><d:status>HTTP/1.1 404"),
        "{}",
        second.body
    );
    assert!(!second.body.contains("standup.ics"));
    let stale = dav(
        &state,
        "REPORT",
        CALENDAR,
        &[],
        &sync("https://rmail.invalid/sync/999999".to_string()),
    )
    .await;
    assert_eq!(stale.status, 403);
    assert!(stale.body.contains("valid-sync-token"));
}

#[tokio::test]
async fn collections_are_created_configured_and_queried() {
    let td = tempfile::tempdir().unwrap();
    let state = state(&td);
    // A to-do list only takes VTODO.
    let made = dav(
        &state,
        "MKCALENDAR",
        "/dav/calendars/user@example.test/tasks/",
        &[],
        r#"<c:mkcalendar xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:set><d:prop>
           <d:displayname>Tasks</d:displayname>
           <c:supported-calendar-component-set><c:comp name="VTODO"/></c:supported-calendar-component-set>
           </d:prop></d:set></c:mkcalendar>"#,
    )
    .await;
    assert_eq!(made.status, 201, "{}", made.body);
    let refused = dav(
        &state,
        "PUT",
        "/dav/calendars/user@example.test/tasks/e.ics",
        &[],
        &event("e", "Event", "20261012T090000Z"),
    )
    .await;
    assert_eq!(refused.status, 403);
    assert!(refused.body.contains("supported-calendar-component"));
    let exists = dav(
        &state,
        "MKCALENDAR",
        "/dav/calendars/user@example.test/tasks/",
        &[],
        "",
    )
    .await;
    assert_eq!(exists.status, 405);

    let patched = dav(
        &state,
        "PROPPATCH",
        "/dav/calendars/user@example.test/tasks/",
        &[],
        r##"<d:propertyupdate xmlns:d="DAV:" xmlns:i="http://apple.com/ns/ical/"><d:set><d:prop>
            <d:displayname>Chores</d:displayname><i:calendar-color>#FF0000</i:calendar-color></d:prop></d:set></d:propertyupdate>"##,
    )
    .await;
    assert_eq!(patched.status, 207);
    assert!(!patched.body.contains("403"), "{}", patched.body);
    let atomic = dav(
        &state,
        "PROPPATCH",
        "/dav/calendars/user@example.test/tasks/",
        &[],
        r#"<d:propertyupdate xmlns:d="DAV:"><d:set><d:prop><d:displayname>Lost</d:displayname><d:getetag>x</d:getetag></d:prop></d:set></d:propertyupdate>"#,
    )
    .await;
    assert!(
        atomic.body.contains("403") && atomic.body.contains("424"),
        "{}",
        atomic.body
    );
    let props = dav(
        &state,
        "PROPFIND",
        "/dav/calendars/user@example.test/tasks/",
        &[("depth", "0")],
        r#"<d:propfind xmlns:d="DAV:" xmlns:i="http://apple.com/ns/ical/"><d:prop><d:displayname/><i:calendar-color/></d:prop></d:propfind>"#,
    )
    .await;
    assert!(
        props.body.contains("<d:displayname>Chores</d:displayname>"),
        "{}",
        props.body
    );
    assert!(props.body.contains("#FF0000"));

    // Address books: extended MKCOL, vCards and addressbook-query.
    let book = dav(
        &state,
        "MKCOL",
        "/dav/addressbooks/user@example.test/work/",
        &[],
        r#"<d:mkcol xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:set><d:prop>
           <d:resourcetype><d:collection/><card:addressbook/></d:resourcetype><d:displayname>Work</d:displayname>
           </d:prop></d:set></d:mkcol>"#,
    )
    .await;
    assert_eq!(book.status, 201, "{}", book.body);
    for (name, full, email) in [
        ("ada", "Ada Lovelace", "ada@x.test"),
        ("alan", "Alan Turing", "alan@y.test"),
    ] {
        let card = format!(
            "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:{name}\r\nFN:{full}\r\nEMAIL:{email}\r\nEND:VCARD\r\n"
        );
        let put = dav(
            &state,
            "PUT",
            &format!("/dav/addressbooks/user@example.test/work/{name}.vcf"),
            &[],
            &card,
        )
        .await;
        assert_eq!(put.status, 201);
    }
    let found = dav(
        &state,
        "REPORT",
        "/dav/addressbooks/user@example.test/work/",
        &[("depth", "1")],
        r#"<card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
           <d:prop><card:address-data/></d:prop>
           <card:filter><card:prop-filter name="EMAIL"><card:text-match match-type="ends-with">@X.TEST</card:text-match></card:prop-filter></card:filter>
           </card:addressbook-query>"#,
    )
    .await;
    assert!(
        found.body.contains("ada.vcf") && found.body.contains("FN:Ada Lovelace"),
        "{}",
        found.body
    );
    assert!(!found.body.contains("alan.vcf"));
    let no_uid = dav(
        &state,
        "PUT",
        "/dav/addressbooks/user@example.test/work/x.vcf",
        &[],
        "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:X\r\nEND:VCARD\r\n",
    )
    .await;
    assert_eq!(no_uid.status, 403);
    assert!(no_uid.body.contains("valid-address-data"));
    // A calendar cannot be made among address books.
    let wrong = dav(
        &state,
        "MKCALENDAR",
        "/dav/addressbooks/user@example.test/cal/",
        &[],
        "",
    )
    .await;
    assert_eq!(wrong.status, 403);
    let removed = dav(
        &state,
        "DELETE",
        "/dav/addressbooks/user@example.test/work/",
        &[],
        "",
    )
    .await;
    assert_eq!(removed.status, 204);
}
