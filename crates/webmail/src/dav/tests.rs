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
    state_with(td, None)
}

fn state_with(td: &tempfile::TempDir, submission: Option<std::net::SocketAddr>) -> Arc<AppState> {
    let db_path = td.path().join("accounts.sqlite");
    db::init_db(&db_path).unwrap();
    for address in [
        USER,
        "other@example.test",
        "third@example.test",
        "far@elsewhere.test",
    ] {
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
        submission,
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
    dav_as(state, USER, method, path, headers, body).await
}

async fn dav_as(
    state: &Arc<AppState>,
    user: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Reply {
    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:secret"))
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
        &sync("https://rmail.invalid/sync/1/999999".to_string()),
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

const OTHER: &str = "other@example.test";

/// iCalendar text unfolded, with plain newlines.
fn unfolded(text: &str) -> String {
    text.replace("\r\n", "\n").replace("\n ", "")
}

fn meeting(attendees: &[(&str, &str)], summary: &str, extra: &str) -> String {
    let lines = attendees
        .iter()
        .map(|(who, status)| format!("ATTENDEE;CN=Guest;PARTSTAT={status}:mailto:{who}\r\n"))
        .collect::<String>();
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:meet-1\r\n\
         DTSTAMP:20261001T000000Z\r\nDTSTART:20261012T090000Z\r\nDTEND:20261012T100000Z\r\n\
         SUMMARY:{summary}\r\nORGANIZER:mailto:{USER}\r\n\
         ATTENDEE;PARTSTAT=ACCEPTED:mailto:{USER}\r\n{lines}{extra}END:VEVENT\r\nEND:VCALENDAR\r\n"
    )
}

/// The hrefs and data of the objects in a collection.
async fn objects_in(state: &Arc<AppState>, user: &str, path: &str) -> Vec<(String, String)> {
    let listing = dav_as(
        state,
        user,
        "REPORT",
        path,
        &[("depth", "1")],
        r#"<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
           <d:prop><c:calendar-data/></d:prop>
           <c:filter><c:comp-filter name="VCALENDAR"/></c:filter></c:calendar-query>"#,
    )
    .await;
    assert_eq!(listing.status, 207, "{}", listing.body);
    let document = roxmltree::Document::parse(&listing.body).unwrap();
    document
        .descendants()
        .filter(|node| node.tag_name().name() == "response")
        .filter_map(|response| {
            let href = response
                .descendants()
                .find(|node| node.tag_name().name() == "href")?
                .text()?
                .to_string();
            let data = response
                .descendants()
                .find(|node| node.tag_name().name() == "calendar-data")?
                .text()?
                .to_string();
            Some((href, data))
        })
        .collect()
}

#[tokio::test]
async fn invitations_replies_and_cancellations_reach_local_attendees() {
    let td = tempfile::tempdir().unwrap();
    let state = state(&td);
    let options = dav(&state, "OPTIONS", CALENDAR, &[], "").await;
    assert!(options.header("dav").contains("calendar-auto-schedule"));
    let principal = dav(
        &state,
        "PROPFIND",
        "/dav/principals/user@example.test/",
        &[("depth", "0")],
        r#"<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop>
           <c:schedule-inbox-URL/><c:schedule-outbox-URL/></d:prop></d:propfind>"#,
    )
    .await;
    assert!(
        principal
            .body
            .contains("/dav/calendars/user@example.test/inbox/")
    );
    assert!(
        principal
            .body
            .contains("/dav/calendars/user@example.test/outbox/")
    );

    // The organizer invites a local attendee and a remote one; sending is
    // off in this test, so the remote one cannot be reached.
    let invite = meeting(
        &[
            (OTHER, "NEEDS-ACTION"),
            ("guest@remote.test", "NEEDS-ACTION"),
        ],
        "Planning",
        "",
    );
    let path = format!("{CALENDAR}meet.ics");
    let created = dav(&state, "PUT", &path, &[], &invite).await;
    assert_eq!(created.status, 201, "{}", created.body);
    assert_eq!(
        created.header("etag"),
        "",
        "stored with statuses, not as sent"
    );
    let tag = created.header("schedule-tag").to_string();
    assert!(!tag.is_empty());
    let mut stored = dav(&state, "GET", &path, &[], "").await;
    assert_eq!(stored.header("schedule-tag"), tag);
    stored.body = unfolded(&stored.body);
    assert!(
        stored
            .body
            .contains("SCHEDULE-STATUS=1.2:mailto:other@example.test"),
        "{}",
        stored.body
    );
    assert!(
        stored
            .body
            .contains("SCHEDULE-STATUS=5.1:mailto:guest@remote.test")
    );

    // The attendee has it in their inbox and their calendar.
    let other_calendar = "/dav/calendars/other@example.test/default/";
    let inbox = objects_in(&state, OTHER, "/dav/calendars/other@example.test/inbox/").await;
    assert_eq!(inbox.len(), 1);
    assert!(inbox[0].1.contains("METHOD:REQUEST"));
    let copies = objects_in(&state, OTHER, other_calendar).await;
    assert_eq!(copies.len(), 1);
    let (copy_href, copy) = copies[0].clone();
    let copy = unfolded(&copy);
    assert!(copy.contains("UID:meet-1") && !copy.contains("METHOD"));
    let copy_tag = dav_as(&state, OTHER, "GET", &copy_href, &[], "")
        .await
        .header("schedule-tag")
        .to_string();

    // They accept: the organizer's copy shows it, its schedule tag stays.
    let accepted = copy.replace(
        "PARTSTAT=NEEDS-ACTION:mailto:other@example.test",
        "PARTSTAT=ACCEPTED:mailto:other@example.test",
    );
    assert_ne!(accepted, copy);
    let stale = dav_as(
        &state,
        OTHER,
        "PUT",
        &copy_href,
        &[("if-schedule-tag-match", "\"stale\"")],
        &accepted,
    )
    .await;
    assert_eq!(stale.status, 412);
    let answer = dav_as(
        &state,
        OTHER,
        "PUT",
        &copy_href,
        &[("if-schedule-tag-match", copy_tag.as_str())],
        &accepted,
    )
    .await;
    assert_eq!(answer.status, 204, "{}", answer.body);
    let organizer_copy = dav(&state, "GET", &path, &[], "").await;
    assert!(
        unfolded(&organizer_copy.body)
            .contains("PARTSTAT=ACCEPTED;SCHEDULE-STATUS=2.0:mailto:other@example.test"),
        "{}",
        organizer_copy.body
    );
    assert_eq!(organizer_copy.header("schedule-tag"), tag);
    let user_inbox = objects_in(&state, USER, "/dav/calendars/user@example.test/inbox/").await;
    assert!(user_inbox[0].1.contains("METHOD:REPLY"));

    // A new time reaches the attendee; deleting the event cancels it.
    let moved = organizer_copy.body.replace("T090000Z", "T130000Z");
    let updated = dav(
        &state,
        "PUT",
        &path,
        &[("if-schedule-tag-match", tag.as_str())],
        &moved,
    )
    .await;
    assert_eq!(updated.status, 204);
    assert_ne!(updated.header("schedule-tag"), tag);
    let copies = objects_in(&state, OTHER, other_calendar).await;
    assert!(copies[0].1.contains("DTSTART:20261012T130000Z"));
    assert_eq!(dav(&state, "DELETE", &path, &[], "").await.status, 204);
    let copies = objects_in(&state, OTHER, other_calendar).await;
    assert!(copies[0].1.contains("STATUS:CANCELLED"), "{}", copies[0].1);
    assert_eq!(
        objects_in(&state, OTHER, "/dav/calendars/other@example.test/inbox/")
            .await
            .len(),
        3
    );

    // Clients cannot write to the inbox or take its name.
    let refused = dav(
        &state,
        "PUT",
        "/dav/calendars/user@example.test/inbox/x.ics",
        &[],
        &invite,
    )
    .await;
    assert_eq!(refused.status, 403);
    let taken = dav(
        &state,
        "MKCALENDAR",
        "/dav/calendars/user@example.test/outbox/",
        &[],
        "",
    )
    .await;
    assert_eq!(taken.status, 403);
}

#[tokio::test]
async fn an_attendee_cannot_take_over_another_organizers_event() {
    let td = tempfile::tempdir().unwrap();
    let state = state(&td);
    // The attendee's own event happens to have the UID of an invitation.
    let own = event("meet-1", "Mine", "20261012T090000Z");
    let other_calendar = "/dav/calendars/other@example.test/default/";
    let put = dav_as(
        &state,
        OTHER,
        "PUT",
        &format!("{other_calendar}mine.ics"),
        &[],
        &own,
    )
    .await;
    assert_eq!(put.status, 201);
    let invite = meeting(&[(OTHER, "NEEDS-ACTION")], "Planning", "");
    dav(&state, "PUT", &format!("{CALENDAR}meet.ics"), &[], &invite).await;
    let copies = objects_in(&state, OTHER, other_calendar).await;
    assert_eq!(copies.len(), 1);
    assert!(copies[0].1.contains("SUMMARY:Mine"));
}

#[tokio::test]
async fn free_busy_queries_answer_for_accounts_in_the_domain() {
    let td = tempfile::tempdir().unwrap();
    let state = state(&td);
    let other_calendar = "/dav/calendars/other@example.test/default/";
    let busy = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:b1\r\n\
                DTSTART;TZID=Europe/Copenhagen:20261012T120000\r\nDURATION:PT1H\r\n\
                RRULE:FREQ=DAILY;COUNT=3\r\nSUMMARY:Busy\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    let free = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:f1\r\n\
                DTSTART:20261012T150000Z\r\nDURATION:PT1H\r\nTRANSP:TRANSPARENT\r\n\
                SUMMARY:Free\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    for (name, data) in [("busy.ics", busy), ("free.ics", free)] {
        let put = dav_as(
            &state,
            OTHER,
            "PUT",
            &format!("{other_calendar}{name}"),
            &[],
            data,
        )
        .await;
        assert_eq!(put.status, 201);
    }
    let query = |organizer: &str| {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REQUEST\r\nBEGIN:VFREEBUSY\r\nUID:q1\r\n\
             DTSTAMP:20261001T000000Z\r\nDTSTART:20261012T000000Z\r\nDTEND:20261014T000000Z\r\n\
             ORGANIZER:mailto:{organizer}\r\nATTENDEE:mailto:{OTHER}\r\n\
             ATTENDEE:mailto:far@elsewhere.test\r\nATTENDEE:mailto:guest@remote.test\r\n\
             END:VFREEBUSY\r\nEND:VCALENDAR\r\n"
        )
    };
    let outbox = "/dav/calendars/user@example.test/outbox/";
    let calendar_type = [("content-type", "text/calendar; charset=utf-8")];
    let answer = dav(&state, "POST", outbox, &calendar_type, &query(USER)).await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    let document = roxmltree::Document::parse(&answer.body).unwrap();
    let responses = document
        .descendants()
        .filter(|node| node.tag_name().name() == "response")
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 3);
    let status_of = |index: usize| {
        responses[index]
            .descendants()
            .find(|node| node.tag_name().name() == "request-status")
            .and_then(|node| node.text())
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(status_of(0), "2.0;Success");
    // Another domain on this server is not answered for, nor remote users.
    assert!(status_of(1).starts_with("5.3"));
    assert!(status_of(2).starts_with("5.3"));
    let data = unfolded(&text_of(&answer.body, "calendar-data"));
    // Noon in Copenhagen is 10:00 UTC (CEST); the transparent event and the
    // third occurrence (outside the range) do not count.
    assert!(
        data.contains(
            "FREEBUSY;FBTYPE=BUSY:20261012T100000Z/20261012T110000Z\n\
             FREEBUSY;FBTYPE=BUSY:20261013T100000Z/20261013T110000Z\n"
        ),
        "{data}"
    );
    assert!(!data.contains("T150000Z/"));

    let forged = dav(&state, "POST", outbox, &calendar_type, &query(OTHER)).await;
    assert_eq!(forged.status, 403);
    assert!(forged.body.contains("organizer-allowed"));
    let elsewhere = dav(&state, "POST", CALENDAR, &calendar_type, &query(USER)).await;
    assert_eq!(elsewhere.status, 405);
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_attendees_get_invitations_by_email() {
    let td = tempfile::tempdir().unwrap();
    let mail_root = td.path().join("mail");
    std::fs::create_dir_all(&mail_root).unwrap();
    let (address, mut received) = crate::jmap::tests::fake_submission(mail_root).await;
    let state = state_with(&td, Some(address));
    let invite = meeting(&[("guest@remote.test", "NEEDS-ACTION")], "Planning", "");
    let path = format!("{CALENDAR}meet.ics");
    assert_eq!(dav(&state, "PUT", &path, &[], &invite).await.status, 201);
    let (envelope, data) = received.recv().await.unwrap();
    assert!(
        envelope
            .iter()
            .any(|line| line.contains("guest@remote.test"))
    );
    assert!(data.contains("Subject: Invitation: Planning"));
    assert!(data.contains("Content-Type: text/calendar; charset=utf-8; method=REQUEST"));
    let stored = unfolded(&dav(&state, "GET", &path, &[], "").await.body);
    assert!(stored.contains("SCHEDULE-STATUS=1.1:mailto:guest@remote.test"));

    // Deleting it emails the cancellation.
    assert_eq!(dav(&state, "DELETE", &path, &[], "").await.status, 204);
    let (_, data) = received.recv().await.unwrap();
    assert!(data.contains("Subject: Cancelled: Planning"));
    assert!(data.contains("method=CANCEL"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_answers_both_reach_the_organizer() {
    use rmail_common::dav::{itip, text};
    let td = tempfile::tempdir().unwrap();
    let state = state(&td);
    let third = "third@example.test";
    let account = |address: &str| {
        let (localpart, domain) = address.split_once('@').unwrap();
        crate::jmap::User {
            address: address.to_string(),
            domain: domain.to_string(),
            localpart: localpart.to_string(),
        }
    };
    for round in 0..20 {
        let uid = format!("race-{round}");
        let invite = meeting(
            &[(OTHER, "NEEDS-ACTION"), (third, "NEEDS-ACTION")],
            "Planning",
            "",
        )
        .replace("UID:meet-1", &format!("UID:{uid}"));
        let path = format!("{CALENDAR}{uid}.ics");
        assert_eq!(dav(&state, "PUT", &path, &[], &invite).await.status, 201);
        // Both attendees' replies are delivered at the same moment.
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let threads = [OTHER, third].map(|attendee| {
            let (state, barrier, uid) = (state.clone(), barrier.clone(), uid.clone());
            let attendee = account(attendee);
            std::thread::spawn(move || {
                let conn = rmail_common::jmap::store::open(
                    &state.mail_root,
                    &attendee.domain,
                    &attendee.localpart,
                )
                .unwrap();
                let (_, object) = rmail_common::dav::store::find_by_uid(&conn, &uid)
                    .unwrap()
                    .unwrap();
                let before = text::parse(&object.data).unwrap();
                let after = text::parse(&unfolded(&object.data).replace(
                    &format!("PARTSTAT=NEEDS-ACTION:mailto:{}", attendee.address),
                    &format!("PARTSTAT=ACCEPTED:mailto:{}", attendee.address),
                ))
                .unwrap();
                let reply =
                    itip::attendee_reply(Some(&before), Some(&after), &attendee.address).unwrap();
                let dav = super::Dav {
                    user: attendee,
                    conn,
                    app: state,
                };
                barrier.wait();
                super::schedule::deliver_local(&dav, &dav.user, &account(USER), &reply).unwrap();
            })
        });
        for thread in threads {
            thread.join().unwrap();
        }
        let organizer_copy = unfolded(&dav(&state, "GET", &path, &[], "").await.body);
        for attendee in [OTHER, third] {
            let line = organizer_copy
                .lines()
                .find(|line| line.ends_with(&format!("mailto:{attendee}")))
                .unwrap();
            assert!(line.contains("PARTSTAT=ACCEPTED"), "round {round}: {line}");
        }
    }
}

const SHARED: &str = "/dav/calendars/other@example.test/user@example.test~default/";

fn share_request(sharee: &str, access: &str) -> String {
    format!(
        r#"<cs:share xmlns:d="DAV:" xmlns:cs="http://calendarserver.org/ns/">
           <cs:set><d:href>mailto:{sharee}</d:href><cs:{access}/></cs:set></cs:share>"#
    )
}

/// The element names and text inside the first `local` element of the
/// response for `href` in a multistatus.
fn prop_of(body: &str, href: &str, local: &str) -> String {
    let document = roxmltree::Document::parse(body).unwrap();
    let Some(response) = document
        .descendants()
        .filter(|node| node.tag_name().name() == "response")
        .find(|response| response.descendants().any(|node| node.text() == Some(href)))
    else {
        return String::new();
    };
    response
        .descendants()
        .find(|node| node.tag_name().name() == local)
        .map(|node| {
            node.descendants()
                .skip(1)
                .filter_map(|node| {
                    if node.is_element() {
                        Some(node.tag_name().name().to_string())
                    } else {
                        node.text().map(str::to_string)
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn shared_calendars_are_read_only_or_writable_as_granted() {
    let td = tempfile::tempdir().unwrap();
    let state = state(&td);
    let existing = format!("{CALENDAR}a.ics");
    let standup = event("a", "Standup", "20261012T090000Z");
    assert_eq!(
        dav(&state, "PUT", &existing, &[], &standup).await.status,
        201
    );
    let options = dav(&state, "OPTIONS", CALENDAR, &[], "").await;
    assert!(options.header("dav").contains("calendarserver-sharing"));

    // Apple Calendar shares with a CalendarServer `share` POST; accounts
    // that do not exist are refused one by one.
    let shared = dav(&state, "POST", CALENDAR, &[], &share_request(OTHER, "read")).await;
    assert_eq!(shared.status, 200, "{}", shared.body);
    let nobody = share_request("nobody@example.test", "read");
    let unknown = dav(&state, "POST", CALENDAR, &[], &nobody).await;
    assert_eq!(unknown.status, 207);
    assert!(unknown.body.contains("mailto:nobody@example.test") && unknown.body.contains("403"));
    let owner_view = dav(
        &state,
        "PROPFIND",
        CALENDAR,
        &[("depth", "0")],
        r#"<d:propfind xmlns:d="DAV:" xmlns:cs="http://calendarserver.org/ns/"><d:prop>
           <d:resourcetype/><cs:invite/><cs:allowed-sharing-modes/></d:prop></d:propfind>"#,
    )
    .await;
    let body = &owner_view.body;
    assert!(body.contains("<cs:shared-owner/>"), "{body}");
    assert!(body.contains("mailto:other@example.test"));
    assert!(body.contains("<cs:read/>") && body.contains("<cs:can-be-shared/>"));

    // The sharee finds it in their own home, read-only.
    let home = dav_as(
        &state,
        OTHER,
        "PROPFIND",
        "/dav/calendars/other@example.test/",
        &[("depth", "1")],
        r#"<d:propfind xmlns:d="DAV:"><d:prop><d:displayname/><d:owner/><d:resourcetype/>
           <d:current-user-privilege-set/></d:prop></d:propfind>"#,
    )
    .await;
    let prop = |local: &str| prop_of(&home.body, SHARED, local);
    assert_eq!(
        prop("displayname"),
        "Calendar (user@example.test)",
        "{}",
        home.body
    );
    assert!(prop("owner").contains("/dav/principals/user@example.test/"));
    assert!(prop("resourcetype").contains("calendar") && prop("resourcetype").contains("shared"));
    let privileges = prop("current-user-privilege-set");
    assert!(privileges.contains("read"));
    assert!(
        !privileges.contains("write") && !privileges.contains("bind"),
        "{privileges}"
    );

    let object = format!("{SHARED}a.ics");
    let read = dav_as(&state, OTHER, "GET", &object, &[], "").await;
    assert_eq!(read.status, 200);
    assert!(read.body.contains("SUMMARY:Standup"));
    let listed = objects_in(&state, OTHER, SHARED).await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].0, object);
    let multiget = dav_as(
        &state,
        OTHER,
        "REPORT",
        SHARED,
        &[],
        &format!(
            r#"<c:calendar-multiget xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
               <d:prop><d:getetag/></d:prop><d:href>{object}</d:href></c:calendar-multiget>"#
        ),
    )
    .await;
    assert!(multiget.body.contains("getetag"), "{}", multiget.body);
    assert!(!multiget.body.contains("404"), "{}", multiget.body);
    let sync = dav_as(
        &state,
        OTHER,
        "REPORT",
        SHARED,
        &[],
        r#"<d:sync-collection xmlns:d="DAV:"><d:sync-token/><d:prop><d:getetag/></d:prop>
           </d:sync-collection>"#,
    )
    .await;
    assert!(sync.body.contains(&object), "{}", sync.body);

    // Writes need privileges the sharee lacks.
    let new_event = event("b", "Sneaky", "20261013T090000Z");
    let added = format!("{SHARED}b.ics");
    let refused = dav_as(&state, OTHER, "PUT", &added, &[], &new_event).await;
    assert_eq!(refused.status, 403);
    assert!(refused.body.contains("need-privileges"), "{}", refused.body);
    assert!(refused.body.contains("<d:bind/>"), "{}", refused.body);
    let changed = event("a", "Changed", "20261012T090000Z");
    let refused = dav_as(&state, OTHER, "PUT", &object, &[], &changed).await;
    assert!(
        refused.body.contains("<d:write-content/>"),
        "{}",
        refused.body
    );
    let refused = dav_as(&state, OTHER, "DELETE", &object, &[], "").await;
    assert_eq!(refused.status, 403);
    assert!(refused.body.contains("<d:unbind/>"));
    let onward = share_request("third@example.test", "read");
    assert_eq!(
        dav_as(&state, OTHER, "POST", SHARED, &[], &onward)
            .await
            .status,
        403
    );

    // Name and color are the sharee's own; the description is the owner's.
    let patch = |prop: &str| {
        format!(
            r#"<d:propertyupdate xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"
               xmlns:i="http://apple.com/ns/ical/"><d:set><d:prop>{prop}</d:prop></d:set>
               </d:propertyupdate>"#
        )
    };
    let personal =
        patch("<i:calendar-color>#00ff00</i:calendar-color><d:displayname>Team</d:displayname>");
    let colored = dav_as(&state, OTHER, "PROPPATCH", SHARED, &[], &personal).await;
    assert!(colored.body.contains("200 OK"), "{}", colored.body);
    assert!(!colored.body.contains("403"), "{}", colored.body);
    let description = patch("<c:calendar-description>Mine</c:calendar-description>");
    let described = dav_as(&state, OTHER, "PROPPATCH", SHARED, &[], &description).await;
    assert!(described.body.contains("403"), "{}", described.body);
    let props = r#"<d:propfind xmlns:d="DAV:" xmlns:i="http://apple.com/ns/ical/">
                   <d:prop><d:displayname/><i:calendar-color/></d:prop></d:propfind>"#;
    let sharee_view = dav_as(&state, OTHER, "PROPFIND", SHARED, &[("depth", "0")], props).await;
    assert!(sharee_view.body.contains("#00ff00"), "{}", sharee_view.body);
    assert!(sharee_view.body.contains(">Team<"), "{}", sharee_view.body);
    let owner_view = dav(&state, "PROPFIND", CALENDAR, &[("depth", "0")], props).await;
    assert!(!owner_view.body.contains("#00ff00") && !owner_view.body.contains("Team"));

    // The owner's principal is visible to the sharee only.
    let principal = r#"<d:propfind xmlns:d="DAV:"><d:prop><d:displayname/></d:prop></d:propfind>"#;
    let owner = "/dav/principals/user@example.test/";
    let depth = [("depth", "0")];
    let seen = dav_as(&state, OTHER, "PROPFIND", owner, &depth, principal).await;
    assert_eq!(seen.status, 207);
    let third = "third@example.test";
    let hidden = dav_as(&state, third, "PROPFIND", owner, &depth, principal).await;
    assert_eq!(hidden.status, 404);
    // Nobody else reaches it, by a binding of their own or the owner's path.
    let guessed = "/dav/calendars/third@example.test/user@example.test~default/a.ics";
    assert_eq!(
        dav_as(&state, third, "GET", guessed, &[], "").await.status,
        404
    );
    assert_eq!(
        dav_as(&state, OTHER, "GET", &existing, &[], "")
            .await
            .status,
        404
    );
    // Own collections cannot take the names kept for shares.
    let reserved = "/dav/calendars/user@example.test/a@b~c/";
    assert_eq!(
        dav(&state, "MKCALENDAR", reserved, &[], "").await.status,
        403
    );

    // With read-write access the sharee changes the owner's calendar.
    let upgrade = share_request(OTHER, "read-write");
    assert_eq!(
        dav(&state, "POST", CALENDAR, &[], &upgrade).await.status,
        200
    );
    let privileges = dav_as(
        &state,
        OTHER,
        "PROPFIND",
        SHARED,
        &depth,
        r#"<d:propfind xmlns:d="DAV:"><d:prop><d:current-user-privilege-set/></d:prop></d:propfind>"#,
    )
    .await;
    assert!(privileges.body.contains("<d:write-content/>"));
    let created = dav_as(&state, OTHER, "PUT", &added, &[], &new_event).await;
    assert_eq!(created.status, 201, "{}", created.body);
    let in_owner = dav(&state, "GET", &format!("{CALENDAR}b.ics"), &[], "").await;
    assert!(in_owner.body.contains("SUMMARY:Sneaky"));
    let description = patch("<c:calendar-description>Shared</c:calendar-description>");
    let described = dav_as(&state, OTHER, "PROPPATCH", SHARED, &[], &description).await;
    assert!(!described.body.contains("403"), "{}", described.body);
    assert_eq!(
        dav_as(&state, OTHER, "DELETE", &added, &[], "")
            .await
            .status,
        204
    );
    // The sharee's own name outlived the change of access.
    let sharee_view = dav_as(&state, OTHER, "PROPFIND", SHARED, &depth, props).await;
    assert!(sharee_view.body.contains(">Team<"));

    // Leaving the share drops the grant; the owner keeps the calendar.
    assert_eq!(
        dav_as(&state, OTHER, "DELETE", SHARED, &[], "")
            .await
            .status,
        204
    );
    assert_eq!(
        dav_as(&state, OTHER, "GET", &object, &[], "").await.status,
        404
    );
    assert_eq!(dav(&state, "GET", &existing, &[], "").await.status, 200);
    let grants = rmail_common::dav::share::shared_with(&state.db_path, OTHER).unwrap();
    assert!(grants.is_empty());

    // Deleting a shared collection forgets its grants.
    let again = share_request(OTHER, "read");
    assert_eq!(dav(&state, "POST", CALENDAR, &[], &again).await.status, 200);
    assert_eq!(dav(&state, "DELETE", CALENDAR, &[], "").await.status, 204);
    let grants = rmail_common::dav::share::shared_with(&state.db_path, OTHER).unwrap();
    assert!(grants.is_empty());
}

#[tokio::test]
async fn sharees_schedule_as_the_calendar_owner() {
    let td = tempfile::tempdir().unwrap();
    let state = state(&td);
    let third = "third@example.test";
    let third_calendar = "/dav/calendars/third@example.test/default/";
    let grant = share_request(OTHER, "read-write");
    assert_eq!(dav(&state, "POST", CALENDAR, &[], &grant).await.status, 200);

    // The sharee books a meeting the owner organizes, in the owner's
    // calendar: the invitation comes from the owner.
    let invite = meeting(&[(third, "NEEDS-ACTION")], "Review", "");
    let shared_event = format!("{SHARED}meet.ics");
    let created = dav_as(&state, OTHER, "PUT", &shared_event, &[], &invite).await;
    assert_eq!(created.status, 201, "{}", created.body);
    let stored = dav(&state, "GET", &format!("{CALENDAR}meet.ics"), &[], "").await;
    let stored = unfolded(&stored.body);
    assert!(
        stored.contains("SCHEDULE-STATUS=1.2:mailto:third@example.test"),
        "{stored}"
    );
    let copies = objects_in(&state, third, third_calendar).await;
    assert_eq!(copies.len(), 1);
    assert!(unfolded(&copies[0].1).contains("ORGANIZER:mailto:user@example.test"));
    // The sharee is no attendee and gets nothing.
    let sharee_inbox = "/dav/calendars/other@example.test/inbox/";
    assert!(objects_in(&state, OTHER, sharee_inbox).await.is_empty());

    // The attendee's answer reaches the owner's copy, where the sharee
    // sees it.
    let (copy_href, copy) = copies[0].clone();
    let accepted = unfolded(&copy).replace(
        "PARTSTAT=NEEDS-ACTION:mailto:third@example.test",
        "PARTSTAT=ACCEPTED:mailto:third@example.test",
    );
    let answered = dav_as(&state, third, "PUT", &copy_href, &[], &accepted).await;
    assert_eq!(answered.status, 204);
    let seen = dav_as(&state, OTHER, "GET", &shared_event, &[], "").await;
    let seen = unfolded(&seen.body);
    let line = seen
        .lines()
        .find(|line| line.ends_with("mailto:third@example.test"))
        .unwrap();
    assert!(line.contains("PARTSTAT=ACCEPTED"), "{seen}");

    // Deleting it in the shared calendar cancels as the owner.
    let deleted = dav_as(&state, OTHER, "DELETE", &shared_event, &[], "").await;
    assert_eq!(deleted.status, 204);
    let cancelled = objects_in(&state, third, third_calendar).await;
    assert!(
        unfolded(&cancelled[0].1).contains("STATUS:CANCELLED"),
        "{}",
        cancelled[0].1
    );
}

#[tokio::test]
async fn address_books_are_shared_too() {
    use rmail_common::dav::{share, store};
    let td = tempfile::tempdir().unwrap();
    let state = state(&td);
    let book = "/dav/addressbooks/user@example.test/default/";
    let card = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:c1\r\nFN:Ada\r\nEND:VCARD\r\n";
    let put = dav(&state, "PUT", &format!("{book}c1.vcf"), &[], card).await;
    assert_eq!(put.status, 201);
    let conn = rmail_common::jmap::store::open(&state.mail_root, "example.test", "user").unwrap();
    let id = store::collection(&conn, store::Kind::AddressBook, "default")
        .unwrap()
        .unwrap()
        .id;
    share::set_access(
        &state.db_path,
        USER,
        id,
        OTHER,
        Some(share::Access::ReadWrite),
    )
    .unwrap();
    let home = "/dav/addressbooks/other@example.test/";
    let listing = dav_as(&state, OTHER, "PROPFIND", home, &[("depth", "1")], "").await;
    let shared = "/dav/addressbooks/other@example.test/user@example.test~default/";
    assert!(listing.body.contains(shared), "{}", listing.body);
    // A shared address book is not reachable as a calendar.
    let as_calendar = "/dav/calendars/other@example.test/user@example.test~default/c1.vcf";
    assert_eq!(
        dav_as(&state, OTHER, "GET", as_calendar, &[], "")
            .await
            .status,
        404
    );
    let card2 = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:c2\r\nFN:Grace\r\nEND:VCARD\r\n";
    let added = dav_as(&state, OTHER, "PUT", &format!("{shared}c2.vcf"), &[], card2).await;
    assert_eq!(added.status, 201);
    let in_owner = dav(&state, "GET", &format!("{book}c2.vcf"), &[], "").await;
    assert!(in_owner.body.contains("FN:Grace"));
    let read = dav_as(&state, OTHER, "GET", &format!("{shared}c1.vcf"), &[], "").await;
    assert!(read.body.contains("FN:Ada"));
}
