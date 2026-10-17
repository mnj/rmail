//! ActiveSync as a phone uses it, over the router.

use axum::body::Body;
use axum::http::Request;
use base64::Engine;
use rmail_common::http::Peer;
use rmail_common::imap_state;
use serde_json::json;

use super::wbxml::{self, Element};
use crate::api::tests::{route, state};

const DEVICE: &str = "Appl1234567890";

fn request(command: &str, body: Option<&Element>) -> Request<Body> {
    let auth = base64::engine::general_purpose::STANDARD.encode("user@example.test:secret");
    let bytes = body.map(wbxml::encode).unwrap_or_default();
    let mut request = Request::builder()
        .method("POST")
        .uri(format!(
            "{}?Cmd={command}&User=user@example.test&DeviceId={DEVICE}&DeviceType=iPhone",
            super::PATH
        ))
        .header("authorization", format!("Basic {auth}"))
        .header("content-type", "application/vnd.ms-sync.wbxml")
        .header("ms-asprotocolversion", "14.1")
        .body(Body::from(bytes))
        .unwrap();
    request
        .extensions_mut()
        .insert(Peer(Some("192.0.2.9:40000".parse().unwrap())));
    request
}

async fn call(
    state: &std::sync::Arc<crate::api::AppState>,
    command: &str,
    body: Option<&Element>,
) -> Element {
    let response = route(request(command, body), state).await;
    assert_eq!(
        response.status,
        200,
        "{command}: {}",
        String::from_utf8_lossy(&response.body)
    );
    wbxml::decode(&response.body).unwrap_or_else(|e| panic!("{command}: {e}"))
}

fn sync_request(
    collection: &str,
    key: &str,
    commands: Option<Element>,
    window: Option<&str>,
) -> Element {
    let mut c = Element::new("AirSync:Collection")
        .with(Element::text("AirSync:SyncKey", key))
        .with(Element::text("AirSync:CollectionId", collection));
    if key != "0" {
        c.push(Element::new("AirSync:DeletesAsMoves"));
        c.push(Element::new("AirSync:GetChanges"));
        if let Some(window) = window {
            c.push(Element::text("AirSync:WindowSize", window));
        }
        c.push(
            Element::new("AirSync:Options")
                .with(Element::text("AirSync:FilterType", "0"))
                .with(
                    Element::new("AirSyncBase:BodyPreference")
                        .with(Element::text("AirSyncBase:Type", "2"))
                        .with(Element::text("AirSyncBase:TruncationSize", "200000")),
                ),
        );
    }
    if let Some(commands) = commands {
        c.push(commands);
    }
    Element::new("AirSync:Sync").with(Element::new("AirSync:Collections").with(c))
}

fn collection(response: &Element) -> &Element {
    response
        .child("AirSync:Collections")
        .and_then(|c| c.child("AirSync:Collection"))
        .expect("a collection")
}

#[test]
fn query_parameters_plain_and_base64() {
    let plain = super::params("Cmd=Sync&User=a%40b.test&DeviceId=ABC&DeviceType=iPhone").unwrap();
    assert_eq!(
        (
            plain.command.as_str(),
            plain.device.as_str(),
            plain.get("User")
        ),
        ("Sync", "ABC", Some("a@b.test"))
    );
    // Version 141, command 0 (Sync), locale, device id "DEV", no policy key, type "SP".
    let raw = [141u8, 0, 0x09, 0x04, 3, b'D', b'E', b'V', 0, 2, b'S', b'P'];
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
    let decoded = super::params(&encoded).unwrap();
    assert_eq!(
        (
            decoded.command.as_str(),
            decoded.device.as_str(),
            decoded.device_type.as_str()
        ),
        ("Sync", "DEV", "SP")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_phone_syncs_reads_moves_and_sends_mail() {
    let td = tempfile::tempdir().unwrap();
    let mail_root = td.path().join("mail");
    std::fs::create_dir_all(&mail_root).unwrap();
    let (submission, mut received) = crate::jmap::tests::fake_submission(mail_root.clone()).await;
    let base = state(&td);
    let state = std::sync::Arc::new(crate::api::AppState {
        mail_root: base.mail_root.clone(),
        db_path: base.db_path.clone(),
        static_dir: base.static_dir.clone(),
        session_secret: base.session_secret.clone(),
        secure_cookies: false,
        throttle: Default::default(),
        revoked: Default::default(),
        submission: Some(submission),
        oauth: None,
        jmap_logins: Default::default(),
        shutdown: None,
        assist_limiter: Default::default(),
    });
    let root = state.mail_root.clone();
    imap_state::init_account(&root, "example.test", "user").unwrap();
    let off = route(
        request(
            "FolderSync",
            Some(
                &Element::new("FolderHierarchy:FolderSync")
                    .with(Element::text("FolderHierarchy:SyncKey", "0")),
            ),
        ),
        &state,
    )
    .await;
    assert_eq!(off.status, 404, "off until the admin turns it on");
    let mut settings = rmail_common::settings::open(&state.db_path).unwrap();
    rmail_common::settings::write_raw(
        &mut settings,
        &[("activesync.enabled".to_string(), Some(json!(true)))]
            .into_iter()
            .collect(),
    )
    .unwrap();
    let options = route(
        {
            let mut r = request("", None);
            *r.method_mut() = axum::http::Method::OPTIONS;
            r
        },
        &state,
    )
    .await;
    assert!(
        options
            .headers
            .iter()
            .any(|(k, v)| k == "Ms-Asprotocolversions" && v.contains("14.1")),
        "{:?}",
        options.headers
    );

    for subject in ["First", "Second", "Third"] {
        let message = format!(
            "From: Ann <ann@remote.test>\r\nTo: user@example.test\r\nSubject: {subject}\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/html\r\n\r\n<p>Hello {subject}</p>\r\n--b\r\nContent-Type: text/plain; name=notes.txt\r\nContent-Disposition: attachment; filename=notes.txt\r\n\r\nattached notes\r\n--b--\r\n"
        );
        imap_state::deliver_message(&root, "example.test", "user", message.as_bytes()).unwrap();
    }

    // Provisioning: a policy, then its acknowledgement.
    let ask = Element::new("Provision:Provision").with(Element::new("Provision:Policies").with(
        Element::new("Provision:Policy").with(Element::text(
            "Provision:PolicyType",
            "MS-EAS-Provisioning-WBXML",
        )),
    ));
    let policy = call(&state, "Provision", Some(&ask)).await;
    let policy = policy
        .child("Provision:Policies")
        .and_then(|p| p.child("Provision:Policy"))
        .unwrap();
    assert!(policy.child("Provision:Data").is_some());
    let key = policy.value("Provision:PolicyKey").unwrap();
    let ack = Element::new("Provision:Provision").with(
        Element::new("Provision:Policies").with(
            Element::new("Provision:Policy")
                .with(Element::text(
                    "Provision:PolicyType",
                    "MS-EAS-Provisioning-WBXML",
                ))
                .with(Element::text("Provision:PolicyKey", key))
                .with(Element::text("Provision:Status", "1")),
        ),
    );
    let done = call(&state, "Provision", Some(&ack)).await;
    assert_eq!(done.value("Provision:Status").as_deref(), Some("1"));

    // Folders.
    let folders = call(
        &state,
        "FolderSync",
        Some(
            &Element::new("FolderHierarchy:FolderSync")
                .with(Element::text("FolderHierarchy:SyncKey", "0")),
        ),
    )
    .await;
    assert_eq!(
        folders.value("FolderHierarchy:Status").as_deref(),
        Some("1")
    );
    let adds: Vec<&Element> = folders
        .child("FolderHierarchy:Changes")
        .unwrap()
        .children_named("FolderHierarchy:Add")
        .collect();
    let find = |kind: &str| {
        adds.iter()
            .find(|a| a.value("FolderHierarchy:Type").as_deref() == Some(kind))
            .and_then(|a| a.value("FolderHierarchy:ServerId"))
            .unwrap()
    };
    let (inbox, trash) = (find("2"), find("4"));
    let again = call(
        &state,
        "FolderSync",
        Some(
            &Element::new("FolderHierarchy:FolderSync").with(Element::text(
                "FolderHierarchy:SyncKey",
                folders.value("FolderHierarchy:SyncKey").unwrap(),
            )),
        ),
    )
    .await;
    assert_eq!(
        again
            .child("FolderHierarchy:Changes")
            .unwrap()
            .value("FolderHierarchy:Count")
            .as_deref(),
        Some("0")
    );

    // Mail: a key, then the messages two at a time.
    let first = call(&state, "Sync", Some(&sync_request(&inbox, "0", None, None))).await;
    assert_eq!(
        collection(&first).value("AirSync:SyncKey").as_deref(),
        Some("1")
    );
    let page = call(
        &state,
        "Sync",
        Some(&sync_request(&inbox, "1", None, Some("2"))),
    )
    .await;
    let c = collection(&page);
    assert!(c.child("AirSync:MoreAvailable").is_some());
    let added: Vec<&Element> = c
        .child("AirSync:Commands")
        .unwrap()
        .children_named("AirSync:Add")
        .collect();
    assert_eq!(added.len(), 2);
    let data = added[0].child("AirSync:ApplicationData").unwrap();
    assert_eq!(
        data.value("Email:Subject").as_deref(),
        Some("Third"),
        "newest first"
    );
    let body = data.child("AirSyncBase:Body").unwrap();
    assert_eq!(body.value("AirSyncBase:Type").as_deref(), Some("2"));
    assert!(
        body.value("AirSyncBase:Data")
            .unwrap()
            .contains("Hello Third")
    );
    let reference = data
        .child("AirSyncBase:Attachments")
        .unwrap()
        .child("AirSyncBase:Attachment")
        .unwrap()
        .value("AirSyncBase:FileReference")
        .unwrap();
    let third = added[0].value("AirSync:ServerId").unwrap();
    let key2 = c.value("AirSync:SyncKey").unwrap();
    let rest = call(
        &state,
        "Sync",
        Some(&sync_request(&inbox, &key2, None, Some("2"))),
    )
    .await;
    let c = collection(&rest);
    assert_eq!(
        c.child("AirSync:Commands")
            .unwrap()
            .children_named("AirSync:Add")
            .count(),
        1
    );
    assert!(c.child("AirSync:MoreAvailable").is_none());
    let key3 = c.value("AirSync:SyncKey").unwrap();

    // The phone reads one; the server flags another; nothing is echoed back.
    let read = Element::new("AirSync:Commands").with(
        Element::new("AirSync:Change")
            .with(Element::text("AirSync:ServerId", third.clone()))
            .with(Element::new("AirSync:ApplicationData").with(Element::text("Email:Read", "1"))),
    );
    let after = call(
        &state,
        "Sync",
        Some(&sync_request(&inbox, &key3, Some(read), None)),
    )
    .await;
    let c = collection(&after);
    assert!(
        c.child("AirSync:Commands").is_none(),
        "the phone's own change is not sent back"
    );
    let uid: u64 = third.split(':').nth(1).unwrap().parse().unwrap();
    let flags = imap_state::load_folder(&root, "example.test", "user", "INBOX")
        .unwrap()
        .1
        .into_iter()
        .find(|m| m.uid == uid)
        .unwrap()
        .flags;
    assert!(flags.iter().any(|f| f == "\\Seen"));
    let key4 = c.value("AirSync:SyncKey").unwrap();
    let estimate_request = Element::new("GetItemEstimate:GetItemEstimate").with(
        Element::new("GetItemEstimate:Collections").with(
            Element::new("GetItemEstimate:Collection")
                .with(Element::text("AirSync:SyncKey", key4.clone()))
                .with(Element::text("GetItemEstimate:CollectionId", inbox.clone())),
        ),
    );
    imap_state::set_uid_flags(
        &root,
        "example.test",
        "user",
        "INBOX",
        uid,
        vec!["\\Seen".into(), "\\Flagged".into()],
    )
    .unwrap();
    let estimate = call(&state, "GetItemEstimate", Some(&estimate_request)).await;
    let count = estimate
        .child("GetItemEstimate:Response")
        .unwrap()
        .child("GetItemEstimate:Collection")
        .unwrap()
        .value("GetItemEstimate:Estimate");
    assert_eq!(count.as_deref(), Some("1"));
    // Push: the waiting change is reported at once.
    let ping = Element::new("Ping:Ping")
        .with(Element::text("Ping:HeartbeatInterval", "480"))
        .with(
            Element::new("Ping:Folders").with(
                Element::new("Ping:Folder")
                    .with(Element::text("Ping:Id", inbox.clone()))
                    .with(Element::text("Ping:Class", "Email")),
            ),
        );
    let pinged = call(&state, "Ping", Some(&ping)).await;
    assert_eq!(pinged.value("Ping:Status").as_deref(), Some("2"));
    let flagged = call(
        &state,
        "Sync",
        Some(&sync_request(&inbox, &key4, None, None)),
    )
    .await;
    let change = collection(&flagged)
        .child("AirSync:Commands")
        .unwrap()
        .child("AirSync:Change")
        .unwrap();
    assert_eq!(
        change
            .child("AirSync:ApplicationData")
            .unwrap()
            .child("Email:Flag")
            .unwrap()
            .value("Email:FlagStatus")
            .as_deref(),
        Some("2")
    );
    let key5 = collection(&flagged).value("AirSync:SyncKey").unwrap();
    // A repeat of the previous key gets the same answer again.
    let repeat = call(
        &state,
        "Sync",
        Some(&sync_request(&inbox, &key4, None, None)),
    )
    .await;
    assert_eq!(
        collection(&repeat).value("AirSync:SyncKey"),
        Some(key5.clone()),
        "the same key again"
    );
    assert!(
        collection(&repeat)
            .child("AirSync:Commands")
            .unwrap()
            .child("AirSync:Change")
            .is_some()
    );

    // The attachment, on request.
    let fetch = Element::new("ItemOperations:ItemOperations").with(
        Element::new("ItemOperations:Fetch")
            .with(Element::text("ItemOperations:Store", "Mailbox"))
            .with(Element::text("AirSyncBase:FileReference", reference)),
    );
    let fetched = call(&state, "ItemOperations", Some(&fetch)).await;
    let data = fetched
        .child("ItemOperations:Response")
        .unwrap()
        .child("ItemOperations:Fetch")
        .unwrap()
        .child("ItemOperations:Properties")
        .unwrap()
        .value("ItemOperations:Data")
        .unwrap();
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(data)
            .unwrap(),
        b"attached notes"
    );

    // Moved to Trash on the phone; gone from the inbox on the next sync.
    let movement = Element::new("Move:MoveItems").with(
        Element::new("Move:Move")
            .with(Element::text("Move:SrcMsgId", third.clone()))
            .with(Element::text("Move:SrcFldId", inbox.clone()))
            .with(Element::text("Move:DstFldId", trash.clone())),
    );
    let moved = call(&state, "MoveItems", Some(&movement)).await;
    assert_eq!(
        moved
            .child("Move:Response")
            .unwrap()
            .value("Move:Status")
            .as_deref(),
        Some("3")
    );
    let gone = call(
        &state,
        "Sync",
        Some(&sync_request(&inbox, &key5, None, None)),
    )
    .await;
    assert_eq!(
        collection(&gone)
            .child("AirSync:Commands")
            .unwrap()
            .child("AirSync:Delete")
            .unwrap()
            .value("AirSync:ServerId")
            .as_deref(),
        Some(third.as_str())
    );

    // Sending, with a copy in Sent.
    let mime = b"From: user@example.test\r\nTo: Bob <bob@remote.test>\r\nBcc: hidden@remote.test\r\nSubject: From my phone\r\n\r\nSent from the phone.\r\n".to_vec();
    let send = Element::new("ComposeMail:SendMail")
        .with(Element::text("ComposeMail:ClientId", "c1"))
        .with(Element::new("ComposeMail:SaveInSentItems"))
        .with(Element {
            opaque: Some(mime),
            ..Element::new("ComposeMail:MIME")
        });
    let response = route(request("SendMail", Some(&send)), &state).await;
    assert_eq!(
        (response.status, response.body.len()),
        (200, 0),
        "success is an empty answer"
    );
    let (envelope, data) = received.recv().await.unwrap();
    assert!(
        envelope.iter().any(|l| l.contains("bob@remote.test"))
            && envelope.iter().any(|l| l.contains("hidden@remote.test"))
    );
    assert!(
        !data.contains("hidden@remote.test"),
        "Bcc stays off the wire"
    );
    let sent = imap_state::list_folders(&root, "example.test", "user")
        .unwrap()
        .into_iter()
        .find(|f| f.special_use.as_deref() == Some("\\Sent"))
        .unwrap();
    assert_eq!(
        imap_state::load_folder(&root, "example.test", "user", &sent.name)
            .unwrap()
            .1
            .len(),
        1
    );

    // Settings: the user's addresses.
    let info = call(
        &state,
        "Settings",
        Some(
            &Element::new("Settings:Settings")
                .with(Element::new("Settings:UserInformation").with(Element::new("Settings:Get"))),
        ),
    )
    .await;
    let get = info
        .child("Settings:UserInformation")
        .unwrap()
        .child("Settings:Get")
        .unwrap();
    assert_eq!(
        get.child("Settings:EmailAddresses")
            .unwrap()
            .value("Settings:SmtpAddress")
            .as_deref(),
        Some("user@example.test")
    );
}

#[test]
fn base64_queries_keep_their_plus_signs() {
    // A device id whose base64 form has a "+" in it.
    let raw = [141u8, 0, 0x09, 0x04, 3, 62, b'E', b'V', 0, 2, b'S', b'P'];
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
    assert!(encoded.contains('+'), "{encoded}");
    assert!(super::params(&encoded).is_some());
}

#[tokio::test]
async fn folders_follow_webmails_rules_and_empty_syncs_move_on() {
    let td = tempfile::tempdir().unwrap();
    let state = state(&td);
    let root = state.mail_root.clone();
    imap_state::init_account(&root, "example.test", "user").unwrap();
    let mut settings = rmail_common::settings::open(&state.db_path).unwrap();
    rmail_common::settings::write_raw(
        &mut settings,
        &[("activesync.enabled".to_string(), Some(json!(true)))]
            .into_iter()
            .collect(),
    )
    .unwrap();
    imap_state::create_folder(&root, "example.test", "user", "Projects").unwrap();
    imap_state::create_folder(&root, "example.test", "user", "Projects/Alpha").unwrap();
    let folders = call(
        &state,
        "FolderSync",
        Some(
            &Element::new("FolderHierarchy:FolderSync")
                .with(Element::text("FolderHierarchy:SyncKey", "0")),
        ),
    )
    .await;
    let adds: Vec<&Element> = folders
        .child("FolderHierarchy:Changes")
        .unwrap()
        .children_named("FolderHierarchy:Add")
        .collect();
    let id = |name: &str| {
        adds.iter()
            .find(|a| a.value("FolderHierarchy:DisplayName").as_deref() == Some(name))
            .and_then(|a| a.value("FolderHierarchy:ServerId"))
            .unwrap()
    };
    let (sent, projects, alpha) = (
        adds.iter()
            .find(|a| a.value("FolderHierarchy:Type").as_deref() == Some("5"))
            .and_then(|a| a.value("FolderHierarchy:ServerId"))
            .unwrap(),
        id("Projects"),
        id("Alpha"),
    );

    let rename = |id: &str, name: &str| {
        Element::new("FolderHierarchy:FolderUpdate")
            .with(Element::text("FolderHierarchy:SyncKey", "1"))
            .with(Element::text("FolderHierarchy:ServerId", id))
            .with(Element::text("FolderHierarchy:ParentId", "0"))
            .with(Element::text("FolderHierarchy:DisplayName", name))
    };
    let refused = call(&state, "FolderUpdate", Some(&rename(&sent, "Outbox2"))).await;
    assert_eq!(
        refused.value("FolderHierarchy:Status").as_deref(),
        Some("3"),
        "special folders stay"
    );
    let create = Element::new("FolderHierarchy:FolderCreate")
        .with(Element::text("FolderHierarchy:SyncKey", "1"))
        .with(Element::text("FolderHierarchy:ParentId", "0"))
        .with(Element::text(
            "FolderHierarchy:DisplayName",
            "Other Users/x",
        ))
        .with(Element::text("FolderHierarchy:Type", "12"));
    assert_eq!(
        call(&state, "FolderCreate", Some(&create))
            .await
            .value("FolderHierarchy:Status")
            .as_deref(),
        Some("10")
    );
    let renamed = call(&state, "FolderUpdate", Some(&rename(&projects, "Work"))).await;
    assert_eq!(
        renamed.value("FolderHierarchy:Status").as_deref(),
        Some("1")
    );
    let db =
        super::state::open(&imap_state::account_maildir(&root, "example.test", "user")).unwrap();
    assert_eq!(
        super::state::folder_name(&db, &alpha).unwrap().as_deref(),
        Some("Work/Alpha"),
        "subfolders keep their ids"
    );

    // An empty Sync repeats the last one at the current key, not the old one.
    let inbox = id("Inbox");
    call(&state, "Sync", Some(&sync_request(&inbox, "0", None, None))).await;
    let first = call(&state, "Sync", Some(&sync_request(&inbox, "1", None, None))).await;
    let key = collection(&first).value("AirSync:SyncKey").unwrap();
    imap_state::deliver_message(
        &root,
        "example.test",
        "user",
        b"From: a@b.test\r\nSubject: New\r\n\r\nhi",
    )
    .unwrap();
    let empty = route(request("Sync", None), &state).await;
    let empty = wbxml::decode(&empty.body).unwrap();
    let c = collection(&empty);
    assert_eq!(
        c.child("AirSync:Commands")
            .unwrap()
            .children_named("AirSync:Add")
            .count(),
        1
    );
    assert_eq!(
        c.value("AirSync:SyncKey").unwrap().parse::<i64>().unwrap(),
        key.parse::<i64>().unwrap() + 1,
        "moves on"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn contacts_calendars_and_invitations() {
    use rmail_common::dav::store::{self, Kind};
    let td = tempfile::tempdir().unwrap();
    let state = state(&td);
    let root = state.mail_root.clone();
    imap_state::init_account(&root, "example.test", "user").unwrap();
    let mut settings = rmail_common::settings::open(&state.db_path).unwrap();
    rmail_common::settings::write_raw(
        &mut settings,
        &[("activesync.enabled".to_string(), Some(json!(true)))]
            .into_iter()
            .collect(),
    )
    .unwrap();
    let conn = rmail_common::jmap::store::open(&root, "example.test", "user").unwrap();
    let book = store::collections(&conn, Kind::AddressBook)
        .unwrap()
        .remove(0);
    store::put(
        &conn,
        &book,
        "c1.vcf",
        "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:c1\r\nFN:Ann Smith\r\nN:Smith;Ann;;;\r\nEMAIL:ann@remote.test\r\nEMAIL:a2@remote.test\r\nEMAIL:a3@remote.test\r\nEMAIL:a4@remote.test\r\nTEL;TYPE=CELL:+4512345678\r\nBDAY:--0315\r\nX-KEPT:yes\r\nEND:VCARD\r\n",
        &|_| true,
    )
    .unwrap()
    .unwrap();

    let folders = call(
        &state,
        "FolderSync",
        Some(
            &Element::new("FolderHierarchy:FolderSync")
                .with(Element::text("FolderHierarchy:SyncKey", "0")),
        ),
    )
    .await;
    let of_type = |kind: &str| {
        folders
            .child("FolderHierarchy:Changes")
            .unwrap()
            .children_named("FolderHierarchy:Add")
            .find(|a| a.value("FolderHierarchy:Type").as_deref() == Some(kind))
            .and_then(|a| a.value("FolderHierarchy:ServerId"))
            .unwrap_or_else(|| panic!("a folder of type {kind}"))
    };
    let (contacts, calendar, inbox) = (of_type("9"), of_type("8"), of_type("2"));

    // The server's contact goes to the phone.
    call(
        &state,
        "Sync",
        Some(&sync_request(&contacts, "0", None, None)),
    )
    .await;
    let first = call(
        &state,
        "Sync",
        Some(&sync_request(&contacts, "1", None, None)),
    )
    .await;
    let add = collection(&first)
        .child("AirSync:Commands")
        .and_then(|c| c.child("AirSync:Add"))
        .expect("the contact");
    assert_eq!(add.value("AirSync:ServerId").as_deref(), Some("c1.vcf"));
    let data = add.child("AirSync:ApplicationData").unwrap();
    assert_eq!(data.value("Contacts:FirstName").as_deref(), Some("Ann"));
    assert_eq!(
        data.value("Contacts:Email1Address").as_deref(),
        Some("ann@remote.test")
    );
    assert_eq!(
        data.value("Contacts:MobilePhoneNumber").as_deref(),
        Some("+4512345678")
    );

    // The phone adds one and changes the other.
    let commands = Element::new("AirSync:Commands")
        .with(
            Element::new("AirSync:Add")
                .with(Element::text("AirSync:ClientId", "x1"))
                .with(
                    Element::new("AirSync:ApplicationData")
                        .with(Element::text("Contacts:FirstName", "Bob"))
                        .with(Element::text("Contacts:LastName", "Lee"))
                        .with(Element::text(
                            "Contacts:Email1Address",
                            "\"Bob Lee\" <bob@x.test>",
                        )),
                ),
        )
        .with(
            Element::new("AirSync:Change")
                .with(Element::text("AirSync:ServerId", "c1.vcf"))
                .with(
                    Element::new("AirSync:ApplicationData")
                        .with(Element::text("Contacts:FirstName", "Ann"))
                        .with(Element::text("Contacts:LastName", "Smith"))
                        .with(Element::text("Contacts:JobTitle", "Engineer"))
                        .with(Element::text("Contacts:Email1Address", "ann@remote.test")),
                ),
        );
    let key = collection(&first).value("AirSync:SyncKey").unwrap();
    call(
        &state,
        "Sync",
        Some(&sync_request(&contacts, &key, Some(commands.clone()), None)),
    )
    .await;
    // The response was lost: the phone sends the same Sync again.
    let second = call(
        &state,
        "Sync",
        Some(&sync_request(&contacts, &key, Some(commands), None)),
    )
    .await;
    let added = collection(&second)
        .child("AirSync:Responses")
        .and_then(|r| r.child("AirSync:Add"))
        .unwrap();
    assert_eq!(added.value("AirSync:Status").as_deref(), Some("1"));
    // Bob is not echoed; Ann comes back merged, with what she was not sent.
    let back = collection(&second)
        .child("AirSync:Commands")
        .expect("Ann's merged card");
    assert!(back.child("AirSync:Add").is_none(), "no echo of the add");
    let merged = back.child("AirSync:Change").unwrap();
    assert_eq!(
        merged
            .child("AirSync:ApplicationData")
            .and_then(|d| d.value("Contacts:Email2Address"))
            .as_deref(),
        Some("a4@remote.test")
    );
    let stored = store::objects(&conn, &book).unwrap();
    assert_eq!(
        stored
            .iter()
            .filter(|o| o.data.contains("bob@x.test"))
            .count(),
        1,
        "a retried Add is not stored twice"
    );
    let ann = stored.iter().find(|o| o.name == "c1.vcf").unwrap();
    assert!(
        ann.data.contains("TITLE:Engineer") && ann.data.contains("X-KEPT:yes"),
        "{}",
        ann.data
    );
    assert!(
        !ann.data.contains("+4512345678") && !ann.data.contains("a2@remote.test"),
        "the phone's version replaces the fields it was sent"
    );
    assert!(
        ann.data.contains("a4@remote.test") && ann.data.contains("--0315"),
        "what it was not sent is kept: {}",
        ann.data
    );

    // A server-side delete reaches the phone.
    store::delete(&conn, &book, "c1.vcf", &|_| true).unwrap();
    let key = collection(&second).value("AirSync:SyncKey").unwrap();
    let third = call(
        &state,
        "Sync",
        Some(&sync_request(&contacts, &key, None, None)),
    )
    .await;
    assert_eq!(
        collection(&third)
            .child("AirSync:Commands")
            .and_then(|c| c.child("AirSync:Delete"))
            .and_then(|d| d.value("AirSync:ServerId"))
            .as_deref(),
        Some("c1.vcf")
    );

    // An event from the phone lands in the calendar, all-day dates intact.
    call(
        &state,
        "Sync",
        Some(&sync_request(&calendar, "0", None, None)),
    )
    .await;
    let event = Element::new("AirSync:Commands")
        .with(
            Element::new("AirSync:Add")
                .with(Element::text("AirSync:ClientId", "e1"))
                .with(
                    Element::new("AirSync:ApplicationData")
                        .with(Element::text("Calendar:AllDayEvent", "1"))
                        .with(Element::text("Calendar:StartTime", "20261021T220000Z"))
                        .with(Element::text("Calendar:EndTime", "20261022T220000Z"))
                        .with(Element::text("Calendar:Subject", "Holiday")),
                ),
        )
        .with(
            // New Zealand in summer (UTC+13): bias -720, daylight bias -60.
            Element::new("AirSync:Add")
                .with(Element::text("AirSync:ClientId", "e2"))
                .with(
                    Element::new("AirSync:ApplicationData")
                        .with(Element::text("Calendar:TimeZone", {
                            let mut zone = [0u8; 172];
                            zone[..4].copy_from_slice(&(-720i32).to_le_bytes());
                            zone[168..].copy_from_slice(&(-60i32).to_le_bytes());
                            base64::engine::general_purpose::STANDARD.encode(zone)
                        }))
                        .with(Element::text("Calendar:AllDayEvent", "1"))
                        .with(Element::text("Calendar:StartTime", "20261021T110000Z"))
                        .with(Element::text("Calendar:EndTime", "20261022T110000Z"))
                        .with(Element::text("Calendar:Subject", "Kiwi")),
                ),
        );
    let synced = call(
        &state,
        "Sync",
        Some(&sync_request(&calendar, "1", Some(event), None)),
    )
    .await;
    assert_eq!(
        collection(&synced)
            .child("AirSync:Responses")
            .and_then(|r| r.child("AirSync:Add"))
            .and_then(|a| a.value("AirSync:Status"))
            .as_deref(),
        Some("1")
    );
    let cal = store::collections(&conn, Kind::Calendar)
        .unwrap()
        .into_iter()
        .find(|c| c.name == "default")
        .unwrap();
    let holiday = store::objects(&conn, &cal).unwrap();
    assert!(
        holiday
            .iter()
            .any(|o| o.data.contains("SUMMARY:Kiwi")
                && o.data.contains("DTSTART;VALUE=DATE:20261022")),
        "the date in the phone's zone"
    );
    assert!(
        holiday.iter().any(|o| o.data.contains("SUMMARY:Holiday")
            && o.data.contains("DTSTART;VALUE=DATE:20261022")),
        "{holiday:?}"
    );

    // An invitation shows as a meeting request and is answered from the phone.
    let invite = "From: org@remote.test\r\nTo: user@example.test\r\nSubject: Planning\r\nContent-Type: text/calendar; method=REQUEST; charset=utf-8\r\n\r\nBEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:plan-1\r\nDTSTAMP:20261001T000000Z\r\nDTSTART:20261030T100000Z\r\nDTEND:20261030T110000Z\r\nSUMMARY:Planning\r\nORGANIZER:mailto:org@remote.test\r\nATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:user@example.test\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    imap_state::deliver_message(&root, "example.test", "user", invite.as_bytes()).unwrap();
    call(&state, "Sync", Some(&sync_request(&inbox, "0", None, None))).await;
    let mail = call(&state, "Sync", Some(&sync_request(&inbox, "1", None, None))).await;
    let message = collection(&mail)
        .child("AirSync:Commands")
        .and_then(|c| c.child("AirSync:Add"))
        .unwrap();
    let data = message.child("AirSync:ApplicationData").unwrap();
    assert_eq!(
        data.value("Email:MessageClass").as_deref(),
        Some("IPM.Schedule.Meeting.Request")
    );
    let request = data.child("Email:MeetingRequest").expect("meeting request");
    assert_eq!(
        request.value("Email:StartTime").as_deref(),
        Some("2026-10-30T10:00:00.000Z")
    );
    let answer = Element::new("MeetingResponse:MeetingResponse").with(
        Element::new("MeetingResponse:Request")
            .with(Element::text("MeetingResponse:UserResponse", "1"))
            .with(Element::text("MeetingResponse:CollectionId", inbox.clone()))
            .with(Element::text(
                "MeetingResponse:RequestId",
                message.value("AirSync:ServerId").unwrap(),
            )),
    );
    let answered = call(&state, "MeetingResponse", Some(&answer)).await;
    let result = answered.child("MeetingResponse:Result").unwrap();
    assert_eq!(result.value("MeetingResponse:Status").as_deref(), Some("1"));
    assert!(result.value("MeetingResponse:CalendarId").is_some());
    let (_, accepted) = store::find_by_uid(&conn, "plan-1")
        .unwrap()
        .expect("in the calendar");
    assert!(
        accepted.data.contains("PARTSTAT=ACCEPTED"),
        "{}",
        accepted.data
    );
}
