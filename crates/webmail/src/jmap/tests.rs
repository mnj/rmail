//! End-to-end JMAP tests over the HTTP router.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, header};
use base64::Engine;
use rmail_common::http::Peer;
use rmail_common::throttle::AuthThrottle;
use rmail_common::{acl, db, imap_state, websession};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::account_id;
use crate::api::{AppState, router};

const USER: &str = "user@example.test";
const FRIEND: &str = "friend@example.test";
const USING: &[&str] = &[super::CORE, super::MAIL, super::SUBMISSION];

fn state(td: &tempfile::TempDir, submission: Option<std::net::SocketAddr>) -> Arc<AppState> {
    let db_path = td.path().join("accounts.sqlite");
    db::init_db(&db_path).unwrap();
    for address in [USER, FRIEND] {
        db::add_mailbox(&db_path, address, Some("plain:secret"), None, None).unwrap();
    }
    let mail_root = td.path().join("mail");
    for local in ["user", "friend"] {
        imap_state::init_account(&mail_root, "example.test", local).unwrap();
    }
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

fn basic(address: &str, password: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{address}:{password}"))
    )
}

async fn send(
    state: &Arc<AppState>,
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: Vec<u8>,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "mail.example.test");
    if let Some(auth) = auth {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    let mut request = builder.body(Body::from(body)).unwrap();
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
        .unwrap()
        .to_vec();
    (status, headers, body)
}

/// A JMAP client for one user.
struct Client {
    state: Arc<AppState>,
    auth: String,
}

impl Client {
    fn new(state: &Arc<AppState>, address: &str) -> Self {
        Self {
            state: state.clone(),
            auth: basic(address, "secret"),
        }
    }

    /// Run method calls; returns the methodResponses.
    async fn call(&self, calls: Value) -> Vec<Value> {
        // Submission is only a known capability when sending is set up.
        let using = USING
            .iter()
            .filter(|capability| {
                self.state.submission.is_some() || **capability != super::SUBMISSION
            })
            .collect::<Vec<_>>();
        let request = json!({"using": using, "methodCalls": calls});
        let (status, _, body) = send(
            &self.state,
            "POST",
            "/jmap/api/",
            Some(&self.auth),
            request.to_string().into_bytes(),
        )
        .await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        let response: Value = serde_json::from_slice(&body).unwrap();
        response["methodResponses"].as_array().unwrap().clone()
    }

    /// One method call; returns its arguments, asserting the name.
    async fn one(&self, name: &str, args: Value) -> Value {
        let responses = self.call(json!([[name, args, "c1"]])).await;
        assert_eq!(responses[0][0], name, "{responses:?}");
        responses[0][1].clone()
    }

    async fn mailbox_id(&self, account: &str, role_or_name: &str) -> String {
        let mailboxes = self.one("Mailbox/get", json!({"accountId": account})).await;
        mailboxes["list"]
            .as_array()
            .unwrap()
            .iter()
            .find(|mailbox| mailbox["role"] == role_or_name || mailbox["name"] == role_or_name)
            .unwrap_or_else(|| panic!("no mailbox {role_or_name}: {mailboxes}"))["id"]
            .as_str()
            .unwrap()
            .to_string()
    }
}

fn deliver(state: &AppState, local: &str, folder: &str, message: &str) {
    imap_state::append_message(
        &state.mail_root,
        "example.test",
        local,
        folder,
        message.as_bytes(),
        Vec::new(),
    )
    .unwrap();
}

#[tokio::test]
async fn session_needs_credentials_and_describes_the_accounts() {
    let td = tempfile::tempdir().unwrap();
    let state = state(&td, None);
    let (status, headers, _) = send(&state, "GET", "/.well-known/jmap", None, Vec::new()).await;
    assert_eq!(status, 401);
    assert!(
        headers
            .iter()
            .any(|(name, value)| name == "www-authenticate" && value.starts_with("Basic"))
    );
    let wrong = basic(USER, "nope");
    let (status, _, _) = send(&state, "GET", "/jmap/session", Some(&wrong), Vec::new()).await;
    assert_eq!(status, 401);

    let auth = basic(USER, "secret");
    let (status, _, body) = send(&state, "GET", "/.well-known/jmap", Some(&auth), Vec::new()).await;
    assert_eq!(status, 200);
    let session: Value = serde_json::from_slice(&body).unwrap();
    let own = account_id(USER);
    assert_eq!(session["username"], USER);
    assert_eq!(session["primaryAccounts"][super::MAIL], own);
    assert_eq!(session["accounts"][&own]["isPersonal"], true);
    assert_eq!(session["apiUrl"], "http://mail.example.test/jmap/api/");
    assert!(session["capabilities"][super::CORE]["maxObjectsInGet"].is_u64());
    // Sending is off, so submission is not offered.
    assert!(session["capabilities"].get(super::SUBMISSION).is_none());
}

#[tokio::test]
async fn request_errors_follow_rfc_8620() {
    let td = tempfile::tempdir().unwrap();
    let state = state(&td, None);
    let auth = basic(USER, "secret");
    let (status, _, body) = send(
        &state,
        "POST",
        "/jmap/api",
        Some(&auth),
        b"not json".to_vec(),
    )
    .await;
    assert_eq!(status, 400);
    assert!(String::from_utf8_lossy(&body).contains("notJSON"));
    let request = json!({"using": ["urn:example:nope"], "methodCalls": []});
    let (status, _, body) = send(
        &state,
        "POST",
        "/jmap/api",
        Some(&auth),
        request.to_string().into_bytes(),
    )
    .await;
    assert_eq!(status, 400);
    assert!(String::from_utf8_lossy(&body).contains("unknownCapability"));

    let client = Client::new(&state, USER);
    let responses = client
        .call(json!([
            ["Nope/get", {}, "a"],
            ["Email/get", {"#ids": {"resultOf": "x", "name": "Email/query", "path": "/ids"}}, "b"],
            ["Email/changes", {"sinceState": "999999"}, "c"],
            ["Email/queryChanges", {"sinceQueryState": "1"}, "d"],
            ["Mailbox/get", {"accountId": "a00"}, "e"],
            ["Core/echo", {"hello": true}, "f"],
        ]))
        .await;
    let kinds = responses
        .iter()
        .map(|response| response[1]["type"].as_str().unwrap_or("").to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        kinds[..5],
        [
            "unknownMethod",
            "invalidResultReference",
            "cannotCalculateChanges",
            "cannotCalculateChanges",
            "accountNotFound"
        ]
    );
    assert_eq!(responses[5], json!(["Core/echo", {"hello": true}, "f"]));
}

#[tokio::test]
async fn mail_round_trip() {
    let td = tempfile::tempdir().unwrap();
    let state = state(&td, None);
    let client = Client::new(&state, USER);
    let own = account_id(USER);

    let mailboxes = client.one("Mailbox/get", json!({})).await;
    let roles = mailboxes["list"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|mailbox| mailbox["role"].as_str())
        .collect::<Vec<_>>();
    assert!(
        roles.contains(&"inbox") && roles.contains(&"sent") && roles.contains(&"drafts"),
        "{roles:?}"
    );
    let start = mailboxes["state"].as_str().unwrap().to_string();
    let inbox = client.mailbox_id(&own, "inbox").await;
    let drafts = client.mailbox_id(&own, "drafts").await;

    // A new mailbox, created and used in the same request.
    let responses = client
        .call(json!([
            ["Mailbox/set", {"create": {"p": {"name": "Projects", "parentId": null}}}, "0"],
            ["Mailbox/get", {"ids": ["#p"], "properties": ["name", "myRights"]}, "1"],
        ]))
        .await;
    let projects = responses[0][1]["created"]["p"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(responses[1][1]["list"][0]["name"], "Projects");
    assert_eq!(responses[1][1]["list"][0]["myRights"]["mayDelete"], true);

    // Mail arrives by delivery, not through JMAP.
    deliver(
        &state,
        "user",
        "INBOX",
        "From: Alice <alice@x.test>\r\nTo: user@example.test\r\nSubject: The plan\r\nMessage-ID: <plan@x.test>\r\nDate: Thu, 30 Oct 2014 14:12:00 +0000\r\n\r\nHere is the plan.\r\n",
    );
    let changed = client
        .one("Email/changes", json!({"sinceState": start}))
        .await;
    assert_eq!(changed["created"].as_array().unwrap().len(), 1);
    let delivered = changed["created"][0].as_str().unwrap().to_string();
    let mailbox_changes = client
        .one("Mailbox/changes", json!({"sinceState": start}))
        .await;
    assert!(
        mailbox_changes["created"]
            .as_array()
            .unwrap()
            .contains(&json!(projects))
    );

    // Query with a back-reference into Email/get.
    let responses = client
        .call(json!([
            ["Email/query", {"filter": {"inMailbox": inbox, "text": "plan"}, "sort": [{"property": "receivedAt", "isAscending": false}], "calculateTotal": true}, "q"],
            ["Email/get", {"#ids": {"resultOf": "q", "name": "Email/query", "path": "/ids"}, "properties": ["subject", "from", "preview", "threadId", "mailboxIds", "keywords", "textBody", "bodyValues"], "fetchTextBodyValues": true, "bodyProperties": ["partId", "type"]}, "g"],
            ["Thread/get", {"#ids": {"resultOf": "g", "name": "Email/get", "path": "/list/*/threadId"}}, "t"],
            ["SearchSnippet/get", {"filter": {"text": "plan"}, "#emailIds": {"resultOf": "q", "name": "Email/query", "path": "/ids"}}, "s"],
        ]))
        .await;
    assert_eq!(responses[0][1]["ids"], json!([delivered]));
    assert_eq!(responses[0][1]["total"], 1);
    let email = &responses[1][1]["list"][0];
    assert_eq!(email["subject"], "The plan");
    assert_eq!(
        email["from"],
        json!([{"name": "Alice", "email": "alice@x.test"}])
    );
    assert_eq!(email["preview"], "Here is the plan.");
    assert_eq!(email["keywords"], json!({}));
    assert_eq!(
        email["textBody"],
        json!([{"partId": "1", "type": "text/plain"}])
    );
    assert_eq!(email["bodyValues"]["1"]["value"], "Here is the plan.\n");
    assert_eq!(responses[2][1]["list"][0]["emailIds"], json!([delivered]));
    assert_eq!(
        responses[3][1]["list"][0]["subject"],
        "The <mark>plan</mark>"
    );

    // Read it and file it: keywords and mailbox membership.
    let before = client.one("Email/get", json!({"ids": []})).await["state"]
        .as_str()
        .unwrap()
        .to_string();
    let updated = client
        .one(
            "Email/set",
            json!({"update": {delivered.clone(): {"keywords/$seen": true, "mailboxIds": {projects.clone(): true}}}}),
        )
        .await;
    assert!(updated["updated"].get(&delivered).is_some(), "{updated}");
    let email = client
        .one(
            "Email/get",
            json!({"ids": [delivered], "properties": ["keywords", "mailboxIds"]}),
        )
        .await;
    assert_eq!(email["list"][0]["keywords"], json!({"$seen": true}));
    assert_eq!(
        email["list"][0]["mailboxIds"],
        json!({projects.clone(): true})
    );
    let changed = client
        .one("Email/changes", json!({"sinceState": before}))
        .await;
    assert_eq!(changed["updated"], json!([delivered]));
    let counts = client
        .one("Mailbox/changes", json!({"sinceState": before}))
        .await;
    assert_eq!(
        counts["updatedProperties"],
        json!([
            "totalEmails",
            "unreadEmails",
            "totalThreads",
            "unreadThreads"
        ])
    );

    // A draft with an uploaded attachment.
    let (status, _, body) = send(
        &state,
        "POST",
        &format!("/jmap/upload/{own}/"),
        Some(&client.auth),
        b"%PDF-1.4 tiny".to_vec(),
    )
    .await;
    assert_eq!(status, 201);
    let blob: Value = serde_json::from_slice(&body).unwrap();
    let created = client
        .one(
            "Email/set",
            json!({"create": {"d": {
                "mailboxIds": {drafts.clone(): true},
                "keywords": {"$draft": true},
                "from": [{"name": "User", "email": USER}],
                "to": [{"name": "Jørgen", "email": "j@x.test"}],
                "subject": "Re: The plan ✓",
                "inReplyTo": ["plan@x.test"],
                "references": ["plan@x.test"],
                "bodyValues": {"t": {"value": "Looks good.\n"}, "h": {"value": "<p>Looks good.</p>"}},
                "textBody": [{"partId": "t", "type": "text/plain"}],
                "htmlBody": [{"partId": "h", "type": "text/html"}],
                "attachments": [{"blobId": blob["blobId"], "type": "application/pdf", "name": "plan.pdf"}],
            }}}),
        )
        .await;
    let draft = &created["created"]["d"];
    let draft_id = draft["id"].as_str().expect("draft created").to_string();
    // The reply joins the original's thread.
    let original = client
        .one(
            "Email/get",
            json!({"ids": [delivered], "properties": ["threadId"]}),
        )
        .await;
    assert_eq!(draft["threadId"], original["list"][0]["threadId"]);
    let fetched = client
        .one(
            "Email/get",
            json!({"ids": [draft_id], "properties": ["subject", "to", "hasAttachment", "attachments", "htmlBody", "bodyValues", "keywords"], "fetchHTMLBodyValues": true}),
        )
        .await;
    let fetched = &fetched["list"][0];
    assert_eq!(fetched["subject"], "Re: The plan ✓");
    assert_eq!(fetched["to"][0]["name"], "Jørgen");
    assert_eq!(fetched["hasAttachment"], true);
    assert_eq!(fetched["keywords"], json!({"$draft": true}));
    assert_eq!(fetched["attachments"][0]["name"], "plan.pdf");
    let html_part = fetched["htmlBody"][0]["partId"].as_str().unwrap();
    assert_eq!(
        fetched["bodyValues"][html_part]["value"],
        "<p>Looks good.</p>\n"
    );
    let attachment_blob = fetched["attachments"][0]["blobId"].as_str().unwrap();
    let (status, headers, body) = send(
        &state,
        "GET",
        &format!("/jmap/download/{own}/{attachment_blob}/plan.pdf?accept=application/pdf"),
        Some(&client.auth),
        Vec::new(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, b"%PDF-1.4 tiny");
    assert!(
        headers
            .iter()
            .any(|(name, value)| name == "content-type" && value == "application/pdf")
    );

    // Destroying removes every copy.
    let before = client.one("Email/get", json!({"ids": []})).await["state"]
        .as_str()
        .unwrap()
        .to_string();
    let destroyed = client
        .one("Email/set", json!({"destroy": [draft_id]}))
        .await;
    assert_eq!(destroyed["destroyed"], json!([draft_id]));
    let changed = client
        .one("Email/changes", json!({"sinceState": before}))
        .await;
    assert_eq!(changed["destroyed"], json!([draft_id]));
    let gone = client.one("Email/get", json!({"ids": [draft_id]})).await;
    assert_eq!(gone["notFound"], json!([draft_id]));

    // A non-empty mailbox is only destroyed when asked to remove its mail.
    let refused = client
        .one("Mailbox/set", json!({"destroy": [projects]}))
        .await;
    assert_eq!(
        refused["notDestroyed"][&projects]["type"],
        "mailboxHasEmail"
    );
    let removed = client
        .one(
            "Mailbox/set",
            json!({"destroy": [projects], "onDestroyRemoveEmails": true}),
        )
        .await;
    assert_eq!(removed["destroyed"], json!([projects]));
}

#[tokio::test]
async fn shared_mailboxes_are_a_separate_account_within_the_grants() {
    let td = tempfile::tempdir().unwrap();
    let state = state(&td, None);
    imap_state::create_folder(&state.mail_root, "example.test", "friend", "Team").unwrap();
    deliver(
        &state,
        "friend",
        "Team",
        "Subject: team news\r\n\r\nNews.\r\n",
    );
    deliver(
        &state,
        "friend",
        "INBOX",
        "Subject: private\r\n\r\nSecret.\r\n",
    );
    let team = imap_state::find_folder(&state.mail_root, "example.test", "friend", "Team")
        .unwrap()
        .unwrap();
    acl::set_rights(
        &state.db_path,
        FRIEND,
        &team.mailbox_id,
        USER,
        acl::Rights::parse("lr").unwrap(),
    )
    .unwrap();

    let auth = basic(USER, "secret");
    let (_, _, body) = send(&state, "GET", "/jmap/session", Some(&auth), Vec::new()).await;
    let session: Value = serde_json::from_slice(&body).unwrap();
    let shared = account_id(FRIEND);
    assert_eq!(session["accounts"][&shared]["isPersonal"], false);
    assert_eq!(session["accounts"][&shared]["isReadOnly"], true);
    assert_eq!(session["accounts"][&shared]["name"], FRIEND);

    let client = Client::new(&state, USER);
    let mailboxes = client
        .one("Mailbox/get", json!({"accountId": shared}))
        .await;
    let list = mailboxes["list"].as_array().unwrap();
    assert_eq!(list.len(), 1, "{mailboxes}");
    assert_eq!(list[0]["name"], "Team");
    assert_eq!(list[0]["myRights"]["mayReadItems"], true);
    assert_eq!(list[0]["myRights"]["maySetSeen"], false);

    let all = client
        .one("Email/query", json!({"accountId": shared}))
        .await;
    let ids = all["ids"].as_array().unwrap().clone();
    assert_eq!(ids.len(), 1, "only the shared mailbox's mail: {all}");
    let email = client
        .one(
            "Email/get",
            json!({"accountId": shared, "ids": ids, "properties": ["subject"]}),
        )
        .await;
    assert_eq!(email["list"][0]["subject"], "team news");

    // Read-only: keywords and new mailboxes are refused.
    let refused = client
        .one("Email/set", json!({"accountId": shared, "update": {ids[0].as_str().unwrap(): {"keywords/$seen": true}}}))
        .await;
    assert_eq!(
        refused["notUpdated"][ids[0].as_str().unwrap()]["type"],
        "forbidden"
    );
    let refused = client
        .one("Mailbox/set", json!({"accountId": shared, "create": {"x": {"name": "Mine", "parentId": team.mailbox_id}}}))
        .await;
    assert_eq!(refused["notCreated"]["x"]["type"], "forbidden");
    // The owner's other mail stays invisible, even by id.
    let owner_inbox = imap_state::load_folder(&state.mail_root, "example.test", "friend", "INBOX")
        .unwrap()
        .1;
    let private = owner_inbox[0].email_id.clone();
    let hidden = client
        .one("Email/get", json!({"accountId": shared, "ids": [private]}))
        .await;
    assert_eq!(hidden["notFound"], json!([private]));

    // Copying a shared email into the user's own account.
    let own = account_id(USER);
    let inbox = client.mailbox_id(&own, "inbox").await;
    let copied = client
        .one(
            "Email/copy",
            json!({"fromAccountId": shared, "accountId": own, "create": {"c": {"id": ids[0], "mailboxIds": {inbox: true}}}}),
        )
        .await;
    assert!(copied["created"]["c"]["id"].is_string(), "{copied}");
}

/// A submission service that accepts everything and reports what it got.
async fn fake_submission(
    mail_root: std::path::PathBuf,
) -> (
    std::net::SocketAddr,
    tokio::sync::mpsc::UnboundedReceiver<(Vec<String>, String)>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (read, mut write) = stream.into_split();
            let mut lines = BufReader::new(read).lines();
            write.write_all(b"220 test\r\n").await.unwrap();
            let mut envelope = Vec::new();
            let mut data = String::new();
            let mut in_data = false;
            while let Ok(Some(line)) = lines.next_line().await {
                if in_data {
                    if line == "." {
                        in_data = false;
                        write.write_all(b"250 queued\r\n").await.unwrap();
                    } else {
                        data.push_str(&line);
                        data.push('\n');
                    }
                    continue;
                }
                let reply: &[u8] = if line.starts_with("EHLO") {
                    b"250 test\r\n"
                } else if let Some(token) = line.strip_prefix("AUTH X-RMAIL-WEBMAIL ") {
                    let decoded = base64::engine::general_purpose::STANDARD
                        .decode(token)
                        .unwrap();
                    let key = rmail_common::runtime::webmail_submission_key(&mail_root).unwrap();
                    if decoded == format!("{USER}\0{key}").into_bytes() {
                        b"235 ok\r\n"
                    } else {
                        b"535 no\r\n"
                    }
                } else if line.starts_with("MAIL FROM:") || line.starts_with("RCPT TO:") {
                    envelope.push(line.clone());
                    b"250 ok\r\n"
                } else if line == "DATA" {
                    in_data = true;
                    b"354 go\r\n"
                } else if line == "QUIT" {
                    write.write_all(b"221 bye\r\n").await.unwrap();
                    break;
                } else {
                    b"250 ok\r\n"
                };
                write.write_all(reply).await.unwrap();
            }
            if !data.is_empty() {
                tx.send((envelope, data)).unwrap();
            }
        }
    });
    (address, rx)
}

#[tokio::test(flavor = "multi_thread")]
async fn submission_sends_the_draft_and_files_it_as_sent() {
    let td = tempfile::tempdir().unwrap();
    let mail_root = td.path().join("mail");
    std::fs::create_dir_all(&mail_root).unwrap();
    let (address, mut received) = fake_submission(mail_root).await;
    let state = state(&td, Some(address));
    let client = Client::new(&state, USER);
    let own = account_id(USER);
    let drafts = client.mailbox_id(&own, "drafts").await;
    let sent = client.mailbox_id(&own, "sent").await;
    let identities = client.one("Identity/get", json!({})).await;
    let identity = identities["list"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(identities["list"][0]["email"], USER);

    let responses = client
        .call(json!([
            ["Email/set", {"create": {"draft": {
                "mailboxIds": {drafts.clone(): true},
                "keywords": {"$draft": true, "$seen": true},
                "from": [{"email": USER}],
                "to": [{"email": "to@x.test"}],
                "bcc": [{"email": "hidden@x.test"}],
                "subject": "Hello",
                "bodyValues": {"b": {"value": "Hi there"}},
                "textBody": [{"partId": "b"}],
            }}}, "0"],
            ["EmailSubmission/set", {
                "create": {"send": {"identityId": identity, "emailId": "#draft"}},
                "onSuccessUpdateEmail": {"#send": {
                    format!("mailboxIds/{drafts}"): null,
                    format!("mailboxIds/{sent}"): true,
                    "keywords/$draft": null,
                }},
            }, "1"],
        ]))
        .await;
    assert!(
        responses[1][1]["created"]["send"]["id"].is_string(),
        "{responses:?}"
    );
    assert_eq!(responses[2][0], "Email/set", "{responses:?}");
    let (envelope, data) = received.recv().await.unwrap();
    assert_eq!(envelope[0], format!("MAIL FROM:<{USER}>"));
    assert!(envelope.contains(&"RCPT TO:<to@x.test>".to_string()));
    assert!(envelope.contains(&"RCPT TO:<hidden@x.test>".to_string()));
    assert!(!data.to_ascii_lowercase().contains("bcc:"), "{data}");
    assert!(data.contains("Hi there"));

    let email_id = responses[0][1]["created"]["draft"]["id"].as_str().unwrap();
    let email = client
        .one(
            "Email/get",
            json!({"ids": [email_id], "properties": ["mailboxIds", "keywords"]}),
        )
        .await;
    assert_eq!(email["list"][0]["mailboxIds"], json!({sent: true}));
    assert_eq!(email["list"][0]["keywords"], json!({"$seen": true}));
    let submissions = client.one("EmailSubmission/get", json!({})).await;
    assert_eq!(submissions["list"][0]["undoStatus"], "final");

    // A From the identity does not own is refused.
    let responses = client
        .call(json!([
            ["Email/set", {"create": {"spoof": {
                "mailboxIds": {drafts: true},
                "from": [{"email": "boss@example.test"}],
                "to": [{"email": "to@x.test"}],
                "subject": "Pay this",
            }}}, "0"],
            ["EmailSubmission/set", {"create": {"s": {"identityId": identity, "emailId": "#spoof"}}}, "1"],
        ]))
        .await;
    assert_eq!(responses[1][1]["notCreated"]["s"]["type"], "forbiddenFrom");
}
