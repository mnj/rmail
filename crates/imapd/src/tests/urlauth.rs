//! URLAUTH (RFC 4467): GENURLAUTH, URLFETCH and RESETKEY, and the URLs
//! they refuse.

use super::*;

const OWNER: &str = "owner@example.test";
const FRIEND: &str = "friend@example.test";
const MESSAGE: &[u8] = b"Subject: draft\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhello\r\n--b--\r\n";

struct Server {
    _dir: tempfile::TempDir,
    mail_root: std::path::PathBuf,
    db_path: std::path::PathBuf,
}

fn server() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let mail_root = dir.path().join("mail");
    let db_path = dir.path().join("config.db");
    rmail_common::db::init_db(&db_path).unwrap();
    for address in [OWNER, FRIEND] {
        rmail_common::db::add_mailbox(&db_path, address, Some("plain:password"), None, None)
            .unwrap();
    }
    for mailbox in ["Drafts", "Projects"] {
        if mailbox != "Drafts" {
            rmail_common::imap_state::create_folder(&mail_root, "example.test", "owner", mailbox)
                .unwrap();
        }
        rmail_common::imap_state::append_message(
            &mail_root,
            "example.test",
            "owner",
            mailbox,
            MESSAGE,
            Vec::new(),
        )
        .unwrap();
    }
    Server {
        _dir: dir,
        mail_root,
        db_path,
    }
}

fn uidvalidity(server: &Server, mailbox: &str) -> u64 {
    rmail_common::imap_state::find_folder(&server.mail_root, "example.test", "owner", mailbox)
        .unwrap()
        .unwrap()
        .uidvalidity
}

/// A rump for `user`'s view of `path` on this server.
fn rump(user: &str, path: &str) -> String {
    format!(
        "imap://{}@{}/{path}",
        user.replace('@', "%40"),
        rmail_common::config::system_hostname()
    )
}

struct Client {
    reader: BufReader<tokio::io::DuplexStream>,
    next: usize,
}

impl Client {
    async fn login(server: &Server, address: &str) -> Self {
        let (client, stream) = duplex(128 * 1024);
        let mail_root = server.mail_root.to_string_lossy().to_string();
        let db_path = server.db_path.to_string_lossy().to_string();
        tokio::spawn(async move {
            let _ = process_stream(
                Box::new(stream),
                mail_root,
                None::<Arc<crate::tls::TlsContext>>,
                Some(db_path),
                None,
                true,
            )
            .await;
        });
        let mut client = Self {
            reader: BufReader::new(client),
            next: 0,
        };
        read_until_contains_bounded(&mut client.reader, "* CAPABILITY").await;
        let reply = client.run(&format!("LOGIN {address} password")).await;
        assert!(reply.contains("URLAUTH"), "{reply}");
        client
    }

    /// Send a command and return everything up to and including the
    /// tagged status line.
    async fn run(&mut self, command: &str) -> String {
        self.next += 1;
        let tag = format!("T{}", self.next);
        self.reader
            .get_mut()
            .write_all(format!("{tag} {command}\r\n").as_bytes())
            .await
            .unwrap();
        read_until_contains_bounded(&mut self.reader, &format!("{tag} "))
            .await
            .concat()
    }

    /// GENURLAUTH for one rump; the authorized URL, or the failed reply.
    async fn authorize(&mut self, rump: &str) -> Result<String, String> {
        let reply = self.run(&format!("GENURLAUTH \"{rump}\" INTERNAL")).await;
        let Some(start) = reply.find("* GENURLAUTH \"") else {
            return Err(reply);
        };
        let rest = &reply[start + "* GENURLAUTH \"".len()..];
        Ok(rest[..rest.find('"').unwrap()].to_string())
    }

    /// URLFETCH for one URL: the content, or `None` for NIL.
    async fn fetch(&mut self, url: &str) -> Option<String> {
        let reply = self.run(&format!("URLFETCH \"{url}\"")).await;
        assert!(reply.contains(&format!("* URLFETCH \"{url}\" ")), "{reply}");
        assert!(reply.contains("OK URLFETCH completed"), "{reply}");
        let line = &reply[reply.find("* URLFETCH").unwrap()..];
        if line.contains("\" NIL\r\n") {
            return None;
        }
        let open = line.find('{').unwrap();
        let close = line.find("}\r\n").unwrap();
        let size: usize = line[open + 1..close].parse().unwrap();
        Some(line[close + 3..close + 3 + size].to_string())
    }
}

#[tokio::test]
async fn generated_urls_fetch_the_message_its_parts_and_nothing_else() {
    let server = server();
    let mut owner = Client::login(&server, OWNER).await;
    let validity = uidvalidity(&server, "Drafts");

    let selected = owner.run("EXAMINE Drafts").await;
    assert!(selected.contains("* OK [URLMECH INTERNAL]"), "{selected}");

    let url = owner
        .authorize(&rump(
            OWNER,
            &format!("Drafts;UIDVALIDITY={validity}/;UID=1;URLAUTH=user+owner%40example.test"),
        ))
        .await
        .unwrap();
    assert!(url.contains(";URLAUTH=user+owner%40example.test:INTERNAL:"));
    assert_eq!(
        owner.fetch(&url).await.as_deref(),
        Some(std::str::from_utf8(MESSAGE).unwrap())
    );

    let part = owner
        .authorize(&rump(
            OWNER,
            "Drafts/;UID=1/;SECTION=1/;PARTIAL=1.3;URLAUTH=authuser",
        ))
        .await
        .unwrap();
    assert_eq!(owner.fetch(&part).await.as_deref(), Some("ell"));

    // Any change to the signed rump or the token is refused.
    let token_at = url.rfind(':').unwrap() + 1;
    let mut flipped = url.clone();
    let last = if url.ends_with('0') { "1" } else { "0" };
    flipped.replace_range(url.len() - 1.., last);
    assert_eq!(owner.fetch(&flipped).await, None);
    assert_eq!(owner.fetch(&url.replace(";UID=1", ";UID=2")).await, None);
    assert_eq!(owner.fetch(&url.replace("Drafts", "DRAFTS")).await, None);
    assert_eq!(owner.fetch(&url[..token_at + 10]).await, None);
    assert_eq!(
        owner.fetch(&url.replace(":INTERNAL:", ":XSAMPLE:")).await,
        None
    );
    assert_eq!(owner.fetch("not a url").await, None);
    // The message is gone once expunged.
    rmail_common::imap_state::delete_message_by_uid(
        &server.mail_root,
        "example.test",
        "owner",
        "Drafts",
        1,
    )
    .unwrap();
    assert_eq!(owner.fetch(&url).await, None);
}

#[tokio::test]
async fn genurlauth_refuses_urls_it_must_not_sign() {
    let server = server();
    let mut owner = Client::login(&server, OWNER).await;
    let validity = uidvalidity(&server, "Drafts");
    let refused = [
        // Another user's namespace, another server, anonymous access.
        rump(FRIEND, "INBOX/;UID=1;URLAUTH=authuser"),
        "imap://owner%40example.test@elsewhere.example/Drafts/;UID=1;URLAUTH=authuser".to_string(),
        rump(OWNER, "Drafts/;UID=1;URLAUTH=anonymous"),
        // A userid that does not exist, a missing mailbox, a stale
        // UIDVALIDITY, an expiry in the past, and no access identifier.
        rump(OWNER, "Drafts/;UID=1;URLAUTH=submit+ghost%40example.test"),
        rump(OWNER, "Missing/;UID=1;URLAUTH=authuser"),
        rump(
            OWNER,
            &format!(
                "Drafts;UIDVALIDITY={}/;UID=1;URLAUTH=authuser",
                validity + 1
            ),
        ),
        rump(
            OWNER,
            "Drafts/;UID=1;EXPIRE=2001-01-01T00:00:00Z;URLAUTH=authuser",
        ),
        rump(OWNER, "Drafts/;UID=1"),
    ];
    for rump in refused {
        let reply = owner.authorize(&rump).await.unwrap_err();
        assert!(reply.contains("BAD GENURLAUTH refused"), "{rump}: {reply}");
    }
    let mechanism = owner
        .run(&format!(
            "GENURLAUTH \"{}\" XSAMPLE",
            rump(OWNER, "Drafts/;UID=1;URLAUTH=authuser")
        ))
        .await;
    assert!(mechanism.contains("BAD"), "{mechanism}");
    assert!(owner.run("GENURLAUTH").await.contains("BAD"));
    // Names of accounts that do not exist never reach storage.
    assert!(!server.mail_root.join("example.test/ghost").exists());
}

#[tokio::test]
async fn access_identifiers_decide_who_may_fetch() {
    let server = server();
    let mut owner = Client::login(&server, OWNER).await;
    let mut friend = Client::login(&server, FRIEND).await;

    let for_friend = owner
        .authorize(&rump(
            OWNER,
            "Drafts/;UID=1;URLAUTH=user+friend%40example.test",
        ))
        .await
        .unwrap();
    assert!(friend.fetch(&for_friend).await.is_some());
    assert_eq!(owner.fetch(&for_friend).await, None);

    let anyone = owner
        .authorize(&rump(OWNER, "Drafts/;UID=1;URLAUTH=authuser"))
        .await
        .unwrap();
    assert!(friend.fetch(&anyone).await.is_some());

    // submit+ URLs are only for the submission server.
    let submit = owner
        .authorize(&rump(
            OWNER,
            "Drafts/;UID=1;URLAUTH=submit+owner%40example.test",
        ))
        .await
        .unwrap();
    assert_eq!(owner.fetch(&submit).await, None);

    // Signed with the owner's key, a URL naming the friend's namespace is
    // not the friend's URL.
    let forged = for_friend.replacen("owner%40example.test@", "friend%40example.test@", 1);
    assert_eq!(friend.fetch(&forged).await, None);
}

#[tokio::test]
async fn resetkey_revokes_urls() {
    let server = server();
    let mut owner = Client::login(&server, OWNER).await;
    let drafts = rump(OWNER, "Drafts/;UID=1;URLAUTH=authuser");
    let projects = rump(OWNER, "Projects/;UID=1;URLAUTH=authuser");
    let first = owner.authorize(&drafts).await.unwrap();
    let other = owner.authorize(&projects).await.unwrap();
    // The key is stable until reset.
    assert_eq!(owner.authorize(&drafts).await.unwrap(), first);

    let reset = owner.run("RESETKEY Drafts INTERNAL").await;
    assert!(reset.contains("OK [URLMECH INTERNAL]"), "{reset}");
    assert_eq!(owner.fetch(&first).await, None);
    assert!(owner.fetch(&other).await.is_some());
    let second = owner.authorize(&drafts).await.unwrap();
    assert_ne!(second, first);
    assert!(owner.fetch(&second).await.is_some());

    assert!(
        owner
            .run("RESETKEY Missing")
            .await
            .contains("NO [NONEXISTENT]")
    );
    assert!(owner.run("RESETKEY Drafts XSAMPLE").await.contains("BAD"));
    assert!(owner.run("RESETKEY").await.contains("OK All keys removed"));
    assert_eq!(owner.fetch(&second).await, None);
    assert_eq!(owner.fetch(&other).await, None);
}

#[tokio::test]
async fn shared_mailbox_urls_follow_the_current_read_right() {
    let server = server();
    let mut owner = Client::login(&server, OWNER).await;
    let mut friend = Client::login(&server, FRIEND).await;
    let shared = rump(
        FRIEND,
        "Other%20Users/owner%40example.test/Projects/;UID=1;URLAUTH=authuser",
    );
    // Not shared yet: nothing to sign.
    assert!(friend.authorize(&shared).await.is_err());
    // Listing alone is not enough to read.
    assert!(
        owner
            .run("SETACL Projects friend@example.test l")
            .await
            .contains("OK")
    );
    assert!(friend.authorize(&shared).await.is_err());
    owner.run("SETACL Projects friend@example.test lr").await;
    let url = friend.authorize(&shared).await.unwrap();
    assert!(owner.fetch(&url).await.is_some());
    // Revoking the right revokes the URL, even for other users.
    owner.run("DELETEACL Projects friend@example.test").await;
    assert_eq!(owner.fetch(&url).await, None);
    assert_eq!(friend.fetch(&url).await, None);
}
