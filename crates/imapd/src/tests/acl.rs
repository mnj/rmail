//! Shared mailboxes: RFC 4314 ACL commands and the rights they grant.

use super::*;

const OWNER: &str = "owner@example.test";
const FRIEND: &str = "friend@example.test";
const SHARED: &str = "\"Other Users/owner@example.test/Projects\"";

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
    rmail_common::imap_state::create_folder(&mail_root, "example.test", "owner", "Projects")
        .unwrap();
    rmail_common::imap_state::append_message(
        &mail_root,
        "example.test",
        "owner",
        "Projects",
        b"Subject: plan\r\n\r\nthe plan\r\n",
        Vec::new(),
    )
    .unwrap();
    Server {
        _dir: dir,
        mail_root,
        db_path,
    }
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
        assert!(reply.starts_with("OK [CAPABILITY"), "{reply}");
        client
    }

    /// Send a command and return its responses, ending with the tagged
    /// status (tag stripped), e.g. `"... \r\nNO [NOPERM]"`.
    async fn run(&mut self, command: &str) -> String {
        self.next += 1;
        let tag = format!("T{}", self.next);
        self.reader
            .get_mut()
            .write_all(format!("{tag} {command}\r\n").as_bytes())
            .await
            .unwrap();
        let lines = read_until_contains_bounded(&mut self.reader, &format!("{tag} ")).await;
        let mut text = lines.concat();
        // Keep the status word and code of the tagged line only.
        let tagged = text.rfind(&format!("{tag} ")).unwrap();
        let status = text[tagged + tag.len() + 1..].trim_end().to_string();
        let status = match status.find(']') {
            Some(end) if status.contains('[') => status[..=end].to_string(),
            _ => status.split(' ').next().unwrap().to_string(),
        };
        text.truncate(tagged);
        format!("{text}{status}")
    }
}

#[tokio::test]
async fn owner_shares_a_mailbox_and_rights_limit_what_the_grantee_can_do() {
    let server = server();
    let mut owner = Client::login(&server, OWNER).await;
    let mut friend = Client::login(&server, FRIEND).await;

    // Nothing is shared yet: the mailbox is invisible.
    let listed = friend.run("LIST \"\" \"*\"").await;
    assert!(!listed.contains("Other Users"), "{listed}");
    assert!(
        friend
            .run(&format!("SELECT {SHARED}"))
            .await
            .ends_with("NO [NONEXISTENT]")
    );
    // Names of accounts that shared nothing never reach storage, not even
    // for a refused APPEND whose literal is already on its way.
    let refused = friend
        .run("APPEND \"Other Users/ghost@example.test/X\" {2+}\r\nhi")
        .await;
    assert!(refused.ends_with("NO [TRYCREATE]"), "{refused}");
    assert!(!server.mail_root.join("example.test/ghost").exists());

    assert_eq!(
        owner.run(&format!("SETACL Projects {FRIEND} lr")).await,
        "OK"
    );
    assert_eq!(
        owner.run("GETACL Projects").await,
        format!("* ACL \"Projects\" {OWNER} lrswipkxteacd {FRIEND} lr\r\nOK")
    );
    assert!(
        owner
            .run("SETACL Projects anyone lr")
            .await
            .ends_with("NO [CANNOT]")
    );
    assert!(
        owner
            .run(&format!("SETACL Projects {OWNER} lr"))
            .await
            .ends_with("NO [CANNOT]")
    );
    assert!(
        owner
            .run(&format!("SETACL Projects {FRIEND} lrz"))
            .await
            .ends_with("BAD")
    );

    // Read-only access.
    let listed = friend.run("LIST \"\" \"*\"").await;
    assert!(
        listed.contains("* LIST (\\Noselect \\HasChildren) \"/\" \"Other Users\""),
        "{listed}"
    );
    assert!(
        listed.contains("\"/\" \"Other Users/owner@example.test\"\r\n"),
        "{listed}"
    );
    assert!(listed.contains(&format!("\"/\" {SHARED}")), "{listed}");
    assert!(!listed.contains("owner@example.test/INBOX"), "{listed}");
    assert_eq!(
        friend.run(&format!("MYRIGHTS {SHARED}")).await,
        format!("* MYRIGHTS {SHARED} lr\r\nOK")
    );
    let status = friend.run(&format!("STATUS {SHARED} (MESSAGES)")).await;
    assert!(
        status.contains(&format!("* STATUS {SHARED} (MESSAGES 1)")),
        "{status}"
    );
    let selected = friend.run(&format!("SELECT {SHARED}")).await;
    assert!(selected.contains("* 1 EXISTS"), "{selected}");
    assert!(selected.ends_with("OK [READ-ONLY]"), "{selected}");
    let fetched = friend.run("FETCH 1 (BODY[TEXT] FLAGS)").await;
    assert!(fetched.contains("the plan"), "{fetched}");
    assert!(
        friend
            .run("STORE 1 +FLAGS (\\Seen)")
            .await
            .starts_with("NO")
    );
    // Copying out needs only read access; copying in needs `i`.
    assert!(friend.run("COPY 1 INBOX").await.starts_with("OK [COPYUID"));
    assert!(
        friend
            .run(&format!("APPEND {SHARED} {{2+}}\r\nhi"))
            .await
            .ends_with("NO [NOPERM]")
    );
    assert!(
        friend
            .run(&format!("GETACL {SHARED}"))
            .await
            .ends_with("NO [NOPERM]")
    );
    assert!(
        friend
            .run("STATUS \"Other Users/owner@example.test/INBOX\" (MESSAGES)")
            .await
            .ends_with("NO [NONEXISTENT]")
    );
    assert!(
        friend
            .run("CREATE \"Other Users/owner@example.test/Projects/Sub\"")
            .await
            .ends_with("NO [NOPERM]")
    );
    assert!(
        friend
            .run("CREATE \"Other Users/mine\"")
            .await
            .ends_with("NO [CANNOT]")
    );
    let copied = friend.run("STATUS INBOX (MESSAGES)").await;
    assert!(copied.contains("MESSAGES 1"), "{copied}");

    // With s, i, t and e (no w): \Seen and \Deleted change, other flags
    // do not, and the mailbox opens read-write.
    assert_eq!(
        owner.run(&format!("SETACL Projects {FRIEND} +site")).await,
        "OK"
    );
    let selected = friend.run(&format!("SELECT {SHARED}")).await;
    assert!(
        selected.contains("PERMANENTFLAGS (\\Seen \\Deleted)"),
        "{selected}"
    );
    assert!(selected.ends_with("OK [READ-WRITE]"), "{selected}");
    let stored = friend.run("STORE 1 +FLAGS (\\Seen \\Flagged)").await;
    // System flag names are case-insensitive.
    assert!(
        stored.to_ascii_lowercase().contains("flags (\\seen)"),
        "{stored}"
    );
    // A STORE the rights allow none of fails rather than reporting success.
    assert!(
        friend
            .run("STORE 1 +FLAGS (\\Flagged)")
            .await
            .ends_with("NO [NOPERM]")
    );
    assert!(
        friend
            .run(&format!("APPEND {SHARED} (\\Flagged) {{5+}}\r\nhello"))
            .await
            .starts_with("OK [APPENDUID")
    );
    let moved = friend.run("MOVE 1 INBOX").await;
    assert!(moved.contains("* 1 EXPUNGE\r\nOK [COPYUID"), "{moved}");
    let owner_view = owner.run("STATUS Projects (MESSAGES UNSEEN)").await;
    assert!(owner_view.contains("MESSAGES 1 UNSEEN 1"), "{owner_view}");
    let fetched = owner.run("SELECT Projects").await;
    assert!(fetched.contains("* 1 EXISTS"), "{fetched}");
    let flags = owner.run("FETCH 1 FLAGS").await;
    assert!(flags.contains("FLAGS ()"), "{flags}");

    // Removing the grant hides the mailbox again.
    assert_eq!(
        owner.run(&format!("DELETEACL Projects {FRIEND}")).await,
        "OK"
    );
    let listed = friend.run("LIST \"\" \"*\"").await;
    assert!(!listed.contains("Other Users"), "{listed}");
    assert!(
        friend
            .run(&format!("STATUS {SHARED} (MESSAGES)"))
            .await
            .ends_with("NO [NONEXISTENT]")
    );
}

#[tokio::test]
async fn grants_follow_renames_and_children_inherit_them() {
    let server = server();
    let mut owner = Client::login(&server, OWNER).await;
    let mut friend = Client::login(&server, FRIEND).await;
    assert_eq!(
        owner.run(&format!("SETACL Projects {FRIEND} lrkx")).await,
        "OK"
    );
    // `k` on the parent lets the grantee create a child, which gets the
    // parent's grants.
    assert!(
        friend
            .run("CREATE \"Other Users/owner@example.test/Projects/Q1\"")
            .await
            .starts_with("OK")
    );
    assert_eq!(
        owner.run("MYRIGHTS Projects/Q1").await,
        "* MYRIGHTS \"Projects/Q1\" lrswipkxteacd\r\nOK"
    );
    let acl = owner.run("GETACL Projects/Q1").await;
    assert!(acl.contains(&format!("{FRIEND} lrkxcd")), "{acl}");
    // A rename keeps the grant; a new mailbox under the old name has none.
    assert_eq!(owner.run("RENAME Projects Plans").await, "OK");
    assert!(
        owner
            .run("CREATE Projects")
            .await
            .starts_with("OK [MAILBOXID")
    );
    let listed = friend.run("LIST \"\" \"Other Users/*\"").await;
    assert!(listed.contains("owner@example.test/Plans\""), "{listed}");
    assert!(listed.contains("owner@example.test/Plans/Q1\""), "{listed}");
    assert!(!listed.contains("owner@example.test/Projects"), "{listed}");
    // RENAME stays within one account; `x` allows DELETE.
    assert!(
        friend
            .run("RENAME \"Other Users/owner@example.test/Plans/Q1\" Mine")
            .await
            .ends_with("NO [CANNOT]")
    );
    assert_eq!(
        friend
            .run("DELETE \"Other Users/owner@example.test/Plans/Q1\"")
            .await,
        "OK"
    );
    assert!(
        owner
            .run("STATUS Plans/Q1 (MESSAGES)")
            .await
            .ends_with("NO [NONEXISTENT]")
    );
}
