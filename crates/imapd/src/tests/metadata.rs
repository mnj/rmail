//! METADATA (RFC 5464): server and mailbox annotations.

use super::sync::authenticated_session;

#[tokio::test]
async fn server_and_mailbox_annotations_round_trip() {
    let mut session = authenticated_session(0).await;
    session
        .command(
            "S1 SETMETADATA \"\" (/shared/comment \"Server note\")",
            "S1 OK",
        )
        .await;
    session
        .command(
            "S2 SETMETADATA INBOX (/private/comment \"Mine\" /shared/comment \"Ours\")",
            "S2 OK",
        )
        .await;

    let server = session
        .command("G1 GETMETADATA \"\" /shared/comment", "G1 OK")
        .await;
    assert_eq!(
        server[0].trim_end(),
        "* METADATA \"\" (\"/shared/comment\" \"Server note\")"
    );

    let inbox = session
        .command(
            "G2 GETMETADATA INBOX (/private/comment /shared/comment /private/missing)",
            "G2 OK",
        )
        .await;
    assert_eq!(
        inbox[0].trim_end(),
        "* METADATA \"INBOX\" (\"/private/comment\" \"Mine\" \"/shared/comment\" \"Ours\" \"/private/missing\" NIL)"
    );

    // NIL removes an entry.
    session
        .command("S3 SETMETADATA INBOX (/private/comment NIL)", "S3 OK")
        .await;
    let removed = session
        .command("G3 GETMETADATA INBOX /private/comment", "G3 OK")
        .await;
    assert_eq!(
        removed[0].trim_end(),
        "* METADATA \"INBOX\" (\"/private/comment\" NIL)"
    );
    session.finish().await;
}

#[tokio::test]
async fn depth_maxsize_and_multi_line_values() {
    let mut session = authenticated_session(0).await;
    session
        .command(
            "S1 SETMETADATA INBOX (/private/vendor/a \"1\" /private/vendor/a/b \"22\" /private/vendor/a/b/c \"333\")",
            "S1 OK",
        )
        .await;

    let one = session
        .command("G1 GETMETADATA (DEPTH 1) INBOX /private/vendor/a", "G1 OK")
        .await;
    assert_eq!(
        one[0].trim_end(),
        "* METADATA \"INBOX\" (\"/private/vendor/a\" \"1\" \"/private/vendor/a/b\" \"22\")"
    );

    let limited = session
        .command(
            "G2 GETMETADATA (MAXSIZE 2 DEPTH infinity) INBOX /private/vendor",
            "G2 OK",
        )
        .await;
    assert_eq!(
        limited[0].trim_end(),
        "* METADATA \"INBOX\" (\"/private/vendor/a\" \"1\" \"/private/vendor/a/b\" \"22\")"
    );
    assert_eq!(
        limited[1].trim_end(),
        "G2 OK [METADATA LONGENTRIES 3] GETMETADATA completed"
    );

    // A literal value with a line break is stored and returned as a literal.
    session
        .command(
            "S2 SETMETADATA INBOX (/private/comment {7+}\r\nab\r\ncd\" )",
            "S2 OK",
        )
        .await;
    let literal = session
        .command("G3 GETMETADATA INBOX /private/comment", "G3 OK")
        .await
        .concat();
    assert!(
        literal.starts_with("* METADATA \"INBOX\" (\"/private/comment\" {7}\r\nab\r\ncd\")\r\n"),
        "{literal:?}"
    );
    session.finish().await;
}

#[tokio::test]
async fn errors_use_rfc_5464_response_codes() {
    let mut session = authenticated_session(0).await;
    session
        .command("B1 SETMETADATA INBOX (/other/comment \"x\")", "B1 BAD")
        .await;
    session
        .command("B2 GETMETADATA INBOX (DEPTH 5) /private/comment", "B2 BAD")
        .await;
    session
        .command("N1 GETMETADATA Missing /private/comment", "N1 NO")
        .await;
    session
        .command("N2 SETMETADATA Missing (/private/comment \"x\")", "N2 NO")
        .await;
    let admin = session
        .command("N3 SETMETADATA \"\" (/shared/admin \"mailto:x\")", "N3 NO")
        .await;
    assert!(admin[0].starts_with("N3 NO [NOPERM]"), "{admin:?}");

    let big = "x".repeat(crate::commands::metadata::MAX_VALUE_BYTES + 1);
    let too_big = session
        .command(
            &format!(
                "N4 SETMETADATA INBOX (/private/comment {{{}+}}\r\n{big})",
                big.len()
            ),
            "N4 NO",
        )
        .await;
    assert!(
        too_big[0].starts_with(&format!(
            "N4 NO [METADATA MAXSIZE {}]",
            crate::commands::metadata::MAX_VALUE_BYTES
        )),
        "{too_big:?}"
    );

    let entries = (0..=crate::commands::metadata::MAX_ENTRIES)
        .map(|index| format!("/private/e{index} \"v\""))
        .collect::<Vec<_>>()
        .join(" ");
    let too_many = session
        .command(&format!("N5 SETMETADATA INBOX ({entries})"), "N5 NO")
        .await;
    assert!(
        too_many[0].starts_with("N5 NO [METADATA TOOMANY]"),
        "{too_many:?}"
    );
    session.finish().await;
}

#[tokio::test]
async fn annotations_follow_rename_and_go_away_with_delete() {
    let mut session = authenticated_session(0).await;
    session.command("C1 CREATE Projects", "C1 OK").await;
    session
        .command(
            "S1 SETMETADATA Projects (/private/comment \"kept\")",
            "S1 OK",
        )
        .await;
    session.command("R1 RENAME Projects Work", "R1 OK").await;
    let renamed = session
        .command("G1 GETMETADATA Work /private/comment", "G1 OK")
        .await;
    assert_eq!(
        renamed[0].trim_end(),
        "* METADATA \"Work\" (\"/private/comment\" \"kept\")"
    );
    session.command("D1 DELETE Work", "D1 OK").await;
    session.command("C2 CREATE Work", "C2 OK").await;
    let recreated = session
        .command("G2 GETMETADATA Work /private/comment", "G2 OK")
        .await;
    assert_eq!(
        recreated[0].trim_end(),
        "* METADATA \"Work\" (\"/private/comment\" NIL)"
    );
    session.finish().await;
}
