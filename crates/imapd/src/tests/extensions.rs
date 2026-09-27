//! UNAUTHENTICATE (RFC 8437), CREATE-SPECIAL-USE (RFC 6154 §3) and
//! APPENDLIMIT (RFC 7889).

use super::sync::authenticated_session;

#[tokio::test]
async fn unauthenticate_returns_to_the_not_authenticated_state() {
    let mut session = authenticated_session(1).await;
    let caps = session.command("C1 CAPABILITY", "C1 OK").await;
    assert!(caps[0].contains(" UNAUTHENTICATE"), "{caps:?}");
    assert!(caps[0].contains(" APPENDLIMIT=104857600"), "{caps:?}");
    session.command("E1 ENABLE CONDSTORE", "E1 OK").await;
    session.command("S1 SELECT INBOX", "S1 OK").await;

    let done = session.command("U1 UNAUTHENTICATE", "U1 ").await;
    assert_eq!(
        done.last().unwrap().trim_end(),
        "U1 OK UNAUTHENTICATE completed"
    );
    let fetch = session.command("F1 FETCH 1 FLAGS", "F1 ").await;
    assert!(
        fetch.last().unwrap().starts_with("F1 NO"),
        "selected state must be gone: {fetch:?}"
    );
    let caps = session.command("C2 CAPABILITY", "C2 OK").await;
    assert!(!caps[0].contains("UNAUTHENTICATE"), "{caps:?}");

    // A fresh login starts with no enabled extensions.
    session
        .command("L2 LOGIN \"user@example.test\" \"password\"", "L2 OK")
        .await;
    let enabled = session.command("E2 ENABLE CONDSTORE", "E2 OK").await;
    assert_eq!(enabled[0].trim_end(), "* ENABLED CONDSTORE");
    session.finish().await;
}

#[tokio::test]
async fn unauthenticate_requires_authentication() {
    let mut session = authenticated_session(0).await;
    session.command("U1 UNAUTHENTICATE", "U1 OK").await;
    let again = session.command("U2 UNAUTHENTICATE", "U2 ").await;
    assert!(
        again
            .last()
            .unwrap()
            .starts_with("U2 NO Authentication required")
    );
    session.finish().await;
}

#[tokio::test]
async fn create_special_use_sets_the_attribute() {
    let mut session = authenticated_session(0).await;
    let caps = session.command("C1 CAPABILITY", "C1 OK").await;
    assert!(caps[0].contains(" CREATE-SPECIAL-USE"), "{caps:?}");
    session
        .command("A1 CREATE \"Old Mail\" (USE (\\Archive))", "A1 OK")
        .await;
    let list = session
        .command("L1 LIST \"\" \"Old Mail\" RETURN (SPECIAL-USE)", "L1 OK")
        .await;
    assert!(
        list.iter()
            .any(|line| line.starts_with("* LIST (") && line.contains("\\Archive")),
        "{list:?}"
    );
    let unsupported = session
        .command("A2 CREATE Everything (USE (\\All))", "A2 ")
        .await;
    assert!(
        unsupported.last().unwrap().starts_with("A2 NO [USEATTR]"),
        "{unsupported:?}"
    );
    let bad = session
        .command("A3 CREATE Other (FOO (\\Archive))", "A3 ")
        .await;
    assert!(bad.last().unwrap().starts_with("A3 BAD"), "{bad:?}");
    let list = session.command("L2 LIST \"\" \"*\"", "L2 OK").await;
    assert!(!list.iter().any(|line| line.contains("Everything")));
    assert!(!list.iter().any(|line| line.contains("\"Other\"")));
    session.finish().await;
}
