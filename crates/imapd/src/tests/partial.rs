//! PARTIAL (RFC 9394): paged SEARCH results and the UID FETCH modifier.

use super::sync::selected_session;

/// Sequence numbers of the untagged FETCH responses in `lines`.
fn fetched(lines: &[String]) -> Vec<u64> {
    lines
        .iter()
        .filter(|line| line.contains(" FETCH ("))
        .filter_map(|line| line.strip_prefix("* ")?.split(' ').next()?.parse().ok())
        .collect()
}

#[tokio::test]
async fn search_return_partial_pages_results() {
    let mut session = selected_session(6).await;
    assert_eq!(session.uids, (1..=6).collect::<Vec<u64>>());
    let capability = session.command("C1 CAPABILITY", "C1 OK").await;
    assert!(
        capability[0].split_whitespace().any(|cap| cap == "PARTIAL"),
        "{capability:?}"
    );
    session
        .command("T1 STORE 1,3 +FLAGS (\\Seen)", "T1 OK")
        .await;

    let first = session
        .command("P1 SEARCH RETURN (PARTIAL 1:2) UNSEEN", "P1 OK")
        .await;
    assert_eq!(
        first[0].trim_end(),
        "* ESEARCH (TAG \"P1\") PARTIAL (1:2 2,4)"
    );

    let last = session
        .command(
            "P2 UID SEARCH RETURN (PARTIAL -1:-3 COUNT MIN MAX) UNSEEN",
            "P2 OK",
        )
        .await;
    assert_eq!(
        last[0].trim_end(),
        "* ESEARCH (TAG \"P2\") UID MIN 2 MAX 6 PARTIAL (-1:-3 4:6) COUNT 4"
    );

    let reversed = session
        .command("P3 SEARCH RETURN (PARTIAL 5:3) ALL", "P3 OK")
        .await;
    assert_eq!(
        reversed[0].trim_end(),
        "* ESEARCH (TAG \"P3\") PARTIAL (5:3 3:5)"
    );

    let beyond = session
        .command("P4 SEARCH RETURN (PARTIAL 10:20) ALL", "P4 OK")
        .await;
    assert_eq!(
        beyond[0].trim_end(),
        "* ESEARCH (TAG \"P4\") PARTIAL (10:20 NIL)"
    );

    let spanning = session
        .command("P5 SEARCH RETURN (PARTIAL -3:-10) UNSEEN", "P5 OK")
        .await;
    assert_eq!(
        spanning[0].trim_end(),
        "* ESEARCH (TAG \"P5\") PARTIAL (-3:-10 2,4)"
    );

    for (tag, command) in [
        ("B1", "SEARCH RETURN (PARTIAL 1:2 ALL) ALL"),
        ("B2", "SEARCH RETURN (PARTIAL 0:2) ALL"),
        ("B3", "SEARCH RETURN (PARTIAL -1:2) ALL"),
        ("B4", "SEARCH RETURN (PARTIAL 1:2 PARTIAL 3:4) ALL"),
        ("B5", "SEARCH RETURN (PARTIAL 1:*) ALL"),
    ] {
        session
            .command(&format!("{tag} {command}"), &format!("{tag} BAD"))
            .await;
    }

    // RFC 9394 Table 1: SAVE PARTIAL saves only the page; with COUNT, all.
    let saved = session
        .command("S1 UID SEARCH RETURN (SAVE PARTIAL -1:-2) UNSEEN", "S1 OK")
        .await;
    assert_eq!(
        saved[0].trim_end(),
        "* ESEARCH (TAG \"S1\") UID PARTIAL (-1:-2 5:6)"
    );
    let page = session.command("S2 FETCH $ (FLAGS)", "S2 OK").await;
    assert_eq!(fetched(&page), vec![5, 6]);
    session
        .command("S3 SEARCH RETURN (SAVE PARTIAL 1:1 MIN) UNSEEN", "S3 OK")
        .await;
    let page = session.command("S4 FETCH $ (FLAGS)", "S4 OK").await;
    assert_eq!(fetched(&page), vec![2]);
    session
        .command("S5 SEARCH RETURN (SAVE PARTIAL 1:1 COUNT) UNSEEN", "S5 OK")
        .await;
    let page = session.command("S6 FETCH $ (FLAGS)", "S6 OK").await;
    assert_eq!(fetched(&page), vec![2, 4, 5, 6]);

    session.finish().await;
}

#[tokio::test]
async fn uid_fetch_partial_modifier_limits_the_addressed_messages() {
    let mut session = selected_session(6).await;
    assert_eq!(session.uids, (1..=6).collect::<Vec<u64>>());

    let last = session
        .command("F1 UID FETCH 1:* (FLAGS) (PARTIAL -1:-2)", "F1 OK")
        .await;
    assert_eq!(fetched(&last), vec![5, 6]);
    let first = session
        .command("F2 UID FETCH 2:* (FLAGS) (PARTIAL 1:2)", "F2 OK")
        .await;
    assert_eq!(fetched(&first), vec![2, 3]);
    let sparse = session
        .command("F3 UID FETCH 1,3,5 (FLAGS) (PARTIAL 2:3)", "F3 OK")
        .await;
    assert_eq!(fetched(&sparse), vec![3, 5]);
    let beyond = session
        .command("F4 UID FETCH 1:* (FLAGS) (PARTIAL 7:9)", "F4 OK")
        .await;
    assert!(fetched(&beyond).is_empty(), "{beyond:?}");

    let non_uid = session
        .command("F5 FETCH 1:* (FLAGS) (PARTIAL 1:2)", "F5 BAD")
        .await;
    assert!(non_uid.last().unwrap().contains("UID FETCH"), "{non_uid:?}");
    session
        .command("F6 UID FETCH 1:* (FLAGS) (PARTIAL 1:*)", "F6 BAD")
        .await;

    // RFC 9394 §3.4: the page is chosen first, then CHANGEDSINCE filters it.
    let modseq = session.command("M1 FETCH 6 (MODSEQ)", "M1 OK").await;
    let modseq: u64 = modseq[0]
        .split("MODSEQ (")
        .nth(1)
        .and_then(|rest| rest.split(')').next())
        .and_then(|value| value.parse().ok())
        .expect("modseq");
    session
        .command("T1 STORE 2,5 +FLAGS (\\Flagged)", "T1 OK")
        .await;
    let changed = session
        .command(
            &format!("F7 UID FETCH 1:* (FLAGS) (PARTIAL 1:3 CHANGEDSINCE {modseq})"),
            "F7 OK",
        )
        .await;
    assert_eq!(fetched(&changed), vec![2]);
    let changed = session
        .command(
            &format!("F8 UID FETCH 1:* (FLAGS) (CHANGEDSINCE {modseq} PARTIAL -1:-3)"),
            "F8 OK",
        )
        .await;
    assert_eq!(fetched(&changed), vec![5]);

    session.finish().await;
}
