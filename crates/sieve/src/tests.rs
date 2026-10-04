use super::*;

const MSG: &[u8] = b"From: Alice <alice@example.org>\r\nTo: Bob <bob@example.com>, carol@example.net\r\nSubject: Weekly REPORT\r\nX-Spam-Score: 7\r\nList-Id: <dev.example.org>\r\n\r\nPlease find the numbers inside.\r\n";

fn run(script: &str) -> Vec<Action> {
    run_with(script, MSG, "alice@example.org", "bob@example.com")
}

fn run_with(script: &str, raw: &[u8], from: &str, to: &str) -> Vec<Action> {
    let script = Script::parse(script).unwrap_or_else(|e| panic!("{e}\n{script}"));
    script.run(&Message::new(raw, from, to)).unwrap()
}

fn keep() -> Action {
    Action::Keep { flags: vec![] }
}

fn file(folder: &str) -> Action {
    Action::FileInto {
        folder: folder.into(),
        flags: vec![],
    }
}

fn err(script: &str) -> String {
    Script::parse(script).unwrap_err().to_string()
}

#[test]
fn empty_script_and_no_matching_rule_keep_implicitly() {
    assert_eq!(run(""), vec![keep()]);
    assert_eq!(run("if false { discard; }"), vec![keep()]);
}

#[test]
fn fileinto_cancels_implicit_keep_unless_copy() {
    let s = "require [\"fileinto\", \"copy\"];\n";
    assert_eq!(run(&format!("{s}fileinto \"Work\";")), vec![file("Work")]);
    assert_eq!(
        run(&format!("{s}fileinto :copy \"Work\";")),
        vec![file("Work"), keep()]
    );
    // Duplicate fileinto of one folder happens once.
    assert_eq!(
        run(&format!("{s}fileinto \"Work\"; fileinto \"Work\";")),
        vec![file("Work")]
    );
}

#[test]
fn explicit_keep_discard_and_stop() {
    assert_eq!(run("discard;"), vec![Action::Discard]);
    assert_eq!(run("keep; discard;"), vec![keep(), Action::Discard]);
    assert_eq!(
        run("require \"fileinto\"; fileinto \"A\"; stop; fileinto \"B\";"),
        vec![file("A")]
    );
}

#[test]
fn redirect_validates_and_cancels_keep() {
    assert_eq!(
        run("redirect \"me@elsewhere.test\";"),
        vec![Action::Redirect {
            address: "me@elsewhere.test".into()
        }]
    );
    assert!(err("redirect \"not an address\";").contains("plain email address"));
    assert_eq!(
        run("require \"copy\"; redirect :copy \"me@elsewhere.test\";"),
        vec![
            Action::Redirect {
                address: "me@elsewhere.test".into()
            },
            keep()
        ]
    );
}

#[test]
fn header_tests_with_match_types() {
    let t = |s: &str| run(&format!("if {s} {{ discard; }}")) == vec![Action::Discard];
    assert!(t("header :contains \"subject\" \"report\""));
    assert!(t("header :is \"Subject\" \"weekly report\""));
    assert!(!t(
        "header :is :comparator \"i;octet\" \"Subject\" \"weekly report\""
    ));
    assert!(t("header :matches \"subject\" \"weekly *\""));
    assert!(t("header :matches \"subject\" \"?eekly ??port\""));
    assert!(t(
        "header :contains [\"x-nope\", \"subject\"] [\"zzz\", \"EPOR\"]"
    ));
    assert!(!t("header :contains \"x-nope\" \"\""));
    assert!(t("exists [\"subject\", \"from\"]"));
    assert!(!t("exists [\"subject\", \"x-missing\"]"));
    assert!(t("not exists \"x-missing\""));
}

#[test]
fn address_tests_and_parts() {
    let t = |s: &str| run(&format!("if {s} {{ discard; }}")) == vec![Action::Discard];
    assert!(t("address :is \"from\" \"ALICE@example.org\""));
    assert!(t("address :is :localpart \"from\" \"alice\""));
    assert!(t("address :is :domain \"to\" \"example.net\""));
    assert!(t("address :domain :contains \"to\" \"example.com\""));
    assert!(!t("address :is :domain \"from\" \"example.com\""));
}

#[test]
fn envelope_and_size_and_body() {
    let t = |s: &str| {
        run(&format!(
            "require [\"envelope\", \"body\"]; if {s} {{ discard; }}"
        )) == vec![Action::Discard]
    };
    assert!(t("envelope :is \"to\" \"bob@example.com\""));
    assert!(t("envelope :domain :is \"from\" \"example.org\""));
    assert!(!t("envelope :is \"from\" \"bob@example.com\""));
    assert!(t("size :over 100"));
    assert!(t("size :under 10K"));
    assert!(!t("size :under 10"));
    assert!(t("body :contains \"numbers\""));
    assert!(!t("body :contains \"secret\""));
}

#[test]
fn null_sender_envelope_matches_empty_string() {
    let out = run_with(
        "require \"envelope\"; if envelope :is \"from\" \"\" { discard; }",
        MSG,
        "",
        "bob@example.com",
    );
    assert_eq!(out, vec![Action::Discard]);
}

#[test]
fn relational_count_and_value() {
    let t = |s: &str| {
        run(&format!(
            "require \"relational\"; require \"comparator-i;ascii-numeric\"; if {s} {{ discard; }}"
        )) == vec![Action::Discard]
    };
    assert!(t("header :count \"eq\" \"to\" \"1\""));
    assert!(t("header :count \"ge\" \"received\" \"0\""));
    assert!(t(
        "header :value \"gt\" :comparator \"i;ascii-numeric\" \"x-spam-score\" \"5\""
    ));
    assert!(!t(
        "header :value \"gt\" :comparator \"i;ascii-numeric\" \"x-spam-score\" \"10\""
    ));
    assert!(t("header :value \"lt\" \"subject\" \"zzz\""));
    assert!(err("if header :count \"eq\" \"to\" \"1\" { keep; }").contains("relational"));
}

#[test]
fn logic_and_elsif_else_chains() {
    let script = r#"
require "fileinto";
if allof (header :contains "subject" "report", address :domain :is "from" "example.org") {
    fileinto "Reports";
} elsif anyof (exists "x-missing", header :contains "list-id" "dev") {
    fileinto "Lists";
} else {
    fileinto "Other";
}"#;
    assert_eq!(run(script), vec![file("Reports")]);
    let lists = r#"require "fileinto";
if header :contains "subject" "nope" { fileinto "A"; }
elsif header :contains "list-id" "dev" { fileinto "Lists"; }
else { fileinto "Other"; }"#;
    assert_eq!(run(lists), vec![file("Lists")]);
    let other = lists.replace("\"dev\"", "\"nomatch\"");
    assert_eq!(run(&other), vec![file("Other")]);
}

#[test]
fn imap4flags_apply_to_later_actions() {
    let out = run(r#"require ["fileinto", "imap4flags"];
addflag "\\Flagged";
addflag ["$work", "\\flagged"];
fileinto "Work";
removeflag "$work";
keep;
fileinto :flags "\\Seen" "Read";"#);
    assert_eq!(
        out,
        vec![
            Action::FileInto {
                folder: "Work".into(),
                flags: vec!["\\Flagged".into(), "$work".into()]
            },
            Action::Keep {
                flags: vec!["\\Flagged".into()]
            },
            Action::FileInto {
                folder: "Read".into(),
                flags: vec!["\\Seen".into()]
            },
        ]
    );
    let set = run("require \"imap4flags\"; setflag \"\\\\Seen \\\\Answered\"; keep;");
    assert_eq!(
        set,
        vec![Action::Keep {
            flags: vec!["\\Seen".into(), "\\Answered".into()]
        }]
    );
}

#[test]
fn require_is_enforced() {
    assert!(err("fileinto \"A\";").contains("require"));
    assert!(err("require \"nonsense\";").contains("unsupported extension"));
    assert!(err("keep; require \"fileinto\";").contains("before other commands"));
    assert!(err("require \"vacation\"; if true { require \"fileinto\"; }").contains("top level"));
    assert!(err("vacation \"hi\";").contains("require"));
}

#[test]
fn syntax_errors_carry_line_numbers() {
    assert!(err("keep").contains("expected ;"));
    assert!(err("if true { keep; ").contains("expected }"));
    assert!(err("\n\nbogus;").contains("line 3"));
    assert!(err("if { keep; }").contains("exactly one test"));
    assert!(err("else { keep; }").contains("without a preceding"));
    assert!(err("if exists \"a\" keep;").contains("nested tests"));
    assert!(err("if header :is :contains \"a\" \"b\" { keep; }").contains("only one match type"));
    assert!(err("if size 5 { keep; }").contains(":over or :under"));
    assert!(err("if header :bogus \"a\" \"b\" { keep; }").contains("unknown tag"));
    assert!(err("if nosuchtest { keep; }").contains("unknown test"));
    assert!(err("keep :weird;").contains("unknown tag"));
}

#[test]
fn nesting_and_size_limits() {
    let deep = format!("{}keep;{}", "if true { ".repeat(40), " }".repeat(40));
    assert!(err(&deep).contains("too deeply"));
    let ok = format!("{}keep;{}", "if true { ".repeat(20), " }".repeat(20));
    assert!(Script::parse(&ok).is_ok());
    assert!(err(&"#".repeat((1 << 20) + 1)).contains("too large"));
}

#[test]
fn runtime_limits_fall_back_to_error() {
    let many = (0..5)
        .map(|i| format!("redirect \"a{i}@x.test\";"))
        .collect::<String>();
    let script = Script::parse(&many).unwrap();
    assert!(matches!(
        script.run(&Message::new(MSG, "a@b.test", "c@d.test")),
        Err(Error::Limit(_))
    ));
    let actions = (0..70).map(|_| "keep;").collect::<String>();
    assert!(matches!(
        Script::parse(&actions)
            .unwrap()
            .run(&Message::new(MSG, "a@b.test", "c@d.test")),
        Err(Error::Limit(_))
    ));
}

fn vacation_action(script: &str) -> Vacation {
    let actions = run(script);
    actions
        .into_iter()
        .find_map(|a| match a {
            Action::Vacation(v) => Some(v),
            _ => None,
        })
        .expect("vacation action")
}

#[test]
fn vacation_parameters_and_defaults() {
    let v = vacation_action(
        "require \"vacation\"; vacation :days 3 :subject \"Away\" :from \"me@example.com\" :addresses [\"b@example.com\"] :handle \"h1\" \"Back soon\";",
    );
    assert_eq!(v.days, 3);
    assert_eq!(v.subject.as_deref(), Some("Away"));
    assert_eq!(v.from.as_deref(), Some("me@example.com"));
    assert_eq!(v.addresses, vec!["b@example.com"]);
    assert_eq!(v.dedupe_key(), "h1");
    let d = vacation_action("require \"vacation\"; vacation \"x\";");
    assert_eq!(d.days, 7);
    assert!(d.dedupe_key().contains('x'));
    assert_eq!(
        vacation_action("require \"vacation\"; vacation :days 0 \"x\";").days,
        1
    );
    assert_eq!(
        vacation_action("require \"vacation\"; vacation :days 9999 \"x\";").days,
        365
    );
    // The vacation action keeps the message implicitly.
    assert!(run("require \"vacation\"; vacation \"x\";").contains(&keep()));
}

fn vac() -> Vacation {
    vacation_action("require \"vacation\"; vacation \"away\";")
}

fn target(raw: &[u8], from: &str, to: &str) -> Option<String> {
    vac().reply_target(&Message::new(raw, from, to))
}

#[test]
fn vacation_replies_only_to_direct_personal_mail() {
    let personal = b"From: a@x.test\r\nTo: bob@example.com\r\nSubject: hi\r\n\r\nb";
    assert_eq!(
        target(personal, "a@x.test", "bob@example.com").as_deref(),
        Some("a@x.test")
    );
    // Not addressed to the user (e.g. Bcc or list): no reply.
    let bcc = b"From: a@x.test\r\nTo: other@example.com\r\n\r\nb";
    assert_eq!(target(bcc, "a@x.test", "bob@example.com"), None);
    // null and system senders
    assert_eq!(target(personal, "", "bob@example.com"), None);
    assert_eq!(
        target(personal, "mailer-daemon@x.test", "bob@example.com"),
        None
    );
    assert_eq!(
        target(personal, "dev-request@x.test", "bob@example.com"),
        None
    );
    assert_eq!(
        target(personal, "owner-dev@x.test", "bob@example.com"),
        None
    );
    // automatic and bulk mail
    for header in [
        "Auto-Submitted: auto-generated",
        "Precedence: bulk",
        "Precedence: list",
        "List-Id: <x.test>",
        "List-Unsubscribe: <mailto:u@x.test>",
        "X-Spam-Flag: YES",
    ] {
        let raw = format!("From: a@x.test\r\nTo: bob@example.com\r\n{header}\r\n\r\nb");
        assert_eq!(
            target(raw.as_bytes(), "a@x.test", "bob@example.com"),
            None,
            "{header}"
        );
    }
    let no = b"From: a@x.test\r\nTo: bob@example.com\r\nAuto-Submitted: no\r\n\r\nb";
    assert!(target(no, "a@x.test", "bob@example.com").is_some());
}

#[test]
fn vacation_uses_addresses_alias_list() {
    let v = vacation_action(
        "require \"vacation\"; vacation :addresses [\"Alias@Example.com\"] \"away\";",
    );
    let raw = b"From: a@x.test\r\nTo: alias@example.com\r\n\r\nb";
    assert!(
        v.reply_target(&Message::new(raw, "a@x.test", "bob@example.com"))
            .is_some()
    );
}

#[test]
fn vacation_reply_message_shape() {
    let v = vacation_action(
        "require \"vacation\"; vacation :subject \"Out\" \"I am away.\nBack Monday.\";",
    );
    let raw = b"From: a@x.test\r\nTo: bob@example.com\r\nSubject: hi\r\nMessage-ID: <orig@x.test>\r\n\r\nb";
    let reply = String::from_utf8(v.build_reply(
        &Message::new(raw, "a@x.test", "bob@example.com"),
        "bob@example.com",
        "a@x.test",
        "Mon, 5 Oct 2026 10:00:00 +0000",
        "<r1@example.com>",
    ))
    .unwrap();
    assert!(reply.starts_with("From: bob@example.com\r\nTo: a@x.test\r\nSubject: Out\r\n"));
    assert!(reply.contains("In-Reply-To: <orig@x.test>\r\n"));
    assert!(reply.contains("Auto-Submitted: auto-replied\r\n"));
    assert!(
        reply.ends_with("\r\n\r\nI am away.\r\nBack Monday.\r\n")
            || reply.ends_with("I am away.\\nBack Monday.\r\n"),
        "{reply:?}"
    );
    let default_subject = vacation_action("require \"vacation\"; vacation \"x\";");
    let r = String::from_utf8(default_subject.build_reply(
        &Message::new(raw, "a@x.test", "b@e.test"),
        "b@e.test",
        "a@x.test",
        "d",
        "<m>",
    ))
    .unwrap();
    assert!(r.contains("Subject: Auto: hi\r\n"));
    // Header injection through :subject is neutralized.
    let evil = Vacation {
        subject: Some("x\r\nBcc: z@z.test".into()),
        ..vac()
    };
    let r = String::from_utf8(evil.build_reply(
        &Message::new(raw, "a@x.test", "b@e.test"),
        "b@e.test",
        "a@x.test",
        "d",
        "<m>",
    ))
    .unwrap();
    assert!(!r.contains("\r\nBcc:"));
}

#[test]
fn text_blocks_and_comments_work_in_scripts() {
    let v = vacation_action(
        "require \"vacation\"; # comment\n/* block */ vacation text:\nLine one\n.\n;",
    );
    assert_eq!(v.reason, "Line one\r\n");
}
