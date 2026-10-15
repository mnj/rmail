//! Out-of-office replies and mail filters, edited from webmail.
//!
//! - The out-of-office reply is the account's JMAP `VacationResponse`
//!   (`db::get_vacation_response`), so JMAP clients and webmail edit the
//!   same thing; delivery answers with it (`rmail_smtpd`).
//! - Filters are kept as Sieve, the account's active script, so they run on
//!   delivery like a script uploaded over ManageSieve. Webmail writes its
//!   rules to a script named [`SCRIPT_NAME`] and records them in a comment
//!   line at its top, which is how it reads them back. A script written by
//!   hand (any other active script, or ours edited so the rules no longer
//!   match) is never overwritten silently: it is shown as text and can be
//!   edited as text, or replaced with rules only when the user asks.

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use rmail_common::db::{self, VacationResponse};
use serde::{Deserialize, Serialize};

use super::{Session, Shared, blocking, internal_error, is_user_keyword};

/// The script webmail's rules are kept in.
pub(crate) const SCRIPT_NAME: &str = "webmail";
/// The comment line that records the rules a script was generated from.
const RULES_MARKER: &str = "# rmail-rules: ";
const MAX_RULES: usize = 100;
const MAX_CONDITIONS: usize = 20;
const MAX_ACTIONS: usize = 10;
const MAX_VALUE_CHARS: usize = 500;
const MAX_SUBJECT_CHARS: usize = 200;
const MAX_REPLY_CHARS: usize = 20_000;
/// A hand-edited script; as ManageSieve allows.
const MAX_SCRIPT_BYTES: usize = 1 << 20;

pub(crate) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/vacation", get(get_vacation).put(put_vacation))
        .route("/api/filters", get(get_filters).put(put_filters))
        .route("/api/filters/script", put(put_script))
}

fn bad_request(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": message.into() })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Out of office

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct Vacation {
    enabled: bool,
    /// Unix seconds; replies go out from `from` until before `until`.
    from: Option<i64>,
    until: Option<i64>,
    subject: String,
    text: String,
}

async fn get_vacation(app: axum::extract::State<Shared>, headers: HeaderMap) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let result =
        blocking(move || db::get_vacation_response(&state.db_path, &session.address)).await;
    match result {
        Ok(response) => Json(Vacation {
            enabled: response.enabled,
            from: response.from_date,
            until: response.to_date,
            subject: response.subject.unwrap_or_default(),
            text: response.text_body.unwrap_or_default(),
        })
        .into_response(),
        Err(error) => internal_error(error),
    }
}

async fn put_vacation(
    app: axum::extract::State<Shared>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<Vacation>(&body) else {
        return bad_request("invalid json");
    };
    if input.subject.chars().count() > MAX_SUBJECT_CHARS
        || input.text.chars().count() > MAX_REPLY_CHARS
    {
        return bad_request("The reply is too long.");
    }
    if let (Some(from), Some(until)) = (input.from, input.until)
        && until <= from
    {
        return bad_request("The end must be after the start.");
    }
    if input.enabled && input.text.trim().is_empty() {
        return bad_request("Write the reply people should get.");
    }
    let result = blocking(move || {
        let response = VacationResponse {
            enabled: input.enabled,
            from_date: input.from,
            to_date: input.until,
            subject: Some(input.subject.replace(['\r', '\n'], " ").trim().to_string())
                .filter(|subject| !subject.is_empty()),
            text_body: Some(input.text.clone()).filter(|text| !text.trim().is_empty()),
            // Webmail writes plain text; an HTML version set over JMAP
            // would no longer match it.
            html_body: None,
        };
        // Logged before saving, as JMAP's VacationResponse/set does, so a
        // saved change is never missed by JMAP clients.
        let conn =
            rmail_common::jmap::store::open(&state.mail_root, &session.domain, &session.localpart)?;
        rmail_common::jmap::store::log_change(
            &conn,
            "VacationResponse",
            "singleton",
            false,
            false,
        )?;
        db::set_vacation_response(&state.db_path, &session.address, &response)?;
        Ok(Vacation {
            enabled: response.enabled,
            from: response.from_date,
            until: response.to_date,
            subject: response.subject.unwrap_or_default(),
            text: response.text_body.unwrap_or_default(),
        })
    })
    .await;
    match result {
        Ok(saved) => Json(saved).into_response(),
        Err(error) => internal_error(error),
    }
}

// ---------------------------------------------------------------------------
// Filters

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Field {
    From,
    /// To or Cc.
    To,
    Subject,
    /// Any header, named in `header`.
    Header,
    /// The message size; `value` like `500K` or `2M`.
    Size,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Op {
    Contains,
    NotContains,
    Is,
    IsNot,
    /// Sizes only.
    Over,
    Under,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct Condition {
    pub field: Field,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub header: String,
    pub op: Op,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Action {
    Move {
        folder: String,
    },
    MarkRead,
    Star,
    Label {
        keyword: String,
    },
    Forward {
        address: String,
        /// Keep a copy here too.
        #[serde(default)]
        keep: bool,
    },
    Delete,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rule {
    pub name: String,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    /// Every condition must hold (`all`) or any one (`any`).
    #[serde(default)]
    pub any: bool,
    pub conditions: Vec<Condition>,
    pub actions: Vec<Action>,
    /// Skip the rules after this one when it matches.
    #[serde(default)]
    pub stop: bool,
}

fn enabled_by_default() -> bool {
    true
}

/// A Sieve string literal.
fn quoted(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

fn valid_size(value: &str) -> bool {
    let digits = value.trim_end_matches(['K', 'M', 'G', 'k', 'm', 'g']);
    !digits.is_empty()
        && digits.len() <= 9
        && digits.bytes().all(|b| b.is_ascii_digit())
        && value.len() - digits.len() <= 1
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 100 && name.bytes().all(|b| b.is_ascii_graphic() && b != b':')
}

/// Why a rule cannot be saved, for the user.
fn check(rules: &[Rule]) -> Result<(), String> {
    if rules.len() > MAX_RULES {
        return Err(format!("At most {MAX_RULES} rules."));
    }
    for rule in rules {
        let name = if rule.name.trim().is_empty() {
            "A rule".to_string()
        } else {
            format!("\"{}\"", rule.name.trim())
        };
        if rule.name.chars().count() > 100 || rule.name.contains(['\r', '\n']) {
            return Err(format!("{name} has an invalid name."));
        }
        if rule.conditions.len() > MAX_CONDITIONS || rule.actions.len() > MAX_ACTIONS {
            return Err(format!("{name} has too many conditions or actions."));
        }
        if rule.actions.is_empty() {
            return Err(format!("{name} does nothing: add an action."));
        }
        for condition in &rule.conditions {
            if condition.value.chars().count() > MAX_VALUE_CHARS
                || condition.value.contains(['\r', '\n'])
            {
                return Err(format!("{name} has a condition that is too long."));
            }
            match condition.field {
                Field::Size => {
                    if !matches!(condition.op, Op::Over | Op::Under)
                        || !valid_size(condition.value.trim())
                    {
                        return Err(format!(
                            "{name}: a size is compared with \"over\" or \"under\", like 500K or 2M."
                        ));
                    }
                }
                _ if matches!(condition.op, Op::Over | Op::Under) => {
                    return Err(format!("{name}: only sizes are over or under."));
                }
                Field::Header if !valid_header_name(condition.header.trim()) => {
                    return Err(format!("{name} needs a header name."));
                }
                _ if condition.value.trim().is_empty() => {
                    return Err(format!("{name} has an empty condition."));
                }
                _ => {}
            }
        }
        for action in &rule.actions {
            match action {
                Action::Move { folder } if folder.trim().is_empty() || folder.len() > 255 => {
                    return Err(format!("{name} needs a folder to move to."));
                }
                Action::Label { keyword } if !is_user_keyword(keyword) => {
                    return Err(format!("{name} has an invalid label."));
                }
                Action::Forward { address, .. }
                    if rmail_common::domain::canonicalize_mailbox_address(address).is_err() =>
                {
                    return Err(format!("{name} has an invalid forwarding address."));
                }
                _ => {}
            }
        }
        let moves = rule
            .actions
            .iter()
            .filter(|action| matches!(action, Action::Move { .. }))
            .count();
        let deletes = rule
            .actions
            .iter()
            .any(|action| matches!(action, Action::Delete));
        if moves > 1 || (deletes && rule.actions.len() > 1) {
            return Err(format!(
                "{name}: move to one folder at most, and delete only on its own."
            ));
        }
    }
    Ok(())
}

fn test(condition: &Condition) -> String {
    let value = quoted(condition.value.trim());
    let (negate, comparator) = match condition.op {
        Op::Contains => (false, ":contains"),
        Op::NotContains => (true, ":contains"),
        Op::Is => (false, ":is"),
        Op::IsNot => (true, ":is"),
        Op::Over => return format!("size :over {}", condition.value.trim().to_ascii_uppercase()),
        Op::Under => {
            return format!(
                "size :under {}",
                condition.value.trim().to_ascii_uppercase()
            );
        }
    };
    let headers = match condition.field {
        Field::From => quoted("from"),
        Field::To => "[\"to\", \"cc\"]".to_string(),
        Field::Subject => quoted("subject"),
        Field::Header => quoted(condition.header.trim()),
        Field::Size => unreachable!("sizes are over or under"),
    };
    let test = format!("header {comparator} {headers} {value}");
    if negate { format!("not {test}") } else { test }
}

/// The Sieve script for `rules`, with the rules recorded at its top.
pub(crate) fn script(rules: &[Rule]) -> String {
    let mut requires = Vec::new();
    let mut body = String::new();
    let mut need = |extension: &'static str| {
        if !requires.contains(&extension) {
            requires.push(extension);
        }
    };
    for rule in rules.iter().filter(|rule| rule.enabled) {
        let tests = rule.conditions.iter().map(test).collect::<Vec<_>>();
        let condition = match tests.len() {
            0 => "true".to_string(),
            1 => tests[0].clone(),
            _ => format!(
                "{}({})",
                if rule.any { "anyof" } else { "allof" },
                tests.join(", ")
            ),
        };
        let mut flags = Vec::new();
        let mut commands = Vec::new();
        for action in &rule.actions {
            match action {
                Action::MarkRead => flags.push(quoted("\\Seen")),
                Action::Star => flags.push(quoted("\\Flagged")),
                Action::Label { keyword } => flags.push(quoted(keyword)),
                Action::Move { .. } | Action::Forward { .. } | Action::Delete => {}
            }
        }
        let moved = rule.actions.iter().find_map(|action| match action {
            Action::Move { folder } => Some(folder),
            _ => None,
        });
        if !flags.is_empty() {
            need("imap4flags");
        }
        for action in &rule.actions {
            match action {
                Action::Forward { address, keep } => {
                    if *keep {
                        need("copy");
                        commands.push(format!("redirect :copy {};", quoted(address.trim())));
                    } else {
                        commands.push(format!("redirect {};", quoted(address.trim())));
                    }
                }
                Action::Delete => commands.push("discard;".to_string()),
                _ => {}
            }
        }
        match moved {
            Some(folder) => {
                need("fileinto");
                let flags = if flags.is_empty() {
                    String::new()
                } else {
                    format!(":flags [{}] ", flags.join(", "))
                };
                commands.insert(0, format!("fileinto {flags}{};", quoted(folder.trim())));
            }
            // Flags for the copy kept in the inbox.
            None if !flags.is_empty() => {
                commands.insert(0, format!("addflag [{}];", flags.join(", ")));
            }
            None => {}
        }
        if rule.stop {
            commands.push("stop;".to_string());
        }
        let name = rule.name.trim();
        if !name.is_empty() {
            body.push_str(&format!("# {name}\n"));
        }
        body.push_str(&format!("if {condition} {{\n"));
        for command in commands {
            body.push_str(&format!("    {command}\n"));
        }
        body.push_str("}\n");
    }
    let mut out = String::from(
        "# Mail filters from rMail webmail. Edit them there: changes made here\n\
         # turn the filters into a hand-written script webmail shows as text.\n",
    );
    out.push_str(RULES_MARKER);
    out.push_str(&serde_json::to_string(rules).unwrap_or_else(|_| "[]".to_string()));
    out.push('\n');
    if !requires.is_empty() {
        let list = requires.iter().map(|r| quoted(r)).collect::<Vec<_>>();
        out.push_str(&format!("require [{}];\n", list.join(", ")));
    }
    out.push_str(&body);
    out
}

/// The rules a script was generated from, when it is still exactly what
/// webmail generated for them.
fn rules_of(source: &str) -> Option<Vec<Rule>> {
    let line = source
        .lines()
        .find_map(|line| line.strip_prefix(RULES_MARKER))?;
    let rules = serde_json::from_str::<Vec<Rule>>(line).ok()?;
    (script(&rules) == source).then_some(rules)
}

#[derive(Serialize, Debug, PartialEq, Eq)]
struct Filters {
    /// `rules` (webmail's own), `script` (a hand-written active script) or
    /// `none` (no active script).
    mode: &'static str,
    rules: Vec<Rule>,
    /// The active hand-written script and its name.
    #[serde(skip_serializing_if = "Option::is_none")]
    script: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    script_name: Option<String>,
}

fn load_filters(db_path: &std::path::Path, account: &str) -> anyhow::Result<Filters> {
    let active = db::list_sieve_scripts(db_path, account)?
        .into_iter()
        .find(|(_, active)| *active)
        .map(|(name, _)| name);
    let Some(name) = active else {
        return Ok(Filters {
            mode: "none",
            rules: Vec::new(),
            script: None,
            script_name: None,
        });
    };
    let source = db::get_sieve_script(db_path, account, &name)?.unwrap_or_default();
    match (name == SCRIPT_NAME).then(|| rules_of(&source)).flatten() {
        Some(rules) => Ok(Filters {
            mode: "rules",
            rules,
            script: None,
            script_name: None,
        }),
        None => Ok(Filters {
            mode: "script",
            rules: Vec::new(),
            script: Some(source),
            script_name: Some(name),
        }),
    }
}

async fn get_filters(app: axum::extract::State<Shared>, headers: HeaderMap) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    match blocking(move || load_filters(&state.db_path, &session.address)).await {
        Ok(filters) => Json(filters).into_response(),
        Err(error) => internal_error(error),
    }
}

#[derive(Deserialize)]
struct SaveRules {
    rules: Vec<Rule>,
    /// Replace an active hand-written script (it is kept, inactive).
    #[serde(default)]
    replace_script: bool,
}

async fn put_filters(
    app: axum::extract::State<Shared>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<SaveRules>(&body) else {
        return bad_request("invalid json");
    };
    if let Err(message) = check(&input.rules) {
        return bad_request(message);
    }
    let source = script(&input.rules);
    if let Err(error) = rmail_sieve::Script::parse(&source) {
        // Every rule is checked above; this would be a bug here.
        return bad_request(format!("The filters could not be saved: {error}"));
    }
    let result = blocking(move || {
        let current = load_filters(&state.db_path, &session.address)?;
        if current.mode == "script" && !input.replace_script {
            return Ok(None);
        }
        // A hand-written script named like ours is kept under another name.
        if current.mode == "script" && current.script_name.as_deref() == Some(SCRIPT_NAME) {
            let kept = format!(
                "{SCRIPT_NAME}-{}",
                chrono::Utc::now().format("%Y%m%d%H%M%S")
            );
            db::set_active_sieve_script(&state.db_path, &session.address, None)?;
            db::rename_sieve_script(&state.db_path, &session.address, SCRIPT_NAME, &kept)?;
        }
        db::put_sieve_script(&state.db_path, &session.address, SCRIPT_NAME, &source)?;
        db::set_active_sieve_script(&state.db_path, &session.address, Some(SCRIPT_NAME))?;
        load_filters(&state.db_path, &session.address).map(Some)
    })
    .await;
    match result {
        Ok(Some(filters)) => Json(filters).into_response(),
        Ok(None) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "Your filters are a hand-written Sieve script. Replace it to use rules here."
            })),
        )
            .into_response(),
        Err(error) => internal_error(error),
    }
}

#[derive(Deserialize)]
struct SaveScript {
    script: String,
}

/// Save the active hand-written script (or start one), checked by the
/// same parser delivery uses.
async fn put_script(
    app: axum::extract::State<Shared>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let Ok(input) = serde_json::from_slice::<SaveScript>(&body) else {
        return bad_request("invalid json");
    };
    if input.script.len() > MAX_SCRIPT_BYTES {
        return bad_request("The script is too large.");
    }
    if let Err(error) = rmail_sieve::Script::parse(&input.script) {
        return bad_request(format!("The script has an error: {error}"));
    }
    let result = blocking(move || {
        let current = load_filters(&state.db_path, &session.address)?;
        let name = current
            .script_name
            .unwrap_or_else(|| SCRIPT_NAME.to_string());
        db::put_sieve_script(&state.db_path, &session.address, &name, &input.script)?;
        db::set_active_sieve_script(&state.db_path, &session.address, Some(&name))?;
        load_filters(&state.db_path, &session.address)
    })
    .await;
    match result {
        Ok(filters) => Json(filters).into_response(),
        Err(error) => internal_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(conditions: Vec<Condition>, actions: Vec<Action>) -> Rule {
        Rule {
            name: "Newsletters".into(),
            enabled: true,
            any: false,
            conditions,
            actions,
            stop: false,
        }
    }

    fn from(value: &str) -> Condition {
        Condition {
            field: Field::From,
            header: String::new(),
            op: Op::Contains,
            value: value.into(),
        }
    }

    #[test]
    fn rules_become_sieve_that_parses_and_round_trips() {
        let rules = vec![
            rule(
                vec![
                    from("news@\"quoted\"\\.test"),
                    Condition {
                        field: Field::Size,
                        header: String::new(),
                        op: Op::Over,
                        value: "2m".into(),
                    },
                ],
                vec![
                    Action::Move {
                        folder: "Reading/News".into(),
                    },
                    Action::MarkRead,
                    Action::Label {
                        keyword: "newsletter".into(),
                    },
                ],
            ),
            Rule {
                any: true,
                stop: true,
                ..rule(
                    vec![
                        Condition {
                            field: Field::Header,
                            header: "List-Id".into(),
                            op: Op::NotContains,
                            value: "x".into(),
                        },
                        Condition {
                            field: Field::To,
                            header: String::new(),
                            op: Op::Is,
                            value: "me@example.test".into(),
                        },
                    ],
                    vec![
                        Action::Star,
                        Action::Forward {
                            address: "boss@example.test".into(),
                            keep: true,
                        },
                    ],
                )
            },
            Rule {
                enabled: false,
                ..rule(vec![from("spam")], vec![Action::Delete])
            },
        ];
        check(&rules).unwrap();
        let source = script(&rules);
        rmail_sieve::Script::parse(&source).unwrap();
        assert!(
            source.contains(r#"require ["imap4flags", "fileinto", "copy"];"#),
            "{source}"
        );
        assert!(source.contains(r#"header :contains "from" "news@\"quoted\"\\.test""#));
        assert!(source.contains("size :over 2M"));
        assert!(source.contains(r#"fileinto :flags ["\\Seen", "newsletter"] "Reading/News";"#));
        assert!(source.contains(r#"anyof(not header :contains "List-Id" "x", header :is ["to", "cc"] "me@example.test")"#));
        assert!(source.contains(r#"redirect :copy "boss@example.test";"#));
        assert!(source.contains("stop;"));
        assert!(!source.contains("discard"), "disabled rules are left out");
        assert_eq!(rules_of(&source), Some(rules));
        // An edit by hand makes it a script.
        assert_eq!(rules_of(&source.replace("stop;", "keep;")), None);
    }

    #[test]
    fn generated_filters_run_on_delivery() {
        let rules = vec![
            rule(
                vec![from("news@northwind.test")],
                vec![
                    Action::Move {
                        folder: "News".into(),
                    },
                    Action::MarkRead,
                ],
            ),
            rule(vec![from("@spam.test")], vec![Action::Delete]),
        ];
        let compiled = rmail_sieve::Script::parse(&script(&rules)).unwrap();
        let run = |raw: &[u8]| {
            compiled
                .run(&rmail_sieve::Message::new(
                    raw,
                    "a@b.test",
                    "me@example.test",
                ))
                .unwrap()
        };
        let actions = run(b"From: Northwind <news@northwind.test>\r\nSubject: hi\r\n\r\nbody");
        assert!(
            actions.contains(&rmail_sieve::Action::FileInto {
                folder: "News".into(),
                flags: vec!["\\Seen".into()],
            }),
            "{actions:?}"
        );
        assert!(run(b"From: x@spam.test\r\n\r\nbody").contains(&rmail_sieve::Action::Discard));
        assert!(matches!(
            run(b"From: friend@example.test\r\n\r\nbody").as_slice(),
            [rmail_sieve::Action::Keep { .. }]
        ));
    }

    /// Through the router: the out-of-office reply, rules, and a
    /// hand-written script that is not overwritten unasked.
    #[tokio::test]
    async fn vacation_and_filters_are_edited_through_the_api() {
        use super::super::tests::{req, route, state};
        use super::super::{SESSION_COOKIE, sign_session};
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        let cookie = Some(format!(
            "{SESSION_COOKIE}={}",
            sign_session(&state, "user@example.test")
        ));
        let call = |method: &'static str, path: &'static str, body: String| {
            let (state, cookie) = (state.clone(), cookie.clone());
            async move {
                let response = route(req(method, path, body.as_bytes(), cookie), &state).await;
                let json: serde_json::Value =
                    serde_json::from_slice(&response.body).unwrap_or_default();
                (response.status, json)
            }
        };

        let (status, vacation) = call("GET", "/api/vacation", String::new()).await;
        assert_eq!(status, 200);
        assert_eq!(vacation["enabled"], false);
        let (status, _) = call(
            "PUT",
            "/api/vacation",
            r#"{"enabled":true,"from":200,"until":100,"subject":"","text":"Away"}"#.into(),
        )
        .await;
        assert_eq!(status, 400, "ends before it starts");
        let (status, saved) = call(
            "PUT",
            "/api/vacation",
            r#"{"enabled":true,"from":null,"until":4102444800,"subject":"Away\nuntil Monday","text":"Back on Monday."}"#.into(),
        )
        .await;
        assert_eq!(status, 200, "{saved}");
        assert_eq!(saved["subject"], "Away until Monday");
        let stored = db::get_vacation_response(&state.db_path, "user@example.test").unwrap();
        assert!(stored.enabled && stored.text_body.as_deref() == Some("Back on Monday."));

        let (_, filters) = call("GET", "/api/filters", String::new()).await;
        assert_eq!(filters["mode"], "none");
        let rules = r#"{"rules":[{"name":"News","conditions":[{"field":"from","op":"contains","value":"news@"}],"actions":[{"type":"move","folder":"News"}]}]}"#;
        let (status, filters) = call("PUT", "/api/filters", rules.into()).await;
        assert_eq!(status, 200, "{filters}");
        assert_eq!(filters["mode"], "rules");
        assert_eq!(filters["rules"][0]["name"], "News");
        assert_eq!(filters["rules"][0]["enabled"], true);

        // A script uploaded over ManageSieve takes over.
        db::put_sieve_script(&state.db_path, "user@example.test", "mine", "keep;").unwrap();
        db::set_active_sieve_script(&state.db_path, "user@example.test", Some("mine")).unwrap();
        let (_, filters) = call("GET", "/api/filters", String::new()).await;
        assert_eq!(filters["mode"], "script");
        assert_eq!(filters["script"], "keep;");
        let (status, _) = call("PUT", "/api/filters", rules.into()).await;
        assert_eq!(status, 409, "not overwritten unasked");
        let (status, saved) = call(
            "PUT",
            "/api/filters/script",
            r#"{"script":"if header :contains \"subject\" \"x\" { discard }"}"#.into(),
        )
        .await;
        assert_eq!(status, 400, "a syntax error is refused: {saved}");
        assert!(saved["error"].as_str().unwrap().contains("line"));
        let (status, saved) = call(
            "PUT",
            "/api/filters/script",
            r#"{"script":"discard;"}"#.into(),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(saved["script_name"], "mine");
        let replace = rules.replace(r#"{"rules""#, r#"{"replace_script":true,"rules""#);
        let (status, filters) = call("PUT", "/api/filters", replace).await;
        assert_eq!(status, 200);
        assert_eq!(filters["mode"], "rules");
        assert_eq!(
            db::get_sieve_script(&state.db_path, "user@example.test", "mine")
                .unwrap()
                .as_deref(),
            Some("discard;"),
            "the hand-written script is kept, inactive"
        );
    }

    #[test]
    fn invalid_rules_are_refused() {
        let move_to = |folder: &str| Action::Move {
            folder: folder.into(),
        };
        assert!(check(&[rule(vec![from("a")], vec![])]).is_err());
        assert!(check(&[rule(vec![from("")], vec![move_to("A")])]).is_err());
        assert!(check(&[rule(vec![from("a\nb")], vec![move_to("A")])]).is_err());
        assert!(check(&[rule(vec![from("a")], vec![move_to("A"), move_to("B")])]).is_err());
        assert!(check(&[rule(vec![from("a")], vec![Action::Delete, Action::Star])]).is_err());
        assert!(
            check(&[rule(
                vec![Condition {
                    field: Field::Size,
                    header: String::new(),
                    op: Op::Contains,
                    value: "1M".into()
                }],
                vec![move_to("A")]
            )])
            .is_err()
        );
        assert!(
            check(&[rule(
                vec![Condition {
                    field: Field::Header,
                    header: "Bad:Name".into(),
                    op: Op::Contains,
                    value: "x".into()
                }],
                vec![move_to("A")]
            )])
            .is_err()
        );
        assert!(
            check(&[rule(
                vec![from("a")],
                vec![Action::Label {
                    keyword: "\\Seen".into()
                }]
            )])
            .is_err()
        );
        assert!(
            check(&[rule(
                vec![from("a")],
                vec![Action::Forward {
                    address: "not an address".into(),
                    keep: false
                }]
            )])
            .is_err()
        );
        assert!(valid_size("500K") && valid_size("2") && !valid_size("K") && !valid_size("1KM"));
    }
}
