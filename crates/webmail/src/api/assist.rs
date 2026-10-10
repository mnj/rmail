//! AI writing suggestions while composing: ghost-text continuations at the
//! cursor and rewrites of a selection, from the OpenAI-compatible endpoint
//! the admin configured (`compose_ai.*` settings, see
//! `rmail_common::compose_ai`). The browser talks only to this server; the
//! API key stays here.
//!
//! A request is answered only when the server has the feature enabled, the
//! user opted in (compose settings) and the user is within the per-minute
//! limit. The answer is streamed: whitespace every [`HEARTBEAT`] while the
//! provider works, then one JSON object (leading whitespace is valid JSON).
//! The connection is served with HTTP/1 half-close allowed, so the only way
//! to notice a browser that gave up (the user typed on) is a failed write;
//! the heartbeat makes that happen quickly, and dropping the body drops the
//! upstream request with it.

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use rmail_common::compose_ai::{self, Style, Task};
use rmail_common::compose_store;
use serde::Deserialize;

use super::{Session, Shared, blocking, internal_error};

/// Largest request accepted; the prompt is trimmed far below this anyway.
const MAX_REQUEST_BYTES: usize = 128 * 1024;
/// Whitespace written while waiting for the provider.
const HEARTBEAT: Duration = Duration::from_millis(250);
/// The window the per-minute limit counts in.
const WINDOW: Duration = Duration::from_secs(60);
/// Users tracked before idle entries are pruned.
const PRUNE_THRESHOLD: usize = 4096;

pub(crate) fn routes() -> Router<Shared> {
    Router::new().route("/api/compose/assist", post(assist))
}

/// Requests per user in a sliding window, like the sign-in throttle but
/// keyed by account.
#[derive(Debug, Default)]
pub(crate) struct Limiter {
    entries: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl Limiter {
    /// Count a request, or say how long until the next one is allowed.
    pub(crate) fn check(&self, user: &str, per_minute: u32) -> Result<(), Duration> {
        self.check_at(user, per_minute, Instant::now())
    }

    fn check_at(&self, user: &str, per_minute: u32, now: Instant) -> Result<(), Duration> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if entries.len() >= PRUNE_THRESHOLD {
            entries.retain(|_, times| {
                times
                    .back()
                    .is_some_and(|last| now.duration_since(*last) < WINDOW)
            });
        }
        let times = entries.entry(user.to_string()).or_default();
        while times
            .front()
            .is_some_and(|first| now.duration_since(*first) >= WINDOW)
        {
            times.pop_front();
        }
        if times.len() >= per_minute.max(1) as usize {
            let first = times.front().copied().unwrap_or(now);
            return Err(WINDOW.saturating_sub(now.duration_since(first)));
        }
        times.push_back(now);
        Ok(())
    }
}

#[derive(Deserialize)]
struct AssistRequest {
    /// `continue` or `rewrite`.
    kind: String,
    #[serde(default)]
    subject: String,
    /// Draft text before and after the cursor (continue).
    #[serde(default)]
    before: String,
    #[serde(default)]
    after: String,
    /// The quoted original of a reply (continue).
    #[serde(default)]
    quoted: String,
    /// The text to rewrite and how (rewrite).
    #[serde(default)]
    selection: String,
    #[serde(default)]
    style: String,
}

fn rejected(status: StatusCode, message: &str) -> Response {
    (status, message.to_string()).into_response()
}

/// The final JSON object of a streamed answer.
fn outcome(result: Result<String, compose_ai::Error>) -> Bytes {
    let value = match result {
        Ok(text) => serde_json::json!({ "text": text }),
        Err(error) => {
            // The kind and the provider's error code only: never the prompt,
            // and never the provider's message, which may quote the key.
            let (status, code) = match &error {
                compose_ai::Error::Status(status, code) => (Some(*status), code.clone()),
                _ => (None, None),
            };
            webmail_log!("warn", "compose_ai_failed", { "kind": error.kind(), "status": status, "code": code });
            serde_json::json!({ "error": error.kind(), "message": error.message() })
        }
    };
    Bytes::from(value.to_string())
}

type Pending = Pin<Box<dyn Future<Output = Result<String, compose_ai::Error>> + Send>>;

/// Heartbeats until `work` finishes, then its outcome. Dropping the stream
/// (the client went away) drops `work`.
fn streamed(work: Pending) -> Body {
    let stream = futures_util::stream::unfold(Some(work), |state| async move {
        let mut work = state?;
        tokio::select! {
            result = &mut work => Some((Ok::<_, Infallible>(outcome(result)), None)),
            _ = tokio::time::sleep(HEARTBEAT) => Some((Ok(Bytes::from_static(b" ")), Some(work))),
        }
    });
    Body::from_stream(stream)
}

async fn assist(app: State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let state = app.0;
    let session = match Session::signed_in(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    if body.len() > MAX_REQUEST_BYTES {
        return rejected(StatusCode::PAYLOAD_TOO_LARGE, "draft too large");
    }
    let Ok(input) = serde_json::from_slice::<AssistRequest>(&body) else {
        return rejected(StatusCode::BAD_REQUEST, "invalid json");
    };
    let task = match input.kind.as_str() {
        "continue" => Task::Continue {
            before: input.before,
            after: input.after,
        },
        "rewrite" => match Style::parse(&input.style) {
            Some(style) => Task::Rewrite {
                selection: input.selection,
                style,
            },
            None => return rejected(StatusCode::BAD_REQUEST, "unknown style"),
        },
        _ => return rejected(StatusCode::BAD_REQUEST, "unknown kind"),
    };
    let shared = state.clone();
    let address = session.address.clone();
    let loaded = blocking(move || {
        let conn = rmail_common::settings::open(&shared.db_path)?;
        let config = rmail_common::settings::compose_ai(&conn)?;
        let prefs = compose_store::prefs(&shared.mail_root, &session.domain, &session.localpart)?;
        Ok((config, prefs))
    })
    .await;
    let (config, prefs) = match loaded {
        Ok(loaded) => loaded,
        Err(error) => return internal_error(error),
    };
    if !config.available() {
        return rejected(
            StatusCode::CONFLICT,
            "writing suggestions are off on this server",
        );
    }
    if !prefs.ai_suggestions {
        return rejected(
            StatusCode::FORBIDDEN,
            "turn on writing suggestions in compose settings first",
        );
    }
    let request = compose_ai::Request::new(task, &input.subject, &input.quoted);
    if request.is_empty() {
        return axum::Json(serde_json::json!({ "text": "" })).into_response();
    }
    if let Err(wait) = state
        .assist_limiter
        .check(&address, config.requests_per_minute)
    {
        let mut response = rejected(
            StatusCode::TOO_MANY_REQUESTS,
            "too many writing suggestions; wait a moment",
        );
        if let Ok(value) = HeaderValue::from_str(&wait.as_secs().max(1).to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        return response;
    }
    let work: Pending = Box::pin(async move { compose_ai::complete(&config, &request).await });
    let mut response = Response::new(streamed(work));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    // Reverse proxies must pass heartbeats on for a closed browser to be
    // noticed.
    headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
    response
}

#[cfg(test)]
mod tests {
    use super::super::tests::{TestResponse, req, route, state};
    use super::super::{AppState, SESSION_COOKIE, sign_session};
    use super::*;
    use serde_json::{Value, json};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const KEY: &str = "sk-test-SECRET-4711";

    /// How the stand-in provider answers one connection.
    #[derive(Clone)]
    enum Answer {
        Reply(u16, String),
        /// Answer after a while.
        Slow(Duration, String),
        /// Never answer; report when the caller hangs up.
        Hang,
    }

    fn completion(text: &str) -> Answer {
        Answer::Reply(
            200,
            json!({"choices": [{"message": {"role": "assistant", "content": text}}]}).to_string(),
        )
    }

    /// A stand-in for an OpenAI-compatible endpoint: each connection gets the
    /// next scripted answer and its request (head and body) is recorded.
    struct FakeAi {
        base: String,
        requests: Arc<Mutex<Vec<String>>>,
        hung_up: tokio::sync::mpsc::UnboundedReceiver<()>,
    }

    impl FakeAi {
        fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }
    }

    async fn fake_ai(answers: Vec<Answer>) -> FakeAi {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/v1", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let answers = Arc::new(Mutex::new(VecDeque::from(answers)));
        let (tx, hung_up) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let answer = answers
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| completion("fallback"));
                let (recorded, tx) = (recorded.clone(), tx.clone());
                tokio::spawn(async move {
                    let mut data = Vec::new();
                    let mut buf = [0u8; 8192];
                    let head_end = loop {
                        let n = stream.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        data.extend_from_slice(&buf[..n]);
                        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                            break end + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&data[..head_end]).to_lowercase();
                    let length = head
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    while data.len() < head_end + length {
                        let n = stream.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        data.extend_from_slice(&buf[..n]);
                    }
                    recorded
                        .lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&data).to_string());
                    let (status, body) = match answer {
                        Answer::Reply(status, body) => (status, body),
                        Answer::Slow(wait, body) => {
                            tokio::time::sleep(wait).await;
                            (200, body)
                        }
                        Answer::Hang => {
                            while stream.read(&mut buf).await.is_ok_and(|n| n > 0) {}
                            let _ = tx.send(());
                            return;
                        }
                    };
                    let response = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        FakeAi {
            base,
            requests,
            hung_up,
        }
    }

    fn configure(state: &AppState, values: Value) {
        let mut conn = rmail_common::settings::open(&state.db_path).unwrap();
        let changes = values
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| (format!("compose_ai.{key}"), value.clone()))
            .collect();
        rmail_common::settings::update(&mut conn, &changes).unwrap();
    }

    fn cookie(state: &AppState) -> Option<String> {
        Some(format!(
            "{SESSION_COOKIE}={}",
            sign_session(state, "user@example.test")
        ))
    }

    async fn call(state: &Arc<AppState>, method: &str, path: &str, body: Value) -> TestResponse {
        let body = if body.is_null() {
            Vec::new()
        } else {
            body.to_string().into_bytes()
        };
        route(req(method, path, &body, cookie(state)), state).await
    }

    async fn opt_in(state: &Arc<AppState>) {
        let saved = call(
            state,
            "PUT",
            "/api/compose/settings",
            json!({"format": "html", "language": "", "undo_seconds": 0, "ai_suggestions": true}),
        )
        .await;
        assert_eq!(saved.status, 200);
    }

    fn parsed(response: &TestResponse) -> Value {
        serde_json::from_slice(&response.body)
            .unwrap_or_else(|_| panic!("not json: {}", String::from_utf8_lossy(&response.body)))
    }

    fn text(response: &TestResponse) -> String {
        String::from_utf8_lossy(&response.body).to_string()
    }

    fn user_prompt(raw_request: &str) -> String {
        let body = &raw_request[raw_request.find("\r\n\r\n").unwrap() + 4..];
        let value: Value = serde_json::from_str(body).unwrap();
        value["messages"][1]["content"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn suggestions_need_the_server_and_the_user_and_keep_the_key() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        let fake = fake_ai(vec![
            completion(" and the slides."),
            completion("\"Could you please send it?\""),
            Answer::Reply(
                401,
                json!({"error": {"message": format!("Incorrect API key provided: {KEY}"), "code": "invalid_api_key"}}).to_string(),
            ),
            Answer::Reply(200, "<html>bad gateway</html>".into()),
            Answer::Reply(200, json!({"choices": []}).to_string()),
            completion(&"x".repeat(100_000)),
        ])
        .await;
        let draft = json!({
            "kind": "continue",
            "subject": "Quarterly report",
            "before": format!("START-MARKER {}Thanks for the update", "filler ".repeat(1_000)),
            "after": "\n\nBest,\nUlla",
            "quoted": format!("Here is the report. {}QUOTE-TAIL", "more ".repeat(1_000)),
        });

        // Off by default: nothing to offer, nothing sent.
        let settings = parsed(&call(&state, "GET", "/api/compose/settings", Value::Null).await);
        assert_eq!(settings["ai"]["available"], false);
        assert_eq!(settings["ai_suggestions"], false);
        let off = call(&state, "POST", "/api/compose/assist", draft.clone()).await;
        assert_eq!(off.status, 409);

        configure(
            &state,
            json!({"enabled": true, "base_url": fake.base, "model": "tiny-model", "api_key": KEY}),
        );
        let settings = call(&state, "GET", "/api/compose/settings", Value::Null).await;
        assert!(!text(&settings).contains(KEY));
        let settings = parsed(&settings);
        assert_eq!(settings["ai"]["available"], true);
        assert_eq!(settings["ai"]["provider"], "127.0.0.1");

        // The server offers it, but this user has not opted in.
        let not_yet = call(&state, "POST", "/api/compose/assist", draft.clone()).await;
        assert_eq!(not_yet.status, 403);
        assert!(fake.requests().is_empty());

        opt_in(&state).await;
        let suggested = call(&state, "POST", "/api/compose/assist", draft.clone()).await;
        assert_eq!(suggested.status, 200);
        assert_eq!(suggested.header("x-accel-buffering"), "no");
        assert_eq!(parsed(&suggested)["text"], " and the slides.");
        assert!(!text(&suggested).contains(KEY));

        // The key went to the provider, and only a trimmed draft did.
        let sent = fake.requests();
        assert_eq!(sent.len(), 1);
        assert!(
            sent[0]
                .to_lowercase()
                .contains(&format!("authorization: bearer {}", KEY.to_lowercase()))
        );
        assert!(sent[0].starts_with("POST /v1/chat/completions "));
        let prompt = user_prompt(&sent[0]);
        assert!(prompt.contains("Thanks for the update"));
        assert!(prompt.contains("Subject: Quarterly report"));
        assert!(prompt.contains("Here is the report."));
        assert!(prompt.contains("Best,\nUlla"));
        assert!(
            !prompt.contains("START-MARKER"),
            "the far start of the draft is cut"
        );
        assert!(!prompt.contains("QUOTE-TAIL"), "the quote is cut");
        assert!(prompt.chars().count() < 4_600, "{}", prompt.chars().count());

        // An empty draft costs no request.
        let empty = call(
            &state,
            "POST",
            "/api/compose/assist",
            json!({"kind": "continue", "before": "  "}),
        )
        .await;
        assert_eq!(parsed(&empty)["text"], "");
        assert_eq!(fake.requests().len(), 1);

        // Rewrites.
        let bad_style = call(
            &state,
            "POST",
            "/api/compose/assist",
            json!({"kind": "rewrite", "selection": "hey", "style": "pirate"}),
        )
        .await;
        assert_eq!(bad_style.status, 400);
        let rewrite = json!({"kind": "rewrite", "selection": "hey can u send it", "style": "formal", "quoted": "SECRET QUOTE"});
        let rewritten = call(&state, "POST", "/api/compose/assist", rewrite.clone()).await;
        assert_eq!(parsed(&rewritten)["text"], "Could you please send it?");
        let prompt = user_prompt(&fake.requests()[1]);
        assert!(prompt.contains("hey can u send it"));
        assert!(
            !prompt.contains("SECRET QUOTE"),
            "rewrites send the selection only"
        );

        // Provider failures come back by kind; the provider's message (which
        // here quotes the key) never reaches the browser.
        let refused = call(&state, "POST", "/api/compose/assist", rewrite.clone()).await;
        assert_eq!(refused.status, 200);
        assert_eq!(parsed(&refused)["error"], "upstream_status");
        assert!(!text(&refused).contains(KEY));
        for _ in 0..3 {
            let malformed = call(&state, "POST", "/api/compose/assist", rewrite.clone()).await;
            assert_eq!(
                parsed(&malformed)["error"],
                "malformed",
                "{}",
                text(&malformed)
            );
        }
    }

    #[tokio::test]
    async fn slow_providers_time_out() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        let fake = fake_ai(vec![Answer::Slow(
            Duration::from_secs(5),
            json!({"choices": [{"message": {"content": "late"}}]}).to_string(),
        )])
        .await;
        configure(
            &state,
            json!({"enabled": true, "base_url": fake.base, "model": "m", "timeout_ms": 500}),
        );
        opt_in(&state).await;
        let started = Instant::now();
        let response = call(
            &state,
            "POST",
            "/api/compose/assist",
            json!({"kind": "continue", "before": "Dear Ann,"}),
        )
        .await;
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(parsed(&response)["error"], "timeout");
        assert!(
            text(&response).starts_with(' '),
            "heartbeats were written while waiting"
        );
        let sent = fake.requests();
        assert!(
            !sent[0].to_lowercase().contains("authorization:"),
            "no key, no header"
        );
    }

    #[tokio::test]
    async fn suggestions_are_rate_limited_per_user() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        let fake = fake_ai(vec![]).await;
        configure(
            &state,
            json!({"enabled": true, "base_url": fake.base, "model": "m", "requests_per_minute": 2}),
        );
        opt_in(&state).await;
        let draft = json!({"kind": "continue", "before": "Dear Ann,"});
        for _ in 0..2 {
            let ok = call(&state, "POST", "/api/compose/assist", draft.clone()).await;
            assert_eq!(parsed(&ok)["text"], " fallback");
        }
        let limited = call(&state, "POST", "/api/compose/assist", draft.clone()).await;
        assert_eq!(limited.status, 429);
        let retry: u64 = limited.header("retry-after").parse().unwrap();
        assert!((1..=60).contains(&retry));
        assert_eq!(fake.requests().len(), 2);
    }

    /// A browser that stops waiting (the user typed on) closes its
    /// connection; the provider request must end with it.
    #[tokio::test]
    async fn abandoned_suggestions_drop_the_provider_request() {
        let td = tempfile::tempdir().unwrap();
        let state = state(&td);
        let mut fake = fake_ai(vec![Answer::Hang]).await;
        configure(
            &state,
            json!({"enabled": true, "base_url": fake.base, "model": "m", "timeout_ms": 30_000}),
        );
        opt_in(&state).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = super::super::router(state.clone());
        tokio::spawn(async move {
            loop {
                let (stream, peer) = listener.accept().await.unwrap();
                let app = app.clone();
                tokio::spawn(async move {
                    let _ =
                        rmail_common::http::serve_connection(stream, Some(peer), app, None).await;
                });
            }
        });
        let body = json!({"kind": "continue", "before": "Dear Ann,"}).to_string();
        let mut browser = tokio::net::TcpStream::connect(address).await.unwrap();
        let request = format!(
            "POST /api/compose/assist HTTP/1.1\r\nHost: mail.example.test\r\nCookie: {}\r\nX-Rmail-Webmail: 1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            cookie(&state).unwrap(),
            body.len()
        );
        browser.write_all(request.as_bytes()).await.unwrap();
        let mut seen = Vec::new();
        let mut buf = [0u8; 1024];
        while !String::from_utf8_lossy(&seen).contains("\r\n\r\n") {
            let n = browser.read(&mut buf).await.unwrap();
            assert!(n > 0, "server closed early");
            seen.extend_from_slice(&buf[..n]);
        }
        assert!(String::from_utf8_lossy(&seen).starts_with("HTTP/1.1 200"));
        let asked = Instant::now();
        while fake.requests().is_empty() {
            assert!(
                asked.elapsed() < Duration::from_secs(5),
                "the provider was not asked"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        drop(browser);
        tokio::time::timeout(Duration::from_secs(5), fake.hung_up.recv())
            .await
            .expect("the provider request should end when the browser leaves")
            .unwrap();
    }

    #[test]
    fn limiter_counts_per_user_in_a_sliding_window() {
        let limiter = Limiter::default();
        let start = Instant::now();
        assert!(limiter.check_at("ann@x.test", 2, start).is_ok());
        assert!(
            limiter
                .check_at("ann@x.test", 2, start + Duration::from_secs(10))
                .is_ok()
        );
        let wait = limiter
            .check_at("ann@x.test", 2, start + Duration::from_secs(20))
            .unwrap_err();
        assert_eq!(wait, Duration::from_secs(40));
        assert!(limiter.check_at("bob@x.test", 2, start).is_ok(), "per user");
        assert!(limiter.check_at("ann@x.test", 2, start + WINDOW).is_ok());
    }
}
