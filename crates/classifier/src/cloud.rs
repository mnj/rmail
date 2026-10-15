//! Hosted models: embeddings and chat from any OpenAI-compatible API
//! (OpenRouter by default, or OpenAI's own), chat from Anthropic's Messages
//! API, and TypeSafe's Jev decision model.
//!
//! These send message text to a third party. The worker only uses them for
//! accounts whose users agreed to that provider in webmail.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use crate::engine::{Choice, Chooser, Embedder, FolderHint, LabelHint, Labeling, l2_normalize};
use crate::prompt::{
    SUMMARY_PROMPT, label_prompt, parse_answer, parse_labels, quoted_examples, system_prompt,
    tidy_summary,
};

pub const TYPESAFE_API: &str = "https://api.typesafe.ai/v1";
pub const OPENAI_API: &str = "https://api.openai.com/v1";
pub const ANTHROPIC_API: &str = "https://api.anthropic.com/v1";

const TIMEOUT: Duration = Duration::from_secs(60);
const ATTEMPTS: u32 = 3;
/// Longest wait honoured from a Retry-After header.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(10);
/// Flex requests queue at the provider; OpenAI suggests a 15 minute timeout.
const FLEX_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// Flex attempts refused for lack of capacity before the standard tier.
const FLEX_ATTEMPTS: u32 = 4;
/// The first pause between attempts; it doubles each time.
const BACKOFF: Duration = if cfg!(test) {
    Duration::from_millis(5)
} else {
    Duration::from_secs(1)
};
/// Jev option that means no folder fits; folder options are `f1`, `f2`, ...
const JEV_NONE: &str = "none";

/// How an endpoint takes its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Auth {
    Bearer,
    /// `x-api-key` and the API version header (Anthropic).
    Anthropic,
}

/// What one request came to.
enum Sent {
    Done(Value),
    /// Rate limited, overloaded or a server error: worth another try.
    Retry(anyhow::Error, Option<Duration>),
    /// No answer: the connection failed or timed out.
    Transport(anyhow::Error),
    /// Refused with this status, or an unreadable answer (no status).
    Failed(anyhow::Error, Option<u16>),
}

/// A JSON-over-HTTPS endpoint with a key, retried on rate limits and
/// server errors.
struct Api {
    client: reqwest::blocking::Client,
    base: String,
    key: String,
    auth: Auth,
}

impl Api {
    fn new(base: &str, key: &str) -> Result<Self> {
        Self::with_auth(base, key, Auth::Bearer)
    }

    fn with_auth(base: &str, key: &str, auth: Auth) -> Result<Self> {
        if key.trim().is_empty() {
            bail!("no API key is set");
        }
        Ok(Self {
            client: reqwest::blocking::Client::builder()
                .timeout(TIMEOUT)
                .user_agent(concat!("rmail_classifier/", env!("CARGO_PKG_VERSION")))
                .build()?,
            base: base.trim_end_matches('/').to_string(),
            key: key.trim().to_string(),
            auth,
        })
    }

    fn send(&self, path: &str, body: &Value, timeout: Duration) -> Sent {
        let url = format!("{}{path}", self.base);
        let request = self.client.post(&url).timeout(timeout).json(body);
        let request = match self.auth {
            Auth::Bearer => request
                .bearer_auth(&self.key)
                // OpenRouter shows these on its activity page; others ignore them.
                .header("X-Title", "rMail"),
            Auth::Anthropic => request
                .header("x-api-key", &self.key)
                .header("anthropic-version", "2023-06-01"),
        };
        let response = match request.send() {
            Ok(response) => response,
            Err(error) => return Sent::Transport(anyhow!("{url}: {error}")),
        };
        let status = response.status();
        if status.is_success() {
            return match response.json::<Value>() {
                Ok(value) => Sent::Done(value),
                Err(error) => Sent::Failed(anyhow!("{url}: reading response: {error}"), None),
            };
        }
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()?.parse::<u64>().ok())
            .map(Duration::from_secs);
        let text = response.text().unwrap_or_default();
        let error = anyhow!("{url}: HTTP {status}: {}", error_message(&text));
        // 529 is TypeSafe's and Anthropic's "overloaded".
        if status.as_u16() == 429 || status.as_u16() == 529 || status.is_server_error() {
            Sent::Retry(error, retry_after)
        } else {
            Sent::Failed(error, Some(status.as_u16()))
        }
    }

    /// Send with `attempts` tries and growing pauses between them; with
    /// `transport`, failed connections are tried again too.
    fn retried(
        &self,
        path: &str,
        body: &Value,
        timeout: Duration,
        attempts: u32,
        transport: bool,
    ) -> Sent {
        let mut last = Sent::Failed(anyhow!("no attempt made"), None);
        for attempt in 0..attempts {
            if attempt > 0 {
                let pause = match &last {
                    Sent::Retry(_, Some(wait)) => (*wait).min(MAX_RETRY_AFTER),
                    _ => BACKOFF * (1 << (attempt - 1)),
                };
                std::thread::sleep(pause);
            }
            last = self.send(path, body, timeout);
            if !(matches!(last, Sent::Retry(..)) || transport && matches!(last, Sent::Transport(_)))
            {
                break;
            }
        }
        last
    }

    fn post(&self, path: &str, body: &Value) -> Result<Value> {
        match self.retried(path, body, TIMEOUT, ATTEMPTS, true) {
            Sent::Done(value) => Ok(value),
            Sent::Retry(error, _) | Sent::Transport(error) | Sent::Failed(error, _) => Err(error),
        }
    }

    /// OpenAI flex processing: billed at batch rates, but queued and refused
    /// with 429 when capacity is short (those are not billed). Those and
    /// server errors are retried, then the request goes out at the standard
    /// tier so the work still gets done. A 400 (a model without the flex
    /// tier) or no answer at all (a flex request that timed out) goes to the
    /// standard tier at once, so one slow request cannot hold up the cycle
    /// for the whole retry budget. Other refusals, such as a bad key, would
    /// fail at the standard tier too and are returned as they are.
    fn post_flex(&self, path: &str, body: &Value) -> Result<Value> {
        let mut flex = body.clone();
        flex["service_tier"] = Value::from("flex");
        match self.retried(path, &flex, FLEX_TIMEOUT, FLEX_ATTEMPTS, false) {
            Sent::Done(value) => Ok(value),
            Sent::Retry(..) | Sent::Transport(_) | Sent::Failed(_, Some(400)) => {
                self.post(path, body)
            }
            Sent::Failed(error, _) => Err(error),
        }
    }
}

/// The provider's error message, or the start of the body.
fn error_message(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| {
            let error = value.get("error").unwrap_or(&value);
            error
                .get("message")
                .or_else(|| error.get("detail"))
                .and_then(Value::as_str)
                .or_else(|| error.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| body.chars().take(300).collect())
}

// ---------------------------------------------------------------------------
// OpenAI-compatible (OpenRouter)

pub struct OpenAiEmbedder {
    api: Api,
    model: String,
    id: String,
}

impl OpenAiEmbedder {
    pub fn load(base: &str, key: &str, model: &str) -> Result<Self> {
        if model.trim().is_empty() {
            bail!("no embedding model id is set");
        }
        let embedder = Self {
            api: Api::new(base, key)?,
            model: model.trim().to_string(),
            // Vectors from another endpoint or model are a different space.
            id: format!("api:{}#{}", base.trim_end_matches('/'), model.trim()),
        };
        // Fail at load time, on the console, rather than on the first message.
        embedder.embed(&["probe".to_string()])?;
        Ok(embedder)
    }
}

impl Embedder for OpenAiEmbedder {
    fn model_id(&self) -> &str {
        &self.id
    }

    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>> {
        let response = self.api.post(
            "/embeddings",
            &json!({ "model": self.model, "input": texts }),
        )?;
        let mut data: Vec<(u64, Vec<f32>)> = response["data"]
            .as_array()
            .context("embedding response has no data")?
            .iter()
            .enumerate()
            .map(|(position, item)| {
                let index = item["index"].as_u64().unwrap_or(position as u64);
                let vector = item["embedding"]
                    .as_array()
                    .context("embedding is not an array")?
                    .iter()
                    .map(|v| {
                        v.as_f64()
                            .map(|v| v as f32)
                            .context("embedding is not numeric")
                    })
                    .collect::<Result<Vec<f32>>>()?;
                Ok((index, vector))
            })
            .collect::<Result<_>>()?;
        if data.len() != texts.len() {
            bail!("asked for {} embeddings, got {}", texts.len(), data.len());
        }
        data.sort_by_key(|(index, _)| *index);
        Ok(data
            .into_iter()
            .map(|(_, mut vector)| {
                l2_normalize(&mut vector);
                vector
            })
            .collect())
    }
}

pub struct OpenAiChooser {
    api: Api,
    model: String,
    /// Send at OpenAI's flex tier (background work only).
    flex: bool,
}

impl OpenAiChooser {
    pub fn load(base: &str, key: &str, model: &str) -> Result<Self> {
        if model.trim().is_empty() {
            bail!("no chat model id is set");
        }
        Ok(Self {
            api: Api::new(base, key)?,
            model: model.trim().to_string(),
            flex: false,
        })
    }

    /// The same model at the flex tier, for calls nobody waits for.
    pub fn flex(mut self) -> Self {
        self.flex = true;
        self
    }
}

impl Chooser for OpenAiChooser {
    fn choose(&self, message: &str, folders: &[FolderHint]) -> Result<Choice> {
        if folders.is_empty() {
            return Ok(no_choice());
        }
        let mut names: Vec<Value> = folders
            .iter()
            .map(|f| Value::from(f.name.clone()))
            .collect();
        names.push(Value::Null);
        let body = json!({
            "model": self.model,
            "temperature": 0,
            "max_tokens": 200,
            "messages": [
                { "role": "system", "content": system_prompt(folders) },
                { "role": "user", "content": message },
            ],
            // Models without structured outputs ignore this; parse_answer
            // still reads their JSON.
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "folder_choice",
                    "strict": true,
                    "schema": {
                        "type": "object",
                        "properties": {
                            "folder": { "type": ["string", "null"], "enum": names },
                            "confidence": { "type": "number" },
                        },
                        "required": ["folder", "confidence"],
                        "additionalProperties": false,
                    },
                },
            },
        });
        Ok(parse_answer(&self.complete(body)?, folders))
    }

    fn label(&self, message: &str, labels: &[LabelHint], may_propose: bool) -> Result<Labeling> {
        if labels.is_empty() && !may_propose {
            return Ok(Labeling::default());
        }
        let schema = labels_schema(labels, may_propose);
        let body = json!({
            "model": self.model,
            "temperature": 0,
            "max_tokens": 400,
            "messages": [
                { "role": "system", "content": label_prompt(labels, may_propose) },
                { "role": "user", "content": message },
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "labels",
                    "strict": true,
                    "schema": schema,
                },
            },
        });
        Ok(parse_labels(&self.complete(body)?, labels, may_propose))
    }

    fn summarize(&self, message: &str) -> Result<String> {
        let body = json!({
            "model": self.model,
            "temperature": 0.2,
            "max_tokens": 220,
            "messages": [
                { "role": "system", "content": SUMMARY_PROMPT },
                { "role": "user", "content": message },
            ],
        });
        Ok(tidy_summary(&self.complete(body)?))
    }
}

impl OpenAiChooser {
    fn complete(&self, body: Value) -> Result<String> {
        let response = if self.flex {
            self.api.post_flex("/chat/completions", &body)?
        } else {
            self.api.post("/chat/completions", &body)?
        };
        Ok(response["choices"][0]["message"]["content"]
            .as_str()
            .context("chat response has no message content")?
            .to_string())
    }
}

/// The JSON schema of a labeling answer: known label names with a
/// confidence each and, when allowed, one proposed new label or null.
fn labels_schema(labels: &[LabelHint], may_propose: bool) -> Value {
    let names: Vec<&str> = labels.iter().map(|label| label.name.as_str()).collect();
    let name_schema = if names.is_empty() {
        json!({ "type": "string" })
    } else {
        json!({ "type": "string", "enum": names })
    };
    let mut properties = json!({
        "labels": {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
            "name": name_schema,
            "confidence": { "type": "number" },
            },
            "required": ["name", "confidence"],
            "additionalProperties": false,
        },
        },
    });
    let mut required = vec!["labels"];
    if may_propose {
        properties["new_label"] = json!({
        "anyOf": [
            { "type": "null" },
            {
            "type": "object",
            "properties": {
                "name": { "type": "string" },
                "description": { "type": "string" },
            },
            "required": ["name", "description"],
            "additionalProperties": false,
            },
        ],
        });
        required.push("new_label");
    }
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
    })
}

// ---------------------------------------------------------------------------
// Anthropic

/// Claude through Anthropic's Messages API. Answers are constrained to the
/// same schemas as the OpenAI-compatible chooser (`output_config.format`).
/// No sampling parameters are sent (current models reject them); a low
/// effort keeps thinking short, with room in `max_tokens` for it.
pub struct AnthropicChooser {
    api: Api,
    model: String,
}

impl AnthropicChooser {
    pub fn load(base: &str, key: &str, model: &str) -> Result<Self> {
        if model.trim().is_empty() {
            bail!("no chat model id is set");
        }
        Ok(Self {
            api: Api::with_auth(base, key, Auth::Anthropic)?,
            model: model.trim().to_string(),
        })
    }

    fn request(
        &self,
        system: &str,
        message: &str,
        answer_tokens: u32,
        schema: Option<Value>,
    ) -> Value {
        let mut output = json!({ "effort": "low" });
        if let Some(schema) = schema {
            output["format"] = json!({ "type": "json_schema", "schema": schema });
        }
        json!({
            "model": self.model,
            // Thinking, if the model does any, counts against this too.
            "max_tokens": answer_tokens + 2_048,
            "system": system,
            "messages": [{ "role": "user", "content": message }],
            "output_config": output,
        })
    }

    fn complete(&self, body: Value) -> Result<String> {
        let response = self.api.post("/messages", &body)?;
        match response["stop_reason"].as_str() {
            Some("refusal") => bail!("the model declined to answer"),
            Some("max_tokens") => bail!("the answer was cut off at the token limit"),
            _ => {}
        }
        let text: String = response["content"]
            .as_array()
            .context("message has no content")?
            .iter()
            .filter(|block| block["type"] == "text")
            .filter_map(|block| block["text"].as_str())
            .collect();
        Ok(text)
    }
}

impl Chooser for AnthropicChooser {
    fn choose(&self, message: &str, folders: &[FolderHint]) -> Result<Choice> {
        if folders.is_empty() {
            return Ok(no_choice());
        }
        let mut names: Vec<Value> = folders
            .iter()
            .map(|f| Value::from(f.name.clone()))
            .collect();
        names.push(Value::Null);
        let schema = json!({
            "type": "object",
            "properties": {
                "folder": { "enum": names },
                "confidence": { "type": "number" },
            },
            "required": ["folder", "confidence"],
            "additionalProperties": false,
        });
        let body = self.request(&system_prompt(folders), message, 200, Some(schema));
        Ok(parse_answer(&self.complete(body)?, folders))
    }

    fn label(&self, message: &str, labels: &[LabelHint], may_propose: bool) -> Result<Labeling> {
        if labels.is_empty() && !may_propose {
            return Ok(Labeling::default());
        }
        let body = self.request(
            &label_prompt(labels, may_propose),
            message,
            400,
            Some(labels_schema(labels, may_propose)),
        );
        Ok(parse_labels(&self.complete(body)?, labels, may_propose))
    }

    fn summarize(&self, message: &str) -> Result<String> {
        let body = self.request(SUMMARY_PROMPT, message, 220, None);
        Ok(tidy_summary(&self.complete(body)?))
    }
}

// ---------------------------------------------------------------------------
// TypeSafe Jev

/// Asks Jev one choice question: which folder, or none. Jev only picks from
/// the options and returns a probability for each, so there is no output to
/// parse or invent.
pub struct JevChooser {
    api: Api,
    model: String,
}

impl JevChooser {
    pub fn load(base: &str, key: &str, model: &str) -> Result<Self> {
        Ok(Self {
            api: Api::new(base, key)?,
            model: if model.trim().is_empty() {
                "jev-latest".to_string()
            } else {
                model.trim().to_string()
            },
        })
    }

    fn request(&self, message: &str, folders: &[FolderHint]) -> Value {
        let mut criteria = serde_json::Map::new();
        for (index, folder) in folders.iter().enumerate() {
            let mut description = format!("The folder named \"{}\"", folder.name);
            if !folder.examples.is_empty() {
                description.push_str(", which holds mail such as ");
                description.push_str(&quoted_examples(folder));
            }
            criteria.insert(format!("f{}", index + 1), Value::from(description));
        }
        criteria.insert(
            JEV_NONE.to_string(),
            Value::from("None of these folders clearly fits; leave the message in the inbox"),
        );
        json!({
            "model": self.model,
            "state": message,
            "questions": {
                "folder": {
                    "type": "choice",
                    "instructions": "Which of the user's mail folders does this email belong in?",
                    "criteria": criteria,
                },
            },
        })
    }
}

impl Chooser for JevChooser {
    fn choose(&self, message: &str, folders: &[FolderHint]) -> Result<Choice> {
        if folders.is_empty() {
            return Ok(no_choice());
        }
        let response = self
            .api
            .post("/systemone", &self.request(message, folders))?;
        let answer = &response["answers"]["folder"];
        let picked = answer["choice"]
            .as_str()
            .context("Jev response has no choice")?;
        let folder = picked
            .strip_prefix('f')
            .and_then(|n| n.parse::<usize>().ok())
            .and_then(|n| folders.get(n.wrapping_sub(1)))
            .map(|hint| hint.name.clone());
        let confidence = answer["confidence"]
            .as_f64()
            .or_else(|| answer["probabilities"][picked].as_f64())
            .unwrap_or(0.0)
            .clamp(0.0, 1.0);
        Ok(Choice {
            confidence: if folder.is_some() { confidence } else { 0.0 },
            folder,
            raw: answer.to_string(),
        })
    }

    /// One yes/no ("noul") question per label; Jev answers each with a
    /// probability and evaluates them in parallel. Jev only picks from what
    /// it is given, so it never proposes labels.
    fn label(&self, message: &str, labels: &[LabelHint], _may_propose: bool) -> Result<Labeling> {
        if labels.is_empty() {
            return Ok(Labeling::default());
        }
        let questions: serde_json::Map<String, Value> = labels
            .iter()
            .enumerate()
            .map(|(index, label)| {
                let mut instructions =
                    format!("Does the label \"{}\" apply to this email?", label.name);
                if !label.description.is_empty() {
                    instructions.push_str(" The label means: ");
                    instructions.push_str(&label.description);
                }
                (
                    format!("l{}", index + 1),
                    json!({ "type": "noul", "instructions": instructions }),
                )
            })
            .collect();
        let response = self.api.post(
            "/systemone",
            &json!({ "model": self.model, "state": message, "questions": questions }),
        )?;
        let labels = labels
            .iter()
            .enumerate()
            .filter_map(|(index, label)| {
                let probability =
                    response["answers"][format!("l{}", index + 1)]["noul"].as_f64()?;
                Some((label.name.clone(), probability.clamp(0.0, 1.0)))
            })
            .collect();
        Ok(Labeling {
            labels,
            proposed: None,
        })
    }
}

fn no_choice() -> Choice {
    Choice {
        folder: None,
        confidence: 0.0,
        raw: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::hints;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    /// Serve canned responses on loopback, one per connection, and pass each
    /// request's authorization header and JSON body back to the test.
    fn serve(responses: Vec<(u16, String)>) -> (String, mpsc::Receiver<(String, Value)>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for (status, body) in responses {
                let (stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let (mut length, mut auth) = (0usize, String::new());
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let lower = line.to_ascii_lowercase();
                    if let Some(value) = lower.strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap();
                    }
                    if lower.starts_with("authorization:") {
                        auth = line["authorization:".len()..].trim().to_string();
                    }
                    if lower.starts_with("x-api-key:") {
                        auth = format!("x-api-key {}", line["x-api-key:".len()..].trim());
                    }
                    if line == "\r\n" {
                        break;
                    }
                }
                let mut request = vec![0; length];
                reader.read_exact(&mut request).unwrap();
                tx.send((
                    auth,
                    serde_json::from_slice(&request).unwrap_or(Value::Null),
                ))
                .unwrap();
                let mut stream = stream;
                write!(
                    stream,
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        (base, rx)
    }

    #[test]
    fn embeddings_are_ordered_and_normalised() {
        let probe = json!({"data": [{"index": 0, "embedding": [3.0, 4.0]}]}).to_string();
        let batch = json!({"data": [
            {"index": 1, "embedding": [0.0, 2.0]},
            {"index": 0, "embedding": [5.0, 0.0]},
        ]})
        .to_string();
        let (base, requests) = serve(vec![(200, probe), (200, batch)]);
        let embedder =
            OpenAiEmbedder::load(&base, "sk-test", "openai/text-embedding-3-small").unwrap();
        let (auth, probe_request) = requests.recv().unwrap();
        assert_eq!(auth, "Bearer sk-test");
        assert_eq!(probe_request["model"], "openai/text-embedding-3-small");
        assert!(
            embedder
                .model_id()
                .ends_with("#openai/text-embedding-3-small")
        );

        let vectors = embedder.embed(&["a".into(), "b".into()]).unwrap();
        assert_eq!(vectors, vec![vec![1.0, 0.0], vec![0.0, 1.0]]);
        assert_eq!(requests.recv().unwrap().1["input"], json!(["a", "b"]));
    }

    #[test]
    fn chat_choice_constrains_answers_to_the_folders() {
        let reply = json!({"choices": [{"message": {"content": "{\"folder\": \"Travel\", \"confidence\": 0.9}"}}]});
        let (base, requests) = serve(vec![(200, reply.to_string())]);
        let chooser = OpenAiChooser::load(&base, "sk-test", "some/model").unwrap();
        let choice = chooser
            .choose("Your boarding pass", &hints(&["Receipts", "Travel"]))
            .unwrap();
        assert_eq!(choice.folder.as_deref(), Some("Travel"));
        assert_eq!(choice.confidence, 0.9);
        let (_, request) = requests.recv().unwrap();
        assert_eq!(request["messages"][1]["content"], "Your boarding pass");
        assert_eq!(
            request["response_format"]["json_schema"]["schema"]["properties"]["folder"]["enum"],
            json!(["Receipts", "Travel", null])
        );
    }

    #[test]
    fn jev_options_map_back_to_folder_names() {
        let reply = json!({
            "model": "jev-1.13.0",
            "answers": {"folder": {"type": "choice", "choice": "f2",
                "probabilities": {"f1": 0.05, "f2": 0.9, "none": 0.05}, "confidence": 0.87}},
            "usage": {"input_tokens": 120, "output_tokens": 4},
        });
        let none =
            json!({"answers": {"folder": {"type": "choice", "choice": "none", "confidence": 0.8}}});
        let (base, requests) = serve(vec![(200, reply.to_string()), (200, none.to_string())]);
        let chooser = JevChooser::load(&base, "ts-test", "").unwrap();
        let folders = hints(&["Receipts", "Rejser/Fly \"2026\""]);
        let choice = chooser.choose("Boarding pass", &folders).unwrap();
        assert_eq!(choice.folder.as_deref(), Some("Rejser/Fly \"2026\""));
        assert_eq!(choice.confidence, 0.87);

        let (auth, request) = requests.recv().unwrap();
        assert_eq!(auth, "Bearer ts-test");
        assert_eq!(request["model"], "jev-latest");
        assert_eq!(request["state"], "Boarding pass");
        let question = &request["questions"]["folder"];
        assert_eq!(question["type"], "choice");
        let criteria = question["criteria"].as_object().unwrap();
        assert_eq!(criteria.len(), 3);
        assert!(
            criteria["f2"]
                .as_str()
                .unwrap()
                .contains("Rejser/Fly \"2026\"")
        );
        assert!(criteria.contains_key(JEV_NONE));

        let declined = chooser.choose("Hello", &folders).unwrap();
        assert_eq!(declined.folder, None);
        assert_eq!(declined.confidence, 0.0);
    }

    #[test]
    fn jev_labels_are_one_yes_no_question_each() {
        let reply = json!({"answers": {
            "l1": {"type": "noul", "noul": 0.93},
            "l2": {"type": "noul", "noul": 0.04},
        }});
        let (base, requests) = serve(vec![(200, reply.to_string())]);
        let chooser = JevChooser::load(&base, "k", "").unwrap();
        let labels = crate::prompt::label_hints(&["Invoices", "Family"]);
        let result = chooser.label("Invoice 42 is due", &labels, true).unwrap();
        assert_eq!(
            result.labels,
            vec![("Invoices".to_string(), 0.93), ("Family".to_string(), 0.04)]
        );
        assert_eq!(result.proposed, None, "Jev never proposes");
        let (_, request) = requests.recv().unwrap();
        assert_eq!(request["questions"]["l1"]["type"], "noul");
        assert!(
            request["questions"]["l2"]["instructions"]
                .as_str()
                .unwrap()
                .contains("\"Family\" apply to this email? The label means: about Family")
        );
    }

    #[test]
    fn chat_labels_use_a_schema_of_known_names() {
        let reply = json!({"choices": [{"message": {"content":
            "{\"labels\": [{\"name\": \"Family\", \"confidence\": 0.8}, {\"name\": \"Made up\", \"confidence\": 1}]}"}}]});
        let (base, requests) = serve(vec![(200, reply.to_string())]);
        let chooser = OpenAiChooser::load(&base, "k", "m").unwrap();
        let labels = crate::prompt::label_hints(&["Invoices", "Family"]);
        assert_eq!(
            chooser
                .label("Dinner on Sunday?", &labels, false)
                .unwrap()
                .labels,
            vec![("Family".to_string(), 0.8)]
        );
        let (_, request) = requests.recv().unwrap();
        assert_eq!(
            request["response_format"]["json_schema"]["schema"]["properties"]["labels"]["items"]["properties"]
                ["name"]["enum"],
            json!(["Invoices", "Family"])
        );
    }

    #[test]
    fn chat_labels_may_propose_a_new_label() {
        let reply = json!({"choices": [{"message": {"content":
            "{\"labels\": [], \"new_label\": {\"name\": \"School\", \"description\": \"The kids' school\"}}"}}]});
        let (base, requests) = serve(vec![(200, reply.to_string())]);
        let chooser = OpenAiChooser::load(&base, "k", "m").unwrap();
        let labels = crate::prompt::label_hints(&["Invoices"]);
        let result = chooser
            .label("Parent evening on Tuesday", &labels, true)
            .unwrap();
        assert_eq!(
            result.proposed,
            Some(("School".into(), "The kids' school".into()))
        );
        let (_, request) = requests.recv().unwrap();
        let schema = &request["response_format"]["json_schema"]["schema"];
        assert_eq!(schema["required"], json!(["labels", "new_label"]));
        assert!(schema["properties"]["new_label"]["anyOf"].is_array());
    }

    #[test]
    fn chat_summaries_are_plain_text_and_jev_declines() {
        let reply =
            json!({"choices": [{"message": {"content": "Summary: Invoice 42 is due Friday."}}]});
        let (base, requests) = serve(vec![(200, reply.to_string())]);
        let chooser = OpenAiChooser::load(&base, "k", "m").unwrap();
        assert_eq!(chooser.summarize("…").unwrap(), "Invoice 42 is due Friday.");
        let (_, request) = requests.recv().unwrap();
        assert!(request.get("response_format").is_none());
        assert_eq!(request["messages"][0]["content"], SUMMARY_PROMPT);
        let jev = JevChooser::load(TYPESAFE_API, "k", "").unwrap();
        assert!(jev.summarize("…").is_err());
    }

    #[test]
    fn rate_limits_are_retried_and_errors_explained() {
        let ok = json!({"answers": {"folder": {"choice": "f1", "confidence": 0.7}}});
        let (base, _requests) = serve(vec![
            (429, json!({"error": {"message": "slow down"}}).to_string()),
            (200, ok.to_string()),
        ]);
        let chooser = JevChooser::load(&base, "k", "").unwrap();
        let choice = chooser.choose("x", &hints(&["Receipts"])).unwrap();
        assert_eq!(choice.folder.as_deref(), Some("Receipts"));

        let (base, _requests) = serve(vec![(
            401,
            json!({"error": {"message": "Missing or invalid API key"}}).to_string(),
        )]);
        let chooser = JevChooser::load(&base, "bad", "").unwrap();
        let error = chooser
            .choose("x", &hints(&["Receipts"]))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("401") && error.contains("Missing or invalid API key"),
            "{error}"
        );
        assert!(!error.contains("bad"), "key leaked into error: {error}");
    }

    #[test]
    fn anthropic_answers_use_its_api_and_schemas() {
        let reply = json!({
            "content": [
                {"type": "thinking", "thinking": ""},
                {"type": "text", "text": "{\"folder\": \"Travel\", \"confidence\": 0.8}"},
            ],
            "stop_reason": "end_turn",
        });
        let (base, requests) = serve(vec![(200, reply.to_string())]);
        let chooser = AnthropicChooser::load(&base, "sk-ant", "claude-haiku-5-5").unwrap();
        let choice = chooser
            .choose("Your boarding pass", &hints(&["Receipts", "Travel"]))
            .unwrap();
        assert_eq!(choice.folder.as_deref(), Some("Travel"));
        let (auth, request) = requests.recv().unwrap();
        assert_eq!(auth, "x-api-key sk-ant");
        assert_eq!(request["model"], "claude-haiku-5-5");
        assert!(request["system"].as_str().unwrap().contains("Travel"));
        assert_eq!(request["messages"][0]["content"], "Your boarding pass");
        assert!(request.get("temperature").is_none(), "{request}");
        assert_eq!(request["output_config"]["format"]["type"], "json_schema");
        assert_eq!(
            request["output_config"]["format"]["schema"]["properties"]["folder"]["enum"],
            json!(["Receipts", "Travel", null])
        );

        let refusal = json!({"content": [], "stop_reason": "refusal"});
        let summary = json!({"content": [{"type": "text", "text": "A flight on Monday."}], "stop_reason": "end_turn"});
        let (base, requests) = serve(vec![(200, refusal.to_string()), (200, summary.to_string())]);
        let chooser = AnthropicChooser::load(&base, "sk-ant", "claude-haiku-5-5").unwrap();
        assert!(
            chooser.label("x", &[], true).is_err(),
            "a refusal is an error"
        );
        requests.recv().unwrap();
        assert_eq!(chooser.summarize("…").unwrap(), "A flight on Monday.");
        let (_, request) = requests.recv().unwrap();
        assert!(request["output_config"].get("format").is_none());
        assert!(AnthropicChooser::load(&base, "", "m").is_err());
    }

    #[test]
    fn flex_requests_retry_then_fall_back_to_the_standard_tier() {
        let ok = json!({"choices": [{"message": {"content": "A flight."}}]}).to_string();
        let busy = json!({"error": {"message": "Resource Unavailable"}}).to_string();
        // Capacity comes back on the second try.
        let (base, requests) = serve(vec![(429, busy.clone()), (200, ok.clone())]);
        let chooser = OpenAiChooser::load(&base, "sk", "gpt").unwrap().flex();
        assert_eq!(chooser.summarize("x").unwrap(), "A flight.");
        for _ in 0..2 {
            assert_eq!(requests.recv().unwrap().1["service_tier"], "flex");
        }

        // No capacity at all: the standard tier does the work.
        let mut responses = vec![(429, busy.clone()); FLEX_ATTEMPTS as usize];
        responses.push((200, ok.clone()));
        let (base, requests) = serve(responses);
        let chooser = OpenAiChooser::load(&base, "sk", "gpt").unwrap().flex();
        assert_eq!(chooser.summarize("x").unwrap(), "A flight.");
        for _ in 0..FLEX_ATTEMPTS {
            assert_eq!(requests.recv().unwrap().1["service_tier"], "flex");
        }
        assert!(requests.recv().unwrap().1.get("service_tier").is_none());

        // A model without the flex tier is asked again at once at the standard one.
        let unsupported =
            json!({"error": {"message": "service_tier flex is not supported"}}).to_string();
        let (base, requests) = serve(vec![(400, unsupported), (200, ok)]);
        let chooser = OpenAiChooser::load(&base, "sk", "gpt").unwrap().flex();
        assert_eq!(chooser.summarize("x").unwrap(), "A flight.");
        assert_eq!(requests.recv().unwrap().1["service_tier"], "flex");
        assert!(requests.recv().unwrap().1.get("service_tier").is_none());

        // A bad key fails at once, without a second request.
        let denied = json!({"error": {"message": "Incorrect API key"}}).to_string();
        let (base, requests) = serve(vec![(401, denied)]);
        let chooser = OpenAiChooser::load(&base, "sk", "gpt").unwrap().flex();
        assert!(
            chooser
                .summarize("x")
                .unwrap_err()
                .to_string()
                .contains("401")
        );
        requests.recv().unwrap();
        assert!(
            requests.recv_timeout(Duration::from_millis(200)).is_err(),
            "no standard-tier retry"
        );

        // Without flex nothing extra is sent.
        let plain = json!({"choices": [{"message": {"content": "A flight."}}]}).to_string();
        let (base, requests) = serve(vec![(200, plain)]);
        let chooser = OpenAiChooser::load(&base, "sk", "gpt").unwrap();
        chooser.summarize("x").unwrap();
        assert!(requests.recv().unwrap().1.get("service_tier").is_none());
    }

    #[test]
    fn missing_keys_fail_at_load() {
        assert!(JevChooser::load(TYPESAFE_API, " ", "").is_err());
        assert!(OpenAiChooser::load("https://openrouter.ai/api/v1", "", "m").is_err());
        assert!(OpenAiChooser::load("https://openrouter.ai/api/v1", "k", "").is_err());
    }
}
