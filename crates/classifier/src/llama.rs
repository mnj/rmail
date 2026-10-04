//! In-process GGUF inference with llama.cpp.
//!
//! Models are memory-mapped once. Each call creates its own short-lived
//! context, so embedding and chat requests from the poll loop and the control
//! socket can run concurrently against the same loaded weights.

use std::num::NonZeroU32;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow, bail};
use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, LlamaChatMessage, LlamaModel};
use llama_cpp_2::sampling::LlamaSampler;
use llama_cpp_2::token::LlamaToken;

use crate::engine::{Choice, Chooser, Embedder, FolderHint, LabelHint, Labeling, l2_normalize};
use crate::prompt::{
    SUMMARY_PROMPT, json_escape, label_prompt, parse_answer, parse_labels, system_prompt,
    tidy_summary,
};
use rmail_common::classifier_models;

/// llama.cpp allows one backend per process.
fn backend() -> Result<&'static LlamaBackend> {
    static BACKEND: OnceLock<std::result::Result<LlamaBackend, String>> = OnceLock::new();
    BACKEND
        .get_or_init(|| {
            llama_cpp_2::send_logs_to_tracing(
                llama_cpp_2::LogOptions::default().with_logs_enabled(false),
            );
            LlamaBackend::init().map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| anyhow!("initialising llama.cpp: {error}"))
}

fn load_model(models_dir: &Path, file: &str) -> Result<LlamaModel> {
    let path = classifier_models::model_path(models_dir, file)?;
    if !path.is_file() {
        bail!("{} is not installed", path.display());
    }
    LlamaModel::load_from_file(backend()?, &path, &LlamaModelParams::default())
        .with_context(|| format!("loading {}", path.display()))
}

fn thread_count(threads: u32) -> i32 {
    if threads > 0 {
        return threads as i32;
    }
    std::thread::available_parallelism()
        .map(|n| n.get() as i32)
        .unwrap_or(4)
}

fn model_id(models_dir: &Path, file: &str) -> String {
    match classifier_models::read_meta(models_dir, file) {
        Some(meta) => format!("{file}@{}", &meta.sha256[..meta.sha256.len().min(16)]),
        None => {
            let size = std::fs::metadata(models_dir.join(file))
                .map(|m| m.len())
                .unwrap_or(0);
            format!("{file}@{size}")
        }
    }
}

// ---------------------------------------------------------------------------
// Embeddings

pub struct LlamaEmbedder {
    model: LlamaModel,
    id: String,
    prefix: String,
    threads: i32,
    n_ctx: u32,
}

impl LlamaEmbedder {
    pub fn load(models_dir: &Path, file: &str, threads: u32) -> Result<Self> {
        let model = load_model(models_dir, file)?;
        let n_ctx = model.n_ctx_train().clamp(128, 1024);
        let embedder = Self {
            id: model_id(models_dir, file),
            prefix: classifier_models::prefix_for(models_dir, file),
            threads: thread_count(threads),
            n_ctx,
            model,
        };
        // Fail at load time, not on the first message, if this is not an
        // embedding model.
        embedder.embed(&["probe".to_string()])?;
        Ok(embedder)
    }
}

impl Embedder for LlamaEmbedder {
    fn model_id(&self) -> &str {
        &self.id
    }

    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>> {
        let params = LlamaContextParams::default()
            .with_embeddings(true)
            .with_n_ctx(NonZeroU32::new(self.n_ctx))
            .with_n_batch(self.n_ctx)
            .with_n_ubatch(self.n_ctx)
            .with_n_threads(self.threads)
            .with_n_threads_batch(self.threads);
        let mut ctx = self
            .model
            .new_context(backend()?, params)
            .context("creating embedding context")?;
        let mut out = Vec::with_capacity(texts.len());
        for text in texts {
            let input = format!("{}{}", self.prefix, text);
            let mut tokens = self
                .model
                .str_to_token(&input, AddBos::Always)
                .context("tokenizing")?;
            tokens.truncate(self.n_ctx as usize);
            if tokens.is_empty() {
                bail!("empty input after tokenizing");
            }
            let mut batch = LlamaBatch::new(tokens.len(), 1);
            batch.add_sequence(&tokens, 0, true)?;
            ctx.clear_kv_cache();
            if let Err(decode_error) = ctx.decode(&mut batch) {
                ctx.encode(&mut batch)
                    .map_err(|_| anyhow!("embedding failed: {decode_error}"))?;
            }
            let mut vector = match ctx.embeddings_seq_ith(0) {
                Ok(pooled) => pooled.to_vec(),
                // Models without pooling: use the last token's state.
                Err(_) => ctx
                    .embeddings_ith(batch.n_tokens() - 1)
                    .context("reading embeddings")?
                    .to_vec(),
            };
            l2_normalize(&mut vector);
            out.push(vector);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Chat

pub struct LlamaChooser {
    model: LlamaModel,
    threads: i32,
}

const CHAT_CTX: u32 = 4096;
const MAX_ANSWER_TOKENS: usize = 96;
/// Room for a dozen `{"name", "confidence"}` items.
const MAX_LABEL_TOKENS: usize = 320;
const MAX_SUMMARY_TOKENS: usize = 200;

impl LlamaChooser {
    pub fn load(models_dir: &Path, file: &str, threads: u32) -> Result<Self> {
        Ok(Self {
            model: load_model(models_dir, file)?,
            threads: thread_count(threads),
        })
    }

    fn prompt(&self, system: String, message: &str) -> Result<String> {
        let user = format!("{message}\n\n/no_think");
        match self.model.chat_template(None) {
            Ok(template) => Ok(self.model.apply_chat_template(
                &template,
                &[
                    LlamaChatMessage::new("system".into(), system)?,
                    LlamaChatMessage::new("user".into(), user)?,
                ],
                true,
            )?),
            Err(_) => Ok(format!("{system}\n\nMessage:\n{user}\n\nAnswer:\n")),
        }
    }

    /// Generate an answer to `system` + `message` that `grammar` admits,
    /// stopping at end of generation, when `done` says the answer is
    /// complete, or after `max_tokens`.
    fn generate(
        &self,
        system: String,
        message: &str,
        grammar: Option<&str>,
        max_tokens: usize,
        done: impl Fn(&str) -> bool,
    ) -> Result<String> {
        let prompt = self.prompt(system, message)?;
        let mut tokens = self
            .model
            .str_to_token(&prompt, AddBos::Always)
            .context("tokenizing prompt")?;
        let budget = CHAT_CTX as usize - max_tokens - 8;
        if tokens.len() > budget {
            // Keep the start (instructions) and the end (the chat template's
            // assistant opening); drop the middle of the message.
            let tail = tokens.split_off(tokens.len() - 256);
            tokens.truncate(budget - tail.len());
            tokens.extend(tail);
        }
        let params = LlamaContextParams::default()
            .with_n_ctx(NonZeroU32::new(CHAT_CTX))
            .with_n_batch(CHAT_CTX)
            .with_n_threads(self.threads)
            .with_n_threads_batch(self.threads);
        let mut ctx = self
            .model
            .new_context(backend()?, params)
            .context("creating chat context")?;
        let mut batch = LlamaBatch::new(CHAT_CTX as usize, 1);
        let last = tokens.len() as i32 - 1;
        for (pos, token) in tokens.iter().enumerate() {
            batch.add(*token, pos as i32, &[0], pos as i32 == last)?;
        }
        ctx.decode(&mut batch).context("evaluating prompt")?;

        let mut sampler = match grammar {
            Some(grammar) => LlamaSampler::chain_simple([
                LlamaSampler::grammar(&self.model, grammar, "root")
                    .map_err(|error| anyhow!("building grammar: {error:?}"))?,
                LlamaSampler::greedy(),
            ]),
            None => LlamaSampler::greedy(),
        };
        let mut decoder = encoding_rs::UTF_8.new_decoder();
        let mut answer = String::new();
        let mut index = batch.n_tokens() - 1;
        for pos in (tokens.len() as i32..).take(max_tokens) {
            let token: LlamaToken = sampler.sample(&ctx, index);
            if self.model.is_eog_token(token) {
                break;
            }
            answer.push_str(
                &self
                    .model
                    .token_to_piece(token, &mut decoder, true, None)
                    .unwrap_or_default(),
            );
            if done(&answer) {
                break;
            }
            batch.clear();
            batch.add(token, pos, &[0], true)?;
            index = 0;
            ctx.decode(&mut batch).context("generating")?;
        }
        Ok(answer)
    }
}

impl Chooser for LlamaChooser {
    fn choose(&self, message: &str, folders: &[FolderHint]) -> Result<Choice> {
        if folders.is_empty() {
            return Ok(Choice {
                folder: None,
                confidence: 0.0,
                raw: String::new(),
            });
        }
        let answer = self.generate(
            system_prompt(folders),
            message,
            Some(&answer_grammar(folders)),
            MAX_ANSWER_TOKENS,
            json_complete,
        )?;
        Ok(parse_answer(&answer, folders))
    }

    fn label(&self, message: &str, labels: &[LabelHint], may_propose: bool) -> Result<Labeling> {
        if labels.is_empty() && !may_propose {
            return Ok(Labeling::default());
        }
        let answer = self.generate(
            label_prompt(labels, may_propose),
            message,
            Some(&label_grammar(labels, may_propose)),
            MAX_LABEL_TOKENS,
            json_complete,
        )?;
        Ok(parse_labels(&answer, labels, may_propose))
    }

    fn summarize(&self, message: &str) -> Result<String> {
        let answer = self.generate(
            SUMMARY_PROMPT.to_string(),
            message,
            None,
            MAX_SUMMARY_TOKENS,
            |_| false,
        )?;
        Ok(tidy_summary(&answer))
    }
}

/// GBNF that only admits `{"folder": "<one of the names>" | null,
/// "confidence": d.d}`.
pub fn answer_grammar(folders: &[FolderHint]) -> String {
    let names: Vec<String> = folders
        .iter()
        .map(|folder| gbnf_literal(&format!("\"{}\"", json_escape(&folder.name))))
        .collect();
    format!(
        "root ::= \"{{\\\"folder\\\": \" folder \", \\\"confidence\\\": \" conf \"}}\"\n\
         folder ::= \"null\" | {}\n\
         conf ::= \"0.\" [0-9] | \"1.0\"\n",
        names.join(" | ")
    )
}

/// GBNF that only admits `{"labels": [{"name": "<label>", "confidence":
/// d.d}, ...]}` with names from `labels`, plus, with `may_propose`,
/// `"new_label": null` or a short `{"name", "description"}`.
pub fn label_grammar(labels: &[LabelHint], may_propose: bool) -> String {
    let names: Vec<String> = labels
        .iter()
        .map(|label| gbnf_literal(&format!("\"{}\"", json_escape(&label.name))))
        .collect();
    let list = if names.is_empty() {
        String::new()
    } else {
        "(item (\", \" item)*)?".to_string()
    };
    let proposal = if may_propose {
        "\", \\\"new_label\\\": \" (\"null\" | \"{\\\"name\\\": \\\"\" pname \"\\\", \\\"description\\\": \\\"\" pdesc \"\\\"}\")"
    } else {
        ""
    };
    let mut grammar = format!("root ::= \"{{\\\"labels\\\": [\" {list} \"]\" {proposal} \"}}\"\n");
    if !names.is_empty() {
        grammar.push_str(&format!(
            "item ::= \"{{\\\"name\\\": \" name \", \\\"confidence\\\": \" conf \"}}\"\n\
             name ::= {}\n\
             conf ::= \"0.\" [0-9] | \"1.0\"\n",
            names.join(" | ")
        ));
    }
    if may_propose {
        grammar.push_str("pname ::= [^\"\\\\\\n]{1,30}\npdesc ::= [^\"\\\\\\n]{0,120}\n");
    }
    grammar
}

/// Whether `answer` holds a complete JSON object: braces balance outside
/// strings. Generation stops there.
fn json_complete(answer: &str) -> bool {
    let (mut depth, mut in_string, mut escaped, mut opened) = (0i32, false, false, false);
    for c in answer.chars() {
        if in_string {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '{' => {
                depth += 1;
                opened = true;
            }
            '}' => depth -= 1,
            _ => {}
        }
    }
    opened && depth == 0
}

fn gbnf_literal(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::hints;

    #[test]
    fn json_completion_ignores_braces_in_strings() {
        assert!(!json_complete("{\"labels\": [{\"name\": \"A\"}"));
        assert!(json_complete(
            "{\"labels\": [], \"new_label\": {\"name\": \"x}\", \"description\": \"\"}}"
        ));
        assert!(!json_complete("{\"folder\": \"a{b\""));
        assert!(!json_complete(""));
    }

    #[test]
    fn label_grammar_only_allows_proposals_when_asked() {
        let labels = crate::prompt::label_hints(&["Invoices"]);
        assert!(!label_grammar(&labels, false).contains("new_label"));
        let open = label_grammar(&labels, true);
        assert!(
            open.contains("new_label") && open.contains("pname ::="),
            "{open}"
        );
        let empty = label_grammar(&[], true);
        assert!(!empty.contains("item ::="), "{empty}");
    }

    #[test]
    fn grammar_escapes_folder_names() {
        let grammar = answer_grammar(&hints(&["Receipts", "Say \"hi\""]));
        assert!(grammar.contains(r#""\"Receipts\"""#), "{grammar}");
        assert!(grammar.contains(r#""\"Say \\\"hi\\\"\"""#), "{grammar}");
    }

    /// Compiles the answer grammar against a real vocabulary. Set
    /// `RMAIL_TEST_VOCAB_GGUF` to any GGUF file (vocab-only is enough).
    #[test]
    fn grammar_compiles_in_llama_cpp() {
        let Ok(path) = std::env::var("RMAIL_TEST_VOCAB_GGUF") else {
            return;
        };
        let params = LlamaModelParams::default().with_vocab_only(true);
        let model = LlamaModel::load_from_file(backend().unwrap(), path, &params).unwrap();
        let grammar = answer_grammar(&hints(&[
            "Receipts",
            "Say \"hi\"",
            "Rejser/Fly",
            "Back\\slash",
        ]));
        LlamaSampler::grammar(&model, &grammar, "root")
            .unwrap_or_else(|e| panic!("{e:?}\n{grammar}"));
        for (names, propose) in [
            (&["Invoices", "Say \"hi\""][..], false),
            (&["Invoices"][..], true),
            (&[][..], true),
        ] {
            let labels = label_grammar(&crate::prompt::label_hints(names), propose);
            LlamaSampler::grammar(&model, &labels, "root")
                .unwrap_or_else(|e| panic!("{e:?}\n{labels}"));
        }
    }

    /// Grammar-constrained generation terminates with JSON the parsers
    /// accept, whatever the model. Set `RMAIL_TEST_TINY_GGUF` to any small
    /// chat-capable GGUF (even a toy model).
    #[test]
    fn constrained_answers_always_parse() {
        let Ok(path) = std::env::var("RMAIL_TEST_TINY_GGUF") else {
            return;
        };
        let path = std::path::PathBuf::from(path);
        let chooser = LlamaChooser::load(
            path.parent().unwrap(),
            path.file_name().unwrap().to_str().unwrap(),
            1,
        )
        .unwrap();
        let folders = hints(&["Receipts", "Travel"]);
        let choice = chooser.choose("Boarding pass for AB123", &folders).unwrap();
        assert!(json_complete(&choice.raw), "{choice:?}");
        let labels = crate::prompt::label_hints(&["Invoices", "Family"]);
        for propose in [false, true] {
            let answer = chooser
                .generate(
                    label_prompt(&labels, propose),
                    "Invoice 42 is due Friday",
                    Some(&label_grammar(&labels, propose)),
                    MAX_LABEL_TOKENS,
                    json_complete,
                )
                .unwrap();
            assert!(json_complete(&answer), "unterminated: {answer}");
            let value: serde_json::Value =
                serde_json::from_str(&answer).unwrap_or_else(|e| panic!("{e}: {answer}"));
            assert!(value["labels"].is_array(), "{answer}");
            assert_eq!(value.get("new_label").is_some(), propose, "{answer}");
            eprintln!("propose={propose}: {answer}");
        }
        // Free text ends at end of generation or the token budget.
        let summary = chooser.summarize("Invoice 42 is due Friday").unwrap();
        assert!(summary.chars().count() <= 600, "{summary}");
    }

    /// End-to-end with real models. Set `RMAIL_TEST_MODEL_DIR` to a directory
    /// holding `RMAIL_TEST_EMBED_MODEL` and optionally `RMAIL_TEST_CHAT_MODEL`.
    #[test]
    fn real_models_embed_and_choose() {
        let Ok(dir) = std::env::var("RMAIL_TEST_MODEL_DIR") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        if let Ok(file) = std::env::var("RMAIL_TEST_EMBED_MODEL") {
            let embedder = LlamaEmbedder::load(&dir, &file, 0).unwrap();
            let vectors = embedder
                .embed(&[
                    "Your order receipt and invoice".to_string(),
                    "Invoice for your purchase".to_string(),
                    "Boarding pass for your flight".to_string(),
                ])
                .unwrap();
            let sim = |a: &[f32], b: &[f32]| a.iter().zip(b).map(|(x, y)| x * y).sum::<f32>();
            assert!(sim(&vectors[0], &vectors[1]) > sim(&vectors[0], &vectors[2]));
        }
        if let Ok(file) = std::env::var("RMAIL_TEST_CHAT_MODEL") {
            let chooser = LlamaChooser::load(&dir, &file, 0).unwrap();
            let choice = chooser
                .choose(
                    "From: airline@example.test\nSubject: Your boarding pass\n\nGate 12, seat 14A.",
                    &hints(&["Receipts", "Travel", "Family"]),
                )
                .unwrap();
            assert_eq!(choice.folder.as_deref(), Some("Travel"), "{choice:?}");
        }
    }
}
