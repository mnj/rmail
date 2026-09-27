//! Turning a message into a folder decision: document extraction, the
//! sender/list prior, the embedding k-nearest-neighbour vote, and when to ask
//! the chat model.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use rmail_common::classifier_store::Example;
use rmail_common::config::ClassifierConfig;
use rmail_common::mime;

use crate::engine::{Chooser, FolderHint};

/// Neighbours considered in the vote.
const K: usize = 10;
/// Senders need this many filed messages before their history counts.
const PRIOR_MIN_MESSAGES: usize = 2;
/// Share of a sender's filed mail that must agree on one folder.
const PRIOR_MIN_SHARE: f64 = 0.8;
/// Votes closer than this are ambiguous and go to the chat model.
const MIN_MARGIN: f64 = 0.15;
/// Chat answers below this self-reported confidence are dropped.
const MIN_CHAT_CONFIDENCE: f64 = 0.5;
/// Example subjects per folder given to the chat model.
const HINTS_PER_FOLDER: usize = 3;
/// Folders offered to the chat model at most.
const MAX_CHAT_FOLDERS: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub sender: String,
    pub list_id: String,
    pub subject: String,
    /// What the models see: headers and the start of the body.
    pub text: String,
}

pub fn document(raw: &[u8], max_bytes: usize) -> Document {
    let parsed = mime::parse_message(raw);
    let body = parsed
        .text_body
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let mut text = format!(
        "From: {}\nSubject: {}\n\n{}",
        parsed.from, parsed.subject, body
    );
    truncate_on_char(&mut text, max_bytes);
    Document {
        sender: address(&parsed.from),
        list_id: list_id(&parsed.list_id),
        subject: parsed.subject,
        text,
    }
}

fn truncate_on_char(text: &mut String, max_bytes: usize) {
    if text.len() > max_bytes {
        let mut end = max_bytes;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
}

/// The bare lower-case address from a From header.
fn address(from: &str) -> String {
    let inner = match (from.rfind('<'), from.rfind('>')) {
        (Some(start), Some(end)) if start < end => &from[start + 1..end],
        _ => from,
    };
    inner.trim().to_ascii_lowercase()
}

fn list_id(header: &str) -> String {
    let inner = match (header.rfind('<'), header.rfind('>')) {
        (Some(start), Some(end)) if start < end => &header[start + 1..end],
        _ => header,
    };
    inner.trim().to_ascii_lowercase()
}

#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub folder: String,
    pub score: f64,
    /// `sender`, `knn` or `llm`.
    pub method: &'static str,
}

impl Decision {
    /// Only votes grounded in the user's own filing may move mail on their own.
    pub fn may_autofile(&self, cfg: &ClassifierConfig) -> bool {
        self.method != "llm" && self.score * 100.0 >= cfg.autofile_confidence as f64
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Vote {
    folder: String,
    score: f64,
    margin: f64,
}

pub struct Inputs<'a> {
    pub doc: &'a Document,
    pub embedding: &'a [f32],
    /// Learned examples, already limited to eligible folders.
    pub examples: &'a [Example],
    /// Every folder that may be suggested.
    pub folders: &'a [String],
    /// Folders the user dismissed for this sender.
    pub dismissed: &'a [String],
}

pub fn decide(
    inputs: &Inputs<'_>,
    cfg: &ClassifierConfig,
    chooser: Option<&dyn Chooser>,
) -> Result<Option<Decision>> {
    let allowed: BTreeSet<&str> = inputs
        .folders
        .iter()
        .map(String::as_str)
        .filter(|folder| !inputs.dismissed.iter().any(|d| d == folder))
        .collect();
    if allowed.is_empty() {
        return Ok(None);
    }
    let examples: Vec<&Example> = inputs
        .examples
        .iter()
        .filter(|example| allowed.contains(example.folder.as_str()))
        .collect();
    let counts = examples
        .iter()
        .fold(BTreeMap::<&str, usize>::new(), |mut map, example| {
            *map.entry(example.folder.as_str()).or_default() += 1;
            map
        });

    let prior = sender_prior(inputs.doc, &examples);
    let knn = knn_vote(inputs.embedding, &examples);
    let threshold = cfg.knn_confidence as f64 / 100.0;

    let combined = match (&prior, &knn) {
        (Some(prior), Some(knn)) if prior.folder == knn.folder => Some(Decision {
            folder: knn.folder.clone(),
            score: 1.0 - (1.0 - prior.score) * (1.0 - knn.score),
            method: "sender",
        }),
        (Some(prior), _) if prior.score >= 0.95 => Some(Decision {
            folder: prior.folder.clone(),
            score: prior.score,
            method: "sender",
        }),
        (_, Some(knn))
            if knn.score >= threshold
                && knn.margin >= MIN_MARGIN
                && counts.get(knn.folder.as_str()).copied().unwrap_or(0)
                    >= cfg.min_examples as usize =>
        {
            Some(Decision {
                folder: knn.folder.clone(),
                score: knn.score,
                method: "knn",
            })
        }
        _ => None,
    };
    if combined.is_some() {
        return Ok(combined);
    }

    let Some(chooser) = chooser else {
        return Ok(None);
    };
    let hints = folder_hints(&allowed, &examples, knn.as_ref());
    let choice = chooser.choose(&inputs.doc.text, &hints)?;
    Ok(match choice.folder {
        Some(folder)
            if choice.confidence >= MIN_CHAT_CONFIDENCE && allowed.contains(folder.as_str()) =>
        {
            Some(Decision {
                folder,
                score: choice.confidence,
                method: "llm",
            })
        }
        _ => None,
    })
}

/// Where earlier mail from the same list, or else the same sender, was filed.
fn sender_prior(doc: &Document, examples: &[&Example]) -> Option<Vote> {
    let matching: Vec<&&Example> = if !doc.list_id.is_empty() {
        examples
            .iter()
            .filter(|e| e.list_id == doc.list_id)
            .collect()
    } else if !doc.sender.is_empty() {
        examples
            .iter()
            .filter(|e| e.list_id.is_empty() && e.sender == doc.sender)
            .collect()
    } else {
        Vec::new()
    };
    if matching.len() < PRIOR_MIN_MESSAGES {
        return None;
    }
    let mut per_folder: BTreeMap<&str, usize> = BTreeMap::new();
    for example in &matching {
        *per_folder.entry(example.folder.as_str()).or_default() += 1;
    }
    let (folder, count) = per_folder.into_iter().max_by_key(|(_, count)| *count)?;
    let share = count as f64 / matching.len() as f64;
    if share < PRIOR_MIN_SHARE {
        return None;
    }
    // More history means more trust: 2 of 2 is 0.67, 9 of 9 is 0.9.
    let score = share * (1.0 - 1.0 / (matching.len() as f64 + 1.0));
    Some(Vote {
        folder: folder.to_string(),
        score,
        margin: score,
    })
}

/// Similarity-weighted vote among the K nearest examples.
fn knn_vote(embedding: &[f32], examples: &[&Example]) -> Option<Vote> {
    let mut scored: Vec<(f32, &str)> = examples
        .iter()
        .filter(|example| example.embedding.len() == embedding.len())
        .map(|example| (dot(embedding, &example.embedding), example.folder.as_str()))
        .collect();
    if scored.is_empty() {
        return None;
    }
    scored.sort_by(|a, b| b.0.total_cmp(&a.0));
    scored.truncate(K);
    let mut weights: BTreeMap<&str, f64> = BTreeMap::new();
    let mut total = 0.0;
    for (similarity, folder) in &scored {
        let weight = (*similarity as f64).max(0.0).powi(2);
        *weights.entry(folder).or_default() += weight;
        total += weight;
    }
    if total <= 0.0 {
        return None;
    }
    let mut ranked: Vec<(&str, f64)> = weights.into_iter().map(|(f, w)| (f, w / total)).collect();
    ranked.sort_by(|a, b| b.1.total_cmp(&a.1));
    let best = ranked[0];
    let second = ranked.get(1).map_or(0.0, |r| r.1);
    // A unanimous vote among distant neighbours is still weak evidence.
    let closeness = (scored[0].0 as f64 / 0.75).clamp(0.0, 1.0);
    Some(Vote {
        folder: best.0.to_string(),
        score: best.1 * closeness,
        margin: (best.1 - second) * closeness,
    })
}

fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

fn folder_hints(
    allowed: &BTreeSet<&str>,
    examples: &[&Example],
    knn: Option<&Vote>,
) -> Vec<FolderHint> {
    let mut hints: Vec<FolderHint> = allowed
        .iter()
        .map(|name| FolderHint {
            name: name.to_string(),
            examples: examples
                .iter()
                .rev()
                .filter(|e| e.folder == *name && !e.subject.is_empty())
                .take(HINTS_PER_FOLDER)
                .map(|e| e.subject.clone())
                .collect(),
        })
        .collect();
    // Keep the kNN favourite in view when the list must be cut.
    if let Some(knn) = knn {
        hints.sort_by_key(|hint| hint.name != knn.folder);
    }
    hints.truncate(MAX_CHAT_FOLDERS);
    hints
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Embedder, fake};

    fn cfg() -> ClassifierConfig {
        ClassifierConfig {
            min_examples: 2,
            ..ClassifierConfig::default()
        }
    }

    fn example(embedder: &fake::BagOfWords, folder: &str, sender: &str, subject: &str) -> Example {
        Example {
            folder: folder.into(),
            uid: 0,
            sender: sender.into(),
            list_id: String::new(),
            subject: subject.into(),
            embedding: embedder.embed(&[subject.to_string()]).unwrap().remove(0),
        }
    }

    fn doc(sender: &str, text: &str) -> Document {
        Document {
            sender: sender.into(),
            list_id: String::new(),
            subject: text.into(),
            text: text.into(),
        }
    }

    fn corpus(embedder: &fake::BagOfWords) -> Vec<Example> {
        vec![
            example(
                embedder,
                "Receipts",
                "a@shop.test",
                "order receipt payment total invoice",
            ),
            example(
                embedder,
                "Receipts",
                "b@shop.test",
                "invoice payment receipt order amount",
            ),
            example(
                embedder,
                "Receipts",
                "c@shop.test",
                "your receipt for order payment",
            ),
            example(
                embedder,
                "Travel",
                "d@air.test",
                "flight booking boarding pass gate",
            ),
            example(
                embedder,
                "Travel",
                "e@air.test",
                "hotel booking reservation flight itinerary",
            ),
            example(
                embedder,
                "Travel",
                "f@air.test",
                "boarding pass flight itinerary seat",
            ),
        ]
    }

    fn folders() -> Vec<String> {
        vec!["Receipts".into(), "Travel".into()]
    }

    #[test]
    fn document_extracts_sender_list_and_text() {
        let raw = b"From: Shop <Orders@Shop.test>\r\nList-Id: News <news.shop.test>\r\nSubject: Receipt\r\n\r\nThanks   for\r\nyour order";
        let doc = document(raw, 1024);
        assert_eq!(doc.sender, "orders@shop.test");
        assert_eq!(doc.list_id, "news.shop.test");
        assert!(doc.text.ends_with("Thanks for your order"));
        let short = document(raw, 20);
        assert!(short.text.len() <= 20);
    }

    #[test]
    fn knn_routes_by_content() {
        let embedder = fake::BagOfWords { id: "t".into() };
        let examples = corpus(&embedder);
        let d = doc("new@shop.test", "payment receipt for your order invoice");
        let embedding = embedder
            .embed(std::slice::from_ref(&d.text))
            .unwrap()
            .remove(0);
        let decision = decide(
            &Inputs {
                doc: &d,
                embedding: &embedding,
                examples: &examples,
                folders: &folders(),
                dismissed: &[],
            },
            &cfg(),
            None,
        )
        .unwrap()
        .expect("decision");
        assert_eq!(decision.folder, "Receipts");
        assert_eq!(decision.method, "knn");
    }

    #[test]
    fn sender_history_wins_even_for_unfamiliar_content() {
        let embedder = fake::BagOfWords { id: "t".into() };
        let mut examples = corpus(&embedder);
        for _ in 0..4 {
            examples.push(example(
                &embedder,
                "Travel",
                "news@club.test",
                "weekly club newsletter",
            ));
        }
        let d = doc("news@club.test", "completely different words here");
        let embedding = embedder
            .embed(std::slice::from_ref(&d.text))
            .unwrap()
            .remove(0);
        let decision = decide(
            &Inputs {
                doc: &d,
                embedding: &embedding,
                examples: &examples,
                folders: &folders(),
                dismissed: &[],
            },
            &cfg(),
            None,
        )
        .unwrap()
        .expect("decision");
        assert_eq!(decision.folder, "Travel");
        assert_eq!(decision.method, "sender");
    }

    #[test]
    fn uncertain_messages_ask_the_chat_model_which_cannot_autofile() {
        let embedder = fake::BagOfWords { id: "t".into() };
        let examples = corpus(&embedder);
        let d = doc("x@y.test", "quarterly tax statement");
        let embedding = embedder
            .embed(std::slice::from_ref(&d.text))
            .unwrap()
            .remove(0);
        let inputs = Inputs {
            doc: &d,
            embedding: &embedding,
            examples: &examples,
            folders: &folders(),
            dismissed: &[],
        };
        assert_eq!(decide(&inputs, &cfg(), None).unwrap(), None);

        let chooser = fake::Fixed::new(Some("Receipts"), 0.9);
        let decision = decide(&inputs, &cfg(), Some(&chooser))
            .unwrap()
            .expect("decision");
        assert_eq!(*chooser.calls.lock().unwrap(), 1);
        assert_eq!(decision.method, "llm");
        assert!(!decision.may_autofile(&cfg()));

        let unsure = fake::Fixed::new(Some("Receipts"), 0.3);
        assert_eq!(decide(&inputs, &cfg(), Some(&unsure)).unwrap(), None);
        let invented = fake::Fixed::new(Some("Taxes"), 0.9);
        assert_eq!(decide(&inputs, &cfg(), Some(&invented)).unwrap(), None);
    }

    #[test]
    fn confident_votes_skip_the_chat_model() {
        let embedder = fake::BagOfWords { id: "t".into() };
        let examples = corpus(&embedder);
        let d = doc("z@air.test", "flight boarding pass itinerary");
        let embedding = embedder
            .embed(std::slice::from_ref(&d.text))
            .unwrap()
            .remove(0);
        let chooser = fake::Fixed::new(Some("Receipts"), 1.0);
        let decision = decide(
            &Inputs {
                doc: &d,
                embedding: &embedding,
                examples: &examples,
                folders: &folders(),
                dismissed: &[],
            },
            &cfg(),
            Some(&chooser),
        )
        .unwrap()
        .expect("decision");
        assert_eq!(decision.folder, "Travel");
        assert_eq!(*chooser.calls.lock().unwrap(), 0);
    }

    #[test]
    fn dismissed_folders_are_not_suggested_again() {
        let embedder = fake::BagOfWords { id: "t".into() };
        let examples = corpus(&embedder);
        let d = doc("z@air.test", "flight boarding pass itinerary");
        let embedding = embedder
            .embed(std::slice::from_ref(&d.text))
            .unwrap()
            .remove(0);
        let decision = decide(
            &Inputs {
                doc: &d,
                embedding: &embedding,
                examples: &examples,
                folders: &folders(),
                dismissed: &["Travel".to_string()],
            },
            &cfg(),
            None,
        )
        .unwrap();
        assert!(decision.is_none_or(|d| d.folder != "Travel"));
    }
}
