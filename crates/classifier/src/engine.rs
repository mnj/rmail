//! Model access behind small traits, so the pipeline can be tested with
//! deterministic fakes and built without llama.cpp.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use rmail_common::config::ClassifierConfig;
use serde::Serialize;

pub trait Embedder: Send + Sync {
    /// Identifies the vector space; examples from another model are stale.
    fn model_id(&self) -> &str;
    /// One L2-normalised vector per input.
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>>;
}

/// A folder picked by the chat model, with its self-reported confidence.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Choice {
    pub folder: Option<String>,
    pub confidence: f64,
    pub raw: String,
}

pub trait Chooser: Send + Sync {
    /// Pick one of `folders` for `message`, or none. `hints` are example
    /// subjects per folder.
    fn choose(&self, message: &str, folders: &[FolderHint]) -> Result<Choice>;
}

#[derive(Debug, Clone, PartialEq)]
pub struct FolderHint {
    pub name: String,
    pub examples: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoadedModel {
    pub file: String,
    pub load_ms: u64,
}

/// The models the daemon currently serves.
#[derive(Clone, Default)]
pub struct Models {
    pub embedder: Option<Arc<dyn Embedder>>,
    pub chooser: Option<Arc<dyn Chooser>>,
    pub embed_info: Option<LoadedModel>,
    pub chat_info: Option<LoadedModel>,
    /// Load failures, shown on the admin console.
    pub errors: Vec<String>,
}

impl Models {
    /// Load the models named in `cfg` from `models_dir`, reusing `previous`
    /// for a model whose file did not change.
    pub fn load(cfg: &ClassifierConfig, models_dir: &Path, previous: &Models) -> Models {
        let mut models = Models::default();
        if !cfg.embed_model.is_empty() {
            if let (Some(info), Some(embedder)) = (&previous.embed_info, &previous.embedder)
                && info.file == cfg.embed_model
            {
                models.embed_info = Some(info.clone());
                models.embedder = Some(embedder.clone());
            } else {
                let started = Instant::now();
                match load_embedder(cfg, models_dir) {
                    Ok(embedder) => {
                        models.embedder = Some(embedder);
                        models.embed_info = Some(LoadedModel {
                            file: cfg.embed_model.clone(),
                            load_ms: started.elapsed().as_millis() as u64,
                        });
                    }
                    Err(error) => models
                        .errors
                        .push(format!("embedding model {}: {error:#}", cfg.embed_model)),
                }
            }
        }
        if !cfg.chat_model.is_empty() {
            if let (Some(info), Some(chooser)) = (&previous.chat_info, &previous.chooser)
                && info.file == cfg.chat_model
            {
                models.chat_info = Some(info.clone());
                models.chooser = Some(chooser.clone());
            } else {
                let started = Instant::now();
                match load_chooser(cfg, models_dir) {
                    Ok(chooser) => {
                        models.chooser = Some(chooser);
                        models.chat_info = Some(LoadedModel {
                            file: cfg.chat_model.clone(),
                            load_ms: started.elapsed().as_millis() as u64,
                        });
                    }
                    Err(error) => models
                        .errors
                        .push(format!("chat model {}: {error:#}", cfg.chat_model)),
                }
            }
        }
        models
    }
}

#[cfg(feature = "local-models")]
fn load_embedder(cfg: &ClassifierConfig, models_dir: &Path) -> Result<Arc<dyn Embedder>> {
    Ok(Arc::new(crate::llama::LlamaEmbedder::load(
        models_dir,
        &cfg.embed_model,
        cfg.threads,
    )?))
}

#[cfg(feature = "local-models")]
fn load_chooser(cfg: &ClassifierConfig, models_dir: &Path) -> Result<Arc<dyn Chooser>> {
    Ok(Arc::new(crate::llama::LlamaChooser::load(
        models_dir,
        &cfg.chat_model,
        cfg.threads,
    )?))
}

#[cfg(not(feature = "local-models"))]
fn load_embedder(_cfg: &ClassifierConfig, _models_dir: &Path) -> Result<Arc<dyn Embedder>> {
    anyhow::bail!("rmail_classifier was built without the local-models feature")
}

#[cfg(not(feature = "local-models"))]
fn load_chooser(_cfg: &ClassifierConfig, _models_dir: &Path) -> Result<Arc<dyn Chooser>> {
    anyhow::bail!("rmail_classifier was built without the local-models feature")
}

#[cfg_attr(not(any(test, feature = "local-models")), allow(dead_code))]
pub fn l2_normalize(vector: &mut [f32]) {
    let norm = vector.iter().map(|v| v * v).sum::<f32>().sqrt();
    if norm > 0.0 {
        vector.iter_mut().for_each(|v| *v /= norm);
    }
}

/// Deterministic stand-ins for tests: a hashed bag-of-words embedder and a
/// chooser with a fixed answer.
#[cfg(test)]
pub mod fake {
    use super::*;
    use std::sync::Mutex;

    pub struct BagOfWords {
        pub id: String,
    }

    impl Embedder for BagOfWords {
        fn model_id(&self) -> &str {
            &self.id
        }

        fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>> {
            Ok(texts
                .iter()
                .map(|text| {
                    let mut vector = vec![0.0f32; 64];
                    for word in text
                        .split(|c: char| !c.is_alphanumeric())
                        .filter(|w| w.len() > 2)
                    {
                        let hash = word
                            .to_lowercase()
                            .bytes()
                            .fold(1469598103934665603u64, |h, b| {
                                (h ^ b as u64).wrapping_mul(1099511628211)
                            });
                        vector[(hash % 64) as usize] += 1.0;
                    }
                    l2_normalize(&mut vector);
                    vector
                })
                .collect())
        }
    }

    pub struct Fixed {
        pub answer: Choice,
        pub calls: Mutex<usize>,
    }

    impl Fixed {
        pub fn new(folder: Option<&str>, confidence: f64) -> Self {
            Self {
                answer: Choice {
                    folder: folder.map(str::to_string),
                    confidence,
                    raw: String::new(),
                },
                calls: Mutex::new(0),
            }
        }
    }

    impl Chooser for Fixed {
        fn choose(&self, _message: &str, _folders: &[FolderHint]) -> Result<Choice> {
            *self.calls.lock().unwrap() += 1;
            Ok(self.answer.clone())
        }
    }
}
