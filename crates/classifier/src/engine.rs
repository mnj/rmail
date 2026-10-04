//! Model access behind small traits, so the pipeline can be tested with
//! deterministic fakes and built without llama.cpp.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use rmail_common::config::{ChatProvider, ClassifierConfig, EmbedProvider};
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
    /// A file in the models directory, or `provider:model` for hosted ones.
    pub file: String,
    pub load_ms: u64,
    /// `None` for a local model; otherwise the provider receiving message text.
    pub cloud: Option<&'static str>,
    /// Everything that requires a reload when it changes, API keys included.
    #[serde(skip)]
    pub fingerprint: u64,
}

/// What one role (embedding or chat) is configured to use.
struct Spec {
    label: String,
    cloud: Option<&'static str>,
    fingerprint: u64,
}

fn fingerprint(parts: &[&str]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    parts.hash(&mut hasher);
    hasher.finish()
}

fn secret(value: &Option<rmail_common::config::SecretString>) -> &str {
    value.as_ref().map_or("", |key| key.expose())
}

/// The embedding model `cfg` asks for, or `None` when it names none.
fn embed_spec(cfg: &ClassifierConfig) -> Option<Spec> {
    match cfg.embed_provider {
        EmbedProvider::Local => (!cfg.embed_model.is_empty()).then(|| Spec {
            label: cfg.embed_model.clone(),
            cloud: None,
            fingerprint: fingerprint(&["local", &cfg.embed_model, &cfg.threads.to_string()]),
        }),
        EmbedProvider::OpenRouter => Some(Spec {
            label: format!("openrouter:{}", cfg.openrouter_embed_model),
            cloud: cfg.embed_provider.cloud(),
            fingerprint: fingerprint(&[
                "openrouter",
                &cfg.openrouter_base_url,
                &cfg.openrouter_embed_model,
                secret(&cfg.openrouter_api_key),
            ]),
        }),
    }
}

/// The fallback chooser `cfg` asks for, or `None` when it names none.
fn chat_spec(cfg: &ClassifierConfig) -> Option<Spec> {
    match cfg.chat_provider {
        ChatProvider::Local => (!cfg.chat_model.is_empty()).then(|| Spec {
            label: cfg.chat_model.clone(),
            cloud: None,
            fingerprint: fingerprint(&["local", &cfg.chat_model, &cfg.threads.to_string()]),
        }),
        ChatProvider::OpenRouter => (!cfg.openrouter_chat_model.is_empty()).then(|| Spec {
            label: format!("openrouter:{}", cfg.openrouter_chat_model),
            cloud: cfg.chat_provider.cloud(),
            fingerprint: fingerprint(&[
                "openrouter",
                &cfg.openrouter_base_url,
                &cfg.openrouter_chat_model,
                secret(&cfg.openrouter_api_key),
            ]),
        }),
        ChatProvider::Jev => Some(Spec {
            label: format!("jev:{}", cfg.jev_model),
            cloud: cfg.chat_provider.cloud(),
            fingerprint: fingerprint(&["jev", &cfg.jev_model, secret(&cfg.typesafe_api_key)]),
        }),
    }
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
        if let Some(spec) = embed_spec(cfg) {
            match reuse(&previous.embed_info, &previous.embedder, &spec) {
                Some((info, embedder)) => {
                    models.embed_info = Some(info);
                    models.embedder = Some(embedder);
                }
                None => match timed(&spec, || load_embedder(cfg, models_dir)) {
                    Ok((info, embedder)) => {
                        models.embed_info = Some(info);
                        models.embedder = Some(embedder);
                    }
                    Err(error) => models
                        .errors
                        .push(format!("embedding model {}: {error:#}", spec.label)),
                },
            }
        }
        if let Some(spec) = chat_spec(cfg) {
            match reuse(&previous.chat_info, &previous.chooser, &spec) {
                Some((info, chooser)) => {
                    models.chat_info = Some(info);
                    models.chooser = Some(chooser);
                }
                None => match timed(&spec, || load_chooser(cfg, models_dir)) {
                    Ok((info, chooser)) => {
                        models.chat_info = Some(info);
                        models.chooser = Some(chooser);
                    }
                    Err(error) => models
                        .errors
                        .push(format!("chat model {}: {error:#}", spec.label)),
                },
            }
        }
        models
    }

    /// Third parties the loaded embedder and chooser send message text to.
    pub fn embed_cloud(&self) -> Option<&'static str> {
        self.embed_info.as_ref().and_then(|info| info.cloud)
    }

    pub fn chat_cloud(&self) -> Option<&'static str> {
        self.chat_info.as_ref().and_then(|info| info.cloud)
    }
}

/// The previously loaded model, when nothing it depends on changed.
fn reuse<T: ?Sized>(
    info: &Option<LoadedModel>,
    model: &Option<Arc<T>>,
    spec: &Spec,
) -> Option<(LoadedModel, Arc<T>)> {
    match (info, model) {
        (Some(info), Some(model)) if info.fingerprint == spec.fingerprint => {
            Some((info.clone(), model.clone()))
        }
        _ => None,
    }
}

fn timed<T: ?Sized>(
    spec: &Spec,
    load: impl FnOnce() -> Result<Arc<T>>,
) -> Result<(LoadedModel, Arc<T>)> {
    let started = Instant::now();
    let model = load()?;
    Ok((
        LoadedModel {
            file: spec.label.clone(),
            load_ms: started.elapsed().as_millis() as u64,
            cloud: spec.cloud,
            fingerprint: spec.fingerprint,
        },
        model,
    ))
}

fn load_embedder(cfg: &ClassifierConfig, models_dir: &Path) -> Result<Arc<dyn Embedder>> {
    match cfg.embed_provider {
        EmbedProvider::Local => load_local_embedder(cfg, models_dir),
        EmbedProvider::OpenRouter => Ok(Arc::new(crate::cloud::OpenAiEmbedder::load(
            &cfg.openrouter_base_url,
            secret(&cfg.openrouter_api_key),
            &cfg.openrouter_embed_model,
        )?)),
    }
}

fn load_chooser(cfg: &ClassifierConfig, models_dir: &Path) -> Result<Arc<dyn Chooser>> {
    match cfg.chat_provider {
        ChatProvider::Local => load_local_chooser(cfg, models_dir),
        ChatProvider::OpenRouter => Ok(Arc::new(crate::cloud::OpenAiChooser::load(
            &cfg.openrouter_base_url,
            secret(&cfg.openrouter_api_key),
            &cfg.openrouter_chat_model,
        )?)),
        ChatProvider::Jev => Ok(Arc::new(crate::cloud::JevChooser::load(
            crate::cloud::TYPESAFE_API,
            secret(&cfg.typesafe_api_key),
            &cfg.jev_model,
        )?)),
    }
}

#[cfg(feature = "local-models")]
fn load_local_embedder(cfg: &ClassifierConfig, models_dir: &Path) -> Result<Arc<dyn Embedder>> {
    Ok(Arc::new(crate::llama::LlamaEmbedder::load(
        models_dir,
        &cfg.embed_model,
        cfg.threads,
    )?))
}

#[cfg(feature = "local-models")]
fn load_local_chooser(cfg: &ClassifierConfig, models_dir: &Path) -> Result<Arc<dyn Chooser>> {
    Ok(Arc::new(crate::llama::LlamaChooser::load(
        models_dir,
        &cfg.chat_model,
        cfg.threads,
    )?))
}

#[cfg(not(feature = "local-models"))]
fn load_local_embedder(_cfg: &ClassifierConfig, _models_dir: &Path) -> Result<Arc<dyn Embedder>> {
    anyhow::bail!(
        "rmail_classifier was built without the local-models feature; choose a cloud provider"
    )
}

#[cfg(not(feature = "local-models"))]
fn load_local_chooser(_cfg: &ClassifierConfig, _models_dir: &Path) -> Result<Arc<dyn Chooser>> {
    anyhow::bail!(
        "rmail_classifier was built without the local-models feature; choose a cloud provider"
    )
}

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
