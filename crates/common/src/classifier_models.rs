//! GGUF models for the mail classifier: the built-in catalog, the models
//! directory, and verified downloads.
//!
//! Models live in `<mail_root>/models`. Each `<file>.gguf` has a sidecar
//! `<file>.gguf.json` recording where it came from and its SHA-256, written
//! only after a download completes and verifies.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelKind {
    Embedding,
    Chat,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct CatalogModel {
    pub id: &'static str,
    pub name: &'static str,
    pub kind: ModelKind,
    pub file: &'static str,
    pub url: &'static str,
    /// Expected SHA-256; `None` records whatever the first download produced.
    pub sha256: Option<&'static str>,
    pub size_mb: u32,
    pub ram_mb: u32,
    pub license: &'static str,
    /// Text the model expects before each input (task instruction).
    pub prefix: &'static str,
    pub notes: &'static str,
}

/// Curated starting points. Any GGUF can also be added by URL.
pub const CATALOG: &[CatalogModel] = &[
    CatalogModel {
        id: "bge-small-en-v1.5-q8",
        name: "BGE small en v1.5 (Q8_0)",
        kind: ModelKind::Embedding,
        file: "bge-small-en-v1.5-q8_0.gguf",
        url: "https://huggingface.co/CompendiumLabs/bge-small-en-v1.5-gguf/resolve/main/bge-small-en-v1.5-q8_0.gguf",
        sha256: None,
        size_mb: 36,
        ram_mb: 100,
        license: "MIT",
        prefix: "",
        notes: "Smallest and fastest. English only.",
    },
    CatalogModel {
        id: "nomic-embed-text-v1.5-q8",
        name: "Nomic Embed Text v1.5 (Q8_0)",
        kind: ModelKind::Embedding,
        file: "nomic-embed-text-v1.5.Q8_0.gguf",
        url: "https://huggingface.co/nomic-ai/nomic-embed-text-v1.5-GGUF/resolve/main/nomic-embed-text-v1.5.Q8_0.gguf",
        sha256: None,
        size_mb: 140,
        ram_mb: 250,
        license: "Apache-2.0",
        prefix: "classification: ",
        notes: "Good English quality with long context.",
    },
    CatalogModel {
        id: "qwen3-embedding-0.6b-q8",
        name: "Qwen3 Embedding 0.6B (Q8_0)",
        kind: ModelKind::Embedding,
        file: "Qwen3-Embedding-0.6B-Q8_0.gguf",
        url: "https://huggingface.co/Qwen/Qwen3-Embedding-0.6B-GGUF/resolve/main/Qwen3-Embedding-0.6B-Q8_0.gguf",
        sha256: None,
        size_mb: 640,
        ram_mb: 900,
        license: "Apache-2.0",
        prefix: "",
        notes: "Multilingual. Slower on CPU.",
    },
    CatalogModel {
        id: "llama-3.2-1b-instruct-q4",
        name: "Llama 3.2 1B Instruct (Q4_K_M)",
        kind: ModelKind::Chat,
        file: "Llama-3.2-1B-Instruct-Q4_K_M.gguf",
        url: "https://huggingface.co/bartowski/Llama-3.2-1B-Instruct-GGUF/resolve/main/Llama-3.2-1B-Instruct-Q4_K_M.gguf",
        sha256: None,
        size_mb: 810,
        ram_mb: 1_400,
        license: "Llama 3.2 Community",
        prefix: "",
        notes: "Fast fallback for uncertain messages.",
    },
    CatalogModel {
        id: "qwen3-1.7b-q8",
        name: "Qwen3 1.7B (Q8_0)",
        kind: ModelKind::Chat,
        file: "Qwen3-1.7B-Q8_0.gguf",
        url: "https://huggingface.co/Qwen/Qwen3-1.7B-GGUF/resolve/main/Qwen3-1.7B-Q8_0.gguf",
        sha256: None,
        size_mb: 1_830,
        ram_mb: 2_600,
        license: "Apache-2.0",
        prefix: "",
        notes: "Better judgement, multilingual. Slower.",
    },
];

pub fn models_dir(mail_root: &Path) -> PathBuf {
    mail_root.join("models")
}

pub fn catalog_entry(file: &str) -> Option<&'static CatalogModel> {
    CATALOG.iter().find(|model| model.file == file)
}

/// Sidecar metadata for an installed model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMeta {
    pub kind: ModelKind,
    pub url: String,
    pub sha256: String,
    pub size: u64,
    pub downloaded_at: i64,
    #[serde(default)]
    pub prefix: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstalledModel {
    pub file: String,
    pub size: u64,
    pub meta: Option<ModelMeta>,
}

/// A bare model file name: no directories, no hidden files, `.gguf` suffix.
pub fn validate_file_name(file: &str) -> Result<()> {
    if file.is_empty()
        || file.len() > 200
        || file.starts_with('.')
        || !file.ends_with(".gguf")
        || !file
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        bail!("model file names are letters, digits, '.', '-' and '_' ending in .gguf");
    }
    Ok(())
}

pub fn model_path(models_dir: &Path, file: &str) -> Result<PathBuf> {
    validate_file_name(file)?;
    Ok(models_dir.join(file))
}

fn meta_path(models_dir: &Path, file: &str) -> PathBuf {
    models_dir.join(format!("{file}.json"))
}

pub fn read_meta(models_dir: &Path, file: &str) -> Option<ModelMeta> {
    let text = std::fs::read_to_string(meta_path(models_dir, file)).ok()?;
    serde_json::from_str(&text).ok()
}

/// The input prefix for a model: from its sidecar, else the catalog.
pub fn prefix_for(models_dir: &Path, file: &str) -> String {
    read_meta(models_dir, file)
        .map(|meta| meta.prefix)
        .filter(|prefix| !prefix.is_empty())
        .or_else(|| catalog_entry(file).map(|model| model.prefix.to_string()))
        .unwrap_or_default()
}

pub fn list_installed(models_dir: &Path) -> Result<Vec<InstalledModel>> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(models_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let file = entry.file_name().to_string_lossy().to_string();
        if validate_file_name(&file).is_err() || !entry.file_type()?.is_file() {
            continue;
        }
        out.push(InstalledModel {
            size: entry.metadata()?.len(),
            meta: read_meta(models_dir, &file),
            file,
        });
    }
    out.sort_by(|a, b| a.file.cmp(&b.file));
    Ok(out)
}

pub fn delete_model(models_dir: &Path, file: &str) -> Result<()> {
    let path = model_path(models_dir, file)?;
    std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    let _ = std::fs::remove_file(meta_path(models_dir, file));
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadRequest {
    pub file: String,
    pub url: String,
    pub kind: ModelKind,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub prefix: String,
}

impl DownloadRequest {
    pub fn from_catalog(model: &CatalogModel) -> Self {
        Self {
            file: model.file.to_string(),
            url: model.url.to_string(),
            kind: model.kind,
            sha256: model.sha256.map(str::to_string),
            prefix: model.prefix.to_string(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_file_name(&self.file)?;
        if !self.url.starts_with("https://") {
            bail!("model downloads must use https");
        }
        if let Some(sha) = &self.sha256
            && (sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()))
        {
            bail!("sha256 must be 64 hex characters");
        }
        Ok(())
    }
}

/// Byte counters a caller can poll while a download runs.
#[derive(Debug, Default)]
pub struct Progress {
    pub received: AtomicU64,
    pub total: AtomicU64,
}

/// Stream `request.url` into the models directory, verify it, then publish it
/// atomically with its sidecar. A failed or mismatched download leaves
/// nothing behind.
pub async fn download(
    client: &reqwest::Client,
    models_dir: &Path,
    request: &DownloadRequest,
    progress: Arc<Progress>,
) -> Result<ModelMeta> {
    request.validate()?;
    fetch_verified(client, models_dir, request, progress).await
}

async fn fetch_verified(
    client: &reqwest::Client,
    models_dir: &Path,
    request: &DownloadRequest,
    progress: Arc<Progress>,
) -> Result<ModelMeta> {
    tokio::fs::create_dir_all(models_dir).await?;
    let target = model_path(models_dir, &request.file)?;
    let partial = models_dir.join(format!(".{}.part", request.file));
    let result = download_to(client, &partial, request, &progress).await;
    let sha256 = match result {
        Ok(sha256) => sha256,
        Err(error) => {
            let _ = tokio::fs::remove_file(&partial).await;
            return Err(error);
        }
    };
    if let Some(expected) = &request.sha256
        && !expected.eq_ignore_ascii_case(&sha256)
    {
        let _ = tokio::fs::remove_file(&partial).await;
        bail!("checksum mismatch: expected {expected}, got {sha256}");
    }
    let meta = ModelMeta {
        kind: request.kind,
        url: request.url.clone(),
        sha256,
        size: progress.received.load(Ordering::Relaxed),
        downloaded_at: crate::classifier_store::now(),
        prefix: request.prefix.clone(),
    };
    tokio::fs::rename(&partial, &target).await?;
    tokio::fs::write(
        meta_path(models_dir, &request.file),
        serde_json::to_vec_pretty(&meta)?,
    )
    .await?;
    Ok(meta)
}

async fn download_to(
    client: &reqwest::Client,
    partial: &Path,
    request: &DownloadRequest,
    progress: &Progress,
) -> Result<String> {
    let mut response = client
        .get(&request.url)
        .send()
        .await
        .context("starting download")?
        .error_for_status()
        .context("download refused")?;
    progress
        .total
        .store(response.content_length().unwrap_or(0), Ordering::Relaxed);
    let mut file = tokio::fs::File::create(partial).await?;
    let mut hasher = Sha256::new();
    while let Some(chunk) = response.chunk().await.context("reading download")? {
        hasher.update(&chunk);
        file.write_all(&chunk).await?;
        progress
            .received
            .fetch_add(chunk.len() as u64, Ordering::Relaxed);
    }
    file.flush().await?;
    file.sync_all().await?;
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_are_restricted() {
        assert!(validate_file_name("bge-small-en-v1.5-q8_0.gguf").is_ok());
        for bad in [
            "../x.gguf",
            "a/b.gguf",
            ".hidden.gguf",
            "model.bin",
            "",
            "a b.gguf",
        ] {
            assert!(validate_file_name(bad).is_err(), "{bad}");
        }
        for model in CATALOG {
            validate_file_name(model.file).unwrap();
            assert!(DownloadRequest::from_catalog(model).validate().is_ok());
        }
    }

    #[test]
    fn installed_models_read_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.gguf"), b"xx").unwrap();
        std::fs::write(dir.path().join(".b.gguf.part"), b"x").unwrap();
        let meta = ModelMeta {
            kind: ModelKind::Embedding,
            url: "https://example.test/a.gguf".into(),
            sha256: "00".repeat(32),
            size: 2,
            downloaded_at: 1,
            prefix: "classification: ".into(),
        };
        std::fs::write(
            meta_path(dir.path(), "a.gguf"),
            serde_json::to_vec(&meta).unwrap(),
        )
        .unwrap();
        let installed = list_installed(dir.path()).unwrap();
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0].meta.as_ref(), Some(&meta));
        assert_eq!(prefix_for(dir.path(), "a.gguf"), "classification: ");
        delete_model(dir.path(), "a.gguf").unwrap();
        assert!(list_installed(dir.path()).unwrap().is_empty());
    }

    /// Serve `body` once per connection over plain HTTP on loopback.
    async fn serve(body: &'static [u8]) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(body).await;
            }
        });
        format!("http://{addr}/m.gguf")
    }

    #[tokio::test]
    async fn downloads_are_verified_before_they_appear() {
        let dir = tempfile::tempdir().unwrap();
        let url = serve(b"model-bytes").await;
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let mut request = DownloadRequest {
            file: "m.gguf".into(),
            url,
            kind: ModelKind::Embedding,
            sha256: Some("00".repeat(32)),
            prefix: String::new(),
        };
        let error = fetch_verified(&client, dir.path(), &request, Arc::default())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("checksum mismatch"), "{error}");
        assert!(
            std::fs::read_dir(dir.path()).unwrap().next().is_none(),
            "nothing left behind"
        );

        request.sha256 = None;
        let progress = Arc::new(Progress::default());
        let meta = fetch_verified(&client, dir.path(), &request, progress.clone())
            .await
            .unwrap();
        assert_eq!(meta.sha256, hex(&Sha256::digest(b"model-bytes")));
        assert_eq!(progress.received.load(Ordering::Relaxed), 11);
        assert_eq!(read_meta(dir.path(), "m.gguf"), Some(meta.clone()));

        request.sha256 = Some(meta.sha256.to_uppercase());
        fetch_verified(&client, dir.path(), &request, Arc::default())
            .await
            .unwrap();
    }
}
