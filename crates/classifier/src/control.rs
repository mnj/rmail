//! The Unix control socket the admin console uses for status, reloads and
//! model tests (see `rmail_common::classifier_control`).

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use rmail_common::classifier_control::{MAX_LINE, Reply, Request};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::Shared;
use crate::engine::FolderHint;

pub async fn serve(shared: Arc<Shared>, socket: &Path) -> Result<()> {
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // A socket left by a previous run blocks bind.
    let _ = std::fs::remove_file(socket);
    let listener =
        UnixListener::bind(socket).with_context(|| format!("binding {}", socket.display()))?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o660))?;
    classifier_log!("info", "control_socket_started", { "path": socket.display().to_string() });
    loop {
        let (stream, _) = listener.accept().await?;
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(error) = handle(shared, stream).await {
                classifier_log!("debug", "control_request_failed", { "error": format!("{error:#}") });
            }
        });
    }
}

async fn handle(shared: Arc<Shared>, stream: UnixStream) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read.take(MAX_LINE as u64));
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let reply = match serde_json::from_str::<Request>(line.trim()) {
        Ok(request) => match execute(&shared, request).await {
            Ok(data) => Reply::ok(data),
            Err(error) => Reply::error(format!("{error:#}")),
        },
        Err(error) => Reply::error(format!("invalid request: {error}")),
    };
    let mut encoded = serde_json::to_vec(&reply)?;
    encoded.push(b'\n');
    write.write_all(&encoded).await?;
    write.shutdown().await?;
    Ok(())
}

async fn execute(shared: &Arc<Shared>, request: Request) -> Result<serde_json::Value> {
    match request {
        Request::Status => Ok(shared.status_json().await),
        Request::Reload => {
            shared.reload().await?;
            Ok(shared.status_json().await)
        }
        Request::TestEmbed { text } => {
            let runtime = shared.runtime().await;
            let embedder = runtime
                .models
                .embedder
                .clone()
                .context("no embedding model is loaded")?;
            let file = runtime.models.embed_info.as_ref().map(|m| m.file.clone());
            let started = Instant::now();
            let vector = tokio::task::spawn_blocking(move || embedder.embed(&[text]))
                .await??
                .remove(0);
            Ok(json!({
                "model": file,
                "dimensions": vector.len(),
                "ms": started.elapsed().as_millis() as u64,
                "preview": vector.iter().take(8).collect::<Vec<_>>(),
            }))
        }
        Request::TestChat { text, folders } => {
            if folders.is_empty() {
                bail!("give at least one folder name");
            }
            let runtime = shared.runtime().await;
            let chooser = runtime
                .models
                .chooser
                .clone()
                .context("no chat model is loaded")?;
            let file = runtime.models.chat_info.as_ref().map(|m| m.file.clone());
            let hints: Vec<FolderHint> = folders
                .into_iter()
                .map(|name| FolderHint {
                    name,
                    examples: Vec::new(),
                })
                .collect();
            let started = Instant::now();
            let choice =
                tokio::task::spawn_blocking(move || chooser.choose(&text, &hints)).await??;
            Ok(json!({
                "model": file,
                "folder": choice.folder,
                "confidence": choice.confidence,
                "raw": choice.raw,
                "ms": started.elapsed().as_millis() as u64,
            }))
        }
    }
}
