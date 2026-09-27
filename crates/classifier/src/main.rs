//! rmail_classifier: suggests folders for new INBOX mail using local models.
//!
//! - `engine` loads models behind small traits; `llama` runs GGUF files with
//!   llama.cpp in-process.
//! - `pipeline` decides a folder from sender history, an embedding vote and,
//!   when unsure, the chat model.
//! - `worker` runs one poll cycle over the accounts that opted in.
//! - `control` serves status, reload and model tests to the admin console.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rmail_common::config::Config;
use serde_json::json;
use tokio::sync::{Notify, RwLock};

macro_rules! classifier_log {
    ($level:expr, $event:expr, $fields:tt) => {
        rmail_common::structured_log!($level, "classifier", $event, $fields)
    };
}

mod control;
mod engine;
#[cfg(feature = "local-models")]
mod llama;
mod pipeline;
mod worker;

use engine::Models;
use worker::CycleReport;

pub struct Runtime {
    pub config: Config,
    pub models: Models,
}

#[derive(Default)]
struct Status {
    last_cycle: Option<(i64, u64, CycleReport)>,
    loaded_at: i64,
}

pub struct Shared {
    cfg_path: String,
    runtime: RwLock<Arc<Runtime>>,
    status: Mutex<Status>,
    reload_lock: tokio::sync::Mutex<()>,
    wake: Notify,
}

impl Shared {
    pub async fn runtime(&self) -> Arc<Runtime> {
        self.runtime.read().await.clone()
    }

    /// Re-read settings and reload the models whose files changed.
    pub async fn reload(&self) -> Result<()> {
        let _guard = self.reload_lock.lock().await;
        let path = self.cfg_path.clone();
        let config = tokio::task::spawn_blocking(move || Config::load(&path)).await??;
        // The daemon now runs this revision, so the console stops asking for a restart.
        if let Err(error) = rmail_common::settings::record_service_start(&config, "classifier") {
            classifier_log!("warn", "service_state_failed", { "error": format!("{error:#}") });
        }
        let previous = self.runtime().await;
        let runtime =
            tokio::task::spawn_blocking(move || load_runtime(config, &previous.models)).await?;
        *self.runtime.write().await = Arc::new(runtime);
        self.status.lock().unwrap().loaded_at = rmail_common::classifier_store::now();
        self.wake.notify_one();
        Ok(())
    }

    pub async fn status_json(&self) -> serde_json::Value {
        let runtime = self.runtime().await;
        let mail_root = PathBuf::from(&runtime.config.global.mail_root);
        let accounts = tokio::task::spawn_blocking(move || worker::folder_counts(&mail_root))
            .await
            .unwrap_or_default();
        let status = self.status.lock().unwrap();
        let cfg = &runtime.config.classifier;
        json!({
            "enabled": cfg.enabled,
            "local_models": cfg!(feature = "local-models"),
            "embed_model": runtime.models.embed_info,
            "chat_model": runtime.models.chat_info,
            "configured": { "embed_model": cfg.embed_model, "chat_model": cfg.chat_model },
            "errors": runtime.models.errors,
            "accounts": accounts,
            "loaded_at": status.loaded_at,
            "last_cycle": status.last_cycle.as_ref().map(|(at, ms, report)| json!({
                "finished_at": at, "duration_ms": ms, "report": report,
            })),
        })
    }
}

fn load_runtime(config: Config, previous: &Models) -> Runtime {
    let models = Models::load(&config.classifier, &config.models_dir(), previous);
    for error in &models.errors {
        classifier_log!("error", "model_load_failed", { "error": error });
    }
    if let Some(info) = &models.embed_info {
        classifier_log!("info", "model_loaded", { "kind": "embedding", "file": info.file, "load_ms": info.load_ms });
    }
    if let Some(info) = &models.chat_info {
        classifier_log!("info", "model_loaded", { "kind": "chat", "file": info.file, "load_ms": info.load_ms });
    }
    Runtime { config, models }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg_path =
        std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string());
    let config = Config::load(&cfg_path).with_context(|| format!("loading {cfg_path}"))?;
    rmail_common::runtime::set_log_level(config.global.log_level.as_deref());
    let mail_root = PathBuf::from(&config.global.mail_root);
    rmail_common::runtime::redirect_stdio_to_log(&mail_root, "classifier")
        .context("redirecting logs")?;
    if let Err(error) = rmail_common::settings::record_service_start(&config, "classifier") {
        classifier_log!("warn", "service_state_failed", { "error": format!("{error:#}") });
    }
    let socket = config.classifier_socket();
    let runtime =
        tokio::task::spawn_blocking(move || load_runtime(config, &Models::default())).await?;
    let shared = Arc::new(Shared {
        cfg_path,
        runtime: RwLock::new(Arc::new(runtime)),
        status: Mutex::new(Status {
            loaded_at: rmail_common::classifier_store::now(),
            ..Status::default()
        }),
        reload_lock: tokio::sync::Mutex::new(()),
        wake: Notify::new(),
    });

    let control_shared = shared.clone();
    tokio::spawn(async move {
        if let Err(error) = control::serve(control_shared, &socket).await {
            classifier_log!("error", "control_socket_failed", { "error": format!("{error:#}") });
        }
    });

    // SIGHUP (systemctl reload) re-reads settings like the console's Reload.
    let hup_shared = shared.clone();
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .context("installing SIGHUP handler")?;
    tokio::spawn(async move {
        while hangup.recv().await.is_some() {
            match hup_shared.reload().await {
                Ok(()) => classifier_log!("info", "reloaded", { "trigger": "SIGHUP" }),
                Err(error) => {
                    classifier_log!("error", "reload_failed", { "error": format!("{error:#}") })
                }
            }
        }
    });

    let poll_shared = shared.clone();
    let poller = tokio::spawn(async move { poll_loop(poll_shared).await });
    rmail_common::runtime::wait_for_shutdown_signal().await?;
    classifier_log!("info", "shutdown_requested", {});
    poller.abort();
    Ok(())
}

async fn poll_loop(shared: Arc<Shared>) {
    loop {
        let runtime = shared.runtime().await;
        let interval = Duration::from_secs(runtime.config.classifier.poll_interval_seconds.max(1));
        let started = Instant::now();
        let mail_root = PathBuf::from(&runtime.config.global.mail_root);
        let cycle_runtime = runtime.clone();
        let report = tokio::task::spawn_blocking(move || {
            worker::run_cycle(
                &mail_root,
                &cycle_runtime.config.classifier,
                &cycle_runtime.models,
            )
        })
        .await
        .unwrap_or_else(|error| CycleReport {
            errors: vec![format!("cycle panicked: {error}")],
            ..CycleReport::default()
        });
        let elapsed = started.elapsed().as_millis() as u64;
        if report.learned + report.classified > 0 || !report.errors.is_empty() {
            classifier_log!("info", "cycle_finished", {
                "duration_ms": elapsed, "accounts": report.accounts, "learned": report.learned,
                "classified": report.classified, "suggested": report.suggested,
                "moved": report.moved, "errors": report.errors.len()
            });
        }
        let busy = report.learned > 0;
        shared.status.lock().unwrap().last_cycle =
            Some((rmail_common::classifier_store::now(), elapsed, report));
        // Keep going without waiting while a backfill is in progress.
        if busy {
            continue;
        }
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shared.wake.notified() => {}
        }
    }
}
