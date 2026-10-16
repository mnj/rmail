//! Labels through a provider's batch API (`background_tier = batch`).
//!
//! The worker queues each labeling question in the account's own store
//! (`classifier_store::LabelRequest`), so message text never leaves the
//! account's directory except to the provider. Once a cycle, [`step`]:
//!
//! - drops questions of accounts that withdrew consent or turned labels
//!   off, and those asked of another provider or model;
//! - sends the waiting questions of every account as one batch, once there
//!   are enough of them or the oldest has waited long enough;
//! - asks the provider about the batches in flight (at most once a minute
//!   each) and applies the answers of those that ended, exactly as answers
//!   from a direct call are applied. Questions a batch ended without an
//!   answer for are sent again, up to [`MAX_ATTEMPTS`] times.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use rmail_common::classifier_store::{self as store, LabelRequest};
use rmail_common::config::ClassifierConfig;
use rmail_common::imap_state;
use serde_json::{Value, json};

use crate::cloud::{BatchPoll, Batcher};
use crate::engine::{LabelHint, Models};
use crate::prompt::parse_labels;
use crate::worker::{CycleReport, apply_labeling};

/// Send a batch once this many questions wait...
const BATCH_MIN: usize = 100;
/// ...or the oldest has waited this long (seconds).
const BATCH_WAIT: i64 = if cfg!(test) { 0 } else { 15 * 60 };
/// Questions in one batch; well under both providers' limits.
const BATCH_MAX: usize = 2_000;
/// Times a question is sent before it is given up.
pub const MAX_ATTEMPTS: u32 = 3;
/// How often one batch is asked about.
const POLL_EVERY: Duration = if cfg!(test) {
    Duration::ZERO
} else {
    Duration::from_secs(60)
};

/// A random id for a question (providers allow `[A-Za-z0-9_-]{1,64}`).
pub fn new_id() -> String {
    (0..16)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect()
}

pub fn hints_json(hints: &[LabelHint]) -> String {
    Value::from(
        hints
            .iter()
            .map(|hint| json!({ "name": hint.name, "description": hint.description }))
            .collect::<Vec<_>>(),
    )
    .to_string()
}

fn hints_of(text: &str) -> Vec<LabelHint> {
    serde_json::from_str::<Vec<Value>>(text)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|hint| {
            Some(LabelHint {
                name: hint["name"].as_str()?.to_string(),
                description: hint["description"].as_str().unwrap_or_default().to_string(),
            })
        })
        .collect()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// When each batch was last asked about, across cycles.
fn last_polls() -> &'static Mutex<HashMap<String, Instant>> {
    static POLLS: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    POLLS.get_or_init(Default::default)
}

/// An account with questions in its store.
struct Queue {
    domain: String,
    localpart: String,
    requests: Vec<LabelRequest>,
}

pub fn step(mail_root: &Path, cfg: &ClassifierConfig, models: &Models, report: &mut CycleReport) {
    let Some((provider, batcher)) = &models.batcher else {
        return;
    };
    if let Err(error) = run(mail_root, cfg, models, provider, batcher.as_ref(), report) {
        classifier_log!("warn", "batch_step_failed", { "error": format!("{error:#}") });
        report.errors.push(format!("batch: {error:#}"));
    }
}

fn run(
    mail_root: &Path,
    cfg: &ClassifierConfig,
    models: &Models,
    provider: &str,
    batcher: &dyn Batcher,
    report: &mut CycleReport,
) -> Result<()> {
    let queues = gather(mail_root, models, provider)?;
    // A failed submission leaves the questions waiting for the next cycle;
    // batches already running are still collected.
    if let Err(error) = submit(mail_root, &queues, batcher, report) {
        classifier_log!("warn", "batch_submit_failed", { "error": format!("{error:#}") });
        report.errors.push(format!("batch submit: {error:#}"));
    }
    let queues = gather(mail_root, models, provider)?;
    collect(mail_root, cfg, &queues, batcher, report)
}

/// Every account's questions for this provider, after dropping those that
/// may no longer be asked.
fn gather(mail_root: &Path, models: &Models, provider: &str) -> Result<Vec<Queue>> {
    let mut queues = Vec::new();
    for (domain, localpart, _) in imap_state::list_accounts(mail_root)? {
        let Some(conn) = store::open_existing(mail_root, &domain, &localpart)? else {
            continue;
        };
        let requests = store::label_requests(&conn)?;
        if requests.is_empty() {
            continue;
        }
        let prefs = store::prefs(&conn)?;
        let allowed = prefs.labels_enabled
            && models
                .chat_cloud()
                .is_none_or(|cloud| prefs.allows_cloud(&[cloud]));
        let mut kept = Vec::new();
        for request in requests {
            if !allowed || request.provider != provider {
                store::remove_label_request(&conn, &request.custom_id)?;
            } else {
                kept.push(request);
            }
        }
        if !kept.is_empty() {
            queues.push(Queue {
                domain,
                localpart,
                requests: kept,
            });
        }
    }
    Ok(queues)
}

fn submit(
    mail_root: &Path,
    queues: &[Queue],
    batcher: &dyn Batcher,
    report: &mut CycleReport,
) -> Result<()> {
    let waiting: Vec<(&Queue, &LabelRequest)> = queues
        .iter()
        .flat_map(|queue| {
            queue
                .requests
                .iter()
                .filter(|request| request.batch_id.is_none())
                .map(move |request| (queue, request))
        })
        .collect();
    let oldest = waiting.iter().map(|(_, request)| request.created_at).min();
    let due = waiting.len() >= BATCH_MIN || oldest.is_some_and(|at| now() - at >= BATCH_WAIT);
    if !due {
        return Ok(());
    }
    let chosen = &waiting[..waiting.len().min(BATCH_MAX)];
    let requests: Vec<(String, Value)> = chosen
        .iter()
        .filter_map(|(_, request)| {
            Some((
                request.custom_id.clone(),
                serde_json::from_str(&request.body).ok()?,
            ))
        })
        .collect();
    let batch = batcher.submit(&requests)?;
    let mut by_account: BTreeMap<(&str, &str), Vec<String>> = BTreeMap::new();
    for (queue, request) in chosen {
        by_account
            .entry((&queue.domain, &queue.localpart))
            .or_default()
            .push(request.custom_id.clone());
    }
    for ((domain, localpart), ids) in by_account {
        if let Some(conn) = store::open_existing(mail_root, domain, localpart)? {
            store::mark_label_requests(&conn, &ids, &batch)?;
        }
    }
    classifier_log!("info", "batch_submitted", { "batch": batch, "requests": requests.len() });
    report.submitted += requests.len();
    Ok(())
}

fn collect(
    mail_root: &Path,
    cfg: &ClassifierConfig,
    queues: &[Queue],
    batcher: &dyn Batcher,
    report: &mut CycleReport,
) -> Result<()> {
    let mut batches: Vec<&str> = queues
        .iter()
        .flat_map(|queue| &queue.requests)
        .filter_map(|request| request.batch_id.as_deref())
        .collect();
    batches.sort_unstable();
    batches.dedup();
    for batch in batches {
        {
            let mut polls = last_polls().lock().unwrap_or_else(|e| e.into_inner());
            if polls.get(batch).is_some_and(|at| at.elapsed() < POLL_EVERY) {
                continue;
            }
            polls.insert(batch.to_string(), Instant::now());
        }
        // One batch the provider cannot report on does not hold up the others;
        // it is asked about again after POLL_EVERY.
        let answers = match batcher.poll(batch) {
            Ok(BatchPoll::Ended(answers)) => answers,
            Ok(BatchPoll::Running) => continue,
            Err(error) => {
                classifier_log!("warn", "batch_poll_failed", { "batch": batch, "error": format!("{error:#}") });
                report.errors.push(format!("batch {batch}: {error:#}"));
                continue;
            }
        };
        let answers: HashMap<String, Result<String, String>> = answers.into_iter().collect();
        for queue in queues {
            let mine: Vec<&LabelRequest> = queue
                .requests
                .iter()
                .filter(|request| request.batch_id.as_deref() == Some(batch))
                .collect();
            if mine.is_empty() {
                continue;
            }
            let Some(conn) = store::open_existing(mail_root, &queue.domain, &queue.localpart)?
            else {
                continue;
            };
            let (inbox, _) =
                imap_state::load_folder(mail_root, &queue.domain, &queue.localpart, "INBOX")?;
            let mut labels = store::labels(&conn)?;
            let threshold = cfg.label_confidence as f64 / 100.0;
            for request in mine {
                match answers.get(&request.custom_id) {
                    Some(Ok(text)) => {
                        // Answers about an INBOX that was rebuilt since are
                        // about other messages.
                        if request.uidvalidity == inbox.uidvalidity {
                            let mut hints = hints_of(&request.hints);
                            let answer = parse_labels(text, &hints, request.may_propose);
                            if apply_labeling(
                                mail_root,
                                &queue.domain,
                                &queue.localpart,
                                &conn,
                                request.uidvalidity,
                                request.uid,
                                answer,
                                &mut labels,
                                &mut hints,
                                threshold,
                            )? {
                                report.labeled += 1;
                            }
                        }
                        report.answered += 1;
                        store::remove_label_request(&conn, &request.custom_id)?;
                    }
                    _ if request.attempts >= MAX_ATTEMPTS => {
                        store::remove_label_request(&conn, &request.custom_id)?;
                    }
                    _ => store::requeue_label_request(&conn, &request.custom_id)?,
                }
            }
        }
        last_polls()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(batch);
        classifier_log!("info", "batch_collected", { "batch": batch, "answers": answers.len() });
    }
    Ok(())
}
