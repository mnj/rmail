//! One poll cycle over the accounts that opted in.
//!
//! Per account: learn from messages newly filed into eligible folders
//! (whatever client filed them), then classify new INBOX mail once learning
//! has caught up. Watermarks in the account's store make every step resumable.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result};
use rmail_common::classifier_store::{self as store, Example, Suggestion, Watermark};
use rmail_common::config::ClassifierConfig;
use rmail_common::imap_state::{self, Folder, Message};
use serde::Serialize;

use crate::engine::Models;
use crate::pipeline::{self, Decision, Inputs};

/// Messages embedded per account per cycle, so one large backfill cannot
/// starve other accounts or new mail.
const LEARN_BUDGET: usize = 256;
/// Embedding batch size.
const EMBED_BATCH: usize = 16;
/// INBOX messages given suggestions when an account first opts in.
const INITIAL_INBOX_SUGGESTIONS: usize = 50;
/// Messages labeled per account per cycle; each is one model call.
const LABEL_BUDGET: usize = 32;
/// INBOX messages labeled when an account first turns labels on.
const INITIAL_INBOX_LABELS: usize = 50;
/// Most labels put on one message.
const MAX_LABELS_PER_MESSAGE: usize = 3;
/// Messages added to an account's search index per cycle.
const SEARCH_BUDGET: usize = 256;
/// Messages queued for the batch API per account per cycle; each is a
/// request in a batch, not a call.
const BATCH_QUEUE_BUDGET: usize = 500;

#[derive(Debug, Default, Clone, Serialize)]
pub struct CycleReport {
    pub accounts: usize,
    pub learned: usize,
    pub classified: usize,
    pub suggested: usize,
    pub moved: usize,
    /// Messages that got at least one label.
    pub labeled: usize,
    /// Messages added to search indexes.
    pub indexed: usize,
    /// Labeling questions queued for the batch API, submitted in a batch,
    /// and answered from one.
    pub queued: usize,
    pub submitted: usize,
    pub answered: usize,
    /// Opted-in accounts skipped (in whole or in part) because a model is a
    /// cloud provider their user has not agreed to.
    pub awaiting_consent: usize,
    pub errors: Vec<String>,
}

pub fn run_cycle(mail_root: &Path, cfg: &ClassifierConfig, models: &Models) -> CycleReport {
    let mut report = CycleReport::default();
    if !cfg.enabled || (models.embedder.is_none() && models.chooser.is_none()) {
        return report;
    }
    let accounts = match imap_state::list_accounts(mail_root) {
        Ok(accounts) => accounts,
        Err(error) => {
            report.errors.push(format!("listing accounts: {error:#}"));
            return report;
        }
    };
    for (domain, localpart, _maildir) in accounts {
        let conn = match store::open_existing(mail_root, &domain, &localpart) {
            Ok(Some(conn)) => conn,
            Ok(None) => continue,
            Err(error) => {
                report
                    .errors
                    .push(format!("{localpart}@{domain}: {error:#}"));
                continue;
            }
        };
        let prefs = match store::prefs(&conn) {
            Ok(prefs) if prefs.any_enabled() => prefs,
            _ => continue,
        };
        drop(conn);
        // Mail only reaches a cloud provider the account's user agreed to.
        let allowed = |provider: Option<&str>| provider.is_none_or(|p| prefs.allows_cloud(&[p]));
        let embed_allowed = allowed(models.embed_cloud());
        let chat_allowed = allowed(models.chat_cloud());
        let folders = prefs.enabled && models.embedder.is_some() && embed_allowed;
        // Labels have no local stand-in for a cloud model the user refused.
        let labels = prefs.labels_enabled && models.chooser.is_some() && chat_allowed;
        let search = prefs.search_enabled && models.embedder.is_some() && embed_allowed;
        if ((prefs.enabled || prefs.search_enabled) && !embed_allowed)
            || (prefs.labels_enabled && !chat_allowed)
        {
            report.awaiting_consent += 1;
        }
        if !folders && !labels && !search {
            continue;
        }
        report.accounts += 1;
        let mut account = Account {
            mail_root,
            domain: &domain,
            localpart: &localpart,
            cfg,
            models,
            use_chooser: chat_allowed,
            report: &mut report,
        };
        // Label first, so messages auto-moved by the folder pass keep their labels.
        let mut result = Ok(());
        if labels {
            result = account.label_inbox();
        }
        if folders && result.is_ok() {
            result = account.run();
        }
        if search && result.is_ok() {
            result = account.index_search();
        }
        if let Err(error) = result {
            classifier_log!("warn", "account_cycle_failed", { "account": format!("{localpart}@{domain}"), "error": format!("{error:#}") });
            report
                .errors
                .push(format!("{localpart}@{domain}: {error:#}"));
        }
    }
    crate::batch::step(mail_root, cfg, models, &mut report);
    report
}

struct Account<'a> {
    mail_root: &'a Path,
    domain: &'a str,
    localpart: &'a str,
    cfg: &'a ClassifierConfig,
    models: &'a Models,
    /// False when the chooser is a cloud provider this user has not agreed to.
    use_chooser: bool,
    report: &'a mut CycleReport,
}

impl Account<'_> {
    /// Add the account's newest unindexed messages to its search index
    /// (every folder but Trash and Junk), and forget what is gone.
    fn index_search(&mut self) -> Result<()> {
        let embedder = self.models.embedder.clone().context("no embedding model")?;
        let conn = store::open_or_create(self.mail_root, self.domain, self.localpart)?;
        let searched: Vec<Folder> =
            imap_state::list_folders(self.mail_root, self.domain, self.localpart)?
                .into_iter()
                .filter(|f| !matches!(f.special_use.as_deref(), Some("\\Trash" | "\\Junk")))
                .collect();
        store::keep_search_folders(
            &conn,
            &searched.iter().map(|f| f.name.clone()).collect::<Vec<_>>(),
        )?;
        let mut budget = SEARCH_BUDGET;
        for folder in &searched {
            let (info, messages) =
                imap_state::load_folder(self.mail_root, self.domain, self.localpart, &folder.name)?;
            let present = messages.iter().map(|m| m.uid).collect();
            store::prune_search(
                &conn,
                &folder.name,
                info.uidvalidity,
                embedder.model_id(),
                &present,
            )?;
            if budget == 0 {
                continue;
            }
            let indexed =
                store::search_indexed(&conn, &folder.name, info.uidvalidity, embedder.model_id())?;
            let mut todo: Vec<&Message> = messages
                .iter()
                .filter(|m| !indexed.contains(&m.uid))
                .collect();
            todo.sort_by_key(|m| std::cmp::Reverse(m.uid));
            // Only embedded messages count against the budget, so unreadable
            // ones (tried again next cycle) cannot starve older mail; reads
            // are bounded all the same.
            let mut reads = budget * 4;
            let mut candidates = todo.into_iter();
            while budget > 0 && reads > 0 {
                let mut docs: Vec<(u64, String)> = Vec::new();
                for message in candidates.by_ref() {
                    reads -= 1;
                    if let Some(doc) = read_document(&message.path, self.cfg) {
                        docs.push((message.uid, doc.text));
                    }
                    if docs.len() == EMBED_BATCH.min(budget) || reads == 0 {
                        break;
                    }
                }
                if docs.is_empty() {
                    break;
                }
                budget = budget.saturating_sub(docs.len());
                let texts: Vec<String> = docs.iter().map(|(_, text)| text.clone()).collect();
                let vectors = embedder.embed(&texts)?;
                for ((uid, _), vector) in docs.iter().zip(vectors) {
                    store::put_search_vector(
                        &conn,
                        &folder.name,
                        info.uidvalidity,
                        *uid,
                        embedder.model_id(),
                        &vector,
                    )?;
                }
                self.report.indexed += docs.len();
            }
        }
        Ok(())
    }

    /// Apply the user's labels to new INBOX mail as IMAP keywords. Resumes
    /// from its own watermark; a failed model call leaves the message for
    /// the next cycle.
    fn label_inbox(&mut self) -> Result<()> {
        let chooser = self.models.worker_chooser().context("no fallback model")?;
        let conn = store::open_existing(self.mail_root, self.domain, self.localpart)?
            .context("store disappeared")?;
        store::seed_starter_labels(&conn)?;
        let mut labels = store::labels(&conn)?;
        let (inbox, messages) =
            imap_state::load_folder(self.mail_root, self.domain, self.localpart, "INBOX")?;
        let mark = store::label_mark(&conn)?;
        let high = messages.iter().map(|m| m.uid).max().unwrap_or(0);
        let first = mark.is_none_or(|m| m.uidvalidity != inbox.uidvalidity);
        let discover = self.cfg.label_discovery;
        if labels.is_empty() && !discover {
            // Nothing to apply; start from new mail once labels exist.
            return store::set_label_mark(
                &conn,
                Watermark {
                    uidvalidity: inbox.uidvalidity,
                    last_uid: high,
                },
            );
        }
        let mut pending: Vec<&Message> = if first {
            newest(&messages, INITIAL_INBOX_LABELS)
        } else {
            let last = mark.map_or(0, |m| m.last_uid);
            messages.iter().filter(|m| m.uid > last).collect()
        };
        pending.sort_by_key(|m| m.uid);
        let hint = |label: &store::Label| crate::engine::LabelHint {
            name: label.name.clone(),
            description: label.description.clone(),
        };
        let mut hints: Vec<crate::engine::LabelHint> = labels.iter().map(hint).collect();
        let threshold = self.cfg.label_confidence as f64 / 100.0;
        let mut done = mark.filter(|_| !first).map_or(0, |m| m.last_uid);
        let batch = self.models.batcher.clone();
        let budget = if batch.is_some() {
            BATCH_QUEUE_BUDGET
        } else {
            LABEL_BUDGET
        };
        let caught_up = pending.len() <= budget;
        for message in pending.into_iter().take(budget) {
            if let Some(doc) = read_document(&message.path, self.cfg) {
                if let Some((provider, batcher)) = &batch {
                    // Asked through the batch API; the answer is applied
                    // when it comes back (`crate::batch`).
                    let body = batcher.label_request(&doc.text, &hints, discover);
                    store::queue_label_request(
                        &conn,
                        &store::LabelRequest {
                            custom_id: crate::batch::new_id(),
                            uidvalidity: inbox.uidvalidity,
                            uid: message.uid,
                            hints: crate::batch::hints_json(&hints),
                            may_propose: discover,
                            provider: provider.clone(),
                            body: body.to_string(),
                            batch_id: None,
                            attempts: 0,
                            created_at: chrono_now(),
                        },
                    )?;
                    self.report.queued += 1;
                } else {
                    let answer = chooser.label(&doc.text, &hints, discover)?;
                    if apply_labeling(
                        self.mail_root,
                        self.domain,
                        self.localpart,
                        &conn,
                        inbox.uidvalidity,
                        message.uid,
                        answer,
                        &mut labels,
                        &mut hints,
                        threshold,
                    )? {
                        self.report.labeled += 1;
                    }
                }
            }
            done = done.max(message.uid);
            store::set_label_mark(
                &conn,
                Watermark {
                    uidvalidity: inbox.uidvalidity,
                    last_uid: done,
                },
            )?;
        }
        if caught_up {
            store::set_label_mark(
                &conn,
                Watermark {
                    uidvalidity: inbox.uidvalidity,
                    last_uid: high.max(done),
                },
            )?;
        }
        Ok(())
    }

    fn run(&mut self) -> Result<()> {
        let embedder = self.models.embedder.clone().context("no embedding model")?;
        let conn = store::open_existing(self.mail_root, self.domain, self.localpart)?
            .context("store disappeared")?;
        let prefs = store::prefs(&conn)?;
        if store::has_stale_examples(&conn, embedder.model_id())? {
            classifier_log!("info", "relearning", { "account": self.name(), "reason": "embedding model changed" });
            store::reset_learning(&conn)?;
        }

        let folders = imap_state::list_folders(self.mail_root, self.domain, self.localpart)?;
        let eligible: Vec<&Folder> = folders
            .iter()
            .filter(|folder| is_eligible(folder, &prefs.excluded_folders))
            .collect();
        let eligible_names: Vec<String> = eligible.iter().map(|f| f.name.clone()).collect();
        let mut marks = store::watermarks(&conn)?;

        // Forget folders that were deleted, renamed or excluded.
        for folder in marks.keys().cloned().collect::<Vec<_>>() {
            if folder != "INBOX" && !eligible_names.contains(&folder) {
                store::remove_folder_examples(&conn, &folder)?;
                store::remove_watermark(&conn, &folder)?;
                marks.remove(&folder);
            }
        }

        let mut budget = LEARN_BUDGET;
        let mut caught_up = true;
        for folder in &eligible {
            let mark = marks.get(&folder.name).copied();
            let fresh = mark.is_none_or(|m| m.uidvalidity != folder.uidvalidity);
            if !fresh && folder.uidnext.saturating_sub(1) <= mark.map_or(0, |m| m.last_uid) {
                continue;
            }
            if fresh {
                store::remove_folder_examples(&conn, &folder.name)?;
            }
            let (_, messages) =
                imap_state::load_folder(self.mail_root, self.domain, self.localpart, &folder.name)?;
            let mut pending: Vec<&Message> = match (fresh, mark) {
                (false, Some(mark)) => messages.iter().filter(|m| m.uid > mark.last_uid).collect(),
                _ => newest(&messages, self.cfg.backfill_per_folder as usize),
            };
            pending.sort_by_key(|m| m.uid);
            let floor = if fresh {
                // Backfill starts below the oldest message it will learn.
                pending
                    .first()
                    .map_or(folder.uidnext.saturating_sub(1), |m| m.uid - 1)
            } else {
                mark.map_or(0, |m| m.last_uid)
            };
            let take = pending.len().min(budget);
            if take < pending.len() {
                caught_up = false;
            }
            let chunk = &pending[..take];
            let source = if fresh { "backfill" } else { "filed" };
            let learned = self.learn(&conn, &folder.name, chunk, source, embedder.as_ref())?;
            budget -= take;
            self.report.learned += learned;
            // Messages are learned oldest first, so the watermark can advance
            // to the last one learned; the rest are newer and follow next cycle.
            let last_uid = if take == pending.len() {
                folder.uidnext.saturating_sub(1).max(floor)
            } else {
                chunk.last().map_or(floor, |m| m.uid)
            };
            store::set_watermark(
                &conn,
                &folder.name,
                Watermark {
                    uidvalidity: folder.uidvalidity,
                    last_uid,
                },
            )?;
            if budget == 0 {
                caught_up = false;
                break;
            }
        }
        if !caught_up {
            return Ok(());
        }
        self.classify_inbox(&conn, &prefs, &eligible_names, marks.get("INBOX").copied())
    }

    fn learn(
        &self,
        conn: &rusqlite_conn::Conn,
        folder: &str,
        messages: &[&Message],
        source: &str,
        embedder: &dyn crate::engine::Embedder,
    ) -> Result<usize> {
        let mut learned = 0;
        for batch in messages.chunks(EMBED_BATCH) {
            let docs: Vec<(u64, pipeline::Document)> = batch
                .iter()
                .filter_map(|m| read_document(&m.path, self.cfg).map(|doc| (m.uid, doc)))
                .collect();
            if docs.is_empty() {
                continue;
            }
            let texts: Vec<String> = docs.iter().map(|(_, doc)| doc.text.clone()).collect();
            let vectors = embedder.embed(&texts)?;
            for ((uid, doc), embedding) in docs.into_iter().zip(vectors) {
                store::insert_example(
                    conn,
                    &Example {
                        folder: folder.to_string(),
                        uid,
                        sender: doc.sender,
                        list_id: doc.list_id,
                        subject: doc.subject,
                        embedding,
                    },
                    embedder.model_id(),
                    source,
                )?;
                learned += 1;
            }
        }
        Ok(learned)
    }

    fn classify_inbox(
        &mut self,
        conn: &rusqlite_conn::Conn,
        prefs: &store::Prefs,
        eligible: &[String],
        mark: Option<Watermark>,
    ) -> Result<()> {
        let (inbox, messages) =
            imap_state::load_folder(self.mail_root, self.domain, self.localpart, "INBOX")?;
        let first = mark.is_none_or(|m| m.uidvalidity != inbox.uidvalidity);
        let present: BTreeSet<u64> = messages.iter().map(|m| m.uid).collect();
        for stale in store::pending_suggestions(conn, inbox.uidvalidity)? {
            if !present.contains(&stale.uid) {
                store::set_suggestion_state(conn, inbox.uidvalidity, stale.uid, "gone")?;
            }
        }
        let mut pending: Vec<&Message> = if first {
            newest(&messages, INITIAL_INBOX_SUGGESTIONS)
        } else {
            let last = mark.map_or(0, |m| m.last_uid);
            messages.iter().filter(|m| m.uid > last).collect()
        };
        pending.sort_by_key(|m| m.uid);
        let high = messages
            .iter()
            .map(|m| m.uid)
            .max()
            .unwrap_or(0)
            .max(mark.map_or(0, |m| m.last_uid));
        if pending.is_empty() || eligible.is_empty() {
            return store::set_watermark(
                conn,
                "INBOX",
                Watermark {
                    uidvalidity: inbox.uidvalidity,
                    last_uid: high,
                },
            );
        }

        let embedder = self.models.embedder.clone().context("no embedding model")?;
        let examples = store::examples(conn, embedder.model_id())?;
        let dismissals = store::dismissals(conn)?;
        let mut handled = mark.filter(|_| !first).map_or(0, |m| m.last_uid);
        for message in pending {
            let Some(doc) = read_document(&message.path, self.cfg) else {
                handled = handled.max(message.uid);
                continue;
            };
            let embedding = embedder.embed(std::slice::from_ref(&doc.text))?.remove(0);
            let dismissed = dismissals.get(&doc.sender).cloned().unwrap_or_default();
            let decision = pipeline::decide(
                &Inputs {
                    doc: &doc,
                    embedding: &embedding,
                    examples: &examples,
                    folders: eligible,
                    dismissed: &dismissed,
                },
                self.cfg,
                self.models
                    .worker_chooser()
                    .filter(|_| self.use_chooser)
                    .as_deref(),
            )?;
            self.report.classified += 1;
            if let Some(decision) = decision {
                // No automatic moves for the backlog found at opt-in.
                let autofile = !first
                    && prefs.autofile_folders.contains(&decision.folder)
                    && decision.may_autofile(self.cfg);
                self.apply(
                    conn,
                    inbox.uidvalidity,
                    message.uid,
                    &doc,
                    &decision,
                    autofile,
                )?;
            }
            handled = handled.max(message.uid);
            store::set_watermark(
                conn,
                "INBOX",
                Watermark {
                    uidvalidity: inbox.uidvalidity,
                    last_uid: handled,
                },
            )?;
        }
        store::set_watermark(
            conn,
            "INBOX",
            Watermark {
                uidvalidity: inbox.uidvalidity,
                last_uid: high,
            },
        )
    }

    fn apply(
        &mut self,
        conn: &rusqlite_conn::Conn,
        uidvalidity: u64,
        uid: u64,
        doc: &pipeline::Document,
        decision: &Decision,
        autofile: bool,
    ) -> Result<()> {
        let mut suggestion = Suggestion {
            uidvalidity,
            uid,
            folder: decision.folder.clone(),
            score: decision.score,
            method: decision.method.to_string(),
            state: "pending".to_string(),
            sender: doc.sender.clone(),
            created_at: store::now(),
        };
        if autofile {
            imap_state::move_message_by_uid(
                self.mail_root,
                self.domain,
                self.localpart,
                "INBOX",
                uid,
                &decision.folder,
            )?;
            suggestion.state = "moved".to_string();
            store::record_suggestion(conn, &suggestion)?;
            self.report.moved += 1;
            classifier_log!("info", "message_moved", {
                "account": self.name(), "uid": uid, "folder": decision.folder,
                "score": decision.score, "method": decision.method
            });
        } else {
            store::record_suggestion(conn, &suggestion)?;
            store::set_keyword(
                self.mail_root,
                self.domain,
                self.localpart,
                "INBOX",
                uid,
                store::SUGGESTED_KEYWORD,
                true,
            )?;
            self.report.suggested += 1;
            classifier_log!("debug", "message_suggested", {
                "account": self.name(), "uid": uid, "folder": decision.folder,
                "score": decision.score, "method": decision.method
            });
        }
        Ok(())
    }

    fn name(&self) -> String {
        format!("{}@{}", self.localpart, self.domain)
    }
}

/// The store's pooled connection type.
mod rusqlite_conn {
    pub type Conn = rmail_common::sqlite_pool::SqliteConnection;
}

/// User folders the account has not excluded.
/// Put the labels a model chose (and one it proposed, if any) on an INBOX
/// message; whether it got any. A message no longer in INBOX is skipped.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_labeling(
    mail_root: &Path,
    domain: &str,
    localpart: &str,
    conn: &rusqlite::Connection,
    uidvalidity: u64,
    uid: u64,
    answer: crate::engine::Labeling,
    labels: &mut Vec<store::Label>,
    hints: &mut Vec<crate::engine::LabelHint>,
    threshold: f64,
) -> Result<bool> {
    let mut applied: Vec<(String, f64)> = answer
        .labels
        .into_iter()
        .filter(|(_, probability)| *probability >= threshold)
        .collect();
    applied.sort_by(|a, b| b.1.total_cmp(&a.1));
    applied.truncate(MAX_LABELS_PER_MESSAGE);
    // The model found no fitting label and named one; it applies to this
    // message and is offered for later mail.
    if let Some((name, description)) = answer.proposed
        && applied.len() < MAX_LABELS_PER_MESSAGE
        && let Some(label) = store::add_ai_label(conn, &name, &description)?
    {
        classifier_log!("info", "label_created", { "account": format!("{localpart}@{domain}"), "label": label.name });
        hints.push(crate::engine::LabelHint {
            name: label.name.clone(),
            description: label.description.clone(),
        });
        applied.push((label.name.clone(), 1.0));
        labels.push(label);
    }
    for (name, _) in &applied {
        if let Some(label) = labels.iter().find(|label| &label.name == name) {
            store::set_keyword(
                mail_root,
                domain,
                localpart,
                "INBOX",
                uid,
                &label.keyword,
                true,
            )?;
        }
    }
    if applied.is_empty() {
        return Ok(false);
    }
    store::record_labels(conn, uidvalidity, uid, &applied)?;
    Ok(true)
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

pub fn is_eligible(folder: &Folder, excluded: &[String]) -> bool {
    store::is_user_folder(folder) && !excluded.iter().any(|name| name == &folder.name)
}

fn newest(messages: &[Message], count: usize) -> Vec<&Message> {
    let mut sorted: Vec<&Message> = messages.iter().collect();
    sorted.sort_by_key(|m| std::cmp::Reverse(m.uid));
    sorted.truncate(count);
    sorted
}

fn read_document(path: &Path, cfg: &ClassifierConfig) -> Option<pipeline::Document> {
    // Headers plus the start of the body are enough; skip huge attachments.
    let limit = (cfg.max_input_bytes * 32).max(64 * 1024);
    let file = std::fs::File::open(path).ok()?;
    let mut raw = Vec::with_capacity(limit.min(1 << 20));
    std::io::Read::read_to_end(&mut std::io::Read::take(file, limit as u64), &mut raw).ok()?;
    Some(pipeline::document(&raw, cfg.max_input_bytes))
}

/// Counts shown by the control socket's status command.
/// Accounts by opt-in state (to folder suggestions or labels);
/// `labels_enabled` counts those labeling, and `cloud_consented` opted-in accounts
/// whose users agreed to every provider in `cloud`.
pub fn folder_counts(mail_root: &Path, cloud: &[&str]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    if let Ok(accounts) = imap_state::list_accounts(mail_root) {
        for (domain, localpart, _) in accounts {
            if let Ok(Some(conn)) = store::open_existing(mail_root, &domain, &localpart) {
                let prefs = store::prefs(&conn).unwrap_or_default();
                *counts
                    .entry(
                        if prefs.any_enabled() {
                            "opted_in"
                        } else {
                            "opted_out"
                        }
                        .to_string(),
                    )
                    .or_default() += 1;
                if prefs.labels_enabled {
                    *counts.entry("labels_enabled".to_string()).or_default() += 1;
                }
                if prefs.any_enabled() && !cloud.is_empty() && prefs.allows_cloud(cloud) {
                    *counts.entry("cloud_consented".to_string()).or_default() += 1;
                }
            }
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::fake;
    use std::sync::Arc;

    const D: &str = "example.test";
    const L: &str = "alice";

    fn mail(from: &str, subject: &str, body: &str) -> Vec<u8> {
        format!("From: {from}\r\nTo: alice@example.test\r\nSubject: {subject}\r\n\r\n{body}\r\n")
            .into_bytes()
    }

    fn cfg() -> ClassifierConfig {
        ClassifierConfig {
            enabled: true,
            min_examples: 2,
            ..ClassifierConfig::default()
        }
    }

    fn models() -> Models {
        Models {
            embedder: Some(Arc::new(fake::BagOfWords { id: "bow".into() })),
            ..Models::default()
        }
    }

    fn seed(root: &Path) {
        imap_state::init_account(root, D, L).unwrap();
        for folder in ["Receipts", "Travel"] {
            imap_state::create_folder(root, D, L, folder).unwrap();
        }
        let receipts = [
            (
                "orders@shop.test",
                "Your receipt",
                "order payment total invoice receipt",
            ),
            (
                "billing@store.test",
                "Invoice 22",
                "invoice payment amount order receipt",
            ),
            (
                "sales@mart.test",
                "Payment received",
                "receipt for your order payment total",
            ),
        ];
        let travel = [
            (
                "noreply@air.test",
                "Boarding pass",
                "flight boarding pass gate seat itinerary",
            ),
            (
                "hotel@stay.test",
                "Reservation",
                "hotel booking reservation flight itinerary",
            ),
            (
                "trips@rail.test",
                "Your trip",
                "train booking itinerary seat boarding",
            ),
        ];
        for (from, subject, body) in receipts {
            imap_state::append_message(root, D, L, "Receipts", &mail(from, subject, body), vec![])
                .unwrap();
        }
        for (from, subject, body) in travel {
            imap_state::append_message(root, D, L, "Travel", &mail(from, subject, body), vec![])
                .unwrap();
        }
    }

    fn opt_in(root: &Path, autofile: &[&str]) {
        let conn = store::open_or_create(root, D, L).unwrap();
        store::set_prefs(
            &conn,
            &store::Prefs {
                enabled: true,
                excluded_folders: vec![],
                autofile_folders: autofile.iter().map(|s| s.to_string()).collect(),
                cloud_consent: vec![],
                labels_enabled: false,
                search_enabled: false,
            },
        )
        .unwrap();
    }

    fn inbox_flags(root: &Path, uid: u64) -> Option<Vec<String>> {
        let (_, messages) = imap_state::load_folder(root, D, L, "INBOX").unwrap();
        messages.into_iter().find(|m| m.uid == uid).map(|m| m.flags)
    }

    fn hosted(provider: &'static str) -> Option<crate::engine::LoadedModel> {
        Some(crate::engine::LoadedModel {
            file: format!("{provider}:model"),
            load_ms: 0,
            cloud: Some(provider),
            fingerprint: 0,
        })
    }

    fn agree(root: &Path, providers: &[&str]) {
        let conn = store::open_existing(root, D, L).unwrap().unwrap();
        let mut prefs = store::prefs(&conn).unwrap();
        prefs.cloud_consent = providers.iter().map(|p| p.to_string()).collect();
        store::set_prefs(&conn, &prefs).unwrap();
    }

    #[test]
    fn cloud_embeddings_wait_for_the_users_consent() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        seed(root);
        opt_in(root, &[]);
        let cloud = Models {
            embed_info: hosted("openrouter"),
            ..models()
        };
        let report = run_cycle(root, &cfg(), &cloud);
        assert_eq!(
            (report.accounts, report.learned, report.awaiting_consent),
            (0, 0, 1)
        );

        // Consent to a different provider is not consent to this one.
        agree(root, &["typesafe"]);
        assert_eq!(run_cycle(root, &cfg(), &cloud).awaiting_consent, 1);

        agree(root, &["openrouter"]);
        let report = run_cycle(root, &cfg(), &cloud);
        assert_eq!(
            (report.accounts, report.learned, report.awaiting_consent),
            (1, 6, 0)
        );
    }

    #[test]
    fn cloud_fallback_is_only_asked_for_consenting_users() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        seed(root);
        opt_in(root, &[]);
        let chooser = Arc::new(fake::Fixed::new(Some("Receipts"), 0.9));
        let cloud = Models {
            chooser: Some(chooser.clone()),
            chat_info: hosted("typesafe"),
            ..models()
        };
        run_cycle(root, &cfg(), &cloud);
        // Too unlike either folder for the vote, so only the fallback could decide.
        let unsure = mail(
            "x@y.test",
            "Quarterly statement",
            "tax statement for the quarter",
        );
        imap_state::deliver_message(root, D, L, &unsure).unwrap();
        let report = run_cycle(root, &cfg(), &cloud);
        assert_eq!((report.classified, report.suggested), (1, 0), "{report:?}");
        assert_eq!(*chooser.calls.lock().unwrap(), 0);

        agree(root, &["typesafe"]);
        imap_state::deliver_message(root, D, L, &unsure).unwrap();
        let report = run_cycle(root, &cfg(), &cloud);
        assert_eq!(*chooser.calls.lock().unwrap(), 1);
        assert_eq!(report.suggested, 1, "{report:?}");
    }

    fn enable_labels(root: &Path, labels: &[(&str, &str)]) {
        let conn = store::open_or_create(root, D, L).unwrap();
        let mut prefs = store::prefs(&conn).unwrap();
        prefs.labels_enabled = true;
        store::set_prefs(&conn, &prefs).unwrap();
        let pairs: Vec<(String, String)> = labels
            .iter()
            .map(|(name, description)| (name.to_string(), description.to_string()))
            .collect();
        store::set_labels(&conn, &pairs, None).unwrap();
    }

    #[test]
    fn labels_are_applied_as_keywords_without_folder_suggestions() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        imap_state::init_account(root, D, L).unwrap();
        let (_, old) =
            imap_state::deliver_message(root, D, L, &mail("a@b.test", "Old", "x")).unwrap();
        enable_labels(root, &[("To do", "Needs action"), ("Family", "")]);
        let chooser = Arc::new(fake::Fixed::labelling(&[("To do", 0.9), ("Family", 0.4)]));
        // No embedder at all: labels only need the fallback model.
        let only_labels = Models {
            chooser: Some(chooser.clone()),
            ..Models::default()
        };

        let report = run_cycle(root, &cfg(), &only_labels);
        assert_eq!((report.accounts, report.labeled), (1, 1), "{report:?}");
        let flags = inbox_flags(root, old).unwrap();
        assert!(flags.iter().any(|f| f == "To_do"), "{flags:?}");
        assert!(
            !flags.iter().any(|f| f == "Family"),
            "below the threshold: {flags:?}"
        );

        // Only new mail is labeled after that.
        let (_, new) =
            imap_state::deliver_message(root, D, L, &mail("c@d.test", "New", "y")).unwrap();
        run_cycle(root, &cfg(), &only_labels);
        assert_eq!(*chooser.label_calls.lock().unwrap(), 2);
        assert!(inbox_flags(root, new).unwrap().iter().any(|f| f == "To_do"));
        let conn = store::open_existing(root, D, L).unwrap().unwrap();
        assert_eq!(store::label_counts(&conn).unwrap()["To do"], 2);
        assert!(
            !store::prefs(&conn).unwrap().enabled,
            "folder suggestions stay off"
        );
    }

    /// A batch API that answers every question with `answer` once `ready`.
    struct FakeBatcher {
        submitted: std::sync::Mutex<Vec<Vec<String>>>,
        answer: String,
        ready: std::sync::atomic::AtomicBool,
        /// Answer only the first question of a batch.
        partial: std::sync::atomic::AtomicBool,
        /// A batch the provider fails to report on.
        failing: std::sync::Mutex<Option<String>>,
        /// Each message's question in a batch of its own.
        apart: std::sync::atomic::AtomicBool,
    }

    impl crate::cloud::Batcher for FakeBatcher {
        fn label_request(
            &self,
            message: &str,
            labels: &[crate::engine::LabelHint],
            _may_propose: bool,
        ) -> serde_json::Value {
            serde_json::json!({ "message": message, "labels": labels.len() })
        }

        fn group(&self, request: &serde_json::Value) -> String {
            if self.apart.load(std::sync::atomic::Ordering::SeqCst) {
                request["message"].to_string()
            } else {
                String::new()
            }
        }

        fn submit(&self, requests: &[(String, serde_json::Value)]) -> Result<String> {
            let mut submitted = self.submitted.lock().unwrap();
            submitted.push(requests.iter().map(|(id, _)| id.clone()).collect());
            Ok(format!("batch-{}", submitted.len()))
        }

        fn poll(&self, batch: &str) -> Result<crate::cloud::BatchPoll> {
            use std::sync::atomic::Ordering;
            if self.failing.lock().unwrap().as_deref() == Some(batch) {
                anyhow::bail!("provider error");
            }
            if !self.ready.load(Ordering::SeqCst) {
                return Ok(crate::cloud::BatchPoll::Running);
            }
            let index: usize = batch.trim_start_matches("batch-").parse().unwrap();
            let ids = self.submitted.lock().unwrap()[index - 1].clone();
            let take = if self.partial.load(Ordering::SeqCst) {
                1
            } else {
                ids.len()
            };
            Ok(crate::cloud::BatchPoll::Ended(
                ids.into_iter()
                    .take(take)
                    .map(|id| (id, Ok(self.answer.clone())))
                    .collect(),
            ))
        }
    }

    #[test]
    fn batch_requests_go_in_one_batch_per_group() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        imap_state::init_account(root, D, L).unwrap();
        imap_state::deliver_message(root, D, L, &mail("a@b.test", "One", "x")).unwrap();
        imap_state::deliver_message(root, D, L, &mail("c@d.test", "Two", "y")).unwrap();
        enable_labels(root, &[("To do", "Needs action")]);
        let batcher = Arc::new(FakeBatcher {
            submitted: Default::default(),
            answer: String::new(),
            ready: false.into(),
            partial: false.into(),
            failing: Default::default(),
            apart: true.into(),
        });
        let batched = Models {
            chooser: Some(Arc::new(fake::Fixed::labelling(&[]))),
            batcher: Some(("fake:model".into(), batcher.clone())),
            ..Models::default()
        };
        let report = run_cycle(root, &cfg(), &batched);
        assert_eq!(report.submitted, 2, "{report:?}");
        let submitted = batcher.submitted.lock().unwrap();
        assert_eq!(submitted.len(), 2, "two groups, two batches");
        assert!(submitted.iter().all(|batch| batch.len() == 1));
        let conn = store::open_existing(root, D, L).unwrap().unwrap();
        let mut ids: Vec<_> = store::label_requests(&conn)
            .unwrap()
            .into_iter()
            .filter_map(|r| r.batch_id)
            .collect();
        ids.sort();
        assert_eq!(ids, ["batch-1", "batch-2"]);
    }

    #[test]
    fn batch_labels_are_queued_sent_together_and_applied_when_answered() {
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        imap_state::init_account(root, D, L).unwrap();
        let (_, first) =
            imap_state::deliver_message(root, D, L, &mail("a@b.test", "One", "x")).unwrap();
        let (_, second) =
            imap_state::deliver_message(root, D, L, &mail("c@d.test", "Two", "y")).unwrap();
        enable_labels(root, &[("To do", "Needs action")]);
        let chooser = Arc::new(fake::Fixed::labelling(&[("To do", 0.9)]));
        let batcher = Arc::new(FakeBatcher {
            submitted: Default::default(),
            answer: r#"{"labels": [{"name": "To do", "confidence": 0.95}], "new_label": null}"#
                .into(),
            ready: false.into(),
            partial: false.into(),
            failing: Default::default(),
            apart: false.into(),
        });
        let batched = Models {
            chooser: Some(chooser.clone()),
            batcher: Some(("fake:model".into(), batcher.clone())),
            ..Models::default()
        };

        let report = run_cycle(root, &cfg(), &batched);
        assert_eq!(
            (report.queued, report.submitted, report.labeled),
            (2, 2, 0),
            "{report:?}"
        );
        assert_eq!(*chooser.label_calls.lock().unwrap(), 0, "no direct calls");
        assert_eq!(
            batcher.submitted.lock().unwrap().len(),
            1,
            "one batch for both"
        );
        // Still running: nothing is sent again.
        let report = run_cycle(root, &cfg(), &batched);
        assert_eq!((report.queued, report.submitted), (0, 0), "{report:?}");

        batcher.ready.store(true, Ordering::SeqCst);
        let report = run_cycle(root, &cfg(), &batched);
        assert_eq!((report.answered, report.labeled), (2, 2), "{report:?}");
        for uid in [first, second] {
            assert!(inbox_flags(root, uid).unwrap().iter().any(|f| f == "To_do"));
        }
        let conn = store::open_existing(root, D, L).unwrap().unwrap();
        assert!(store::label_requests(&conn).unwrap().is_empty());

        // A batch the provider fails to report on does not stop the others.
        batcher.ready.store(false, Ordering::SeqCst);
        imap_state::deliver_message(root, D, L, &mail("i@j.test", "Five", "v")).unwrap();
        run_cycle(root, &cfg(), &batched);
        imap_state::deliver_message(root, D, L, &mail("k@l.test", "Six", "u")).unwrap();
        run_cycle(root, &cfg(), &batched);
        *batcher.failing.lock().unwrap() = Some("batch-2".into());
        batcher.ready.store(true, Ordering::SeqCst);
        let report = run_cycle(root, &cfg(), &batched);
        assert_eq!(report.answered, 1, "batch-3 is collected: {report:?}");
        assert!(report.errors.iter().any(|e| e.contains("batch-2")));
        *batcher.failing.lock().unwrap() = None;
        let report = run_cycle(root, &cfg(), &batched);
        assert_eq!(report.answered, 1, "and batch-2 next time: {report:?}");

        // A question a batch ended without answering is sent again.
        batcher.partial.store(true, Ordering::SeqCst);
        imap_state::deliver_message(root, D, L, &mail("e@f.test", "Three", "z")).unwrap();
        imap_state::deliver_message(root, D, L, &mail("g@h.test", "Four", "w")).unwrap();
        batcher.ready.store(false, Ordering::SeqCst);
        run_cycle(root, &cfg(), &batched);
        batcher.ready.store(true, Ordering::SeqCst);
        let report = run_cycle(root, &cfg(), &batched);
        assert_eq!(report.answered, 1, "{report:?}");
        let left = store::label_requests(&conn).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!((left[0].batch_id.as_deref(), left[0].attempts), (None, 1));

        // Another provider or model: what was queued for this one is dropped.
        let other = Models {
            batcher: Some(("fake:other".into(), batcher.clone())),
            ..batched.clone()
        };
        batcher.ready.store(false, Ordering::SeqCst);
        run_cycle(root, &cfg(), &other);
        assert!(
            store::label_requests(&conn)
                .unwrap()
                .iter()
                .all(|request| request.provider == "fake:other")
        );

        // Labels turned off: the queue is emptied.
        let mut prefs = store::prefs(&conn).unwrap();
        prefs.labels_enabled = false;
        store::set_prefs(&conn, &prefs).unwrap();
        run_cycle(root, &cfg(), &other);
        assert!(store::label_requests(&conn).unwrap().is_empty());
    }

    #[test]
    fn labels_work_without_setup_and_the_model_can_add_one() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        imap_state::init_account(root, D, L).unwrap();
        let (_, uid) = imap_state::deliver_message(
            root,
            D,
            L,
            &mail("pta@school.test", "Parent evening", "Tuesday 18:00"),
        )
        .unwrap();
        // Labels on, but the user defined none.
        enable_labels(root, &[]);
        let models = Models {
            chooser: Some(Arc::new(fake::Fixed::proposing(
                "School",
                "The kids' school",
            ))),
            ..Models::default()
        };
        let report = run_cycle(root, &cfg(), &models);
        assert_eq!(report.labeled, 1, "{report:?}");
        let conn = store::open_existing(root, D, L).unwrap().unwrap();
        let labels = store::labels(&conn).unwrap();
        assert!(
            labels
                .iter()
                .any(|l| l.name == "Receipts" && l.origin == store::ORIGIN_STARTER)
        );
        let school = labels
            .iter()
            .find(|l| l.name == "School")
            .expect("AI label created");
        assert_eq!(school.origin, store::ORIGIN_AI);
        assert!(
            inbox_flags(root, uid)
                .unwrap()
                .iter()
                .any(|f| f == "School")
        );
    }

    #[test]
    fn label_discovery_can_be_turned_off() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        imap_state::init_account(root, D, L).unwrap();
        imap_state::deliver_message(root, D, L, &mail("a@b.test", "Hi", "x")).unwrap();
        enable_labels(root, &[]);
        let models = Models {
            chooser: Some(Arc::new(fake::Fixed::proposing("School", ""))),
            ..Models::default()
        };
        let no_discovery = ClassifierConfig {
            label_discovery: false,
            ..cfg()
        };
        let report = run_cycle(root, &no_discovery, &models);
        assert_eq!(report.labeled, 0, "{report:?}");
        let conn = store::open_existing(root, D, L).unwrap().unwrap();
        assert!(
            !store::labels(&conn)
                .unwrap()
                .iter()
                .any(|l| l.name == "School")
        );
    }

    #[test]
    fn cloud_labels_wait_for_consent() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        imap_state::init_account(root, D, L).unwrap();
        imap_state::deliver_message(root, D, L, &mail("a@b.test", "Hi", "x")).unwrap();
        enable_labels(root, &[("Urgent", "")]);
        let chooser = Arc::new(fake::Fixed::labelling(&[("Urgent", 0.99)]));
        let cloud = Models {
            chooser: Some(chooser.clone()),
            chat_info: hosted("typesafe"),
            ..Models::default()
        };
        let report = run_cycle(root, &cfg(), &cloud);
        assert_eq!((report.accounts, report.awaiting_consent), (0, 1));
        assert_eq!(*chooser.label_calls.lock().unwrap(), 0);

        agree(root, &["typesafe"]);
        let report = run_cycle(root, &cfg(), &cloud);
        assert_eq!(report.labeled, 1, "{report:?}");
    }

    #[test]
    fn autofiled_mail_keeps_its_labels() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        seed(root);
        opt_in(root, &["Receipts"]);
        enable_labels(root, &[("Money", "")]);
        let models = Models {
            chooser: Some(Arc::new(fake::Fixed::labelling(&[("Money", 0.95)]))),
            ..models()
        };
        run_cycle(root, &cfg(), &models);
        // Known sender history makes this an auto-move into Receipts.
        for _ in 0..3 {
            let receipt = mail(
                "orders@shop.test",
                "Your receipt",
                "order payment total invoice receipt",
            );
            imap_state::deliver_message(root, D, L, &receipt).unwrap();
            run_cycle(root, &cfg(), &models);
        }
        let (_, receipts) = imap_state::load_folder(root, D, L, "Receipts").unwrap();
        // Only flags in the failure message: message records carry mailbox paths.
        let flags: Vec<&Vec<String>> = receipts.iter().map(|m| &m.flags).collect();
        assert!(
            flags.iter().any(|f| f.iter().any(|f| f == "Money")),
            "flags in Receipts: {flags:?}"
        );
    }

    #[test]
    fn search_indexes_every_folder_but_trash_and_forgets_what_goes() {
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        seed(root);
        let conn = store::open_or_create(root, D, L).unwrap();
        let mut prefs = store::prefs(&conn).unwrap();
        prefs.search_enabled = true;
        store::set_prefs(&conn, &prefs).unwrap();
        imap_state::append_message(
            root,
            D,
            L,
            "Trash",
            &mail("x@y.test", "Thrown away", "gone"),
            vec![],
        )
        .unwrap();
        let report = run_cycle(root, &cfg(), &models());
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        let total: usize = imap_state::list_folders(root, D, L)
            .unwrap()
            .iter()
            .filter(|f| f.name != "Trash")
            .map(|f| {
                imap_state::load_folder(root, D, L, &f.name)
                    .unwrap()
                    .1
                    .len()
            })
            .sum();
        assert_eq!(report.indexed, total);
        assert!(
            store::search_vectors(&conn, "Trash", "bow")
                .unwrap()
                .is_empty()
        );
        let receipts = store::search_vectors(&conn, "Receipts", "bow").unwrap();
        assert!(!receipts.is_empty());
        // A second cycle has nothing new; a deleted message leaves the index.
        assert_eq!(run_cycle(root, &cfg(), &models()).indexed, 0);
        let gone = receipts[0].1;
        imap_state::delete_message_by_uid(root, D, L, "Receipts", gone).unwrap();
        run_cycle(root, &cfg(), &models());
        assert!(
            !store::search_vectors(&conn, "Receipts", "bow")
                .unwrap()
                .iter()
                .any(|(_, uid, _)| *uid == gone)
        );
    }

    #[test]
    fn accounts_without_a_store_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        seed(dir.path());
        let report = run_cycle(dir.path(), &cfg(), &models());
        assert_eq!(report.accounts, 0);
        assert!(store::open_existing(dir.path(), D, L).unwrap().is_none());
    }

    #[test]
    fn learns_folders_then_suggests_and_accepts() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        seed(root);
        opt_in(root, &[]);

        let report = run_cycle(root, &cfg(), &models());
        assert_eq!(report.accounts, 1);
        assert_eq!(report.learned, 6, "{report:?}");
        assert!(report.errors.is_empty(), "{report:?}");

        let (_, uid) = imap_state::deliver_message(
            root,
            D,
            L,
            &mail(
                "shop@new.test",
                "Order confirmation",
                "your order receipt payment invoice total",
            ),
        )
        .unwrap();
        let report = run_cycle(root, &cfg(), &models());
        assert_eq!(report.suggested, 1, "{report:?}");
        assert!(
            inbox_flags(root, uid)
                .unwrap()
                .iter()
                .any(|f| f == store::SUGGESTED_KEYWORD)
        );

        let conn = store::open_existing(root, D, L).unwrap().unwrap();
        let (inbox, _) = imap_state::load_folder(root, D, L, "INBOX").unwrap();
        let pending = store::pending_suggestions(&conn, inbox.uidvalidity).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].folder, "Receipts");

        // Nothing new: the next cycle does nothing.
        let report = run_cycle(root, &cfg(), &models());
        assert_eq!(report.classified + report.learned, 0, "{report:?}");

        assert_eq!(store::accept(root, D, L, uid).unwrap(), "Receipts");
        assert!(inbox_flags(root, uid).is_none());
        let (_, receipts) = imap_state::load_folder(root, D, L, "Receipts").unwrap();
        assert_eq!(receipts.len(), 4);
        assert!(
            receipts
                .iter()
                .all(|m| !m.flags.iter().any(|f| f == store::SUGGESTED_KEYWORD))
        );

        // The accepted message is learned as a new Receipts example.
        let report = run_cycle(root, &cfg(), &models());
        assert_eq!(report.learned, 1, "{report:?}");
    }

    #[test]
    fn autofile_moves_only_trusted_folders_and_dismissals_stick() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        seed(root);
        opt_in(root, &["Travel"]);
        // The toy corpus overlaps, so votes land around 0.8.
        let cfg = ClassifierConfig {
            autofile_confidence: 70,
            ..cfg()
        };
        run_cycle(root, &cfg, &models());

        let (_, flight) = imap_state::deliver_message(
            root,
            D,
            L,
            &mail(
                "noreply@air.test",
                "Boarding pass",
                "flight boarding pass gate seat itinerary",
            ),
        )
        .unwrap();
        let (_, receipt) = imap_state::deliver_message(
            root,
            D,
            L,
            &mail(
                "orders@shop.test",
                "Your receipt",
                "order payment total invoice receipt",
            ),
        )
        .unwrap();
        let report = run_cycle(root, &cfg, &models());
        assert_eq!(report.moved, 1, "{report:?}");
        assert_eq!(report.suggested, 1, "{report:?}");
        assert!(
            inbox_flags(root, flight).is_none(),
            "flight moved to Travel"
        );
        assert!(
            inbox_flags(root, receipt).is_some(),
            "receipt only suggested"
        );

        store::dismiss(root, D, L, receipt).unwrap();
        assert!(
            !inbox_flags(root, receipt)
                .unwrap()
                .iter()
                .any(|f| f == store::SUGGESTED_KEYWORD)
        );
        let (_, again) = imap_state::deliver_message(
            root,
            D,
            L,
            &mail(
                "orders@shop.test",
                "Your receipt",
                "order payment total invoice receipt",
            ),
        )
        .unwrap();
        run_cycle(root, &cfg, &models());
        let conn = store::open_existing(root, D, L).unwrap().unwrap();
        let (inbox, _) = imap_state::load_folder(root, D, L, "INBOX").unwrap();
        let found = store::suggestion(&conn, inbox.uidvalidity, again).unwrap();
        assert!(
            found.as_ref().is_none_or(|s| s.folder != "Receipts"),
            "{found:?}"
        );
    }

    #[test]
    fn changing_the_embedding_model_relearns() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        seed(root);
        opt_in(root, &[]);
        assert_eq!(run_cycle(root, &cfg(), &models()).learned, 6);
        let other = Models {
            embedder: Some(Arc::new(fake::BagOfWords { id: "other".into() })),
            ..Models::default()
        };
        assert_eq!(run_cycle(root, &cfg(), &other).learned, 6);
    }

    #[test]
    fn excluded_folders_are_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        seed(root);
        opt_in(root, &[]);
        run_cycle(root, &cfg(), &models());
        let conn = store::open_existing(root, D, L).unwrap().unwrap();
        store::set_prefs(
            &conn,
            &store::Prefs {
                enabled: true,
                excluded_folders: vec!["Travel".into()],
                autofile_folders: vec![],
                cloud_consent: vec![],
                labels_enabled: false,
                search_enabled: false,
            },
        )
        .unwrap();
        run_cycle(root, &cfg(), &models());
        let counts = store::example_counts(&conn).unwrap();
        assert_eq!(counts.get("Travel"), None);
        assert_eq!(counts.get("Receipts"), Some(&3));
    }
}
