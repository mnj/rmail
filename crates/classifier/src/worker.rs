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

#[derive(Debug, Default, Clone, Serialize)]
pub struct CycleReport {
    pub accounts: usize,
    pub learned: usize,
    pub classified: usize,
    pub suggested: usize,
    pub moved: usize,
    /// Messages that got at least one label.
    pub labeled: usize,
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
        if (prefs.enabled && !embed_allowed) || (prefs.labels_enabled && !chat_allowed) {
            report.awaiting_consent += 1;
        }
        if !folders && !labels {
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
        if let Err(error) = result {
            classifier_log!("warn", "account_cycle_failed", { "account": format!("{localpart}@{domain}"), "error": format!("{error:#}") });
            report
                .errors
                .push(format!("{localpart}@{domain}: {error:#}"));
        }
    }
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
    /// Apply the user's labels to new INBOX mail as IMAP keywords. Resumes
    /// from its own watermark; a failed model call leaves the message for
    /// the next cycle.
    fn label_inbox(&mut self) -> Result<()> {
        let chooser = self.models.chooser.clone().context("no fallback model")?;
        let conn = store::open_existing(self.mail_root, self.domain, self.localpart)?
            .context("store disappeared")?;
        let labels = store::labels(&conn)?;
        let (inbox, messages) =
            imap_state::load_folder(self.mail_root, self.domain, self.localpart, "INBOX")?;
        let mark = store::label_mark(&conn)?;
        let high = messages.iter().map(|m| m.uid).max().unwrap_or(0);
        let first = mark.is_none_or(|m| m.uidvalidity != inbox.uidvalidity);
        if labels.is_empty() {
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
        let hints: Vec<crate::engine::LabelHint> = labels
            .iter()
            .map(|label| crate::engine::LabelHint {
                name: label.name.clone(),
                description: label.description.clone(),
            })
            .collect();
        let threshold = self.cfg.label_confidence as f64 / 100.0;
        let mut done = mark.filter(|_| !first).map_or(0, |m| m.last_uid);
        let caught_up = pending.len() <= LABEL_BUDGET;
        for message in pending.into_iter().take(LABEL_BUDGET) {
            if let Some(doc) = read_document(&message.path, self.cfg) {
                let applied: Vec<(String, f64)> = chooser
                    .label(&doc.text, &hints)?
                    .into_iter()
                    .filter(|(_, probability)| *probability >= threshold)
                    .collect();
                for (name, _) in &applied {
                    if let Some(label) = labels.iter().find(|label| &label.name == name) {
                        store::set_keyword(
                            self.mail_root,
                            self.domain,
                            self.localpart,
                            "INBOX",
                            message.uid,
                            &label.keyword,
                            true,
                        )?;
                    }
                }
                if !applied.is_empty() {
                    store::record_labels(&conn, inbox.uidvalidity, message.uid, &applied)?;
                    self.report.labeled += 1;
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
                self.models.chooser.as_deref().filter(|_| self.use_chooser),
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
        store::set_labels(&conn, &pairs).unwrap();
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
        let moved: Vec<_> = receipts
            .iter()
            .filter(|m| m.flags.iter().any(|f| f == "Money"))
            .collect();
        assert!(!moved.is_empty(), "{receipts:?}");
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
            },
        )
        .unwrap();
        run_cycle(root, &cfg(), &models());
        let counts = store::example_counts(&conn).unwrap();
        assert_eq!(counts.get("Travel"), None);
        assert_eq!(counts.get("Receipts"), Some(&3));
    }
}
