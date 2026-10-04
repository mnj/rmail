//! CONTEXT=SEARCH and CONTEXT=SORT (RFC 5267 §4): `RETURN (UPDATE)` keeps a
//! SEARCH or SORT result current with ESEARCH ADDTO/REMOVEFROM responses,
//! and CANCELUPDATE stops that.
//!
//! A context remembers its result by UID (in the requested order) and the
//! flags/MODSEQ of every message it has evaluated. After each change to the
//! session's view of the selected mailbox only new or changed messages are
//! evaluated again. Sequence numbers and `$` in the search program are
//! resolved when the command runs (RFC 5267 §4.3), so later renumbering does
//! not change the result. Time-relative keys (YOUNGER, OLDER) are evaluated
//! only when a message changes, not as time passes.

use std::collections::{HashMap, HashSet};

use anyhow::Result;

use crate::{
    mailbox::{MailboxSyncEvent, SelectedMailbox},
    parser::{self, SearchCriterion, SortCriterion},
    response::{Response, Status, StatusLine},
    sort::{self, SortRecord},
};

use super::search::compress_ids;

/// Updating contexts per session; RFC 5267 §4.3.1 requires at least one.
/// Further requests get `NO [NOUPDATE]`.
pub(crate) const MAX_UPDATE_CONTEXTS: usize = 16;

/// The requested order of a context's results.
#[derive(Debug, Clone)]
pub(crate) enum Order {
    /// SEARCH and UID SEARCH: mailbox (UID) order; updates use position 0.
    Mailbox,
    /// SORT and UID SORT: updates carry context positions.
    Sort(Vec<SortCriterion>),
}

#[derive(Debug)]
struct Entry {
    uid: u64,
    /// Sort keys, for sorted contexts.
    record: Option<SortRecord>,
}

/// What a message looked like when a context last evaluated it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Evaluated {
    modseq: u64,
    flags: Vec<String>,
    recent: bool,
}

#[derive(Debug)]
pub(crate) struct UpdateContext {
    tag: String,
    uid_mode: bool,
    criterion: SearchCriterion,
    order: Order,
    evaluated: HashMap<u64, Evaluated>,
    results: Vec<Entry>,
}

impl UpdateContext {
    /// A context for a search command that just ran against `view`.
    /// `results` are the matching UIDs in the requested order with their
    /// sort records (sorted contexts only). `criterion` must already be
    /// [`freeze`]d.
    pub(crate) fn new(
        tag: &str,
        uid_mode: bool,
        criterion: SearchCriterion,
        order: Order,
        view: &SelectedMailbox,
        results: Vec<(u64, Option<SortRecord>)>,
    ) -> Self {
        let evaluated = view
            .msgs
            .iter()
            .filter(|message| !view.is_expunged(message.0))
            .map(|(uid, _, flags, modseq)| (*uid, evaluated_state(view, *uid, flags, *modseq)))
            .collect();
        let results = results
            .into_iter()
            .map(|(uid, record)| Entry {
                uid,
                record: record.map(|mut record| {
                    // Records compare by UID in place of the sequence number,
                    // which stays valid as the mailbox changes.
                    record.seq = uid;
                    record
                }),
            })
            .collect();
        Self {
            tag: tag.to_string(),
            uid_mode,
            criterion,
            order,
            evaluated,
            results,
        }
    }

    fn sorted(&self) -> Option<&[SortCriterion]> {
        match &self.order {
            Order::Mailbox => None,
            Order::Sort(criteria) => Some(criteria),
        }
    }

    /// Whether the view holds messages this context has not evaluated in
    /// their current state, or lacks messages it has.
    fn is_stale(&self, view: &SelectedMailbox) -> bool {
        let mut live = 0;
        for (uid, _, flags, modseq) in &view.msgs {
            if view.is_expunged(*uid) {
                continue;
            }
            live += 1;
            match self.evaluated.get(uid) {
                Some(state) if *state == evaluated_state(view, *uid, flags, *modseq) => {}
                _ => return true,
            }
        }
        live != self.evaluated.len()
    }

    /// Remove `uids` from the result; returns the REMOVEFROM payload.
    /// Message numbers come from `view`; in a message-number context a
    /// message `view` no longer holds was already expunged to the client,
    /// which dropped it then, so it is dropped silently.
    fn remove(&mut self, uids: &HashSet<u64>, view: &SelectedMailbox) -> Option<String> {
        let seqs = sequence_numbers(view);
        if !self.uid_mode {
            self.results.retain(|entry| seqs.contains_key(&entry.uid));
        }
        let id = |uid: u64| {
            if self.uid_mode {
                Some(uid)
            } else {
                seqs.get(&uid).copied()
            }
        };
        let payload = if self.sorted().is_some() {
            // Runs of adjacent positions, last run first so every position
            // is still valid when the client applies it.
            let mut runs: Vec<(usize, Vec<u64>)> = Vec::new();
            for (index, entry) in self.results.iter().enumerate() {
                if !uids.contains(&entry.uid) {
                    continue;
                }
                let Some(id) = id(entry.uid) else { continue };
                match runs.last_mut() {
                    Some((start, ids)) if *start + ids.len() == index + 1 => ids.push(id),
                    _ => runs.push((index + 1, vec![id])),
                }
            }
            runs.iter()
                .rev()
                .map(|(position, ids)| format!("{position} {}", compress_ids(ids)))
                .collect::<Vec<_>>()
                .join(" ")
        } else {
            let mut ids = self
                .results
                .iter()
                .filter(|entry| uids.contains(&entry.uid))
                .filter_map(|entry| id(entry.uid))
                .collect::<Vec<_>>();
            ids.sort_unstable();
            if ids.is_empty() {
                String::new()
            } else {
                format!("0 {}", compress_ids(&ids))
            }
        };
        self.results.retain(|entry| !uids.contains(&entry.uid));
        (!payload.is_empty()).then(|| format!("REMOVEFROM ({payload})"))
    }

    /// Insert new matches; returns the ADDTO payload.
    fn add(&mut self, added: Vec<Entry>, view: &SelectedMailbox) -> Option<String> {
        if added.is_empty() {
            return None;
        }
        let seqs = sequence_numbers(view);
        let new_uids = added.iter().map(|entry| entry.uid).collect::<HashSet<_>>();
        match &self.order {
            Order::Mailbox => {
                self.results.extend(added);
                self.results.sort_by_key(|entry| entry.uid);
            }
            Order::Sort(criteria) => {
                for entry in added {
                    let record = entry.record.as_ref().expect("sorted entries carry records");
                    let at = self.results.partition_point(|existing| {
                        let existing = existing
                            .record
                            .as_ref()
                            .expect("sorted entries carry records");
                        sort::compare_records(existing, record, criteria).is_lt()
                    });
                    self.results.insert(at, entry);
                }
            }
        }
        let id = |uid: u64| {
            if self.uid_mode {
                uid
            } else {
                seqs.get(&uid).copied().unwrap_or(0)
            }
        };
        let payload = if self.sorted().is_some() {
            // Runs at their final positions, first run first: when a run is
            // inserted every earlier result is already in place.
            let mut runs: Vec<(usize, Vec<u64>)> = Vec::new();
            for (index, entry) in self.results.iter().enumerate() {
                if !new_uids.contains(&entry.uid) {
                    continue;
                }
                match runs.last_mut() {
                    Some((start, ids)) if *start + ids.len() == index + 1 => {
                        ids.push(id(entry.uid))
                    }
                    _ => runs.push((index + 1, vec![id(entry.uid)])),
                }
            }
            runs.iter()
                .map(|(position, ids)| format!("{position} {}", compress_ids(ids)))
                .collect::<Vec<_>>()
                .join(" ")
        } else {
            let ids = self
                .results
                .iter()
                .filter(|entry| new_uids.contains(&entry.uid))
                .map(|entry| id(entry.uid))
                .collect::<Vec<_>>();
            format!("0 {}", compress_ids(&ids))
        };
        Some(format!("ADDTO ({payload})"))
    }

    /// Bring the result up to date with `view`; returns the ESEARCH line.
    fn refresh(&mut self, view: &SelectedMailbox, imap4rev2: bool) -> Option<String> {
        let now = chrono::Utc::now().timestamp();
        let needs_data = parser::search_requires_message_data(&self.criterion);
        let in_results = self
            .results
            .iter()
            .map(|entry| entry.uid)
            .collect::<HashSet<_>>();
        let live = view
            .msgs
            .iter()
            .filter(|message| !view.is_expunged(message.0))
            .map(|message| message.0)
            .collect::<HashSet<_>>();
        let mut removed = in_results
            .iter()
            .copied()
            .filter(|uid| !live.contains(uid))
            .collect::<HashSet<_>>();
        self.evaluated.retain(|uid, _| live.contains(uid));
        let mut added = Vec::new();
        for (index, (uid, path, flags, modseq)) in view.msgs.iter().enumerate() {
            if !live.contains(uid) {
                continue;
            }
            let state = evaluated_state(view, *uid, flags, *modseq);
            if self.evaluated.get(uid) == Some(&state) {
                continue;
            }
            // A file that cannot be read was most likely expunged elsewhere;
            // the message stays unevaluated until synchronization drops it.
            let mut data = if needs_data {
                match std::fs::read(path) {
                    Ok(data) => Some(data),
                    Err(_) => continue,
                }
            } else {
                None
            };
            let mut effective_flags = flags.clone();
            if state.recent && !imap4rev2 {
                effective_flags.push("\\Recent".to_string());
            }
            let internal_date = view.internal_dates.get(uid).map_or(0, |date| date.0);
            let matched = {
                let message = parser::SearchMessage {
                    seq: index + 1,
                    uid: *uid,
                    flags: &effective_flags,
                    internal_date,
                    in_saved_result: false,
                    now,
                    size: view.sizes.get(uid).copied().unwrap_or(0) as usize,
                    email_id: view.email_ids.get(uid).map_or("", String::as_str),
                    data: data.as_deref().unwrap_or_default(),
                    fts: None,
                };
                parser::search_matches(&self.criterion, &message, view.msgs.len())
            };
            self.evaluated.insert(*uid, state);
            match (matched, in_results.contains(uid)) {
                (true, false) => {
                    let record = if self.sorted().is_some() {
                        let data = match data.take() {
                            Some(data) => data,
                            None => match std::fs::read(path) {
                                Ok(data) => data,
                                Err(_) => {
                                    self.evaluated.remove(uid);
                                    continue;
                                }
                            },
                        };
                        Some(SortRecord::from_message(*uid, *uid, internal_date, &data))
                    } else {
                        None
                    };
                    added.push(Entry { uid: *uid, record });
                }
                (false, true) => {
                    removed.insert(*uid);
                }
                _ => {}
            }
        }
        let mut items = Vec::new();
        if !removed.is_empty() {
            items.extend(self.remove(&removed, view));
        }
        items.extend(self.add(added, view));
        (!items.is_empty()).then(|| self.esearch(&items.join(" ")))
    }

    fn esearch(&self, items: &str) -> String {
        let tag = self.tag.replace('\\', "\\\\").replace('"', "\\\"");
        let uid = if self.uid_mode { " UID" } else { "" };
        format!("ESEARCH (TAG \"{tag}\"){uid} {items}")
    }
}

fn evaluated_state(view: &SelectedMailbox, uid: u64, flags: &[String], modseq: u64) -> Evaluated {
    Evaluated {
        modseq,
        flags: flags.to_vec(),
        recent: view.recent_uids.contains(&uid),
    }
}

fn sequence_numbers(view: &SelectedMailbox) -> HashMap<u64, u64> {
    view.msgs
        .iter()
        .enumerate()
        .map(|(index, message)| (message.0, index as u64 + 1))
        .collect()
}

/// The session's updating contexts.
#[derive(Debug, Default)]
pub(crate) struct UpdateContexts {
    contexts: Vec<UpdateContext>,
}

impl UpdateContexts {
    pub(crate) fn is_empty(&self) -> bool {
        self.contexts.is_empty()
    }

    /// Updates stop when the mailbox is no longer selected (RFC 5267 §4.3).
    pub(crate) fn clear(&mut self) {
        self.contexts.clear();
    }

    pub(crate) fn has_tag(&self, tag: &str) -> bool {
        self.contexts.iter().any(|context| context.tag == tag)
    }

    pub(crate) fn is_full(&self) -> bool {
        self.contexts.len() >= MAX_UPDATE_CONTEXTS
    }

    pub(crate) fn insert(&mut self, context: UpdateContext) {
        self.contexts.push(context);
    }

    /// CANCELUPDATE: all tags must name contexts, or nothing is cancelled.
    pub(crate) fn cancel(&mut self, tags: &[String]) -> std::result::Result<(), String> {
        if let Some(unknown) = tags.iter().find(|tag| !self.has_tag(tag)) {
            return Err(unknown.clone());
        }
        self.contexts.retain(|context| !tags.contains(&context.tag));
        Ok(())
    }

    /// REMOVEFROM for messages about to be reported expunged, numbered as
    /// in `view` (the client's view before the expunges). RFC 5267 §4.3.4
    /// requires these ahead of the EXPUNGE responses.
    pub(crate) fn before_expunge(&mut self, view: &SelectedMailbox, uids: &[u64]) -> String {
        if self.contexts.is_empty() || uids.is_empty() {
            return String::new();
        }
        let uids = uids.iter().copied().collect::<HashSet<_>>();
        let mut response = Response::new();
        for context in &mut self.contexts {
            for uid in &uids {
                context.evaluated.remove(uid);
            }
            if let Some(item) = context.remove(&uids, view) {
                response = response.data(context.esearch(&item));
            }
        }
        response.encode()
    }

    /// Before-expunge REMOVEFROM for a batch of synchronization events.
    pub(crate) fn before_events(
        &mut self,
        view: &SelectedMailbox,
        events: &[MailboxSyncEvent],
    ) -> String {
        let expunged = events
            .iter()
            .filter_map(|event| match event {
                MailboxSyncEvent::Expunge { uid, .. } => Some(*uid),
                _ => None,
            })
            .collect::<Vec<_>>();
        self.before_expunge(view, &expunged)
    }

    /// ADDTO/REMOVEFROM for every change between the contexts' results and
    /// `view`, the client's current view. Message files are read (off the
    /// async runtime) only for messages that are new or changed.
    pub(crate) async fn refresh(
        &mut self,
        view: Option<&SelectedMailbox>,
        imap4rev2: bool,
    ) -> Result<String> {
        let Some(view) = view else {
            self.clear();
            return Ok(String::new());
        };
        if !self.contexts.iter().any(|context| context.is_stale(view)) {
            return Ok(String::new());
        }
        let mut contexts = std::mem::take(&mut self.contexts);
        let view = view.clone();
        let (contexts, output) = tokio::task::spawn_blocking(move || {
            let mut response = Response::new();
            for context in &mut contexts {
                if let Some(line) = context.refresh(&view, imap4rev2) {
                    response = response.data(line);
                }
            }
            (contexts, response.encode())
        })
        .await?;
        self.contexts = contexts;
        Ok(output)
    }
}

/// Resolve message numbers and `$` in `criterion` against `view` as the
/// command runs; later renumbering must not change the context's program.
pub(crate) fn freeze(
    criterion: &SearchCriterion,
    view: &SelectedMailbox,
    saved_uids: &[u64],
) -> SearchCriterion {
    let uid_set = |mut uids: Vec<u64>| {
        uids.sort_unstable();
        uids.dedup();
        if uids.is_empty() {
            SearchCriterion::Never
        } else {
            SearchCriterion::UidSet(compress_ids(&uids))
        }
    };
    match criterion {
        SearchCriterion::SeqSet(set) => uid_set(
            parser::ids_from_set(set, view.msgs.len() as u64)
                .into_iter()
                .filter_map(|seq| view.msgs.get(seq as usize - 1).map(|message| message.0))
                .collect(),
        ),
        SearchCriterion::SavedResult => uid_set(saved_uids.to_vec()),
        SearchCriterion::Not(inner) => {
            SearchCriterion::Not(Box::new(freeze(inner, view, saved_uids)))
        }
        SearchCriterion::Or(left, right) => SearchCriterion::Or(
            Box::new(freeze(left, view, saved_uids)),
            Box::new(freeze(right, view, saved_uids)),
        ),
        SearchCriterion::And(items) => SearchCriterion::And(
            items
                .iter()
                .map(|item| freeze(item, view, saved_uids))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Tags of a CANCELUPDATE command: `1*(SP quoted)`.
pub(crate) fn parse_cancel_update(args: &str) -> Option<Vec<String>> {
    let tokens = parser::tokenize_search(args).ok()?;
    if tokens.is_empty()
        || tokens
            .iter()
            .any(|token| token.is_empty() || token == "(" || token == ")")
    {
        return None;
    }
    Some(tokens)
}

pub(crate) fn cancel_update(tag: &str, args: &str, contexts: &mut UpdateContexts) -> Response {
    let Some(tags) = parse_cancel_update(args) else {
        return Response::new().status(StatusLine::tagged(
            tag,
            Status::Bad,
            "Invalid CANCELUPDATE arguments",
        ));
    };
    match contexts.cancel(&tags) {
        Ok(()) => Response::new().status(StatusLine::tagged(
            tag,
            Status::Ok,
            "CANCELUPDATE completed",
        )),
        Err(unknown) => Response::new().status(StatusLine::tagged(
            tag,
            Status::Bad,
            format!("No update context for tag {unknown}"),
        )),
    }
}

/// The untagged `NO [NOUPDATE "tag"]` of RFC 5267 §4.3.1.
pub(crate) fn refused(tag: &str) -> StatusLine {
    let escaped = tag.replace('\\', "\\\\").replace('"', "\\\"");
    StatusLine::untagged(Status::No, "Too many update contexts")
        .with_code(format!("NOUPDATE \"{escaped}\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(uids: &[u64]) -> SelectedMailbox {
        SelectedMailbox {
            domain: "example.test".to_string(),
            local: "user".to_string(),
            mailbox: "INBOX".to_string(),
            uidvalidity: 1,
            uidnext: uids.last().map_or(1, |uid| uid + 1),
            highest_modseq: 1,
            mailbox_id: "Ftest".to_string(),
            read_only: false,
            msgs: uids
                .iter()
                .map(|uid| (*uid, std::path::PathBuf::new(), Vec::new(), 1))
                .collect(),
            internal_dates: Default::default(),
            save_dates: Default::default(),
            sizes: Default::default(),
            email_ids: Default::default(),
            recent_uids: Default::default(),
            expunged: Default::default(),
        }
    }

    #[test]
    fn freezing_resolves_message_numbers_and_saved_results() {
        let view = view(&[10, 20, 30, 40]);
        let criterion = SearchCriterion::And(vec![
            SearchCriterion::SeqSet("2:*".to_string()),
            SearchCriterion::Not(Box::new(SearchCriterion::SavedResult)),
            SearchCriterion::Seen,
        ]);
        let SearchCriterion::And(items) = freeze(&criterion, &view, &[30]) else {
            panic!("shape changed");
        };
        assert!(matches!(&items[0], SearchCriterion::UidSet(set) if set == "20,30,40"));
        assert!(matches!(
            &items[1],
            SearchCriterion::Not(inner)
                if matches!(&**inner, SearchCriterion::UidSet(set) if set == "30")
        ));
        assert!(matches!(items[2], SearchCriterion::Seen));
        assert!(matches!(
            freeze(&SearchCriterion::SavedResult, &view, &[]),
            SearchCriterion::Never
        ));
    }

    #[test]
    fn cancel_update_takes_one_or_more_tags() {
        assert_eq!(
            parse_cancel_update("\"A1\" \"B 2\""),
            Some(vec!["A1".to_string(), "B 2".to_string()])
        );
        assert_eq!(parse_cancel_update(""), None);
        assert_eq!(parse_cancel_update("(A1)"), None);
        assert_eq!(parse_cancel_update("\"\""), None);

        let mut contexts = UpdateContexts::default();
        let view = view(&[1, 2]);
        contexts.insert(UpdateContext::new(
            "A1",
            true,
            SearchCriterion::All,
            Order::Mailbox,
            &view,
            vec![(1, None), (2, None)],
        ));
        assert_eq!(
            contexts.cancel(&["A1".to_string(), "Z9".to_string()]),
            Err("Z9".to_string())
        );
        assert!(contexts.has_tag("A1"));
        assert_eq!(contexts.cancel(&["A1".to_string()]), Ok(()));
        assert!(contexts.is_empty());
    }

    #[test]
    fn expunged_results_leave_before_the_expunge_is_reported() {
        let view = view(&[5, 6, 7]);
        let mut contexts = UpdateContexts::default();
        contexts.insert(UpdateContext::new(
            "S1",
            false,
            SearchCriterion::All,
            Order::Mailbox,
            &view,
            vec![(5, None), (6, None), (7, None)],
        ));
        assert_eq!(
            contexts.before_expunge(&view, &[6, 7]),
            "* ESEARCH (TAG \"S1\") REMOVEFROM (0 2:3)\r\n"
        );
        assert_eq!(contexts.before_expunge(&view, &[6]), "");
    }
}
