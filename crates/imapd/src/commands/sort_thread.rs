use crate::{
    mailbox::SelectedMailbox,
    parser,
    response::{Response, Status, StatusLine},
    sort, thread,
};

use super::context::{self, Order, UpdateContext, UpdateContexts};
use super::search;

/// Result of SORT / UID SORT.
pub(crate) struct SortOutcome {
    pub(crate) response: Response,
    /// New SEARCHRES result for `RETURN (SAVE)` (RFC 5182 covers SORT).
    pub(crate) saved_uids: Option<Vec<u64>>,
    /// A new CONTEXT=SORT updating context (`RETURN (UPDATE)`).
    pub(crate) context: Option<UpdateContext>,
}

impl SortOutcome {
    fn only(response: Response) -> Self {
        Self {
            response,
            saved_uids: None,
            context: None,
        }
    }
}

/// SORT, with the ESORT and CONTEXT=SORT return options (RFC 5267).
pub(crate) async fn sort(
    tag: &str,
    raw_args: &str,
    selected: &SelectedMailbox,
    saved_uids: &[u64],
    uid_mode: bool,
    imap4rev2: bool,
    contexts: &UpdateContexts,
) -> SortOutcome {
    let command = if uid_mode { "UID SORT" } else { "SORT" };
    let request = match parser::parse_sort_request(raw_args) {
        Ok(request) => request,
        Err(parser::SortParseError::UnsupportedCharset(_)) => {
            return SortOutcome::only(bad_charset(tag));
        }
        Err(parser::SortParseError::Syntax) => {
            return SortOutcome::only(bad(tag, format!("Invalid {command} arguments")));
        }
    };
    let options = request.return_options.clone();
    let save = options.as_ref().is_some_and(|options| options.save);
    let update = options.as_ref().is_some_and(|options| options.update);
    // RFC 5267 §4.3: a tag names at most one updating context.
    if update && contexts.has_tag(tag) {
        return SortOutcome::only(bad(tag, "Tag reuse".to_string()));
    }
    let view = selected.clone();
    let saved = saved_uids.to_vec();
    let (request, records) = match tokio::task::spawn_blocking(move || {
        let records = execute_sort(&view, &request, &saved, imap4rev2);
        (request, records)
    })
    .await
    {
        Ok((request, Ok(records))) => (request, records),
        Ok((_, Err(error))) => return failed(tag, command, error, save),
        Err(error) => return failed(tag, command, error, save),
    };
    let ids = records
        .iter()
        .map(|record| if uid_mode { record.uid } else { record.seq })
        .collect::<Vec<_>>();
    let mut response = Response::new();
    match &options {
        Some(options) => {
            if let Some(data) = search::esearch_data(tag, uid_mode, &ids, options) {
                response = response.data(data);
            }
        }
        None => {
            // RFC 5256: "SORT" *(SP nz-number), so no space when empty.
            let line = ids.iter().fold("SORT".to_string(), |mut line, id| {
                line.push(' ');
                line.push_str(&id.to_string());
                line
            });
            response = response.data(line);
        }
    }
    let new_saved = options
        .as_ref()
        .filter(|options| options.save)
        .map(|options| {
            let matches = records
                .iter()
                .map(|record| (record.seq, record.uid))
                .collect::<Vec<_>>();
            search::saved_result(&matches, options)
        });
    let mut update_context = None;
    if update {
        if contexts.is_full() {
            response = response.status(context::refused(tag));
        } else {
            update_context = Some(UpdateContext::new(
                tag,
                uid_mode,
                context::freeze(&request.search, selected, saved_uids),
                Order::Sort(request.criteria.clone()),
                selected,
                records
                    .into_iter()
                    .map(|record| (record.uid, Some(record)))
                    .collect(),
            ));
        }
    }
    SortOutcome {
        response: response.status(StatusLine::tagged(
            tag,
            Status::Ok,
            format!("{command} completed"),
        )),
        saved_uids: new_saved,
        context: update_context,
    }
}

/// A SORT that could not run; RFC 5182 §2.1 empties the saved result when
/// SAVE was requested.
fn failed(tag: &str, command: &str, error: impl std::fmt::Display, save: bool) -> SortOutcome {
    SortOutcome {
        response: unavailable(tag, command, error),
        saved_uids: save.then(Vec::new),
        context: None,
    }
}

pub(crate) async fn thread(
    tag: &str,
    raw_args: &str,
    selected: &SelectedMailbox,
    saved_uids: &[u64],
    uid_mode: bool,
) -> Response {
    let command = if uid_mode { "UID THREAD" } else { "THREAD" };
    let request = match parser::parse_thread_request(raw_args) {
        Ok(request) => request,
        Err(parser::SortParseError::UnsupportedCharset(_)) => return bad_charset(tag),
        Err(parser::SortParseError::Syntax) => {
            return bad(tag, format!("Invalid {command} arguments"));
        }
    };
    let selected = selected.clone();
    let saved_uids = saved_uids.to_vec();
    let algorithm = request.algorithm;
    let messages =
        match tokio::task::spawn_blocking(move || execute_thread(&selected, &request, &saved_uids))
            .await
        {
            Ok(Ok(messages)) => messages,
            Ok(Err(error)) => return unavailable(tag, command, error),
            Err(error) => return unavailable(tag, command, error),
        };
    let body = match algorithm {
        parser::ThreadAlgorithm::OrderedSubject => thread::ordered_subject(&messages, uid_mode),
        parser::ThreadAlgorithm::References => thread::references(&messages, uid_mode),
        parser::ThreadAlgorithm::Refs => thread::refs(&messages, uid_mode),
    };
    // RFC 5256: "THREAD" [SP 1*thread-list], so no space when empty.
    let line = if body.is_empty() {
        "THREAD".to_string()
    } else {
        format!("THREAD {body}")
    };
    Response::new().data(line).status(StatusLine::tagged(
        tag,
        Status::Ok,
        format!("{command} completed"),
    ))
}

fn execute_sort(
    selected: &SelectedMailbox,
    request: &parser::SortRequest,
    saved_uids: &[u64],
    imap4rev2: bool,
) -> anyhow::Result<Vec<sort::SortRecord>> {
    let mut records = Vec::new();
    let now = chrono::Utc::now().timestamp();
    for (index, (uid, path, flags, _)) in selected.msgs.iter().enumerate() {
        // Expunged by another session; the file may already be gone.
        if selected.is_expunged(*uid) {
            continue;
        }
        let data = std::fs::read(path)?;
        let internal_date = selected
            .internal_dates
            .get(uid)
            .map(|date| date.0)
            .unwrap_or(0);
        // As in SEARCH, \Recent exists only before IMAP4rev2.
        let mut effective_flags = flags.clone();
        if !imap4rev2 && selected.recent_uids.contains(uid) {
            effective_flags.push("\\Recent".to_string());
        }
        let message = parser::SearchMessage {
            seq: index + 1,
            uid: *uid,
            flags: &effective_flags,
            internal_date,
            save_date: selected.save_dates.get(uid).copied().unwrap_or(0),
            in_saved_result: saved_uids.binary_search(uid).is_ok(),
            now,
            size: selected
                .sizes
                .get(uid)
                .copied()
                .unwrap_or(data.len() as u64) as usize,
            email_id: selected.email_ids.get(uid).map_or("", String::as_str),
            data: &data,
            fts: None,
        };
        if parser::search_matches(&request.search, &message, selected.msgs.len()) {
            records.push(sort::SortRecord::from_message(
                index as u64 + 1,
                *uid,
                internal_date,
                &data,
            ));
        }
    }
    records.sort_by(|left, right| sort::compare_records(left, right, &request.criteria));
    Ok(records)
}

fn execute_thread(
    selected: &SelectedMailbox,
    request: &parser::ThreadRequest,
    saved_uids: &[u64],
) -> anyhow::Result<Vec<thread::ThreadMessage>> {
    debug_assert!(matches!(request.charset.as_str(), "UTF-8" | "US-ASCII"));
    let mut messages = Vec::new();
    let now = chrono::Utc::now().timestamp();
    for (index, (uid, path, flags, _)) in selected.msgs.iter().enumerate() {
        // Expunged by another session; the file may already be gone.
        if selected.is_expunged(*uid) {
            continue;
        }
        let data = std::fs::read(path)?;
        let internal_date = selected
            .internal_dates
            .get(uid)
            .map(|date| date.0)
            .unwrap_or(0);
        let search_message = parser::SearchMessage {
            seq: index + 1,
            uid: *uid,
            flags,
            internal_date,
            save_date: selected.save_dates.get(uid).copied().unwrap_or(0),
            in_saved_result: saved_uids.binary_search(uid).is_ok(),
            now,
            size: selected
                .sizes
                .get(uid)
                .copied()
                .unwrap_or(data.len() as u64) as usize,
            email_id: selected.email_ids.get(uid).map_or("", String::as_str),
            data: &data,
            fts: None,
        };
        if parser::search_matches(&request.search, &search_message, selected.msgs.len()) {
            messages.push(thread::ThreadMessage::from_message(
                index as u64 + 1,
                *uid,
                internal_date,
                &data,
            ));
        }
    }
    Ok(messages)
}

fn bad_charset(tag: &str) -> Response {
    Response::new().status(
        StatusLine::tagged(tag, Status::No, "Unsupported charset")
            .with_code("BADCHARSET (US-ASCII UTF-8)"),
    )
}

fn bad(tag: &str, text: String) -> Response {
    Response::new().status(StatusLine::tagged(tag, Status::Bad, text))
}

fn unavailable(tag: &str, command: &str, error: impl std::fmt::Display) -> Response {
    Response::new().status(
        StatusLine::tagged(tag, Status::No, format!("{command} failed: {error}"))
            .with_code("UNAVAILABLE"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_selected() -> SelectedMailbox {
        SelectedMailbox {
            domain: "example.test".to_string(),
            local: "user".to_string(),
            mailbox: "INBOX".to_string(),
            uidvalidity: 1,
            uidnext: 1,
            highest_modseq: 1,
            mailbox_id: "Ftest".to_string(),
            read_only: false,
            msgs: Vec::new(),
            internal_dates: Default::default(),
            save_dates: Default::default(),
            sizes: Default::default(),
            email_ids: Default::default(),
            recent_uids: Default::default(),
            expunged: Default::default(),
        }
    }

    #[tokio::test]
    async fn empty_sort_and_thread_have_complete_typed_responses() {
        let selected = empty_selected();
        assert_eq!(
            sort(
                "A1",
                "(DATE) UTF-8 ALL",
                &selected,
                &[],
                false,
                false,
                &Default::default()
            )
            .await
            .response
            .encode(),
            "* SORT\r\nA1 OK SORT completed\r\n"
        );
        assert_eq!(
            thread("A2", "REFERENCES UTF-8 ALL", &selected, &[], true)
                .await
                .encode(),
            "* THREAD\r\nA2 OK UID THREAD completed\r\n"
        );
    }
}
