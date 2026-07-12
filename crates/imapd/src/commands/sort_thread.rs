use crate::{
    mailbox::SelectedMailbox,
    parser,
    response::{Response, Status, StatusLine},
    sort, thread,
};

pub(crate) async fn sort(
    tag: &str,
    raw_args: &str,
    selected: &SelectedMailbox,
    saved_uids: &[u64],
    uid_mode: bool,
) -> Response {
    let command = if uid_mode { "UID SORT" } else { "SORT" };
    let request = match parser::parse_sort_request(raw_args) {
        Ok(request) => request,
        Err(parser::SortParseError::UnsupportedCharset(_)) => return bad_charset(tag),
        Err(parser::SortParseError::Syntax) => {
            return bad(tag, format!("Invalid {command} arguments"));
        }
    };
    let selected = selected.clone();
    let saved_uids = saved_uids.to_vec();
    let records =
        match tokio::task::spawn_blocking(move || execute_sort(&selected, &request, &saved_uids))
            .await
        {
            Ok(Ok(records)) => records,
            Ok(Err(error)) => return unavailable(tag, command, error),
            Err(error) => return unavailable(tag, command, error),
        };
    let ids = records
        .iter()
        .map(|record| if uid_mode { record.uid } else { record.seq })
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    Response::new()
        .data(format!("SORT {ids}"))
        .status(StatusLine::tagged(
            tag,
            Status::Ok,
            format!("{command} completed"),
        ))
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
    Response::new()
        .data(format!("THREAD {body}"))
        .status(StatusLine::tagged(
            tag,
            Status::Ok,
            format!("{command} completed"),
        ))
}

fn execute_sort(
    selected: &SelectedMailbox,
    request: &parser::SortRequest,
    saved_uids: &[u64],
) -> anyhow::Result<Vec<sort::SortRecord>> {
    let mut records = Vec::new();
    let now = chrono::Utc::now().timestamp();
    for (index, (uid, path, flags, _)) in selected.msgs.iter().enumerate() {
        let data = std::fs::read(path)?;
        let internal_date = selected
            .internal_dates
            .get(uid)
            .map(|date| date.0)
            .unwrap_or(0);
        let message = parser::SearchMessage {
            seq: index + 1,
            uid: *uid,
            flags,
            internal_date,
            in_saved_result: saved_uids.binary_search(uid).is_ok(),
            now,
            data: &data,
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
            in_saved_result: saved_uids.binary_search(uid).is_ok(),
            now,
            data: &data,
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
            read_only: false,
            msgs: Vec::new(),
            internal_dates: Default::default(),
            save_dates: Default::default(),
            sizes: Default::default(),
            recent_uids: Default::default(),
        }
    }

    #[tokio::test]
    async fn empty_sort_and_thread_have_complete_typed_responses() {
        let selected = empty_selected();
        assert_eq!(
            sort("A1", "(DATE) UTF-8 ALL", &selected, &[], false)
                .await
                .encode(),
            "* SORT \r\nA1 OK SORT completed\r\n"
        );
        assert_eq!(
            thread("A2", "REFERENCES UTF-8 ALL", &selected, &[], true)
                .await
                .encode(),
            "* THREAD \r\nA2 OK UID THREAD completed\r\n"
        );
    }
}
