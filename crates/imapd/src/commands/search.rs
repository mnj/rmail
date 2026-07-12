use crate::{
    mailbox::SelectedMailbox,
    parser,
    response::{Response, Status, StatusLine},
};

pub(crate) struct Outcome {
    pub(crate) response: Response,
    pub(crate) saved_uids: Option<Vec<u64>>,
}

pub(crate) async fn handle(
    tag: &str,
    raw_args: &str,
    selected: &SelectedMailbox,
    previous_saved_uids: &[u64],
    uid_mode: bool,
    utf8_accept: bool,
) -> Outcome {
    let request = match parser::parse_search_request(raw_args) {
        Ok(request) => request,
        Err(parser::SearchParseError::UnsupportedCharset(_)) => {
            return response(
                StatusLine::tagged(tag, Status::No, "Unsupported charset")
                    .with_code("BADCHARSET (US-ASCII UTF-8)"),
            );
        }
        Err(parser::SearchParseError::Syntax) => {
            return response(StatusLine::tagged(
                tag,
                Status::Bad,
                format!(
                    "Invalid {}SEARCH arguments",
                    if uid_mode { "UID " } else { "" }
                ),
            ));
        }
    };
    if utf8_accept && request.charset.is_some() {
        return response(StatusLine::tagged(
            tag,
            Status::Bad,
            "Cannot set SEARCH charset when UTF8=ACCEPT is enabled",
        ));
    }

    let selected = selected.clone();
    let criterion = request.criterion.clone();
    let saved = previous_saved_uids.to_vec();
    let matches =
        match tokio::task::spawn_blocking(move || execute(&selected, &criterion, &saved)).await {
            Ok(Ok(matches)) => matches,
            Ok(Err(error)) => {
                return response(
                    StatusLine::tagged(tag, Status::No, format!("SEARCH failed: {error}"))
                        .with_code("UNAVAILABLE"),
                );
            }
            Err(error) => {
                return response(
                    StatusLine::tagged(tag, Status::No, format!("SEARCH task failed: {error}"))
                        .with_code("UNAVAILABLE"),
                );
            }
        };
    let ids = matches
        .iter()
        .map(|(sequence, uid)| if uid_mode { *uid } else { *sequence })
        .collect::<Vec<_>>();
    let save = request
        .return_options
        .as_ref()
        .is_some_and(|options| options.save)
        .then(|| matches.iter().map(|(_, uid)| *uid).collect());
    let mut result = Response::new();
    if let Some(data) = result_data(tag, uid_mode, &ids, request.return_options.as_ref()) {
        result = result.data(data);
    }
    result = result.status(StatusLine::tagged(
        tag,
        Status::Ok,
        format!("{}SEARCH completed", if uid_mode { "UID " } else { "" }),
    ));
    Outcome {
        response: result,
        saved_uids: save,
    }
}

fn execute(
    selected: &SelectedMailbox,
    criterion: &parser::SearchCriterion,
    saved_search_uids: &[u64],
) -> anyhow::Result<Vec<(u64, u64)>> {
    let mut matches = Vec::new();
    let now = chrono::Utc::now().timestamp();
    for (index, (uid, path, flags, _)) in selected.msgs.iter().enumerate() {
        let data = std::fs::read(path)?;
        let mut effective_flags = flags.clone();
        if selected.recent_uids.contains(uid) {
            effective_flags.push("\\Recent".to_string());
        }
        let message = parser::SearchMessage {
            seq: index + 1,
            uid: *uid,
            flags: &effective_flags,
            internal_date: selected
                .internal_dates
                .get(uid)
                .map(|date| date.0)
                .unwrap_or(0),
            in_saved_result: saved_search_uids.binary_search(uid).is_ok(),
            now,
            data: &data,
        };
        if parser::search_matches(criterion, &message, selected.msgs.len()) {
            matches.push((index as u64 + 1, *uid));
        }
    }
    Ok(matches)
}

fn response(line: StatusLine) -> Outcome {
    Outcome {
        response: Response::new().status(line),
        saved_uids: None,
    }
}

fn result_data(
    tag: &str,
    uid_mode: bool,
    ids: &[u64],
    return_options: Option<&parser::SearchReturnOptions>,
) -> Option<String> {
    let Some(options) = return_options else {
        return Some(format!(
            "SEARCH {}",
            ids.iter().map(u64::to_string).collect::<Vec<_>>().join(" ")
        ));
    };
    if options.save && !options.min && !options.max && !options.all && !options.count {
        return None;
    }
    let escaped_tag = tag.replace('\\', "\\\\").replace('"', "\\\"");
    let mut data = format!("ESEARCH (TAG \"{escaped_tag}\")");
    if uid_mode {
        data.push_str(" UID");
    }
    if options.min {
        if let Some(minimum) = ids.first() {
            data.push_str(&format!(" MIN {minimum}"));
        }
    }
    if options.max {
        if let Some(maximum) = ids.last() {
            data.push_str(&format!(" MAX {maximum}"));
        }
    }
    if options.all && !ids.is_empty() {
        data.push_str(&format!(" ALL {}", compress_ids(ids)));
    }
    if options.count {
        data.push_str(&format!(" COUNT {}", ids.len()));
    }
    Some(data)
}

pub(crate) fn compress_ids(ids: &[u64]) -> String {
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < ids.len() {
        let mut end = start;
        while end + 1 < ids.len() && ids[end + 1] == ids[end].saturating_add(1) {
            end += 1;
        }
        if start == end {
            ranges.push(ids[start].to_string());
        } else {
            ranges.push(format!("{}:{}", ids[start], ids[end]));
        }
        start = end + 1;
    }
    ranges.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esearch_formats_uid_aggregates_and_empty_results() {
        let options = parser::SearchReturnOptions {
            min: true,
            max: true,
            all: true,
            count: true,
            save: false,
        };
        assert_eq!(
            result_data("A1", true, &[2, 3, 4, 8], Some(&options)),
            Some("ESEARCH (TAG \"A1\") UID MIN 2 MAX 8 ALL 2:4,8 COUNT 4".to_string())
        );
        assert_eq!(
            result_data("A1", false, &[], Some(&options)),
            Some("ESEARCH (TAG \"A1\") COUNT 0".to_string())
        );
    }

    #[tokio::test]
    async fn charset_errors_are_typed_and_do_not_replace_saved_results() {
        let selected = SelectedMailbox {
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
        };
        let outcome = handle(
            "A1",
            "CHARSET ISO-8859-1 ALL",
            &selected,
            &[9],
            false,
            false,
        )
        .await;
        assert_eq!(outcome.saved_uids, None);
        assert_eq!(
            outcome.response.encode(),
            "A1 NO [BADCHARSET (US-ASCII UTF-8)] Unsupported charset\r\n"
        );
    }
}
