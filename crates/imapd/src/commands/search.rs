use crate::{
    mailbox::SelectedMailbox,
    parser,
    response::{Response, Status, StatusLine},
};

use super::context::{self, Order, UpdateContext, UpdateContexts};

pub(crate) struct Outcome {
    pub(crate) response: Response,
    pub(crate) saved_uids: Option<Vec<u64>>,
    /// A new CONTEXT=SEARCH updating context (RETURN (UPDATE)).
    pub(crate) context: Option<UpdateContext>,
}

pub(crate) async fn handle(
    tag: &str,
    raw_args: &str,
    mail_root: Option<&std::path::Path>,
    selected: &SelectedMailbox,
    previous_saved_uids: &[u64],
    uid_mode: bool,
    utf8_accept: bool,
    imap4rev2: bool,
    contexts: &UpdateContexts,
    message_limit: Option<usize>,
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
    let update = request
        .return_options
        .as_ref()
        .is_some_and(|options| options.update);
    // RFC 5267 §4.3: a tag names at most one updating context.
    if update && contexts.has_tag(tag) {
        return response(StatusLine::tagged(tag, Status::Bad, "Tag reuse"));
    }

    let mut request = request;
    if parser::mentions_thread_id(&request.criterion)
        && let Some(root) = mail_root
    {
        // RFC 8474 §6: THREADID names a JMAP thread; find its emails.
        let root = root.to_path_buf();
        let domain = selected.domain.clone();
        let local = selected.local.clone();
        let criterion = request.criterion.clone();
        if let Ok(resolved) = tokio::task::spawn_blocking(move || {
            parser::resolve_thread_ids(criterion, &|thread| {
                rmail_common::jmap::store::thread_members(&root, &domain, &local, thread)
                    .unwrap_or_default()
            })
        })
        .await
        {
            request.criterion = resolved;
        }
    }
    let view = selected;
    let selected = selected.clone();
    let criterion = request.criterion.clone();
    let saved = previous_saved_uids.to_vec();
    let mail_root = mail_root.map(std::path::Path::to_path_buf);
    let (matches, limited) = match tokio::task::spawn_blocking(move || {
        execute_limited(
            &selected,
            &criterion,
            &saved,
            imap4rev2,
            mail_root.as_deref(),
            message_limit,
        )
    })
    .await
    {
        Ok(Ok(found)) => found,
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
        .filter(|options| options.save)
        .map(|options| saved_result(&matches, options));
    let mut result = Response::new();
    if let Some(data) = result_data(
        tag,
        uid_mode,
        &ids,
        request.return_options.as_ref(),
        imap4rev2,
    ) {
        result = result.data(data);
    }
    let mut update_context = None;
    if update {
        if contexts.is_full() {
            result = result.status(context::refused(tag));
        } else {
            update_context = Some(UpdateContext::new(
                tag,
                uid_mode,
                context::freeze(&request.criterion, view, previous_saved_uids),
                Order::Mailbox,
                view,
                matches.iter().map(|(_, uid)| (*uid, None)).collect(),
            ));
        }
    }
    result = result.status(StatusLine::tagged(
        tag,
        Status::Ok,
        format!("{}SEARCH completed", if uid_mode { "UID " } else { "" }),
    ));
    let result = match limited {
        Some(code) => result.with_message_limit(code),
        None => result,
    };
    Outcome {
        response: result,
        saved_uids: save,
        context: update_context,
    }
}

/// Messages indexed per SEARCH before the rest are scanned: bounds the first
/// search of a large mailbox, and later searches finish the job.
const INDEX_BUDGET: usize = 1000;

/// Index answers for the BODY/TEXT needles of `criterion`, or `None` to scan
/// (no such needles, no mail root, or any index error: the index is only a cache).
fn index_lookup(
    selected: &SelectedMailbox,
    criterion: &parser::SearchCriterion,
    mail_root: Option<&std::path::Path>,
) -> Option<parser::FtsLookup> {
    use rmail_common::search_index::{Field, SearchIndex};
    let root = mail_root?;
    let (body, text) = parser::fts_needles(criterion);
    if body.is_empty() && text.is_empty() {
        return None;
    }
    let build = || -> anyhow::Result<parser::FtsLookup> {
        let index = SearchIndex::open(root, &selected.domain, &selected.local)?;
        let messages: Vec<(u64, std::path::PathBuf)> = selected
            .msgs
            .iter()
            .filter(|(uid, ..)| !selected.is_expunged(*uid))
            .map(|(uid, path, ..)| (*uid, path.clone()))
            .collect();
        index.sync(
            &selected.mailbox,
            selected.uidvalidity,
            &messages,
            INDEX_BUDGET,
        )?;
        let mut lookup = parser::FtsLookup::default();
        for needle in body {
            if let Some(hits) = index.query(
                &selected.mailbox,
                selected.uidvalidity,
                Field::Body,
                &needle,
            )? {
                lookup.body.insert(needle, hits);
            }
        }
        for needle in text {
            if let Some(hits) = index.query(
                &selected.mailbox,
                selected.uidvalidity,
                Field::Text,
                &needle,
            )? {
                lookup.text.insert(needle, hits);
            }
        }
        Ok(lookup)
    };
    match build() {
        Ok(lookup) => Some(lookup),
        Err(error) => {
            imap_log!("warn", "search_index_unavailable", { "error": format!("{error:#}") });
            None
        }
    }
}

#[cfg(test)]
fn execute(
    selected: &SelectedMailbox,
    criterion: &parser::SearchCriterion,
    saved_search_uids: &[u64],
    imap4rev2: bool,
    mail_root: Option<&std::path::Path>,
) -> anyhow::Result<Vec<(u64, u64)>> {
    execute_limited(
        selected,
        criterion,
        saved_search_uids,
        imap4rev2,
        mail_root,
        None,
    )
    .map(|(matches, _)| matches)
}

/// The (sequence, UID) pairs matching `criterion`, and the MESSAGELIMIT
/// code when only part of the mailbox was examined.
fn execute_limited(
    selected: &SelectedMailbox,
    criterion: &parser::SearchCriterion,
    saved_search_uids: &[u64],
    imap4rev2: bool,
    mail_root: Option<&std::path::Path>,
    message_limit: Option<usize>,
) -> anyhow::Result<(Vec<(u64, u64)>, Option<String>)> {
    let mut matches = Vec::new();
    let now = chrono::Utc::now().timestamp();
    let fts = index_lookup(selected, criterion, mail_root);
    // RFC 9738: examine at most `message_limit` messages, the highest UIDs
    // first, and name the lowest UID examined so the client can continue
    // below it. Mailbox order follows file names, not UIDs, so the window is
    // chosen by UID and the mailbox order kept for sequence numbers.
    let mut live = selected
        .msgs
        .iter()
        .map(|(uid, _, _, _)| *uid)
        .filter(|uid| !selected.is_expunged(*uid))
        .collect::<Vec<_>>();
    let mut lowest_examined = 0;
    let mut limited = None;
    if let Some(limit) = message_limit.filter(|limit| live.len() > *limit) {
        live.sort_unstable();
        lowest_examined = live.get(live.len() - limit).copied().unwrap_or(u64::MAX);
        if limit > 0 {
            limited = Some(format!("MESSAGELIMIT {limit} {lowest_examined}"));
        }
    }
    for (index, (uid, path, flags, _)) in selected.msgs.iter().enumerate() {
        // Expunged by another session; the file may already be gone.
        if selected.is_expunged(*uid) || *uid < lowest_examined {
            continue;
        }
        let data = if parser::search_requires_message_data_for(criterion, *uid, fts.as_ref()) {
            std::fs::read(path)?
        } else {
            Vec::new()
        };
        let mut effective_flags = flags.clone();
        if !imap4rev2 && selected.recent_uids.contains(uid) {
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
            save_date: selected.save_dates.get(uid).copied().unwrap_or(0),
            in_saved_result: saved_search_uids.binary_search(uid).is_ok(),
            now,
            size: selected.sizes.get(uid).copied().unwrap_or(0) as usize,
            email_id: selected.email_ids.get(uid).map_or("", String::as_str),
            data: &data,
            fts: fts.as_ref(),
        };
        if parser::search_matches(criterion, &message, selected.msgs.len()) {
            matches.push((index as u64 + 1, *uid));
        }
    }
    Ok((matches, limited))
}

/// The UIDs SEARCH or SORT RETURN (SAVE ...) stores as `$`: everything found,
/// unless only MIN, MAX and/or PARTIAL were requested, in which case just the
/// messages those report (RFC 5182 §2.4, RFC 9394 §3.2 Table 1). `matches`
/// are `(sequence, uid)` pairs in result order.
pub(crate) fn saved_result(
    matches: &[(u64, u64)],
    options: &parser::SearchReturnOptions,
) -> Vec<u64> {
    let everything =
        options.all || options.count || (!options.min && !options.max && options.partial.is_none());
    if everything {
        return matches.iter().map(|(_, uid)| *uid).collect();
    }
    let mut uids = std::collections::BTreeSet::new();
    if let Some(range) = options.partial {
        uids.extend(range.select(matches).iter().map(|(_, uid)| *uid));
    }
    if options.min
        && let Some((_, uid)) = matches.first()
    {
        uids.insert(*uid);
    }
    if options.max
        && let Some((_, uid)) = matches.last()
    {
        uids.insert(*uid);
    }
    uids.into_iter().collect()
}

fn response(line: StatusLine) -> Outcome {
    Outcome {
        response: Response::new().status(line),
        saved_uids: None,
        context: None,
    }
}

fn result_data(
    tag: &str,
    uid_mode: bool,
    ids: &[u64],
    return_options: Option<&parser::SearchReturnOptions>,
    imap4rev2: bool,
) -> Option<String> {
    // RFC 9051 §6.4.4: IMAP4rev2 answers every SEARCH with ESEARCH; without
    // RETURN options that is RETURN (ALL).
    let rev2_default = parser::SearchReturnOptions {
        all: true,
        ..Default::default()
    };
    let options = match return_options {
        Some(options) => options,
        None if imap4rev2 => &rev2_default,
        None => {
            // RFC 3501: "SEARCH" *(SP nz-number), so no space when empty.
            return Some(ids.iter().fold("SEARCH".to_string(), |mut line, id| {
                line.push(' ');
                line.push_str(&id.to_string());
                line
            }));
        }
    };
    esearch_data(tag, uid_mode, ids, options)
}

/// ESEARCH data for `ids` in result order: mailbox order for SEARCH, sort
/// order for ESORT (RFC 5267 §3.1: MIN and MAX are the first and last sorted
/// results). PARTIAL selects by position in `ids`. `None` when only SAVE was
/// requested.
pub(crate) fn esearch_data(
    tag: &str,
    uid_mode: bool,
    ids: &[u64],
    options: &parser::SearchReturnOptions,
) -> Option<String> {
    if options.save
        && !options.min
        && !options.max
        && !options.all
        && !options.count
        && options.partial.is_none()
    {
        return None;
    }
    let escaped_tag = tag.replace('\\', "\\\\").replace('"', "\\\"");
    let mut data = format!("ESEARCH (TAG \"{escaped_tag}\")");
    if uid_mode {
        data.push_str(" UID");
    }
    if options.min
        && let Some(minimum) = ids.first()
    {
        data.push_str(&format!(" MIN {minimum}"));
    }
    if options.max
        && let Some(maximum) = ids.last()
    {
        data.push_str(&format!(" MAX {maximum}"));
    }
    if options.all && !ids.is_empty() {
        data.push_str(&format!(" ALL {}", compress_ids(ids)));
    }
    if let Some(range) = options.partial {
        // RFC 9394 §3.1: the requested range is echoed, with NIL when no
        // result falls inside it.
        let selected = range.select(ids);
        let results = if selected.is_empty() {
            "NIL".to_string()
        } else {
            compress_ids(selected)
        };
        data.push_str(&format!(" PARTIAL ({range} {results})"));
    }
    if options.count {
        data.push_str(&format!(" COUNT {}", ids.len()));
    }
    Some(data)
}

/// A sequence-set for `ids` that keeps their order: only ascending runs
/// become ranges (RFC 5267 §3.2), so sorted results expand in sort order.
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
            ..Default::default()
        };
        assert_eq!(
            result_data("A1", true, &[2, 3, 4, 8], Some(&options), false),
            Some("ESEARCH (TAG \"A1\") UID MIN 2 MAX 8 ALL 2:4,8 COUNT 4".to_string())
        );
        assert_eq!(
            result_data("A1", false, &[], Some(&options), false),
            Some("ESEARCH (TAG \"A1\") COUNT 0".to_string())
        );
    }

    fn options(spec: &str) -> parser::SearchReturnOptions {
        parser::parse_search_request(&format!("RETURN ({spec}) ALL"))
            .unwrap()
            .return_options
            .unwrap()
    }

    #[test]
    fn esearch_partial_pages_results_and_combines_with_aggregates() {
        let ids = [2, 3, 4, 8, 9, 12];
        assert_eq!(
            result_data("A1", true, &ids, Some(&options("PARTIAL 2:4")), false),
            Some("ESEARCH (TAG \"A1\") UID PARTIAL (2:4 3:4,8)".to_string())
        );
        assert_eq!(
            result_data("A1", false, &ids, Some(&options("PARTIAL -1:-2")), false),
            Some("ESEARCH (TAG \"A1\") PARTIAL (-1:-2 9,12)".to_string())
        );
        assert_eq!(
            result_data(
                "A1",
                false,
                &ids,
                Some(&options("MIN MAX COUNT PARTIAL 5:10")),
                false
            ),
            Some("ESEARCH (TAG \"A1\") MIN 2 MAX 12 PARTIAL (5:10 9,12) COUNT 6".to_string())
        );
        assert_eq!(
            result_data("A1", false, &ids, Some(&options("PARTIAL 7:9")), false),
            Some("ESEARCH (TAG \"A1\") PARTIAL (7:9 NIL)".to_string())
        );
        assert_eq!(
            result_data("A1", false, &[], Some(&options("SAVE PARTIAL 1:5")), false),
            Some("ESEARCH (TAG \"A1\") PARTIAL (1:5 NIL)".to_string())
        );
    }

    #[test]
    fn saved_results_follow_rfc_9394_table_1() {
        let matches = (1..=6).map(|seq| (seq, seq * 10)).collect::<Vec<_>>();
        let saved = |spec: &str| saved_result(&matches, &options(spec));
        assert_eq!(saved("SAVE"), vec![10, 20, 30, 40, 50, 60]);
        assert_eq!(saved("SAVE PARTIAL 2:3"), vec![20, 30]);
        assert_eq!(saved("SAVE PARTIAL 2:3 MIN"), vec![10, 20, 30]);
        assert_eq!(saved("SAVE PARTIAL 2:3 MAX"), vec![20, 30, 60]);
        assert_eq!(saved("SAVE PARTIAL -1:-2 MIN MAX"), vec![10, 50, 60]);
        assert_eq!(
            saved("SAVE PARTIAL 2:3 COUNT MIN"),
            vec![10, 20, 30, 40, 50, 60]
        );
        assert_eq!(saved("SAVE PARTIAL 9:10"), Vec::<u64>::new());
        assert_eq!(saved("SAVE MIN"), vec![10]);
    }

    #[test]
    fn esearch_partial_windows_and_sorted_order() {
        let partial = parser::SearchReturnOptions {
            partial: parser::PartialRange::parse("2:4"),
            ..Default::default()
        };
        assert_eq!(
            esearch_data("P1", true, &[9, 3, 4, 5, 1], &partial),
            Some("ESEARCH (TAG \"P1\") UID PARTIAL (2:4 3:5)".to_string())
        );
        let beyond = parser::SearchReturnOptions {
            partial: parser::PartialRange::parse("10:20"),
            ..Default::default()
        };
        assert_eq!(
            esearch_data("P2", false, &[1, 2], &beyond),
            Some("ESEARCH (TAG \"P2\") PARTIAL (10:20 NIL)".to_string())
        );
        // Sorted results keep their order; descending runs are not ranges.
        let all = parser::SearchReturnOptions {
            min: true,
            max: true,
            all: true,
            ..Default::default()
        };
        assert_eq!(
            esearch_data("S1", false, &[7, 6, 5, 1, 2, 3], &all),
            Some("ESEARCH (TAG \"S1\") MIN 7 MAX 3 ALL 7,6,5,1:3".to_string())
        );
    }

    #[tokio::test]
    async fn charset_errors_are_typed_and_do_not_replace_saved_results() {
        let selected = SelectedMailbox {
            domain: "example.test".to_string(),
            local: "user".to_string(),
            mailbox: "INBOX".to_string(),
            name: "INBOX".to_string(),
            rights: rmail_common::acl::Rights::ALL,
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
        };
        let outcome = handle(
            "A1",
            "CHARSET ISO-8859-1 ALL",
            None,
            &selected,
            &[9],
            false,
            false,
            false,
            &Default::default(),
            None,
        )
        .await;
        assert_eq!(outcome.saved_uids, None);
        assert_eq!(
            outcome.response.encode(),
            "A1 NO [BADCHARSET (US-ASCII UTF-8)] Unsupported charset\r\n"
        );
    }

    #[test]
    fn message_limit_keeps_the_highest_uids_whatever_the_mailbox_order() {
        let missing = std::path::PathBuf::from("/definitely/missing/rmail-message.eml");
        let message = |uid| (uid, missing.clone(), Vec::new(), 1);
        let selected = SelectedMailbox {
            domain: "example.test".to_string(),
            local: "user".to_string(),
            mailbox: "INBOX".to_string(),
            name: "INBOX".to_string(),
            rights: rmail_common::acl::Rights::ALL,
            uidvalidity: 1,
            uidnext: 10,
            highest_modseq: 1,
            mailbox_id: "Ftest".to_string(),
            read_only: false,
            // File-name order need not be UID order.
            msgs: vec![message(9), message(2), message(5), message(7)],
            internal_dates: Default::default(),
            save_dates: Default::default(),
            sizes: Default::default(),
            email_ids: Default::default(),
            recent_uids: Default::default(),
            expunged: Default::default(),
        };
        let (matches, code) = execute_limited(
            &selected,
            &parser::SearchCriterion::All,
            &[],
            false,
            None,
            Some(2),
        )
        .unwrap();
        assert_eq!(matches, vec![(1, 9), (4, 7)]);
        assert_eq!(code.as_deref(), Some("MESSAGELIMIT 2 7"));
    }

    #[test]
    fn metadata_searches_do_not_open_message_files() {
        let missing = std::path::PathBuf::from("/definitely/missing/rmail-message.eml");
        let selected = SelectedMailbox {
            domain: "example.test".to_string(),
            local: "user".to_string(),
            mailbox: "INBOX".to_string(),
            name: "INBOX".to_string(),
            rights: rmail_common::acl::Rights::ALL,
            uidvalidity: 1,
            uidnext: 8,
            highest_modseq: 1,
            mailbox_id: "Ftest".to_string(),
            read_only: false,
            msgs: vec![(7, missing, vec!["\\Seen".to_string()], 1)],
            internal_dates: [(7, (1_700_000_000, 0))].into(),
            save_dates: Default::default(),
            sizes: [(7, 12_345)].into(),
            email_ids: Default::default(),
            recent_uids: Default::default(),
            expunged: Default::default(),
        };

        let criterion = parser::SearchCriterion::And(vec![
            parser::SearchCriterion::Seen,
            parser::SearchCriterion::Larger(10_000),
        ]);
        assert_eq!(
            execute(&selected, &criterion, &[], false, None).unwrap(),
            vec![(1, 7)]
        );
        assert!(
            execute(
                &selected,
                &parser::SearchCriterion::Text("body".to_string()),
                &[],
                false,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn indexed_body_and_text_searches_match_the_scan() {
        use parser::SearchCriterion as C;
        let td = tempfile::tempdir().unwrap();
        let root = td.path().join("mail");
        let write = |name: &str, data: &str| {
            let path = td.path().join(name);
            std::fs::write(&path, data).unwrap();
            path
        };
        let messages = [
            (
                1u64,
                "Subject: Quarterly\r\n\r\nThe numbers are in. Caf\u{e9} menu.\r\n",
            ),
            (
                2,
                "Subject: lunch\r\nFrom: bob@example.org\r\n\r\nno figures here\r\n",
            ),
            (3, "Subject: numbers\nX: y\n\nplain LF body NUMBERS\n"),
        ];
        let view = |msgs: &[(u64, &str)], paths: &[std::path::PathBuf]| SelectedMailbox {
            domain: "example.test".to_string(),
            local: "user".to_string(),
            mailbox: "INBOX".to_string(),
            name: "INBOX".to_string(),
            rights: rmail_common::acl::Rights::ALL,
            uidvalidity: 5,
            uidnext: 99,
            highest_modseq: 1,
            mailbox_id: "Ftest".to_string(),
            read_only: false,
            msgs: msgs
                .iter()
                .zip(paths)
                .map(|((uid, _), path)| (*uid, path.clone(), vec!["\\Seen".to_string()], 1))
                .collect(),
            internal_dates: Default::default(),
            save_dates: Default::default(),
            sizes: Default::default(),
            email_ids: Default::default(),
            recent_uids: Default::default(),
            expunged: Default::default(),
        };
        let paths: Vec<_> = messages
            .iter()
            .map(|(uid, data)| write(&format!("m{uid}"), data))
            .collect();
        let selected = view(&messages, &paths);
        let criteria = vec![
            C::Body("numbers".into()),
            C::Body("NUMBERS ARE".into()),
            C::Body("cafe".into()),
            C::Body("subject".into()),
            C::Text("subject: lunch".into()),
            C::Text("bob@example".into()),
            C::Not(Box::new(C::Body("numbers".into()))),
            C::Or(Box::new(C::Body("figures".into())), Box::new(C::Seen)),
            C::And(vec![C::Seen, C::Text("quarterly".into())]),
            C::And(vec![
                C::Header("subject".into(), "lunch".into()),
                C::Body("figures".into()),
            ]),
            C::Body("ab".into()),
            C::Body("nomatchatall".into()),
        ];
        for criterion in &criteria {
            let scanned = execute(&selected, criterion, &[], false, None).unwrap();
            // Twice: the first call builds the index, the second uses it.
            for _ in 0..2 {
                assert_eq!(
                    execute(&selected, criterion, &[], false, Some(&root)).unwrap(),
                    scanned,
                    "{criterion:?}"
                );
            }
        }

        // The index answers without opening covered messages: delete a file and
        // the indexed search still works while the scan cannot read it.
        std::fs::remove_file(&paths[0]).unwrap();
        let criterion = C::Body("numbers".into());
        assert_eq!(
            execute(&selected, &criterion, &[], false, Some(&root)).unwrap(),
            vec![(1, 1), (3, 3)]
        );
        assert!(execute(&selected, &criterion, &[], false, None).is_err());

        // A new arrival is indexed on the next search; an expunged message
        // (gone from the view) drops out.
        let mut more = messages.to_vec();
        more.push((4, "Subject: late\r\n\r\nnumbers again\r\n"));
        let mut more_paths = paths.clone();
        more_paths.push(write("m4", more[3].1));
        let mut grown = view(&more[1..], &more_paths[1..]);
        grown.uidnext = 100;
        assert_eq!(
            execute(&grown, &criterion, &[], false, Some(&root)).unwrap(),
            vec![(2, 3), (3, 4)]
        );
        assert_eq!(
            execute(&grown, &criterion, &[], false, None).unwrap(),
            vec![(2, 3), (3, 4)]
        );
    }
}
