//! `/query` support: filters, paging (RFC 8620 section 5.5) and
//! Email/query (RFC 8621 section 4.4).
//!
//! Query results are computed from scratch each time, so `/queryChanges`
//! answers `cannotCalculateChanges` and clients run the query again.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use rmail_common::jmap::{mime, store::EmailRow};
use serde_json::{Map, Value, json};

use super::email::{self, visible_emails};
use super::{Ctx, MethodError, MethodResult, current_state, keyword_to_flag, parse_utc_date};

pub(crate) const EMAIL_SORT_OPTIONS: &[&str] = &[
    "receivedAt",
    "sentAt",
    "size",
    "from",
    "to",
    "subject",
    "hasKeyword",
    "allInThreadHaveKeyword",
    "someInThreadHaveKeyword",
];

/// Decides whether one `FilterCondition` matches.
pub(crate) type Condition<'a> = dyn Fn(&Map<String, Value>) -> Result<bool, MethodError> + 'a;

/// Evaluate a `FilterOperator`/`FilterCondition` tree.
pub(crate) fn matches(filter: &Value, condition: &Condition) -> Result<bool, MethodError> {
    let object = filter
        .as_object()
        .ok_or_else(|| MethodError::invalid("a filter must be an object"))?;
    let Some(operator) = object.get("operator") else {
        return condition(object);
    };
    let conditions = object
        .get("conditions")
        .and_then(Value::as_array)
        .ok_or_else(|| MethodError::invalid("an operator needs conditions"))?;
    match operator.as_str() {
        Some("AND") => {
            for item in conditions {
                if !matches(item, condition)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        Some("OR") => {
            for item in conditions {
                if matches(item, condition)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Some("NOT") => {
            for item in conditions {
                if matches(item, condition)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        _ => Err(MethodError::new("unsupportedFilter")),
    }
}

/// Apply `position`/`anchor`/`anchorOffset`/`limit` to the full result
/// list; the response fields `position`, `ids`, `total`, `limit` and
/// `canCalculateChanges`.
pub(crate) fn page(ids: Vec<String>, args: &Map<String, Value>) -> Result<Value, MethodError> {
    let total = ids.len();
    let limit = super::uint_arg(args, "limit")?.map(|limit| limit as usize);
    let start = match args.get("anchor").and_then(Value::as_str) {
        Some(anchor) => {
            let index = ids
                .iter()
                .position(|id| id == anchor)
                .ok_or_else(|| MethodError::new("anchorNotFound"))?;
            let offset = args
                .get("anchorOffset")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            (index as i64 + offset).max(0) as usize
        }
        None => {
            let position = match args.get("position") {
                None | Some(Value::Null) => 0,
                Some(value) => value
                    .as_i64()
                    .ok_or_else(|| MethodError::invalid("position must be an integer"))?,
            };
            if position < 0 {
                (total as i64 + position).max(0) as usize
            } else {
                position as usize
            }
        }
    };
    let start = start.min(total);
    let end = limit.map_or(total, |limit| start.saturating_add(limit).min(total));
    let mut response = json!({
        "canCalculateChanges": false,
        "position": start,
        "ids": ids[start..end],
    });
    if super::bool_arg(args, "calculateTotal")? {
        response["total"] = json!(total);
    }
    Ok(response)
}

pub(crate) fn cannot_calculate(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    ctx.account(&args)?;
    Err(MethodError::new("cannotCalculateChanges"))
}

fn contains(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// Text of a message's bodies, read on demand during one query.
struct Bodies<'a> {
    cache: HashMap<&'a str, String>,
}

impl<'a> Bodies<'a> {
    fn text(&mut self, row: &'a EmailRow) -> &str {
        self.cache.entry(&row.email_id).or_insert_with(|| {
            let Some(data) = row
                .copies
                .first()
                .and_then(|copy| std::fs::read(&copy.path).ok())
            else {
                return String::new();
            };
            let root = mime::parse(&data);
            let lists = mime::body_lists(&root);
            let mut text = String::new();
            for id in lists.text.iter().chain(&lists.html) {
                if let Some(part) = root.find(id) {
                    let part_text = part.text(&data);
                    if part.content_type == "text/html" {
                        text.push_str(&rmail_common::mime::snippet(&part_text));
                    } else {
                        text.push_str(&part_text);
                    }
                    text.push('\n');
                }
            }
            text
        })
    }
}

fn headers_of(row: &EmailRow) -> Vec<mime::Header> {
    row.copies
        .first()
        .and_then(|copy| std::fs::read(&copy.path).ok())
        .map(|data| {
            let root = mime::parse(&data);
            root.headers
        })
        .unwrap_or_default()
}

/// The subject without reply and forward prefixes, for sorting.
fn base_subject(subject: &str) -> String {
    let mut subject = subject.trim();
    loop {
        let lower = subject.to_ascii_lowercase();
        let stripped = ["re:", "fwd:", "fw:", "aw:", "sv:", "vs:"]
            .iter()
            .find(|prefix| lower.starts_with(*prefix))
            .map(|prefix| subject[prefix.len()..].trim_start());
        match stripped {
            Some(rest) => subject = rest,
            None => return subject.to_lowercase(),
        }
    }
}

pub(crate) fn email_query(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let account = ctx.account(&args)?;
    let rows = visible_emails(ctx, &account, None)?;
    let threads = {
        let mut threads: HashMap<&str, Vec<&EmailRow>> = HashMap::new();
        for row in &rows {
            threads.entry(&row.thread_id).or_default().push(row);
        }
        threads
    };
    let keyword_arg = |value: &Value| {
        value
            .as_str()
            .map(keyword_to_flag)
            .ok_or_else(|| MethodError::new("unsupportedFilter"))
    };
    let filter = args
        .get("filter")
        .filter(|filter| !filter.is_null())
        .cloned();
    let mut matching: Vec<&EmailRow> = Vec::new();
    let bodies = std::cell::RefCell::new(Bodies {
        cache: HashMap::new(),
    });
    for row in &rows {
        let keep = match &filter {
            None => true,
            Some(filter) => matches(filter, &|condition| {
                for (key, value) in condition {
                    let text = || {
                        value
                            .as_str()
                            .ok_or_else(|| MethodError::new("unsupportedFilter"))
                    };
                    let ok = match key.as_str() {
                        "inMailbox" => {
                            let id = text()?;
                            let id = ctx.resolve_id(id).unwrap_or_else(|| id.to_string());
                            row.copies.iter().any(|copy| copy.mailbox_id == id)
                        }
                        "inMailboxOtherThan" => {
                            let ids = value
                                .as_array()
                                .ok_or_else(|| MethodError::new("unsupportedFilter"))?
                                .iter()
                                .filter_map(Value::as_str)
                                .map(|id| ctx.resolve_id(id).unwrap_or_else(|| id.to_string()))
                                .collect::<HashSet<_>>();
                            row.copies
                                .iter()
                                .any(|copy| !ids.contains(&copy.mailbox_id))
                        }
                        "before" => {
                            row.received_at
                                < parse_utc_date(text()?)
                                    .ok_or_else(|| MethodError::new("unsupportedFilter"))?
                        }
                        "after" => {
                            row.received_at
                                >= parse_utc_date(text()?)
                                    .ok_or_else(|| MethodError::new("unsupportedFilter"))?
                        }
                        "minSize" => {
                            row.size
                                >= value
                                    .as_u64()
                                    .ok_or_else(|| MethodError::new("unsupportedFilter"))?
                        }
                        "maxSize" => {
                            row.size
                                < value
                                    .as_u64()
                                    .ok_or_else(|| MethodError::new("unsupportedFilter"))?
                        }
                        "hasKeyword" => row.has_flag(&keyword_arg(value)?),
                        "notKeyword" => !row.has_flag(&keyword_arg(value)?),
                        "allInThreadHaveKeyword" => {
                            let flag = keyword_arg(value)?;
                            threads[row.thread_id.as_str()]
                                .iter()
                                .all(|other| other.has_flag(&flag))
                        }
                        "someInThreadHaveKeyword" => {
                            let flag = keyword_arg(value)?;
                            threads[row.thread_id.as_str()]
                                .iter()
                                .any(|other| other.has_flag(&flag))
                        }
                        "noneInThreadHaveKeyword" => {
                            let flag = keyword_arg(value)?;
                            !threads[row.thread_id.as_str()]
                                .iter()
                                .any(|other| other.has_flag(&flag))
                        }
                        "hasAttachment" => {
                            value
                                .as_bool()
                                .ok_or_else(|| MethodError::new("unsupportedFilter"))?
                                == row.has_attachment
                        }
                        "from" => contains(&row.from, text()?),
                        "to" => contains(&row.to, text()?),
                        "cc" => contains(&row.cc, text()?),
                        "bcc" => contains(&row.bcc, text()?),
                        "subject" => contains(&row.subject, text()?),
                        "body" => contains(bodies.borrow_mut().text(row), text()?),
                        "text" => {
                            let needle = text()?;
                            [&row.subject, &row.from, &row.to, &row.cc, &row.bcc]
                                .iter()
                                .any(|field| contains(field, needle))
                                || contains(bodies.borrow_mut().text(row), needle)
                        }
                        "header" => {
                            let pair = value
                                .as_array()
                                .ok_or_else(|| MethodError::new("unsupportedFilter"))?;
                            let name = pair
                                .first()
                                .and_then(Value::as_str)
                                .ok_or_else(|| MethodError::new("unsupportedFilter"))?;
                            let wanted = pair.get(1).and_then(Value::as_str);
                            headers_of(row).iter().any(|header| {
                                header.name.eq_ignore_ascii_case(name)
                                    && wanted.is_none_or(|wanted| {
                                        contains(&mime::as_text(&header.value), wanted)
                                    })
                            })
                        }
                        _ => return Err(MethodError::new("unsupportedFilter")),
                    };
                    if !ok {
                        return Ok(false);
                    }
                }
                Ok(true)
            })?,
        };
        if keep {
            matching.push(row);
        }
    }

    let mut comparators: Vec<(String, bool, Option<String>)> = Vec::new();
    match args.get("sort").filter(|sort| !sort.is_null()) {
        None => comparators.push(("receivedAt".to_string(), false, None)),
        Some(sort) => {
            for comparator in sort
                .as_array()
                .ok_or_else(|| MethodError::invalid("sort must be a list"))?
            {
                let property = comparator
                    .get("property")
                    .and_then(Value::as_str)
                    .ok_or_else(|| MethodError::invalid("a comparator needs a property"))?;
                if !EMAIL_SORT_OPTIONS.contains(&property) {
                    return Err(MethodError::new("unsupportedSort"));
                }
                let keyword = comparator
                    .get("keyword")
                    .and_then(Value::as_str)
                    .map(keyword_to_flag);
                if property.contains("Keyword") && keyword.is_none() {
                    return Err(MethodError::invalid("keyword sorts need a keyword"));
                }
                let ascending = comparator
                    .get("isAscending")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                comparators.push((property.to_string(), ascending, keyword));
            }
        }
    }
    let compare = |a: &&EmailRow, b: &&EmailRow| -> Ordering {
        for (property, ascending, keyword) in &comparators {
            let flag = keyword.as_deref().unwrap_or_default();
            let order = match property.as_str() {
                "receivedAt" => a.received_at.cmp(&b.received_at),
                "sentAt" => a.sent_at.cmp(&b.sent_at),
                "size" => a.size.cmp(&b.size),
                "from" => a.from.to_lowercase().cmp(&b.from.to_lowercase()),
                "to" => a.to.to_lowercase().cmp(&b.to.to_lowercase()),
                "subject" => base_subject(&a.subject).cmp(&base_subject(&b.subject)),
                "hasKeyword" => a.has_flag(flag).cmp(&b.has_flag(flag)),
                "allInThreadHaveKeyword" => {
                    let all = |row: &EmailRow| {
                        threads[row.thread_id.as_str()]
                            .iter()
                            .all(|other| other.has_flag(flag))
                    };
                    all(a).cmp(&all(b))
                }
                _ => {
                    let some = |row: &EmailRow| {
                        threads[row.thread_id.as_str()]
                            .iter()
                            .any(|other| other.has_flag(flag))
                    };
                    some(a).cmp(&some(b))
                }
            };
            let order = if *ascending { order } else { order.reverse() };
            if order.is_ne() {
                return order;
            }
        }
        a.email_id.cmp(&b.email_id)
    };
    matching.sort_by(compare);
    if super::bool_arg(&args, "collapseThreads")? {
        let mut seen = HashSet::new();
        matching.retain(|row| seen.insert(row.thread_id.clone()));
    }
    let ids = matching
        .iter()
        .map(|row| row.email_id.clone())
        .collect::<Vec<_>>();
    let mut response = page(ids, &args)?;
    response["accountId"] = json!(account.id);
    response["queryState"] = json!(current_state(ctx, &account)?);
    let _ = email::PROPERTIES;
    Ok(vec![("Email/query".to_string(), response)])
}
