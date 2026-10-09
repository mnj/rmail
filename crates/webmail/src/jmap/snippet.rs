//! SearchSnippet/get (RFC 8621 section 5): the subject and a piece of the
//! body with the search terms marked.

use rmail_common::jmap::mime;
use serde_json::{Map, Value, json};

use super::email::visible_emails;
use super::{Ctx, MethodError, MethodResult, ids_arg};

/// The words a filter searches for in text (`text`, `subject`, `body`).
fn terms(filter: &Value, out: &mut Vec<String>) {
    let Some(object) = filter.as_object() else {
        return;
    };
    if let Some(conditions) = object.get("conditions").and_then(Value::as_array) {
        if object.get("operator").and_then(Value::as_str) == Some("NOT") {
            return;
        }
        for condition in conditions {
            terms(condition, out);
        }
        return;
    }
    for key in ["text", "subject", "body"] {
        if let Some(term) = object.get(key).and_then(Value::as_str) {
            let term = term.trim();
            if !term.is_empty() && !out.iter().any(|known| known.eq_ignore_ascii_case(term)) {
                out.push(term.to_string());
            }
        }
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// `text` as HTML with each term wrapped in `<mark>`, or `None` when no
/// term occurs.
fn highlight(text: &str, terms: &[String]) -> Option<String> {
    let lower = text.to_lowercase();
    // Lower-casing can change byte lengths; only mark when it does not.
    if lower.len() != text.len() {
        return None;
    }
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for term in terms {
        let needle = term.to_lowercase();
        let mut from = 0;
        while let Some(found) = lower[from..].find(&needle) {
            let start = from + found;
            ranges.push((start, start + needle.len()));
            from = start + needle.len().max(1);
        }
    }
    if ranges.is_empty() {
        return None;
    }
    ranges.sort();
    let mut out = String::new();
    let mut at = 0;
    for (start, end) in ranges {
        if start < at || !text.is_char_boundary(start) || !text.is_char_boundary(end) {
            continue;
        }
        out.push_str(&escape(&text[at..start]));
        out.push_str("<mark>");
        out.push_str(&escape(&text[start..end]));
        out.push_str("</mark>");
        at = end;
    }
    out.push_str(&escape(&text[at..]));
    Some(out)
}

/// Up to 255 characters of `text` around the first term.
fn excerpt(text: &str, terms: &[String]) -> Option<String> {
    let lower = text.to_lowercase();
    let first = terms
        .iter()
        .filter_map(|term| lower.find(&term.to_lowercase()))
        .min()?;
    let mut start = first.saturating_sub(60);
    while !text.is_char_boundary(start) {
        start -= 1;
    }
    let piece = text[start..].chars().take(255).collect::<String>();
    highlight(&piece, terms)
}

pub(crate) fn get(ctx: &mut Ctx, args: Map<String, Value>) -> MethodResult {
    let account = ctx.account(&args)?;
    let ids = ids_arg(ctx, &args, "emailIds")?
        .ok_or_else(|| MethodError::invalid("emailIds is required"))?;
    let mut search_terms = Vec::new();
    if let Some(filter) = args.get("filter") {
        terms(filter, &mut search_terms);
    }
    let rows = visible_emails(ctx, &account, Some(&ids))?;
    let mut list = Vec::new();
    let mut not_found = Vec::new();
    for id in ids {
        let Some(row) = rows.iter().find(|row| row.email_id == id) else {
            not_found.push(id);
            continue;
        };
        let body = row
            .copies
            .first()
            .and_then(|copy| std::fs::read(&copy.path).ok())
            .map(|data| {
                let root = mime::parse(&data);
                let lists = mime::body_lists(&root);
                mime::preview(&data, &root, &lists, 100_000)
            })
            .unwrap_or_default();
        list.push(json!({
            "emailId": row.email_id,
            "subject": highlight(&row.subject, &search_terms),
            "preview": excerpt(&body, &search_terms),
        }));
    }
    Ok(vec![(
        "SearchSnippet/get".to_string(),
        json!({"accountId": account.id, "list": list, "notFound": not_found}),
    )])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_terms_and_escapes_html() {
        let words = vec!["plan".to_string()];
        assert_eq!(
            highlight("The <Plan> & the plan", &words).as_deref(),
            Some("The &lt;<mark>Plan</mark>&gt; &amp; the <mark>plan</mark>")
        );
        assert_eq!(highlight("nothing here", &words), None);
        let mut found = Vec::new();
        terms(
            &json!({"operator": "AND", "conditions": [{"text": "a"}, {"subject": "b"}, {"operator": "NOT", "conditions": [{"text": "c"}]}]}),
            &mut found,
        );
        assert_eq!(found, ["a", "b"]);
    }
}
