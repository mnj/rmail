//! RFC 5464 METADATA: GETMETADATA and SETMETADATA for server ("") and
//! mailbox annotations.

use crate::mailbox;
use crate::parser::{self, Command, ImapArg};
use crate::response::{Response, Status, StatusLine};
use std::path::Path;

/// Largest value SETMETADATA accepts, in octets (`NO [METADATA MAXSIZE]`).
pub(crate) const MAX_VALUE_BYTES: usize = 64 * 1024;
/// Most entries one account may hold across the server and all mailboxes
/// (`NO [METADATA TOOMANY]`).
pub(crate) const MAX_ENTRIES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Depth {
    Zero,
    One,
    Infinity,
}

#[derive(Debug, PartialEq, Eq)]
struct GetRequest {
    mailbox: String,
    max_size: Option<u64>,
    depth: Depth,
    entries: Vec<String>,
}

pub(crate) fn handle(
    tag: &str,
    command: &Command,
    args: &str,
    mail_root: &str,
    address: &str,
    utf8_accept: bool,
) -> Response {
    let Ok(arguments) = parser::parse_imap_args(args) else {
        return bad(tag, "Invalid metadata arguments");
    };
    let Ok((local, domain)) = mailbox::address_parts(address) else {
        return unavailable(tag, "Invalid authenticated mailbox");
    };
    let account = Account {
        root: Path::new(mail_root),
        domain: &domain,
        local: &local,
    };
    match command {
        Command::GetMetadata => match parse_get(&arguments) {
            Ok(request) => get(tag, &account, request, utf8_accept),
            Err(message) => bad(tag, message),
        },
        Command::SetMetadata => match parse_set(&arguments) {
            Ok((mailbox, changes)) => set(tag, &account, mailbox, changes, utf8_accept),
            Err(message) => bad(tag, message),
        },
        _ => bad(tag, "Invalid metadata command"),
    }
}

struct Account<'a> {
    root: &'a Path,
    domain: &'a str,
    local: &'a str,
}

fn get(tag: &str, account: &Account<'_>, request: GetRequest, utf8_accept: bool) -> Response {
    let Ok(mailbox_name) = wire_mailbox(&request.mailbox, utf8_accept) else {
        return bad(tag, "Invalid mailbox name");
    };
    let stored = match rmail_common::imap_state::get_metadata(
        account.root,
        account.domain,
        account.local,
        mailbox_name.as_deref(),
    ) {
        Ok(Some(stored)) => stored,
        Ok(None) => return Response::new().status(no(tag, "Mailbox does not exist")),
        Err(error) => return unavailable(tag, &error.to_string()),
    };
    let mut values: Vec<(&str, Option<&str>)> = Vec::new();
    let mut longest_omitted: Option<u64> = None;
    for requested in &request.entries {
        let mut found = false;
        for (entry, value) in &stored {
            if !matches_request(entry, requested, request.depth) {
                continue;
            }
            found = true;
            if values
                .iter()
                .any(|(seen, _)| seen.eq_ignore_ascii_case(entry))
            {
                continue;
            }
            let size = value.len() as u64;
            if request.max_size.is_some_and(|max_size| size > max_size) {
                longest_omitted = Some(longest_omitted.map_or(size, |longest| longest.max(size)));
                continue;
            }
            values.push((entry, Some(value)));
        }
        // An entry asked for by name that does not exist reads as NIL.
        if !found
            && request.depth == Depth::Zero
            && !values
                .iter()
                .any(|(seen, _)| seen.eq_ignore_ascii_case(requested))
        {
            values.push((requested, None));
        }
    }
    let mut response = Response::new();
    if !values.is_empty() {
        let mailbox = match &mailbox_name {
            Some(name) => mailbox::quote_wire_mailbox_name(name, utf8_accept),
            None => "\"\"".to_string(),
        };
        let items = values
            .iter()
            .map(|(entry, value)| format!("{} {}", quote(entry), encode_value(*value)))
            .collect::<Vec<_>>()
            .join(" ");
        response = response.literal_data(format!("METADATA {mailbox} ({items})"));
    }
    let mut line = StatusLine::tagged(tag, Status::Ok, "GETMETADATA completed");
    if let Some(longest) = longest_omitted {
        line = line.with_code(format!("METADATA LONGENTRIES {longest}"));
    }
    response.status(line)
}

type Changes = Vec<(String, Option<String>)>;

fn set(
    tag: &str,
    account: &Account<'_>,
    mailbox: String,
    changes: Changes,
    utf8_accept: bool,
) -> Response {
    let Ok(mailbox_name) = wire_mailbox(&mailbox, utf8_accept) else {
        return bad(tag, "Invalid mailbox name");
    };
    if mailbox_name.is_none()
        && changes
            .iter()
            .any(|(entry, _)| entry.eq_ignore_ascii_case("/shared/admin"))
    {
        return Response::new().status(
            no(tag, "/shared/admin is set by the server administrator").with_code("NOPERM"),
        );
    }
    if changes
        .iter()
        .any(|(_, value)| value.as_ref().is_some_and(|v| v.len() > MAX_VALUE_BYTES))
    {
        return Response::new().status(
            StatusLine::tagged(tag, Status::No, "Metadata value too large")
                .with_code(format!("METADATA MAXSIZE {MAX_VALUE_BYTES}")),
        );
    }
    match rmail_common::imap_state::set_metadata(
        account.root,
        account.domain,
        account.local,
        mailbox_name.as_deref(),
        &changes,
        MAX_ENTRIES,
    ) {
        Ok(true) => {
            Response::new().status(StatusLine::tagged(tag, Status::Ok, "SETMETADATA completed"))
        }
        Ok(false) => Response::new().status(no(tag, "Mailbox does not exist")),
        Err(error)
            if error
                .downcast_ref::<rmail_common::imap_state::MetadataTooMany>()
                .is_some() =>
        {
            Response::new().status(
                StatusLine::tagged(tag, Status::No, "Too many metadata entries")
                    .with_code("METADATA TOOMANY"),
            )
        }
        Err(error) => unavailable(tag, &error.to_string()),
    }
}

/// `""` names the server; anything else is a mailbox.
fn wire_mailbox(name: &str, utf8_accept: bool) -> anyhow::Result<Option<String>> {
    if name.is_empty() {
        return Ok(None);
    }
    mailbox::decode_wire_mailbox_name(name, utf8_accept).map(Some)
}

/// GETMETADATA [options] mailbox entries (RFC 5464 §4.2). Options placed
/// after the mailbox, as in earlier drafts, are accepted too.
fn parse_get(arguments: &[ImapArg]) -> Result<GetRequest, &'static str> {
    let (options, mailbox, entries) = match arguments {
        [ImapArg::List(options), mailbox, entries] => (Some(options), mailbox, entries),
        [mailbox, ImapArg::List(options), entries] => (Some(options), mailbox, entries),
        [mailbox, entries] => (None, mailbox, entries),
        _ => return Err("Invalid GETMETADATA arguments"),
    };
    let mailbox = mailbox.as_text().ok_or("Invalid mailbox name")?.to_string();
    let mut request = GetRequest {
        mailbox,
        max_size: None,
        depth: Depth::Zero,
        entries: Vec::new(),
    };
    if let Some(options) = options {
        if options.is_empty() || options.len() % 2 != 0 {
            return Err("Invalid GETMETADATA options");
        }
        for pair in options.chunks(2) {
            let (Some(name), Some(value)) = (pair[0].as_text(), pair[1].as_text()) else {
                return Err("Invalid GETMETADATA options");
            };
            if name.eq_ignore_ascii_case("MAXSIZE") {
                let max_size = value
                    .parse::<u64>()
                    .ok()
                    .filter(|_| value.bytes().all(|byte| byte.is_ascii_digit()))
                    .ok_or("Invalid MAXSIZE")?;
                request.max_size = Some(max_size);
            } else if name.eq_ignore_ascii_case("DEPTH") {
                request.depth = match value.to_ascii_lowercase().as_str() {
                    "0" => Depth::Zero,
                    "1" => Depth::One,
                    "infinity" => Depth::Infinity,
                    _ => return Err("Invalid DEPTH"),
                };
            } else {
                return Err("Unknown GETMETADATA option");
            }
        }
    }
    let entries = match entries {
        ImapArg::List(entries) if !entries.is_empty() => entries.as_slice(),
        ImapArg::List(_) => return Err("Invalid GETMETADATA entries"),
        entry => std::slice::from_ref(entry),
    };
    for entry in entries {
        let entry = entry.as_text().ok_or("Invalid metadata entry")?;
        // "/private" and "/shared" alone may be read with DEPTH, not set.
        let is_root =
            entry.eq_ignore_ascii_case("/private") || entry.eq_ignore_ascii_case("/shared");
        if !is_root && !valid_entry(entry) {
            return Err("Invalid metadata entry name");
        }
        request.entries.push(entry.to_string());
    }
    Ok(request)
}

/// SETMETADATA mailbox (entry value ...) (RFC 5464 §4.3).
fn parse_set(arguments: &[ImapArg]) -> Result<(String, Changes), &'static str> {
    let [mailbox, ImapArg::List(items)] = arguments else {
        return Err("Invalid SETMETADATA arguments");
    };
    let mailbox = mailbox.as_text().ok_or("Invalid mailbox name")?.to_string();
    if items.is_empty() || items.len() % 2 != 0 {
        return Err("Invalid SETMETADATA arguments");
    }
    let mut changes: Changes = Vec::new();
    for pair in items.chunks(2) {
        let entry = pair[0].as_text().ok_or("Invalid metadata entry")?;
        if !valid_entry(entry) {
            return Err("Invalid metadata entry name");
        }
        let value = match &pair[1] {
            ImapArg::Nil => None,
            ImapArg::String(value) => Some(value.clone()),
            _ => return Err("Invalid metadata value"),
        };
        // A later value for the same entry replaces an earlier one.
        changes.retain(|(seen, _)| !seen.eq_ignore_ascii_case(entry));
        changes.push((entry.to_string(), value));
    }
    Ok((mailbox, changes))
}

/// RFC 9590 LIST RETURN (METADATA (...)): the METADATA data for `mailbox`
/// with each requested entry's value, or NIL when unset. `None` when the
/// annotations cannot be read, which the RFC lets the server leave out.
pub(crate) fn list_metadata(
    root: &Path,
    domain: &str,
    local: &str,
    mailbox: &str,
    entries: &[String],
    utf8_accept: bool,
) -> Option<String> {
    let stored = rmail_common::imap_state::get_metadata(root, domain, local, Some(mailbox))
        .ok()
        .flatten()?;
    let items = entries
        .iter()
        .map(|entry| {
            let value = stored
                .iter()
                .find(|(stored, _)| stored.eq_ignore_ascii_case(entry))
                .map(|(_, value)| value.as_str());
            format!("{} {}", quote(entry), encode_value(value))
        })
        .collect::<Vec<_>>()
        .join(" ");
    Some(format!(
        "METADATA {} ({items})",
        mailbox::quote_wire_mailbox_name(mailbox, utf8_accept)
    ))
}

/// RFC 5464 §3.2: a slash-separated name under `/private/` or `/shared/`
/// with no empty components, no `*` or `%`, and no control characters.
pub(crate) fn valid_entry(entry: &str) -> bool {
    let lower = entry.to_ascii_lowercase();
    let rest = if let Some(rest) = lower.strip_prefix("/private/") {
        rest
    } else if let Some(rest) = lower.strip_prefix("/shared/") {
        rest
    } else {
        return false;
    };
    entry.len() <= 1024
        && !rest.is_empty()
        && rest.split('/').all(|component| !component.is_empty())
        && !entry
            .chars()
            .any(|character| character.is_control() || matches!(character, '*' | '%'))
}

fn matches_request(entry: &str, requested: &str, depth: Depth) -> bool {
    if entry.eq_ignore_ascii_case(requested) {
        return true;
    }
    if depth == Depth::Zero {
        return false;
    }
    let (Some(prefix), Some(rest)) = (entry.get(..requested.len()), entry.get(requested.len()..))
    else {
        return false;
    };
    let Some(child) = rest.strip_prefix('/').filter(|child| !child.is_empty()) else {
        return false;
    };
    prefix.eq_ignore_ascii_case(requested) && (depth == Depth::Infinity || !child.contains('/'))
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Printable ASCII goes out quoted; anything else as a literal.
fn encode_value(value: Option<&str>) -> String {
    match value {
        None => "NIL".to_string(),
        Some(value) if value.bytes().all(|byte| (0x20..0x7f).contains(&byte)) => quote(value),
        Some(value) => format!("{{{}}}\r\n{value}", value.len()),
    }
}

fn no(tag: &str, message: &str) -> StatusLine {
    StatusLine::tagged(tag, Status::No, message)
}

fn bad(tag: &str, message: &str) -> Response {
    Response::new().status(StatusLine::tagged(tag, Status::Bad, message))
}

fn unavailable(tag: &str, message: &str) -> Response {
    Response::new().status(StatusLine::tagged(tag, Status::No, message).with_code("UNAVAILABLE"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(input: &str) -> Vec<ImapArg> {
        parser::parse_imap_args(input).unwrap()
    }

    #[test]
    fn entry_names_follow_rfc_5464_syntax() {
        for valid in [
            "/private/comment",
            "/shared/comment",
            "/Private/vendor/example/x",
        ] {
            assert!(valid_entry(valid), "{valid}");
        }
        for invalid in [
            "/private",
            "/private/",
            "/shared//comment",
            "/shared/comment/",
            "/other/comment",
            "private/comment",
            "/private/a*",
            "/private/a%",
            "/private/a\u{7f}",
        ] {
            assert!(!valid_entry(invalid), "{invalid}");
        }
    }

    #[test]
    fn getmetadata_accepts_options_before_or_after_the_mailbox() {
        let expected = GetRequest {
            mailbox: "INBOX".to_string(),
            max_size: Some(1024),
            depth: Depth::Infinity,
            entries: vec!["/private/a".to_string(), "/shared".to_string()],
        };
        assert_eq!(
            parse_get(&args(
                "(MAXSIZE 1024 DEPTH infinity) INBOX (/private/a /shared)"
            )),
            Ok(expected)
        );
        let request = parse_get(&args("INBOX (depth 1) /private/a")).unwrap();
        assert_eq!(request.depth, Depth::One);
        assert_eq!(request.entries, vec!["/private/a".to_string()]);
        assert!(parse_get(&args("INBOX (DEPTH 2) /private/a")).is_err());
        assert!(parse_get(&args("INBOX (MAXSIZE -1) /private/a")).is_err());
        assert!(parse_get(&args("INBOX /private")).is_ok());
        assert!(parse_get(&args("INBOX /other/a")).is_err());
        assert!(parse_get(&args("INBOX ()")).is_err());
    }

    #[test]
    fn setmetadata_keeps_the_last_value_for_repeated_entries() {
        let (mailbox, changes) = parse_set(&args(
            "\"\" (/shared/a \"1\" /SHARED/A NIL /shared/b \"2\")",
        ))
        .unwrap();
        assert_eq!(mailbox, "");
        assert_eq!(
            changes,
            vec![
                ("/SHARED/A".to_string(), None),
                ("/shared/b".to_string(), Some("2".to_string())),
            ]
        );
        assert!(parse_set(&args("INBOX (/private/a)")).is_err());
        assert!(parse_set(&args("INBOX (/private \"x\")")).is_err());
        assert!(parse_set(&args("INBOX /private/a \"x\"")).is_err());
    }

    #[test]
    fn depth_selects_the_entry_and_its_descendants() {
        assert!(matches_request("/private/a", "/private/a", Depth::Zero));
        assert!(matches_request("/Private/A", "/private/a", Depth::Zero));
        assert!(!matches_request("/private/a/b", "/private/a", Depth::Zero));
        assert!(matches_request("/private/a/b", "/private/a", Depth::One));
        assert!(!matches_request("/private/a/b/c", "/private/a", Depth::One));
        assert!(matches_request(
            "/private/a/b/c",
            "/private/a",
            Depth::Infinity
        ));
        assert!(!matches_request(
            "/private/ab",
            "/private/a",
            Depth::Infinity
        ));
    }

    #[test]
    fn values_with_line_breaks_or_non_ascii_are_sent_as_literals() {
        assert_eq!(encode_value(None), "NIL");
        assert_eq!(encode_value(Some("say \"hi\"")), "\"say \\\"hi\\\"\"");
        assert_eq!(encode_value(Some("a\r\nb")), "{4}\r\na\r\nb");
        assert_eq!(encode_value(Some("é")), "{2}\r\né");
    }
}
