//! RFC 4467 URLAUTH: GENURLAUTH, URLFETCH and RESETKEY.
//!
//! The URL rules, access keys and resolution live in
//! `rmail_common::urlauth`, which the submission server shares for BURL.
//! URLFETCH resolves URLs for this session's user only: `submit+` URLs are
//! for rMail's own submission service, which reads the store directly, so
//! an IMAP session never stands in for it.

use std::path::Path;

use rmail_common::urlauth::{self, Refusal, Requester};

use crate::parser;
use crate::response::{Response, Status, StatusLine};
use crate::{MAX_APPEND_LITERAL_BYTES, mailbox, shared};

/// The response code naming the supported mechanisms (RFC 4467 section 8).
pub(crate) const URLMECH: &str = "URLMECH INTERNAL";

/// The arguments as strings, or `None` for a list, NIL or a malformed line.
fn text_arguments(args: &str) -> Option<Vec<String>> {
    parser::parse_imap_args(args)
        .ok()?
        .iter()
        .map(|argument| argument.as_text().map(str::to_string))
        .collect()
}

/// `GENURLAUTH 1*(SP url-rump SP mechanism)`.
pub(crate) fn genurlauth(
    tag: &str,
    args: &str,
    mail_root: &Path,
    db_path: Option<&Path>,
    address: &str,
) -> Response {
    let arguments = match text_arguments(args) {
        Some(arguments) if !arguments.is_empty() && arguments.len() % 2 == 0 => arguments,
        _ => return bad(tag, "Invalid GENURLAUTH arguments"),
    };
    let mut urls = Vec::new();
    for pair in arguments.chunks(2) {
        match urlauth::generate(mail_root, db_path, address, &pair[0], &pair[1]) {
            Ok(url) => urls.push(quoted(&url)),
            // RFC 4467 section 7: a URL the server will not authorize is a
            // BAD; failing storage is a NO.
            Err(Refusal::Unavailable) => {
                return Response::new().status(
                    StatusLine::tagged(tag, Status::No, "GENURLAUTH failed")
                        .with_code("UNAVAILABLE"),
                );
            }
            Err(refusal) => return bad(tag, &format!("GENURLAUTH refused: {refusal}")),
        }
    }
    Response::new()
        .data(format!("GENURLAUTH {}", urls.join(" ")))
        .status(StatusLine::tagged(tag, Status::Ok, "GENURLAUTH completed"))
}

/// `URLFETCH 1*(SP url)`: one untagged URLFETCH per URL, with NIL for any
/// URL that is invalid, revoked or not for this user (RFC 4467 section 7).
/// The content is raw message data, so the reply is bytes.
pub(crate) fn urlfetch(
    tag: &str,
    args: &str,
    mail_root: &Path,
    db_path: Option<&Path>,
    address: &str,
) -> (Vec<u8>, usize) {
    let urls = match text_arguments(args) {
        Some(urls) if !urls.is_empty() => urls,
        // URLAUTH=BINARY (RFC 5524) parenthesized forms are not offered.
        _ => {
            return (
                bad(tag, "Invalid URLFETCH arguments").encode().into_bytes(),
                0,
            );
        }
    };
    let mut output = Vec::new();
    let mut resolved = 0;
    for url in &urls {
        output.extend_from_slice(format!("* URLFETCH {} ", quoted(url)).as_bytes());
        match urlauth::fetch(
            mail_root,
            db_path,
            url,
            Requester::Imap(address),
            MAX_APPEND_LITERAL_BYTES as u64,
        ) {
            // A literal cannot carry NUL without the BINARY extension.
            Ok(data) if !data.contains(&0) => {
                resolved += 1;
                output.extend_from_slice(format!("{{{}}}\r\n", data.len()).as_bytes());
                output.extend_from_slice(&data);
            }
            _ => output.extend_from_slice(b"NIL"),
        }
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(
        Response::new()
            .status(StatusLine::tagged(tag, Status::Ok, "URLFETCH completed"))
            .encode()
            .as_bytes(),
    );
    (output, resolved)
}

/// `RESETKEY [SP mailbox *(SP mechanism)]`: revoke the user's URLs for one
/// mailbox, or for all of them.
pub(crate) fn resetkey(
    tag: &str,
    args: &str,
    mail_root: &Path,
    db_path: Option<&Path>,
    address: &str,
    utf8_accept: bool,
) -> Response {
    let Some(arguments) = text_arguments(args) else {
        return bad(tag, "Invalid RESETKEY arguments");
    };
    if arguments[1.min(arguments.len())..]
        .iter()
        .any(|mechanism| !mechanism.eq_ignore_ascii_case(urlauth::MECHANISM))
    {
        return bad(tag, "Unsupported URLAUTH mechanism");
    }
    let Some(name) = arguments.first() else {
        return match urlauth::reset_keys(mail_root, address, None) {
            Ok(()) => {
                Response::new().status(StatusLine::tagged(tag, Status::Ok, "All keys removed"))
            }
            Err(error) => no(tag, "UNAVAILABLE", &format!("RESETKEY failed: {error}")),
        };
    };
    let Ok(name) = mailbox::decode_wire_mailbox_name(name, utf8_accept) else {
        return bad(tag, "Invalid mailbox name");
    };
    let result = mailbox_id(mail_root, db_path, address, &name).and_then(|id| match id {
        Some(id) => urlauth::reset_keys(mail_root, address, Some(&id)).map(|()| true),
        None => Ok(false),
    });
    match result {
        Ok(true) => Response::new()
            .status(StatusLine::tagged(tag, Status::Ok, "Key reset").with_code(URLMECH)),
        Ok(false) => no(tag, "NONEXISTENT", "Mailbox does not exist"),
        Err(error) => no(tag, "UNAVAILABLE", &format!("RESETKEY failed: {error}")),
    }
}

/// The MAILBOXID of a mailbox the user can see, own or shared.
fn mailbox_id(
    mail_root: &Path,
    db_path: Option<&Path>,
    address: &str,
    name: &str,
) -> anyhow::Result<Option<String>> {
    let target = shared::resolve(mail_root, db_path, address, name)?;
    if target.is_shared() {
        let visible = target.visible();
        return Ok(target.mailbox_id.filter(|_| visible));
    }
    Ok(rmail_common::imap_state::find_folder(
        mail_root,
        &target.domain,
        &target.local,
        &target.mailbox,
    )?
    .map(|folder| folder.mailbox_id))
}

/// A URL as an IMAP quoted string; URLs never need a literal.
fn quoted(url: &str) -> String {
    format!("\"{}\"", url.replace('\\', "\\\\").replace('"', "\\\""))
}

fn bad(tag: &str, text: &str) -> Response {
    Response::new().status(StatusLine::tagged(tag, Status::Bad, text))
}

fn no(tag: &str, code: &str, text: &str) -> Response {
    Response::new().status(StatusLine::tagged(tag, Status::No, text).with_code(code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_atoms_or_strings_but_never_lists() {
        assert_eq!(
            text_arguments("imap://a%40b.test@h/INBOX/;UID=1;URLAUTH=authuser INTERNAL"),
            Some(vec![
                "imap://a%40b.test@h/INBOX/;UID=1;URLAUTH=authuser".to_string(),
                "INTERNAL".to_string()
            ])
        );
        assert_eq!(text_arguments("(\"imap://x\" BINARY)"), None);
    }
}
