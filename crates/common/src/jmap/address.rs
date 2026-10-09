//! RFC 5322 address lists as JMAP `EmailAddress` and `EmailAddressGroup`
//! values (RFC 8621 section 4.1.2.3).
//!
//! The parser is forgiving, as mail in the wild needs: an unparseable item
//! becomes an address whose `email` is the item's text, so nothing a header
//! says is lost.

use serde::Serialize;

use crate::mime::decode_rfc2047_words;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EmailAddress {
    pub name: Option<String>,
    pub email: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressGroup {
    pub name: Option<String>,
    pub addresses: Vec<EmailAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    Quoted(String),
    Comment(String),
    Angle(String),
    Comma,
    Colon,
    Semicolon,
}

fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    let mut word = String::new();
    let flush = |word: &mut String, tokens: &mut Vec<Token>| {
        if !word.is_empty() {
            tokens.push(Token::Word(std::mem::take(word)));
        }
    };
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                flush(&mut word, &mut tokens);
                let mut text = String::new();
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => {
                            if let Some(next) = chars.next() {
                                text.push(next);
                            }
                        }
                        '"' => break,
                        '\r' | '\n' => {}
                        c => text.push(c),
                    }
                }
                tokens.push(Token::Quoted(text));
            }
            '(' => {
                flush(&mut word, &mut tokens);
                let mut depth = 1;
                let mut text = String::new();
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => {
                            if let Some(next) = chars.next() {
                                text.push(next);
                            }
                        }
                        '(' => {
                            depth += 1;
                            text.push(c);
                        }
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                            text.push(c);
                        }
                        c => text.push(c),
                    }
                }
                tokens.push(Token::Comment(text));
            }
            '<' => {
                flush(&mut word, &mut tokens);
                let mut text = String::new();
                for c in chars.by_ref() {
                    if c == '>' {
                        break;
                    }
                    if !c.is_whitespace() {
                        text.push(c);
                    }
                }
                tokens.push(Token::Angle(text));
            }
            ',' => {
                flush(&mut word, &mut tokens);
                tokens.push(Token::Comma);
            }
            ':' => {
                flush(&mut word, &mut tokens);
                tokens.push(Token::Colon);
            }
            ';' => {
                flush(&mut word, &mut tokens);
                tokens.push(Token::Semicolon);
            }
            c if c.is_whitespace() => flush(&mut word, &mut tokens),
            c => word.push(c),
        }
    }
    flush(&mut word, &mut tokens);
    tokens
}

/// The display name a phrase spells: words joined by spaces, encoded words
/// decoded (an encoded word inside a quoted string is decoded too, as many
/// mailers write them that way).
fn phrase_text(tokens: &[Token]) -> Option<String> {
    let words = tokens
        .iter()
        .filter_map(|token| match token {
            Token::Word(text) | Token::Quoted(text) => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if words.is_empty() {
        return None;
    }
    let text = decode_rfc2047_words(&words.join(" "));
    let text = text.trim().to_string();
    (!text.is_empty()).then_some(text)
}

fn comment_text(tokens: &[Token]) -> Option<String> {
    tokens.iter().find_map(|token| match token {
        Token::Comment(text) => {
            let text = decode_rfc2047_words(text.trim());
            (!text.is_empty()).then_some(text)
        }
        _ => None,
    })
}

/// One mailbox from the tokens between separators.
fn mailbox(tokens: &[Token]) -> Option<EmailAddress> {
    if tokens.is_empty() {
        return None;
    }
    if let Some(index) = tokens.iter().position(|t| matches!(t, Token::Angle(_))) {
        let Token::Angle(email) = &tokens[index] else {
            unreachable!()
        };
        let name = phrase_text(&tokens[..index]).or_else(|| comment_text(tokens));
        return Some(EmailAddress {
            name,
            email: email.clone(),
        });
    }
    // A bare addr-spec, perhaps with a comment naming its owner. Quoted
    // local parts keep their quotes.
    let email = tokens
        .iter()
        .filter_map(|token| match token {
            Token::Word(text) => Some(text.clone()),
            Token::Quoted(text) => Some(format!("\"{text}\"")),
            _ => None,
        })
        .collect::<String>();
    if email.is_empty() {
        return None;
    }
    Some(EmailAddress {
        name: comment_text(tokens),
        email,
    })
}

/// Parse an address-list header value, keeping groups. Addresses outside any
/// group are collected into groups whose `name` is `None`, one per run of
/// ungrouped addresses, as RFC 8621 describes.
pub fn parse_grouped(value: &str) -> Vec<AddressGroup> {
    let tokens = tokenize(&value.replace(['\r', '\n'], ""));
    let mut groups: Vec<AddressGroup> = Vec::new();
    let mut current: Vec<Token> = Vec::new();
    let mut group: Option<AddressGroup> = None;
    let push =
        |groups: &mut Vec<AddressGroup>, group: &mut Option<AddressGroup>, address| match group {
            Some(group) => group.addresses.push(address),
            None => match groups.last_mut() {
                Some(last) if last.name.is_none() => last.addresses.push(address),
                _ => groups.push(AddressGroup {
                    name: None,
                    addresses: vec![address],
                }),
            },
        };
    for token in tokens {
        match token {
            Token::Colon if group.is_none() && !current.iter().any(is_angle) => {
                group = Some(AddressGroup {
                    name: phrase_text(&current),
                    addresses: Vec::new(),
                });
                current.clear();
            }
            Token::Comma => {
                if let Some(address) = mailbox(&current) {
                    push(&mut groups, &mut group, address);
                }
                current.clear();
            }
            Token::Semicolon => {
                if let Some(address) = mailbox(&current) {
                    push(&mut groups, &mut group, address);
                }
                current.clear();
                if let Some(finished) = group.take() {
                    groups.push(finished);
                }
            }
            token => current.push(token),
        }
    }
    if let Some(address) = mailbox(&current) {
        push(&mut groups, &mut group, address);
    }
    if let Some(unfinished) = group.take() {
        groups.push(unfinished);
    }
    groups
}

fn is_angle(token: &Token) -> bool {
    matches!(token, Token::Angle(_))
}

/// Parse an address-list header value, flattening groups.
pub fn parse(value: &str) -> Vec<EmailAddress> {
    parse_grouped(value)
        .into_iter()
        .flat_map(|group| group.addresses)
        .collect()
}

/// An address as it appears in a header: `"Name" <email>` or `email`.
pub fn format(address: &EmailAddress) -> String {
    match address.name.as_deref().filter(|name| !name.is_empty()) {
        None => address.email.clone(),
        Some(name) => format!("{} <{}>", encode_phrase(name), address.email),
    }
}

/// A display name as a header phrase: an atom sequence when possible, a
/// quoted string for specials, and RFC 2047 encoded words for non-ASCII.
pub fn encode_phrase(name: &str) -> String {
    if !name.is_ascii() {
        return crate::jmap::mime::encode_word(name);
    }
    let atom = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-/=?^_`{|}~ ".contains(c);
    if name.chars().all(atom) && !name.starts_with(' ') && !name.ends_with(' ') {
        name.to_string()
    } else {
        format!("\"{}\"", name.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(name: Option<&str>, email: &str) -> EmailAddress {
        EmailAddress {
            name: name.map(str::to_string),
            email: email.to_string(),
        }
    }

    #[test]
    fn parses_names_quotes_comments_and_bare_addresses() {
        assert_eq!(
            parse(
                r#""Doe, Jane" <jane@example.com>, bob@example.com (Bob Smith), Joe Q <joe@x.test>"#
            ),
            vec![
                address(Some("Doe, Jane"), "jane@example.com"),
                address(Some("Bob Smith"), "bob@example.com"),
                address(Some("Joe Q"), "joe@x.test"),
            ]
        );
        assert_eq!(
            parse("=?UTF-8?Q?J=C3=B8rgen?= <j@example.dk>"),
            vec![address(Some("Jørgen"), "j@example.dk")]
        );
        assert_eq!(parse(""), Vec::new());
    }

    #[test]
    fn groups_are_kept_and_ungrouped_runs_are_collected() {
        let groups = parse_grouped("a@x.test, Team: b@x.test, C <c@x.test>;, d@x.test");
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].name, None);
        assert_eq!(groups[0].addresses, vec![address(None, "a@x.test")]);
        assert_eq!(groups[1].name.as_deref(), Some("Team"));
        assert_eq!(groups[1].addresses.len(), 2);
        assert_eq!(groups[2].addresses, vec![address(None, "d@x.test")]);
        assert_eq!(
            parse_grouped("undisclosed-recipients:;")[0].name.as_deref(),
            Some("undisclosed-recipients")
        );
    }

    #[test]
    fn formats_names_safely() {
        assert_eq!(
            format(&address(Some("Doe, Jane"), "j@x.test")),
            "\"Doe, Jane\" <j@x.test>"
        );
        assert_eq!(format(&address(Some("Bob"), "b@x.test")), "Bob <b@x.test>");
        assert_eq!(format(&address(None, "b@x.test")), "b@x.test");
        assert!(format(&address(Some("Jørgen"), "j@x.test")).starts_with("=?UTF-8?"));
    }
}
