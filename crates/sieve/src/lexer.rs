//! Tokenizer for the Sieve grammar (RFC 5228 section 8.1).

use crate::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Tok {
    Ident(String),
    Tag(String),
    Num(u64),
    Str(String),
    LBracket,
    RBracket,
    LParen,
    RParen,
    LBrace,
    RBrace,
    Comma,
    Semi,
}

#[derive(Debug, Clone)]
pub(crate) struct Token {
    pub tok: Tok,
    pub line: usize,
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

pub(crate) fn lex(src: &str) -> Result<Vec<Token>, Error> {
    let chars: Vec<char> = src.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    let mut line = 1;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\n' => {
                line += 1;
                i += 1;
            }
            c if c.is_whitespace() => i += 1,
            '#' => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '/' if chars.get(i + 1) == Some(&'*') => {
                let start_line = line;
                i += 2;
                loop {
                    match (chars.get(i), chars.get(i + 1)) {
                        (Some('*'), Some('/')) => {
                            i += 2;
                            break;
                        }
                        (Some('\n'), _) => {
                            line += 1;
                            i += 1;
                        }
                        (Some(_), _) => i += 1,
                        (None, _) => {
                            return Err(Error::syntax(start_line, "unterminated comment"));
                        }
                    }
                }
            }
            '[' | ']' | '(' | ')' | '{' | '}' | ',' | ';' => {
                let tok = match c {
                    '[' => Tok::LBracket,
                    ']' => Tok::RBracket,
                    '(' => Tok::LParen,
                    ')' => Tok::RParen,
                    '{' => Tok::LBrace,
                    '}' => Tok::RBrace,
                    ',' => Tok::Comma,
                    _ => Tok::Semi,
                };
                tokens.push(Token { tok, line });
                i += 1;
            }
            '"' => {
                let start_line = line;
                i += 1;
                let mut out = String::new();
                loop {
                    match chars.get(i) {
                        None => return Err(Error::syntax(start_line, "unterminated string")),
                        Some('"') => {
                            i += 1;
                            break;
                        }
                        Some('\\') => {
                            match chars.get(i + 1) {
                                Some(&escaped) => out.push(escaped),
                                None => {
                                    return Err(Error::syntax(start_line, "unterminated string"));
                                }
                            }
                            i += 2;
                        }
                        Some('\n') => {
                            line += 1;
                            out.push('\n');
                            i += 1;
                        }
                        Some(&ch) => {
                            out.push(ch);
                            i += 1;
                        }
                    }
                }
                tokens.push(Token {
                    tok: Tok::Str(out),
                    line: start_line,
                });
            }
            ':' => {
                let start = i + 1;
                i += 1;
                while i < chars.len() && is_ident(chars[i]) {
                    i += 1;
                }
                if i == start || !is_ident_start(chars[start]) {
                    return Err(Error::syntax(line, "invalid tag"));
                }
                tokens.push(Token {
                    tok: Tok::Tag(
                        chars[start..i]
                            .iter()
                            .collect::<String>()
                            .to_ascii_lowercase(),
                    ),
                    line,
                });
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                let digits: String = chars[start..i].iter().collect();
                let mut value: u64 = digits
                    .parse()
                    .map_err(|_| Error::syntax(line, "number too large"))?;
                if let Some(&suffix) = chars.get(i) {
                    let factor = match suffix.to_ascii_uppercase() {
                        'K' => Some(1u64 << 10),
                        'M' => Some(1 << 20),
                        'G' => Some(1 << 30),
                        _ => None,
                    };
                    if let Some(factor) = factor {
                        value = value
                            .checked_mul(factor)
                            .ok_or_else(|| Error::syntax(line, "number too large"))?;
                        i += 1;
                    }
                }
                tokens.push(Token {
                    tok: Tok::Num(value),
                    line,
                });
            }
            c if is_ident_start(c) => {
                let start = i;
                while i < chars.len() && is_ident(chars[i]) {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                if word.eq_ignore_ascii_case("text") && chars.get(i) == Some(&':') {
                    let start_line = line;
                    i += 1;
                    // Rest of the line may hold whitespace and a comment.
                    while i < chars.len() && chars[i] != '\n' {
                        if chars[i] == '#' {
                            while i < chars.len() && chars[i] != '\n' {
                                i += 1;
                            }
                            break;
                        }
                        if !chars[i].is_whitespace() {
                            return Err(Error::syntax(line, "text: must be followed by a newline"));
                        }
                        i += 1;
                    }
                    if i >= chars.len() {
                        return Err(Error::syntax(start_line, "unterminated text: block"));
                    }
                    i += 1;
                    line += 1;
                    let mut out = String::new();
                    loop {
                        let mut end = i;
                        while end < chars.len() && chars[end] != '\n' {
                            end += 1;
                        }
                        let text: String = chars[i..end].iter().collect();
                        let text = text.strip_suffix('\r').unwrap_or(&text);
                        if end >= chars.len() && text != "." {
                            return Err(Error::syntax(start_line, "unterminated text: block"));
                        }
                        i = (end + 1).min(chars.len());
                        line += 1;
                        if text == "." {
                            break;
                        }
                        out.push_str(
                            text.strip_prefix('.')
                                .filter(|_| text.starts_with(".."))
                                .unwrap_or(text),
                        );
                        out.push_str("\r\n");
                    }
                    tokens.push(Token {
                        tok: Tok::Str(out),
                        line: start_line,
                    });
                } else {
                    tokens.push(Token {
                        tok: Tok::Ident(word.to_ascii_lowercase()),
                        line,
                    });
                }
            }
            other => {
                return Err(Error::syntax(
                    line,
                    format!("unexpected character {other:?}"),
                ));
            }
        }
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(src: &str) -> Vec<Tok> {
        lex(src).unwrap().into_iter().map(|t| t.tok).collect()
    }

    #[test]
    fn lexes_commands_tags_numbers_and_lists() {
        assert_eq!(
            toks("if size :over 100K { keep; } # c\n/* x */ fileinto [\"a\", \"b\"];"),
            vec![
                Tok::Ident("if".into()),
                Tok::Ident("size".into()),
                Tok::Tag("over".into()),
                Tok::Num(100 * 1024),
                Tok::LBrace,
                Tok::Ident("keep".into()),
                Tok::Semi,
                Tok::RBrace,
                Tok::Ident("fileinto".into()),
                Tok::LBracket,
                Tok::Str("a".into()),
                Tok::Comma,
                Tok::Str("b".into()),
                Tok::RBracket,
                Tok::Semi,
            ]
        );
    }

    #[test]
    fn strings_handle_escapes_and_multiline_text() {
        assert_eq!(toks(r#""a\"b\\c""#), vec![Tok::Str("a\"b\\c".into())]);
        assert_eq!(
            toks("vacation text:\nHello\n..dot\n.\n;"),
            vec![
                Tok::Ident("vacation".into()),
                Tok::Str("Hello\r\n.dot\r\n".into()),
                Tok::Semi
            ]
        );
    }

    #[test]
    fn identifiers_and_tags_are_case_insensitive() {
        assert_eq!(
            toks("IF :IS"),
            vec![Tok::Ident("if".into()), Tok::Tag("is".into())]
        );
    }

    #[test]
    fn reports_lexical_errors_with_lines() {
        assert!(lex("\"open").is_err());
        assert!(lex("/* open").is_err());
        assert!(lex("keep; @").unwrap_err().to_string().contains("line 1"));
        assert!(lex("text: x\nfoo\n.\n").is_err());
        assert!(lex("99999999999999999999").is_err());
    }
}
