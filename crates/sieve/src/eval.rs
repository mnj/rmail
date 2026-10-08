//! Runs a compiled script against a message and collects the resulting actions.

use std::cmp::Ordering;

use crate::ast::*;
use crate::message::{Message, parse_addresses, split_address};
use crate::{Error, Script};

const MAX_ACTIONS: usize = 64;
const MAX_REDIRECTS: usize = 4;

/// What the delivery agent should do. `Keep` is always present when the
/// message should land in the inbox, including the implicit keep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Keep { flags: Vec<String> },
    FileInto { folder: String, flags: Vec<String> },
    Redirect { address: String },
    Discard,
    Vacation(Vacation),
}

struct Run<'a> {
    msg: &'a Message<'a>,
    flags: Vec<String>,
    actions: Vec<Action>,
    implicit_keep: bool,
    redirects: usize,
    stopped: bool,
}

pub(crate) fn run(script: &Script, msg: &Message<'_>) -> Result<Vec<Action>, Error> {
    let mut state = Run {
        msg,
        flags: Vec::new(),
        actions: Vec::new(),
        implicit_keep: true,
        redirects: 0,
        stopped: false,
    };
    state.exec(&script.commands)?;
    if state.implicit_keep {
        let flags = state.flags.clone();
        state.actions.push(Action::Keep { flags });
    }
    Ok(state.actions)
}

fn normalize(flags: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for flag in flags.iter().flat_map(|f| f.split_whitespace()) {
        if !out.iter().any(|f| f.eq_ignore_ascii_case(flag)) {
            out.push(flag.to_string());
        }
    }
    out
}

impl Run<'_> {
    fn push(&mut self, action: Action) -> Result<(), Error> {
        if self.actions.len() >= MAX_ACTIONS {
            return Err(Error::Limit("too many actions"));
        }
        self.actions.push(action);
        Ok(())
    }

    fn exec(&mut self, commands: &[Cmd]) -> Result<(), Error> {
        for command in commands {
            if self.stopped {
                return Ok(());
            }
            match command {
                Cmd::If {
                    cond,
                    then,
                    otherwise,
                } => {
                    if self.test(cond) {
                        self.exec(then)?;
                    } else {
                        self.exec(otherwise)?;
                    }
                }
                Cmd::Keep { flags } => {
                    let flags = flags
                        .as_deref()
                        .map_or_else(|| self.flags.clone(), normalize);
                    self.push(Action::Keep { flags })?;
                    self.implicit_keep = false;
                }
                Cmd::Discard => {
                    self.push(Action::Discard)?;
                    self.implicit_keep = false;
                }
                Cmd::Stop => self.stopped = true,
                Cmd::FileInto {
                    folder,
                    copy,
                    flags,
                } => {
                    let flags = flags
                        .as_deref()
                        .map_or_else(|| self.flags.clone(), normalize);
                    let duplicate = self
                        .actions
                        .iter()
                        .any(|a| matches!(a, Action::FileInto { folder: f, .. } if f == folder));
                    if !duplicate {
                        self.push(Action::FileInto {
                            folder: folder.clone(),
                            flags,
                        })?;
                    }
                    if !copy {
                        self.implicit_keep = false;
                    }
                }
                Cmd::Redirect { address, copy } => {
                    self.redirects += 1;
                    if self.redirects > MAX_REDIRECTS {
                        return Err(Error::Limit("too many redirects"));
                    }
                    let duplicate = self.actions.iter().any(|a| {
                        matches!(a, Action::Redirect { address: x } if x.eq_ignore_ascii_case(address))
                    });
                    if !duplicate {
                        self.push(Action::Redirect {
                            address: address.clone(),
                        })?;
                    }
                    if !copy {
                        self.implicit_keep = false;
                    }
                }
                Cmd::SetFlag(flags) => self.flags = normalize(flags),
                Cmd::AddFlag(flags) => {
                    let mut all = self.flags.clone();
                    all.extend(flags.iter().cloned());
                    self.flags = normalize(&all);
                }
                Cmd::RemoveFlag(flags) => {
                    let remove = normalize(flags);
                    self.flags
                        .retain(|f| !remove.iter().any(|r| r.eq_ignore_ascii_case(f)));
                }
                Cmd::Vacation(vacation) => self.push(Action::Vacation(vacation.clone()))?,
            }
        }
        Ok(())
    }

    fn test(&self, test: &Test) -> bool {
        match test {
            Test::True => true,
            Test::False => false,
            Test::Not(inner) => !self.test(inner),
            Test::AllOf(tests) => tests.iter().all(|t| self.test(t)),
            Test::AnyOf(tests) => tests.iter().any(|t| self.test(t)),
            Test::Exists(names) => names.iter().all(|n| self.msg.has_header(n)),
            Test::Size { over, limit } => {
                let size = self.msg.size();
                if *over { size > *limit } else { size < *limit }
            }
            Test::Header { names, keys, m } => {
                let values: Vec<String> = names
                    .iter()
                    .flat_map(|n| self.msg.header_values(n))
                    .map(str::to_string)
                    .collect();
                matches_any(m, &values, keys)
            }
            Test::Address {
                part,
                names,
                keys,
                m,
            } => {
                let values: Vec<String> = names
                    .iter()
                    .flat_map(|n| self.msg.header_values(n))
                    .flat_map(parse_addresses)
                    .map(|a| part_of(*part, &a))
                    .collect();
                matches_any(m, &values, keys)
            }
            Test::Envelope {
                part,
                names,
                keys,
                m,
            } => {
                let values: Vec<String> = names
                    .iter()
                    .map(|n| {
                        let address = if n.eq_ignore_ascii_case("from") {
                            &self.msg.envelope_from
                        } else {
                            &self.msg.envelope_to
                        };
                        part_of(*part, address)
                    })
                    .collect();
                matches_any(m, &values, keys)
            }
            Test::Body { keys, m } => matches_any(m, &[self.msg.body_text()], keys),
        }
    }
}

fn part_of(part: AddrPart, address: &str) -> String {
    let (local, domain) = split_address(address);
    match part {
        AddrPart::All => address.to_string(),
        AddrPart::LocalPart => local.to_string(),
        AddrPart::Domain => domain.to_string(),
    }
}

fn matches_any(m: &Match, values: &[String], keys: &[String]) -> bool {
    match m.kind {
        MatchKind::Count(rel) => {
            let count = values.len() as u128;
            keys.iter()
                .any(|key| numeric(key).is_some_and(|limit| rel_holds(rel, count.cmp(&limit))))
        }
        MatchKind::Value(rel) => values
            .iter()
            .any(|v| keys.iter().any(|k| rel_holds(rel, order(m.cmp, v, k)))),
        kind => values
            .iter()
            .any(|v| keys.iter().any(|k| string_match(kind, m.cmp, v, k))),
    }
}

fn rel_holds(rel: Rel, ordering: Ordering) -> bool {
    match rel {
        Rel::Gt => ordering == Ordering::Greater,
        Rel::Ge => ordering != Ordering::Less,
        Rel::Lt => ordering == Ordering::Less,
        Rel::Le => ordering != Ordering::Greater,
        Rel::Eq => ordering == Ordering::Equal,
        Rel::Ne => ordering != Ordering::Equal,
    }
}

/// Leading decimal digits, per i;ascii-numeric. `None` means no number.
fn numeric(s: &str) -> Option<u128> {
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        None
    } else {
        Some(digits.parse().unwrap_or(u128::MAX))
    }
}

fn order(cmp: Comparator, a: &str, b: &str) -> Ordering {
    match cmp {
        Comparator::Octet => a.cmp(b),
        Comparator::AsciiCasemap => a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase()),
        // Strings without a number sort after every number and equal each other.
        Comparator::AsciiNumeric => match (numeric(a), numeric(b)) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        },
    }
}

fn string_match(kind: MatchKind, cmp: Comparator, value: &str, key: &str) -> bool {
    let fold = |s: &str| -> String {
        if cmp == Comparator::Octet {
            s.to_string()
        } else {
            s.to_ascii_lowercase()
        }
    };
    match kind {
        MatchKind::Is => order(cmp, value, key) == Ordering::Equal,
        MatchKind::Contains => fold(value).contains(&fold(key)),
        MatchKind::Matches => glob(&fold(value), &fold(key)),
        MatchKind::Count(_) | MatchKind::Value(_) => false,
    }
}

/// `*` matches any run, `?` any one character, `\x` a literal `x`.
fn glob(text: &str, pattern: &str) -> bool {
    enum P {
        Star,
        Any,
        Lit(char),
    }
    let mut tokens = Vec::new();
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        tokens.push(match c {
            '*' => P::Star,
            '?' => P::Any,
            '\\' => P::Lit(chars.next().unwrap_or('\\')),
            c => P::Lit(c),
        });
    }
    let text: Vec<char> = text.chars().collect();
    let (mut t, mut p) = (0, 0);
    let (mut star_p, mut star_t) = (None, 0);
    while t < text.len() {
        match tokens.get(p) {
            Some(P::Star) => {
                star_p = Some(p);
                star_t = t;
                p += 1;
            }
            Some(P::Any) => {
                t += 1;
                p += 1;
            }
            Some(P::Lit(c)) if *c == text[t] => {
                t += 1;
                p += 1;
            }
            _ => match star_p {
                Some(sp) => {
                    star_t += 1;
                    t = star_t;
                    p = sp + 1;
                }
                None => return false,
            },
        }
    }
    tokens[p..].iter().all(|tok| matches!(tok, P::Star))
}

#[cfg(test)]
mod tests {
    use super::glob;

    #[test]
    fn glob_semantics() {
        assert!(glob("hello", "h*o"));
        assert!(glob("hello", "*"));
        assert!(glob("", "*"));
        assert!(glob("hello", "he?lo"));
        assert!(!glob("hello", "he?o"));
        assert!(glob("a*b", "a\\*b"));
        assert!(!glob("axb", "a\\*b"));
        assert!(glob("abcabc", "*abc"));
        assert!(!glob("abcab", "*abc"));
        assert!(glob("x", "x**"));
    }
}
