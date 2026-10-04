//! Parses Sieve source into a typed [`Script`], checking `require`.

use std::collections::HashSet;

use crate::ast::*;
use crate::lexer::{Tok, Token, lex};
use crate::{Error, Script};

const MAX_DEPTH: usize = 32;
const MAX_SCRIPT_BYTES: usize = 1 << 20;

const EXTENSIONS: &[&str] = &[
    "fileinto",
    "envelope",
    "imap4flags",
    "copy",
    "body",
    "relational",
    "vacation",
    "comparator-i;ascii-casemap",
    "comparator-i;octet",
    "comparator-i;ascii-numeric",
];

#[derive(Debug, Clone)]
enum Arg {
    Tag(String),
    Str(String),
    List(Vec<String>),
    Num(u64),
}

#[derive(Debug)]
struct Node {
    name: String,
    args: Vec<Arg>,
    tests: Vec<Node>,
    block: Option<Vec<Node>>,
    line: usize,
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn line(&self) -> usize {
        self.peek()
            .or(self.tokens.last())
            .map_or(1, |token| token.line)
    }

    fn next_is(&self, tok: &Tok) -> bool {
        self.peek().is_some_and(|token| &token.tok == tok)
    }

    fn expect(&mut self, tok: Tok, what: &str) -> Result<(), Error> {
        if self.next_is(&tok) {
            self.pos += 1;
            Ok(())
        } else {
            Err(Error::syntax(self.line(), format!("expected {what}")))
        }
    }

    fn commands(&mut self, depth: usize, in_block: bool) -> Result<Vec<Node>, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::syntax(self.line(), "blocks nested too deeply"));
        }
        let mut out = Vec::new();
        loop {
            match self.peek().map(|t| &t.tok) {
                None if in_block => return Err(Error::syntax(self.line(), "expected }")),
                None => return Ok(out),
                Some(Tok::RBrace) if in_block => return Ok(out),
                Some(Tok::Ident(_)) => out.push(self.command(depth)?),
                Some(_) => return Err(Error::syntax(self.line(), "expected a command")),
            }
        }
    }

    fn command(&mut self, depth: usize) -> Result<Node, Error> {
        let line = self.line();
        let Some(Tok::Ident(name)) = self.peek().map(|t| t.tok.clone()) else {
            return Err(Error::syntax(line, "expected a command"));
        };
        self.pos += 1;
        let args = self.args()?;
        let tests = self.tests(depth)?;
        if self.next_is(&Tok::LBrace) {
            self.pos += 1;
            let block = self.commands(depth + 1, true)?;
            self.expect(Tok::RBrace, "}")?;
            Ok(Node {
                name,
                args,
                tests,
                block: Some(block),
                line,
            })
        } else {
            self.expect(Tok::Semi, ";")?;
            Ok(Node {
                name,
                args,
                tests,
                block: None,
                line,
            })
        }
    }

    fn args(&mut self) -> Result<Vec<Arg>, Error> {
        let mut args = Vec::new();
        loop {
            match self.peek().map(|t| t.tok.clone()) {
                Some(Tok::Tag(tag)) => {
                    self.pos += 1;
                    args.push(Arg::Tag(tag));
                }
                Some(Tok::Str(s)) => {
                    self.pos += 1;
                    args.push(Arg::Str(s));
                }
                Some(Tok::Num(n)) => {
                    self.pos += 1;
                    args.push(Arg::Num(n));
                }
                Some(Tok::LBracket) => {
                    self.pos += 1;
                    let mut items = Vec::new();
                    loop {
                        match self.peek().map(|t| t.tok.clone()) {
                            Some(Tok::Str(s)) => {
                                self.pos += 1;
                                items.push(s);
                            }
                            _ => return Err(Error::syntax(self.line(), "expected a string")),
                        }
                        if self.next_is(&Tok::Comma) {
                            self.pos += 1;
                        } else {
                            break;
                        }
                    }
                    self.expect(Tok::RBracket, "]")?;
                    args.push(Arg::List(items));
                }
                _ => return Ok(args),
            }
        }
    }

    /// Zero tests, one test, or a parenthesised list.
    fn tests(&mut self, depth: usize) -> Result<Vec<Node>, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::syntax(self.line(), "tests nested too deeply"));
        }
        match self.peek().map(|t| &t.tok) {
            Some(Tok::Ident(_)) => Ok(vec![self.test(depth + 1)?]),
            Some(Tok::LParen) => {
                self.pos += 1;
                let mut tests = vec![self.test(depth + 1)?];
                while self.next_is(&Tok::Comma) {
                    self.pos += 1;
                    tests.push(self.test(depth + 1)?);
                }
                self.expect(Tok::RParen, ")")?;
                Ok(tests)
            }
            _ => Ok(Vec::new()),
        }
    }

    fn test(&mut self, depth: usize) -> Result<Node, Error> {
        let line = self.line();
        let Some(Tok::Ident(name)) = self.peek().map(|t| t.tok.clone()) else {
            return Err(Error::syntax(line, "expected a test"));
        };
        self.pos += 1;
        let args = self.args()?;
        let tests = self.tests(depth)?;
        Ok(Node {
            name,
            args,
            tests,
            block: None,
            line,
        })
    }
}

/// Tags that consume the next argument.
fn takes_value(tag: &str) -> bool {
    matches!(
        tag,
        "comparator"
            | "count"
            | "value"
            | "days"
            | "subject"
            | "from"
            | "addresses"
            | "handle"
            | "flags"
    )
}

/// Tags and positional arguments of one command or test.
struct Parsed {
    tags: Vec<(String, Option<Arg>)>,
    pos: Vec<Arg>,
}

fn split_args(node: &Node) -> Result<Parsed, Error> {
    let mut tags = Vec::new();
    let mut pos = Vec::new();
    let mut iter = node.args.iter().cloned().peekable();
    while let Some(arg) = iter.next() {
        match arg {
            Arg::Tag(tag) if takes_value(&tag) => {
                let value = iter
                    .next()
                    .ok_or_else(|| Error::syntax(node.line, format!(":{tag} needs a value")))?;
                tags.push((tag, Some(value)));
            }
            Arg::Tag(tag) => tags.push((tag, None)),
            other => pos.push(other),
        }
    }
    Ok(Parsed { tags, pos })
}

fn strings(arg: &Arg, line: usize, what: &str) -> Result<Vec<String>, Error> {
    match arg {
        Arg::Str(s) => Ok(vec![s.clone()]),
        Arg::List(items) => Ok(items.clone()),
        _ => Err(Error::syntax(
            line,
            format!("{what} must be a string or string list"),
        )),
    }
}

fn one_string(arg: &Arg, line: usize, what: &str) -> Result<String, Error> {
    match arg {
        Arg::Str(s) => Ok(s.clone()),
        _ => Err(Error::syntax(line, format!("{what} must be a string"))),
    }
}

struct Compiler {
    ext: HashSet<String>,
}

impl Compiler {
    fn need(&self, ext: &str, line: usize) -> Result<(), Error> {
        if self.ext.contains(ext) {
            Ok(())
        } else {
            Err(Error::syntax(
                line,
                format!("\"{ext}\" requires `require \"{ext}\";`"),
            ))
        }
    }

    fn matcher(
        &self,
        parsed: &Parsed,
        line: usize,
        address: bool,
    ) -> Result<(Match, Option<AddrPart>), Error> {
        let mut kind = MatchKind::Is;
        let mut cmp = Comparator::AsciiCasemap;
        let mut part = None;
        let mut kind_set = false;
        for (tag, value) in &parsed.tags {
            let mut set_kind = |new: MatchKind| {
                if kind_set {
                    return Err(Error::syntax(line, "only one match type is allowed"));
                }
                kind_set = true;
                kind = new;
                Ok(())
            };
            match tag.as_str() {
                "is" => set_kind(MatchKind::Is)?,
                "contains" => set_kind(MatchKind::Contains)?,
                "matches" => set_kind(MatchKind::Matches)?,
                "count" | "value" => {
                    self.need("relational", line)?;
                    let rel =
                        match one_string(value.as_ref().unwrap(), line, "relational operator")?
                            .to_ascii_lowercase()
                            .as_str()
                        {
                            "gt" => Rel::Gt,
                            "ge" => Rel::Ge,
                            "lt" => Rel::Lt,
                            "le" => Rel::Le,
                            "eq" => Rel::Eq,
                            "ne" => Rel::Ne,
                            other => {
                                return Err(Error::syntax(
                                    line,
                                    format!("unknown relational operator {other:?}"),
                                ));
                            }
                        };
                    set_kind(if tag == "count" {
                        MatchKind::Count(rel)
                    } else {
                        MatchKind::Value(rel)
                    })?;
                }
                "comparator" => {
                    let name = one_string(value.as_ref().unwrap(), line, "comparator")?
                        .to_ascii_lowercase();
                    let ext = format!("comparator-{name}");
                    cmp = match name.as_str() {
                        "i;ascii-casemap" => Comparator::AsciiCasemap,
                        "i;octet" => Comparator::Octet,
                        "i;ascii-numeric" => Comparator::AsciiNumeric,
                        _ => {
                            return Err(Error::syntax(
                                line,
                                format!("unknown comparator {name:?}"),
                            ));
                        }
                    };
                    // i;ascii-casemap and i;octet are always available; others need require.
                    if name == "i;ascii-numeric" {
                        self.need(&ext, line)?;
                    }
                }
                "all" if address => part = Some(AddrPart::All),
                "localpart" if address => part = Some(AddrPart::LocalPart),
                "domain" if address => part = Some(AddrPart::Domain),
                other => return Err(Error::syntax(line, format!("unknown tag :{other}"))),
            }
        }
        Ok((Match { kind, cmp }, part))
    }

    fn test(&self, node: &Node) -> Result<Test, Error> {
        let line = node.line;
        let parsed = split_args(node)?;
        let arity = |n: usize| -> Result<(), Error> {
            if parsed.pos.len() == n {
                Ok(())
            } else {
                Err(Error::syntax(
                    line,
                    format!("`{}` needs {n} argument(s)", node.name),
                ))
            }
        };
        let no_tests = || -> Result<(), Error> {
            if node.tests.is_empty() {
                Ok(())
            } else {
                Err(Error::syntax(
                    line,
                    format!("`{}` takes no nested tests", node.name),
                ))
            }
        };
        match node.name.as_str() {
            "true" | "false" => {
                arity(0)?;
                no_tests()?;
                Ok(if node.name == "true" {
                    Test::True
                } else {
                    Test::False
                })
            }
            "not" => {
                arity(0)?;
                match node.tests.as_slice() {
                    [inner] => Ok(Test::Not(Box::new(self.test(inner)?))),
                    _ => Err(Error::syntax(line, "`not` needs exactly one test")),
                }
            }
            "allof" | "anyof" => {
                arity(0)?;
                if node.tests.is_empty() {
                    return Err(Error::syntax(
                        line,
                        format!("`{}` needs at least one test", node.name),
                    ));
                }
                let tests = node
                    .tests
                    .iter()
                    .map(|t| self.test(t))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(if node.name == "allof" {
                    Test::AllOf(tests)
                } else {
                    Test::AnyOf(tests)
                })
            }
            "exists" => {
                arity(1)?;
                no_tests()?;
                Ok(Test::Exists(strings(&parsed.pos[0], line, "header names")?))
            }
            "size" => {
                no_tests()?;
                arity(1)?;
                let over = match parsed.tags.as_slice() {
                    [(tag, None)] if tag == "over" => true,
                    [(tag, None)] if tag == "under" => false,
                    _ => return Err(Error::syntax(line, "`size` needs :over or :under")),
                };
                let Arg::Num(limit) = parsed.pos[0] else {
                    return Err(Error::syntax(line, "`size` needs a number"));
                };
                Ok(Test::Size { over, limit })
            }
            "header" => {
                no_tests()?;
                arity(2)?;
                let (m, _) = self.matcher(&parsed, line, false)?;
                Ok(Test::Header {
                    names: strings(&parsed.pos[0], line, "header names")?,
                    keys: strings(&parsed.pos[1], line, "keys")?,
                    m,
                })
            }
            "address" | "envelope" => {
                no_tests()?;
                if node.name == "envelope" {
                    self.need("envelope", line)?;
                }
                arity(2)?;
                let (m, part) = self.matcher(&parsed, line, true)?;
                let names = strings(&parsed.pos[0], line, "names")?;
                let keys = strings(&parsed.pos[1], line, "keys")?;
                let part = part.unwrap_or(AddrPart::All);
                if node.name == "envelope" {
                    if names
                        .iter()
                        .any(|n| !n.eq_ignore_ascii_case("from") && !n.eq_ignore_ascii_case("to"))
                    {
                        return Err(Error::syntax(
                            line,
                            "envelope supports only \"from\" and \"to\"",
                        ));
                    }
                    Ok(Test::Envelope {
                        part,
                        names,
                        keys,
                        m,
                    })
                } else {
                    Ok(Test::Address {
                        part,
                        names,
                        keys,
                        m,
                    })
                }
            }
            "body" => {
                no_tests()?;
                self.need("body", line)?;
                // Body transform tags (:raw, :text) are accepted; the interpreter
                // matches the undecoded body text.
                let filtered = Parsed {
                    tags: parsed
                        .tags
                        .iter()
                        .filter(|(tag, _)| !matches!(tag.as_str(), "raw" | "text"))
                        .cloned()
                        .collect(),
                    pos: parsed.pos.clone(),
                };
                arity(1)?;
                let (m, _) = self.matcher(&filtered, line, false)?;
                Ok(Test::Body {
                    keys: strings(&parsed.pos[0], line, "keys")?,
                    m,
                })
            }
            other => Err(Error::syntax(line, format!("unknown test `{other}`"))),
        }
    }

    fn flags_tag(&self, parsed: &Parsed, line: usize) -> Result<Option<Vec<String>>, Error> {
        for (tag, value) in &parsed.tags {
            if tag == "flags" {
                self.need("imap4flags", line)?;
                return Ok(Some(strings(value.as_ref().unwrap(), line, ":flags")?));
            }
        }
        Ok(None)
    }

    fn block(&self, nodes: &[Node], top_level: bool) -> Result<Vec<Cmd>, Error> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < nodes.len() {
            let node = &nodes[i];
            i += 1;
            let line = node.line;
            match node.name.as_str() {
                "require" => {
                    if !top_level {
                        return Err(Error::syntax(
                            line,
                            "`require` is only allowed at the top level",
                        ));
                    }
                }
                "if" => {
                    let cond = self.test(single_test(node)?)?;
                    let then = self.block(block_of(node)?, false)?;
                    // Gather `elsif`/`else` into nested otherwise-branches.
                    let mut tail: Vec<(Option<Test>, Vec<Cmd>)> = Vec::new();
                    while i < nodes.len() && matches!(nodes[i].name.as_str(), "elsif" | "else") {
                        let next = &nodes[i];
                        i += 1;
                        let body = self.block(block_of(next)?, false)?;
                        if next.name == "elsif" {
                            tail.push((Some(self.test(single_test(next)?)?), body));
                        } else {
                            if !next.tests.is_empty() || !next.args.is_empty() {
                                return Err(Error::syntax(next.line, "`else` takes no arguments"));
                            }
                            tail.push((None, body));
                            break;
                        }
                    }
                    let mut otherwise = Vec::new();
                    for (cond, body) in tail.into_iter().rev() {
                        otherwise = match cond {
                            Some(cond) => vec![Cmd::If {
                                cond,
                                then: body,
                                otherwise,
                            }],
                            None => body,
                        };
                    }
                    out.push(Cmd::If {
                        cond,
                        then,
                        otherwise,
                    });
                }
                "elsif" | "else" => {
                    return Err(Error::syntax(
                        line,
                        format!("`{}` without a preceding `if`", node.name),
                    ));
                }
                _ => out.push(self.action(node)?),
            }
        }
        Ok(out)
    }

    fn action(&self, node: &Node) -> Result<Cmd, Error> {
        let line = node.line;
        if node.block.is_some() || !node.tests.is_empty() {
            return Err(Error::syntax(
                line,
                format!("`{}` takes no block or tests", node.name),
            ));
        }
        let parsed = split_args(node)?;
        let has_tag = |name: &str| parsed.tags.iter().any(|(t, _)| t == name);
        let only_tags = |allowed: &[&str]| -> Result<(), Error> {
            match parsed
                .tags
                .iter()
                .find(|(t, _)| !allowed.contains(&t.as_str()))
            {
                Some((t, _)) => Err(Error::syntax(line, format!("unknown tag :{t}"))),
                None => Ok(()),
            }
        };
        let positional = |n: usize| -> Result<(), Error> {
            if parsed.pos.len() == n {
                Ok(())
            } else {
                Err(Error::syntax(
                    line,
                    format!("`{}` needs {n} argument(s)", node.name),
                ))
            }
        };
        match node.name.as_str() {
            "keep" => {
                only_tags(&["flags"])?;
                positional(0)?;
                Ok(Cmd::Keep {
                    flags: self.flags_tag(&parsed, line)?,
                })
            }
            "discard" => {
                only_tags(&[])?;
                positional(0)?;
                Ok(Cmd::Discard)
            }
            "stop" => {
                only_tags(&[])?;
                positional(0)?;
                Ok(Cmd::Stop)
            }
            "fileinto" => {
                self.need("fileinto", line)?;
                only_tags(&["copy", "flags"])?;
                if has_tag("copy") {
                    self.need("copy", line)?;
                }
                positional(1)?;
                Ok(Cmd::FileInto {
                    folder: one_string(&parsed.pos[0], line, "folder")?,
                    copy: has_tag("copy"),
                    flags: self.flags_tag(&parsed, line)?,
                })
            }
            "redirect" => {
                only_tags(&["copy"])?;
                if has_tag("copy") {
                    self.need("copy", line)?;
                }
                positional(1)?;
                let address = one_string(&parsed.pos[0], line, "address")?;
                if !address.contains('@') || address.contains(['\r', '\n', ' ', '<', '>']) {
                    return Err(Error::syntax(line, "redirect needs a plain email address"));
                }
                Ok(Cmd::Redirect {
                    address,
                    copy: has_tag("copy"),
                })
            }
            "setflag" | "addflag" | "removeflag" => {
                self.need("imap4flags", line)?;
                only_tags(&[])?;
                positional(1)?;
                let flags = strings(&parsed.pos[0], line, "flags")?;
                Ok(match node.name.as_str() {
                    "setflag" => Cmd::SetFlag(flags),
                    "addflag" => Cmd::AddFlag(flags),
                    _ => Cmd::RemoveFlag(flags),
                })
            }
            "vacation" => {
                self.need("vacation", line)?;
                only_tags(&["days", "subject", "from", "addresses", "mime", "handle"])?;
                positional(1)?;
                let mut vacation = Vacation {
                    reason: one_string(&parsed.pos[0], line, "reason")?,
                    subject: None,
                    from: None,
                    days: 7,
                    addresses: Vec::new(),
                    mime: has_tag("mime"),
                    handle: None,
                };
                for (tag, value) in &parsed.tags {
                    let Some(value) = value else { continue };
                    match tag.as_str() {
                        "days" => {
                            let Arg::Num(days) = value else {
                                return Err(Error::syntax(line, ":days needs a number"));
                            };
                            vacation.days = (*days).clamp(1, 365) as u32;
                        }
                        "subject" => vacation.subject = Some(one_string(value, line, ":subject")?),
                        "from" => vacation.from = Some(one_string(value, line, ":from")?),
                        "handle" => vacation.handle = Some(one_string(value, line, ":handle")?),
                        "addresses" => vacation.addresses = strings(value, line, ":addresses")?,
                        _ => {}
                    }
                }
                Ok(Cmd::Vacation(vacation))
            }
            other => Err(Error::syntax(line, format!("unknown command `{other}`"))),
        }
    }
}

fn single_test(node: &Node) -> Result<&Node, Error> {
    match node.tests.as_slice() {
        [test] if node.args.is_empty() => Ok(test),
        _ => Err(Error::syntax(
            node.line,
            format!("`{}` needs exactly one test", node.name),
        )),
    }
}

fn block_of(node: &Node) -> Result<&[Node], Error> {
    node.block
        .as_deref()
        .ok_or_else(|| Error::syntax(node.line, format!("`{}` needs a block", node.name)))
}

pub(crate) fn parse(source: &str) -> Result<Script, Error> {
    if source.len() > MAX_SCRIPT_BYTES {
        return Err(Error::syntax(1, "script is too large"));
    }
    let mut parser = Parser {
        tokens: lex(source)?,
        pos: 0,
    };
    let nodes = parser.commands(0, false)?;

    // `require` may only be preceded by other `require` commands.
    let mut ext = HashSet::new();
    let mut seen_other = false;
    for node in &nodes {
        if node.name == "require" {
            if seen_other {
                return Err(Error::syntax(
                    node.line,
                    "`require` must come before other commands",
                ));
            }
            let parsed = split_args(node)?;
            if !parsed.tags.is_empty()
                || parsed.pos.len() != 1
                || node.block.is_some()
                || !node.tests.is_empty()
            {
                return Err(Error::syntax(
                    node.line,
                    "`require` needs one string or string list",
                ));
            }
            for name in strings(&parsed.pos[0], node.line, "require")? {
                let name = name.to_ascii_lowercase();
                if !EXTENSIONS.contains(&name.as_str()) {
                    return Err(Error::syntax(
                        node.line,
                        format!("unsupported extension \"{name}\""),
                    ));
                }
                ext.insert(name);
            }
        } else {
            seen_other = true;
        }
    }
    let compiler = Compiler { ext };
    let commands = compiler.block(&nodes, true)?;
    Ok(Script { commands })
}
