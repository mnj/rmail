//! A Sieve (RFC 5228) parser and interpreter with the `fileinto`, `envelope`,
//! `imap4flags`, `copy`, `body`, `relational` and `vacation` extensions.
//!
//! The crate does no I/O: [`Script::parse`] validates a script and
//! [`Script::run`] returns the actions a delivery agent should carry out.
//! Header values are not RFC 2047-decoded and the `body` test matches the
//! undecoded body text.

mod ast;
mod eval;
mod lexer;
mod message;
mod parser;
mod vacation;

use std::fmt;

pub use ast::{Cmd, Vacation};
pub use eval::Action;
pub use message::Message;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Syntax { line: usize, message: String },
    Limit(&'static str),
}

impl Error {
    pub(crate) fn syntax(line: usize, message: impl Into<String>) -> Self {
        Self::Syntax {
            line,
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { line, message } => write!(f, "line {line}: {message}"),
            Self::Limit(what) => write!(f, "script limit exceeded: {what}"),
        }
    }
}

impl std::error::Error for Error {}

/// A parsed, validated script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    pub(crate) commands: Vec<Cmd>,
}

impl Script {
    pub fn parse(source: &str) -> Result<Self, Error> {
        parser::parse(source)
    }

    /// Run against `message`. On error (limits exceeded) the caller should
    /// fall back to delivering to the inbox.
    pub fn run(&self, message: &Message<'_>) -> Result<Vec<Action>, Error> {
        eval::run(self, message)
    }
}

#[cfg(test)]
mod tests;
