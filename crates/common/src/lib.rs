//! rmail_common: shared utilities and types

pub mod auth;
pub mod config;
pub mod db;
pub mod imap_state;
pub mod mail_auth;
pub mod maildir;
pub mod metrics;
pub mod outbound;
pub mod runtime;
pub mod scanner;
pub mod transport;

pub fn hello() -> &'static str {
    "rmail_common"
}
