//! rmail_common: shared utilities and types

pub mod config;
pub mod maildir;
pub mod outbound;
pub mod auth;
pub mod db;
pub mod metrics;

pub fn hello() -> &'static str {
    "rmail_common"
}
