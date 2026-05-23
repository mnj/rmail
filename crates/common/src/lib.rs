//! rmail_common: shared utilities and types

pub mod config;
pub mod maildir;
pub mod auth;
pub mod db;

pub fn hello() -> &'static str {
    "rmail_common"
}
