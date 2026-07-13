//! rmail_common: shared utilities and types

// These data-access and protocol APIs deliberately mirror records/wire fields.
// Grouping them solely to satisfy lint thresholds would obscure their call sites.
#![allow(clippy::too_many_arguments, clippy::type_complexity)]

pub mod auth;
pub mod config;
pub mod db;
pub mod domain;
pub mod imap_state;
pub mod mail_auth;
pub mod maildir;
pub mod metrics;
pub mod net;
pub mod oauth;
pub mod outbound;
pub mod runtime;
pub mod scanner;
pub mod sqlite_pool;
pub mod tls;
pub mod tracking;
pub mod transport;

pub fn hello() -> &'static str {
    "rmail_common"
}
