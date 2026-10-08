//! rmail_common: shared utilities and types

// These data-access and protocol APIs deliberately mirror records/wire fields.
// Grouping them solely to satisfy lint thresholds would obscure their call sites.
#![allow(clippy::too_many_arguments, clippy::type_complexity)]

pub mod acme;
pub mod auth;
pub mod classifier_control;
pub mod classifier_models;
pub mod classifier_store;
pub mod compose;
pub mod config;
pub mod db;
pub mod discovery;
pub mod dnsbl;
pub mod domain;
pub mod greylist;
pub mod http;
pub mod imap_state;
pub mod mail_auth;
pub mod maildir;
pub mod metrics;
pub mod mime;
pub mod net;
pub mod oauth;
pub mod outbound;
pub mod proxy;
pub mod restart;
pub mod runtime;
pub mod scanner;
pub mod search_index;
pub mod settings;
pub mod sqlite_pool;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod throttle;
pub mod tls;
pub mod tlsrpt;
pub mod tracking;
pub mod transport;
pub mod websession;

#[doc(hidden)]
pub use serde_json;

pub fn hello() -> &'static str {
    "rmail_common"
}
