//! rmail_common: shared utilities and types

// These data-access and protocol APIs deliberately mirror records/wire fields.
// Grouping them solely to satisfy lint thresholds would obscure their call sites.
#![allow(clippy::too_many_arguments, clippy::type_complexity)]

pub mod acl;
pub mod acme;
pub mod auth;
pub mod classifier_control;
pub mod classifier_models;
pub mod classifier_store;
pub mod compose;
pub mod compose_ai;
pub mod compose_html;
pub mod compose_store;
pub mod config;
pub mod dav;
pub mod db;
pub mod deliverability;
pub mod directory;
pub mod discovery;
pub mod dkim;
pub mod dmarc_reports;
pub mod dnsbl;
pub mod dnscheck;
pub mod domain;
pub mod etrn;
pub mod feedback;
pub mod greylist;
pub mod hold;
pub mod http;
pub mod imap_state;
pub mod jmap;
pub mod local_submit;
pub mod mail_auth;
pub mod maildir;
pub mod metrics;
pub mod mime;
pub mod mime_section;
pub mod net;
pub mod oauth;
pub mod oidc;
pub mod outbound;
pub mod proxy;
pub mod resources;
pub mod restart;
pub mod retention;
pub mod runtime;
pub mod scanner;
pub mod search_index;
pub mod settings;
pub mod sqlite_pool;
pub mod srs;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod throttle;
pub mod tls;
pub mod tlsrpt;
pub mod tracking;
pub mod transport;
pub mod two_factor;
pub mod urlauth;
pub mod websession;

#[doc(hidden)]
pub use serde_json;

pub fn hello() -> &'static str {
    "rmail_common"
}
