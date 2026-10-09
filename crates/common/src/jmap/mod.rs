//! JMAP (RFC 8620, RFC 8621) support shared by the services: the change log
//! and email index in each account's state database, and the MIME and
//! header parsing JMAP's Email objects need. The HTTP API lives in webmail.

pub mod address;
pub mod mime;
pub mod store;
