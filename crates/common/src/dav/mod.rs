//! CalDAV (RFC 4791) and CardDAV (RFC 6352) storage shared by the services:
//! iCalendar/vCard reading and the calendars and address books kept in
//! each account's state database. The HTTP side lives in webmail.

pub mod store;
pub mod text;
