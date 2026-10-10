//! CalDAV (RFC 4791) and CardDAV (RFC 6352) storage shared by the services:
//! iCalendar/vCard reading and the calendars and address books kept in
//! each account's state database, the scheduling messages (iTIP, RFC 5546)
//! CalDAV scheduling exchanges, also when they arrive by email (iMIP,
//! RFC 6047), and the grants that share collections between accounts. The
//! HTTP side lives in webmail.

pub mod imip;
pub mod itip;
pub mod recur;
pub mod share;
pub mod store;
pub mod text;
