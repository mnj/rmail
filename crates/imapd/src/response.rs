use std::net::SocketAddr;

use crate::auth;

pub(crate) fn log_imap_response(peer: Option<SocketAddr>, tag: &str, cmd: &str, response: &str) {
    let escaped = response.replace("\r", "\\r").replace("\n", "\\n");
    println!(
        "IMAP response peer={:?} tag={} cmd={} bytes={} data={:?}",
        peer,
        tag,
        cmd,
        response.len(),
        escaped
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapabilityPhase {
    NotAuthenticatedPlain,
    NotAuthenticatedTls,
    Authenticated,
    Selected,
}

pub(crate) fn capability_tokens(phase: CapabilityPhase, starttls_available: bool) -> String {
    let mut caps = vec!["IMAP4rev1", "ID", "ENABLE", "IDLE", "SASL-IR", "LITERAL-"];
    match phase {
        CapabilityPhase::NotAuthenticatedPlain => {
            caps.push("LOGINDISABLED");
            if starttls_available {
                caps.push("STARTTLS");
            }
            caps.extend(
                auth::advertised_sasl_mechanisms(false, false)
                    .map(|mechanism| mechanism.capability),
            );
        }
        CapabilityPhase::NotAuthenticatedTls => {
            caps.extend(
                auth::advertised_sasl_mechanisms(true, starttls_available)
                    .map(|mechanism| mechanism.capability),
            );
        }
        CapabilityPhase::Authenticated | CapabilityPhase::Selected => caps.extend([
            "UIDPLUS",
            "NAMESPACE",
            "SPECIAL-USE",
            "LIST-EXTENDED",
            "CHILDREN",
            "LIST-STATUS",
            "CONDSTORE",
            "QRESYNC",
            "ESEARCH",
            "SEARCHRES",
            "SORT",
            "THREAD=ORDEREDSUBJECT",
            "THREAD=REFERENCES",
            "WITHIN",
            "STATUS=SIZE",
            "SAVEDATE",
            "BINARY",
            "UTF8=ACCEPT",
            "COMPRESS=DEFLATE",
            "MOVE",
            "UNSELECT",
        ]),
    }
    caps.join(" ")
}

pub(crate) fn greeting(capabilities: &str) -> String {
    format!(
        "* OK rMail IMAPD ready\r\n* CAPABILITY {}\r\n",
        capabilities
    )
}

pub(crate) fn capability_response(tag: &str, capabilities: &str) -> String {
    format!(
        "* CAPABILITY {}\r\n{} OK CAPABILITY completed\r\n",
        capabilities, tag
    )
}

pub(crate) fn namespace_response(tag: &str) -> String {
    format!(
        "* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n{} OK NAMESPACE completed\r\n",
        tag
    )
}
