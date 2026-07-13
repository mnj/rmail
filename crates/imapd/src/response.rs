use std::net::SocketAddr;

use crate::auth;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    Ok,
    No,
    Bad,
    Bye,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::No => "NO",
            Self::Bad => "BAD",
            Self::Bye => "BYE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StatusLine {
    tag: Option<String>,
    status: Status,
    code: Option<String>,
    text: String,
}

impl StatusLine {
    pub(crate) fn tagged(tag: impl Into<String>, status: Status, text: impl Into<String>) -> Self {
        Self {
            tag: Some(tag.into()),
            status,
            code: None,
            text: text.into(),
        }
    }

    pub(crate) fn untagged(status: Status, text: impl Into<String>) -> Self {
        Self {
            tag: None,
            status,
            code: None,
            text: text.into(),
        }
    }

    pub(crate) fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }

    fn encode(&self, output: &mut String) {
        output.push_str(
            &self
                .tag
                .as_deref()
                .map(sanitize_component)
                .unwrap_or_else(|| "*".to_string()),
        );
        output.push(' ');
        output.push_str(self.status.as_str());
        if let Some(code) = &self.code {
            output.push_str(" [");
            output.push_str(&sanitize_code(code));
            output.push(']');
        }
        if !self.text.is_empty() {
            output.push(' ');
            output.push_str(&sanitize_component(&self.text));
        }
        output.push_str("\r\n");
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Line {
    Status(StatusLine),
    UntaggedData(String),
    Continuation(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Response {
    lines: Vec<Line>,
}

impl Response {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn status(mut self, line: StatusLine) -> Self {
        self.lines.push(Line::Status(line));
        self
    }

    pub(crate) fn data(mut self, data: impl Into<String>) -> Self {
        self.lines.push(Line::UntaggedData(data.into()));
        self
    }

    pub(crate) fn continuation(mut self, text: impl Into<String>) -> Self {
        self.lines.push(Line::Continuation(text.into()));
        self
    }

    pub(crate) fn encode(&self) -> String {
        let mut output = String::new();
        for line in &self.lines {
            match line {
                Line::Status(line) => line.encode(&mut output),
                Line::UntaggedData(data) => {
                    output.push_str("* ");
                    output.push_str(&sanitize_component(data));
                    output.push_str("\r\n");
                }
                Line::Continuation(text) => {
                    output.push_str("+ ");
                    if !text.is_empty() {
                        output.push_str(&sanitize_component(text));
                    }
                    output.push_str("\r\n");
                }
            }
        }
        output
    }
}

fn sanitize_component(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\r' | '\n' | '\0' => ' ',
            character => character,
        })
        .collect()
}

fn sanitize_code(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\r' | '\n' | '\0' | '[' | ']' => ' ',
            character => character,
        })
        .collect()
}

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

#[cfg(test)]
pub(crate) fn capability_tokens(phase: CapabilityPhase, starttls_available: bool) -> String {
    capability_tokens_with_policy(phase, starttls_available, &auth::AuthPolicy::default())
}

pub(crate) fn capability_tokens_with_policy(
    phase: CapabilityPhase,
    starttls_available: bool,
    auth_policy: &auth::AuthPolicy,
) -> String {
    let mut caps = vec![
        "IMAP4rev1",
        "ID",
        "ENABLE",
        "IDLE",
        "SASL-IR",
        "LITERAL+",
        "LITERAL-",
    ];
    match phase {
        CapabilityPhase::NotAuthenticatedPlain => {
            caps.push("LOGINDISABLED");
            if starttls_available {
                caps.push("STARTTLS");
            }
            caps.extend(
                auth_policy
                    .advertised_mechanisms(false, false)
                    .map(|mechanism| mechanism.capability),
            );
        }
        CapabilityPhase::NotAuthenticatedTls => {
            caps.extend(
                auth_policy
                    .advertised_mechanisms(true, starttls_available)
                    .map(|mechanism| mechanism.capability),
            );
        }
        CapabilityPhase::Authenticated | CapabilityPhase::Selected => caps.extend([
            "UIDPLUS",
            "MULTIAPPEND",
            "CATENATE",
            "QUOTA",
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
            "THREAD=REFS",
            "WITHIN",
            "STATUS=SIZE",
            "SAVEDATE",
            "PREVIEW",
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
    Response::new()
        .status(StatusLine::untagged(Status::Ok, "rMail IMAPD ready"))
        .data(format!("CAPABILITY {capabilities}"))
        .encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_response_serializes_all_line_kinds() {
        let response = Response::new()
            .data("CAPABILITY IMAP4rev1")
            .status(StatusLine::untagged(Status::Ok, "ready").with_code("CAPABILITY IMAP4rev1"))
            .continuation("challenge")
            .status(StatusLine::tagged("A1", Status::No, "failed").with_code("TRYCREATE"))
            .encode();
        assert_eq!(
            response,
            "* CAPABILITY IMAP4rev1\r\n* OK [CAPABILITY IMAP4rev1] ready\r\n+ challenge\r\nA1 NO [TRYCREATE] failed\r\n"
        );
    }

    #[test]
    fn typed_response_cannot_inject_additional_protocol_lines() {
        let response = Response::new()
            .status(
                StatusLine::tagged("A1\r\n*", Status::Bad, "bad\r\n* BYE injected")
                    .with_code("CLIENTBUG] A2 OK [injected"),
            )
            .data("ID \0bad\nA2 OK injected")
            .encode();
        assert_eq!(
            response,
            "A1  * BAD [CLIENTBUG  A2 OK  injected] bad  * BYE injected\r\n* ID  bad A2 OK injected\r\n"
        );
    }
}
