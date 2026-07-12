use crate::response::{Response, Status, StatusLine};

pub(crate) fn capability(tag: &str, capabilities: &str) -> Response {
    Response::new()
        .data(format!("CAPABILITY {capabilities}"))
        .status(StatusLine::tagged(tag, Status::Ok, "CAPABILITY completed"))
}

pub(crate) fn namespace(tag: &str) -> Response {
    Response::new()
        .data("NAMESPACE ((\"\" \"/\")) NIL NIL")
        .status(StatusLine::tagged(tag, Status::Ok, "NAMESPACE completed"))
}

pub(crate) fn id(tag: &str) -> Response {
    Response::new()
        .data(format!(
            "ID (\"name\" \"rMail\" \"vendor\" \"rMail\" \"version\" \"{}\")",
            env!("CARGO_PKG_VERSION")
        ))
        .status(StatusLine::tagged(tag, Status::Ok, "ID completed"))
}

pub(crate) fn completed(tag: &str, command: &str) -> Response {
    Response::new().status(StatusLine::tagged(
        tag,
        Status::Ok,
        format!("{command} completed"),
    ))
}

pub(crate) fn logout(tag: &str) -> Response {
    Response::new()
        .status(StatusLine::untagged(Status::Bye, "Logging out"))
        .status(StatusLine::tagged(tag, Status::Ok, "LOGOUT completed"))
}

pub(crate) fn unknown(tag: &str) -> Response {
    Response::new().status(StatusLine::tagged(
        tag,
        Status::Bad,
        "Unknown or unimplemented command",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_and_namespace_are_complete_command_responses() {
        assert_eq!(
            capability("A1", "IMAP4rev1 ID").encode(),
            "* CAPABILITY IMAP4rev1 ID\r\nA1 OK CAPABILITY completed\r\n"
        );
        assert_eq!(
            namespace("A2").encode(),
            "* NAMESPACE ((\"\" \"/\")) NIL NIL\r\nA2 OK NAMESPACE completed\r\n"
        );
    }

    #[test]
    fn logout_orders_bye_before_tagged_completion() {
        assert_eq!(
            logout("A3").encode(),
            "* BYE Logging out\r\nA3 OK LOGOUT completed\r\n"
        );
    }

    #[test]
    fn simple_handlers_return_typed_statuses() {
        assert_eq!(completed("A4", "NOOP").encode(), "A4 OK NOOP completed\r\n");
        assert_eq!(
            unknown("A5").encode(),
            "A5 BAD Unknown or unimplemented command\r\n"
        );
        assert!(id("A6").encode().contains("A6 OK ID completed\r\n"));
    }
}
