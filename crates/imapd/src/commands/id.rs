use crate::{
    parser,
    response::{Response, Status, StatusLine},
};

pub(crate) struct Outcome {
    pub(crate) response: Response,
    pub(crate) field_keys: Vec<String>,
}

pub(crate) fn handle(tag: &str, raw_args: &str) -> Outcome {
    match parser::parse_id_args(raw_args) {
        Ok(fields) => Outcome {
            response: Response::new()
                .data(format!(
                    "ID (\"name\" \"rMail\" \"vendor\" \"rMail\" \"version\" \"{}\")",
                    env!("CARGO_PKG_VERSION")
                ))
                .status(StatusLine::tagged(tag, Status::Ok, "ID completed")),
            field_keys: fields
                .unwrap_or_default()
                .into_iter()
                .map(|(key, _)| key)
                .collect(),
        },
        Err(_) => Outcome {
            response: Response::new().status(StatusLine::tagged(
                tag,
                Status::Bad,
                "Invalid ID arguments",
            )),
            field_keys: Vec::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_parses_client_fields_without_echoing_values() {
        let outcome = handle("A1", r#"("name" "Geary" "version" NIL)"#);
        assert_eq!(outcome.field_keys, ["name", "version"]);
        let response = outcome.response.encode();
        assert!(response.starts_with("* ID (\"name\" \"rMail\""));
        assert!(response.ends_with("A1 OK ID completed\r\n"));
        assert!(!response.contains("Geary"));
    }

    #[test]
    fn malformed_id_is_typed_bad() {
        assert_eq!(
            handle("A2", r#"("name")"#).response.encode(),
            "A2 BAD Invalid ID arguments\r\n"
        );
    }
}
