use std::path::Path;

use crate::{
    mailbox, parser,
    response::{Response, Status, StatusLine},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operation {
    Create,
    Delete,
    Rename,
    Subscribe,
    Unsubscribe,
}

impl Operation {
    fn command(self) -> &'static str {
        match self {
            Self::Create => "CREATE",
            Self::Delete => "DELETE",
            Self::Rename => "RENAME",
            Self::Subscribe => "SUBSCRIBE",
            Self::Unsubscribe => "UNSUBSCRIBE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SelectionEffect {
    None,
    Deleted(String),
    Renamed { source: String, destination: String },
}

impl SelectionEffect {
    pub(crate) fn renamed_selection(&self, selected: &str) -> Option<String> {
        let Self::Renamed {
            source,
            destination,
        } = self
        else {
            return None;
        };
        if selected.eq_ignore_ascii_case(source) {
            return Some(destination.clone());
        }
        let prefix = format!("{source}/");
        selected
            .get(..prefix.len())
            .filter(|candidate| candidate.eq_ignore_ascii_case(&prefix))
            .map(|_| format!("{destination}/{}", &selected[prefix.len()..]))
    }
}

pub(crate) struct Outcome {
    pub(crate) response: Response,
    pub(crate) selection_effect: SelectionEffect,
}

impl Outcome {
    fn response(response: Response) -> Self {
        Self {
            response,
            selection_effect: SelectionEffect::None,
        }
    }
}

pub(crate) fn handle(
    operation: Operation,
    tag: &str,
    raw_args: &str,
    mail_root: &Path,
    address: &str,
    utf8_accept: bool,
) -> Outcome {
    let command = operation.command();
    let parsed = match operation {
        Operation::Rename => parser::parse_rename_arguments(raw_args)
            .map(|(source, destination)| vec![source, destination]),
        _ => parser::parse_mailbox_argument(raw_args).map(|mailbox| vec![mailbox]),
    };
    let wire_names = match parsed {
        Ok(names) => names,
        Err(_) => return Outcome::response(bad(tag, format!("Invalid {command} arguments"))),
    };
    let names = match wire_names
        .iter()
        .map(|name| mailbox::decode_wire_mailbox_name(name, utf8_accept))
        .collect::<anyhow::Result<Vec<_>>>()
    {
        Ok(names) => names,
        Err(_) => return Outcome::response(bad(tag, "Invalid mailbox name")),
    };
    let (local, domain) = match mailbox::address_parts(address) {
        Ok(parts) => parts,
        Err(error) => return Outcome::response(storage_failure(tag, command, error, None)),
    };

    let result = match operation {
        Operation::Create => {
            rmail_common::maildir::create_mailbox(mail_root, &domain, &local, &names[0])
        }
        Operation::Delete => {
            rmail_common::maildir::delete_mailbox(mail_root, &domain, &local, &names[0])
        }
        Operation::Rename => {
            rmail_common::maildir::rename_mailbox(mail_root, &domain, &local, &names[0], &names[1])
        }
        Operation::Subscribe | Operation::Unsubscribe => {
            rmail_common::maildir::set_mailbox_subscription(
                mail_root,
                &domain,
                &local,
                &names[0],
                operation == Operation::Subscribe,
            )
        }
    };

    match result {
        Ok(()) => Outcome {
            response: completed(tag, command),
            selection_effect: match operation {
                Operation::Delete => SelectionEffect::Deleted(names[0].clone()),
                Operation::Rename => SelectionEffect::Renamed {
                    source: names[0].clone(),
                    destination: names[1].clone(),
                },
                _ => SelectionEffect::None,
            },
        },
        Err(error) => {
            let message = error.to_string();
            let code = match operation {
                Operation::Create if message.contains("already exists") => Some("ALREADYEXISTS"),
                Operation::Delete if message.contains("does not exist") => Some("NONEXISTENT"),
                _ => None,
            };
            Outcome::response(storage_failure(tag, command, error, code))
        }
    }
}

fn completed(tag: &str, command: &str) -> Response {
    Response::new().status(StatusLine::tagged(
        tag,
        Status::Ok,
        format!("{command} completed"),
    ))
}

fn bad(tag: &str, text: impl Into<String>) -> Response {
    Response::new().status(StatusLine::tagged(tag, Status::Bad, text))
}

fn storage_failure(
    tag: &str,
    command: &str,
    error: impl std::fmt::Display,
    code: Option<&str>,
) -> Response {
    let mut line = StatusLine::tagged(tag, Status::No, format!("{command} failed: {error}"));
    if let Some(code) = code {
        line = line.with_code(code);
    }
    Response::new().status(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_delete_and_rename_return_selection_effects_and_codes() {
        let temp = tempfile::tempdir().unwrap();
        let address = "user@example.test";
        let create = handle(
            Operation::Create,
            "A1",
            "Projects",
            temp.path(),
            address,
            false,
        );
        assert_eq!(create.response.encode(), "A1 OK CREATE completed\r\n");
        assert_eq!(create.selection_effect, SelectionEffect::None);

        let duplicate = handle(
            Operation::Create,
            "A2",
            "Projects",
            temp.path(),
            address,
            false,
        )
        .response
        .encode();
        assert!(duplicate.starts_with("A2 NO [ALREADYEXISTS] CREATE failed:"));

        let rename = handle(
            Operation::Rename,
            "A3",
            "Projects Renamed",
            temp.path(),
            address,
            false,
        );
        assert_eq!(
            rename.selection_effect,
            SelectionEffect::Renamed {
                source: "Projects".to_string(),
                destination: "Renamed".to_string(),
            }
        );
        assert_eq!(rename.response.encode(), "A3 OK RENAME completed\r\n");

        let delete = handle(
            Operation::Delete,
            "A4",
            "Renamed",
            temp.path(),
            address,
            false,
        );
        assert_eq!(
            delete.selection_effect,
            SelectionEffect::Deleted("Renamed".to_string())
        );
        assert_eq!(delete.response.encode(), "A4 OK DELETE completed\r\n");
    }

    #[test]
    fn malformed_arguments_fail_before_storage_changes() {
        let temp = tempfile::tempdir().unwrap();
        let outcome = handle(
            Operation::Rename,
            "A1",
            "OnlyOneName",
            temp.path(),
            "user@example.test",
            false,
        );
        assert_eq!(
            outcome.response.encode(),
            "A1 BAD Invalid RENAME arguments\r\n"
        );
        assert_eq!(outcome.selection_effect, SelectionEffect::None);
    }

    #[test]
    fn hierarchy_rename_remaps_selected_descendants() {
        let effect = SelectionEffect::Renamed {
            source: "Projects".to_string(),
            destination: "Archive/Projects".to_string(),
        };
        assert_eq!(
            effect.renamed_selection("Projects/Client/2026"),
            Some("Archive/Projects/Client/2026".to_string())
        );
        assert_eq!(effect.renamed_selection("Projects-Old"), None);
    }
}
