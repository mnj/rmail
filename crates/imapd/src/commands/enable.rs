use crate::{
    parser::{self, ImapArg, ParseError},
    response::{Response, Status, StatusLine},
    state::SessionState,
};

pub(crate) fn handle(
    tag: &str,
    raw_args: &str,
    session: &mut SessionState,
    selected_highest_modseq: Option<u64>,
) -> Result<Response, ParseError> {
    let args = parser::parse_imap_args(raw_args)?;
    let features = args
        .into_iter()
        .map(|arg| match arg {
            ImapArg::Atom(feature) => Ok(feature),
            _ => Err(ParseError::InvalidAtom),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut newly_enabled = Vec::new();
    for feature in features {
        if session.enable_feature(&feature) {
            newly_enabled.push(feature.to_ascii_uppercase());
        }
    }
    newly_enabled.sort();
    newly_enabled.dedup();

    let condstore_enabled = newly_enabled.iter().any(|feature| feature == "CONDSTORE");
    let mut response = Response::new().data(
        format!("ENABLED {}", newly_enabled.join(" "))
            .trim_end()
            .to_string(),
    );
    if condstore_enabled && let Some(highest_modseq) = selected_highest_modseq {
        response = response.status(
            StatusLine::untagged(Status::Ok, "Highest")
                .with_code(format!("HIGHESTMODSEQ {highest_modseq}")),
        );
    }
    Ok(response.status(StatusLine::tagged(tag, Status::Ok, "ENABLE completed")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enables_supported_atoms_and_reports_selected_modseq() {
        let mut session = SessionState::default();
        let response = handle(
            "A1",
            "IMAP4rev1 CONDSTORE unknown CONDSTORE",
            &mut session,
            Some(42),
        )
        .unwrap()
        .encode();
        assert_eq!(
            response,
            "* ENABLED CONDSTORE IMAP4REV1\r\n* OK [HIGHESTMODSEQ 42] Highest\r\nA1 OK ENABLE completed\r\n"
        );
        assert!(session.feature_enabled("CONDSTORE"));
        assert!(session.feature_enabled("IMAP4REV1"));
        assert!(!session.feature_enabled("unknown"));
    }

    #[test]
    fn rejects_non_atom_feature_names_without_partial_response() {
        let mut session = SessionState::default();
        assert_eq!(
            handle("A1", "CONDSTORE \"QRESYNC\"", &mut session, None),
            Err(ParseError::InvalidAtom)
        );
        assert!(!session.feature_enabled("CONDSTORE"));
    }

    #[test]
    fn rev2_enables_utf8_behavior_and_empty_enable_still_responds() {
        let mut session = SessionState::default();
        assert_eq!(
            handle("A1", "unknown", &mut session, None)
                .unwrap()
                .encode(),
            "* ENABLED\r\nA1 OK ENABLE completed\r\n"
        );
        assert!(!session.utf8_enabled());
        assert!(handle("A2", "IMAP4rev2", &mut session, None).is_ok());
        assert!(session.utf8_enabled());
    }
}
