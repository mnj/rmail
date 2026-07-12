use std::path::Path;

use crate::{
    commands::status::status_values,
    mailbox, parser,
    response::{Response, Status, StatusLine},
};

pub(crate) fn handle(
    tag: &str,
    command_name: &str,
    raw_args: &str,
    mail_root: &Path,
    address: &str,
    utf8_accept: bool,
) -> Response {
    let lsub = command_name == "LSUB";
    let mut request = match parser::parse_list_request(raw_args, lsub) {
        Ok(request) => request,
        Err(error) => {
            return Response::new().status(StatusLine::tagged(
                tag,
                Status::Bad,
                format!("Invalid {command_name} arguments: {error:?}"),
            ));
        }
    };
    request.reference = match mailbox::decode_wire_mailbox_name(&request.reference, utf8_accept) {
        Ok(reference) => reference,
        Err(_) => return bad_mailbox_name(tag),
    };
    request.patterns = match request
        .patterns
        .iter()
        .map(|pattern| mailbox::decode_wire_mailbox_name(pattern, utf8_accept))
        .collect::<anyhow::Result<Vec<_>>>()
    {
        Ok(patterns) => patterns,
        Err(_) => return bad_mailbox_name(tag),
    };
    let (local, domain) = match mailbox::address_parts(address) {
        Ok(parts) => parts,
        Err(error) => return unavailable(tag, command_name, error),
    };
    let summaries =
        match rmail_common::imap_state::list_folder_summaries(mail_root, &domain, &local) {
            Ok(summaries) => summaries,
            Err(error) => return unavailable(tag, command_name, error),
        };
    let subscriptions =
        match rmail_common::imap_state::list_subscriptions(mail_root, &domain, &local) {
            Ok(subscriptions) => subscriptions,
            Err(error) => return unavailable(tag, command_name, error),
        };

    let mut response = Response::new();
    if !lsub
        && !request.extended
        && request.reference.is_empty()
        && request.patterns.iter().any(String::is_empty)
    {
        response = response.data("LIST (\\Noselect \\HasChildren) \"/\" \"\"");
    }
    for summary in &summaries {
        if request.selection.remote {
            continue;
        }
        let subscribed = subscriptions
            .iter()
            .any(|name| name == &summary.folder.name);
        if lsub && !subscribed {
            continue;
        }
        let directly_selected = (!request.selection.subscribed || subscribed)
            && (!request.selection.special_use || summary.folder.special_use.is_some());
        let child_info = child_info(&request, summary, &summaries, &subscriptions);
        if !lsub && !directly_selected && child_info.is_empty() {
            continue;
        }
        if !matches_patterns(&request, &summary.folder.name) {
            continue;
        }
        let attrs = attributes(command_name, &request, summary, &summaries, subscribed);
        let mut data = format!(
            "{command_name} ({}) \"/\" {}",
            attrs.join(" "),
            mailbox::quote_wire_mailbox_name(&summary.folder.name, utf8_accept)
        );
        if !child_info.is_empty() {
            data.push_str(&format!(
                " (CHILDINFO ({}))",
                child_info
                    .iter()
                    .map(|item| format!("\"{item}\""))
                    .collect::<Vec<_>>()
                    .join(" ")
            ));
        }
        response = response.data(data);
        if !request.returns.status.is_empty() {
            response = response.data(format!(
                "STATUS {} ({})",
                mailbox::quote_wire_mailbox_name(&summary.folder.name, utf8_accept),
                status_values(summary, &request.returns.status).join(" ")
            ));
        }
    }
    if lsub || request.selection.subscribed {
        for name in &subscriptions {
            if summaries.iter().any(|summary| summary.folder.name == *name)
                || !matches_patterns(&request, name)
            {
                continue;
            }
            let mut attrs = vec![if lsub { "\\Noselect" } else { "\\NonExistent" }];
            if request.returns.subscribed {
                attrs.push("\\Subscribed");
            }
            response = response.data(format!(
                "{command_name} ({}) \"/\" {}",
                attrs.join(" "),
                mailbox::quote_wire_mailbox_name(name, utf8_accept)
            ));
        }
    }
    response.status(StatusLine::tagged(
        tag,
        Status::Ok,
        format!("{command_name} completed"),
    ))
}

fn matches_patterns(request: &parser::ListRequest, name: &str) -> bool {
    request
        .patterns
        .iter()
        .any(|pattern| parser::mailbox_pattern_matches(name, &request.reference, pattern))
}

fn has_children(name: &str, summaries: &[rmail_common::imap_state::FolderSummary]) -> bool {
    let prefix = format!("{name}/");
    summaries
        .iter()
        .any(|candidate| candidate.folder.name.starts_with(&prefix))
}

fn attributes(
    command_name: &str,
    request: &parser::ListRequest,
    summary: &rmail_common::imap_state::FolderSummary,
    summaries: &[rmail_common::imap_state::FolderSummary],
    subscribed: bool,
) -> Vec<String> {
    let mut attributes = Vec::new();
    if request.returns.children {
        attributes.push(
            if has_children(&summary.folder.name, summaries) {
                "\\HasChildren"
            } else {
                "\\HasNoChildren"
            }
            .to_string(),
        );
    }
    if request.returns.subscribed && subscribed {
        attributes.push("\\Subscribed".to_string());
    }
    if command_name == "XLIST" && summary.folder.name.eq_ignore_ascii_case("INBOX") {
        attributes.push("\\Inbox".to_string());
    }
    if request.returns.special_use {
        if let Some(special_use) = &summary.folder.special_use {
            attributes.push(special_use.clone());
        }
    }
    attributes
}

fn child_info(
    request: &parser::ListRequest,
    summary: &rmail_common::imap_state::FolderSummary,
    summaries: &[rmail_common::imap_state::FolderSummary],
    subscriptions: &[String],
) -> Vec<&'static str> {
    if !request.selection.recursive_match {
        return Vec::new();
    }
    let prefix = format!("{}/", summary.folder.name);
    let mut info = Vec::new();
    if request.selection.subscribed && subscriptions.iter().any(|name| name.starts_with(&prefix)) {
        info.push("SUBSCRIBED");
    }
    if request.selection.special_use
        && summaries.iter().any(|candidate| {
            candidate.folder.name.starts_with(&prefix) && candidate.folder.special_use.is_some()
        })
    {
        info.push("SPECIAL-USE");
    }
    info
}

fn bad_mailbox_name(tag: &str) -> Response {
    Response::new().status(StatusLine::tagged(tag, Status::Bad, "Invalid mailbox name"))
}

fn unavailable(tag: &str, command_name: &str, error: impl std::fmt::Display) -> Response {
    Response::new().status(
        StatusLine::tagged(tag, Status::No, format!("{command_name} failed: {error}"))
            .with_code("UNAVAILABLE"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_subscriptions_have_command_specific_attributes() {
        let temp = tempfile::tempdir().unwrap();
        rmail_common::imap_state::set_subscription(
            temp.path(),
            "example.test",
            "user",
            "Ghost",
            true,
        )
        .unwrap();
        assert!(
            handle(
                "A1",
                "LSUB",
                "\"\" \"Ghost\"",
                temp.path(),
                "user@example.test",
                false,
            )
            .encode()
            .contains("* LSUB (\\Noselect) \"/\" \"Ghost\"")
        );
        assert!(
            handle(
                "A2",
                "LIST",
                "(SUBSCRIBED) \"\" \"Ghost\" RETURN (SUBSCRIBED)",
                temp.path(),
                "user@example.test",
                false,
            )
            .encode()
            .contains("* LIST (\\NonExistent \\Subscribed) \"/\" \"Ghost\"")
        );
    }
}
