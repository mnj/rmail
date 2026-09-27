//! Account- and mailbox-level commands: SELECT/EXAMINE, STATUS, LIST/LSUB,
//! CREATE/DELETE/RENAME/(UN)SUBSCRIBE, APPEND, quota, ENABLE, ID, NAMESPACE.

use std::path::Path;

use anyhow::Result;

use super::{Flow, ImapReader, Invocation, Session};
use crate::commands::{self, mailboxes::Operation, mailboxes::SelectionEffect};
use crate::{mailbox, parser, response};

impl Session {
    pub(super) async fn id(&self, reader: &mut ImapReader, call: &Invocation<'_>) -> Result<Flow> {
        let outcome = commands::id::handle(call.tag, call.args);
        if !outcome.field_keys.is_empty() {
            imap_log!("info", "client_identified", { "peer": self.peer_label(), "field_keys": outcome.field_keys });
        }
        self.send(reader, outcome.response.encode()).await
    }

    pub(super) async fn namespace(
        &self,
        reader: &mut ImapReader,
        call: &Invocation<'_>,
    ) -> Result<Flow> {
        imap_log!("info", "namespace_requested", { "peer": self.peer_label() });
        let response = commands::basic::namespace(call.tag).encode();
        self.respond(reader, call.tag, &call.name, response).await
    }

    pub(super) async fn enable(
        &mut self,
        reader: &mut ImapReader,
        call: &Invocation<'_>,
    ) -> Result<Flow> {
        let highest_modseq = self.selected.as_ref().map(|mailbox| mailbox.highest_modseq);
        match commands::enable::handle(call.tag, call.args, &mut self.state, highest_modseq) {
            Ok(response) => {
                self.respond(reader, call.tag, &call.name, response.encode())
                    .await
            }
            Err(error) => {
                let response = response::Response::new()
                    .status(response::StatusLine::tagged(
                        call.tag,
                        response::Status::Bad,
                        format!("Invalid ENABLE arguments: {error:?}"),
                    ))
                    .encode();
                self.send(reader, response).await
            }
        }
    }

    pub(super) async fn quota(
        &self,
        reader: &mut ImapReader,
        call: &Invocation<'_>,
    ) -> Result<Flow> {
        self.sync_quota().await?;
        let response = commands::quota::handle(
            call.tag,
            call.command,
            call.args,
            &self.mail_root,
            self.address(),
            self.state.utf8_enabled(),
        )
        .encode();
        self.send(reader, response).await
    }

    pub(super) async fn unselect(
        &mut self,
        reader: &mut ImapReader,
        call: &Invocation<'_>,
    ) -> Result<Flow> {
        let outcome = commands::session::unselect(call.tag);
        if outcome.selection_effect == commands::session::SelectionEffect::Clear {
            self.clear_selection();
        }
        self.send(reader, outcome.response.encode()).await
    }

    pub(super) async fn append(
        &mut self,
        reader: &mut ImapReader,
        call: &Invocation<'_>,
    ) -> Result<Flow> {
        self.sync_quota().await?;
        let outcome = commands::append::handle(
            reader,
            call.tag,
            call.args,
            &self.mail_root,
            self.address(),
            self.state.utf8_enabled(),
            self.selected
                .as_ref()
                .map(|mailbox| mailbox.mailbox.as_str()),
        )
        .await?;
        if outcome.close_connection {
            return Ok(Flow::Close);
        }
        // A message appended to the selected mailbox is reported as EXISTS
        // by the next command that synchronizes the mailbox; the selected
        // view is left alone so that EXISTS is not lost.
        Ok(Flow::Continue)
    }

    pub(super) async fn list(
        &self,
        reader: &mut ImapReader,
        call: &Invocation<'_>,
    ) -> Result<Flow> {
        let operation = call.name.clone();
        let root = self.mail_root.clone();
        let address = self.address().to_string();
        let args = call.args.to_string();
        let tag = call.tag.to_string();
        let utf8_accept = self.state.utf8_enabled();
        let response = tokio::task::spawn_blocking(move || {
            commands::list::handle(
                &tag,
                &operation,
                &args,
                Path::new(&root),
                &address,
                utf8_accept,
            )
            .encode()
        })
        .await?;
        self.respond(reader, call.tag, &call.name, response).await
    }

    /// CREATE, DELETE, RENAME, SUBSCRIBE and UNSUBSCRIBE.
    pub(super) async fn manage_mailbox(
        &mut self,
        reader: &mut ImapReader,
        call: &Invocation<'_>,
    ) -> Result<Flow> {
        let operation = match call.command {
            parser::Command::Create => Operation::Create,
            parser::Command::Delete => Operation::Delete,
            parser::Command::Rename => Operation::Rename,
            parser::Command::Subscribe { subscribe: true } => Operation::Subscribe,
            parser::Command::Subscribe { subscribe: false } => Operation::Unsubscribe,
            _ => unreachable!("dispatch only routes mailbox management commands here"),
        };
        let root = self.mail_root.clone();
        let address = self.address().to_string();
        let args = call.args.to_string();
        let tag = call.tag.to_string();
        let utf8_accept = self.state.utf8_enabled();
        let outcome = tokio::task::spawn_blocking(move || {
            commands::mailboxes::handle(
                operation,
                &tag,
                &args,
                Path::new(&root),
                &address,
                utf8_accept,
            )
        })
        .await?;

        match &outcome.selection_effect {
            SelectionEffect::Deleted(name) => {
                if self
                    .selected
                    .as_ref()
                    .is_some_and(|selected| selected.mailbox.eq_ignore_ascii_case(name))
                {
                    self.clear_selection();
                }
            }
            SelectionEffect::Renamed { .. } => {
                let destination = self.selected.as_ref().and_then(|selected| {
                    outcome
                        .selection_effect
                        .renamed_selection(&selected.mailbox)
                });
                if let Some(destination) = destination {
                    self.selected = Some(
                        mailbox::load_selected_mailbox(
                            &self.mail_root,
                            self.address(),
                            &destination,
                        )
                        .await?,
                    );
                    self.state.selected_mailbox = Some(destination);
                }
            }
            SelectionEffect::None => {}
        }
        self.respond(reader, call.tag, &call.name, outcome.response.encode())
            .await
    }

    /// SELECT and EXAMINE.
    pub(super) async fn select(
        &mut self,
        reader: &mut ImapReader,
        call: &Invocation<'_>,
    ) -> Result<Flow> {
        let outcome = commands::select::handle(
            call.tag,
            &call.name,
            call.args,
            &self.mail_root,
            self.address(),
            self.state.utf8_enabled(),
            self.state.feature_enabled("CONDSTORE"),
            self.state.feature_enabled("QRESYNC"),
            self.selected.is_some(),
            self.state.imap4rev2_enabled(),
        )
        .await;
        if outcome.condstore_activated {
            self.state.activate_condstore();
        }
        self.selected = outcome.selected;
        self.state.selected_mailbox = self
            .selected
            .as_ref()
            .map(|mailbox| mailbox.mailbox.clone());
        self.respond(reader, call.tag, &call.name, outcome.response.encode())
            .await
    }

    pub(super) async fn status(
        &self,
        reader: &mut ImapReader,
        call: &Invocation<'_>,
    ) -> Result<Flow> {
        let root = self.mail_root.clone();
        let address = self.address().to_string();
        let args = call.args.to_string();
        let tag = call.tag.to_string();
        let utf8_accept = self.state.utf8_enabled();
        let selected = self
            .selected
            .as_ref()
            .map(|mailbox| mailbox.mailbox.clone());
        let response = tokio::task::spawn_blocking(move || {
            commands::status::handle(
                &tag,
                &args,
                Path::new(&root),
                &address,
                utf8_accept,
                selected.as_deref(),
            )
            .encode()
        })
        .await?;
        self.respond(reader, call.tag, &call.name, response).await
    }
}
