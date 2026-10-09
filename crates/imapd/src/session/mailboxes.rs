//! Account- and mailbox-level commands: SELECT/EXAMINE, STATUS, LIST/LSUB,
//! CREATE/DELETE/RENAME/(UN)SUBSCRIBE, APPEND, quota, metadata, ENABLE, ID,
//! NAMESPACE.

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
            self.db_path.as_deref(),
            self.address(),
            self.state.utf8_enabled(),
        )
        .encode();
        self.send(reader, response).await
    }

    pub(super) async fn metadata(
        &self,
        reader: &mut ImapReader,
        call: &Invocation<'_>,
    ) -> Result<Flow> {
        let response = commands::metadata::handle(
            call.tag,
            call.command,
            call.args,
            &self.mail_root,
            self.address(),
            self.state.utf8_enabled(),
        )
        .encode();
        self.respond(reader, call.tag, &call.name, response).await
    }

    /// SETACL, DELETEACL, GETACL, LISTRIGHTS and MYRIGHTS (RFC 4314).
    pub(super) async fn acl(&self, reader: &mut ImapReader, call: &Invocation<'_>) -> Result<Flow> {
        let command = call.command.clone();
        let root = self.mail_root.clone();
        let db_path = self.db_path.clone();
        let address = self.address().to_string();
        let args = call.args.to_string();
        let tag = call.tag.to_string();
        let utf8_accept = self.state.utf8_enabled();
        let response = tokio::task::spawn_blocking(move || {
            commands::acl::handle(
                &tag,
                &command,
                &args,
                Path::new(&root),
                db_path.as_deref().map(Path::new),
                &address,
                utf8_accept,
            )
            .encode()
        })
        .await?;
        self.respond(reader, call.tag, &call.name, response).await
    }

    /// NOTIFY SET and NOTIFY NONE (RFC 5465).
    pub(super) async fn notify(
        &mut self,
        reader: &mut ImapReader,
        call: &Invocation<'_>,
    ) -> Result<Flow> {
        use commands::notify;

        let request = match notify::parse(call.args, self.state.utf8_enabled()) {
            Ok(request) => request,
            Err(rejection) => {
                let response = rejection.response(call.tag).encode();
                return self.respond(reader, call.tag, &call.name, response).await;
            }
        };
        let (status, spec) = match request {
            notify::Request::None => {
                self.notify = None;
                let response = commands::basic::completed(call.tag, "NOTIFY").encode();
                return self.respond(reader, call.tag, &call.name, response).await;
            }
            notify::Request::Set { status, spec } => (status, spec),
        };
        let (local, domain) = mailbox::address_parts(self.address())?;
        let root = self.mail_root.clone();
        let scan_spec = spec.clone();
        let scanned = tokio::task::spawn_blocking(move || {
            notify::scan(Path::new(&root), &domain, &local, &scan_spec)
        })
        .await?;
        let snapshot = match scanned {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let response = response::Response::new()
                    .status(
                        response::StatusLine::tagged(
                            call.tag,
                            response::Status::No,
                            format!("NOTIFY failed: {error}"),
                        )
                        .with_code("UNAVAILABLE"),
                    )
                    .encode();
                return self.respond(reader, call.tag, &call.name, response).await;
            }
        };
        let mut response = response::Response::new();
        if status {
            let selected = self.selected.as_ref().map(|mailbox| mailbox.name.as_str());
            for line in notify::initial_status(&snapshot, selected, self.notify_format()) {
                response = response.data(line);
            }
        }
        self.notify = Some(notify::Notifier::new(spec, snapshot));
        let response = response
            .status(response::StatusLine::tagged(
                call.tag,
                response::Status::Ok,
                "NOTIFY completed",
            ))
            .encode();
        self.respond(reader, call.tag, &call.name, response).await
    }

    /// Report changes for the active NOTIFY between commands.
    pub(super) async fn poll_notifications(&mut self, reader: &mut ImapReader) -> Result<()> {
        let options = self.sync_options(true);
        let format = self.notify_format();
        let Some(notifier) = self.notify.as_mut() else {
            return Ok(());
        };
        let Some(address) = self.state.authenticated_mailbox.as_deref() else {
            return Ok(());
        };
        let account = commands::notify::Account {
            mail_root: &self.mail_root,
            address,
        };
        notifier
            .poll(
                reader,
                account,
                &mut self.selected,
                &mut self.contexts,
                options,
                format,
                false,
            )
            .await?;
        if !notifier.is_active() {
            self.notify = None;
        }
        Ok(())
    }

    pub(super) fn notify_format(&self) -> commands::notify::Format {
        commands::notify::Format {
            utf8_accept: self.state.utf8_enabled(),
            condstore: self.state.condstore_enabled(),
        }
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
            self.db_path.as_deref(),
            self.address(),
            self.state.utf8_enabled(),
            // CATENATE URLs without a mailbox refer to the selected one; a
            // shared one's name is not in the user's account, so such URLs
            // cannot reach it.
            self.selected.as_ref().map(|mailbox| mailbox.name.as_str()),
            self.auth_policy.message_limit(),
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
        let db_path = self.db_path.clone();
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
                db_path.as_deref().map(Path::new),
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
        let db_path = self.db_path.clone();
        let address = self.address().to_string();
        let args = call.args.to_string();
        let tag = call.tag.to_string();
        let utf8_accept = self.state.utf8_enabled();
        let imap4rev2 = self.state.imap4rev2_enabled();
        let outcome = tokio::task::spawn_blocking(move || {
            commands::mailboxes::handle(
                operation,
                &tag,
                &args,
                Path::new(&root),
                db_path.as_deref().map(Path::new),
                &address,
                utf8_accept,
                imap4rev2,
            )
        })
        .await?;

        match &outcome.selection_effect {
            SelectionEffect::Deleted(name) => {
                if self
                    .selected
                    .as_ref()
                    .is_some_and(|selected| selected.name.eq_ignore_ascii_case(name))
                {
                    self.clear_selection();
                }
            }
            SelectionEffect::Renamed { .. } => {
                let renamed = self.selected.as_ref().and_then(|selected| {
                    let destination = outcome.selection_effect.renamed_selection(&selected.name)?;
                    // A RENAME stays within one account, so a shared
                    // mailbox keeps its owner.
                    let storage_name = match crate::shared::split_shared_name(&destination) {
                        Some((_, rest)) => rest.to_string(),
                        None => destination.clone(),
                    };
                    Some((
                        format!("{}@{}", selected.local, selected.domain),
                        storage_name,
                        destination,
                        selected.rights,
                        selected.read_only,
                    ))
                });
                if let Some((owner, storage_name, destination, rights, read_only)) = renamed {
                    let mut reloaded =
                        mailbox::load_selected_mailbox(&self.mail_root, &owner, &storage_name)
                            .await?;
                    reloaded.name = destination.clone();
                    reloaded.rights = rights;
                    reloaded.read_only = read_only;
                    self.selected = Some(reloaded);
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
            self.db_path.as_deref(),
            self.address(),
            self.state.utf8_enabled(),
            self.state.feature_enabled("CONDSTORE"),
            self.state.feature_enabled("QRESYNC"),
            self.selected.is_some(),
            self.state.imap4rev2_enabled(),
            self.state.uidonly_enabled(),
        )
        .await;
        if outcome.condstore_activated {
            self.state.activate_condstore();
        }
        // Updating contexts belong to the previous selection.
        self.contexts.clear();
        self.selected = outcome.selected;
        self.state.selected_mailbox = self.selected.as_ref().map(|mailbox| mailbox.name.clone());
        self.respond(reader, call.tag, &call.name, outcome.response.encode())
            .await
    }

    pub(super) async fn status(
        &self,
        reader: &mut ImapReader,
        call: &Invocation<'_>,
    ) -> Result<Flow> {
        let root = self.mail_root.clone();
        let db_path = self.db_path.clone();
        let address = self.address().to_string();
        let args = call.args.to_string();
        let tag = call.tag.to_string();
        let utf8_accept = self.state.utf8_enabled();
        let selected = self.selected.as_ref().map(|mailbox| mailbox.name.clone());
        let response = tokio::task::spawn_blocking(move || {
            commands::status::handle(
                &tag,
                &args,
                Path::new(&root),
                db_path.as_deref().map(Path::new),
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
