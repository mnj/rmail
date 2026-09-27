//! Commands on the selected mailbox: FETCH, STORE, SEARCH, SORT, THREAD,
//! COPY/MOVE, EXPUNGE/CLOSE, IDLE and their UID forms.

use anyhow::Result;

use super::{Flow, ImapReader, Invocation, Session};
use crate::commands::{self, expunge::SelectionEffect};
use crate::parser;

impl Session {
    pub(super) async fn uid(
        &mut self,
        reader: &mut ImapReader,
        call: &Invocation<'_>,
        subcommand: &str,
    ) -> Result<Flow> {
        let tag = call.tag;
        let args = call
            .args
            .trim()
            .split_once(|character: char| character.is_ascii_whitespace())
            .map(|(_, args)| args.trim_start())
            .unwrap_or("");
        match subcommand {
            "FETCH" => self.fetch(reader, tag, args, true).await,
            "THREAD" => self.thread(reader, tag, args, true).await,
            "SORT" => self.sort(reader, tag, args, true).await,
            "SEARCH" => self.search(reader, tag, args, true).await,
            "STORE" => self.store(reader, tag, args, true).await,
            "EXPUNGE" => {
                let outcome = commands::expunge::uid_expunge(
                    tag,
                    args,
                    &self.mail_root,
                    self.selected(),
                    self.state.saved_search_uids(),
                    self.state.feature_enabled("QRESYNC"),
                )
                .await;
                self.apply_selection_effect(outcome.selection_effect)
                    .await?;
                self.respond(reader, tag, "UID EXPUNGE", outcome.response.encode())
                    .await
            }
            "COPY" | "MOVE" => {
                let name = format!("UID {subcommand}");
                self.transfer(reader, tag, &name, args, true).await
            }
            _ => {
                self.send(reader, format!("{tag} BAD Unsupported UID subcommand\r\n"))
                    .await
            }
        }
    }

    pub(super) async fn fetch(
        &mut self,
        reader: &mut ImapReader,
        tag: &str,
        args: &str,
        uid: bool,
    ) -> Result<Flow> {
        let outcome = commands::fetch::handle(
            reader,
            tag,
            args,
            &self.mail_root,
            self.selected(),
            self.state.saved_search_uids(),
            uid,
            commands::fetch::FetchContext {
                qresync: self.state.feature_enabled("QRESYNC"),
                condstore: self.state.condstore_enabled(),
                imap4rev2: self.state.imap4rev2_enabled(),
            },
        )
        .await?;
        if outcome.condstore_activated {
            self.state.activate_condstore();
        }
        self.apply_flag_updates(&outcome.flag_updates);
        Ok(Flow::Continue)
    }

    pub(super) async fn store(
        &mut self,
        reader: &mut ImapReader,
        tag: &str,
        args: &str,
        uid: bool,
    ) -> Result<Flow> {
        let outcome = commands::store::handle(
            tag,
            args,
            &self.mail_root,
            self.selected(),
            self.state.saved_search_uids(),
            uid,
            commands::store::StoreContext {
                condstore: self.state.condstore_enabled(),
                imap4rev2: self.state.imap4rev2_enabled(),
            },
        )
        .await;
        if outcome.condstore_activated {
            self.state.activate_condstore();
        }
        self.apply_flag_updates(&outcome.flag_updates);
        let name = if uid { "UID STORE" } else { "STORE" };
        self.respond(reader, tag, name, outcome.response.encode())
            .await
    }

    pub(super) async fn search(
        &mut self,
        reader: &mut ImapReader,
        tag: &str,
        args: &str,
        uid: bool,
    ) -> Result<Flow> {
        let outcome = commands::search::handle(
            tag,
            args,
            self.selected(),
            self.state.saved_search_uids(),
            uid,
            self.state.utf8_enabled(),
        )
        .await;
        if let Some(saved) = outcome.saved_uids {
            self.state.save_search_uids(saved);
        }
        let name = if uid { "UID SEARCH" } else { "SEARCH" };
        self.respond(reader, tag, name, outcome.response.encode())
            .await
    }

    pub(super) async fn sort(
        &self,
        reader: &mut ImapReader,
        tag: &str,
        args: &str,
        uid: bool,
    ) -> Result<Flow> {
        let response = commands::sort_thread::sort(
            tag,
            args,
            self.selected(),
            self.state.saved_search_uids(),
            uid,
        )
        .await
        .encode();
        let name = if uid { "UID SORT" } else { "SORT" };
        self.respond(reader, tag, name, response).await
    }

    pub(super) async fn thread(
        &self,
        reader: &mut ImapReader,
        tag: &str,
        args: &str,
        uid: bool,
    ) -> Result<Flow> {
        let response = commands::sort_thread::thread(
            tag,
            args,
            self.selected(),
            self.state.saved_search_uids(),
            uid,
        )
        .await
        .encode();
        let name = if uid { "UID THREAD" } else { "THREAD" };
        self.respond(reader, tag, name, response).await
    }

    /// COPY and MOVE (`name` is the command as logged, e.g. "UID MOVE").
    pub(super) async fn transfer(
        &mut self,
        reader: &mut ImapReader,
        tag: &str,
        name: &str,
        args: &str,
        uid: bool,
    ) -> Result<Flow> {
        self.sync_quota().await?;
        let outcome = commands::transfer::handle(
            tag,
            name,
            args,
            &self.mail_root,
            self.address(),
            self.selected(),
            self.state.saved_search_uids(),
            uid,
            self.state.utf8_enabled(),
            self.state.feature_enabled("QRESYNC"),
        )
        .await;
        if let Some(selected) = self.selected.as_mut() {
            selected.remove_reported(&outcome.removed_uids);
        }
        self.respond(reader, tag, name, outcome.response.encode())
            .await
    }

    /// EXPUNGE and CLOSE.
    pub(super) async fn expunge(
        &mut self,
        reader: &mut ImapReader,
        call: &Invocation<'_>,
    ) -> Result<Flow> {
        let outcome = if matches!(call.command, parser::Command::Close) {
            commands::expunge::close(call.tag, &self.mail_root, self.selected()).await
        } else {
            commands::expunge::expunge(
                call.tag,
                &self.mail_root,
                self.selected(),
                self.state.feature_enabled("QRESYNC"),
            )
            .await
        };
        self.apply_selection_effect(outcome.selection_effect)
            .await?;
        self.respond(reader, call.tag, &call.name, outcome.response.encode())
            .await
    }

    pub(super) async fn idle(
        &mut self,
        reader: &mut ImapReader,
        call: &Invocation<'_>,
    ) -> Result<Flow> {
        let options = self.sync_options(true);
        let outcome = commands::idle::handle(
            reader,
            call.tag,
            &self.mail_root,
            &mut self.selected,
            options,
        )
        .await?;
        Ok(if outcome == commands::idle::Outcome::Disconnected {
            Flow::Close
        } else {
            Flow::Continue
        })
    }

    async fn apply_selection_effect(&mut self, effect: SelectionEffect) -> Result<()> {
        match effect {
            SelectionEffect::Remove(uids) => {
                if let Some(selected) = self.selected.as_mut() {
                    selected.remove_reported(&uids);
                }
            }
            SelectionEffect::Clear => self.clear_selection(),
            SelectionEffect::Keep => {}
        }
        Ok(())
    }

    /// Record flag changes the client already saw in this command's own
    /// responses, so the next synchronization does not repeat them.
    fn apply_flag_updates(&mut self, updates: &[(u64, Vec<String>, u64)]) {
        if let Some(selected) = self.selected.as_mut() {
            selected.apply_flag_updates(updates);
        }
    }
}
