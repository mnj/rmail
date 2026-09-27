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
            self.state.feature_enabled("QRESYNC"),
        )
        .await?;
        if outcome.refresh_selected {
            self.refresh_selected().await?;
        }
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
        )
        .await;
        if outcome.refresh_selected {
            self.refresh_selected().await?;
        }
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
        )
        .await;
        if outcome.refresh_selected {
            self.refresh_selected().await?;
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
        let qresync = self.state.feature_enabled("QRESYNC");
        let outcome = commands::idle::handle(
            reader,
            call.tag,
            &self.mail_root,
            &mut self.selected,
            qresync,
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
            SelectionEffect::Refresh => self.refresh_selected().await?,
            SelectionEffect::Clear => self.clear_selection(),
            SelectionEffect::Keep => {}
        }
        Ok(())
    }
}
