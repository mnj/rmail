//! Commands on the selected mailbox: FETCH, STORE, SEARCH, SORT, THREAD,
//! COPY/MOVE, EXPUNGE/CLOSE, IDLE and their UID forms.

use anyhow::Result;

use super::{Flow, ImapReader, Invocation, Session, write};
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
        if self.state.uidonly_enabled()
            && commands::uid_search_uses_sequence_numbers(subcommand, args)
        {
            let response = crate::response::Response::new()
                .status(commands::uid_required(tag))
                .encode();
            return self.respond(reader, tag, &call.name, response).await;
        }
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
                    self.state.vanished_enabled(),
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
            "REPLACE" => self.replace(reader, tag, "UID REPLACE", args, true).await,
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
                qresync: self.state.vanished_enabled(),
                condstore: self.state.condstore_enabled(),
                imap4rev2: self.state.imap4rev2_enabled(),
                uidonly: self.state.uidonly_enabled(),
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
                uidonly: self.state.uidonly_enabled(),
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
            self.state.imap4rev2_enabled(),
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
            self.state.vanished_enabled(),
        )
        .await;
        if let Some(selected) = self.selected.as_mut() {
            selected.remove_reported(&outcome.removed_uids);
        }
        self.respond(reader, tag, name, outcome.response.encode())
            .await
    }

    /// REPLACE and UID REPLACE (RFC 8508). Reported like MOVE: the new
    /// message's APPENDUID in an untagged OK, EXISTS when it went to the
    /// selected mailbox, then EXPUNGE (or VANISHED) for the old message.
    pub(super) async fn replace(
        &mut self,
        reader: &mut ImapReader,
        tag: &str,
        name: &str,
        args: &str,
        uid: bool,
    ) -> Result<Flow> {
        self.sync_quota().await?;
        let outcome = commands::replace::handle(
            reader,
            tag,
            name,
            args,
            commands::replace::Context {
                mail_root: &self.mail_root,
                address: self.address(),
                selected: self.selected(),
                uid_mode: uid,
                utf8_accept: self.state.utf8_enabled(),
            },
        )
        .await?;
        let replaced = match outcome {
            commands::replace::Outcome::Failed { close_connection } => {
                return Ok(if close_connection {
                    Flow::Close
                } else {
                    Flow::Continue
                });
            }
            commands::replace::Outcome::Replaced(replaced) => replaced,
        };
        write(
            reader,
            format!(
                "* OK [APPENDUID {} {}] Replacement message stored\r\n",
                replaced.uidvalidity, replaced.uid
            )
            .as_bytes(),
        )
        .await?;
        if replaced.target_is_selected {
            // Report the new message now; expunges by others wait, as the
            // old message's sequence number must stay valid until its own
            // EXPUNGE below.
            let options = self.sync_options(false);
            super::sync_selected_mailbox(reader, &self.mail_root, &mut self.selected, options)
                .await?;
        }
        let vanished = self.state.vanished_enabled();
        let mut response = String::new();
        if let (Some(old_uid), Some(selected)) = (replaced.expunged_uid, self.selected.as_mut()) {
            if vanished {
                response.push_str(&format!("* VANISHED {old_uid}\r\n"));
            } else if let Some(index) = selected
                .msgs
                .iter()
                .position(|message| message.0 == old_uid)
            {
                response.push_str(&format!("* {} EXPUNGE\r\n", index + 1));
            }
            selected.remove_reported(&[old_uid]);
        }
        response.push_str(&format!("{tag} OK {name} completed\r\n"));
        self.respond(reader, tag, name, response).await
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
                self.state.vanished_enabled(),
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
        let format = self.notify_format();
        let notify = match (
            self.notify.as_mut(),
            self.state.authenticated_mailbox.as_deref(),
        ) {
            (Some(notifier), Some(address)) => Some(commands::idle::Notify {
                notifier,
                account: commands::notify::Account {
                    mail_root: &self.mail_root,
                    address,
                },
                format,
            }),
            _ => None,
        };
        let outcome = commands::idle::handle(
            reader,
            call.tag,
            &self.mail_root,
            &mut self.selected,
            options,
            self.auth_policy.timeouts().idle,
            notify,
        )
        .await?;
        if self
            .notify
            .as_ref()
            .is_some_and(|notifier| !notifier.is_active())
        {
            self.notify = None;
        }
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
