//! CAPABILITY, LOGIN and AUTHENTICATE.

use anyhow::Result;

use super::{Flow, ImapReader, Invocation, Session, write};
use crate::{auth as sasl, commands, parser, response};

impl Session {
    pub(super) async fn capability(
        &self,
        reader: &mut ImapReader,
        call: &Invocation<'_>,
    ) -> Result<Flow> {
        let phase = if self.state.selected_mailbox.is_some() {
            response::CapabilityPhase::Selected
        } else if self.state.authenticated_mailbox.is_some() {
            response::CapabilityPhase::Authenticated
        } else if self.encrypted {
            response::CapabilityPhase::NotAuthenticatedTls
        } else {
            response::CapabilityPhase::NotAuthenticatedPlain
        };
        let caps = self.capabilities(phase);
        let response = commands::basic::capability(call.tag, &caps).encode();
        self.respond(reader, call.tag, &call.name, response).await
    }

    pub(super) async fn login(
        &mut self,
        reader: &mut ImapReader,
        call: &Invocation<'_>,
    ) -> Result<Flow> {
        let caps = self.capabilities(response::CapabilityPhase::Authenticated);
        let outcome =
            commands::login::handle(call.tag, call.args, self.db_path.as_ref(), self.peer, &caps)
                .await;
        self.set_authenticated(outcome.authenticated_mailbox);
        self.respond(reader, call.tag, &call.name, outcome.response.encode())
            .await
    }

    pub(super) async fn authenticate(
        &mut self,
        reader: &mut ImapReader,
        call: &Invocation<'_>,
    ) -> Result<Flow> {
        let tag = call.tag;
        let (mechanism, initial_response) = match parser::parse_authenticate_args(call.args) {
            Ok(parsed) => parsed,
            Err(error) => {
                let reply = format!("{tag} BAD Invalid AUTHENTICATE arguments: {error:?}\r\n");
                write(reader, reply.as_bytes()).await?;
                return Ok(Flow::Continue);
            }
        };
        let Some(metadata) = self.auth_policy.mechanism(&mechanism) else {
            write(
                reader,
                format!("{tag} NO Unsupported authentication mechanism\r\n").as_bytes(),
            )
            .await?;
            return Ok(Flow::Continue);
        };
        if let Some(remaining) = self
            .peer
            .and_then(|peer| sasl::auth_block_remaining(peer.ip()))
        {
            let reply = format!(
                "{tag} NO Too many failed auth attempts; try again in {}s\r\n",
                remaining.as_secs()
            );
            write(reader, reply.as_bytes()).await?;
            return Ok(Flow::Continue);
        }
        if !self.encrypted && metadata.security != sasl::SaslSecurity::ChallengeResponse {
            write(
                reader,
                format!("{tag} NO [PRIVACYREQUIRED] Encryption required for authentication\r\n")
                    .as_bytes(),
            )
            .await?;
            return Ok(Flow::Continue);
        }
        if metadata.channel_binding_required
            && (!self.encrypted || !self.channel_bindings.is_available())
        {
            write(
                reader,
                format!("{tag} NO Channel binding is not available\r\n").as_bytes(),
            )
            .await?;
            return Ok(Flow::Continue);
        }

        let caps = self.capabilities(response::CapabilityPhase::Authenticated);
        let initial = initial_response.as_deref();
        let db_path = self.db_path.as_ref();
        let outcome = match mechanism.as_str() {
            "PLAIN" | "LOGIN" => {
                commands::authenticate::handle_password(
                    reader, tag, &mechanism, initial, db_path, self.peer, &caps,
                )
                .await
            }
            "OAUTHBEARER" | "XOAUTH2" => {
                let Some(validator) = self.auth_policy.oauth() else {
                    write(
                        reader,
                        format!("{tag} NO OAuth authentication is unavailable\r\n").as_bytes(),
                    )
                    .await?;
                    return Ok(Flow::Continue);
                };
                commands::authenticate::handle_oauth(
                    reader, tag, &mechanism, initial, db_path, self.peer, validator, &caps,
                )
                .await
            }
            // SCRAM-SHA-256 and SCRAM-SHA-256-PLUS.
            _ => {
                let policy = if metadata.channel_binding_required {
                    sasl::ScramChannelBindingPolicy::Required
                } else if self.scram_plus_advertised() {
                    sasl::ScramChannelBindingPolicy::OfferedButNotSelected
                } else {
                    sasl::ScramChannelBindingPolicy::NotOffered
                };
                commands::authenticate::handle_scram(
                    reader,
                    tag,
                    initial,
                    db_path,
                    self.peer,
                    policy,
                    &self.channel_bindings,
                    &caps,
                )
                .await
            }
        };
        if outcome.disconnected {
            return Ok(Flow::Close);
        }
        self.set_authenticated(outcome.authenticated_mailbox);
        match outcome.response {
            Some(response) => {
                self.respond(reader, tag, &call.name, response.encode())
                    .await
            }
            None => Ok(Flow::Continue),
        }
    }
}
