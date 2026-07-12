#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommandAuth {
    Any,
    NotAuthenticated,
    Authenticated,
    Selected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CommandSpec {
    pub(crate) auth: CommandAuth,
    pub(crate) tls_required: bool,
    pub(crate) uses_sequences: bool,
    pub(crate) breaks_sequences: bool,
    pub(crate) requires_sync: bool,
}

impl CommandSpec {
    pub(crate) fn needs_mailbox_sync(self) -> bool {
        self.requires_sync || self.uses_sequences || self.breaks_sequences
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionContext {
    pub(crate) authenticated: bool,
    pub(crate) selected: bool,
    pub(crate) encrypted: bool,
}

pub(crate) fn preflight(
    spec: Option<CommandSpec>,
    session: SessionContext,
) -> Option<&'static str> {
    let spec = spec?;
    match spec.auth {
        CommandAuth::Any => {}
        CommandAuth::NotAuthenticated if session.authenticated => {
            return Some("BAD Command not allowed after authentication");
        }
        CommandAuth::NotAuthenticated => {}
        CommandAuth::Authenticated if !session.authenticated => {
            return Some("NO Authentication required");
        }
        CommandAuth::Authenticated => {}
        CommandAuth::Selected if !session.authenticated => {
            return Some("NO Authentication required");
        }
        CommandAuth::Selected if !session.selected => return Some("BAD No mailbox selected"),
        CommandAuth::Selected => {}
    }
    if spec.tls_required && !session.encrypted {
        return Some("NO [PRIVACYREQUIRED] Encryption required for authentication");
    }
    None
}

const ANY: CommandSpec = CommandSpec {
    auth: CommandAuth::Any,
    tls_required: false,
    uses_sequences: false,
    breaks_sequences: false,
    requires_sync: false,
};

const NOT_AUTH: CommandSpec = CommandSpec {
    auth: CommandAuth::NotAuthenticated,
    tls_required: false,
    uses_sequences: false,
    breaks_sequences: false,
    requires_sync: false,
};

const AUTH: CommandSpec = CommandSpec {
    auth: CommandAuth::Authenticated,
    tls_required: false,
    uses_sequences: false,
    breaks_sequences: false,
    requires_sync: false,
};

const SELECTED: CommandSpec = CommandSpec {
    auth: CommandAuth::Selected,
    tls_required: false,
    uses_sequences: false,
    breaks_sequences: false,
    requires_sync: false,
};

const SELECTED_USES_SEQS: CommandSpec = CommandSpec {
    auth: CommandAuth::Selected,
    tls_required: false,
    uses_sequences: true,
    breaks_sequences: false,
    requires_sync: false,
};

const SELECTED_BREAKS_SEQS: CommandSpec = CommandSpec {
    auth: CommandAuth::Selected,
    tls_required: false,
    uses_sequences: false,
    breaks_sequences: true,
    requires_sync: true,
};

const LOGIN: CommandSpec = CommandSpec {
    auth: CommandAuth::NotAuthenticated,
    tls_required: true,
    uses_sequences: false,
    breaks_sequences: false,
    requires_sync: false,
};

pub(crate) fn command_spec(command: &Command) -> Option<CommandSpec> {
    match command {
        Command::Capability | Command::Logout | Command::Id => Some(ANY),
        Command::Noop => Some(CommandSpec {
            breaks_sequences: true,
            ..ANY
        }),
        Command::StartTls => Some(NOT_AUTH),
        Command::Login => Some(LOGIN),
        Command::Authenticate => Some(NOT_AUTH),
        Command::Append
        | Command::Create
        | Command::Delete
        | Command::Rename
        | Command::List { .. }
        | Command::Lsub
        | Command::Namespace
        | Command::Status
        | Command::Subscribe { .. }
        | Command::Enable
        | Command::Compress
        | Command::Select { .. } => Some(AUTH),
        Command::Fetch
        | Command::Search
        | Command::Sort
        | Command::Thread
        | Command::Store
        | Command::Copy
        | Command::Move => Some(SELECTED_USES_SEQS),
        Command::Close | Command::Expunge => Some(SELECTED_BREAKS_SEQS),
        Command::Idle => Some(CommandSpec {
            requires_sync: true,
            ..SELECTED_BREAKS_SEQS
        }),
        Command::Check => Some(CommandSpec {
            breaks_sequences: true,
            requires_sync: true,
            ..SELECTED
        }),
        Command::Unselect => Some(SELECTED),
        Command::Uid { command } => match command {
            UidCommand::Fetch
            | UidCommand::Search
            | UidCommand::Sort
            | UidCommand::Thread
            | UidCommand::Store
            | UidCommand::Copy
            | UidCommand::Move => Some(CommandSpec {
                auth: CommandAuth::Selected,
                tls_required: false,
                uses_sequences: false,
                breaks_sequences: true,
                requires_sync: false,
            }),
            UidCommand::Expunge => Some(CommandSpec {
                auth: CommandAuth::Selected,
                tls_required: false,
                uses_sequences: false,
                breaks_sequences: true,
                requires_sync: true,
            }),
            UidCommand::Unknown(name) => {
                let _unsupported_subcommand = name;
                Some(SELECTED)
            }
        },
        Command::Unknown { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_request_line;

    #[test]
    fn every_implemented_command_has_typed_registry_metadata() {
        let commands = [
            "CAPABILITY",
            "COMPRESS DEFLATE",
            "LOGIN user password",
            "AUTHENTICATE PLAIN",
            "NOOP",
            "CHECK",
            "CLOSE",
            "COPY 1 Archive",
            "EXPUNGE",
            "FETCH 1 FLAGS",
            "SEARCH ALL",
            "SORT (DATE) UTF-8 ALL",
            "STORE 1 +FLAGS (\\Seen)",
            "THREAD REFERENCES UTF-8 ALL",
            "MOVE 1 Trash",
            "IDLE",
            "LOGOUT",
            "STARTTLS",
            "STATUS INBOX (MESSAGES)",
            "UNSELECT",
            "APPEND INBOX {1}",
            "LIST \"\" \"*\"",
            "XLIST \"\" \"*\"",
            "LSUB \"\" \"*\"",
            "NAMESPACE",
            "ENABLE QRESYNC",
            "CREATE Archive",
            "DELETE Archive",
            "RENAME Old New",
            "SUBSCRIBE Archive",
            "UNSUBSCRIBE Archive",
            "ID NIL",
            "SELECT INBOX",
            "EXAMINE INBOX",
        ];
        for command in commands {
            let line = format!("A1 {command}");
            let request = parse_request_line(&line).unwrap();
            assert!(
                !matches!(request.command, Command::Unknown { .. }),
                "{command} parsed as unknown"
            );
            assert!(
                command_spec(&request.command).is_some(),
                "{command} has no command metadata"
            );
        }
    }

    #[test]
    fn uid_subcommands_are_typed_and_never_use_sequence_numbers() {
        for subcommand in [
            "COPY 1 Archive",
            "EXPUNGE 1",
            "FETCH 1 FLAGS",
            "MOVE 1 Trash",
            "SEARCH ALL",
            "SORT (DATE) UTF-8 ALL",
            "STORE 1 +FLAGS (\\Seen)",
            "THREAD REFERENCES UTF-8 ALL",
        ] {
            let line = format!("A1 UID {subcommand}");
            let request = parse_request_line(&line).unwrap();
            assert!(
                matches!(&request.command, Command::Uid { command } if !matches!(command, UidCommand::Unknown(_))),
                "UID {subcommand} was not typed"
            );
            let spec = command_spec(&request.command).unwrap();
            assert_eq!(spec.auth, CommandAuth::Selected);
            assert!(!spec.uses_sequences);
        }
    }

    #[test]
    fn unknown_top_level_commands_are_not_registered() {
        let request = parse_request_line("A1 X-UNKNOWN arg").unwrap();
        assert!(matches!(request.command, Command::Unknown { .. }));
        assert!(command_spec(&request.command).is_none());
    }

    #[test]
    fn preflight_enforces_state_and_transport_policy() {
        let plain_unauthenticated = SessionContext {
            authenticated: false,
            selected: false,
            encrypted: false,
        };
        assert_eq!(
            preflight(Some(LOGIN), plain_unauthenticated),
            Some("NO [PRIVACYREQUIRED] Encryption required for authentication")
        );
        assert_eq!(
            preflight(Some(SELECTED), plain_unauthenticated),
            Some("NO Authentication required")
        );
        assert_eq!(
            preflight(
                Some(SELECTED),
                SessionContext {
                    authenticated: true,
                    ..plain_unauthenticated
                }
            ),
            Some("BAD No mailbox selected")
        );
        assert_eq!(
            preflight(
                Some(NOT_AUTH),
                SessionContext {
                    authenticated: true,
                    encrypted: true,
                    ..plain_unauthenticated
                }
            ),
            Some("BAD Command not allowed after authentication")
        );
    }

    #[test]
    fn synchronization_policy_matches_command_sequence_effects() {
        for command in [
            "NOOP",
            "CHECK",
            "FETCH 1 FLAGS",
            "UID FETCH 1 FLAGS",
            "EXPUNGE",
        ] {
            let line = format!("A1 {command}");
            let request = parse_request_line(&line).unwrap();
            assert!(
                command_spec(&request.command).unwrap().needs_mailbox_sync(),
                "{command}"
            );
        }
        for command in ["CAPABILITY", "CREATE Archive", "STATUS INBOX (MESSAGES)"] {
            let line = format!("A1 {command}");
            let request = parse_request_line(&line).unwrap();
            assert!(
                !command_spec(&request.command).unwrap().needs_mailbox_sync(),
                "{command}"
            );
        }
    }
}
use crate::parser::{Command, UidCommand};
pub(crate) mod append;
pub(crate) mod authenticate;
pub(crate) mod basic;
pub(crate) mod enable;
pub(crate) mod expunge;
pub(crate) mod fetch;
pub(crate) mod idle;
pub(crate) mod list;
pub(crate) mod login;
pub(crate) mod mailboxes;
pub(crate) mod search;
pub(crate) mod select;
pub(crate) mod sort_thread;
pub(crate) mod status;
pub(crate) mod store;
pub(crate) mod transfer;
