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

pub(crate) fn command_spec(command: &str, args: &str) -> Option<CommandSpec> {
    let upper = command.to_ascii_uppercase();
    match upper.as_str() {
        "CAPABILITY" | "NOOP" | "LOGOUT" | "ID" => Some(ANY),
        "STARTTLS" => Some(NOT_AUTH),
        "LOGIN" => Some(LOGIN),
        "AUTHENTICATE" => Some(NOT_AUTH),
        "APPEND" | "CREATE" | "DELETE" | "RENAME" | "LIST" | "XLIST" | "LSUB" | "NAMESPACE"
        | "STATUS" | "SUBSCRIBE" | "UNSUBSCRIBE" | "ENABLE" | "COMPRESS" => Some(AUTH),
        "SELECT" | "EXAMINE" => Some(AUTH),
        "CHECK" | "CLOSE" | "EXPUNGE" | "FETCH" | "SEARCH" | "SORT" | "THREAD" | "STORE"
        | "COPY" | "MOVE" | "UNSELECT" | "IDLE" => {
            let mut spec = if matches!(
                upper.as_str(),
                "FETCH" | "SEARCH" | "SORT" | "THREAD" | "STORE" | "COPY" | "MOVE"
            ) {
                SELECTED_USES_SEQS
            } else if matches!(upper.as_str(), "CLOSE" | "EXPUNGE" | "IDLE") {
                SELECTED_BREAKS_SEQS
            } else {
                SELECTED
            };
            if upper == "IDLE" {
                spec.requires_sync = true;
            }
            Some(spec)
        }
        "UID" => {
            let subcommand = args
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_uppercase();
            match subcommand.as_str() {
                "FETCH" | "SEARCH" | "SORT" | "THREAD" | "STORE" | "COPY" | "MOVE" => {
                    Some(CommandSpec {
                        auth: CommandAuth::Selected,
                        tls_required: false,
                        uses_sequences: false,
                        breaks_sequences: true,
                        requires_sync: false,
                    })
                }
                "EXPUNGE" => Some(CommandSpec {
                    auth: CommandAuth::Selected,
                    tls_required: false,
                    uses_sequences: false,
                    breaks_sequences: true,
                    requires_sync: true,
                }),
                _ => Some(SELECTED),
            }
        }
        _ => None,
    }
}
