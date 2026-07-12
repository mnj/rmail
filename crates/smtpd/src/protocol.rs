#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MailFromArgs {
    pub(crate) sender: Option<String>,
    pub(crate) declared_size: Option<usize>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Command<'a> {
    Helo(&'a str),
    Ehlo(&'a str),
    Mail(&'a str),
    Rcpt(&'a str),
    Data,
    Rset,
    Noop,
    Quit,
    StartTls,
    Auth(&'a str),
    Vrfy,
    Expn,
    Unknown,
    BadSyntax,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionContext {
    pub(crate) greeted: bool,
    pub(crate) extended_smtp: bool,
    pub(crate) encrypted: bool,
    pub(crate) authenticated: bool,
    pub(crate) transaction_active: bool,
    pub(crate) recipients: usize,
}

pub(crate) fn preflight(command: &Command<'_>, session: SessionContext) -> Option<&'static [u8]> {
    match command {
        Command::Mail(_) if !session.greeted => Some(b"503 5.5.1 Send HELO/EHLO first\r\n"),
        Command::Rcpt(_) if !session.greeted => Some(b"503 5.5.1 Send HELO/EHLO first\r\n"),
        Command::Rcpt(_) if !session.transaction_active => {
            Some(b"503 5.5.1 MAIL required before RCPT\r\n")
        }
        Command::Data if !session.greeted => Some(b"503 5.5.1 Send HELO/EHLO first\r\n"),
        Command::Data if !session.transaction_active => {
            Some(b"503 5.5.1 MAIL required before DATA\r\n")
        }
        Command::Data if session.recipients == 0 => {
            Some(b"503 5.5.1 RCPT required before DATA\r\n")
        }
        Command::Auth(_) if !session.extended_smtp => Some(b"503 5.5.1 Send EHLO before AUTH\r\n"),
        Command::Auth(_) if session.authenticated => Some(b"503 5.5.0 Already authenticated\r\n"),
        Command::Auth(_) if session.transaction_active => {
            Some(b"503 5.5.1 AUTH not permitted during a mail transaction\r\n")
        }
        Command::Auth(_) if !session.encrypted => {
            Some(b"538 5.7.11 Encryption required for authentication\r\n")
        }
        Command::StartTls if !session.extended_smtp => {
            Some(b"503 5.5.1 Send EHLO before STARTTLS\r\n")
        }
        Command::StartTls if session.encrypted => Some(b"503 5.5.1 TLS already active\r\n"),
        Command::StartTls if session.transaction_active => {
            Some(b"503 5.5.1 STARTTLS not permitted during a mail transaction\r\n")
        }
        _ => None,
    }
}

pub(crate) fn parse_command(command: &str) -> Command<'_> {
    let trimmed = command.trim();
    let (verb, args) =
        match trimmed.split_once(|character: char| character == ' ' || character == '\t') {
            Some((verb, rest)) => (verb, rest.trim_start()),
            None => (trimmed, ""),
        };
    let verb_upper = verb.to_ascii_uppercase();
    match verb_upper.as_str() {
        "HELO" if !args.is_empty() => Command::Helo(args),
        "EHLO" if !args.is_empty() => Command::Ehlo(args),
        "MAIL" if !args.is_empty() => Command::Mail(args),
        "RCPT" if !args.is_empty() => Command::Rcpt(args),
        "DATA" if args.is_empty() => Command::Data,
        "RSET" if args.is_empty() => Command::Rset,
        "NOOP" => Command::Noop,
        "QUIT" if args.is_empty() => Command::Quit,
        "STARTTLS" if args.is_empty() => Command::StartTls,
        "AUTH" if !args.is_empty() => Command::Auth(args),
        "VRFY" => Command::Vrfy,
        "EXPN" => Command::Expn,
        "HELO" | "EHLO" | "MAIL" | "RCPT" | "DATA" | "RSET" | "QUIT" | "STARTTLS" | "AUTH" => {
            Command::BadSyntax
        }
        _ if [
            "HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "QUIT", "STARTTLS", "AUTH",
        ]
        .iter()
        .any(|known| verb_upper.starts_with(known)) =>
        {
            Command::BadSyntax
        }
        _ => Command::Unknown,
    }
}

fn extract_address(value: &str) -> Option<String> {
    let value = value
        .trim()
        .trim_matches(|character| matches!(character, '<' | '>' | ' '));
    if value.contains('@') && !value.chars().any(char::is_whitespace) {
        Some(value.to_ascii_lowercase())
    } else {
        None
    }
}

fn parse_path_with_params<'a>(args: &'a str, keyword: &str) -> Option<(&'a str, &'a str)> {
    let trimmed = args.trim_start();
    let prefix_len = keyword.len();
    if trimmed.len() < prefix_len || !trimmed[..prefix_len].eq_ignore_ascii_case(keyword) {
        return None;
    }
    let mut rest = trimmed[prefix_len..].trim_start();
    if !rest.starts_with('<') {
        return None;
    }
    let end = rest.find('>')?;
    let path = &rest[..=end];
    rest = rest[end + 1..].trim_start();
    Some((path, rest))
}

pub(crate) fn parse_mail_from_args(args: &str) -> Option<MailFromArgs> {
    let (path, params) = parse_path_with_params(args, "FROM:")?;
    let sender = if path == "<>" {
        None
    } else {
        extract_address(path).map(Some)?
    };
    let mut declared_size = None;
    for parameter in params.split_whitespace() {
        if let Some(size) = parameter
            .strip_prefix("SIZE=")
            .or_else(|| parameter.strip_prefix("size="))
        {
            if declared_size.is_some() {
                return None;
            }
            declared_size = Some(size.parse().ok()?);
        } else if parameter.eq_ignore_ascii_case("BODY=7BIT")
            || parameter.eq_ignore_ascii_case("BODY=8BITMIME")
            || parameter.eq_ignore_ascii_case("SMTPUTF8")
        {
            continue;
        } else {
            return None;
        }
    }
    Some(MailFromArgs {
        sender,
        declared_size,
    })
}

pub(crate) fn parse_rcpt_to_args(args: &str) -> Option<String> {
    let (path, params) = parse_path_with_params(args, "TO:")?;
    let address = extract_address(path)?;
    for parameter in params.split_whitespace() {
        let uppercase = parameter.to_ascii_uppercase();
        if !(uppercase == "NOTIFY=NEVER"
            || uppercase.starts_with("NOTIFY=")
            || uppercase.starts_with("ORCPT=")
            || uppercase.starts_with('X'))
        {
            return None;
        }
    }
    Some(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preflight_enforces_smtp_transaction_and_auth_states() {
        let initial = SessionContext {
            greeted: false,
            extended_smtp: false,
            encrypted: false,
            authenticated: false,
            transaction_active: false,
            recipients: 0,
        };
        assert!(preflight(&Command::Mail("FROM:<a@b>"), initial).is_some());
        assert!(preflight(&Command::Auth("PLAIN"), initial).is_some());
        assert!(preflight(&Command::StartTls, initial).is_some());

        let ready = SessionContext {
            greeted: true,
            extended_smtp: true,
            encrypted: true,
            ..initial
        };
        assert!(preflight(&Command::Auth("PLAIN"), ready).is_none());
        assert!(preflight(&Command::Data, ready).is_some());
        assert!(
            preflight(
                &Command::Auth("PLAIN"),
                SessionContext {
                    transaction_active: true,
                    ..ready
                }
            )
            .is_some()
        );
        assert!(
            preflight(
                &Command::Auth("PLAIN"),
                SessionContext {
                    authenticated: true,
                    ..ready
                }
            )
            .is_some()
        );
    }

    #[test]
    fn envelope_parser_rejects_duplicate_or_unknown_parameters() {
        assert!(parse_mail_from_args("FROM:<a@b> SIZE=1 SIZE=2").is_none());
        assert!(parse_mail_from_args("FROM:<a@b> UNKNOWN=x").is_none());
        assert_eq!(
            parse_mail_from_args("FROM:<a@b> SIZE=42 BODY=8BITMIME SMTPUTF8"),
            Some(MailFromArgs {
                sender: Some("a@b".to_string()),
                declared_size: Some(42),
            })
        );
    }
}
