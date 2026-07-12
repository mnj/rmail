#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MailFromArgs {
    pub(crate) sender: Option<String>,
    pub(crate) declared_size: Option<usize>,
    pub(crate) body: MailBody,
    pub(crate) smtp_utf8: bool,
    pub(crate) has_esmtp_parameters: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvelopeError {
    Syntax,
    UnsupportedParameter,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum MailBody {
    #[default]
    SevenBit,
    EightBitMime,
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
    if command.is_empty()
        || command.starts_with(|character: char| character == ' ' || character == '\t')
        || command.chars().any(|character| character == '\0')
    {
        return Command::BadSyntax;
    }
    let trimmed = command;
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
        "VRFY" if !args.is_empty() => Command::Vrfy,
        "EXPN" if !args.is_empty() => Command::Expn,
        "HELO" | "EHLO" | "MAIL" | "RCPT" | "DATA" | "RSET" | "QUIT" | "STARTTLS" | "AUTH"
        | "VRFY" | "EXPN" => Command::BadSyntax,
        _ => Command::Unknown,
    }
}

pub(crate) fn valid_helo_domain(value: &str) -> bool {
    valid_domain(value, false) || valid_address_literal(value)
}

fn is_atext(character: char) -> bool {
    character.is_ascii_alphanumeric()
        || matches!(
            character,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '/'
                | '='
                | '?'
                | '^'
                | '_'
                | '`'
                | '{'
                | '|'
                | '}'
                | '~'
        )
}

fn valid_local_part(value: &str, allow_utf8: bool) -> bool {
    if value.is_empty() || value.as_bytes().len() > 64 {
        return false;
    }
    if value.starts_with('"') {
        if !value.ends_with('"') || value.len() < 2 {
            return false;
        }
        let mut escaped = false;
        for character in value[1..value.len() - 1].chars() {
            if escaped {
                if character == '\r' || character == '\n' {
                    return false;
                }
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"'
                || character == '\r'
                || character == '\n'
                || (!allow_utf8 && !character.is_ascii())
                || character.is_control()
            {
                return false;
            }
        }
        return !escaped;
    }
    value.split('.').all(|atom| {
        !atom.is_empty()
            && atom
                .chars()
                .all(|character| is_atext(character) || (allow_utf8 && !character.is_ascii()))
    })
}

fn valid_domain(value: &str, allow_utf8: bool) -> bool {
    if value.is_empty() || value.as_bytes().len() > 255 {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.as_bytes().len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|character| {
                character.is_ascii_alphanumeric()
                    || character == '-'
                    || (allow_utf8 && !character.is_ascii() && !character.is_control())
            })
    })
}

fn valid_address_literal(value: &str) -> bool {
    let Some(inner) = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    else {
        return false;
    };
    if let Some(ipv6) = inner
        .strip_prefix("IPv6:")
        .or_else(|| inner.strip_prefix("ipv6:"))
    {
        return ipv6.parse::<std::net::Ipv6Addr>().is_ok();
    }
    inner.parse::<std::net::Ipv4Addr>().is_ok()
}

fn strip_source_route(value: &str) -> Option<&str> {
    if !value.starts_with('@') {
        return Some(value);
    }
    let (route, mailbox) = value.split_once(':')?;
    if route.split(',').all(|domain| {
        domain
            .strip_prefix('@')
            .is_some_and(|domain| valid_domain(domain, false))
    }) {
        Some(mailbox)
    } else {
        None
    }
}

fn parse_mailbox(value: &str, allow_utf8: bool) -> Option<String> {
    let value = strip_source_route(value)?;
    let mut quoted = false;
    let mut escaped = false;
    let mut separator = None;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if quoted && character == '\\' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character == '@' && !quoted {
            separator = Some(index);
        }
    }
    if quoted || escaped {
        return None;
    }
    let separator = separator?;
    let (local, domain_with_at) = value.split_at(separator);
    let domain = &domain_with_at[1..];
    if !valid_local_part(local, allow_utf8)
        || !(valid_domain(domain, allow_utf8) || valid_address_literal(domain))
    {
        return None;
    }
    Some(format!("{local}@{}", domain.to_lowercase()))
}

fn parse_path_with_params<'a>(args: &'a str, keyword: &str) -> Option<(&'a str, &'a str)> {
    let trimmed = args.trim_start();
    let prefix_len = keyword.len();
    if trimmed.len() < prefix_len || !trimmed[..prefix_len].eq_ignore_ascii_case(keyword) {
        return None;
    }
    let mut rest = trimmed[prefix_len..].trim_start();
    if !rest.starts_with('<') || rest.as_bytes().len() > 256 {
        return None;
    }
    let end = rest.find('>')?;
    let path = &rest[..=end];
    rest = rest[end + 1..].trim_start();
    Some((path, rest))
}

pub(crate) fn parse_mail_from_args(args: &str) -> Result<MailFromArgs, EnvelopeError> {
    let (path, params) = parse_path_with_params(args, "FROM:").ok_or(EnvelopeError::Syntax)?;
    let mut declared_size = None;
    let mut body = None;
    let mut smtp_utf8 = false;
    for parameter in params.split_whitespace() {
        if let Some(size) = parameter
            .strip_prefix("SIZE=")
            .or_else(|| parameter.strip_prefix("size="))
        {
            if declared_size.is_some() {
                return Err(EnvelopeError::Syntax);
            }
            declared_size = Some(size.parse().map_err(|_| EnvelopeError::Syntax)?);
        } else if parameter.eq_ignore_ascii_case("BODY=7BIT") {
            if body.replace(MailBody::SevenBit).is_some() {
                return Err(EnvelopeError::Syntax);
            }
        } else if parameter.eq_ignore_ascii_case("BODY=8BITMIME") {
            if body.replace(MailBody::EightBitMime).is_some() {
                return Err(EnvelopeError::Syntax);
            }
        } else if parameter.eq_ignore_ascii_case("SMTPUTF8") {
            if smtp_utf8 {
                return Err(EnvelopeError::Syntax);
            }
            smtp_utf8 = true;
        } else {
            return Err(EnvelopeError::UnsupportedParameter);
        }
    }
    let inner = path
        .strip_prefix('<')
        .and_then(|path| path.strip_suffix('>'))
        .ok_or(EnvelopeError::Syntax)?;
    let sender = if inner.is_empty() {
        None
    } else {
        Some(parse_mailbox(inner, smtp_utf8).ok_or(EnvelopeError::Syntax)?)
    };
    Ok(MailFromArgs {
        sender,
        declared_size,
        body: body.unwrap_or_default(),
        smtp_utf8,
        has_esmtp_parameters: !params.is_empty(),
    })
}

pub(crate) fn parse_rcpt_to_args(args: &str, smtp_utf8: bool) -> Result<String, EnvelopeError> {
    let (path, params) = parse_path_with_params(args, "TO:").ok_or(EnvelopeError::Syntax)?;
    if !params.is_empty() {
        return Err(EnvelopeError::UnsupportedParameter);
    }
    let inner = path
        .strip_prefix('<')
        .and_then(|path| path.strip_suffix('>'))
        .ok_or(EnvelopeError::Syntax)?;
    if inner.is_empty() {
        return Err(EnvelopeError::Syntax);
    }
    parse_mailbox(inner, smtp_utf8).ok_or(EnvelopeError::Syntax)
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
        assert!(parse_mail_from_args("FROM:<a@b> SIZE=1 SIZE=2").is_err());
        assert_eq!(
            parse_mail_from_args("FROM:<a@b> UNKNOWN=x"),
            Err(EnvelopeError::UnsupportedParameter)
        );
        assert_eq!(
            parse_mail_from_args("FROM:<a@b> SIZE=42 BODY=8BITMIME SMTPUTF8"),
            Ok(MailFromArgs {
                sender: Some("a@b".to_string()),
                declared_size: Some(42),
                body: MailBody::EightBitMime,
                smtp_utf8: true,
                has_esmtp_parameters: true,
            })
        );
        assert_eq!(
            parse_rcpt_to_args("TO:<a@b> NOTIFY=SUCCESS", false),
            Err(EnvelopeError::UnsupportedParameter)
        );
        assert!(parse_mail_from_args("FROM:<a..b@example.test>").is_err());
        assert!(parse_mail_from_args("FROM:<a@example..test>").is_err());
        assert!(parse_mail_from_args("FROM:<ü@example.test>").is_err());
        assert!(parse_mail_from_args("FROM:<ü@example.test> SMTPUTF8").is_ok());
        assert_eq!(
            parse_rcpt_to_args("TO:<\"quoted local\"@[127.0.0.1]>", false),
            Ok("\"quoted local\"@[127.0.0.1]".to_string())
        );
        assert_eq!(
            parse_rcpt_to_args("TO:<@old.example,@relay.example:user@Example.TEST>", false),
            Ok("user@example.test".to_string())
        );
    }

    #[test]
    fn command_and_helo_grammar_reject_leading_space_missing_args_and_bad_domains() {
        assert_eq!(parse_command(" DATA"), Command::BadSyntax);
        assert_eq!(parse_command("VRFY"), Command::BadSyntax);
        assert_eq!(parse_command("QUITzzz"), Command::Unknown);
        assert!(valid_helo_domain("mail.example.test"));
        assert!(valid_helo_domain("[IPv6:2001:db8::1]"));
        assert!(!valid_helo_domain("-bad.example"));
        assert!(!valid_helo_domain("bad..example"));
    }

    #[tokio::test]
    async fn bounded_reader_drains_an_overlong_line_and_preserves_the_next_command() {
        let input = format!("{}\r\nNOOP\r\n", "x".repeat(32));
        let mut reader = tokio::io::BufReader::new(input.as_bytes());
        assert_eq!(
            read_bounded_line(&mut reader, 16).await.unwrap(),
            BoundedLine::TooLong
        );
        assert_eq!(
            read_bounded_line(&mut reader, 16).await.unwrap(),
            BoundedLine::Line(b"NOOP\r\n".to_vec())
        );
    }

    #[test]
    fn sasl_capabilities_are_validated_and_follow_configuration_order() {
        let configured = vec!["SCRAM-SHA-256".to_string(), "PLAIN".to_string()];
        validate_sasl_mechanisms(&configured).unwrap();
        assert_eq!(
            advertised_sasl_mechanisms(&configured),
            "SCRAM-SHA-256 PLAIN"
        );
        assert!(validate_sasl_mechanisms(&["XOAUTH2".to_string()]).is_err());
        assert!(validate_sasl_mechanisms(&["PLAIN".to_string(), "plain".to_string()]).is_err());
    }
}
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

pub(crate) const MAX_COMMAND_LINE_BYTES: usize = 512;
pub(crate) const MAX_AUTH_LINE_BYTES: usize = 12 * 1024;
pub(crate) const SMTP_SASL_MECHANISMS: &[&str] = &["PLAIN", "LOGIN", "SCRAM-SHA-256"];

pub(crate) fn validate_sasl_mechanisms(configured: &[String]) -> anyhow::Result<()> {
    if configured.is_empty() {
        anyhow::bail!("security.smtp_sasl_mechanisms must not be empty");
    }
    let mut seen = Vec::new();
    for mechanism in configured {
        let canonical = SMTP_SASL_MECHANISMS
            .iter()
            .copied()
            .find(|supported| supported.eq_ignore_ascii_case(mechanism))
            .ok_or_else(|| anyhow::anyhow!("unsupported SMTP SASL mechanism {mechanism:?}"))?;
        if seen.contains(&canonical) {
            anyhow::bail!("duplicate SMTP SASL mechanism {canonical:?}");
        }
        seen.push(canonical);
    }
    Ok(())
}

pub(crate) fn advertised_sasl_mechanisms(configured: &[String]) -> String {
    configured
        .iter()
        .filter_map(|configured| {
            SMTP_SASL_MECHANISMS
                .iter()
                .copied()
                .find(|supported| supported.eq_ignore_ascii_case(configured))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthArgs<'a> {
    pub(crate) mechanism: &'a str,
    pub(crate) initial_response: Option<&'a str>,
}

pub(crate) fn parse_auth_args(args: &str) -> Option<AuthArgs<'_>> {
    let mut parts = args.split_ascii_whitespace();
    let mechanism = parts.next()?;
    let initial_response = parts.next();
    if parts.next().is_some()
        || mechanism.is_empty()
        || !mechanism
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return None;
    }
    Some(AuthArgs {
        mechanism,
        initial_response,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BoundedLine {
    Eof,
    Line(Vec<u8>),
    TooLong,
}

pub(crate) async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> std::io::Result<BoundedLine> {
    let mut line = Vec::new();
    let mut too_long = false;
    loop {
        let (consumed, newline) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                return if too_long {
                    Ok(BoundedLine::TooLong)
                } else if line.is_empty() {
                    Ok(BoundedLine::Eof)
                } else {
                    Ok(BoundedLine::Line(line))
                };
            }
            let consumed = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(available.len(), |index| index + 1);
            if !too_long {
                if line.len().saturating_add(consumed) > limit {
                    too_long = true;
                    line.clear();
                } else {
                    line.extend_from_slice(&available[..consumed]);
                }
            }
            (consumed, available[..consumed].ends_with(b"\n"))
        };
        reader.consume(consumed);
        if newline {
            return if too_long {
                Ok(BoundedLine::TooLong)
            } else {
                Ok(BoundedLine::Line(line))
            };
        }
    }
}
