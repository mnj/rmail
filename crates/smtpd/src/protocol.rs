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
    if !params.is_empty() {
        return None;
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
        assert!(parse_rcpt_to_args("TO:<a@b> NOTIFY=SUCCESS").is_none());
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
