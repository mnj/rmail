#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ImapArg {
    Atom(String),
    String(String),
    Nil,
    List(Vec<ImapArg>),
    LiteralSize {
        size: usize,
        non_sync: bool,
        literal8: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParseError {
    UnexpectedEnd,
    UnexpectedByte(char),
    UnterminatedString,
    UnterminatedList,
    InvalidLiteral,
    InvalidDateTime,
    InvalidAtom,
    TrailingData,
    InvalidTag,
    TagTooLong,
    MissingCommand,
}

impl ImapArg {
    pub(crate) fn as_text(&self) -> Option<&str> {
        match self {
            ImapArg::Atom(value) | ImapArg::String(value) => Some(value),
            ImapArg::Nil | ImapArg::List(_) | ImapArg::LiteralSize { .. } => None,
        }
    }
}

struct ArgParser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> ArgParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            pos: 0,
        }
    }

    fn eof(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_spaces(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }

    fn parse_args(&mut self) -> Result<Vec<ImapArg>, ParseError> {
        let mut args = Vec::new();
        self.skip_spaces();
        while !self.eof() {
            if self.peek() == Some(b')') {
                return Err(ParseError::UnexpectedByte(')'));
            }
            args.push(self.parse_arg()?);
            self.skip_spaces();
        }
        Ok(args)
    }

    fn parse_list(&mut self) -> Result<ImapArg, ParseError> {
        self.expect(b'(')?;
        let mut items = Vec::new();
        loop {
            self.skip_spaces();
            match self.peek() {
                Some(b')') => {
                    self.pos += 1;
                    return Ok(ImapArg::List(items));
                }
                Some(_) => items.push(self.parse_arg()?),
                None => return Err(ParseError::UnterminatedList),
            }
        }
    }

    fn parse_arg(&mut self) -> Result<ImapArg, ParseError> {
        self.skip_spaces();
        match self.peek() {
            Some(b'"') => self.parse_quoted().map(ImapArg::String),
            Some(b'(') => self.parse_list(),
            Some(b'{') => self.parse_literal(false),
            Some(b'~') => {
                self.pos += 1;
                self.parse_literal(true)
            }
            Some(_) => self.parse_atom(),
            None => Err(ParseError::UnexpectedEnd),
        }
    }

    fn parse_quoted(&mut self) -> Result<String, ParseError> {
        self.expect(b'"')?;
        let mut out = Vec::new();
        let mut escaped = false;
        while let Some(b) = self.bump() {
            if escaped {
                out.push(b);
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                return String::from_utf8(out).map_err(|_| ParseError::InvalidAtom);
            } else if b == b'\r' || b == b'\n' {
                return Err(ParseError::UnexpectedByte(b as char));
            } else {
                out.push(b);
            }
        }
        Err(ParseError::UnterminatedString)
    }

    fn parse_literal(&mut self, literal8: bool) -> Result<ImapArg, ParseError> {
        self.expect(b'{')?;
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.pos == start {
            return Err(ParseError::InvalidLiteral);
        }
        let size = std::str::from_utf8(&self.input[start..self.pos])
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or(ParseError::InvalidLiteral)?;
        let non_sync = if self.peek() == Some(b'+') {
            self.pos += 1;
            true
        } else {
            false
        };
        self.expect(b'}')?;
        Ok(ImapArg::LiteralSize {
            size,
            non_sync,
            literal8,
        })
    }

    fn parse_atom(&mut self) -> Result<ImapArg, ParseError> {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b.is_ascii_whitespace() || matches!(b, b'(' | b')' | b'{' | b'"') {
                break;
            }
            if b < 0x20 || b == 0x7f {
                return Err(ParseError::InvalidAtom);
            }
            self.pos += 1;
        }
        if self.pos == start {
            return Err(ParseError::InvalidAtom);
        }
        let value = String::from_utf8_lossy(&self.input[start..self.pos]).to_string();
        if value.eq_ignore_ascii_case("NIL") {
            Ok(ImapArg::Nil)
        } else {
            Ok(ImapArg::Atom(value))
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), ParseError> {
        match self.bump() {
            Some(b) if b == expected => Ok(()),
            Some(b) => Err(ParseError::UnexpectedByte(b as char)),
            None => Err(ParseError::UnexpectedEnd),
        }
    }
}

pub(crate) fn parse_imap_args(input: &str) -> Result<Vec<ImapArg>, ParseError> {
    ArgParser::new(input).parse_args()
}

pub(crate) fn parse_login_args(input: &str) -> Result<(String, String), ParseError> {
    let args = parse_imap_args(input)?;
    match args.as_slice() {
        [user, pass] => {
            let user = user.as_text().ok_or(ParseError::InvalidAtom)?.to_string();
            let pass = pass.as_text().ok_or(ParseError::InvalidAtom)?.to_string();
            Ok((user, pass))
        }
        _ => Err(ParseError::TrailingData),
    }
}

pub(crate) fn parse_mailbox_argument(input: &str) -> Result<String, ParseError> {
    let arguments = parse_imap_args(input)?;
    let [mailbox] = arguments.as_slice() else {
        return Err(ParseError::TrailingData);
    };
    mailbox
        .as_text()
        .map(str::to_string)
        .ok_or(ParseError::InvalidAtom)
}

pub(crate) fn parse_rename_arguments(input: &str) -> Result<(String, String), ParseError> {
    let arguments = parse_imap_args(input)?;
    let [source, destination] = arguments.as_slice() else {
        return Err(ParseError::TrailingData);
    };
    Ok((
        source
            .as_text()
            .map(str::to_string)
            .ok_or(ParseError::InvalidAtom)?,
        destination
            .as_text()
            .map(str::to_string)
            .ok_or(ParseError::InvalidAtom)?,
    ))
}

pub(crate) fn parse_authenticate_args(input: &str) -> Result<(String, Option<String>), ParseError> {
    let args = parse_imap_args(input)?;
    match args.as_slice() {
        [mechanism] => {
            let mechanism = mechanism
                .as_text()
                .ok_or(ParseError::InvalidAtom)?
                .to_ascii_uppercase();
            Ok((mechanism, None))
        }
        [mechanism, initial_response] => {
            let mechanism = mechanism
                .as_text()
                .ok_or(ParseError::InvalidAtom)?
                .to_ascii_uppercase();
            let initial_response = initial_response
                .as_text()
                .ok_or(ParseError::InvalidAtom)?
                .to_string();
            Ok((mechanism, Some(initial_response)))
        }
        _ => Err(ParseError::TrailingData),
    }
}

pub(crate) fn parse_id_args(
    input: &str,
) -> Result<Option<Vec<(String, Option<String>)>>, ParseError> {
    const MAX_PAIRS: usize = 30;
    const MAX_KEY_BYTES: usize = 30;
    const MAX_VALUE_BYTES: usize = 1024;

    let args = parse_imap_args(input)?;
    let items = match args.as_slice() {
        [ImapArg::Nil] => return Ok(None),
        [ImapArg::List(items)] => items,
        _ => return Err(ParseError::TrailingData),
    };
    if items.len() % 2 != 0 || items.len() / 2 > MAX_PAIRS {
        return Err(ParseError::TrailingData);
    }
    let mut fields = Vec::with_capacity(items.len() / 2);
    for pair in items.chunks_exact(2) {
        let ImapArg::String(key) = &pair[0] else {
            return Err(ParseError::InvalidAtom);
        };
        if key.as_bytes().len() > MAX_KEY_BYTES {
            return Err(ParseError::InvalidAtom);
        }
        let value = match &pair[1] {
            ImapArg::String(value) if value.as_bytes().len() <= MAX_VALUE_BYTES => {
                Some(value.clone())
            }
            ImapArg::Nil => None,
            _ => return Err(ParseError::InvalidAtom),
        };
        fields.push((key.clone(), value));
    }
    Ok(Some(fields))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UidCommand {
    Copy,
    Expunge,
    Fetch,
    Move,
    Search,
    Sort,
    Store,
    Thread,
    Unknown(String),
}

impl UidCommand {
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Copy => "COPY",
            Self::Expunge => "EXPUNGE",
            Self::Fetch => "FETCH",
            Self::Move => "MOVE",
            Self::Search => "SEARCH",
            Self::Sort => "SORT",
            Self::Store => "STORE",
            Self::Thread => "THREAD",
            Self::Unknown(name) => name,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Command {
    Capability,
    Compress,
    Login,
    Authenticate,
    Noop,
    Check,
    Close,
    Copy,
    Expunge,
    Fetch,
    Search,
    Sort,
    Store,
    Thread,
    Move,
    Idle,
    Logout,
    StartTls,
    Status,
    Unselect,
    Append,
    List { kind: &'static str },
    Lsub,
    Namespace,
    Enable,
    Create,
    Delete,
    Rename,
    Subscribe { subscribe: bool },
    Id,
    Select { read_only: bool },
    Uid { command: UidCommand },
    Unknown { name: String },
}

#[derive(Debug, Clone)]
pub(crate) struct RequestLine<'a> {
    pub(crate) tag: &'a str,
    pub(crate) raw_args: &'a str,
    pub(crate) command: Command,
}

impl<'a> RequestLine<'a> {
    pub(crate) fn command_name(&self) -> &str {
        match &self.command {
            Command::Capability => "CAPABILITY",
            Command::Compress => "COMPRESS",
            Command::Login => "LOGIN",
            Command::Authenticate => "AUTHENTICATE",
            Command::Noop => "NOOP",
            Command::Check => "CHECK",
            Command::Close => "CLOSE",
            Command::Copy => "COPY",
            Command::Expunge => "EXPUNGE",
            Command::Fetch => "FETCH",
            Command::Search => "SEARCH",
            Command::Sort => "SORT",
            Command::Store => "STORE",
            Command::Thread => "THREAD",
            Command::Move => "MOVE",
            Command::Idle => "IDLE",
            Command::Logout => "LOGOUT",
            Command::StartTls => "STARTTLS",
            Command::Status => "STATUS",
            Command::Unselect => "UNSELECT",
            Command::Append => "APPEND",
            Command::List { kind } => kind,
            Command::Lsub => "LSUB",
            Command::Namespace => "NAMESPACE",
            Command::Enable => "ENABLE",
            Command::Create => "CREATE",
            Command::Delete => "DELETE",
            Command::Rename => "RENAME",
            Command::Subscribe { subscribe } => {
                if *subscribe {
                    "SUBSCRIBE"
                } else {
                    "UNSUBSCRIBE"
                }
            }
            Command::Id => "ID",
            Command::Select { read_only } => {
                if *read_only {
                    "EXAMINE"
                } else {
                    "SELECT"
                }
            }
            Command::Uid { .. } => "UID",
            Command::Unknown { name } => name.as_str(),
        }
    }

    pub(crate) fn raw_args(&self) -> &str {
        self.raw_args
    }
}

impl Command {
    pub(crate) fn requires_empty_arguments(&self) -> bool {
        matches!(
            self,
            Self::Capability
                | Self::Noop
                | Self::Check
                | Self::Close
                | Self::Expunge
                | Self::Idle
                | Self::Logout
                | Self::Namespace
                | Self::StartTls
                | Self::Unselect
        )
    }
}

pub(crate) fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 1024
        && tag.bytes().all(|byte| {
            (0x21..=0x7e).contains(&byte)
                && !matches!(
                    byte,
                    b'(' | b')' | b'{' | b' ' | b'%' | b'*' | b'"' | b'\\' | b'+'
                )
        })
}

pub(crate) fn parse_request_line(input: &str) -> Result<RequestLine<'_>, ParseError> {
    let tag_end = input
        .find(|ch: char| ch == ' ' || ch == '\t')
        .unwrap_or(input.len());
    let tag = &input[..tag_end];
    if tag.len() > 1024 {
        return Err(ParseError::TagTooLong);
    }
    if !valid_tag(tag) {
        return Err(ParseError::InvalidTag);
    }
    let rest = input[tag_end..].trim_start_matches([' ', '\t']);
    let command_end = rest
        .find(|ch: char| ch == ' ' || ch == '\t')
        .unwrap_or(rest.len());
    let raw_name = &rest[..command_end];
    if raw_name.is_empty() {
        return Err(ParseError::MissingCommand);
    }
    if !raw_name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(ParseError::InvalidAtom);
    }
    let args = rest[command_end..].trim();
    let name = raw_name.to_ascii_uppercase();
    let command = match name.as_str() {
        "CAPABILITY" => Command::Capability,
        "COMPRESS" => Command::Compress,
        "LOGIN" => Command::Login,
        "AUTHENTICATE" => Command::Authenticate,
        "NOOP" => Command::Noop,
        "CHECK" => Command::Check,
        "CLOSE" => Command::Close,
        "COPY" => Command::Copy,
        "EXPUNGE" => Command::Expunge,
        "FETCH" => Command::Fetch,
        "SEARCH" => Command::Search,
        "SORT" => Command::Sort,
        "STORE" => Command::Store,
        "THREAD" => Command::Thread,
        "MOVE" => Command::Move,
        "IDLE" => Command::Idle,
        "LOGOUT" => Command::Logout,
        "STARTTLS" => Command::StartTls,
        "STATUS" => Command::Status,
        "UNSELECT" => Command::Unselect,
        "APPEND" => Command::Append,
        "LIST" | "XLIST" => Command::List {
            kind: if name == "XLIST" { "XLIST" } else { "LIST" },
        },
        "LSUB" => Command::Lsub,
        "NAMESPACE" => Command::Namespace,
        "ENABLE" => Command::Enable,
        "CREATE" => Command::Create,
        "DELETE" => Command::Delete,
        "RENAME" => Command::Rename,
        "SUBSCRIBE" => Command::Subscribe { subscribe: true },
        "UNSUBSCRIBE" => Command::Subscribe { subscribe: false },
        "ID" => Command::Id,
        "SELECT" => Command::Select { read_only: false },
        "EXAMINE" => Command::Select { read_only: true },
        "UID" => {
            let subcommand = args
                .split_ascii_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_uppercase();
            let command = match subcommand.as_str() {
                "COPY" => UidCommand::Copy,
                "EXPUNGE" => UidCommand::Expunge,
                "FETCH" => UidCommand::Fetch,
                "MOVE" => UidCommand::Move,
                "SEARCH" => UidCommand::Search,
                "SORT" => UidCommand::Sort,
                "STORE" => UidCommand::Store,
                "THREAD" => UidCommand::Thread,
                _ => UidCommand::Unknown(subcommand),
            };
            Command::Uid { command }
        }
        _ => Command::Unknown { name },
    };
    Ok(RequestLine {
        tag,
        raw_args: args,
        command,
    })
}

pub(crate) fn unquote(s: &str) -> &str {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        &s[1..(s.len() - 1)]
    } else {
        s
    }
}

pub(crate) fn seqs_from_set(seq_set: &str, total: usize) -> Vec<usize> {
    SequenceSet::parse(seq_set, total as u64)
        .map(|set| {
            (1..=total)
                .filter(|sequence| set.contains(*sequence as u64))
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn uids_from_set(
    uid_set: &str,
    msgs: &[(u64, std::path::PathBuf, Vec<String>, u64)],
) -> Vec<u64> {
    let max_uid = msgs.iter().map(|(uid, _, _, _)| *uid).max().unwrap_or(0);
    SequenceSet::parse(uid_set, max_uid)
        .map(|set| {
            msgs.iter()
                .filter_map(|(uid, _, _, _)| set.contains(*uid).then_some(*uid))
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SequenceSet {
    ranges: Vec<(u64, u64)>,
}

fn parse_nz_number(value: &str) -> Option<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| (1..=u64::from(u32::MAX)).contains(value))
}

impl SequenceSet {
    pub(crate) fn parse(input: &str, star_value: u64) -> Option<Self> {
        if input.is_empty() {
            return None;
        }
        let mut ranges = Vec::new();
        for component in input.split(',') {
            let parse_value = |value: &str| {
                if value == "*" {
                    Some(star_value)
                } else {
                    value
                        .parse::<u64>()
                        .ok()
                        .filter(|value| (1..=u64::from(u32::MAX)).contains(value))
                }
            };
            let (start, end) = if let Some((start, end)) = component.split_once(':') {
                (parse_value(start)?, parse_value(end)?)
            } else {
                let value = parse_value(component)?;
                (value, value)
            };
            if start == 0 || end == 0 {
                continue;
            }
            ranges.push((start.min(end), start.max(end)));
        }
        (!ranges.is_empty()).then_some(Self { ranges })
    }

    pub(crate) fn parse_nostar(input: &str) -> Option<Self> {
        if input.is_empty() || input.contains('*') {
            return None;
        }
        let mut ranges = Vec::new();
        for component in input.split(',') {
            let (start, end) = if let Some((start, end)) = component.split_once(':') {
                (parse_nz_number(start)?, parse_nz_number(end)?)
            } else {
                let value = parse_nz_number(component)?;
                (value, value)
            };
            if start == 0 || end == 0 {
                return None;
            }
            ranges.push((start.min(end), start.max(end)));
        }
        Some(Self { ranges })
    }

    pub(crate) fn contains(&self, value: u64) -> bool {
        self.ranges
            .iter()
            .any(|(start, end)| (*start..=*end).contains(&value))
    }

    fn cardinality(&self) -> Option<u64> {
        self.ranges.iter().try_fold(0_u64, |count, (start, end)| {
            count.checked_add(end.checked_sub(*start)?.checked_add(1)?)
        })
    }

    fn nth(&self, mut index: u64) -> Option<u64> {
        for (start, end) in &self.ranges {
            let length = end.checked_sub(*start)?.checked_add(1)?;
            if index < length {
                return start.checked_add(index);
            }
            index = index.checked_sub(length)?;
        }
        None
    }

    pub(crate) fn qresync_sample_endpoints(
        sequences: &Self,
        uids: &Self,
    ) -> Option<Vec<(u64, u64)>> {
        if sequences.cardinality()? != uids.cardinality()? {
            return None;
        }
        let mut samples = Vec::with_capacity(uids.ranges.len().saturating_mul(2));
        let mut offset = 0_u64;
        for (uid_start, uid_end) in &uids.ranges {
            samples.push((sequences.nth(offset)?, *uid_start));
            let width = uid_end.checked_sub(*uid_start)?;
            if width > 0 {
                offset = offset.checked_add(width)?;
                samples.push((sequences.nth(offset)?, *uid_end));
            }
            offset = offset.checked_add(1)?;
        }
        Some(samples)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QresyncRequest {
    pub(crate) uidvalidity: u64,
    pub(crate) modseq: u64,
    pub(crate) known_uids: Option<SequenceSet>,
    pub(crate) sample: Option<(SequenceSet, SequenceSet)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SelectRequest {
    pub(crate) mailbox: String,
    pub(crate) condstore: bool,
    pub(crate) qresync: Option<QresyncRequest>,
}

pub(crate) fn parse_select_request(input: &str) -> Result<SelectRequest, ParseError> {
    let args = parse_imap_args(input)?;
    let mailbox = args
        .first()
        .and_then(ImapArg::as_text)
        .ok_or(ParseError::InvalidAtom)?
        .to_string();
    let mut request = SelectRequest {
        mailbox,
        condstore: false,
        qresync: None,
    };
    let options = match args.as_slice() {
        [_] => return Ok(request),
        [_, ImapArg::List(options)] => options,
        _ => return Err(ParseError::TrailingData),
    };
    let mut index = 0;
    while index < options.len() {
        let name = options[index]
            .as_text()
            .ok_or(ParseError::InvalidAtom)?
            .to_ascii_uppercase();
        index += 1;
        match name.as_str() {
            "CONDSTORE" if !request.condstore => request.condstore = true,
            "QRESYNC" if request.qresync.is_none() => {
                let ImapArg::List(parameters) =
                    options.get(index).ok_or(ParseError::UnexpectedEnd)?
                else {
                    return Err(ParseError::InvalidAtom);
                };
                index += 1;
                if !(2..=4).contains(&parameters.len()) {
                    return Err(ParseError::TrailingData);
                }
                let uidvalidity = parameters[0]
                    .as_text()
                    .and_then(parse_nz_number)
                    .ok_or(ParseError::InvalidAtom)?;
                let modseq = parameters[1]
                    .as_text()
                    .and_then(|value| value.parse::<u64>().ok())
                    .ok_or(ParseError::InvalidAtom)?;
                let known_uids = parameters
                    .get(2)
                    .map(|argument| {
                        argument
                            .as_text()
                            .and_then(SequenceSet::parse_nostar)
                            .ok_or(ParseError::InvalidAtom)
                    })
                    .transpose()?;
                let sample = parameters
                    .get(3)
                    .map(|argument| {
                        let ImapArg::List(sample) = argument else {
                            return Err(ParseError::InvalidAtom);
                        };
                        if sample.len() != 2 {
                            return Err(ParseError::TrailingData);
                        }
                        let sequences = sample[0]
                            .as_text()
                            .and_then(SequenceSet::parse_nostar)
                            .ok_or(ParseError::InvalidAtom)?;
                        let uids = sample[1]
                            .as_text()
                            .and_then(SequenceSet::parse_nostar)
                            .ok_or(ParseError::InvalidAtom)?;
                        if sequences.cardinality() != uids.cardinality() {
                            return Err(ParseError::InvalidAtom);
                        }
                        Ok((sequences, uids))
                    })
                    .transpose()?;
                request.condstore = true;
                request.qresync = Some(QresyncRequest {
                    uidvalidity,
                    modseq,
                    known_uids,
                    sample,
                });
            }
            _ => return Err(ParseError::InvalidAtom),
        }
    }
    Ok(request)
}

pub(crate) fn ids_from_set(id_set: &str, max: u64) -> Vec<u64> {
    if id_set == "*" {
        return (1..=max).collect();
    }
    let mut out = Vec::new();
    for part in id_set.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once(':') {
            let start = if start == "*" {
                max
            } else {
                start.parse::<u64>().unwrap_or(1)
            };
            let end = if end == "*" {
                max
            } else {
                end.parse::<u64>().unwrap_or(max)
            };
            let (lo, hi) = if start <= end {
                (start, end)
            } else {
                (end, start)
            };
            out.extend(lo..=hi);
        } else if part == "*" {
            out.push(max);
        } else if let Ok(id) = part.parse::<u64>() {
            out.push(id);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

#[derive(Debug, Clone)]
pub(crate) enum SearchCriterion {
    All,
    Never,
    Seen,
    Unseen,
    Answered,
    Unanswered,
    Deleted,
    Undeleted,
    Draft,
    Undraft,
    Flagged,
    Unflagged,
    Recent,
    Old,
    New,
    Keyword(String),
    Unkeyword(String),
    SeqSet(String),
    UidSet(String),
    SavedResult,
    Younger(u64),
    Older(u64),
    Since(chrono::NaiveDate),
    Before(chrono::NaiveDate),
    On(chrono::NaiveDate),
    SentSince(chrono::NaiveDate),
    SentBefore(chrono::NaiveDate),
    SentOn(chrono::NaiveDate),
    Larger(usize),
    Smaller(usize),
    Header(String, String),
    Body(String),
    Text(String),
    Not(Box<SearchCriterion>),
    Or(Box<SearchCriterion>, Box<SearchCriterion>),
    And(Vec<SearchCriterion>),
}

#[derive(Debug)]
pub(crate) struct SearchMessage<'a> {
    pub(crate) seq: usize,
    pub(crate) uid: u64,
    pub(crate) flags: &'a [String],
    pub(crate) internal_date: i64,
    pub(crate) in_saved_result: bool,
    pub(crate) now: i64,
    pub(crate) data: &'a [u8],
}

pub(crate) fn tokenize_search(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            ' ' | '\t' | '\r' | '\n' => {}
            '(' | ')' => tokens.push(ch.to_string()),
            '"' => {
                let mut token = String::new();
                let mut escaped = false;
                for next in chars.by_ref() {
                    if escaped {
                        token.push(next);
                        escaped = false;
                    } else if next == '\\' {
                        escaped = true;
                    } else if next == '"' {
                        break;
                    } else {
                        token.push(next);
                    }
                }
                tokens.push(token);
            }
            _ => {
                let mut token = String::new();
                token.push(ch);
                while let Some(next) = chars.peek().copied() {
                    if next.is_whitespace() || next == '(' || next == ')' {
                        break;
                    }
                    token.push(next);
                    chars.next();
                }
                tokens.push(token);
            }
        }
    }
    tokens
}

fn parse_imap_date(token: &str) -> Option<chrono::NaiveDate> {
    chrono::NaiveDate::parse_from_str(token, "%d-%b-%Y").ok()
}

fn parse_search_criterion(tokens: &[String], pos: &mut usize) -> Option<SearchCriterion> {
    let token = tokens.get(*pos)?.clone();
    *pos += 1;
    if token == "(" {
        let mut items = Vec::new();
        while tokens.get(*pos).map(|s| s.as_str()) != Some(")") {
            items.push(parse_search_criterion(tokens, pos)?);
        }
        *pos += 1;
        return Some(SearchCriterion::And(items));
    }
    if token == ")" {
        return None;
    }
    let upper = token.to_uppercase();
    match upper.as_str() {
        "ALL" => Some(SearchCriterion::All),
        "SEEN" => Some(SearchCriterion::Seen),
        "UNSEEN" => Some(SearchCriterion::Unseen),
        "ANSWERED" => Some(SearchCriterion::Answered),
        "UNANSWERED" => Some(SearchCriterion::Unanswered),
        "DELETED" => Some(SearchCriterion::Deleted),
        "UNDELETED" => Some(SearchCriterion::Undeleted),
        "DRAFT" => Some(SearchCriterion::Draft),
        "UNDRAFT" => Some(SearchCriterion::Undraft),
        "FLAGGED" => Some(SearchCriterion::Flagged),
        "UNFLAGGED" => Some(SearchCriterion::Unflagged),
        "RECENT" => Some(SearchCriterion::Recent),
        "OLD" => Some(SearchCriterion::Old),
        "NEW" => Some(SearchCriterion::New),
        "KEYWORD" => {
            let value = tokens.get(*pos)?.clone();
            *pos += 1;
            Some(SearchCriterion::Keyword(value))
        }
        "UNKEYWORD" => {
            let value = tokens.get(*pos)?.clone();
            *pos += 1;
            Some(SearchCriterion::Unkeyword(value))
        }
        "UID" => {
            let set = tokens.get(*pos)?.clone();
            *pos += 1;
            Some(SearchCriterion::UidSet(set))
        }
        "$" => Some(SearchCriterion::SavedResult),
        "YOUNGER" => {
            let seconds = tokens.get(*pos)?.parse::<u64>().ok()?;
            *pos += 1;
            Some(SearchCriterion::Younger(seconds))
        }
        "OLDER" => {
            let seconds = tokens.get(*pos)?.parse::<u64>().ok()?;
            *pos += 1;
            Some(SearchCriterion::Older(seconds))
        }
        "SINCE" => {
            let date = parse_imap_date(tokens.get(*pos)?)?;
            *pos += 1;
            Some(SearchCriterion::Since(date))
        }
        "BEFORE" => {
            let date = parse_imap_date(tokens.get(*pos)?)?;
            *pos += 1;
            Some(SearchCriterion::Before(date))
        }
        "ON" => {
            let date = parse_imap_date(tokens.get(*pos)?)?;
            *pos += 1;
            Some(SearchCriterion::On(date))
        }
        "SENTSINCE" => {
            let date = parse_imap_date(tokens.get(*pos)?)?;
            *pos += 1;
            Some(SearchCriterion::SentSince(date))
        }
        "SENTBEFORE" => {
            let date = parse_imap_date(tokens.get(*pos)?)?;
            *pos += 1;
            Some(SearchCriterion::SentBefore(date))
        }
        "SENTON" => {
            let date = parse_imap_date(tokens.get(*pos)?)?;
            *pos += 1;
            Some(SearchCriterion::SentOn(date))
        }
        "LARGER" => {
            let size = tokens.get(*pos)?.parse::<usize>().ok()?;
            *pos += 1;
            Some(SearchCriterion::Larger(size))
        }
        "SMALLER" => {
            let size = tokens.get(*pos)?.parse::<usize>().ok()?;
            *pos += 1;
            Some(SearchCriterion::Smaller(size))
        }
        "FROM" | "TO" | "CC" | "BCC" | "SUBJECT" => {
            let value = tokens.get(*pos)?.clone();
            *pos += 1;
            Some(SearchCriterion::Header(upper, value))
        }
        "HEADER" => {
            let name = tokens.get(*pos)?.clone();
            *pos += 1;
            let value = tokens.get(*pos)?.clone();
            *pos += 1;
            Some(SearchCriterion::Header(name, value))
        }
        "BODY" => {
            let value = tokens.get(*pos)?.clone();
            *pos += 1;
            Some(SearchCriterion::Body(value))
        }
        "TEXT" => {
            let value = tokens.get(*pos)?.clone();
            *pos += 1;
            Some(SearchCriterion::Text(value))
        }
        "NOT" => Some(SearchCriterion::Not(Box::new(parse_search_criterion(
            tokens, pos,
        )?))),
        "OR" => {
            let left = parse_search_criterion(tokens, pos)?;
            let right = parse_search_criterion(tokens, pos)?;
            Some(SearchCriterion::Or(Box::new(left), Box::new(right)))
        }
        _ if token
            .chars()
            .all(|c| c.is_ascii_digit() || c == ':' || c == '*' || c == ',') =>
        {
            Some(SearchCriterion::SeqSet(token))
        }
        _ => None,
    }
}

fn parse_search_tokens(tokens: &[String]) -> Option<SearchCriterion> {
    if tokens.is_empty() {
        return Some(SearchCriterion::All);
    }
    let mut pos = 0;
    if tokens
        .get(pos)
        .map(|token| token.eq_ignore_ascii_case("CHARSET"))
        .unwrap_or(false)
    {
        pos += 1;
        let charset = tokens.get(pos)?;
        pos += 1;
        if !charset.eq_ignore_ascii_case("UTF-8") && !charset.eq_ignore_ascii_case("US-ASCII") {
            return Some(SearchCriterion::Never);
        }
    }
    let mut criteria = Vec::new();
    while pos < tokens.len() {
        criteria.push(parse_search_criterion(&tokens, &mut pos)?);
    }
    if criteria.len() == 1 {
        criteria.pop()
    } else {
        Some(SearchCriterion::And(criteria))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SearchReturnOptions {
    pub(crate) min: bool,
    pub(crate) max: bool,
    pub(crate) all: bool,
    pub(crate) count: bool,
    pub(crate) save: bool,
}

#[derive(Debug)]
pub(crate) struct SearchRequest {
    pub(crate) return_options: Option<SearchReturnOptions>,
    pub(crate) charset: Option<String>,
    pub(crate) criterion: SearchCriterion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SearchParseError {
    Syntax,
    UnsupportedCharset(String),
}

pub(crate) fn parse_search_request(input: &str) -> Result<SearchRequest, SearchParseError> {
    let tokens = tokenize_search(input);
    let mut pos = 0;
    let return_options = if tokens
        .first()
        .is_some_and(|token| token.eq_ignore_ascii_case("RETURN"))
    {
        pos += 1;
        if tokens.get(pos).map(String::as_str) != Some("(") {
            return Err(SearchParseError::Syntax);
        }
        pos += 1;
        let mut options = SearchReturnOptions::default();
        while tokens.get(pos).map(String::as_str) != Some(")") {
            match tokens
                .get(pos)
                .ok_or(SearchParseError::Syntax)?
                .to_ascii_uppercase()
                .as_str()
            {
                "MIN" => options.min = true,
                "MAX" => options.max = true,
                "ALL" => options.all = true,
                "COUNT" => options.count = true,
                "SAVE" => options.save = true,
                _ => return Err(SearchParseError::Syntax),
            }
            pos += 1;
        }
        pos += 1;
        if !options.min && !options.max && !options.all && !options.count && !options.save {
            options.all = true;
        }
        Some(options)
    } else {
        None
    };
    let charset = if tokens
        .get(pos)
        .is_some_and(|token| token.eq_ignore_ascii_case("CHARSET"))
    {
        let charset = tokens.get(pos + 1).ok_or(SearchParseError::Syntax)?;
        if !charset.eq_ignore_ascii_case("UTF-8") && !charset.eq_ignore_ascii_case("US-ASCII") {
            return Err(SearchParseError::UnsupportedCharset(charset.clone()));
        }
        pos += 2;
        Some(charset.to_ascii_uppercase())
    } else {
        None
    };
    Ok(SearchRequest {
        return_options,
        charset,
        criterion: parse_search_tokens(&tokens[pos..]).ok_or(SearchParseError::Syntax)?,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SortKey {
    Arrival,
    Cc,
    Date,
    From,
    Size,
    Subject,
    To,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SortCriterion {
    pub(crate) key: SortKey,
    pub(crate) reverse: bool,
}

#[derive(Debug)]
pub(crate) struct SortRequest {
    pub(crate) criteria: Vec<SortCriterion>,
    pub(crate) charset: String,
    pub(crate) search: SearchCriterion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SortParseError {
    Syntax,
    UnsupportedCharset(String),
}

pub(crate) fn parse_sort_request(input: &str) -> Result<SortRequest, SortParseError> {
    let request = parse_sort_request_inner(input).ok_or(SortParseError::Syntax)?;
    if request.charset != "UTF-8" && request.charset != "US-ASCII" {
        return Err(SortParseError::UnsupportedCharset(request.charset));
    }
    Ok(request)
}

fn parse_sort_request_inner(input: &str) -> Option<SortRequest> {
    use std::collections::HashSet;

    let tokens = tokenize_search(input);
    if tokens.first().map(String::as_str) != Some("(") {
        return None;
    }
    let mut pos = 1;
    let mut reverse = false;
    let mut criteria = Vec::new();
    let mut seen = HashSet::new();
    while tokens.get(pos).map(String::as_str) != Some(")") {
        let token = tokens.get(pos)?.to_ascii_uppercase();
        pos += 1;
        if token == "REVERSE" {
            reverse = !reverse;
            continue;
        }
        let key = match token.as_str() {
            "ARRIVAL" => SortKey::Arrival,
            "CC" => SortKey::Cc,
            "DATE" => SortKey::Date,
            "FROM" => SortKey::From,
            "SIZE" => SortKey::Size,
            "SUBJECT" => SortKey::Subject,
            "TO" => SortKey::To,
            _ => return None,
        };
        if seen.insert(key) {
            criteria.push(SortCriterion { key, reverse });
        }
        reverse = false;
    }
    if criteria.is_empty() || reverse {
        return None;
    }
    pos += 1;
    let charset = tokens.get(pos)?.to_ascii_uppercase();
    pos += 1;
    Some(SortRequest {
        criteria,
        charset,
        search: parse_search_tokens(&tokens[pos..])?,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThreadAlgorithm {
    OrderedSubject,
    References,
    Refs,
}

#[derive(Debug)]
pub(crate) struct ThreadRequest {
    pub(crate) algorithm: ThreadAlgorithm,
    pub(crate) charset: String,
    pub(crate) search: SearchCriterion,
}

pub(crate) fn parse_thread_request(input: &str) -> Result<ThreadRequest, SortParseError> {
    let tokens = tokenize_search(input);
    let algorithm = match tokens.first().map(|token| token.to_ascii_uppercase()) {
        Some(value) if value == "ORDEREDSUBJECT" => ThreadAlgorithm::OrderedSubject,
        Some(value) if value == "REFERENCES" => ThreadAlgorithm::References,
        Some(value) if value == "REFS" => ThreadAlgorithm::Refs,
        _ => return Err(SortParseError::Syntax),
    };
    let charset = tokens
        .get(1)
        .ok_or(SortParseError::Syntax)?
        .to_ascii_uppercase();
    if charset != "UTF-8" && charset != "US-ASCII" {
        return Err(SortParseError::UnsupportedCharset(charset));
    }
    Ok(ThreadRequest {
        algorithm,
        charset,
        search: parse_search_tokens(&tokens[2..]).ok_or(SortParseError::Syntax)?,
    })
}

fn message_internal_date(timestamp: i64) -> Option<chrono::NaiveDate> {
    use chrono::TimeZone;

    chrono::Utc
        .timestamp_opt(timestamp, 0)
        .single()
        .map(|dt| dt.date_naive())
}

fn message_sent_date(data: &[u8]) -> Option<chrono::NaiveDate> {
    let raw = crate::mailbox::header_value(data, "Date")?;
    chrono::DateTime::parse_from_rfc2822(&raw)
        .ok()
        .map(|dt| dt.date_naive())
}

fn contains_ascii_casefold(haystack: &[u8], needle: &str) -> bool {
    String::from_utf8_lossy(haystack)
        .to_lowercase()
        .contains(&needle.to_lowercase())
}

fn has_flag(flags: &[String], wanted: &str) -> bool {
    flags.iter().any(|flag| flag.eq_ignore_ascii_case(wanted))
}

pub(crate) fn search_matches(
    criterion: &SearchCriterion,
    msg: &SearchMessage<'_>,
    total: usize,
) -> bool {
    match criterion {
        SearchCriterion::All => true,
        SearchCriterion::Never => false,
        SearchCriterion::Seen => has_flag(msg.flags, "\\Seen"),
        SearchCriterion::Unseen => !has_flag(msg.flags, "\\Seen"),
        SearchCriterion::Answered => has_flag(msg.flags, "\\Answered"),
        SearchCriterion::Unanswered => !has_flag(msg.flags, "\\Answered"),
        SearchCriterion::Deleted => has_flag(msg.flags, "\\Deleted"),
        SearchCriterion::Undeleted => !has_flag(msg.flags, "\\Deleted"),
        SearchCriterion::Draft => has_flag(msg.flags, "\\Draft"),
        SearchCriterion::Undraft => !has_flag(msg.flags, "\\Draft"),
        SearchCriterion::Flagged => has_flag(msg.flags, "\\Flagged"),
        SearchCriterion::Unflagged => !has_flag(msg.flags, "\\Flagged"),
        SearchCriterion::Recent => has_flag(msg.flags, "\\Recent"),
        SearchCriterion::Old => !has_flag(msg.flags, "\\Recent"),
        SearchCriterion::New => has_flag(msg.flags, "\\Recent") && !has_flag(msg.flags, "\\Seen"),
        SearchCriterion::Keyword(keyword) => has_flag(msg.flags, keyword),
        SearchCriterion::Unkeyword(keyword) => !has_flag(msg.flags, keyword),
        SearchCriterion::SeqSet(set) => ids_from_set(set, total as u64).contains(&(msg.seq as u64)),
        SearchCriterion::UidSet(set) => {
            ids_from_set(set, msg.uid.max(total as u64)).contains(&msg.uid)
        }
        SearchCriterion::SavedResult => msg.in_saved_result,
        SearchCriterion::Younger(seconds) => {
            let cutoff = msg
                .now
                .saturating_sub((*seconds).min(i64::MAX as u64) as i64);
            msg.internal_date >= cutoff
        }
        SearchCriterion::Older(seconds) => {
            let cutoff = msg
                .now
                .saturating_sub((*seconds).min(i64::MAX as u64) as i64);
            msg.internal_date < cutoff
        }
        SearchCriterion::Since(date) => message_internal_date(msg.internal_date)
            .map(|msg_date| msg_date >= *date)
            .unwrap_or(false),
        SearchCriterion::Before(date) => message_internal_date(msg.internal_date)
            .map(|msg_date| msg_date < *date)
            .unwrap_or(false),
        SearchCriterion::On(date) => message_internal_date(msg.internal_date)
            .map(|msg_date| msg_date == *date)
            .unwrap_or(false),
        SearchCriterion::SentSince(date) => message_sent_date(msg.data)
            .map(|msg_date| msg_date >= *date)
            .unwrap_or(false),
        SearchCriterion::SentBefore(date) => message_sent_date(msg.data)
            .map(|msg_date| msg_date < *date)
            .unwrap_or(false),
        SearchCriterion::SentOn(date) => message_sent_date(msg.data)
            .map(|msg_date| msg_date == *date)
            .unwrap_or(false),
        SearchCriterion::Larger(size) => msg.data.len() > *size,
        SearchCriterion::Smaller(size) => msg.data.len() < *size,
        SearchCriterion::Header(name, value) => crate::mailbox::header_value(msg.data, name)
            .map(|header| header.to_lowercase().contains(&value.to_lowercase()))
            .unwrap_or(false),
        SearchCriterion::Body(value) => {
            contains_ascii_casefold(crate::mailbox::body_after_header(msg.data), value)
        }
        SearchCriterion::Text(value) => contains_ascii_casefold(msg.data, value),
        SearchCriterion::Not(inner) => !search_matches(inner, msg, total),
        SearchCriterion::Or(left, right) => {
            search_matches(left, msg, total) || search_matches(right, msg, total)
        }
        SearchCriterion::And(items) => items.iter().all(|item| search_matches(item, msg, total)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FetchRequest {
    pub(crate) items: Vec<String>,
    pub(crate) modifier_spec: Option<String>,
}

fn split_fetch_item_list(spec: &str) -> Result<(&str, &str), ParseError> {
    let spec = spec.trim();
    if !spec.starts_with('(') {
        let end = spec.find(char::is_whitespace).unwrap_or(spec.len());
        return Ok((&spec[..end], spec[end..].trim()));
    }
    let mut depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for (index, ch) in spec.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
            continue;
        }
        match ch {
            '"' => quoted = true,
            '[' => bracket_depth += 1,
            ']' => {
                bracket_depth = bracket_depth
                    .checked_sub(1)
                    .ok_or(ParseError::InvalidAtom)?
            }
            '(' if bracket_depth == 0 => depth += 1,
            ')' if bracket_depth == 0 => {
                depth = depth.checked_sub(1).ok_or(ParseError::InvalidAtom)?;
                if depth == 0 {
                    return Ok((&spec[1..index], spec[index + 1..].trim()));
                }
            }
            _ => {}
        }
    }
    Err(ParseError::UnterminatedList)
}

fn valid_partial(suffix: &str) -> bool {
    let Some(inner) = suffix
        .strip_prefix('<')
        .and_then(|value| value.strip_suffix('>'))
    else {
        return false;
    };
    let Some((start, count)) = inner.split_once('.') else {
        return false;
    };
    !start.is_empty()
        && !count.is_empty()
        && start.bytes().all(|byte| byte.is_ascii_digit())
        && count.bytes().all(|byte| byte.is_ascii_digit())
        && start.parse::<u64>().is_ok()
        && count.parse::<u64>().is_ok()
}

fn valid_numeric_section(section: &str) -> bool {
    !section.is_empty()
        && section.split('.').all(|component| {
            !component.is_empty()
                && component.bytes().all(|byte| byte.is_ascii_digit())
                && component.parse::<u64>().is_ok_and(|value| value != 0)
        })
}

fn validate_body_fetch_item(item: &str) -> bool {
    let Some(open) = item.find('[') else {
        return false;
    };
    let Some(close) = item.rfind(']') else {
        return false;
    };
    if close < open || item[open + 1..close].contains(['[', ']']) {
        return false;
    }
    let prefix = &item[..open];
    let section = &item[open + 1..close];
    let suffix = &item[close + 1..];
    if !suffix.is_empty() && !valid_partial(suffix) {
        return false;
    }
    if matches!(prefix, "BINARY.SIZE") && !suffix.is_empty() {
        return false;
    }
    if matches!(prefix, "BINARY" | "BINARY.PEEK" | "BINARY.SIZE") {
        return section.is_empty() || valid_numeric_section(section);
    }
    if !matches!(prefix, "BODY" | "BODY.PEEK") {
        return false;
    }
    let section = section.trim();
    if section.is_empty() || matches!(section, "HEADER" | "TEXT") {
        return true;
    }
    if section.starts_with("HEADER.FIELDS (") || section.starts_with("HEADER.FIELDS.NOT (") {
        return section.ends_with(')')
            && section.rsplit_once('(').is_some_and(|(_, fields)| {
                let fields = fields[..fields.len() - 1]
                    .split_whitespace()
                    .collect::<Vec<_>>();
                !fields.is_empty()
                    && fields
                        .iter()
                        .all(|field| !field.is_empty() && !field.contains(['(', ')']))
            });
    }
    let (path, suffix) = section
        .rsplit_once('.')
        .filter(|(_, suffix)| matches!(*suffix, "MIME" | "HEADER" | "TEXT"))
        .map_or((section, None), |(path, suffix)| (path, Some(suffix)));
    valid_numeric_section(path) && suffix.is_none_or(|value| !value.is_empty())
}

pub(crate) fn parse_fetch_request(spec: &str) -> Result<FetchRequest, ParseError> {
    let (inner, remainder) = split_fetch_item_list(spec)?;
    if inner.trim().is_empty() {
        return Err(ParseError::InvalidAtom);
    }
    let mut out = Vec::new();
    let raw_items = split_fetch_items(inner);
    if raw_items.is_empty() {
        return Err(ParseError::InvalidAtom);
    }
    for item in raw_items.into_iter().map(|s| s.to_uppercase()) {
        match item.as_str() {
            "ALL" => {
                if !out.is_empty() || !inner.eq_ignore_ascii_case("ALL") {
                    return Err(ParseError::InvalidAtom);
                }
                out.extend(["FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE"].map(str::to_string))
            }
            "FAST" if inner.eq_ignore_ascii_case("FAST") => {
                out.extend(["FLAGS", "INTERNALDATE", "RFC822.SIZE"].map(str::to_string))
            }
            "FULL" if inner.eq_ignore_ascii_case("FULL") => out.extend(
                ["FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", "BODY"].map(str::to_string),
            ),
            "FLAGS" | "INTERNALDATE" | "RFC822" | "RFC822.HEADER" | "RFC822.SIZE"
            | "RFC822.TEXT" | "ENVELOPE" | "BODY" | "BODYSTRUCTURE" | "UID" | "MODSEQ"
            | "SAVEDATE" => out.push(item),
            _ if validate_body_fetch_item(&item) => out.push(item),
            _ => return Err(ParseError::InvalidAtom),
        }
    }
    out.sort();
    out.dedup();
    let modifier_spec = if remainder.is_empty() {
        None
    } else if remainder.starts_with('(') && remainder.ends_with(')') {
        Some(remainder.to_string())
    } else {
        return Err(ParseError::TrailingData);
    };
    Ok(FetchRequest {
        items: out,
        modifier_spec,
    })
}

pub(crate) fn split_fetch_items(spec: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let mut start = None;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut in_quote = false;
    let mut escaped = false;

    for (idx, ch) in spec.char_indices() {
        if start.is_none() {
            if ch.is_whitespace() {
                continue;
            }
            start = Some(idx);
        }

        if in_quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_quote = false;
            }
            continue;
        }

        match ch {
            '"' => in_quote = true,
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '(' if bracket_depth == 0 => paren_depth += 1,
            ')' if bracket_depth == 0 => paren_depth = paren_depth.saturating_sub(1),
            c if c.is_whitespace() && paren_depth == 0 && bracket_depth == 0 => {
                if let Some(item_start) = start.take() {
                    items.push(spec[item_start..idx].trim());
                }
            }
            _ => {}
        }
    }

    if let Some(item_start) = start {
        let item = spec[item_start..].trim();
        if !item.is_empty() {
            items.push(item);
        }
    }

    items
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreMode {
    Replace,
    Add,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoreRequest {
    pub(crate) message_set: String,
    pub(crate) unchanged_since: Option<u64>,
    pub(crate) mode: StoreMode,
    pub(crate) silent: bool,
    pub(crate) flags: Vec<String>,
}

pub(crate) fn parse_store_request(input: &str) -> Result<StoreRequest, ParseError> {
    let arguments = parse_imap_args(input)?;
    let Some(ImapArg::Atom(message_set)) = arguments.first() else {
        return Err(ParseError::InvalidAtom);
    };
    if message_set != "$" {
        SequenceSet::parse(message_set, 1).ok_or(ParseError::InvalidAtom)?;
    }
    let mut index = 1;
    let unchanged_since = if let Some(ImapArg::List(modifiers)) = arguments.get(index) {
        let [ImapArg::Atom(name), ImapArg::Atom(value)] = modifiers.as_slice() else {
            return Err(ParseError::InvalidAtom);
        };
        if !name.eq_ignore_ascii_case("UNCHANGEDSINCE") {
            return Err(ParseError::InvalidAtom);
        }
        index += 1;
        Some(value.parse().map_err(|_| ParseError::InvalidAtom)?)
    } else {
        None
    };
    let Some(ImapArg::Atom(operation)) = arguments.get(index) else {
        return Err(ParseError::InvalidAtom);
    };
    index += 1;
    let upper_operation = operation.to_ascii_uppercase();
    let (operation, silent) = upper_operation
        .strip_suffix(".SILENT")
        .map_or((upper_operation.as_str(), false), |operation| {
            (operation, true)
        });
    let mode = match operation {
        "FLAGS" => StoreMode::Replace,
        "+FLAGS" => StoreMode::Add,
        "-FLAGS" => StoreMode::Remove,
        _ => return Err(ParseError::InvalidAtom),
    };
    let flag_arguments = arguments.get(index..).ok_or(ParseError::UnexpectedEnd)?;
    let raw_flags: Vec<&ImapArg> = match flag_arguments {
        [ImapArg::List(flags)] => flags.iter().collect(),
        [] => return Err(ParseError::UnexpectedEnd),
        flags => flags.iter().collect(),
    };
    let mut flags = raw_flags
        .into_iter()
        .map(|flag| match flag {
            ImapArg::Atom(flag) => Ok(flag.to_ascii_uppercase()),
            _ => Err(ParseError::InvalidAtom),
        })
        .collect::<Result<Vec<_>, _>>()?;
    flags.sort();
    flags.dedup();
    Ok(StoreRequest {
        message_set: message_set.clone(),
        unchanged_since,
        mode,
        silent,
        flags,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppendRequest {
    pub(crate) mailbox: String,
    pub(crate) flags: Vec<String>,
    pub(crate) internal_date: Option<AppendDate>,
    pub(crate) literal_len: usize,
    pub(crate) non_sync: bool,
    pub(crate) literal8: bool,
    pub(crate) utf8: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AppendDate {
    pub(crate) timestamp: i64,
    pub(crate) timezone_offset_minutes: i32,
}

fn parse_append_date(value: &str) -> Result<AppendDate, ParseError> {
    use chrono::Offset;

    let parsed = chrono::DateTime::parse_from_str(value, "%e-%b-%Y %H:%M:%S %z")
        .map_err(|_| ParseError::InvalidDateTime)?;
    Ok(AppendDate {
        timestamp: parsed.timestamp(),
        timezone_offset_minutes: parsed.offset().fix().local_minus_utc() / 60,
    })
}

pub(crate) fn parse_append_args(args: &str) -> Result<AppendRequest, ParseError> {
    let parsed = parse_imap_args(args)?;
    let (mailbox_arg, tail) = parsed.split_first().ok_or(ParseError::UnexpectedEnd)?;
    let mailbox = mailbox_arg
        .as_text()
        .ok_or(ParseError::InvalidAtom)?
        .to_string();
    let (literal_arg, optional, utf8) = match tail {
        [optional @ .., ImapArg::Atom(name), ImapArg::List(items)]
            if name.eq_ignore_ascii_case("UTF8") && items.len() == 1 =>
        {
            (&items[0], optional, true)
        }
        _ => {
            let (literal, optional) = tail.split_last().ok_or(ParseError::UnexpectedEnd)?;
            (literal, optional, false)
        }
    };
    let (literal_len, non_sync, literal8) = match literal_arg {
        ImapArg::LiteralSize {
            size,
            non_sync,
            literal8,
        } => (*size, *non_sync, *literal8),
        _ => return Err(ParseError::InvalidLiteral),
    };
    if utf8 && !literal8 {
        return Err(ParseError::InvalidLiteral);
    }

    let mut flags = Vec::new();
    let mut saw_flags = false;
    let mut internal_date = None;
    for arg in optional {
        match arg {
            ImapArg::List(items) if !saw_flags && internal_date.is_none() => {
                saw_flags = true;
                flags = items
                    .iter()
                    .map(|item| {
                        item.as_text()
                            .map(|value| value.to_ascii_uppercase())
                            .ok_or(ParseError::InvalidAtom)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
            }
            ImapArg::String(value) if internal_date.is_none() => {
                internal_date = Some(parse_append_date(value)?);
            }
            _ => return Err(ParseError::TrailingData),
        }
    }

    Ok(AppendRequest {
        mailbox,
        flags,
        internal_date,
        literal_len,
        non_sync,
        literal8,
        utf8,
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ListSelectionOptions {
    pub(crate) subscribed: bool,
    pub(crate) remote: bool,
    pub(crate) recursive_match: bool,
    pub(crate) special_use: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ListReturnOptions {
    pub(crate) subscribed: bool,
    pub(crate) children: bool,
    pub(crate) special_use: bool,
    pub(crate) status: Vec<StatusItem>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatusItem {
    Messages,
    Recent,
    UidNext,
    UidValidity,
    Unseen,
    HighestModSeq,
    Size,
}

impl StatusItem {
    fn parse(argument: &ImapArg) -> Result<Self, ParseError> {
        let ImapArg::Atom(argument) = argument else {
            return Err(ParseError::InvalidAtom);
        };
        match argument.to_ascii_uppercase().as_str() {
            "MESSAGES" => Ok(Self::Messages),
            "RECENT" => Ok(Self::Recent),
            "UIDNEXT" => Ok(Self::UidNext),
            "UIDVALIDITY" => Ok(Self::UidValidity),
            "UNSEEN" => Ok(Self::Unseen),
            "HIGHESTMODSEQ" => Ok(Self::HighestModSeq),
            "SIZE" => Ok(Self::Size),
            _ => Err(ParseError::InvalidAtom),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StatusRequest {
    pub(crate) mailbox: String,
    pub(crate) items: Vec<StatusItem>,
}

fn parse_status_items(arguments: &[ImapArg]) -> Result<Vec<StatusItem>, ParseError> {
    if arguments.is_empty() {
        return Err(ParseError::UnexpectedEnd);
    }
    let mut items = Vec::with_capacity(arguments.len());
    for argument in arguments {
        let item = StatusItem::parse(argument)?;
        if items.contains(&item) {
            return Err(ParseError::InvalidAtom);
        }
        items.push(item);
    }
    Ok(items)
}

pub(crate) fn parse_status_request(input: &str) -> Result<StatusRequest, ParseError> {
    let arguments = parse_imap_args(input)?;
    let [mailbox, ImapArg::List(items)] = arguments.as_slice() else {
        return Err(ParseError::InvalidAtom);
    };
    Ok(StatusRequest {
        mailbox: mailbox
            .as_text()
            .ok_or(ParseError::InvalidAtom)?
            .to_string(),
        items: parse_status_items(items)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListRequest {
    pub(crate) selection: ListSelectionOptions,
    pub(crate) reference: String,
    pub(crate) patterns: Vec<String>,
    pub(crate) returns: ListReturnOptions,
    pub(crate) extended: bool,
}

fn arg_text(arg: &ImapArg) -> Result<String, ParseError> {
    arg.as_text()
        .map(str::to_string)
        .ok_or(ParseError::InvalidAtom)
}

fn arg_list(arg: &ImapArg) -> Result<&[ImapArg], ParseError> {
    match arg {
        ImapArg::List(items) => Ok(items.as_slice()),
        _ => Err(ParseError::InvalidAtom),
    }
}

fn parse_list_selection(items: &[ImapArg]) -> Result<ListSelectionOptions, ParseError> {
    let mut out = ListSelectionOptions::default();
    for item in items {
        match arg_text(item)?.to_ascii_uppercase().as_str() {
            "SUBSCRIBED" => out.subscribed = true,
            "REMOTE" => out.remote = true,
            "RECURSIVEMATCH" => out.recursive_match = true,
            "SPECIAL-USE" => out.special_use = true,
            _ => return Err(ParseError::InvalidAtom),
        }
    }
    if out.recursive_match && !out.subscribed && !out.special_use {
        return Err(ParseError::InvalidAtom);
    }
    Ok(out)
}

fn parse_list_return(items: &[ImapArg]) -> Result<ListReturnOptions, ParseError> {
    let mut out = ListReturnOptions::default();
    let mut pos = 0;
    while pos < items.len() {
        match arg_text(&items[pos])?.to_ascii_uppercase().as_str() {
            "SUBSCRIBED" => out.subscribed = true,
            "CHILDREN" => out.children = true,
            "SPECIAL-USE" => out.special_use = true,
            "STATUS" => {
                pos += 1;
                let status_items = arg_list(items.get(pos).ok_or(ParseError::UnexpectedEnd)?)?;
                out.status = parse_status_items(status_items)?;
            }
            _ => return Err(ParseError::InvalidAtom),
        }
        pos += 1;
    }
    Ok(out)
}

pub(crate) fn parse_list_request(input: &str, lsub: bool) -> Result<ListRequest, ParseError> {
    let args = parse_imap_args(input)?;
    let mut pos = 0;
    let mut extended = false;
    let mut selection = ListSelectionOptions::default();

    if !lsub && matches!(args.get(pos), Some(ImapArg::List(_))) {
        selection = parse_list_selection(arg_list(&args[pos])?)?;
        extended = true;
        pos += 1;
    }

    let reference = arg_text(args.get(pos).ok_or(ParseError::UnexpectedEnd)?)?;
    pos += 1;
    let pattern_arg = args.get(pos).ok_or(ParseError::UnexpectedEnd)?;
    let patterns = match pattern_arg {
        ImapArg::List(items) => {
            extended = true;
            items.iter().map(arg_text).collect::<Result<Vec<_>, _>>()?
        }
        _ => vec![arg_text(pattern_arg)?],
    };
    pos += 1;

    let mut returns = if lsub {
        ListReturnOptions {
            special_use: true,
            ..ListReturnOptions::default()
        }
    } else if extended {
        ListReturnOptions::default()
    } else {
        ListReturnOptions {
            children: true,
            special_use: true,
            ..ListReturnOptions::default()
        }
    };

    if pos < args.len() {
        if arg_text(&args[pos])?.eq_ignore_ascii_case("RETURN") {
            pos += 1;
            returns =
                parse_list_return(arg_list(args.get(pos).ok_or(ParseError::UnexpectedEnd)?)?)?;
            extended = true;
            pos += 1;
        } else {
            return Err(ParseError::InvalidAtom);
        }
    }

    if pos != args.len() || patterns.is_empty() {
        return Err(ParseError::TrailingData);
    }

    Ok(ListRequest {
        selection,
        reference,
        patterns,
        returns,
        extended,
    })
}

fn list_effective_pattern(reference: &str, pattern: &str) -> String {
    if pattern.is_empty() {
        reference.to_string()
    } else if reference.is_empty() || pattern.starts_with('/') {
        pattern.to_string()
    } else {
        format!("{}/{}", reference.trim_end_matches('/'), pattern)
    }
}

pub(crate) fn mailbox_pattern_matches(name: &str, reference: &str, pattern: &str) -> bool {
    let effective = list_effective_pattern(reference, pattern);
    if effective.is_empty() {
        return name.is_empty();
    }
    mailbox_pattern_match_bytes(name.as_bytes(), effective.as_bytes())
}

fn mailbox_pattern_match_bytes(name: &[u8], pattern: &[u8]) -> bool {
    if pattern.is_empty() {
        return name.is_empty();
    }
    match pattern[0] {
        b'*' => {
            mailbox_pattern_match_bytes(name, &pattern[1..])
                || (!name.is_empty() && mailbox_pattern_match_bytes(&name[1..], pattern))
        }
        b'%' => {
            mailbox_pattern_match_bytes(name, &pattern[1..])
                || (!name.is_empty()
                    && name[0] != b'/'
                    && mailbox_pattern_match_bytes(&name[1..], pattern))
        }
        ch => {
            !name.is_empty()
                && name[0].eq_ignore_ascii_case(&ch)
                && mailbox_pattern_match_bytes(&name[1..], &pattern[1..])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_atoms_quoted_strings_nil_lists_and_literal_markers() {
        let args = parse_imap_args(r#"atom "quoted \"value\"" NIL (one "two" NIL) {12} ~{4+}"#)
            .expect("parse args");
        assert_eq!(
            args,
            vec![
                ImapArg::Atom("atom".to_string()),
                ImapArg::String("quoted \"value\"".to_string()),
                ImapArg::Nil,
                ImapArg::List(vec![
                    ImapArg::Atom("one".to_string()),
                    ImapArg::String("two".to_string()),
                    ImapArg::Nil,
                ]),
                ImapArg::LiteralSize {
                    size: 12,
                    non_sync: false,
                    literal8: false,
                },
                ImapArg::LiteralSize {
                    size: 4,
                    non_sync: true,
                    literal8: true,
                },
            ]
        );
    }

    #[test]
    fn parses_login_args_with_escaping() {
        let (user, password) =
            parse_login_args(r#""user@example.test" "pa\"ss\\word""#).expect("login args");
        assert_eq!(user, "user@example.test");
        assert_eq!(password, "pa\"ss\\word");

        assert_eq!(
            parse_mailbox_argument(r#""Project Mail""#),
            Ok("Project Mail".to_string())
        );
        assert!(parse_mailbox_argument("Projects trailing").is_err());
        assert_eq!(
            parse_rename_arguments(r#""Old Name" "New Name""#),
            Ok(("Old Name".to_string(), "New Name".to_string()))
        );
        assert!(parse_rename_arguments("Old New trailing").is_err());
    }

    #[test]
    fn parses_authenticate_args_and_empty_initial_response() {
        let (mechanism, initial) = parse_authenticate_args("plain =").expect("authenticate args");
        assert_eq!(mechanism, "PLAIN");
        assert_eq!(initial.as_deref(), Some("="));
    }

    #[test]
    fn parses_and_validates_id_parameters() {
        assert_eq!(parse_id_args("NIL"), Ok(None));
        assert_eq!(
            parse_id_args(r#"("name" "Geary" "version" "46.0" "support-url" NIL)"#),
            Ok(Some(vec![
                ("name".to_string(), Some("Geary".to_string())),
                ("version".to_string(), Some("46.0".to_string())),
                ("support-url".to_string(), None),
            ]))
        );
        assert!(parse_id_args(r#"("name")"#).is_err());
        assert!(parse_id_args(r#"(name "Geary")"#).is_err());
        assert!(parse_id_args(r#"("1234567890123456789012345678901" "x")"#).is_err());
        assert!(parse_id_args(r#"("name" "x") trailing"#).is_err());
    }

    #[test]
    fn parses_append_literal_markers() {
        assert_eq!(
            parse_append_args(r#"Sent (\Seen) {42}"#),
            Ok(AppendRequest {
                mailbox: "Sent".to_string(),
                flags: vec!["\\SEEN".to_string()],
                internal_date: None,
                literal_len: 42,
                non_sync: false,
                literal8: false,
                utf8: false,
            })
        );
        assert_eq!(
            parse_append_args(r#""Sent Items" ($Label) {12+}"#),
            Ok(AppendRequest {
                mailbox: "Sent Items".to_string(),
                flags: vec!["$LABEL".to_string()],
                internal_date: None,
                literal_len: 12,
                non_sync: true,
                literal8: false,
                utf8: false,
            })
        );
        assert_eq!(
            parse_append_args(r#"INBOX ~{3+}"#),
            Ok(AppendRequest {
                mailbox: "INBOX".to_string(),
                flags: Vec::new(),
                internal_date: None,
                literal_len: 3,
                non_sync: true,
                literal8: true,
                utf8: false,
            })
        );
        assert_eq!(
            parse_append_args(r#"INBOX (\Seen) UTF8 (~{9})"#),
            Ok(AppendRequest {
                mailbox: "INBOX".to_string(),
                flags: vec!["\\SEEN".to_string()],
                internal_date: None,
                literal_len: 9,
                non_sync: false,
                literal8: true,
                utf8: true,
            })
        );
        assert!(parse_append_args(r#"INBOX UTF8 ({9})"#).is_err());
        assert_eq!(
            parse_append_args(r#"Sent (\Seen) "17-Jul-1996 02:44:25 -0700" {42}"#),
            Ok(AppendRequest {
                mailbox: "Sent".to_string(),
                flags: vec!["\\SEEN".to_string()],
                internal_date: Some(AppendDate {
                    timestamp: 837596665,
                    timezone_offset_minutes: -420,
                }),
                literal_len: 42,
                non_sync: false,
                literal8: false,
                utf8: false,
            })
        );
        assert_eq!(
            parse_append_args(r#"Sent "31-Apr-2025 12:00:00 +0000" {1}"#),
            Err(ParseError::InvalidDateTime)
        );
        assert!(parse_append_args(r#"Sent "17-Jul-1996 02:44:25 -0700" () {1}"#).is_err());
    }

    #[test]
    fn parses_store_request_and_rejects_unknown_operations_or_modifiers() {
        assert_eq!(
            parse_store_request("1:4 (UNCHANGEDSINCE 42) +FLAGS.SILENT (\\Seen keyword)").unwrap(),
            StoreRequest {
                message_set: "1:4".to_string(),
                unchanged_since: Some(42),
                mode: StoreMode::Add,
                silent: true,
                flags: vec!["KEYWORD".to_string(), "\\SEEN".to_string()],
            }
        );
        assert!(parse_store_request("1 XFLAGS (\\Seen)").is_err());
        assert!(parse_store_request("1 (UNKNOWN 1) FLAGS (\\Seen)").is_err());
        assert!(parse_store_request("1 FLAGS (\"\\Seen\")").is_err());
        assert!(parse_store_request("bogus FLAGS (\\Seen)").is_err());
    }

    #[test]
    fn rejects_unterminated_quoted_string() {
        assert_eq!(
            parse_imap_args(r#""unterminated"#),
            Err(ParseError::UnterminatedString)
        );
    }

    #[test]
    fn validates_request_tags_and_command_atoms() {
        let request = parse_request_line("A001   NOOP").unwrap();
        assert_eq!(request.tag, "A001");
        assert_eq!(request.command_name(), "NOOP");
        assert!(matches!(
            parse_request_line("bad+tag NOOP"),
            Err(ParseError::InvalidTag)
        ));
        assert!(matches!(
            parse_request_line("* NOOP"),
            Err(ParseError::InvalidTag)
        ));
        assert!(matches!(
            parse_request_line("A001"),
            Err(ParseError::MissingCommand)
        ));
        assert!(matches!(
            parse_request_line("A001 BAD/COMMAND"),
            Err(ParseError::InvalidAtom)
        ));
        let long_tag = "a".repeat(1025);
        assert!(matches!(
            parse_request_line(&format!("{} NOOP", long_tag)),
            Err(ParseError::TagTooLong)
        ));
    }

    #[test]
    fn parses_condstore_and_full_qresync_select_options() {
        let request =
            parse_select_request("INBOX (CONDSTORE QRESYNC (123 456 1:4,9 (1:2,5 10:11,20)))")
                .unwrap();
        assert_eq!(request.mailbox, "INBOX");
        assert!(request.condstore);
        let qresync = request.qresync.unwrap();
        assert_eq!(qresync.uidvalidity, 123);
        assert_eq!(qresync.modseq, 456);
        assert!(qresync.known_uids.unwrap().contains(9));
        assert!(qresync.sample.is_some());

        assert!(parse_select_request("INBOX (QRESYNC (1 2 1:*))").is_err());
        assert!(parse_select_request("INBOX (QRESYNC (4294967296 2))").is_err());
        assert!(parse_select_request("INBOX (QRESYNC (1 2 4294967296))").is_err());
        assert!(parse_select_request("INBOX (QRESYNC (1 2 1:4 (1:2 1:3)))").is_err());
        assert!(parse_select_request("INBOX (UNKNOWN)").is_err());
        assert!(parse_select_request("INBOX (CONDSTORE CONDSTORE)").is_err());

        let sequences = SequenceSet::parse_nostar("2:4,8:10").unwrap();
        let uids = SequenceSet::parse_nostar("20:22,40:42").unwrap();
        assert_eq!(
            SequenceSet::qresync_sample_endpoints(&sequences, &uids),
            Some(vec![(2, 20), (4, 22), (8, 40), (10, 42)])
        );
    }

    #[test]
    fn sequence_set_handles_reverse_ranges_star_and_deduplication() {
        assert_eq!(ids_from_set("4:2,*,2", 5), vec![2, 3, 4, 5]);
        assert!(SequenceSet::parse("4294967296", 1).is_none());
        assert!(SequenceSet::parse_nostar("4294967296").is_none());
    }

    #[test]
    fn parses_fetch_items_separately_from_modifiers_and_rejects_invalid_items() {
        let request = parse_fetch_request(
            "(UID FLAGS BODY.PEEK[HEADER.FIELDS (From Subject)] BODY[2.TEXT]<4.8> BINARY.SIZE[3]) (CHANGEDSINCE 42 VANISHED)",
        )
        .unwrap();
        assert!(request.items.contains(&"UID".to_string()));
        assert!(request.items.contains(&"FLAGS".to_string()));
        assert!(
            request
                .items
                .contains(&"BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)]".to_string())
        );
        assert!(request.items.contains(&"BODY[2.TEXT]<4.8>".to_string()));
        assert!(request.items.contains(&"BINARY.SIZE[3]".to_string()));
        assert_eq!(
            request.modifier_spec.as_deref(),
            Some("(CHANGEDSINCE 42 VANISHED)")
        );

        let full = parse_fetch_request("FULL").unwrap();
        assert!(full.items.contains(&"BODY".to_string()));
        for invalid in [
            "()",
            "(ALL UID)",
            "(UNKNOWN)",
            "(BODY[0])",
            "(BODY[1..2])",
            "(BODY[1]<x.2>)",
            "(BODY[1]<2>)",
            "(BODY[1]<2.3>junk)",
            "(BODY[HEADER.FIELDS ()])",
            "(BINARY.SIZE[1]<0.2>)",
            "(BINARY[1.TEXT])",
            "(UID) trailing",
            "(UID",
        ] {
            assert!(parse_fetch_request(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn parses_esearch_return_options_before_search_keys() {
        let request = parse_search_request("RETURN (MIN MAX ALL COUNT) UNSEEN").unwrap();
        assert_eq!(
            request.return_options,
            Some(SearchReturnOptions {
                min: true,
                max: true,
                all: true,
                count: true,
                save: false,
            })
        );
        assert!(matches!(request.criterion, SearchCriterion::Unseen));

        let default_all = parse_search_request("RETURN () ALL").unwrap();
        assert!(default_all.return_options.unwrap().all);
        assert!(
            parse_search_request("RETURN (SAVE) ALL")
                .unwrap()
                .return_options
                .unwrap()
                .save
        );
        assert!(parse_search_request("RETURN MIN ALL").is_err());
    }

    #[test]
    fn parses_sort_program_charset_and_search_criteria() {
        let request = parse_sort_request("(REVERSE DATE SUBJECT SIZE) UTF-8 UNSEEN").unwrap();
        assert_eq!(
            request.criteria,
            vec![
                SortCriterion {
                    key: SortKey::Date,
                    reverse: true,
                },
                SortCriterion {
                    key: SortKey::Subject,
                    reverse: false,
                },
                SortCriterion {
                    key: SortKey::Size,
                    reverse: false,
                },
            ]
        );
        assert_eq!(request.charset, "UTF-8");
        assert!(matches!(request.search, SearchCriterion::Unseen));
        assert!(parse_sort_request("() UTF-8 ALL").is_err());
        assert!(parse_sort_request("(DATE REVERSE) UTF-8 ALL").is_err());
        assert!(parse_sort_request("(UNKNOWN) UTF-8 ALL").is_err());
        assert_eq!(
            parse_sort_request("(DATE) ISO-8859-1 ALL").unwrap_err(),
            SortParseError::UnsupportedCharset("ISO-8859-1".to_string())
        );
    }

    #[test]
    fn parses_thread_algorithm_charset_and_search_criteria() {
        let references = parse_thread_request("REFERENCES UTF-8 UNSEEN").unwrap();
        assert_eq!(references.algorithm, ThreadAlgorithm::References);
        assert!(matches!(references.search, SearchCriterion::Unseen));
        let ordered = parse_thread_request("ORDEREDSUBJECT US-ASCII ALL").unwrap();
        assert_eq!(ordered.algorithm, ThreadAlgorithm::OrderedSubject);
        assert_eq!(
            parse_thread_request("REFS UTF-8 ALL").unwrap().algorithm,
            ThreadAlgorithm::Refs
        );
        assert!(matches!(
            parse_thread_request("REFERENCES ISO-8859-1 ALL"),
            Err(SortParseError::UnsupportedCharset(_))
        ));
    }

    #[test]
    fn parses_basic_list_with_wildcard_pattern() {
        let request = parse_list_request("\"\" \"*\"", false).expect("list request");
        assert_eq!(request.reference, "");
        assert_eq!(request.patterns, vec!["*"]);
        assert!(request.returns.children);
        assert!(request.returns.special_use);
        assert!(!request.extended);
    }

    #[test]
    fn parses_extended_list_selection_pattern_list_and_status_return() {
        let request = parse_list_request(
            r#"(SPECIAL-USE) "" ("INBOX" "Archive/%") RETURN (SPECIAL-USE CHILDREN STATUS (MESSAGES UIDNEXT UNSEEN))"#,
            false,
        )
        .expect("extended list");
        assert!(request.extended);
        assert!(request.selection.special_use);
        assert_eq!(request.patterns, vec!["INBOX", "Archive/%"]);
        assert!(request.returns.special_use);
        assert!(request.returns.children);
        assert_eq!(
            request.returns.status,
            vec![
                StatusItem::Messages,
                StatusItem::UidNext,
                StatusItem::Unseen
            ]
        );
        assert!(parse_list_request(r#""" "*" RETURN (STATUS (MESSAGES UNKNOWN))"#, false).is_err());

        let status = parse_status_request("INBOX (MESSAGES UIDNEXT SIZE)").unwrap();
        assert_eq!(status.mailbox, "INBOX");
        assert_eq!(
            status.items,
            [StatusItem::Messages, StatusItem::UidNext, StatusItem::Size]
        );
        for invalid in [
            "INBOX MESSAGES",
            "INBOX ()",
            "INBOX (UNKNOWN)",
            "INBOX (MESSAGES MESSAGES)",
            "INBOX (MESSAGES) trailing",
        ] {
            assert!(parse_status_request(invalid).is_err(), "accepted {invalid}");
        }
    }
}
