//! RFC 5465 NOTIFY: which changes the server reports on its own, and for
//! which mailboxes.
//!
//! `NOTIFY SET` stores the requested event groups in a [`Notifier`]. While
//! one is active the session polls storage between commands (and during
//! IDLE): changes to the selected mailbox go out as EXISTS, EXPUNGE and
//! FETCH, changes to other mailboxes as STATUS, and mailbox, subscription
//! and metadata changes as LIST and METADATA responses. Other mailboxes are
//! tracked by comparing successive account [`Snapshot`]s.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::io::AsyncWriteExt;

use super::context::UpdateContexts;
use crate::mailbox::{self, MailboxSyncEvent, SelectedMailbox, SyncOptions};
use crate::parser;
use crate::response::{Response, Status, StatusLine};
use crate::session::ImapReader;

/// How often the session looks for changes while waiting for a command.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// How often mailboxes other than the selected one are rescanned.
const ACCOUNT_SCAN_INTERVAL: Duration = Duration::from_secs(2);
/// More notifications than this from one scan end notifications with
/// `[NOTIFICATIONOVERFLOW]` (RFC 5465 §5.8).
const MAX_NOTIFICATIONS_PER_SCAN: usize = 1000;

const SUPPORTED_EVENTS: &str = "MessageNew MessageExpunge FlagChange MailboxName \
                                SubscriptionChange MailboxMetadataChange ServerMetadataChange";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Filter {
    Selected,
    SelectedDelayed,
    Inboxes,
    Personal,
    Subscribed,
    Subtree(Vec<String>),
    Mailboxes(Vec<String>),
}

impl Filter {
    fn is_selected(&self) -> bool {
        matches!(self, Self::Selected | Self::SelectedDelayed)
    }

    /// Whether a mailbox other than the selected one matches.
    fn matches(&self, name: &str, subscribed: &dyn Fn(&str) -> bool) -> bool {
        match self {
            Self::Selected | Self::SelectedDelayed => false,
            Self::Inboxes => name == "INBOX",
            Self::Personal => true,
            Self::Subscribed => subscribed(name),
            Self::Subtree(roots) => roots.iter().any(|root| {
                name == root
                    || name
                        .strip_prefix(root.as_str())
                        .is_some_and(|rest| rest.starts_with('/'))
            }),
            Self::Mailboxes(names) => names.iter().any(|candidate| candidate == name),
        }
    }
}

/// The message attributes sent with MessageNew for the selected mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FetchItems {
    items: Vec<String>,
    raw: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Events {
    message_new: bool,
    fetch: Option<FetchItems>,
    message_expunge: bool,
    flag_change: bool,
    mailbox_name: bool,
    subscription_change: bool,
    mailbox_metadata: bool,
    server_metadata: bool,
}

impl Events {
    fn message_events(&self) -> bool {
        self.message_new || self.message_expunge || self.flag_change
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Group {
    filter: Filter,
    events: Events,
}

/// The event groups of one `NOTIFY SET`, in the order given. A mailbox gets
/// the events of the first group whose filter matches it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Spec {
    groups: Vec<Group>,
}

impl Spec {
    fn selected_group(&self) -> Option<&Group> {
        self.groups.iter().find(|group| group.filter.is_selected())
    }

    /// The events for a mailbox other than the selected one.
    fn events_for(&self, name: &str, subscribed: &dyn Fn(&str) -> bool) -> Option<&Events> {
        self.groups
            .iter()
            .find(|group| group.filter.matches(name, subscribed))
            .map(|group| &group.events)
    }

    /// The events for any mailbox; the selected mailbox uses the SELECTED
    /// group when there is one.
    fn events_for_any(
        &self,
        name: &str,
        selected: Option<&str>,
        subscribed: &dyn Fn(&str) -> bool,
    ) -> Option<&Events> {
        if selected.is_some_and(|selected| selected == name)
            && let Some(group) = self.selected_group()
        {
            return Some(&group.events);
        }
        self.events_for(name, subscribed)
    }

    fn server_metadata(&self) -> bool {
        self.groups.iter().any(|group| group.events.server_metadata)
    }

    fn needs_subscriptions(&self) -> bool {
        self.groups
            .iter()
            .any(|group| group.filter == Filter::Subscribed || group.events.subscription_change)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Request {
    None,
    Set { status: bool, spec: Spec },
}

/// A rejected NOTIFY command: `BAD` for syntax errors, `NO [BADEVENT]` for
/// events the server does not support.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Rejection {
    Bad(String),
    BadEvent,
}

impl Rejection {
    pub(crate) fn response(&self, tag: &str) -> Response {
        match self {
            Self::Bad(text) => {
                Response::new().status(StatusLine::tagged(tag, Status::Bad, text.clone()))
            }
            Self::BadEvent => Response::new().status(
                StatusLine::tagged(tag, Status::No, "Unsupported NOTIFY event")
                    .with_code(format!("BADEVENT ({SUPPORTED_EVENTS})")),
            ),
        }
    }
}

fn bad(text: &str) -> Rejection {
    Rejection::Bad(text.to_string())
}

pub(crate) fn parse(args: &str, utf8_accept: bool) -> Result<Request, Rejection> {
    let tokens = tokenize(args).map_err(|_| bad("Invalid NOTIFY arguments"))?;
    let mut tokens = tokens.into_iter();
    let action = match tokens.next() {
        Some(Token::Atom(atom)) => atom.to_ascii_uppercase(),
        _ => return Err(bad("Expected NOTIFY SET or NOTIFY NONE")),
    };
    match action.as_str() {
        "NONE" => {
            if tokens.next().is_some() {
                return Err(bad("NOTIFY NONE takes no arguments"));
            }
            Ok(Request::None)
        }
        "SET" => {
            let mut tokens = tokens.peekable();
            let status = matches!(
                tokens.peek(),
                Some(Token::Atom(atom)) if atom.eq_ignore_ascii_case("STATUS")
            );
            if status {
                tokens.next();
            }
            let mut groups = Vec::new();
            for token in tokens {
                let Token::List(items, _) = token else {
                    return Err(bad("Expected an event group"));
                };
                groups.push(parse_group(items, utf8_accept)?);
            }
            if groups.is_empty() {
                return Err(bad("NOTIFY SET needs at least one event group"));
            }
            if groups
                .iter()
                .filter(|group| group.filter.is_selected())
                .count()
                > 1
            {
                return Err(bad(
                    "Only one SELECTED or SELECTED-DELAYED group is allowed",
                ));
            }
            Ok(Request::Set {
                status,
                spec: Spec { groups },
            })
        }
        _ => Err(bad("Expected NOTIFY SET or NOTIFY NONE")),
    }
}

fn parse_group(items: Vec<Token>, utf8_accept: bool) -> Result<Group, Rejection> {
    let mut items = items.into_iter();
    let Some(Token::Atom(filter)) = items.next() else {
        return Err(bad("Expected a mailbox filter"));
    };
    let filter = match filter.to_ascii_uppercase().as_str() {
        "SELECTED" => Filter::Selected,
        "SELECTED-DELAYED" => Filter::SelectedDelayed,
        "INBOXES" => Filter::Inboxes,
        "PERSONAL" => Filter::Personal,
        "SUBSCRIBED" => Filter::Subscribed,
        kind @ ("SUBTREE" | "MAILBOXES") => {
            let names = match items.next() {
                Some(Token::List(names, _)) if !names.is_empty() => names,
                Some(token @ (Token::Atom(_) | Token::Quoted(_))) => vec![token],
                _ => return Err(bad("Expected one or more mailbox names")),
            };
            let names = names
                .into_iter()
                .map(|name| mailbox_name(name, utf8_accept))
                .collect::<Result<Vec<_>, _>>()?;
            if kind == "SUBTREE" {
                Filter::Subtree(names)
            } else {
                Filter::Mailboxes(names)
            }
        }
        _ => return Err(bad("Unknown mailbox filter")),
    };
    let events = match items.next() {
        Some(Token::Atom(atom)) if atom.eq_ignore_ascii_case("NONE") => Events::default(),
        Some(Token::List(events, _)) if !events.is_empty() => {
            parse_events(events, filter.is_selected())?
        }
        _ => return Err(bad("Expected an event list or NONE")),
    };
    if items.next().is_some() {
        return Err(bad("Unexpected data after event list"));
    }
    Ok(Group { filter, events })
}

fn mailbox_name(token: Token, utf8_accept: bool) -> Result<String, Rejection> {
    let name = match token {
        Token::Atom(name) | Token::Quoted(name) => name,
        Token::List(..) => return Err(bad("Invalid mailbox name")),
    };
    mailbox::decode_wire_mailbox_name(&name, utf8_accept)
        .and_then(|name| rmail_common::maildir::normalize_mailbox_name(&name))
        .map_err(|_| bad("Invalid mailbox name"))
}

fn parse_events(tokens: Vec<Token>, selected: bool) -> Result<Events, Rejection> {
    let mut events = Events::default();
    let mut tokens = tokens.into_iter().peekable();
    let mut unsupported = false;
    while let Some(token) = tokens.next() {
        let Token::Atom(name) = token else {
            return Err(bad("Expected an event name"));
        };
        match name.to_ascii_uppercase().as_str() {
            "MESSAGENEW" => {
                events.message_new = true;
                if let Some(Token::List(..)) = tokens.peek() {
                    let Some(Token::List(_, raw)) = tokens.next() else {
                        unreachable!("peeked a list");
                    };
                    if !selected {
                        return Err(bad(
                            "MessageNew fetch attributes are only allowed for SELECTED",
                        ));
                    }
                    events.fetch = Some(parse_fetch_items(&raw)?);
                }
            }
            "MESSAGEEXPUNGE" => events.message_expunge = true,
            "FLAGCHANGE" => events.flag_change = true,
            "MAILBOXNAME" => events.mailbox_name = true,
            "SUBSCRIPTIONCHANGE" => events.subscription_change = true,
            "MAILBOXMETADATACHANGE" => events.mailbox_metadata = true,
            "SERVERMETADATACHANGE" => events.server_metadata = true,
            // AnnotationChange needs ANNOTATE (RFC 5257); unknown names are
            // extension events this server does not have.
            _ => unsupported = true,
        }
    }
    // RFC 5465 §5: MessageNew and MessageExpunge come together, and
    // FlagChange needs both.
    if events.message_new != events.message_expunge || (events.flag_change && !events.message_new) {
        return Err(bad(
            "MessageNew and MessageExpunge must be given together, and FlagChange needs both",
        ));
    }
    if unsupported {
        return Err(Rejection::BadEvent);
    }
    Ok(events)
}

fn parse_fetch_items(raw: &str) -> Result<FetchItems, Rejection> {
    let request = parser::parse_fetch_command_request(&format!("1 ({raw})"))
        .map_err(|_| bad("Invalid MessageNew fetch attributes"))?;
    if request.changed_since.is_some() || request.vanished {
        return Err(bad("Invalid MessageNew fetch attributes"));
    }
    if super::fetch::fetch_marks_seen(&request.items) {
        // A notification must not change the message; BODY.PEEK and
        // BINARY.PEEK fetch the same data without setting \Seen.
        return Err(bad("MessageNew fetch attributes must not set \\Seen"));
    }
    Ok(FetchItems {
        items: request.items,
        raw: request.raw_items,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Atom(String),
    Quoted(String),
    /// A parenthesized list and its raw inner text.
    List(Vec<Token>, String),
}

fn tokenize(input: &str) -> Result<Vec<Token>, ()> {
    let mut parser = Tokenizer {
        input,
        position: 0,
        depth: 0,
    };
    let tokens = parser.list_items()?;
    if parser.position < input.len() {
        return Err(());
    }
    Ok(tokens)
}

struct Tokenizer<'a> {
    input: &'a str,
    position: usize,
    depth: usize,
}

impl Tokenizer<'_> {
    fn peek(&self) -> Option<char> {
        self.input[self.position..].chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let character = self.peek()?;
        self.position += character.len_utf8();
        Some(character)
    }

    /// Tokens up to the end of input or a closing parenthesis.
    fn list_items(&mut self) -> Result<Vec<Token>, ()> {
        let mut tokens = Vec::new();
        loop {
            while self.peek().is_some_and(|character| character == ' ') {
                self.bump();
            }
            match self.peek() {
                None | Some(')') => return Ok(tokens),
                Some('(') => {
                    self.bump();
                    self.depth += 1;
                    if self.depth > 8 {
                        return Err(());
                    }
                    let start = self.position;
                    let items = self.list_items()?;
                    let end = self.position;
                    if self.bump() != Some(')') {
                        return Err(());
                    }
                    self.depth -= 1;
                    tokens.push(Token::List(items, self.input[start..end].to_string()));
                }
                Some('"') => tokens.push(Token::Quoted(self.quoted()?)),
                Some(_) => tokens.push(Token::Atom(self.atom()?)),
            }
            if !matches!(self.peek(), None | Some(' ') | Some(')')) {
                return Err(());
            }
        }
    }

    fn quoted(&mut self) -> Result<String, ()> {
        self.bump();
        let mut value = String::new();
        loop {
            match self.bump().ok_or(())? {
                '"' => return Ok(value),
                '\\' => value.push(self.bump().ok_or(())?),
                '\r' | '\n' => return Err(()),
                character => value.push(character),
            }
        }
    }

    /// An atom; a `[...]` section (as in `BODY.PEEK[HEADER.FIELDS (A B)]`)
    /// may contain spaces and parentheses.
    fn atom(&mut self) -> Result<String, ()> {
        let start = self.position;
        let mut brackets = 0usize;
        while let Some(character) = self.peek() {
            match character {
                '[' => brackets += 1,
                ']' if brackets > 0 => brackets -= 1,
                ' ' | '(' | ')' if brackets == 0 => break,
                '"' | '\r' | '\n' | '{' if brackets == 0 => return Err(()),
                _ => {}
            }
            self.bump();
        }
        if brackets > 0 || self.position == start {
            return Err(());
        }
        Ok(self.input[start..self.position].to_string())
    }
}

/// STATUS values reported for a mailbox other than the selected one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counts {
    messages: usize,
    uidnext: u64,
    uidvalidity: u64,
    unseen: usize,
    highest_modseq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FolderState {
    name: String,
    /// Kept for mailboxes whose group has message events.
    counts: Option<Counts>,
    /// Kept for mailboxes whose group has MailboxMetadataChange.
    metadata: Option<Vec<(String, String)>>,
}

/// The account state NOTIFY compares against, keyed by MAILBOXID so a
/// renamed mailbox is recognized.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Snapshot {
    folders: HashMap<String, FolderState>,
    subscriptions: BTreeSet<String>,
    server_metadata: Option<Vec<(String, String)>>,
}

/// Read the account state the groups in `spec` need.
pub(crate) fn scan(root: &Path, domain: &str, local: &str, spec: &Spec) -> Result<Snapshot> {
    use rmail_common::imap_state;

    let subscriptions = if spec.needs_subscriptions() {
        imap_state::list_subscriptions(root, domain, local)?
            .into_iter()
            .collect::<BTreeSet<_>>()
    } else {
        BTreeSet::new()
    };
    let is_subscribed = |name: &str| subscriptions.contains(name);
    let mut folders = HashMap::new();
    for folder in imap_state::list_folders(root, domain, local)? {
        let events = spec.events_for(&folder.name, &is_subscribed);
        let counts = if events.is_some_and(Events::message_events) {
            imap_state::folder_summary(root, domain, local, &folder.name)?.map(|summary| Counts {
                messages: summary.messages,
                uidnext: summary.folder.uidnext,
                uidvalidity: summary.folder.uidvalidity,
                unseen: summary.unseen,
                highest_modseq: summary.folder.highest_modseq,
            })
        } else {
            None
        };
        // The selected mailbox may have a SELECTED group with metadata
        // events, so metadata is read for every group that asks for it.
        let wants_metadata = events.is_some_and(|events| events.mailbox_metadata)
            || spec
                .selected_group()
                .is_some_and(|group| group.events.mailbox_metadata);
        let metadata = if wants_metadata {
            imap_state::get_metadata(root, domain, local, Some(&folder.name))?
        } else {
            None
        };
        folders.insert(
            folder.mailbox_id,
            FolderState {
                name: folder.name,
                counts,
                metadata,
            },
        );
    }
    let server_metadata = if spec.server_metadata() {
        imap_state::get_metadata(root, domain, local, None)?
    } else {
        None
    };
    Ok(Snapshot {
        folders,
        subscriptions,
        server_metadata,
    })
}

/// Session settings that shape notifications.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Format {
    pub(crate) utf8_accept: bool,
    pub(crate) condstore: bool,
}

fn status_line(name: &str, counts: &Counts, format: Format) -> String {
    let mut line = format!(
        "STATUS {} (MESSAGES {} UIDNEXT {} UIDVALIDITY {} UNSEEN {}",
        mailbox::quote_wire_mailbox_name(name, format.utf8_accept),
        counts.messages,
        counts.uidnext,
        counts.uidvalidity,
        counts.unseen
    );
    if format.condstore {
        line.push_str(&format!(" HIGHESTMODSEQ {}", counts.highest_modseq));
    }
    line.push(')');
    line
}

fn list_line(attributes: &[&str], name: &str, old_name: Option<&str>, format: Format) -> String {
    let mut line = format!(
        "LIST ({}) \"/\" {}",
        attributes.join(" "),
        mailbox::quote_wire_mailbox_name(name, format.utf8_accept)
    );
    if let Some(old_name) = old_name {
        line.push_str(&format!(
            " (\"OLDNAME\" ({}))",
            mailbox::quote_wire_mailbox_name(old_name, format.utf8_accept)
        ));
    }
    line
}

fn metadata_line(mailbox: Option<&str>, entries: &[&str], format: Format) -> String {
    let mailbox = mailbox.map_or_else(
        || "\"\"".to_string(),
        |name| mailbox::quote_wire_mailbox_name(name, format.utf8_accept),
    );
    let entries = entries
        .iter()
        .map(|entry| format!("\"{}\"", entry.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(" ");
    format!("METADATA {mailbox} {entries}")
}

/// Entries added, changed or removed between two metadata listings.
fn changed_entries<'a>(old: &'a [(String, String)], new: &'a [(String, String)]) -> Vec<&'a str> {
    let old_map = old
        .iter()
        .map(|(entry, value)| (entry.to_ascii_lowercase(), value))
        .collect::<HashMap<_, _>>();
    let new_map = new
        .iter()
        .map(|(entry, value)| (entry.to_ascii_lowercase(), value))
        .collect::<HashMap<_, _>>();
    let mut changed = Vec::new();
    for (entry, value) in new {
        if old_map.get(&entry.to_ascii_lowercase()) != Some(&value) {
            changed.push(entry.as_str());
        }
    }
    for (entry, _) in old {
        if !new_map.contains_key(&entry.to_ascii_lowercase()) {
            changed.push(entry.as_str());
        }
    }
    changed
}

/// STATUS responses for `NOTIFY SET STATUS`: every mailbox with message
/// events, other than the selected one.
pub(crate) fn initial_status(
    snapshot: &Snapshot,
    selected: Option<&str>,
    format: Format,
) -> Vec<String> {
    let mut folders = snapshot
        .folders
        .values()
        .filter(|folder| selected != Some(folder.name.as_str()))
        .filter_map(|folder| Some((folder.name.as_str(), folder.counts.as_ref()?)))
        .collect::<Vec<_>>();
    folders.sort_by(|a, b| a.0.cmp(b.0));
    folders
        .into_iter()
        .map(|(name, counts)| status_line(name, counts, format))
        .collect()
}

/// The untagged responses (without the leading `* `) that describe how the
/// account changed from `old` to `new`. Message changes in the selected
/// mailbox are not included; they are reported as EXISTS/EXPUNGE/FETCH.
pub(crate) fn diff(
    spec: &Spec,
    old: &Snapshot,
    new: &Snapshot,
    selected: Option<&str>,
    format: Format,
) -> Vec<String> {
    let subscribed_now = |name: &str| new.subscriptions.contains(name);
    let subscribed_either =
        |name: &str| new.subscriptions.contains(name) || old.subscriptions.contains(name);
    let mut lines = Vec::new();
    // Names already sent in a MailboxName LIST, which carries \Subscribed.
    let mut listed = HashSet::new();

    let mut ids = old
        .folders
        .keys()
        .chain(new.folders.keys())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    ids.sort_by_key(|id| {
        new.folders
            .get(*id)
            .or_else(|| old.folders.get(*id))
            .map(|folder| folder.name.clone())
    });

    for id in ids {
        match (old.folders.get(id), new.folders.get(id)) {
            (None, Some(created)) => {
                if spec
                    .events_for_any(&created.name, selected, &subscribed_now)
                    .is_some_and(|events| events.mailbox_name)
                {
                    let mut attributes = Vec::new();
                    if subscribed_now(&created.name) {
                        attributes.push("\\Subscribed");
                    }
                    lines.push(list_line(&attributes, &created.name, None, format));
                    listed.insert(created.name.as_str());
                }
            }
            (Some(deleted), None) => {
                if spec
                    .events_for_any(&deleted.name, selected, &subscribed_either)
                    .is_some_and(|events| events.mailbox_name)
                {
                    lines.push(list_line(&["\\NonExistent"], &deleted.name, None, format));
                    listed.insert(deleted.name.as_str());
                }
            }
            (Some(before), Some(after)) => {
                if before.name != after.name {
                    let wanted = [&before.name, &after.name].iter().any(|name| {
                        spec.events_for_any(name, selected, &subscribed_either)
                            .is_some_and(|events| events.mailbox_name)
                    });
                    if wanted {
                        let mut attributes = Vec::new();
                        if subscribed_now(&after.name) {
                            attributes.push("\\Subscribed");
                        }
                        lines.push(list_line(
                            &attributes,
                            &after.name,
                            Some(&before.name),
                            format,
                        ));
                        listed.insert(before.name.as_str());
                        listed.insert(after.name.as_str());
                    }
                    // Counts and metadata of a renamed mailbox are compared
                    // from the next scan on.
                    continue;
                }
                let Some(events) = spec.events_for_any(&after.name, selected, &subscribed_now)
                else {
                    continue;
                };
                if selected != Some(after.name.as_str())
                    && let (Some(was), Some(now)) = (&before.counts, &after.counts)
                {
                    let arrived = was.uidnext != now.uidnext || was.uidvalidity != now.uidvalidity;
                    let count_changed = was.messages != now.messages;
                    let flags_changed =
                        was.unseen != now.unseen || was.highest_modseq != now.highest_modseq;
                    if (events.message_new && (arrived || count_changed))
                        || (events.message_expunge && count_changed)
                        || (events.flag_change && flags_changed)
                    {
                        lines.push(status_line(&after.name, now, format));
                    }
                }
                if events.mailbox_metadata
                    && let (Some(was), Some(now)) = (&before.metadata, &after.metadata)
                {
                    let entries = changed_entries(was, now);
                    if !entries.is_empty() {
                        lines.push(metadata_line(Some(&after.name), &entries, format));
                    }
                }
            }
            (None, None) => {}
        }
    }

    let mut subscription_changes = old
        .subscriptions
        .symmetric_difference(&new.subscriptions)
        .collect::<Vec<_>>();
    subscription_changes.sort();
    for name in subscription_changes {
        if !listed.contains(name.as_str())
            && spec
                .events_for_any(name, selected, &subscribed_either)
                .is_some_and(|events| events.subscription_change)
        {
            let attributes: &[&str] = if new.subscriptions.contains(name) {
                &["\\Subscribed"]
            } else {
                &[]
            };
            lines.push(list_line(attributes, name, None, format));
        }
    }

    if let (Some(was), Some(now)) = (&old.server_metadata, &new.server_metadata) {
        let entries = changed_entries(was, now);
        if !entries.is_empty() {
            lines.push(metadata_line(None, &entries, format));
        }
    }
    lines
}

/// Account context for polling.
#[derive(Clone, Copy)]
pub(crate) struct Account<'a> {
    pub(crate) mail_root: &'a str,
    pub(crate) address: &'a str,
}

/// The active `NOTIFY SET` of a session.
pub(crate) struct Notifier {
    spec: Spec,
    snapshot: Snapshot,
    last_scan: Instant,
    overflowed: bool,
}

impl Notifier {
    pub(crate) fn new(spec: Spec, snapshot: Snapshot) -> Self {
        Self {
            spec,
            snapshot,
            last_scan: Instant::now(),
            overflowed: false,
        }
    }

    /// False once notifications overflowed; the session then drops the
    /// notifier, as after `NOTIFY NONE`.
    pub(crate) fn is_active(&self) -> bool {
        !self.overflowed
    }

    /// Report changes made since the last poll. `in_idle` is true inside
    /// IDLE, which may always report expunges in the selected mailbox.
    pub(crate) async fn poll(
        &mut self,
        reader: &mut ImapReader,
        account: Account<'_>,
        selected: &mut Option<SelectedMailbox>,
        contexts: &mut UpdateContexts,
        options: SyncOptions,
        format: Format,
        in_idle: bool,
    ) -> Result<()> {
        if self.overflowed {
            return Ok(());
        }
        self.poll_selected(
            reader,
            account.mail_root,
            selected,
            contexts,
            options,
            in_idle,
        )
        .await?;
        if self.last_scan.elapsed() < ACCOUNT_SCAN_INTERVAL {
            return Ok(());
        }
        self.last_scan = Instant::now();
        let (local, domain) = mailbox::address_parts(account.address)?;
        let root = account.mail_root.to_string();
        let spec = self.spec.clone();
        let scanned =
            tokio::task::spawn_blocking(move || scan(Path::new(&root), &domain, &local, &spec))
                .await?;
        let snapshot = match scanned {
            Ok(snapshot) => snapshot,
            Err(error) => {
                imap_log!("warn", "notify_scan_failed", { "error": error.to_string() });
                return Ok(());
            }
        };
        let selected_name = selected.as_ref().map(|mailbox| mailbox.name.as_str());
        let lines = diff(&self.spec, &self.snapshot, &snapshot, selected_name, format);
        self.snapshot = snapshot;
        if lines.is_empty() {
            return Ok(());
        }
        let mut response = Response::new();
        let overflow = lines.len() > MAX_NOTIFICATIONS_PER_SCAN;
        if overflow {
            response = response.status(
                StatusLine::untagged(Status::Ok, "Too many changes; notifications are off")
                    .with_code("NOTIFICATIONOVERFLOW"),
            );
        } else {
            for line in lines {
                response = response.data(line);
            }
        }
        write(reader, &response.encode()).await?;
        self.overflowed = overflow;
        Ok(())
    }

    async fn poll_selected(
        &self,
        reader: &mut ImapReader,
        mail_root: &str,
        selected: &mut Option<SelectedMailbox>,
        contexts: &mut UpdateContexts,
        options: SyncOptions,
        in_idle: bool,
    ) -> Result<()> {
        let Some(current) = selected.as_ref() else {
            return Ok(());
        };
        let group = self
            .spec
            .selected_group()
            .filter(|group| group.events.message_events());
        let Some(group) = group else {
            // Without message events for the selected mailbox, updates wait
            // for a command; IDLE still reports them as always.
            if in_idle {
                crate::sync_selected_mailbox(reader, mail_root, selected, contexts, options)
                    .await?;
            }
            return Ok(());
        };
        let options = SyncOptions {
            // SELECTED-DELAYED holds expunges until a command that may
            // report them (RFC 5465 §5.1).
            allow_expunge: in_idle || group.filter == Filter::Selected,
            ..options
        };
        let known = current
            .msgs
            .iter()
            .map(|message| message.0)
            .collect::<HashSet<_>>();
        let (refreshed, events) =
            mailbox::refresh_selected_mailbox(mail_root, current, options).await?;
        // RFC 5267: REMOVEFROM ahead of EXPUNGE, ADDTO after EXISTS.
        let mut output = contexts.before_events(current, &events);
        for event in &events {
            if matches!(event, MailboxSyncEvent::FetchFlags { .. }) && !group.events.flag_change {
                continue;
            }
            output.push_str(&event.response_line(options));
        }
        if !output.is_empty() {
            reader.get_mut().write_all(output.as_bytes()).await?;
        }
        if let Some(fetch) = &group.events.fetch {
            write_new_messages(reader, mail_root, &refreshed, &known, fetch, options).await?;
        }
        let updates = contexts
            .refresh(Some(&refreshed), options.imap4rev2)
            .await?;
        reader.get_mut().write_all(updates.as_bytes()).await?;
        reader.get_mut().flush().await?;
        *selected = Some(refreshed);
        Ok(())
    }
}

/// FETCH responses with the MessageNew attributes for messages that arrived
/// in the selected mailbox.
async fn write_new_messages(
    reader: &mut ImapReader,
    mail_root: &str,
    refreshed: &SelectedMailbox,
    known: &HashSet<u64>,
    fetch: &FetchItems,
    options: SyncOptions,
) -> Result<()> {
    let mut items = fetch.items.clone();
    if options.condstore && !items.iter().any(|item| item == "MODSEQ") {
        items.push("MODSEQ".to_string());
    }
    let new_ids = refreshed
        .msgs
        .iter()
        .filter(|message| !known.contains(&message.0))
        .filter_map(|message| refreshed.email_ids.get(&message.0).cloned())
        .collect();
    let thread_ids = mailbox::thread_ids_for(mail_root, refreshed, &items, new_ids).await;
    for (index, (uid, path, flags, modseq)) in refreshed.msgs.iter().enumerate() {
        if known.contains(uid) || refreshed.is_expunged(*uid) {
            continue;
        }
        let email_id = refreshed
            .email_ids
            .get(uid)
            .map(String::as_str)
            .unwrap_or_default();
        let mut flags = flags.clone();
        if !options.imap4rev2 && refreshed.recent_uids.contains(uid) {
            flags.push("\\Recent".to_string());
            flags.sort();
            flags.dedup();
        }
        mailbox::write_fetch_response(
            reader,
            index + 1,
            *uid,
            &flags,
            *modseq,
            refreshed.internal_dates.get(uid).copied().unwrap_or((0, 0)),
            refreshed.save_dates.get(uid).copied().unwrap_or(0),
            email_id,
            thread_ids.get(email_id).map(String::as_str),
            path.clone(),
            &items,
            &fetch.raw,
            options.condstore,
            options.uidonly,
        )
        .await?;
    }
    Ok(())
}

async fn write(reader: &mut ImapReader, output: &str) -> Result<()> {
    reader.get_mut().write_all(output.as_bytes()).await?;
    reader.get_mut().flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(args: &str) -> Spec {
        match parse(args, false) {
            Ok(Request::Set { spec, .. }) => spec,
            other => panic!("{args}: {other:?}"),
        }
    }

    #[test]
    fn parses_none_and_set_with_status() {
        assert_eq!(parse("NONE", false), Ok(Request::None));
        let Ok(Request::Set { status, spec }) = parse(
            "SET STATUS (selected (MessageNew (UID BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)]) MessageExpunge FlagChange)) (subtree \"Lists\" (MessageNew MessageExpunge MailboxName))",
            false,
        ) else {
            panic!("expected SET");
        };
        assert!(status);
        assert_eq!(spec.groups.len(), 2);
        let fetch = spec.groups[0].events.fetch.as_ref().unwrap();
        assert_eq!(fetch.raw, "(UID BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)])");
        assert_eq!(spec.groups[1].filter, Filter::Subtree(vec!["Lists".into()]));
        assert!(spec.groups[1].events.mailbox_name);
    }

    #[test]
    fn mailbox_lists_and_none_events() {
        let spec = spec("SET (mailboxes (INBOX \"Sent Items\") NONE) (personal (MailboxName))");
        assert_eq!(
            spec.groups[0].filter,
            Filter::Mailboxes(vec!["INBOX".into(), "Sent Items".into()])
        );
        assert_eq!(spec.groups[0].events, Events::default());
        // The first matching group wins.
        let never = |_: &str| false;
        assert!(!spec.events_for("INBOX", &never).unwrap().mailbox_name);
        assert!(spec.events_for("Archive", &never).unwrap().mailbox_name);
    }

    #[test]
    fn rejects_invalid_combinations() {
        for args in [
            "",
            "SET",
            "SET STATUS",
            "NONE extra",
            "SET (personal (MessageNew))",
            "SET (personal (FlagChange))",
            "SET (personal (MessageNew (UID) MessageExpunge))",
            "SET (selected (MessageNew (BODY[]) MessageExpunge))",
            "SET (selected (MessageNew MessageExpunge)) (selected-delayed NONE)",
            "SET (unknown (MailboxName))",
            "SET (personal ())",
            "SET (subtree (MailboxName))",
        ] {
            assert!(
                matches!(parse(args, false), Err(Rejection::Bad(_))),
                "{args:?} was accepted"
            );
        }
        assert_eq!(
            parse(
                "SET (personal (AnnotationChange MessageNew MessageExpunge))",
                false
            ),
            Err(Rejection::BadEvent)
        );
    }

    fn folder(name: &str, messages: usize, uidnext: u64) -> FolderState {
        FolderState {
            name: name.to_string(),
            counts: Some(Counts {
                messages,
                uidnext,
                uidvalidity: 1,
                unseen: messages,
                highest_modseq: uidnext,
            }),
            metadata: None,
        }
    }

    fn snapshot(folders: &[(&str, FolderState)]) -> Snapshot {
        Snapshot {
            folders: folders
                .iter()
                .map(|(id, folder)| (id.to_string(), folder.clone()))
                .collect(),
            ..Snapshot::default()
        }
    }

    const FORMAT: Format = Format {
        utf8_accept: false,
        condstore: false,
    };

    #[test]
    fn diff_reports_status_and_mailbox_names() {
        let spec = spec("SET (personal (MessageNew MessageExpunge MailboxName))");
        let old = snapshot(&[
            ("1", folder("INBOX", 1, 2)),
            ("2", folder("Old", 0, 1)),
            ("3", folder("Gone", 0, 1)),
        ]);
        let new = snapshot(&[
            ("1", folder("INBOX", 2, 3)),
            ("2", folder("New", 0, 1)),
            ("4", folder("Fresh", 0, 1)),
        ]);
        assert_eq!(
            diff(&spec, &old, &new, None, FORMAT),
            vec![
                "LIST () \"/\" \"Fresh\"",
                "LIST (\\NonExistent) \"/\" \"Gone\"",
                "STATUS \"INBOX\" (MESSAGES 2 UIDNEXT 3 UIDVALIDITY 1 UNSEEN 2)",
                "LIST () \"/\" \"New\" (\"OLDNAME\" (\"Old\"))",
            ]
        );
        // The selected mailbox reports through EXISTS/EXPUNGE instead.
        assert_eq!(
            diff(&spec, &old, &new, Some("INBOX"), FORMAT)
                .iter()
                .filter(|line| line.starts_with("STATUS"))
                .count(),
            0
        );
    }

    #[test]
    fn diff_reports_subscriptions_and_metadata() {
        let spec =
            spec("SET (personal (SubscriptionChange MailboxMetadataChange ServerMetadataChange))");
        let mut old = snapshot(&[("1", folder("INBOX", 0, 1))]);
        old.folders.get_mut("1").unwrap().metadata = Some(vec![("/private/a".into(), "1".into())]);
        old.subscriptions.insert("Gone".into());
        old.server_metadata = Some(Vec::new());
        let mut new = old.clone();
        new.folders.get_mut("1").unwrap().metadata = Some(vec![("/private/b".into(), "2".into())]);
        new.subscriptions = BTreeSet::from(["INBOX".to_string()]);
        new.server_metadata = Some(vec![("/shared/comment".into(), "x".into())]);
        assert_eq!(
            diff(&spec, &old, &new, None, FORMAT),
            vec![
                "METADATA \"INBOX\" \"/private/b\" \"/private/a\"",
                "LIST () \"/\" \"Gone\"",
                "LIST (\\Subscribed) \"/\" \"INBOX\"",
                "METADATA \"\" \"/shared/comment\"",
            ]
        );
    }
}
