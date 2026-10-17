//! WBXML (WAP Binary XML) as ActiveSync uses it ([MS-ASWBXML]): a tree of
//! elements named by code page and token, with inline strings and opaque
//! data. Only the code pages rMail speaks are known; others decode as
//! `Unknown` and are ignored.

use anyhow::{Result, bail};

const SWITCH_PAGE: u8 = 0x00;
const END: u8 = 0x01;
const STR_I: u8 = 0x03;
const OPAQUE: u8 = 0xC3;
const HAS_CONTENT: u8 = 0x40;

/// Token tables: (code page, namespace, [(token, name)]).
/// A code page: number, namespace and its tokens.
type Page = (u8, &'static str, &'static [(u8, &'static str)]);

const PAGES: &[Page] = &[
    (
        0,
        "AirSync",
        &[
            (0x05, "Sync"),
            (0x06, "Responses"),
            (0x07, "Add"),
            (0x08, "Change"),
            (0x09, "Delete"),
            (0x0A, "Fetch"),
            (0x0B, "SyncKey"),
            (0x0C, "ClientId"),
            (0x0D, "ServerId"),
            (0x0E, "Status"),
            (0x0F, "Collection"),
            (0x10, "Class"),
            (0x12, "CollectionId"),
            (0x13, "GetChanges"),
            (0x14, "MoreAvailable"),
            (0x15, "WindowSize"),
            (0x16, "Commands"),
            (0x17, "Options"),
            (0x18, "FilterType"),
            (0x1B, "Conflict"),
            (0x1C, "Collections"),
            (0x1D, "ApplicationData"),
            (0x1E, "DeletesAsMoves"),
            (0x20, "Supported"),
            (0x21, "SoftDelete"),
            (0x22, "MIMESupport"),
            (0x23, "MIMETruncation"),
            (0x24, "Wait"),
            (0x25, "Limit"),
            (0x26, "Partial"),
            (0x27, "ConversationMode"),
            (0x28, "MaxItems"),
            (0x29, "HeartbeatInterval"),
        ],
    ),
    (
        1,
        "Contacts",
        &[
            (0x08, "Birthday"),
            (0x0C, "Business2PhoneNumber"),
            (0x0D, "BusinessCity"),
            (0x0E, "BusinessCountry"),
            (0x0F, "BusinessPostalCode"),
            (0x10, "BusinessState"),
            (0x11, "BusinessStreet"),
            (0x12, "BusinessFaxNumber"),
            (0x13, "BusinessPhoneNumber"),
            (0x14, "CarPhoneNumber"),
            (0x19, "CompanyName"),
            (0x1A, "Department"),
            (0x1B, "Email1Address"),
            (0x1C, "Email2Address"),
            (0x1D, "Email3Address"),
            (0x1E, "FileAs"),
            (0x1F, "FirstName"),
            (0x20, "Home2PhoneNumber"),
            (0x21, "HomeCity"),
            (0x22, "HomeCountry"),
            (0x23, "HomePostalCode"),
            (0x24, "HomeState"),
            (0x25, "HomeStreet"),
            (0x26, "HomeFaxNumber"),
            (0x27, "HomePhoneNumber"),
            (0x28, "JobTitle"),
            (0x29, "LastName"),
            (0x2A, "MiddleName"),
            (0x2B, "MobilePhoneNumber"),
            (0x2C, "OfficeLocation"),
            (0x2D, "OtherCity"),
            (0x2E, "OtherCountry"),
            (0x2F, "OtherPostalCode"),
            (0x30, "OtherState"),
            (0x31, "OtherStreet"),
            (0x32, "PagerNumber"),
            (0x35, "Suffix"),
            (0x36, "Title"),
            (0x37, "WebPage"),
            (0x3C, "Picture"),
        ],
    ),
    (
        2,
        "Email",
        &[
            (0x0F, "DateReceived"),
            (0x11, "DisplayTo"),
            (0x12, "Importance"),
            (0x13, "MessageClass"),
            (0x14, "Subject"),
            (0x15, "Read"),
            (0x16, "To"),
            (0x17, "Cc"),
            (0x18, "From"),
            (0x19, "ReplyTo"),
            (0x1A, "AllDayEvent"),
            (0x1D, "DtStamp"),
            (0x1E, "EndTime"),
            (0x1F, "InstanceType"),
            (0x20, "BusyStatus"),
            (0x21, "Location"),
            (0x22, "MeetingRequest"),
            (0x23, "Organizer"),
            (0x24, "RecurrenceId"),
            (0x25, "Reminder"),
            (0x26, "ResponseRequested"),
            (0x31, "StartTime"),
            (0x32, "Sensitivity"),
            (0x33, "TimeZone"),
            (0x34, "GlobalObjId"),
            (0x35, "ThreadTopic"),
            (0x39, "InternetCPID"),
            (0x3A, "Flag"),
            (0x3B, "FlagStatus"),
            (0x3C, "ContentClass"),
            (0x3D, "FlagType"),
            (0x3E, "CompleteTime"),
        ],
    ),
    (
        4,
        "Calendar",
        &[
            (0x05, "TimeZone"),
            (0x06, "AllDayEvent"),
            (0x07, "Attendees"),
            (0x08, "Attendee"),
            (0x09, "Email"),
            (0x0A, "Name"),
            (0x0D, "BusyStatus"),
            (0x0E, "Categories"),
            (0x0F, "Category"),
            (0x11, "DtStamp"),
            (0x12, "EndTime"),
            (0x13, "Exception"),
            (0x14, "Exceptions"),
            (0x15, "Deleted"),
            (0x16, "ExceptionStartTime"),
            (0x17, "Location"),
            (0x18, "MeetingStatus"),
            (0x19, "OrganizerEmail"),
            (0x1A, "OrganizerName"),
            (0x1B, "Recurrence"),
            (0x1C, "Type"),
            (0x1D, "Until"),
            (0x1E, "Occurrences"),
            (0x1F, "Interval"),
            (0x20, "DayOfWeek"),
            (0x21, "DayOfMonth"),
            (0x22, "WeekOfMonth"),
            (0x23, "MonthOfYear"),
            (0x24, "Reminder"),
            (0x25, "Sensitivity"),
            (0x26, "Subject"),
            (0x27, "StartTime"),
            (0x28, "UID"),
            (0x29, "AttendeeStatus"),
            (0x2A, "AttendeeType"),
            (0x33, "DisallowNewTimeProposal"),
            (0x34, "ResponseRequested"),
            (0x35, "AppointmentReplyTime"),
            (0x36, "ResponseType"),
        ],
    ),
    (
        8,
        "MeetingResponse",
        &[
            (0x05, "CalendarId"),
            (0x06, "CollectionId"),
            (0x07, "MeetingResponse"),
            (0x08, "RequestId"),
            (0x09, "Request"),
            (0x0A, "Result"),
            (0x0B, "Status"),
            (0x0C, "UserResponse"),
            (0x0E, "InstanceId"),
        ],
    ),
    (
        9,
        "Tasks",
        &[
            (0x08, "Categories"),
            (0x09, "Category"),
            (0x0A, "Complete"),
            (0x0B, "DateCompleted"),
            (0x0C, "DueDate"),
            (0x0D, "UtcDueDate"),
            (0x0E, "Importance"),
            (0x0F, "Recurrence"),
            (0x10, "Type"),
            (0x11, "Start"),
            (0x12, "Until"),
            (0x13, "Occurrences"),
            (0x14, "Interval"),
            (0x15, "DayOfMonth"),
            (0x16, "DayOfWeek"),
            (0x17, "WeekOfMonth"),
            (0x18, "MonthOfYear"),
            (0x19, "Regenerate"),
            (0x1A, "DeadOccur"),
            (0x1B, "ReminderSet"),
            (0x1C, "ReminderTime"),
            (0x1D, "Sensitivity"),
            (0x1E, "StartDate"),
            (0x1F, "UtcStartDate"),
            (0x20, "Subject"),
            (0x22, "OrdinalDate"),
            (0x23, "SubOrdinalDate"),
            (0x24, "CalendarType"),
            (0x25, "IsLeapMonth"),
            (0x26, "FirstDayOfWeek"),
        ],
    ),
    (
        5,
        "Move",
        &[
            (0x05, "MoveItems"),
            (0x06, "Move"),
            (0x07, "SrcMsgId"),
            (0x08, "SrcFldId"),
            (0x09, "DstFldId"),
            (0x0A, "Response"),
            (0x0B, "Status"),
            (0x0C, "DstMsgId"),
        ],
    ),
    (
        6,
        "GetItemEstimate",
        &[
            (0x05, "GetItemEstimate"),
            (0x07, "Collections"),
            (0x08, "Collection"),
            (0x0A, "CollectionId"),
            (0x0C, "Estimate"),
            (0x0D, "Response"),
            (0x0E, "Status"),
        ],
    ),
    (
        7,
        "FolderHierarchy",
        &[
            (0x07, "DisplayName"),
            (0x08, "ServerId"),
            (0x09, "ParentId"),
            (0x0A, "Type"),
            (0x0C, "Status"),
            (0x0E, "Changes"),
            (0x0F, "Add"),
            (0x10, "Delete"),
            (0x11, "Update"),
            (0x12, "SyncKey"),
            (0x13, "FolderCreate"),
            (0x14, "FolderDelete"),
            (0x15, "FolderUpdate"),
            (0x16, "FolderSync"),
            (0x17, "Count"),
        ],
    ),
    (
        13,
        "Ping",
        &[
            (0x05, "Ping"),
            (0x07, "Status"),
            (0x08, "HeartbeatInterval"),
            (0x09, "Folders"),
            (0x0A, "Folder"),
            (0x0B, "Id"),
            (0x0C, "Class"),
            (0x0D, "MaxFolders"),
        ],
    ),
    (
        14,
        "Provision",
        &[
            (0x05, "Provision"),
            (0x06, "Policies"),
            (0x07, "Policy"),
            (0x08, "PolicyType"),
            (0x09, "PolicyKey"),
            (0x0A, "Data"),
            (0x0B, "Status"),
            (0x0C, "RemoteWipe"),
            (0x0D, "EASProvisionDoc"),
            (0x0E, "DevicePasswordEnabled"),
            (0x13, "AttachmentsEnabled"),
            (0x18, "AllowSimpleDevicePassword"),
            (0x29, "AllowHTMLEmail"),
        ],
    ),
    (
        17,
        "AirSyncBase",
        &[
            (0x05, "BodyPreference"),
            (0x06, "Type"),
            (0x07, "TruncationSize"),
            (0x08, "AllOrNone"),
            (0x0A, "Body"),
            (0x0B, "Data"),
            (0x0C, "EstimatedDataSize"),
            (0x0D, "Truncated"),
            (0x0E, "Attachments"),
            (0x0F, "Attachment"),
            (0x10, "DisplayName"),
            (0x11, "FileReference"),
            (0x12, "Method"),
            (0x13, "ContentId"),
            (0x15, "IsInline"),
            (0x16, "NativeBodyType"),
            (0x17, "ContentType"),
            (0x18, "Preview"),
        ],
    ),
    (
        18,
        "Settings",
        &[
            (0x05, "Settings"),
            (0x06, "Status"),
            (0x07, "Get"),
            (0x08, "Set"),
            (0x09, "Oof"),
            (0x16, "DeviceInformation"),
            (0x17, "Model"),
            (0x19, "FriendlyName"),
            (0x1A, "OS"),
            (0x1D, "UserInformation"),
            (0x1E, "EmailAddresses"),
            (0x1F, "SmtpAddress"),
            (0x20, "UserAgent"),
            (0x23, "PrimarySmtpAddress"),
            (0x24, "Accounts"),
            (0x25, "Account"),
            (0x28, "UserDisplayName"),
        ],
    ),
    (
        20,
        "ItemOperations",
        &[
            (0x05, "ItemOperations"),
            (0x06, "Fetch"),
            (0x07, "Store"),
            (0x08, "Options"),
            (0x09, "Range"),
            (0x0A, "Total"),
            (0x0B, "Properties"),
            (0x0C, "Data"),
            (0x0D, "Status"),
            (0x0E, "Response"),
            (0x10, "Schema"),
            (0x12, "EmptyFolderContents"),
            (0x13, "DeleteSubFolders"),
            (0x16, "Move"),
        ],
    ),
    (
        21,
        "ComposeMail",
        &[
            (0x05, "SendMail"),
            (0x06, "SmartForward"),
            (0x07, "SmartReply"),
            (0x08, "SaveInSentItems"),
            (0x09, "ReplaceMime"),
            (0x0B, "Source"),
            (0x0C, "FolderId"),
            (0x0D, "ItemId"),
            (0x0E, "LongId"),
            (0x0F, "InstanceId"),
            (0x10, "MIME"),
            (0x11, "ClientId"),
            (0x12, "Status"),
        ],
    ),
];

/// An element: `Namespace:Name`, with children, text or opaque data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    pub ns: &'static str,
    pub name: &'static str,
    pub children: Vec<Element>,
    pub text: Option<String>,
    pub opaque: Option<Vec<u8>>,
}

impl Element {
    pub fn new(tag: &str) -> Self {
        let (ns, name) = lookup_name(tag).unwrap_or_else(|| panic!("unknown ActiveSync tag {tag}"));
        Element {
            ns,
            name,
            children: Vec::new(),
            text: None,
            opaque: None,
        }
    }

    /// `<tag>text</tag>`.
    pub fn text(tag: &str, value: impl Into<String>) -> Self {
        let mut element = Self::new(tag);
        element.text = Some(value.into());
        element
    }

    #[cfg(test)]
    pub fn opaque(tag: &str, value: Vec<u8>) -> Self {
        let mut element = Self::new(tag);
        element.opaque = Some(value);
        element
    }

    pub fn with(mut self, child: Element) -> Self {
        self.children.push(child);
        self
    }

    pub fn push(&mut self, child: Element) {
        self.children.push(child);
    }

    pub fn is(&self, tag: &str) -> bool {
        tag.split_once(':')
            .is_some_and(|(ns, name)| self.ns == ns && self.name == name)
    }

    /// The first child named `tag` (`Namespace:Name`).
    pub fn child(&self, tag: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.is(tag))
    }

    pub fn children_named<'a>(&'a self, tag: &'a str) -> impl Iterator<Item = &'a Element> {
        self.children.iter().filter(move |c| c.is(tag))
    }

    /// The text of the first child named `tag` (or its opaque data as text).
    pub fn value(&self, tag: &str) -> Option<String> {
        let child = self.child(tag)?;
        child
            .text
            .clone()
            .or_else(|| {
                child
                    .opaque
                    .as_ref()
                    .map(|d| String::from_utf8_lossy(d).into_owned())
            })
            .or_else(|| Some(String::new()))
    }
}

fn lookup_name(tag: &str) -> Option<(&'static str, &'static str)> {
    let (ns, name) = tag.split_once(':')?;
    PAGES
        .iter()
        .find(|(_, n, _)| *n == ns)
        .and_then(|(_, n, tokens)| {
            tokens
                .iter()
                .find(|(_, t)| *t == name)
                .map(|(_, t)| (*n, *t))
        })
}

fn token_of(element: &Element) -> (u8, u8) {
    let (page, _, tokens) = PAGES
        .iter()
        .find(|(_, n, _)| *n == element.ns)
        .expect("known page");
    let (token, _) = tokens
        .iter()
        .find(|(_, t)| *t == element.name)
        .expect("known token");
    (*page, *token)
}

fn mb_u32(out: &mut Vec<u8>, mut value: u32) {
    let mut bytes = vec![(value & 0x7F) as u8];
    value >>= 7;
    while value > 0 {
        bytes.push(((value & 0x7F) as u8) | 0x80);
        value >>= 7;
    }
    bytes.reverse();
    out.extend(bytes);
}

/// The WBXML document for `root`.
pub fn encode(root: &Element) -> Vec<u8> {
    // Version 1.3, unknown public id, UTF-8, empty string table.
    let mut out = vec![0x03, 0x01, 0x6A, 0x00];
    let mut page = 0u8;
    encode_element(root, &mut out, &mut page);
    out
}

fn encode_element(element: &Element, out: &mut Vec<u8>, page: &mut u8) {
    let (wanted, token) = token_of(element);
    if wanted != *page {
        out.extend([SWITCH_PAGE, wanted]);
        *page = wanted;
    }
    let has_content =
        !element.children.is_empty() || element.text.is_some() || element.opaque.is_some();
    if !has_content {
        out.push(token);
        return;
    }
    out.push(token | HAS_CONTENT);
    if let Some(text) = &element.text {
        out.push(STR_I);
        out.extend(text.replace('\0', "").as_bytes());
        out.push(0);
    }
    if let Some(data) = &element.opaque {
        out.push(OPAQUE);
        mb_u32(out, data.len() as u32);
        out.extend(data);
    }
    for child in &element.children {
        encode_element(child, out, page);
    }
    out.push(END);
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
    page: u8,
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8> {
        let byte = *self
            .data
            .get(self.at)
            .ok_or_else(|| anyhow::anyhow!("WBXML ends early"))?;
        self.at += 1;
        Ok(byte)
    }

    fn mb_u32(&mut self) -> Result<u32> {
        let mut value: u32 = 0;
        for _ in 0..5 {
            let byte = self.byte()?;
            value = (value << 7) | u32::from(byte & 0x7F);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        bail!("WBXML number too long")
    }

    fn element(&mut self, depth: usize) -> Result<Option<Element>> {
        if depth > 64 {
            bail!("WBXML nests too deep");
        }
        let mut tag = self.byte()?;
        while tag == SWITCH_PAGE {
            self.page = self.byte()?;
            tag = self.byte()?;
        }
        if tag == END {
            return Ok(None);
        }
        let token = tag & 0x3F;
        let (ns, name) = PAGES
            .iter()
            .find(|(p, _, _)| *p == self.page)
            .and_then(|(_, ns, tokens)| {
                tokens
                    .iter()
                    .find(|(t, _)| *t == token)
                    .map(|(_, name)| (*ns, *name))
            })
            .unwrap_or(("Unknown", "Unknown"));
        let mut element = Element {
            ns,
            name,
            children: Vec::new(),
            text: None,
            opaque: None,
        };
        if tag & 0x80 != 0 {
            bail!("WBXML attributes are not used by ActiveSync");
        }
        if tag & HAS_CONTENT == 0 {
            return Ok(Some(element));
        }
        loop {
            let next = *self
                .data
                .get(self.at)
                .ok_or_else(|| anyhow::anyhow!("WBXML ends early"))?;
            match next {
                END => {
                    self.at += 1;
                    return Ok(Some(element));
                }
                STR_I => {
                    self.at += 1;
                    let end = self.data[self.at..]
                        .iter()
                        .position(|b| *b == 0)
                        .ok_or_else(|| anyhow::anyhow!("unterminated WBXML string"))?;
                    let text =
                        String::from_utf8_lossy(&self.data[self.at..self.at + end]).into_owned();
                    self.at += end + 1;
                    element.text = Some(element.text.take().unwrap_or_default() + &text);
                }
                OPAQUE => {
                    self.at += 1;
                    let length = self.mb_u32()? as usize;
                    let data = self
                        .data
                        .get(self.at..self.at + length)
                        .ok_or_else(|| anyhow::anyhow!("WBXML opaque data ends early"))?;
                    element.opaque = Some(data.to_vec());
                    self.at += length;
                }
                _ => {
                    if let Some(child) = self.element(depth + 1)? {
                        element.children.push(child);
                    }
                }
            }
        }
    }
}

/// The root element of a WBXML document.
pub fn decode(data: &[u8]) -> Result<Element> {
    let mut reader = Reader {
        data,
        at: 0,
        page: 0,
    };
    let _version = reader.byte()?;
    let _public_id = reader.mb_u32()?;
    let _charset = reader.mb_u32()?;
    let table = reader.mb_u32()? as usize;
    reader.at += table;
    reader
        .element(0)?
        .ok_or_else(|| anyhow::anyhow!("empty WBXML document"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documents_round_trip() {
        let document = Element::new("FolderHierarchy:FolderSync")
            .with(Element::text("FolderHierarchy:SyncKey", "0"))
            .with(
                Element::new("AirSync:Sync")
                    .with(Element::opaque("ComposeMail:MIME", vec![0, 1, 2, 255])),
            );
        let bytes = encode(&document);
        assert_eq!(&bytes[..4], &[0x03, 0x01, 0x6A, 0x00]);
        assert_eq!(decode(&bytes).unwrap(), document);
    }

    #[test]
    fn a_folder_sync_request_from_a_phone_decodes() {
        // <FolderSync xmlns="FolderHierarchy:"><SyncKey>0</SyncKey></FolderSync>
        let bytes = [
            0x03, 0x01, 0x6A, 0x00, 0x00, 0x07, 0x56, 0x52, 0x03, b'0', 0x00, 0x01, 0x01,
        ];
        let root = decode(&bytes).unwrap();
        assert!(root.is("FolderHierarchy:FolderSync"));
        assert_eq!(root.value("FolderHierarchy:SyncKey").as_deref(), Some("0"));
    }
}
