//! HTML that webmail users write: cleaned to a small allowlist before it is
//! sent, stored as a draft or signature, or put into the editor as a quote,
//! and turned into the plain-text alternative of outgoing mail.
//!
//! The reader's [`crate::mime::sanitize_email_html`] only removes what is
//! dangerous and relies on a sandboxed frame and a content policy. Composed
//! HTML is shown in the app's own document (the editor) and sent to other
//! people, so it is rebuilt from scratch instead: only listed elements,
//! attributes and style properties survive, URLs must use a listed scheme,
//! every value is re-escaped and the element tree is balanced, so a quote or
//! signature can never close the markup around it.

use base64::Engine;

/// Nesting deeper than this keeps the text but drops the extra elements.
pub const MAX_DEPTH: usize = 64;
/// Most inline (pasted or dropped) images in one message.
pub const MAX_INLINE_IMAGES: usize = 64;

/// What happens to `data:image/...` sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataImages {
    /// Kept as data URLs (drafts in the editor, signatures).
    Keep,
    /// Moved into [`Cleaned::images`] and referenced as `cid:` (sending).
    Extract,
    /// Removed.
    Drop,
}

#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Keep `http(s)` image sources. Quotes leave them out unless the user
    /// chose to load remote content, so replying cannot trigger a tracker.
    pub remote_images: bool,
    pub data_images: DataImages,
}

/// An image that was inline in the HTML, for a `multipart/related` part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineImage {
    /// Without angle brackets; the HTML refers to it as `cid:<content_id>`.
    pub content_id: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct Cleaned {
    /// A body fragment (no `<html>`/`<body>`).
    pub html: String,
    pub images: Vec<InlineImage>,
}

const ALLOWED: &[&str] = &[
    "a",
    "abbr",
    "b",
    "bdi",
    "bdo",
    "big",
    "blockquote",
    "br",
    "caption",
    "center",
    "cite",
    "code",
    "col",
    "colgroup",
    "dd",
    "del",
    "dfn",
    "div",
    "dl",
    "dt",
    "em",
    "figcaption",
    "figure",
    "font",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "i",
    "img",
    "ins",
    "kbd",
    "li",
    "mark",
    "ol",
    "p",
    "pre",
    "q",
    "s",
    "samp",
    "small",
    "span",
    "strike",
    "strong",
    "sub",
    "sup",
    "table",
    "tbody",
    "td",
    "tfoot",
    "th",
    "thead",
    "tr",
    "tt",
    "u",
    "ul",
    "var",
    "wbr",
];

const VOID: &[&str] = &["br", "col", "hr", "img", "wbr"];

/// Elements removed together with everything inside them.
const DROP_CONTENT: &[&str] = &[
    "applet", "audio", "button", "canvas", "datalist", "dialog", "embed", "frame", "frameset",
    "head", "iframe", "map", "math", "meter", "noembed", "noframes", "noscript", "object",
    "picture", "progress", "script", "select", "style", "svg", "template", "textarea", "title",
    "video", "xmp",
];

/// Elements whose content the HTML parser reads as raw text: everything up
/// to the matching end tag is skipped without looking for markup.
const RAW_TEXT: &[&str] = &[
    "iframe",
    "noembed",
    "noframes",
    "noscript",
    "plaintext",
    "script",
    "style",
    "textarea",
    "title",
    "xmp",
];

/// Starting one of these closes an open paragraph.
const BLOCK: &[&str] = &[
    "blockquote",
    "center",
    "div",
    "dl",
    "figure",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "ol",
    "p",
    "pre",
    "table",
    "ul",
];

const STYLE_PROPERTIES: &[&str] = &[
    "background-color",
    "border",
    "border-bottom",
    "border-collapse",
    "border-color",
    "border-left",
    "border-radius",
    "border-right",
    "border-spacing",
    "border-style",
    "border-top",
    "border-width",
    "color",
    "direction",
    "font",
    "font-family",
    "font-size",
    "font-style",
    "font-variant",
    "font-weight",
    "height",
    "letter-spacing",
    "line-height",
    "list-style-type",
    "margin",
    "margin-bottom",
    "margin-left",
    "margin-right",
    "margin-top",
    "max-width",
    "min-width",
    "padding",
    "padding-bottom",
    "padding-left",
    "padding-right",
    "padding-top",
    "text-align",
    "text-decoration",
    "text-indent",
    "text-transform",
    "vertical-align",
    "white-space",
    "width",
    "word-break",
];

enum Token<'a> {
    Text(&'a str),
    Start {
        name: String,
        attributes: Vec<(String, &'a str)>,
    },
    End(String),
}

/// Split HTML into text, start tags (with raw attribute values) and end
/// tags. Comments, doctypes and processing instructions are dropped, and
/// the content of raw-text elements is skipped.
fn tokenize(input: &str) -> Vec<Token<'_>> {
    let bytes = input.as_bytes();
    // ASCII lowercasing keeps byte offsets, so one copy serves every search
    // for a raw-text end tag (copying the rest per tag would be quadratic).
    let lower_input = input.to_ascii_lowercase();
    let mut tokens = Vec::new();
    let mut i = 0;
    let mut text_start = 0;
    let find = |from: usize, needle: &str| input[from..].find(needle).map(|at| from + at);
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let next = bytes.get(i + 1).copied().unwrap_or(0);
        let tag_end;
        let mut token = None;
        if input[i..].starts_with("<!--") {
            tag_end = find(i + 4, "-->").map_or(bytes.len(), |at| at + 3);
        } else if next == b'!'
            || next == b'?'
            || (next == b'/' && !bytes.get(i + 2).is_some_and(u8::is_ascii_alphabetic))
        {
            tag_end = find(i + 1, ">").map_or(bytes.len(), |at| at + 1);
        } else if next == b'/' {
            let name_start = i + 2;
            let mut j = name_start;
            while j < bytes.len()
                && !bytes[j].is_ascii_whitespace()
                && bytes[j] != b'>'
                && bytes[j] != b'/'
            {
                j += 1;
            }
            token = Some(Token::End(input[name_start..j].to_ascii_lowercase()));
            tag_end = find(j, ">").map_or(bytes.len(), |at| at + 1);
        } else if next.is_ascii_alphabetic() {
            let (start, end) = start_tag(input, i);
            tag_end = end;
            // A tag cut off by the end of the input is not a tag.
            token = input[..end].ends_with('>').then_some(start);
        } else {
            // A lone `<` is text.
            i += 1;
            continue;
        }
        if text_start < i {
            tokens.push(Token::Text(&input[text_start..i]));
        }
        i = tag_end;
        text_start = i;
        if let Some(token) = token {
            if let Token::Start { name, .. } = &token
                && RAW_TEXT.contains(&name.as_str())
            {
                // Skip to `</name`; the end tag itself is read normally.
                let rest = &lower_input[i..];
                let skip = rest.find(&format!("</{name}")).unwrap_or(rest.len());
                i += skip;
                text_start = i;
            }
            tokens.push(token);
        }
    }
    if text_start < bytes.len() {
        tokens.push(Token::Text(&input[text_start..]));
    }
    tokens
}

/// Read the start tag at `at` (a `<` followed by a letter); returns it and
/// where it ends. A tag cut off by the end of the input ends there.
fn start_tag(input: &str, at: usize) -> (Token<'_>, usize) {
    let bytes = input.as_bytes();
    let mut i = at + 1;
    while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' && bytes[i] != b'/'
    {
        i += 1;
    }
    let name = input[at + 1..i].to_ascii_lowercase();
    let mut attributes = Vec::new();
    loop {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        if bytes[i] == b'>' {
            i += 1;
            break;
        }
        let name_start = i;
        // The first character may be `=` (it is then part of the name).
        i += 1;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && !matches!(bytes[i], b'=' | b'>' | b'/')
        {
            i += 1;
        }
        let attribute = input[name_start..i].to_ascii_lowercase();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = "";
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let quote = bytes[i];
                let value_start = i + 1;
                let value_end = input[value_start..]
                    .find(quote as char)
                    .map_or(bytes.len(), |at| value_start + at);
                value = &input[value_start..value_end];
                i = (value_end + 1).min(bytes.len());
            } else {
                let value_start = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
                    i += 1;
                }
                value = &input[value_start..i];
            }
        }
        if !attributes.iter().any(|(known, _)| known == &attribute) {
            attributes.push((attribute, value));
        }
    }
    (Token::Start { name, attributes }, i)
}

/// Named character references: the common ones and all of Latin-1.
fn named_entity(name: &str) -> Option<char> {
    const LATIN1: [&str; 96] = [
        "nbsp", "iexcl", "cent", "pound", "curren", "yen", "brvbar", "sect", "uml", "copy", "ordf",
        "laquo", "not", "shy", "reg", "macr", "deg", "plusmn", "sup2", "sup3", "acute", "micro",
        "para", "middot", "cedil", "sup1", "ordm", "raquo", "frac14", "frac12", "frac34", "iquest",
        "Agrave", "Aacute", "Acirc", "Atilde", "Auml", "Aring", "AElig", "Ccedil", "Egrave",
        "Eacute", "Ecirc", "Euml", "Igrave", "Iacute", "Icirc", "Iuml", "ETH", "Ntilde", "Ograve",
        "Oacute", "Ocirc", "Otilde", "Ouml", "times", "Oslash", "Ugrave", "Uacute", "Ucirc",
        "Uuml", "Yacute", "THORN", "szlig", "agrave", "aacute", "acirc", "atilde", "auml", "aring",
        "aelig", "ccedil", "egrave", "eacute", "ecirc", "euml", "igrave", "iacute", "icirc",
        "iuml", "eth", "ntilde", "ograve", "oacute", "ocirc", "otilde", "ouml", "divide", "oslash",
        "ugrave", "uacute", "ucirc", "uuml", "yacute", "thorn", "yuml",
    ];
    if let Some(at) = LATIN1.iter().position(|known| *known == name) {
        return char::from_u32(160 + at as u32);
    }
    Some(match name {
        "amp" | "AMP" => '&',
        "lt" | "LT" => '<',
        "gt" | "GT" => '>',
        "quot" | "QUOT" => '"',
        "apos" => '\'',
        "Tab" => '\t',
        "NewLine" => '\n',
        "colon" => ':',
        "lpar" => '(',
        "rpar" => ')',
        "sol" => '/',
        "bsol" => '\\',
        "ensp" => '\u{2002}',
        "emsp" => '\u{2003}',
        "thinsp" => '\u{2009}',
        "zwnj" => '\u{200c}',
        "zwj" => '\u{200d}',
        "lrm" => '\u{200e}',
        "rlm" => '\u{200f}',
        "ndash" => '–',
        "mdash" => '—',
        "lsquo" => '‘',
        "rsquo" => '’',
        "sbquo" => '‚',
        "ldquo" => '“',
        "rdquo" => '”',
        "bdquo" => '„',
        "bull" => '•',
        "hellip" => '…',
        "prime" => '′',
        "lsaquo" => '‹',
        "rsaquo" => '›',
        "euro" => '€',
        "trade" => '™',
        "larr" => '←',
        "rarr" => '→',
        "uarr" => '↑',
        "darr" => '↓',
        "dagger" => '†',
        "Dagger" => '‡',
        "permil" => '‰',
        "OElig" => 'Œ',
        "oelig" => 'œ',
        "Scaron" => 'Š',
        "scaron" => 'š',
        "Yuml" => 'Ÿ',
        "fnof" => 'ƒ',
        "circ" => 'ˆ',
        "tilde" => '˜',
        _ => return None,
    })
}

/// The character reference at the start of `rest` (which begins with `&`):
/// the character, or `None` for an unknown name, and its length. `None`
/// overall when `rest` does not start with a complete reference.
fn entity_at(rest: &str) -> Option<(Option<char>, usize)> {
    let end = rest[1..].find(';').map(|at| at + 1)?;
    if end > 33 {
        return None;
    }
    let body = &rest[1..end];
    let decoded = if let Some(number) = body.strip_prefix('#') {
        let value = match number.strip_prefix(['x', 'X']) {
            Some(hex) if !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) => {
                u32::from_str_radix(hex, 16).ok()
            }
            None if !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()) => {
                number.parse::<u32>().ok()
            }
            _ => return None,
        };
        Some(
            value
                .filter(|&v| v != 0)
                .and_then(char::from_u32)
                .unwrap_or('\u{fffd}'),
        )
    } else if !body.is_empty()
        && body.as_bytes()[0].is_ascii_alphabetic()
        && body.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        named_entity(body)
    } else {
        return None;
    };
    Some((decoded, end + 1))
}

/// Decode character references; unknown names stay as written.
pub fn decode_entities(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        match entity_at(rest) {
            Some((Some(c), length)) => {
                out.push(c);
                rest = &rest[length..];
            }
            _ => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn push_escaped(out: &mut String, c: char) {
    match c {
        '&' => out.push_str("&amp;"),
        '<' => out.push_str("&lt;"),
        '>' => out.push_str("&gt;"),
        '"' => out.push_str("&quot;"),
        '\0' => {}
        c if c.is_control() && !matches!(c, '\t' | '\n' | '\r') => {}
        c => out.push(c),
    }
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        push_escaped(&mut out, c);
    }
    out
}

/// Text content, re-escaped. Known references are decoded (and escaped
/// again where needed); unknown well-formed names are kept for the
/// recipient's browser; any other `&` becomes `&amp;`.
fn clean_text(out: &mut String, text: &str) {
    let mut rest = text;
    while let Some(at) = rest.find(['&', '<', '>', '"', '\0']) {
        for c in rest[..at].chars() {
            push_escaped(out, c);
        }
        rest = &rest[at..];
        if rest.starts_with('&') {
            match entity_at(rest) {
                Some((Some(c), length)) => {
                    push_escaped(out, c);
                    rest = &rest[length..];
                }
                Some((None, length)) => {
                    out.push_str(&rest[..length]);
                    rest = &rest[length..];
                }
                None => {
                    out.push_str("&amp;");
                    rest = &rest[1..];
                }
            }
        } else {
            let c = rest.chars().next().unwrap_or_default();
            push_escaped(out, c);
            rest = &rest[c.len_utf8()..];
        }
    }
    for c in rest.chars() {
        push_escaped(out, c);
    }
}

/// A link target: `http(s)`, `mailto` or `tel`, after decoding and with the
/// whitespace and control characters browsers ignore in URLs removed.
fn clean_link(decoded: &str) -> Option<String> {
    let compact: String = decoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && !c.is_control())
        .collect();
    let lower = compact.to_ascii_lowercase();
    ["http://", "https://", "mailto:", "tel:"]
        .iter()
        .any(|scheme| lower.starts_with(scheme) && lower.len() > scheme.len())
        .then_some(compact)
        .filter(|url| url.len() <= 4096)
}

fn clean_style(decoded: &str) -> Option<String> {
    let mut kept = Vec::new();
    for declaration in decoded.split(';') {
        let Some((property, value)) = declaration.split_once(':') else {
            continue;
        };
        let property = property.trim().to_ascii_lowercase();
        let value = value.trim();
        let lower = value.to_ascii_lowercase();
        let unsafe_value = value.is_empty()
            || value.len() > 200
            || [
                "url(",
                "expression",
                "script:",
                "@",
                "\\",
                "<",
                ">",
                "/*",
                "image-set",
                "var(",
            ]
            .iter()
            .any(|needle| lower.contains(needle))
            || value.chars().any(char::is_control);
        if STYLE_PROPERTIES.contains(&property.as_str()) && !unsafe_value {
            kept.push(format!("{property}: {value}"));
        }
    }
    (!kept.is_empty()).then(|| kept.join("; "))
}

fn is_length(value: &str) -> bool {
    let digits = value.strip_suffix('%').unwrap_or(value);
    let digits = digits.strip_suffix("px").unwrap_or(digits);
    !digits.is_empty() && digits.len() <= 6 && digits.bytes().all(|b| b.is_ascii_digit())
}

fn is_number(value: &str) -> bool {
    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
    !digits.is_empty() && digits.len() <= 4 && digits.bytes().all(|b| b.is_ascii_digit())
}

fn is_word(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'#' || b == b'-')
}

/// A decoded `data:image/...;base64,` URL: its type and bytes.
fn data_image(url: &str) -> Option<(String, Vec<u8>)> {
    let rest = url.trim().strip_prefix("data:")?;
    let (header, data) = rest.split_once(',')?;
    let mut parts = header.split(';');
    let content_type = parts.next()?.trim().to_ascii_lowercase();
    if !["image/png", "image/jpeg", "image/gif", "image/webp"].contains(&content_type.as_str())
        || !parts.any(|part| part.trim().eq_ignore_ascii_case("base64"))
    {
        return None;
    }
    let compact: String = data.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .ok()?;
    Some((content_type, bytes))
}

struct Cleaner {
    options: Options,
    out: String,
    stack: Vec<String>,
    images: Vec<InlineImage>,
    /// Inside an element removed with its content: its name and nesting.
    skipping: Option<(String, usize)>,
    image_tag: String,
}

impl Cleaner {
    /// The attributes kept on `name`, as ` key="value"` text; `None` when the
    /// element itself has to go (an image without a usable source).
    fn attributes(&mut self, name: &str, attributes: &[(String, &str)]) -> Option<String> {
        let mut out = String::new();
        let mut has_src = false;
        for (attribute, raw) in attributes {
            let decoded = decode_entities(raw);
            let value = decoded.trim();
            let kept: Option<String> = match (name, attribute.as_str()) {
                (_, "style") => clean_style(value),
                (_, "dir")
                    if ["ltr", "rtl", "auto"].contains(&value.to_ascii_lowercase().as_str()) =>
                {
                    Some(value.to_ascii_lowercase())
                }
                (_, "lang") if is_word(value, 35) => Some(value.to_string()),
                (_, "title") => Some(value.chars().take(500).collect()),
                (_, "align")
                    if ["left", "right", "center", "justify"]
                        .contains(&value.to_ascii_lowercase().as_str()) =>
                {
                    Some(value.to_ascii_lowercase())
                }
                ("a", "href") => clean_link(value),
                ("img", "src") => {
                    let src = self.image_source(value);
                    has_src = src.is_some();
                    src
                }
                ("img", "alt") => Some(value.chars().take(500).collect()),
                ("img" | "table" | "td" | "th" | "col" | "hr", "width") if is_length(value) => {
                    Some(value.to_string())
                }
                ("img" | "td" | "th", "height") if is_length(value) => Some(value.to_string()),
                ("td" | "th", "colspan" | "rowspan") | ("col" | "colgroup", "span")
                    if is_number(value) =>
                {
                    Some(value.to_string())
                }
                ("table", "border" | "cellpadding" | "cellspacing") if is_number(value) => {
                    Some(value.to_string())
                }
                ("td" | "th" | "tr", "valign")
                    if ["top", "middle", "bottom", "baseline"]
                        .contains(&value.to_ascii_lowercase().as_str()) =>
                {
                    Some(value.to_ascii_lowercase())
                }
                ("table" | "td" | "th" | "tr", "bgcolor") | ("font", "color")
                    if is_word(value, 30) =>
                {
                    Some(value.to_string())
                }
                ("font", "size") if is_number(value) => Some(value.to_string()),
                ("font", "face")
                    if value.len() <= 200
                        && value.chars().all(|c| {
                            c.is_alphanumeric() || matches!(c, ' ' | ',' | '-' | '\'' | '_')
                        }) =>
                {
                    Some(value.to_string())
                }
                ("ol", "start") if is_number(value) => Some(value.to_string()),
                ("ol", "type") if ["1", "a", "A", "i", "I"].contains(&value) => {
                    Some(value.to_string())
                }
                ("blockquote", "type") if value.eq_ignore_ascii_case("cite") => {
                    Some("cite".to_string())
                }
                _ => None,
            };
            if let Some(kept) = kept {
                out.push_str(&format!(" {attribute}=\"{}\"", escape(&kept)));
            }
        }
        if name == "img" && !has_src {
            return None;
        }
        Some(out)
    }

    fn image_source(&mut self, value: &str) -> Option<String> {
        if value.len() >= 5 && value[..5].eq_ignore_ascii_case("data:") {
            let (content_type, data) = data_image(value)?;
            return match self.options.data_images {
                DataImages::Drop => None,
                DataImages::Keep => Some(format!(
                    "data:{content_type};base64,{}",
                    base64::engine::general_purpose::STANDARD.encode(&data)
                )),
                DataImages::Extract => {
                    if self.images.len() >= MAX_INLINE_IMAGES {
                        return None;
                    }
                    let content_id = format!(
                        "image{}.{}@{}",
                        self.images.len() + 1,
                        self.image_tag,
                        "rmail.invalid"
                    );
                    self.images.push(InlineImage {
                        content_id: content_id.clone(),
                        content_type,
                        data,
                    });
                    Some(format!("cid:{content_id}"))
                }
            };
        }
        let lower = value.to_ascii_lowercase();
        (self.options.remote_images
            && (lower.starts_with("https://") || lower.starts_with("http://")))
        .then(|| clean_link(value))
        .flatten()
    }

    /// Close the outermost open element of `targets` above the innermost
    /// open one of `boundaries` (a new row closes the open row and cell).
    fn close_within(&mut self, targets: &[&str], boundaries: &[&str]) {
        let scope = self
            .stack
            .iter()
            .rposition(|open| boundaries.contains(&open.as_str()))
            .map_or(0, |at| at + 1);
        if let Some(offset) = self.stack[scope..]
            .iter()
            .position(|open| targets.contains(&open.as_str()))
        {
            self.close_to(scope + offset);
        }
    }

    fn close_to(&mut self, position: usize) {
        while self.stack.len() > position {
            let name = self.stack.pop().unwrap_or_default();
            self.out.push_str(&format!("</{name}>"));
        }
    }

    fn start(&mut self, name: &str, attributes: &[(String, &str)]) {
        if let Some((skipped, depth)) = &mut self.skipping {
            if skipped == name && !VOID.contains(&name) {
                *depth += 1;
            }
            return;
        }
        if DROP_CONTENT.contains(&name) {
            if !RAW_TEXT.contains(&name) && name != "embed" {
                self.skipping = Some((name.to_string(), 1));
            }
            return;
        }
        if !ALLOWED.contains(&name) {
            return;
        }
        match name {
            "li" => self.close_within(&["li"], &["ul", "ol"]),
            "dt" | "dd" => self.close_within(&["dt", "dd"], &["dl"]),
            "tr" => self.close_within(&["tr", "td", "th"], &["table", "tbody", "thead", "tfoot"]),
            "td" | "th" => self.close_within(&["td", "th"], &["tr", "table"]),
            "tbody" | "thead" | "tfoot" => {
                self.close_within(&["tbody", "thead", "tfoot", "tr", "td", "th"], &["table"])
            }
            _ => {}
        }
        if BLOCK.contains(&name) && self.stack.last().is_some_and(|top| top == "p") {
            self.close_to(self.stack.len() - 1);
        }
        let void = VOID.contains(&name);
        if !void && self.stack.len() >= MAX_DEPTH {
            return;
        }
        let Some(kept) = self.attributes(name, attributes) else {
            return;
        };
        self.out.push_str(&format!("<{name}{kept}>"));
        if !void {
            self.stack.push(name.to_string());
        }
    }

    fn end(&mut self, name: &str) {
        if let Some((skipped, depth)) = &mut self.skipping {
            if skipped == name {
                *depth -= 1;
                if *depth == 0 {
                    self.skipping = None;
                }
            }
            return;
        }
        if let Some(position) = self.stack.iter().rposition(|open| open == name) {
            self.close_to(position);
        }
    }
}

/// Clean user-written HTML (see the module documentation).
pub fn clean(input: &str, options: Options) -> Cleaned {
    let mut cleaner = Cleaner {
        options,
        out: String::with_capacity(input.len().min(1 << 20)),
        stack: Vec::new(),
        images: Vec::new(),
        skipping: None,
        image_tag: (0..6)
            .map(|_| format!("{:02x}", rand::random::<u8>()))
            .collect(),
    };
    for token in tokenize(input) {
        match token {
            Token::Text(text) if cleaner.skipping.is_none() => clean_text(&mut cleaner.out, text),
            Token::Text(_) => {}
            Token::Start { name, attributes } => cleaner.start(&name, &attributes),
            Token::End(name) => cleaner.end(&name),
        }
    }
    cleaner.close_to(0);
    Cleaned {
        html: cleaner.out,
        images: cleaner.images,
    }
}

/// A complete HTML document around a cleaned fragment.
pub fn document(fragment: &str) -> String {
    format!(
        "<!DOCTYPE html>\n<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\n</head>\n<body>\n{fragment}\n</body>\n</html>\n"
    )
}

/// Plain text with the HTML's paragraphs, line breaks, lists, quotes (as
/// `> `), links (`text <url>`) and image descriptions; for the text
/// alternative of a message and for switching the editor to plain text.
pub fn to_text(html: &str) -> String {
    let mut writer = TextWriter::default();
    let mut skipping: Option<(String, usize)> = None;
    for token in tokenize(html) {
        if let Some((name, depth)) = &mut skipping {
            match &token {
                Token::Start { name: started, .. } if started == name => *depth += 1,
                Token::End(ended) if ended == name => {
                    *depth -= 1;
                    if *depth == 0 {
                        skipping = None;
                    }
                }
                _ => {}
            }
            continue;
        }
        match token {
            Token::Text(text) => writer.text(&decode_entities(text)),
            Token::Start { name, attributes } => {
                if DROP_CONTENT.contains(&name.as_str()) {
                    if !RAW_TEXT.contains(&name.as_str()) && name != "embed" {
                        skipping = Some((name, 1));
                    }
                    continue;
                }
                let attribute = |key: &str| {
                    attributes
                        .iter()
                        .find(|(name, _)| name == key)
                        .map(|(_, value)| decode_entities(value))
                };
                writer.start(
                    &name,
                    attribute("href"),
                    attribute("alt"),
                    attribute("start"),
                );
            }
            Token::End(name) => writer.end(&name),
        }
    }
    writer.finish()
}

/// An empty line, or one with only quote markers.
fn is_blank(line: &str) -> bool {
    line.bytes().all(|b| b == b'>')
}

#[derive(Default)]
struct TextWriter {
    lines: Vec<String>,
    line: String,
    /// The line has content (beyond a list marker).
    line_has_text: bool,
    quote: usize,
    pre: usize,
    /// Open lists: ordered, next number.
    lists: Vec<(bool, u64)>,
    /// Open links: target and where their text starts in `line`.
    links: Vec<(Option<String>, usize, usize)>,
    cells: usize,
}

impl TextWriter {
    fn push_line(&mut self) {
        let line = std::mem::take(&mut self.line);
        let line = if line == "-- " {
            line
        } else {
            line.trim_end().to_string()
        };
        let prefix = ">".repeat(self.quote);
        self.lines.push(match (prefix.is_empty(), line.is_empty()) {
            (true, _) => line,
            (false, true) => prefix,
            (false, false) => format!("{prefix} {line}"),
        });
        self.line_has_text = false;
    }

    /// End the current line if it has anything on it.
    fn flush(&mut self) {
        if !self.line.trim().is_empty() {
            self.push_line();
        } else {
            self.line.clear();
            self.line_has_text = false;
        }
    }

    /// Start a paragraph: end the line and leave one empty line before it.
    fn paragraph(&mut self) {
        self.flush();
        if self.lines.last().is_some_and(|last| !is_blank(last)) {
            self.push_line();
        }
    }

    fn text(&mut self, text: &str) {
        if self.pre > 0 {
            let mut parts = text.split('\n');
            if let Some(first) = parts.next() {
                self.line.push_str(first);
            }
            for part in parts {
                self.push_line();
                self.line.push_str(part);
            }
            self.line_has_text = true;
            return;
        }
        for c in text.chars() {
            let c = if c == '\u{a0}' { ' ' } else { c };
            if c.is_whitespace() {
                if self.line_has_text && !self.line.ends_with(' ') {
                    self.line.push(' ');
                }
            } else {
                self.line.push(c);
                self.line_has_text = true;
            }
        }
    }

    fn start(
        &mut self,
        name: &str,
        href: Option<String>,
        alt: Option<String>,
        start: Option<String>,
    ) {
        match name {
            "br" => {
                // The signature separator keeps its trailing space.
                if self.line == "--" {
                    self.line.push(' ');
                }
                self.push_line();
            }
            "p" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "table" | "pre" | "figure" => {
                self.paragraph();
                if name == "pre" {
                    self.pre += 1;
                }
            }
            "blockquote" => {
                self.paragraph();
                self.quote += 1;
            }
            "ul" | "ol" => {
                if self.lists.is_empty() {
                    self.paragraph();
                } else {
                    self.flush();
                }
                let first = start.and_then(|s| s.trim().parse().ok()).unwrap_or(1);
                self.lists.push((name == "ol", first));
            }
            "li" => {
                self.flush();
                let depth = self.lists.len().max(1);
                let marker = match self.lists.last_mut() {
                    Some((true, next)) => {
                        let marker = format!("{next}. ");
                        *next += 1;
                        marker
                    }
                    _ => "- ".to_string(),
                };
                self.line = format!("{}{marker}", "  ".repeat(depth - 1));
            }
            "tr" => {
                self.flush();
                self.cells = 0;
            }
            "td" | "th" => {
                if self.cells > 0 && self.line_has_text {
                    self.line.push('\t');
                }
                self.cells += 1;
            }
            "hr" => {
                self.paragraph();
                self.line.push_str("----------");
                self.line_has_text = true;
                self.push_line();
            }
            "img" => {
                if let Some(alt) = alt.filter(|alt| !alt.trim().is_empty()) {
                    self.text(&format!("[{}]", alt.trim()));
                }
            }
            "a" => {
                let at = self.lines.len();
                self.links.push((href, at, self.line.len()));
            }
            name if BLOCK.contains(&name)
                || matches!(name, "dt" | "dd" | "caption" | "figcaption") =>
            {
                self.flush()
            }
            _ => {}
        }
    }

    fn end(&mut self, name: &str) {
        match name {
            "p" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "table" | "figure" => self.paragraph(),
            "pre" => {
                self.pre = self.pre.saturating_sub(1);
                self.paragraph();
            }
            "blockquote" => {
                self.flush();
                while self
                    .lines
                    .last()
                    .is_some_and(|last| !last.is_empty() && is_blank(last))
                {
                    self.lines.pop();
                }
                self.quote = self.quote.saturating_sub(1);
                self.paragraph();
            }
            "ul" | "ol" => {
                self.flush();
                self.lists.pop();
                if self.lists.is_empty() {
                    self.paragraph();
                }
            }
            "a" => {
                if let Some((Some(href), line, at)) = self.links.pop() {
                    let target = href.strip_prefix("mailto:").unwrap_or(&href).to_string();
                    let label = if line == self.lines.len() {
                        self.line.get(at..).unwrap_or_default().trim().to_string()
                    } else {
                        String::new()
                    };
                    let lower = target.to_ascii_lowercase();
                    let linkable = lower.starts_with("http")
                        || lower.starts_with("tel:")
                        || href.to_ascii_lowercase().starts_with("mailto:");
                    if linkable && label != target && label != href {
                        self.text(&format!(" <{target}>"));
                    }
                }
            }
            name if BLOCK.contains(&name)
                || matches!(name, "li" | "tr" | "dt" | "dd" | "caption" | "figcaption") =>
            {
                self.flush()
            }
            _ => {}
        }
    }

    fn finish(mut self) -> String {
        self.flush();
        let mut out: Vec<String> = Vec::new();
        for line in self.lines {
            // An empty quote line that ends a quote is left out, and so are
            // repeated empty lines.
            if line.is_empty()
                && out
                    .last()
                    .is_some_and(|last| !last.is_empty() && is_blank(last))
            {
                out.pop();
            }
            if line.is_empty() && out.last().is_none_or(|last| last.is_empty()) {
                continue;
            }
            out.push(line);
        }
        while out.last().is_some_and(|last| is_blank(last)) {
            out.pop();
        }
        let mut text = out.join("\n");
        if !text.is_empty() {
            text.push('\n');
        }
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send(html: &str) -> Cleaned {
        clean(
            html,
            Options {
                remote_images: true,
                data_images: DataImages::Extract,
            },
        )
    }

    fn quote(html: &str) -> String {
        clean(
            html,
            Options {
                remote_images: false,
                data_images: DataImages::Keep,
            },
        )
        .html
    }

    #[test]
    fn many_raw_text_elements_are_skipped_in_linear_time() {
        // Each skipped element used to copy the rest of the document.
        let html = "<STYLE>p{}</Style><script>x()</SCRIPT>ok ".repeat(20_000);
        let started = std::time::Instant::now();
        let body = send(&html).html;
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert!(body.contains("ok") && !body.contains("x()") && !body.contains("p{}"));
    }

    #[test]
    fn scripts_handlers_and_dangerous_urls_are_removed() {
        let html = send(concat!(
            "<p onclick=\"steal()\" class=x>Hi <b>there</b></p>",
            "<script>alert(1)</script><style>p{color:red}</style>",
            "<a href=\"javascript:alert(1)\">a</a>",
            "<a href=\"jav&#x09;ascript:alert(1)\">b</a>",
            "<a href=\" &#106;avascript:alert(1)\">c</a>",
            "<a href=\"https://example.test/?a=1&amp;b=2\" target=_top>d</a>",
            "<img src=x onerror=alert(1)>",
            "<iframe src=\"https://evil.test\"></iframe>",
            "<svg><script>alert(1)</script><a href=x>e</a></svg>",
            "<div style=\"color: red; background: url(https://t.test/p.gif); position: fixed; font-weight: bold\">f</div>",
            "<form action=x><input name=a><button>g</button>h</form>",
            "<!-- <script>alert(1)</script> -->",
            "<math><mi xlink:href=\"javascript:alert(1)\">i</mi></math>",
            "<object data=x>j</object><embed src=x>",
        ))
        .html;
        assert_eq!(
            html,
            concat!(
                "<p>Hi <b>there</b></p>",
                "<a>a</a><a>b</a><a>c</a>",
                "<a href=\"https://example.test/?a=1&amp;b=2\">d</a>",
                "<div style=\"color: red; font-weight: bold\">f</div>",
                "h",
            )
        );
        for needle in [
            "script",
            "onerror",
            "onclick",
            "javascript",
            "iframe",
            "url(",
            "svg",
        ] {
            assert!(!html.contains(needle), "{needle} in {html}");
        }
    }

    #[test]
    fn markup_is_balanced_and_cannot_escape_its_container() {
        assert_eq!(
            send("<blockquote><div>quoted</blockquote></div></blockquote><b>after").html,
            "<blockquote><div>quoted</div></blockquote><b>after</b>"
        );
        assert_eq!(
            send("<ul><li>one<li>two</ul><p>a<p>b").html,
            "<ul><li>one</li><li>two</li></ul><p>a</p><p>b</p>"
        );
        assert_eq!(
            send("<table><tr><td>a<td>b<tr><td>c</table>").html,
            "<table><tr><td>a</td><td>b</td></tr><tr><td>c</td></tr></table>"
        );
        let deep = "<div>".repeat(500) + "x";
        let cleaned = send(&deep).html;
        assert_eq!(cleaned.matches("<div>").count(), MAX_DEPTH);
        assert!(cleaned.ends_with(&"</div>".repeat(MAX_DEPTH)));
        // Attribute values and text are re-escaped.
        assert_eq!(
            send("<span title='a\"><script>'>1 < 2 &unknown; &amp; &lt;b&gt; &bogus</span>").html,
            "<span title=\"a&quot;&gt;&lt;script&gt;\">1 &lt; 2 &unknown; &amp; &lt;b&gt; &amp;bogus</span>"
        );
        // An unterminated tag at the end is dropped.
        assert_eq!(send("ok<img src=\"https://x.test/a.png").html, "ok");
    }

    #[test]
    fn images_become_inline_parts_or_are_dropped() {
        let png = base64::engine::general_purpose::STANDARD.encode(b"\x89PNG fake");
        let html = format!(
            "<img src=\"data:image/png;base64,{png}\" alt=\"logo\" width=\"40\"><img src=\"https://example.test/a.png\"><img src=\"data:text/html;base64,PHNjcmlwdD4=\"><img src=\"cid:x@y\">"
        );
        let cleaned = send(&html);
        assert_eq!(cleaned.images.len(), 1);
        assert_eq!(cleaned.images[0].content_type, "image/png");
        assert_eq!(cleaned.images[0].data, b"\x89PNG fake");
        assert_eq!(
            cleaned.html,
            format!(
                "<img src=\"cid:{}\" alt=\"logo\" width=\"40\"><img src=\"https://example.test/a.png\">",
                cleaned.images[0].content_id
            )
        );
        // Quotes keep data images but leave remote ones out.
        let quoted = quote(&html);
        assert!(quoted.starts_with(&format!("<img src=\"data:image/png;base64,{png}\"")));
        assert!(!quoted.contains("example.test"));
    }

    #[test]
    fn word_and_docs_pastes_are_reduced_to_structure() {
        let word = concat!(
            "<html xmlns:o=\"urn:schemas-microsoft-com:office:office\"><head><meta charset=utf-8>",
            "<style>p.MsoNormal{margin:0}</style><title>Doc</title></head><body lang=DA>",
            "<!--[if gte mso 9]><xml><o:OfficeDocumentSettings/></xml><![endif]-->",
            "<p class=MsoNormal style='mso-line-height-alt:12pt;font-size:11.0pt;font-family:\"Calibri\",sans-serif'>",
            "<b><span style='mso-bidi-font-weight:normal'>Hej</span></b> verden<o:p></o:p></p>",
            "<b style=\"font-weight:normal\" id=\"docs-internal-guid-1\"><span style=\"color:#000000;\">Docs</span></b>",
            "</body></html>",
        );
        assert_eq!(
            send(word).html,
            "<p style=\"font-size: 11.0pt; font-family: &quot;Calibri&quot;,sans-serif\"><b><span>Hej</span></b> verden</p><b style=\"font-weight: normal\"><span style=\"color: #000000\">Docs</span></b>"
        );
    }

    #[test]
    fn text_alternative_follows_the_structure() {
        let html = concat!(
            "<div>Hi <b>Ann</b>,</div><div><br></div>",
            "<div>See <a href=\"https://example.test/doc\">the doc</a> and ",
            "<a href=\"https://example.test\">https://example.test</a>, or mail ",
            "<a href=\"mailto:bob@example.test\">bob@example.test</a>.</div>",
            "<ul><li>one</li><li>two<ol start=\"3\"><li>three</li></ol></li></ul>",
            "<p>Para&nbsp;one &amp; more</p><p>Para two</p>",
            "<blockquote><div>quoted</div><blockquote><div>deeper</div></blockquote></blockquote>",
            "<img src=\"cid:x\" alt=\"chart\"><hr>",
            "<pre>  code\n    indented</pre>",
            "<div>-- <br>Ann</div>",
        );
        assert_eq!(
            to_text(html),
            concat!(
                "Hi Ann,\n\nSee the doc <https://example.test/doc> and https://example.test, or mail bob@example.test.\n\n",
                "- one\n- two\n  3. three\n\n",
                "Para one & more\n\nPara two\n\n",
                "> quoted\n>\n>> deeper\n\n",
                "[chart]\n\n----------\n\n",
                "  code\n    indented\n\n",
                "-- \nAnn\n",
            )
        );
    }

    #[test]
    fn entities_decode() {
        assert_eq!(
            decode_entities("&aring;&#229;&#xE5; &nope; &amp &#0;"),
            "ååå &nope; &amp \u{fffd}"
        );
    }
}
