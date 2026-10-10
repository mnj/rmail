//! The content lines shared by iCalendar (RFC 5545) and vCard (RFC 6350):
//! `NAME;PARAM=value:value`, folded at 75 octets, grouped into components
//! by `BEGIN:`/`END:`. Only what the DAV server needs is interpreted: UIDs,
//! component kinds and the dates that bound an event in time.

use anyhow::{Result, bail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Property {
    /// Upper-cased name, without any vCard group (`item1.EMAIL` is `EMAIL`).
    pub name: String,
    /// Parameters with upper-cased names; quotes removed from values.
    pub params: Vec<(String, String)>,
    pub value: String,
}

impl Property {
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    /// Upper-cased, e.g. `VCALENDAR`, `VEVENT`, `VCARD`.
    pub name: String,
    pub properties: Vec<Property>,
    pub components: Vec<Component>,
}

impl Component {
    pub fn property(&self, name: &str) -> Option<&Property> {
        self.properties
            .iter()
            .find(|property| property.name.eq_ignore_ascii_case(name))
    }

    pub fn properties_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Property> {
        self.properties
            .iter()
            .filter(move |property| property.name.eq_ignore_ascii_case(name))
    }
}

impl Property {
    pub fn new(name: &str, value: &str) -> Self {
        Property {
            name: name.to_ascii_uppercase(),
            params: Vec::new(),
            value: value.to_string(),
        }
    }

    /// Set (or with `None`, remove) a parameter; a replaced one keeps its
    /// place.
    pub fn set_param(&mut self, name: &str, value: Option<&str>) {
        let at = self
            .params
            .iter()
            .position(|(key, _)| key.eq_ignore_ascii_case(name));
        self.params
            .retain(|(key, _)| !key.eq_ignore_ascii_case(name));
        if let Some(value) = value {
            let param = (name.to_ascii_uppercase(), value.to_string());
            match at {
                Some(at) => self.params.insert(at, param),
                None => self.params.push(param),
            }
        }
    }
}

impl Component {
    pub fn new(name: &str) -> Self {
        Component {
            name: name.to_ascii_uppercase(),
            properties: Vec::new(),
            components: Vec::new(),
        }
    }

    /// Replace every property `name` with one holding `value`.
    pub fn set_property(&mut self, name: &str, value: &str) {
        let at = self
            .properties
            .iter()
            .position(|property| property.name.eq_ignore_ascii_case(name));
        self.properties
            .retain(|property| !property.name.eq_ignore_ascii_case(name));
        let property = Property::new(name, value);
        match at {
            Some(at) => self
                .properties
                .insert(at.min(self.properties.len()), property),
            None => self.properties.push(property),
        }
    }

    /// The content lines again, folded at 75 octets with CRLF ends.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        fold(out, &format!("BEGIN:{}", self.name));
        for property in &self.properties {
            let mut line = property.name.clone();
            for (key, value) in &property.params {
                line.push(';');
                line.push_str(key);
                line.push('=');
                line.push_str(&param_text(key, value));
            }
            line.push(':');
            line.push_str(&property.value);
            fold(out, &line);
        }
        for component in &self.components {
            component.write(out);
        }
        fold(out, &format!("END:{}", self.name));
    }
}

/// A parameter value as written: quoted when it holds `:`, `;` or `,`.
/// The parser drops quotes, so lists of addresses (`DELEGATED-TO`,
/// `MEMBER`) are quoted value by value.
fn param_text(key: &str, value: &str) -> String {
    let quote = |text: &str| {
        if text.contains([':', ';', ',']) {
            format!("\"{}\"", text.replace('"', ""))
        } else {
            text.to_string()
        }
    };
    if matches!(key, "DELEGATED-TO" | "DELEGATED-FROM" | "MEMBER") {
        value.split(',').map(quote).collect::<Vec<_>>().join(",")
    } else {
        quote(value)
    }
}

/// Append `line`, folded at 75 octets without splitting a character.
fn fold(out: &mut String, line: &str) {
    let mut width = 0;
    for c in line.chars() {
        if width + c.len_utf8() > 75 {
            out.push_str("\r\n ");
            width = 1;
        }
        out.push(c);
        width += c.len_utf8();
    }
    out.push_str("\r\n");
}

/// Unfold and split into logical lines.
fn lines(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(rest) = raw.strip_prefix([' ', '\t']) {
            if let Some(last) = out.last_mut() {
                last.push_str(rest);
            }
            continue;
        }
        if !raw.is_empty() {
            out.push(raw.to_string());
        }
    }
    out
}

fn parse_line(line: &str) -> Result<Property> {
    // The name and parameters end at the first colon outside quotes.
    let mut in_quotes = false;
    let mut colon = None;
    for (index, c) in line.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ':' if !in_quotes => {
                colon = Some(index);
                break;
            }
            _ => {}
        }
    }
    let Some(colon) = colon else {
        bail!("content line without a colon: {line:.60}");
    };
    let (head, value) = (&line[..colon], &line[colon + 1..]);
    let mut pieces = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for c in head.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            ';' if !in_quotes => pieces.push(std::mem::take(&mut current)),
            c => current.push(c),
        }
    }
    pieces.push(current);
    let name = pieces[0]
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        bail!("invalid property name in {line:.60}");
    }
    let params = pieces[1..]
        .iter()
        .map(|piece| match piece.split_once('=') {
            Some((key, value)) => (key.to_ascii_uppercase(), value.to_string()),
            None => (piece.to_ascii_uppercase(), String::new()),
        })
        .collect();
    Ok(Property {
        name,
        params,
        value: value.to_string(),
    })
}

/// Parse one top-level component (VCALENDAR or VCARD) and nothing else.
pub fn parse(text: &str) -> Result<Component> {
    let mut stack: Vec<Component> = Vec::new();
    let mut root = None;
    for line in lines(text) {
        let property = parse_line(&line)?;
        match property.name.as_str() {
            "BEGIN" => {
                if root.is_some() {
                    bail!("content after the end of the object");
                }
                stack.push(Component {
                    name: property.value.trim().to_ascii_uppercase(),
                    properties: Vec::new(),
                    components: Vec::new(),
                });
                if stack.len() > 20 {
                    bail!("components nested too deeply");
                }
            }
            "END" => {
                let Some(done) = stack.pop() else {
                    bail!("END without BEGIN");
                };
                if !done.name.eq_ignore_ascii_case(property.value.trim()) {
                    bail!("END:{} closes BEGIN:{}", property.value.trim(), done.name);
                }
                match stack.last_mut() {
                    Some(parent) => parent.components.push(done),
                    None => root = Some(done),
                }
            }
            _ => match stack.last_mut() {
                Some(current) => current.properties.push(property),
                None => bail!("property outside any component"),
            },
        }
    }
    if !stack.is_empty() {
        bail!("BEGIN:{} is not closed", stack[0].name);
    }
    root.ok_or_else(|| anyhow::anyhow!("no component"))
}

// ---------------------------------------------------------------------------
// Dates

/// An instant, Unix seconds. Floating and zoned times are read as UTC; the
/// caller widens ranges by `ZONE_SLACK` to cover any zone.
fn parse_date_time(value: &str) -> Option<(i64, bool)> {
    let value = value.trim();
    let utc = value.ends_with('Z');
    let value = value.trim_end_matches('Z');
    if value.len() == 8 {
        let date = chrono::NaiveDate::parse_from_str(value, "%Y%m%d").ok()?;
        return Some((date.and_hms_opt(0, 0, 0)?.and_utc().timestamp(), utc));
    }
    let date = chrono::NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%S").ok()?;
    Some((date.and_utc().timestamp(), utc))
}

/// Seconds a local time can differ from UTC; a time with a zone or a
/// floating time is somewhere within this of its UTC reading.
pub const ZONE_SLACK: i64 = 14 * 3600;

/// A property's time, with whether it was all-day and whether it was UTC.
fn property_time(property: &Property) -> Option<(i64, bool, bool)> {
    let all_day = property
        .param("VALUE")
        .is_some_and(|value| value.eq_ignore_ascii_case("DATE"))
        || property.value.trim().len() == 8;
    let (at, utc) = parse_date_time(&property.value)?;
    Some((at, all_day, utc))
}

/// An RFC 5545 duration (`P1W`, `-PT15M`, `P1DT2H`), in seconds.
pub fn parse_duration(value: &str) -> Option<i64> {
    let value = value.trim();
    let (sign, rest) = match value.strip_prefix('-') {
        Some(rest) => (-1, rest),
        None => (1, value.strip_prefix('+').unwrap_or(value)),
    };
    let rest = rest.strip_prefix('P')?;
    let mut total = 0i64;
    let mut number = String::new();
    let mut in_time = false;
    for c in rest.chars() {
        match c {
            'T' => in_time = true,
            '0'..='9' => number.push(c),
            unit => {
                let amount: i64 = number.parse().ok()?;
                number.clear();
                total += amount
                    * match (unit, in_time) {
                        ('W', false) => 7 * 86_400,
                        ('D', false) => 86_400,
                        ('H', true) => 3_600,
                        ('M', true) => 60,
                        ('S', true) => 1,
                        _ => return None,
                    };
            }
        }
    }
    number.is_empty().then_some(sign * total)
}

/// The span of time a calendar object may occupy, for time-range queries:
/// `(start, end)` in Unix seconds, `None` meaning unbounded. It is a
/// superset: recurrences without an end make it open-ended, and zoned or
/// floating times are widened by `ZONE_SLACK`, so a query never misses an
/// object (RFC 4791 lets clients filter the results further).
pub fn time_bounds(calendar: &Component) -> (Option<i64>, Option<i64>) {
    let mut start: Option<i64> = None;
    let mut end: Option<i64> = None;
    let mut open_start = false;
    let mut open_end = false;
    for component in &calendar.components {
        if component.name == "VTIMEZONE" {
            continue;
        }
        let begin = component
            .property("DTSTART")
            .and_then(property_time)
            .or_else(|| component.property("DUE").and_then(property_time));
        let Some((begin, all_day, utc)) = begin else {
            // A to-do without dates is always in range (RFC 4791 9.9).
            open_start = true;
            open_end = true;
            continue;
        };
        let slack = if utc { 0 } else { ZONE_SLACK };
        let finish =
            if let Some((finish, _, _)) = component.property("DTEND").and_then(property_time) {
                finish
            } else if let Some(duration) = component
                .property("DURATION")
                .and_then(|property| parse_duration(&property.value))
            {
                begin + duration.max(0)
            } else if all_day {
                begin + 86_400
            } else {
                begin
            };
        let mut finish = finish.max(begin) + slack;
        if component.property("RRULE").is_some() || component.property("RDATE").is_some() {
            match component.property("RRULE").and_then(|rule| {
                rule.value
                    .split(';')
                    .find_map(|part| part.strip_prefix("UNTIL="))
                    .and_then(parse_date_time)
            }) {
                // UNTIL bounds the last start; the last occurrence ends
                // at most one occurrence length after it.
                Some((until, _)) if component.property("RDATE").is_none() => {
                    finish = finish.max(until + (finish - begin) + ZONE_SLACK);
                }
                _ => open_end = true,
            }
        }
        let begin = begin - slack;
        start = Some(start.map_or(begin, |known| known.min(begin)));
        end = Some(end.map_or(finish, |known| known.max(finish)));
    }
    (
        if open_start { None } else { start },
        if open_end { None } else { end },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVENT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n\
BEGIN:VEVENT\r\nUID:abc@example.test\r\nDTSTART:20261012T090000Z\r\nDTEND:20261012T100000Z\r\n\
SUMMARY:Stand\r\n up\r\nDESCRIPTION;LANGUAGE=en:Room \"A\": first floor\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    #[test]
    fn parses_folded_lines_parameters_and_components() {
        let calendar = parse(EVENT).unwrap();
        assert_eq!(calendar.name, "VCALENDAR");
        let event = &calendar.components[0];
        assert_eq!(event.property("summary").unwrap().value, "Standup");
        assert_eq!(
            event.property("DESCRIPTION").unwrap().param("language"),
            Some("en")
        );
        assert_eq!(
            event.property("DESCRIPTION").unwrap().value,
            "Room \"A\": first floor"
        );
        let card =
            parse("BEGIN:VCARD\nVERSION:4.0\nitem1.EMAIL;TYPE=\"work,pref\":a@x.test\nEND:VCARD\n")
                .unwrap();
        assert_eq!(
            card.property("EMAIL").unwrap().param("TYPE"),
            Some("work,pref")
        );
        assert!(parse("BEGIN:VCALENDAR\r\nEND:VEVENT\r\n").is_err());
        assert!(parse("BEGIN:VCARD\r\nFN:x\r\n").is_err());
        assert!(parse("FN:x\r\n").is_err());
    }

    #[test]
    fn writes_back_what_it_reads() {
        let calendar = parse(EVENT).unwrap();
        let text = calendar.to_text();
        assert!(text.contains("SUMMARY:Standup\r\n"));
        assert!(text.contains("DESCRIPTION;LANGUAGE=en:Room \"A\": first floor\r\n"));
        assert_eq!(parse(&text).unwrap(), calendar);
        let mut attendee = Property::new("ATTENDEE", "mailto:a@x.test");
        attendee.set_param("CN", Some("Doe, Jane"));
        attendee.set_param("DELEGATED-TO", Some("mailto:b@x.test,mailto:c@x.test"));
        let mut event = Component::new("VEVENT");
        event.properties.push(attendee);
        event.set_property("SUMMARY", &"é".repeat(60));
        let text = event.to_text();
        assert!(text.contains(
            "ATTENDEE;CN=\"Doe, Jane\";DELEGATED-TO=\"mailto:b@x.test\",\"mailto:c@x.test\":"
        ));
        assert!(text.split("\r\n").all(|line| line.len() <= 75));
        let back = parse(&format!("BEGIN:VCALENDAR\r\n{text}END:VCALENDAR\r\n")).unwrap();
        assert_eq!(back.components[0], event);
    }

    #[test]
    fn bounds_cover_zones_all_day_and_recurrence() {
        let utc = parse(EVENT).unwrap();
        assert_eq!(
            time_bounds(&utc),
            (Some(1_791_795_600), Some(1_791_799_200))
        );
        let all_day = parse(
            "BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:x\nDTSTART;VALUE=DATE:20261012\nEND:VEVENT\nEND:VCALENDAR\n",
        )
        .unwrap();
        let (start, end) = time_bounds(&all_day);
        assert_eq!(end.unwrap() - start.unwrap(), 86_400 + 2 * ZONE_SLACK);
        let weekly = parse(
            "BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:x\nDTSTART:20261012T090000Z\nDURATION:PT1H\nRRULE:FREQ=WEEKLY\nEND:VEVENT\nEND:VCALENDAR\n",
        )
        .unwrap();
        assert_eq!(time_bounds(&weekly), (Some(1_791_795_600), None));
        let todo =
            parse("BEGIN:VCALENDAR\nBEGIN:VTODO\nUID:t\nEND:VTODO\nEND:VCALENDAR\n").unwrap();
        assert_eq!(time_bounds(&todo), (None, None));
        assert_eq!(parse_duration("P1DT2H"), Some(93_600));
        assert_eq!(parse_duration("-PT15M"), Some(-900));
        assert_eq!(parse_duration("P2W"), Some(1_209_600));
    }
}
