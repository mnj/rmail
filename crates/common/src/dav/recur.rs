//! When the occurrences of a calendar object happen: date-times read in
//! their time zones and recurrences expanded (RFC 5545 3.3.5, 3.8.5), for
//! free-busy lookups.
//!
//! - `TZID`s are read as IANA zone names, which is what calendar clients
//!   send; an unknown zone, like a floating time, is read as UTC.
//! - Recurrence rules expand with the `rrule` crate, which caps how many
//!   occurrences one rule may produce.

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};

use super::text::{self, Component, Property};

/// An occurrence: start and end in Unix seconds, and the component
/// (index into the calendar's components) it comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Occurrence {
    pub start: i64,
    pub end: i64,
    pub component: usize,
}

/// The most occurrences produced for one object.
const MAX_OCCURRENCES: u16 = 2000;

fn zone(property: &Property) -> chrono_tz::Tz {
    property
        .param("TZID")
        .map(|tzid| tzid.trim().trim_start_matches('/'))
        .and_then(|tzid| tzid.parse::<chrono_tz::Tz>().ok())
        .unwrap_or(chrono_tz::UTC)
}

fn naive(value: &str) -> Option<(NaiveDateTime, bool)> {
    let value = value.trim();
    let utc = value.ends_with('Z');
    let value = value.trim_end_matches('Z');
    if value.len() == 8 {
        let date = NaiveDate::parse_from_str(value, "%Y%m%d").ok()?;
        return Some((date.and_hms_opt(0, 0, 0)?, utc));
    }
    Some((
        NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%S").ok()?,
        utc,
    ))
}

/// A date-time value in the zone of its property.
fn zoned(property: &Property, value: &str) -> Option<DateTime<chrono_tz::Tz>> {
    let (local, utc) = naive(value)?;
    let tz = if utc { chrono_tz::UTC } else { zone(property) };
    // A time skipped by a daylight-saving change counts from an hour on.
    tz.from_local_datetime(&local).earliest().or_else(|| {
        tz.from_local_datetime(&(local + chrono::Duration::hours(1)))
            .earliest()
    })
}

/// A date-time property (DTSTART, RECURRENCE-ID...) as Unix seconds.
pub fn instant(property: &Property) -> Option<i64> {
    zoned(property, &property.value).map(|time| time.timestamp())
}

fn is_date(property: &Property) -> bool {
    property
        .param("VALUE")
        .is_some_and(|value| value.eq_ignore_ascii_case("DATE"))
        || property.value.trim().len() == 8
}

/// How long each occurrence of `component` lasts, in seconds.
fn length(component: &Component, start: &Property) -> i64 {
    let begin = instant(start).unwrap_or_default();
    if let Some(end) = component.property("DTEND").and_then(instant) {
        return (end - begin).max(0);
    }
    if let Some(duration) = component
        .property("DURATION")
        .and_then(|property| text::parse_duration(&property.value))
    {
        return duration.max(0);
    }
    if is_date(start) { 86_400 } else { 0 }
}

/// The start times of a component's occurrences between `from` and
/// `until` (Unix seconds), ignoring overridden ones.
fn starts(component: &Component, start: &Property, from: i64, until: i64) -> Vec<i64> {
    let Some(dt_start) = zoned(start, &start.value) else {
        return Vec::new();
    };
    let has_rule = component.property("RRULE").is_some();
    let rdates = component.properties_named("RDATE").collect::<Vec<_>>();
    if !has_rule && rdates.is_empty() {
        return vec![dt_start.timestamp()];
    }
    let tz = rrule::Tz::Tz(dt_start.timezone());
    let dt_start = dt_start.with_timezone(&tz);
    let mut set = rrule::RRuleSet::new(dt_start);
    for rule in component.properties_named("RRULE") {
        let Ok(parsed) = rule.value.parse::<rrule::RRule<rrule::Unvalidated>>() else {
            // An unreadable rule: the first occurrence still happens.
            return vec![dt_start.timestamp()];
        };
        match parsed.validate(dt_start) {
            Ok(rule) => set = set.rrule(rule),
            Err(_) => return vec![dt_start.timestamp()],
        }
    }
    let dates = |property: &Property| {
        property
            .value
            .split(',')
            .filter_map(|value| zoned(property, value))
            .map(|time| time.with_timezone(&tz))
            .collect::<Vec<_>>()
    };
    for property in rdates {
        // PERIOD values (start/end) count by their start.
        let starts_only = Property {
            value: property
                .value
                .split(',')
                .map(|value| value.split('/').next().unwrap_or_default())
                .collect::<Vec<_>>()
                .join(","),
            ..property.clone()
        };
        for date in dates(&starts_only) {
            set = set.rdate(date);
        }
    }
    for property in component.properties_named("EXDATE") {
        for date in dates(property) {
            set = set.exdate(date);
        }
    }
    let at = |seconds: i64| {
        Utc.timestamp_opt(seconds, 0)
            .single()
            .unwrap_or_default()
            .with_timezone(&tz)
    };
    let mut found = Vec::new();
    // Rules without a set start year still expand from DTSTART; `after`
    // and `before` are exclusive.
    let result = set
        .after(at(from - 1))
        .before(at(until))
        .all(MAX_OCCURRENCES);
    for date in result.dates {
        found.push(date.timestamp());
    }
    found
}

/// The occurrences of the calendar's events and to-dos that overlap
/// `from..until`, with overridden instances (RECURRENCE-ID) replaced.
pub fn occurrences(calendar: &Component, from: i64, until: i64) -> Vec<Occurrence> {
    let mut found = Vec::new();
    let overridden = calendar
        .components
        .iter()
        .filter_map(|component| component.property("RECURRENCE-ID").and_then(instant))
        .collect::<Vec<_>>();
    for (index, component) in calendar.components.iter().enumerate() {
        if component.name == "VTIMEZONE" {
            continue;
        }
        let Some(start) = component
            .property("DTSTART")
            .or_else(|| component.property("DUE"))
        else {
            continue;
        };
        let length = length(component, start);
        let is_override = component.property("RECURRENCE-ID").is_some();
        let starts = if is_override {
            instant(start).into_iter().collect()
        } else {
            starts(component, start, from - length, until)
        };
        for begin in starts {
            if !is_override && overridden.contains(&begin) {
                continue;
            }
            let end = begin + length;
            let overlaps = if length == 0 {
                begin >= from && begin < until
            } else {
                begin < until && end > from
            };
            if overlaps {
                found.push(Occurrence {
                    start: begin,
                    end,
                    component: index,
                });
            }
        }
    }
    found.sort_by_key(|occurrence| occurrence.start);
    found
}

/// A UTC date-time value (`20261012T090000Z`).
pub fn utc_text(seconds: i64) -> String {
    Utc.timestamp_opt(seconds, 0)
        .single()
        .unwrap_or_default()
        .format("%Y%m%dT%H%M%SZ")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn calendar(body: &str) -> Component {
        text::parse(&format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n{body}END:VCALENDAR\r\n"
        ))
        .unwrap()
    }

    fn at(text: &str) -> i64 {
        NaiveDateTime::parse_from_str(text, "%Y%m%dT%H%M%S")
            .unwrap()
            .and_utc()
            .timestamp()
    }

    #[test]
    fn zones_follow_daylight_saving() {
        let winter = Property {
            name: "DTSTART".into(),
            params: vec![("TZID".into(), "Europe/Copenhagen".into())],
            value: "20261210T090000".into(),
        };
        assert_eq!(instant(&winter), Some(at("20261210T080000")));
        let summer = Property {
            value: "20260710T090000".into(),
            ..winter.clone()
        };
        assert_eq!(instant(&summer), Some(at("20260710T070000")));
        let unknown = Property {
            params: vec![("TZID".into(), "W. Europe Standard Time".into())],
            ..winter
        };
        assert_eq!(instant(&unknown), Some(at("20261210T090000")));
    }

    #[test]
    fn weekly_events_expand_with_exceptions_and_overrides() {
        let weekly = calendar(
            "BEGIN:VEVENT\r\nUID:w\r\nDTSTART;TZID=Europe/Copenhagen:20261005T090000\r\n\
             DTEND;TZID=Europe/Copenhagen:20261005T100000\r\nRRULE:FREQ=WEEKLY;COUNT=10\r\n\
             EXDATE;TZID=Europe/Copenhagen:20261012T090000\r\nEND:VEVENT\r\n\
             BEGIN:VEVENT\r\nUID:w\r\nRECURRENCE-ID;TZID=Europe/Copenhagen:20261019T090000\r\n\
             DTSTART;TZID=Europe/Copenhagen:20261019T140000\r\n\
             DTEND;TZID=Europe/Copenhagen:20261019T150000\r\nEND:VEVENT\r\n",
        );
        let found = occurrences(&weekly, at("20261001T000000"), at("20261031T000000"));
        let starts = found.iter().map(|o| o.start).collect::<Vec<_>>();
        // 5 Oct (CEST, UTC+2), 12 Oct excluded, 19 Oct moved to 14:00,
        // 26 Oct after the change to CET (UTC+1).
        assert_eq!(
            starts,
            vec![
                at("20261005T070000"),
                at("20261019T120000"),
                at("20261026T080000"),
            ]
        );
        assert_eq!(found[1].component, 1);
        assert_eq!(found[0].end - found[0].start, 3600);
        // A range in the middle of an occurrence still finds it.
        let inside = occurrences(&weekly, at("20261005T073000"), at("20261005T074500"));
        assert_eq!(inside.len(), 1);
    }

    #[test]
    fn single_and_all_day_events() {
        let single = calendar(
            "BEGIN:VEVENT\r\nUID:s\r\nDTSTART:20261012T090000Z\r\nDURATION:PT30M\r\nEND:VEVENT\r\n\
             BEGIN:VEVENT\r\nUID:s\r\nRECURRENCE-ID:20261013T090000Z\r\nDTSTART:20261013T090000Z\r\nEND:VEVENT\r\n",
        );
        let found = occurrences(&single, at("20261012T000000"), at("20261013T000000"));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].end - found[0].start, 1800);
        let day =
            calendar("BEGIN:VEVENT\r\nUID:d\r\nDTSTART;VALUE=DATE:20261012\r\nEND:VEVENT\r\n");
        let found = occurrences(&day, at("20261012T120000"), at("20261012T130000"));
        assert_eq!(found[0].end - found[0].start, 86_400);
        assert_eq!(utc_text(at("20261012T090000")), "20261012T090000Z");
    }
}
