//! The event viewer's model. For each of the four event rows it holds the queries the row's
//! check reads, reads them again with redacted messages, and filters the events by level,
//! time range and text. The window in `src/gui/event_view.rs` draws what this returns.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use crate::clock::{self, Stamp};
use crate::events::{self, Category, Event, Limit, LogRead, Query, ReadError, Tier};

/// Message characters kept per event; the engine's redaction applies first.
pub const MESSAGE_CHARS: usize = 4000;
/// Events read per log when the range is longer than the check's own.
pub const LONG_RANGE_LIMIT: usize = 5000;
/// How long one read may take, shared out between the preset's queries.
pub const READ_TIME: Duration = Duration::from_secs(30);
/// After this many seconds the progress line says the read is slow.
pub const SLOW_SECONDS: u64 = 10;
/// Where "Search the web" goes; only the source and the event id are sent.
pub const SEARCH_URL: &str = "https://www.google.com/search?q=";

const HOUR: Duration = Duration::from_secs(3600);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Range {
    Day,
    Week,
    Month,
}

impl Range {
    pub const ALL: [Range; 3] = [Range::Day, Range::Week, Range::Month];

    pub fn span(self) -> Duration {
        match self {
            Range::Day => HOUR * 24,
            Range::Week => HOUR * 24 * 7,
            Range::Month => HOUR * 24 * 30,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Range::Day => "24 hours",
            Range::Week => "7 days",
            Range::Month => "30 days",
        }
    }
}

/// The four level toggles. Verbose events fall under information.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Critical,
    Error,
    Warning,
    Information,
}

impl Level {
    pub const ALL: [Level; 4] = [
        Level::Critical,
        Level::Error,
        Level::Warning,
        Level::Information,
    ];

    pub fn of(level: u8) -> Level {
        match level {
            1 => Level::Critical,
            2 => Level::Error,
            3 => Level::Warning,
            _ => Level::Information,
        }
    }

    pub fn index(self) -> usize {
        self as usize
    }

    pub fn label(self) -> &'static str {
        match self {
            Level::Critical => "Critical",
            Level::Error => "Error",
            Level::Warning => "Warning",
            Level::Information => "Information",
        }
    }

    /// The level number a query asks for; information also brings level 0.
    fn code(self) -> u8 {
        self as u8 + 1
    }
}

/// Which events of a query the row's check counts.
#[derive(Clone, Copy, Debug)]
pub enum Scope {
    All,
    Crashes,
    Services,
    Hardware(&'static Category),
}

impl Scope {
    pub fn keeps(&self, event: &Event) -> bool {
        match self {
            Scope::All => true,
            Scope::Crashes => events::is_crash_or_hang(event),
            Scope::Services => events::is_service_failure(event),
            Scope::Hardware(category) => category.owns(event),
        }
    }

    /// The kind's short name and whether it is serious: the known kind, else for a
    /// hardware category its own label and tier.
    pub fn kind(&self, event: &Event) -> (Option<&'static str>, bool) {
        if let Some(kind) = events::known(&event.provider, event.id) {
            return (Some(kind.short), kind.tier == Tier::Serious);
        }
        match self {
            Scope::Hardware(category) => (Some(category.label), category.all_serious),
            _ => (None, false),
        }
    }
}

/// One query of a preset.
#[derive(Clone, Debug)]
pub struct Part {
    /// "the System log", "drive error events": used in progress and notes.
    pub label: String,
    pub query: Query,
    pub scope: Scope,
}

/// What the viewer shows for one row: the row check's own queries.
#[derive(Clone, Debug)]
pub struct Preset {
    pub title: &'static str,
    pub description: String,
    pub parts: Vec<Part>,
    /// Kinds in the noise table are hidden, as the check hides them.
    pub hide_routine: bool,
}

fn log_part(query: Query, scope: Scope) -> Part {
    Part {
        label: format!("the {} log", query.logs.join(" and ")),
        query,
        scope,
    }
}

/// The preset for a row's check id, or None for a row that has no event viewer.
pub fn preset(check: &str) -> Option<Preset> {
    match check {
        "events.recent" => {
            let survey = Query::survey();
            Some(Preset {
                title: "Recent system events",
                description: "Critical, error and warning events from the System and Application logs. Kinds Windows logs routinely are hidden, as in the check.".into(),
                hide_routine: !survey.include_noise,
                parts: survey
                    .logs
                    .iter()
                    .map(|log| {
                        log_part(
                            Query {
                                logs: vec![log.clone()],
                                ..survey.clone()
                            },
                            Scope::All,
                        )
                    })
                    .collect(),
            })
        }
        "events.crashes" => Some(Preset {
            title: "App crashes",
            description: "Application Error 1000 (an app crashed) and Application Hang 1002 (an app stopped responding), from the Application log.".into(),
            hide_routine: false,
            parts: vec![log_part(events::crash_query(), Scope::Crashes)],
        }),
        "services.failures" => Some(Preset {
            title: "Service failures",
            description: "Service Control Manager 7031 and 7034 (a service stopped unexpectedly) and 7000, 7001, 7009, 7011, 7023, 7024 (a service failed to start or respond), from the System log.".into(),
            hide_routine: false,
            parts: vec![log_part(events::service_query(), Scope::Services)],
        }),
        "hardware.events" => Some(Preset {
            title: "Hardware and driver events",
            description: format!(
                "Hardware, drive, file system, graphics driver and driver load events from the System log: {}.",
                events::HARDWARE
                    .iter()
                    .map(|category| format!("{} ({})", category.label, category.scope))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            hide_routine: false,
            parts: events::HARDWARE
                .iter()
                .map(|category| Part {
                    label: format!("{} events", category.label.to_lowercase()),
                    query: events::hardware_query(category),
                    scope: Scope::Hardware(category),
                })
                .collect(),
        }),
        _ => None,
    }
}

impl Preset {
    /// The level toggles the row's check reads: every level when any query reads all.
    pub fn default_levels(&self) -> [bool; 4] {
        if self.parts.iter().any(|part| part.query.levels.is_empty()) {
            return [true; 4];
        }
        let mut on = [false; 4];
        for part in &self.parts {
            for &level in &part.query.levels {
                on[Level::of(level).index()] = true;
            }
        }
        on
    }

    /// The check's own time range, which the viewer opens at.
    pub fn default_range(&self) -> Range {
        let span = self
            .parts
            .iter()
            .map(|part| part.query.since)
            .max()
            .unwrap_or_default();
        Range::ALL
            .into_iter()
            .find(|range| range.span() >= span)
            .unwrap_or(Range::Month)
    }

    pub fn default_filter(&self) -> Filter {
        Filter {
            levels: self.default_levels(),
            range: self.default_range(),
            text: String::new(),
        }
    }

    /// The logs read, for the scope line: "System and Application logs".
    pub fn logs(&self) -> String {
        let mut logs: Vec<&str> = Vec::new();
        for part in &self.parts {
            for log in &part.query.logs {
                if !logs.contains(&log.as_str()) {
                    logs.push(log);
                }
            }
        }
        format!(
            "{} {}",
            logs.join(" and "),
            if logs.len() == 1 { "log" } else { "logs" }
        )
    }

    /// The queries a filter needs: the check's own, with messages, the filter's range and
    /// any level the user turned on beyond the check's.
    pub fn queries(&self, filter: &Filter) -> Vec<Query> {
        let defaults = self.default_levels();
        let extra: Vec<u8> = Level::ALL
            .into_iter()
            .filter(|level| filter.levels[level.index()] && !defaults[level.index()])
            .map(Level::code)
            .collect();
        self.parts
            .iter()
            .map(|part| {
                let mut query = part.query.clone();
                query.messages = true;
                if filter.range.span() > query.since {
                    query.per_log_limit = query.per_log_limit.max(LONG_RANGE_LIMIT);
                }
                query.since = filter.range.span();
                if !query.levels.is_empty() {
                    for &level in &extra {
                        if !query.levels.contains(&level) {
                            query.levels.push(level);
                        }
                    }
                }
                query
            })
            .collect()
    }
}

/// What the user chose to see.
#[derive(Clone, Debug, PartialEq)]
pub struct Filter {
    /// On or off for critical, error, warning and information, in that order.
    pub levels: [bool; 4],
    pub range: Range,
    pub text: String,
}

/// Whether events read with `loaded` already hold everything `wanted` asks for, so a
/// changed filter only needs filtering again.
pub fn covers(loaded: &[Query], wanted: &[Query]) -> bool {
    loaded.len() == wanted.len()
        && loaded.iter().zip(wanted).all(|(have, want)| {
            have.since >= want.since
                && have.per_log_limit >= want.per_log_limit
                && (have.levels.is_empty()
                    || (!want.levels.is_empty()
                        && want.levels.iter().all(|level| have.levels.contains(level))))
        })
}

/// One event as the viewer lists it.
#[derive(Clone, Debug)]
pub struct Row {
    pub event: Event,
    /// The known kind's short name, or the hardware category's label.
    pub kind: Option<&'static str>,
    pub serious: bool,
    /// A kind in the noise table.
    pub routine: bool,
    /// Lower-case source, id and message, for the text search.
    search: String,
}

impl Row {
    pub fn new(event: Event, scope: &Scope) -> Self {
        let (kind, serious) = scope.kind(&event);
        let search = format!(
            "{} {} {}",
            event.provider,
            event.id,
            event.message.as_deref().unwrap_or("")
        )
        .to_lowercase();
        Self {
            routine: events::noise(&event.provider, event.id).is_some(),
            event,
            kind,
            serious,
            search,
        }
    }

    pub fn mark(&self) -> Mark {
        match Level::of(self.event.level) {
            Level::Critical => Mark::Serious,
            _ if self.serious => Mark::Serious,
            Level::Error | Level::Warning => Mark::Warn,
            Level::Information => Mark::Muted,
        }
    }
}

/// The colour of an event's level icon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark {
    /// Critical events and serious known kinds.
    Serious,
    /// Errors and warnings.
    Warn,
    /// Information.
    Muted,
}

/// How reading one query ended.
#[derive(Clone, Debug)]
pub struct PartRead {
    pub label: String,
    pub read: LogRead,
    /// The oldest event read, to tell whether a limit cut into the range shown.
    pub oldest: Option<SystemTime>,
}

/// The events of one read, newest first.
#[derive(Clone, Debug)]
pub struct Loaded {
    pub queries: Vec<Query>,
    pub rows: Vec<Row>,
    pub parts: Vec<PartRead>,
}

/// Which query is being read and how many events so far, for the progress line.
#[derive(Debug, Default)]
pub struct Progress {
    pub part: AtomicUsize,
    pub events: AtomicUsize,
}

/// Reads the preset's queries for a filter, each within its share of `READ_TIME`. A query
/// that cannot be read is kept as unavailable with its reason; only Stop ends the read.
pub fn read(
    preset: &Preset,
    filter: &Filter,
    cancelled: &AtomicBool,
    progress: &Progress,
) -> Result<Loaded, ReadError> {
    let queries = preset.queries(filter);
    let start = Instant::now();
    let count = queries.len().max(1) as u32;
    let mut rows = Vec::new();
    let mut parts = Vec::new();
    for (index, (part, query)) in preset.parts.iter().zip(&queries).enumerate() {
        progress.part.store(index, Ordering::Relaxed);
        // A slow query cannot starve the ones after it of their share.
        let deadline = start + READ_TIME * (index as u32 + 1) / count;
        let outcome = events::read_events_long(query, MESSAGE_CHARS, deadline, cancelled);
        let unavailable = |reason: String| LogRead {
            log: query.logs.join(" and "),
            events: 0,
            unreadable: 0,
            limit: None,
            unavailable: Some(reason),
        };
        let (found, read) = match outcome {
            Ok((found, mut reads)) => {
                let read = reads
                    .pop()
                    .unwrap_or_else(|| unavailable("the event log returned no read".into()));
                (found, read)
            }
            Err(ReadError::Cancelled) => return Err(ReadError::Cancelled),
            Err(ReadError::Invalid(reason) | ReadError::Unavailable(reason)) => {
                (Vec::new(), unavailable(reason))
            }
        };
        parts.push(PartRead {
            label: part.label.clone(),
            oldest: found.iter().map(|event| event.time).min(),
            read,
        });
        rows.extend(
            found
                .into_iter()
                .filter(|event| part.scope.keeps(event))
                .map(|event| Row::new(event, &part.scope)),
        );
        progress.events.store(rows.len(), Ordering::Relaxed);
    }
    rows.sort_by_key(|row| std::cmp::Reverse(row.event.time));
    Ok(Loaded {
        queries,
        rows,
        parts,
    })
}

/// The rows a filter shows, as indexes into `Loaded::rows`, and what was left out.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct View {
    pub rows: Vec<usize>,
    /// Rows the levels and range allow, before the text search.
    pub before_search: usize,
    /// Routine kinds hidden among those.
    pub routine: usize,
}

pub fn view(loaded: &Loaded, filter: &Filter, hide_routine: bool, now: SystemTime) -> View {
    let words: Vec<String> = filter
        .text
        .split_whitespace()
        .map(str::to_lowercase)
        .collect();
    let span = filter.range.span();
    let mut view = View::default();
    for (index, row) in loaded.rows.iter().enumerate() {
        let in_range = now
            .duration_since(row.event.time)
            .map(|age| age <= span)
            .unwrap_or(true);
        if !in_range || !filter.levels[Level::of(row.event.level).index()] {
            continue;
        }
        if hide_routine && row.routine {
            view.routine += 1;
            continue;
        }
        view.before_search += 1;
        if words.iter().all(|word| row.search.contains(word.as_str())) {
            view.rows.push(index);
        }
    }
    view
}

fn plural(count: usize, one: &str, many: &str) -> String {
    if count == 1 {
        format!("1 {one}")
    } else {
        format!("{count} {many}")
    }
}

/// "System and Application logs · critical, error and warning · past 7 days"
pub fn scope_line(preset: &Preset, filter: &Filter) -> String {
    let names: Vec<String> = Level::ALL
        .into_iter()
        .filter(|level| filter.levels[level.index()])
        .map(|level| level.label().to_lowercase())
        .collect();
    let levels = match names.len() {
        0 => "no levels".to_string(),
        4 => "all levels".to_string(),
        1 => names[0].clone(),
        n => format!("{} and {}", names[..n - 1].join(", "), names[n - 1]),
    };
    format!(
        "{}  ·  {levels}  ·  past {}",
        preset.logs(),
        filter.range.label()
    )
}

/// The progress line while a read runs.
pub fn reading_text(preset: &Preset, part: usize, events: usize, seconds: u64) -> String {
    let label = preset
        .parts
        .get(part)
        .map_or("the events", |part| part.label.as_str());
    let of = if preset.parts.len() > 1 {
        format!(" ({} of {})", part + 1, preset.parts.len())
    } else {
        String::new()
    };
    let so_far = if events > 0 {
        format!(", {} so far", plural(events, "event", "events"))
    } else {
        String::new()
    };
    let slow = if seconds >= SLOW_SECONDS {
        "; this is slow, the log is large or the PC is busy"
    } else {
        ""
    };
    format!("Reading {label}{of}{so_far}, {seconds} s{slow}")
}

/// The count line under the filters once a read is done.
pub fn status_text(view: &View, filter: &Filter) -> String {
    let routine = if view.routine > 0 {
        format!(
            "; {} of routine kinds hidden, as in the check",
            plural(view.routine, "event", "events")
        )
    } else {
        String::new()
    };
    let text = filter.text.trim();
    if !text.is_empty() {
        return format!(
            "{} of {} match \"{text}\"{routine}",
            view.rows.len(),
            plural(view.before_search, "event", "events")
        );
    }
    if view.rows.is_empty() {
        return format!(
            "No events at these levels in the past {}{routine}",
            filter.range.label()
        );
    }
    format!("{}{routine}", plural(view.rows.len(), "event", "events"))
}

/// `status_text`, unless no query could be read at all: an unread log is never shown as
/// a log without events.
pub fn summary_text(loaded: &Loaded, view: &View, filter: &Filter) -> String {
    let unread = loaded
        .parts
        .iter()
        .filter(|part| part.read.unavailable.is_some())
        .count();
    if unread > 0 && unread == loaded.parts.len() {
        return "No events could be read; the reason is below".into();
    }
    if unread > 0 && view.rows.is_empty() && filter.text.trim().is_empty() {
        return format!(
            "No events at these levels in the past {} in what could be read",
            filter.range.label()
        );
    }
    status_text(view, filter)
}

fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// What the reader could not read or stopped short of, one sentence per query. Empty
/// when everything in the range was read.
pub fn notes(loaded: &Loaded, range: Range, now: SystemTime) -> Vec<String> {
    let start = now.checked_sub(range.span());
    let mut notes = Vec::new();
    for part in &loaded.parts {
        let label = capitalized(&part.label);
        let read = &part.read;
        if let Some(reason) = &read.unavailable {
            notes.push(format!("{label} could not be read: {reason}."));
            continue;
        }
        // A limit matters only when the events read stop short of the range's start.
        let cut_short = match (part.oldest, start) {
            (Some(oldest), Some(start)) => oldest > start,
            _ => true,
        };
        match read.limit {
            Some(Limit::Count) if cut_short => notes.push(format!(
                "{label}: only the newest {} were read; older ones were not.",
                plural(read.events, "event", "events")
            )),
            Some(Limit::Time) if cut_short => notes.push(format!(
                "{label}: reading stopped at the time limit after {}; older ones were not read.",
                plural(read.events, "event", "events")
            )),
            _ => {}
        }
        if read.unreadable > 0 {
            notes.push(format!(
                "{label}: {} could not be read.",
                plural(read.unreadable, "event", "events")
            ));
        }
    }
    notes
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// "6 Nov 14:03:22", for a list row.
pub fn short_time(stamp: &Stamp) -> String {
    let month = MONTHS
        .get(stamp.month.saturating_sub(1) as usize)
        .unwrap_or(&"");
    format!("{} {month} {}", stamp.day, stamp.time())
}

/// "6 November 2026, 14:03:22 (UTC-06:00)", for the details.
pub fn long_time(stamp: &Stamp) -> String {
    let date = stamp.long();
    let date = date.split(" at ").next().unwrap_or(&date).to_string();
    format!("{date}, {} ({})", stamp.time(), stamp.zone())
}

/// What screen readers announce for a row.
pub fn row_text(row: &Row, stamp: &Stamp) -> String {
    let mut text = format!(
        "{}, {}, {}, event {}",
        events::level_name(row.event.level),
        short_time(stamp),
        row.event.provider,
        row.event.id
    );
    if let Some(kind) = row.kind {
        text.push_str(&format!(", {kind}"));
    }
    text
}

/// The details area's text: the fields, then the message. Lines end in CR LF for the edit.
pub fn details_text(row: &Row, stamp: &Stamp) -> String {
    let event = &row.event;
    let mut lines = vec![
        format!("Level: {}", events::level_name(event.level)),
        format!("Time: {}", long_time(stamp)),
        format!("Source: {}", event.provider),
        format!("Event id: {}", event.id),
        format!("Log: {}", event.log),
    ];
    match events::known(&event.provider, event.id) {
        Some(kind) => lines.push(format!("Kind: {}, {}", kind.short, kind.meaning)),
        None => {
            if let Some(kind) = row.kind {
                lines.push(format!("Kind: {kind}"));
            }
        }
    }
    if row.serious {
        lines.push("Serious: this kind points at a fault.".into());
    }
    lines.push(String::new());
    lines.push(match &event.message {
        Some(message) if !message.trim().is_empty() => message.clone(),
        _ => "No message: this source's message text is not registered or could not be formatted on this PC.".into(),
    });
    lines.join("\r\n")
}

/// A web search for the source and event id. Nothing else goes in the address, and a
/// source that redaction changes (it held a computer or account name) is left out.
pub fn search_url(provider: &str, id: u32, names: &[String]) -> String {
    let clean = events::redact(provider, names);
    let plain = clean == provider.split_whitespace().collect::<Vec<_>>().join(" ")
        && !provider.trim().is_empty();
    let terms = if plain {
        format!("\"{clean}\" event id {id}")
    } else {
        format!("Windows event id {id}")
    };
    format!("{SEARCH_URL}{}", url_encode(&terms))
}

/// Percent-encodes everything but letters, digits and `-._~`; spaces become `+`.
fn url_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Local time of an event, for drawing and details.
pub fn local(event: &Event) -> Stamp {
    clock::local(event.time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    const NOW_SECS: u64 = 1_800_000_000;

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(NOW_SECS)
    }

    fn event(provider: &str, id: u32, level: u8, hours_ago: u64, message: &str) -> Event {
        Event {
            log: "System".into(),
            provider: provider.into(),
            id,
            level,
            time: now() - HOUR * hours_ago as u32,
            message: (!message.is_empty()).then(|| message.into()),
        }
    }

    fn loaded(rows: Vec<Row>) -> Loaded {
        Loaded {
            queries: Vec::new(),
            rows,
            parts: Vec::new(),
        }
    }

    #[test]
    fn every_event_row_has_a_preset_and_other_rows_do_not() {
        for check in [
            "events.recent",
            "events.crashes",
            "services.failures",
            "hardware.events",
        ] {
            let preset = preset(check).unwrap();
            let label = crate::checks::CHECKS
                .iter()
                .find(|spec| spec.id == check)
                .map(|spec| spec.label);
            assert_eq!(Some(preset.title), label, "{check}");
            assert!(!preset.parts.is_empty());
            assert!(!preset.description.is_empty());
        }
        assert!(preset("disk.free").is_none());
    }

    #[test]
    fn presets_use_the_checks_own_queries() {
        let survey = preset("events.recent").unwrap();
        let logs: Vec<_> = survey.parts.iter().map(|p| p.query.logs.clone()).collect();
        assert_eq!(
            logs,
            [vec!["System".to_string()], vec!["Application".into()]]
        );
        for part in &survey.parts {
            let mut whole = Query::survey();
            whole.logs = part.query.logs.clone();
            assert_eq!(format!("{:?}", part.query), format!("{whole:?}"));
        }
        assert!(survey.hide_routine);
        let crashes = preset("events.crashes").unwrap();
        assert_eq!(
            format!("{:?}", crashes.parts[0].query),
            format!("{:?}", events::crash_query())
        );
        let services = preset("services.failures").unwrap();
        assert_eq!(
            format!("{:?}", services.parts[0].query),
            format!("{:?}", events::service_query())
        );
        let hardware = preset("hardware.events").unwrap();
        assert_eq!(hardware.parts.len(), events::HARDWARE.len());
        for (part, category) in hardware.parts.iter().zip(events::HARDWARE) {
            assert_eq!(
                format!("{:?}", part.query),
                format!("{:?}", events::hardware_query(category))
            );
            assert!(events::xpath(&part.query).is_ok());
        }
        assert_eq!(hardware.parts[1].label, "drive error events");
    }

    #[test]
    fn presets_open_at_the_checks_levels_and_range() {
        let survey = preset("events.recent").unwrap();
        assert_eq!(survey.default_levels(), [true, true, true, false]);
        assert_eq!(survey.default_range(), Range::Week);
        for check in ["events.crashes", "services.failures", "hardware.events"] {
            let preset = preset(check).unwrap();
            assert_eq!(preset.default_levels(), [true; 4], "{check}");
            assert_eq!(preset.default_range(), Range::Week, "{check}");
        }
    }

    #[test]
    fn queries_ask_for_messages_the_range_and_extra_levels() {
        let survey = preset("events.recent").unwrap();
        let mut filter = survey.default_filter();
        let queries = survey.queries(&filter);
        assert!(queries.iter().all(|q| q.messages));
        assert!(queries.iter().all(|q| q.levels == [1, 2, 3]));
        assert!(queries.iter().all(|q| q.per_log_limit == 2000));
        // Information was off in the check: turning it on reads it.
        filter.levels[Level::Information.index()] = true;
        let wider = survey.queries(&filter);
        assert!(wider.iter().all(|q| q.levels == [1, 2, 3, 4]));
        assert!(!covers(&queries, &wider));
        assert!(covers(&wider, &queries));
        // A level the check reads, turned off, filters in memory.
        filter.levels = [false, true, true, false];
        assert!(covers(&queries, &survey.queries(&filter)));
        // Shorter ranges filter in memory; a longer one reads again with a larger limit.
        filter.range = Range::Day;
        assert!(covers(&queries, &survey.queries(&filter)));
        filter.range = Range::Month;
        let month = survey.queries(&filter);
        assert!(!covers(&queries, &month));
        assert!(month.iter().all(|q| q.per_log_limit == LONG_RANGE_LIMIT));
        assert!(month.iter().all(|q| q.since == Range::Month.span()));
        assert!(month.iter().all(|q| events::xpath(q).is_ok()));
        // The hardware file system query keeps its own levels.
        let hardware = preset("hardware.events").unwrap();
        let queries = hardware.queries(&hardware.default_filter());
        assert_eq!(queries[2].levels, [1, 2, 3]);
        assert!(queries[0].levels.is_empty());
    }

    #[test]
    fn scopes_keep_only_what_the_check_counts() {
        let hang_as_crash = event("Application Hang", 1000, 2, 1, "");
        assert!(!Scope::Crashes.keeps(&hang_as_crash));
        assert!(Scope::Crashes.keeps(&event("Application Error", 1000, 2, 1, "")));
        assert!(Scope::Crashes.keeps(&event("Application Hang", 1002, 2, 1, "")));
        assert!(Scope::Services.keeps(&event("Service Control Manager", 7031, 2, 1, "")));
        assert!(!Scope::Services.keeps(&event("Service Control Manager", 7036, 4, 1, "")));
        let drive = &events::HARDWARE[1];
        assert!(Scope::Hardware(drive).keeps(&event("disk", 7, 2, 1, "")));
        assert!(!Scope::Hardware(drive).keeps(&event("disk", 129, 3, 1, "")));
        let whea = &events::HARDWARE[0];
        let any = event("Microsoft-Windows-WHEA-Logger", 9999, 3, 1, "");
        assert!(Scope::Hardware(whea).keeps(&any));
        assert_eq!(
            Scope::Hardware(whea).kind(&any),
            (Some("Hardware error"), true)
        );
        assert_eq!(Scope::All.kind(&any), (None, false));
    }

    #[test]
    fn marks_follow_level_and_known_kind() {
        let crit = Row::new(event("Foo", 1, 1, 1, ""), &Scope::All);
        assert_eq!(crit.mark(), Mark::Serious);
        let unclean = Row::new(
            event("Microsoft-Windows-Kernel-Power", 41, 4, 1, ""),
            &Scope::All,
        );
        assert_eq!(unclean.kind, Some("Unexpected restart"));
        assert_eq!(unclean.mark(), Mark::Serious);
        assert_eq!(
            Row::new(event("Foo", 1, 2, 1, ""), &Scope::All).mark(),
            Mark::Warn
        );
        assert_eq!(
            Row::new(event("Foo", 1, 3, 1, ""), &Scope::All).mark(),
            Mark::Warn
        );
        assert_eq!(
            Row::new(event("Foo", 1, 4, 1, ""), &Scope::All).mark(),
            Mark::Muted
        );
        assert_eq!(
            Row::new(event("Foo", 1, 0, 1, ""), &Scope::All).mark(),
            Mark::Muted
        );
    }

    #[test]
    fn the_filter_applies_levels_range_text_and_routine_kinds() {
        let noise = &events::NOISE[0];
        let rows = vec![
            Row::new(
                event("Disk", 7, 2, 1, "The device has a bad block"),
                &Scope::All,
            ),
            Row::new(
                event(
                    "Service Control Manager",
                    7031,
                    2,
                    30,
                    "The Spooler service terminated",
                ),
                &Scope::All,
            ),
            Row::new(event("Foo", 5, 3, 100, ""), &Scope::All),
            Row::new(event("Bar", 6, 4, 2, "all fine"), &Scope::All),
            Row::new(event(noise.provider, noise.id, 3, 1, ""), &Scope::All),
        ];
        let data = loaded(rows);
        let mut filter = Filter {
            levels: [true, true, true, false],
            range: Range::Week,
            text: String::new(),
        };
        let v = view(&data, &filter, true, now());
        assert_eq!(v.rows, [0, 1, 2]);
        assert_eq!(v.routine, 1);
        assert_eq!(view(&data, &filter, false, now()).rows, [0, 1, 2, 4]);
        filter.range = Range::Day;
        assert_eq!(view(&data, &filter, true, now()).rows, [0]);
        filter.range = Range::Week;
        filter.levels = [false, false, true, true];
        assert_eq!(view(&data, &filter, true, now()).rows, [2, 3]);
        filter.levels = [true; 4];
        filter.text = "spooler".into();
        let v = view(&data, &filter, true, now());
        assert_eq!(v.rows, [1]);
        assert_eq!(v.before_search, 4);
        filter.text = "7031".into();
        assert_eq!(view(&data, &filter, true, now()).rows, [1]);
        filter.text = "DISK  block".into();
        assert_eq!(view(&data, &filter, true, now()).rows, [0]);
        filter.text = "disk spooler".into();
        assert!(view(&data, &filter, true, now()).rows.is_empty());
    }

    #[test]
    fn lines_say_what_is_shown_and_what_was_not_read() {
        let survey = preset("events.recent").unwrap();
        let mut filter = survey.default_filter();
        assert_eq!(
            scope_line(&survey, &filter),
            "System and Application logs  ·  critical, error and warning  ·  past 7 days"
        );
        filter.levels = [true; 4];
        filter.range = Range::Day;
        assert_eq!(
            scope_line(&survey, &filter),
            "System and Application logs  ·  all levels  ·  past 24 hours"
        );
        filter.levels = [false, true, false, false];
        assert!(scope_line(&survey, &filter).contains("  ·  error  ·  "));
        let crashes = preset("events.crashes").unwrap();
        assert!(scope_line(&crashes, &filter).starts_with("Application log  ·  "));

        assert_eq!(
            reading_text(&survey, 0, 0, 2),
            "Reading the System log (1 of 2), 2 s"
        );
        assert_eq!(
            reading_text(&crashes, 0, 1, 12),
            "Reading the Application log, 1 event so far, 12 s; this is slow, the log is large or the PC is busy"
        );

        let v = View {
            rows: vec![0, 1],
            before_search: 5,
            routine: 3,
        };
        filter.text = String::new();
        assert_eq!(
            status_text(&v, &filter),
            "2 events; 3 events of routine kinds hidden, as in the check"
        );
        filter.text = " spooler ".into();
        assert!(status_text(&v, &filter).starts_with("2 of 5 events match \"spooler\""));
        filter.text.clear();
        assert_eq!(
            status_text(&View::default(), &filter),
            "No events at these levels in the past 24 hours"
        );
    }

    #[test]
    fn notes_name_unreadable_logs_and_limits_that_cut_into_the_range() {
        let read = |limit, unavailable: Option<&str>, events, unreadable| LogRead {
            log: "System".into(),
            events,
            unreadable,
            limit,
            unavailable: unavailable.map(Into::into),
        };
        let part = |read, oldest_hours: Option<u64>| PartRead {
            label: "the System log".into(),
            read,
            oldest: oldest_hours.map(|h| now() - HOUR * h as u32),
        };
        let data = Loaded {
            queries: Vec::new(),
            rows: Vec::new(),
            parts: vec![
                part(read(None, Some("this account may not read it"), 0, 0), None),
                part(read(Some(Limit::Count), None, 2000, 0), Some(48)),
                part(read(Some(Limit::Time), None, 7, 2), Some(10)),
                part(read(None, None, 7, 0), Some(10)),
            ],
        };
        let notes = notes(&data, Range::Week, now());
        assert_eq!(
            notes,
            [
                "The System log could not be read: this account may not read it.",
                "The System log: only the newest 2000 events were read; older ones were not.",
                "The System log: reading stopped at the time limit after 7 events; older ones were not read.",
                "The System log: 2 events could not be read.",
            ]
        );
        let filter = preset("events.recent").unwrap().default_filter();
        assert_eq!(
            summary_text(&data, &View::default(), &filter),
            "No events at these levels in the past 7 days in what could be read"
        );
        // A count limit reached beyond the range shown does not matter to it.
        let in_memory = Loaded {
            parts: vec![part(read(Some(Limit::Count), None, 5000, 0), Some(500))],
            ..data
        };
        assert!(super::notes(&in_memory, Range::Week, now()).is_empty());
    }

    #[test]
    fn rows_and_details_carry_the_fields_and_message() {
        let stamp = Stamp {
            year: 2026,
            month: 11,
            day: 6,
            hour: 14,
            minute: 3,
            second: 22,
            offset_minutes: -360,
        };
        assert_eq!(short_time(&stamp), "6 Nov 14:03:22");
        assert_eq!(long_time(&stamp), "6 November 2026, 14:03:22 (UTC-06:00)");
        let row = Row::new(
            event(
                "Microsoft-Windows-Kernel-Power",
                41,
                1,
                1,
                "The system has rebooted",
            ),
            &Scope::All,
        );
        assert_eq!(
            row_text(&row, &stamp),
            "critical, 6 Nov 14:03:22, Microsoft-Windows-Kernel-Power, event 41, Unexpected restart"
        );
        let details = details_text(&row, &stamp);
        assert!(details.starts_with("Level: critical\r\nTime: 6 November 2026, 14:03:22"));
        assert!(details.contains(
            "\r\nSource: Microsoft-Windows-Kernel-Power\r\nEvent id: 41\r\nLog: System\r\n"
        ));
        assert!(details.contains("Kind: Unexpected restart, Windows restarted"));
        assert!(details.ends_with("\r\n\r\nThe system has rebooted"));
        let bare = Row::new(event("Foo", 3, 4, 1, ""), &Scope::All);
        assert!(details_text(&bare, &stamp).ends_with("could not be formatted on this PC."));
        assert!(!details_text(&bare, &stamp).contains("Kind:"));
    }

    #[test]
    fn web_searches_carry_only_the_source_and_id() {
        let names = vec!["DESKTOP-ABC123".to_string(), "alex".into()];
        assert_eq!(
            search_url("Service Control Manager", 7031, &names),
            "https://www.google.com/search?q=%22Service+Control+Manager%22+event+id+7031"
        );
        // A source holding a local name is left out, not sent.
        let url = search_url("Backup for DESKTOP-ABC123", 5, &names);
        assert_eq!(url, "https://www.google.com/search?q=Windows+event+id+5");
        assert!(search_url("a&b=c", 1, &names).contains("%22a%26b%3Dc%22"));
        assert!(search_url("", 9, &names).ends_with("Windows+event+id+9"));
    }

    #[test]
    fn long_messages_keep_more_and_are_still_redacted() {
        let names = vec!["DESKTOP-ABC123".to_string()];
        let text = format!(
            "{} sent by user@example.com from DESKTOP-ABC123 at 10.0.0.7",
            "word ".repeat(300)
        );
        let short = events::redact(&text, &names);
        assert_eq!(short.chars().count(), events::EXCERPT_CHARS);
        let long = events::redact_to(&text, &names, MESSAGE_CHARS);
        assert!(long.ends_with("sent by [email] from [name] at [address]"));
        let capped = events::redact_to(&"x ".repeat(5000), &names, MESSAGE_CHARS);
        assert_eq!(capped.chars().count(), MESSAGE_CHARS);
        assert!(capped.ends_with('…'));
    }

    #[test]
    fn reading_a_bad_query_is_unavailable_not_empty() {
        let mut preset = preset("services.failures").unwrap();
        preset.parts[0].query.logs = vec!["No/Such?Log".into()];
        let cancelled = AtomicBool::new(false);
        let loaded = read(
            &preset,
            &preset.default_filter(),
            &cancelled,
            &Progress::default(),
        )
        .unwrap();
        assert!(loaded.rows.is_empty());
        assert!(loaded.parts[0].read.unavailable.is_some());
        assert!(notes(&loaded, Range::Week, SystemTime::now())[0].contains("could not be read"));
        let filter = preset.default_filter();
        let shown = view(&loaded, &filter, false, SystemTime::now());
        assert_eq!(
            summary_text(&loaded, &shown, &filter),
            "No events could be read; the reason is below"
        );
    }

    /// Reads this PC's logs with every preset: each query is read or names why not, and the
    /// rows are newest first, inside the range and of the check's own kinds.
    #[test]
    fn this_pc_reads_every_preset() {
        for check in [
            "events.recent",
            "events.crashes",
            "services.failures",
            "hardware.events",
        ] {
            let preset = preset(check).unwrap();
            let filter = preset.default_filter();
            let started = Instant::now();
            let loaded = read(
                &preset,
                &filter,
                &AtomicBool::new(false),
                &Progress::default(),
            )
            .unwrap();
            let messages = loaded
                .rows
                .iter()
                .filter(|row| row.event.message.is_some())
                .count();
            println!(
                "{check}: {} rows, {messages} with messages, {:?}, {:?}",
                loaded.rows.len(),
                started.elapsed(),
                notes(&loaded, filter.range, SystemTime::now())
            );
            assert_eq!(loaded.parts.len(), preset.parts.len());
            assert!(loaded
                .rows
                .windows(2)
                .all(|w| w[0].event.time >= w[1].event.time));
            for (part, query) in loaded.parts.iter().zip(&loaded.queries) {
                assert!(part.read.unavailable.is_some() || part.read.events <= query.per_log_limit);
            }
            let oldest = SystemTime::now() - filter.range.span() - HOUR;
            assert!(loaded.rows.iter().all(|row| row.event.time >= oldest));
            assert!(loaded.rows.iter().all(|row| row
                .event
                .message
                .as_ref()
                .is_none_or(|m| m.chars().count() <= MESSAGE_CHARS)));
        }
    }

    #[test]
    fn a_cancelled_read_returns_nothing() {
        let preset = preset("services.failures").unwrap();
        let cancelled = AtomicBool::new(true);
        let result = read(
            &preset,
            &preset.default_filter(),
            &cancelled,
            &Progress::default(),
        );
        assert!(matches!(result, Err(ReadError::Cancelled)));
    }
}
