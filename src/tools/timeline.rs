//! What changed and what failed, merged by local day.
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime};

use serde_json::{json, Value};

use super::events::{limit_name, rfc3339};
use super::{Args, Output, Tool};
use crate::clock;
use crate::events::{self, Event, Limit, LogRead, Query, ReadError};

pub const TOOL: Tool = Tool {
    name: "timeline",
    summary: "what changed and what failed, by day: installs, updates, drivers, crashes",
    usage: "\
Usage: toolkit timeline [options]
  --days N   days to cover, 1 to 365 (default 14)
  --all      list each failure instead of one line per kind per day",
    run,
};

const DEADLINE: Duration = Duration::from_secs(30);
const PER_LOG_LIMIT: usize = 2000;
/// Start type changes repeat constantly on some PCs, so they get a small budget.
const START_TYPE_LIMIT: usize = 300;
/// A system time change smaller than this is routine clock correction.
const TIME_STEP_SECS: u64 = 300;
const DETAIL_CHARS: usize = 100;
/// Windows refuses an XPath filter of more than 23 expressions; sources and ids use one
/// each, and levels and the time range use up to four more.
const EXPRESSION_BUDGET: usize = 16;

/// One kind of change or boot event: where it is read and how it reads.
struct Change {
    log: &'static str,
    provider: &'static str,
    id: u32,
    label: &'static str,
    boot: bool,
}

const CHANGES: &[Change] = &[
    change("Application", "MsiInstaller", 11707, "Installed", false),
    change("Application", "MsiInstaller", 11724, "Removed", false),
    change(
        "System",
        "Microsoft-Windows-WindowsUpdateClient",
        19,
        "Update installed",
        false,
    ),
    change(
        "System",
        "Microsoft-Windows-WindowsUpdateClient",
        20,
        "Update failed",
        false,
    ),
    change(
        "Setup",
        "Microsoft-Windows-Servicing",
        2,
        "Package installed",
        false,
    ),
    change(
        "System",
        "Microsoft-Windows-UserPnp",
        20001,
        "Driver installed",
        false,
    ),
    change(
        "System",
        "Service Control Manager",
        7045,
        "Service installed",
        false,
    ),
    change(
        "System",
        "Service Control Manager",
        7040,
        "Service start type changed",
        false,
    ),
    change(
        "System",
        "Microsoft-Windows-Kernel-General",
        1,
        "System time changed",
        false,
    ),
    change("System", "EventLog", 6005, "Boot", true),
    change("System", "EventLog", 6006, "Clean shutdown", true),
    change("System", "EventLog", 6008, "Unexpected shutdown", true),
    change(
        "System",
        "Microsoft-Windows-Kernel-Power",
        41,
        "Unclean restart",
        true,
    ),
];

const fn change(
    log: &'static str,
    provider: &'static str,
    id: u32,
    label: &'static str,
    boot: bool,
) -> Change {
    Change {
        log,
        provider,
        id,
        label,
        boot,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Category {
    Change,
    Failure,
}

#[derive(Clone, Debug, PartialEq)]
struct Entry {
    time: SystemTime,
    category: Category,
    label: String,
    detail: String,
}

fn run(args: &Args) -> Result<Output, String> {
    let days = args.number("--days", 14, 1, 365)?;
    let since = Duration::from_secs(days * 24 * 3600);
    let cancelled = AtomicBool::new(false);
    let deadline = Instant::now() + DEADLINE;
    let mut events = Vec::new();
    let mut reads = Vec::new();
    let mut notes = Vec::new();
    for query in queries(since) {
        match events::read_events(&query, deadline, &cancelled) {
            Ok((found, mut done)) => {
                if query.per_log_limit == START_TYPE_LIMIT {
                    // Its own limit is reported on its own line, not as the log's.
                    for read in &mut done {
                        if let Some(limit) = read.limit.take() {
                            notes.push(start_type_note(&read.log, limit));
                        }
                    }
                }
                events.extend(found);
                reads.extend(done);
            }
            Err(ReadError::Cancelled) => return Err("Canceled".into()),
            Err(ReadError::Invalid(reason)) => return Err(format!("Refused: {reason}")),
            Err(ReadError::Unavailable(reason)) => {
                reads.extend(query.logs.iter().map(|log| LogRead {
                    log: log.clone(),
                    events: 0,
                    unreadable: 0,
                    limit: None,
                    unavailable: Some(reason.clone()),
                }));
            }
        }
    }
    let mut built = build(&events, &reads, days, args.switch("--all"));
    for note in &notes {
        built.text.push('\n');
        built.text.push_str(note);
    }
    built.data["notes"] = json!(notes);
    Ok(Output {
        text: built.text,
        data: built.data,
    })
}

/// A detail without its version number, so definition updates of one product count as
/// the same change.
fn family(detail: &str) -> String {
    match (detail.find(" (Version "), detail.rfind(')')) {
        (Some(start), Some(end)) if end > start => {
            format!("{}{}", &detail[..start], &detail[end + 1..])
        }
        _ => detail.to_string(),
    }
}

fn start_type_note(log: &str, limit: Limit) -> String {
    let why = match limit {
        Limit::Count => format!("the {START_TYPE_LIMIT}-event limit"),
        Limit::Time => "the time limit".into(),
    };
    format!(
        "{log}: service start type changes (event 7040) stopped at {why}, older ones are missing."
    )
}

fn is_chatty(provider: &str, id: u32) -> bool {
    matches!(
        (provider, id),
        ("Microsoft-Windows-Kernel-General", 1) | ("Service Control Manager", 7040)
    )
}

/// Narrow queries: change events per log, then the known failure kinds in batches that
/// fit the engine's source and id limits.
fn queries(since: Duration) -> Vec<Query> {
    let query = |log: &str, providers: Vec<String>, ids: Vec<u32>, levels: Vec<u8>| Query {
        logs: vec![log.into()],
        levels,
        providers,
        ids,
        since,
        include_noise: true,
        per_log_limit: PER_LOG_LIMIT,
        messages: true,
    };
    let mut out = Vec::new();
    for log in ["Application", "System", "Setup"] {
        let mut providers: Vec<String> = Vec::new();
        let mut ids: Vec<u32> = Vec::new();
        for item in CHANGES
            .iter()
            .filter(|item| item.log == log && !is_chatty(item.provider, item.id))
        {
            if !providers.iter().any(|name| name == item.provider) {
                providers.push(item.provider.into());
            }
            if !ids.contains(&item.id) {
                ids.push(item.id);
            }
        }
        out.push(query(log, providers, ids, Vec::new()));
    }
    // These repeat often; their own queries keep them from crowding out the rest.
    for item in CHANGES
        .iter()
        .filter(|item| is_chatty(item.provider, item.id))
    {
        let mut chatty = query(
            item.log,
            vec![item.provider.into()],
            vec![item.id],
            Vec::new(),
        );
        if item.id == 7040 {
            chatty.per_log_limit = START_TYPE_LIMIT;
        }
        out.push(chatty);
    }
    let mut batch: (Vec<String>, Vec<u32>) = (Vec::new(), Vec::new());
    let mut batches = Vec::new();
    for known in events::KNOWN {
        let mut next = batch.clone();
        for provider in known.providers {
            if !next
                .0
                .iter()
                .any(|name| name.eq_ignore_ascii_case(provider))
            {
                next.0.push((*provider).into());
            }
        }
        for id in known.ids {
            if !next.1.contains(id) {
                next.1.push(*id);
            }
        }
        if next.0.len() + next.1.len() > EXPRESSION_BUDGET {
            batches.push(std::mem::take(&mut batch));
            batch = (
                known.providers.iter().map(|p| (*p).into()).collect(),
                known.ids.to_vec(),
            );
        } else {
            batch = next;
        }
    }
    batches.push(batch);
    for (providers, ids) in batches {
        for log in ["System", "Application"] {
            out.push(query(log, providers.clone(), ids.clone(), vec![1, 2, 3]));
        }
    }
    out
}

/// Turns one event into a timeline entry, or drops it when it is neither a wanted change
/// nor a known failure at critical, error or warning level.
fn classify(event: &Event) -> Option<Entry> {
    let message = event.message.as_deref().unwrap_or("");
    if let Some(item) = CHANGES.iter().find(|item| {
        item.id == event.id
            && item.log.eq_ignore_ascii_case(&event.log)
            && item.provider.eq_ignore_ascii_case(&event.provider)
    }) {
        let detail = if item.boot {
            String::new()
        } else if item.id == 1 {
            time_step(message)?
        } else {
            change_detail(item.provider, item.id, message)
        };
        return Some(Entry {
            time: event.time,
            category: Category::Change,
            label: item.label.into(),
            detail,
        });
    }
    if !(1..=3).contains(&event.level) {
        return None;
    }
    let known = events::known(&event.provider, event.id)?;
    Some(Entry {
        time: event.time,
        category: Category::Failure,
        label: known.short.into(),
        detail: failure_detail(&event.provider, event.id, message),
    })
}

fn change_detail(provider: &str, id: u32, message: &str) -> String {
    let named = match (provider, id) {
        ("MsiInstaller", _) => between(message, "Product: ", " -- "),
        ("Microsoft-Windows-WindowsUpdateClient", 19) => after(message, "following update", ": "),
        ("Microsoft-Windows-WindowsUpdateClient", _) => after(message, "following update", ": ")
            .map(|title| match between(message, "with error ", ":") {
                Some(code) if !code.contains(' ') => format!("{title} (error {code})"),
                _ => title,
            }),
        ("Microsoft-Windows-UserPnp", _) => driver(message),
        ("Service Control Manager", 7045) => {
            between(message, "Service Name:", " Service File Name:")
                .or_else(|| after(message, "Service Name:", ""))
        }
        ("Service Control Manager", _) => service_start_type(message),
        _ => None,
    };
    named
        .map(|text| cap(text.trim()))
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| cap(message))
}

fn failure_detail(provider: &str, id: u32, message: &str) -> String {
    let named = if provider.eq_ignore_ascii_case("Application Error") && id == 1000 {
        between(message, "Faulting application name: ", ",")
    } else if provider.eq_ignore_ascii_case("Service Control Manager") {
        between(message, "The ", " service ")
    } else {
        None
    };
    named
        .map(|text| cap(text.trim()))
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| cap(message))
}

/// The text between two markers, the first of each after the start.
fn between(text: &str, start: &str, end: &str) -> Option<String> {
    let from = text.find(start)? + start.len();
    let rest = &text[from..];
    Some(rest[..rest.find(end)?].to_string())
}

/// The text after `end` once `start` has been found; `end` empty means right after `start`.
fn after(text: &str, start: &str, end: &str) -> Option<String> {
    let rest = &text[text.find(start)? + start.len()..];
    let rest = &rest[rest.find(end)? + end.len()..];
    Some(rest.to_string())
}

/// "install driver X for Device Instance ID Y with the following status: 0x0."
fn driver(message: &str) -> Option<String> {
    let name = between(message, "install driver ", " for ")?;
    let device = after(message, "Device Instance ID ", "")
        .map(|rest| rest.split(' ').next().unwrap_or("").to_string())
        .filter(|id| !id.is_empty());
    let status = after(message, "following status: ", "")
        .map(|rest| rest.trim_end_matches('.').to_string())
        .filter(|status| status != "0x0" && !status.is_empty());
    let mut text = match device {
        Some(device) => format!("{name} for {device}"),
        None => name,
    };
    if let Some(status) = status {
        text.push_str(&format!(" (status {status})"));
    }
    Some(text)
}

/// "The start type of the X service was changed from A to B."
fn service_start_type(message: &str) -> Option<String> {
    let name = between(message, "The start type of the ", " service")?;
    let change = after(message, "was changed from ", "")?;
    Some(format!("{name}: {}", change.trim_end_matches('.')))
}

/// "The system time has changed to T1 from T2." as a change only above the step.
fn time_step(message: &str) -> Option<String> {
    let clean: String = message.chars().filter(char::is_ascii).collect();
    let mut stamps = clean
        .split_whitespace()
        .filter_map(|word| clock::parse_utc(word.trim_end_matches('.')));
    let (new, old) = (stamps.next()?, stamps.next()?);
    let (step, forward) = match new.duration_since(old) {
        Ok(step) => (step, true),
        Err(error) => (error.duration(), false),
    };
    if step.as_secs() <= TIME_STEP_SECS {
        return None;
    }
    let span = match step.as_secs() {
        s if s < 3600 => format!("{} minutes", s / 60),
        s if s < 86_400 => format!("{} hours", s / 3600),
        s => format!("{} days", s / 86_400),
    };
    Some(format!(
        "{} by {span}",
        if forward { "forward" } else { "back" }
    ))
}

fn cap(text: &str) -> String {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() > DETAIL_CHARS {
        let mut cut: String = text.chars().take(DETAIL_CHARS).collect();
        cut.push_str("...");
        cut
    } else {
        text
    }
}

/// One timeline line: the text and the fields it was written from.
struct Line {
    time: SystemTime,
    label: String,
    detail: String,
    /// How many entries it stands for, and when the last of them happened.
    count: usize,
    last: SystemTime,
    text: String,
}

impl Line {
    fn json(&self) -> Value {
        json!({
            "time": rfc3339(self.time),
            "label": self.label,
            "detail": self.detail,
            "count": self.count,
            "last_time": rfc3339(self.last),
            "text": self.text,
        })
    }
}

struct Built {
    text: String,
    data: Value,
}

#[cfg(test)]
fn render(events: &[Event], reads: &[LogRead], days: u64, all: bool) -> String {
    build(events, reads, days, all).text
}

fn build(events: &[Event], reads: &[LogRead], days: u64, all: bool) -> Built {
    let mut entries: Vec<Entry> = events.iter().filter_map(classify).collect();
    entries.sort_by_key(|entry| (entry.time, entry.label.clone(), entry.detail.clone()));
    entries.dedup();
    let mut by_day: BTreeMap<(i32, u32, u32), Vec<Entry>> = BTreeMap::new();
    for entry in entries {
        let stamp = clock::local(entry.time);
        by_day
            .entry((stamp.year, stamp.month, stamp.day))
            .or_default()
            .push(entry);
    }
    let mut out = vec![format!(
        "Timeline for the last {days} days, newest day first."
    )];
    if by_day.is_empty() {
        out.push(
            "No changes, boots or known failures were recorded in that time range.".to_string(),
        );
    }
    let mut day_json = Vec::new();
    for ((year, month, day), entries) in by_day.iter().rev() {
        out.push(String::new());
        let date = format!("{year:04}-{month:02}-{day:02}");
        out.push(date.clone());
        let mut lines = day_lines(entries, all);
        lines.sort_by_key(|line| line.time);
        day_json.push(json!({
            "date_local": date,
            "lines": lines.iter().map(Line::json).collect::<Vec<_>>(),
        }));
        out.extend(lines.into_iter().map(|line| line.text));
    }
    out.push(String::new());
    let summaries = log_summaries(reads);
    out.extend(read_lines(&summaries));
    let data = json!({
        "tool": "timeline",
        "days": days,
        "each_failure_listed": all,
        "days_listed": day_json,
        "logs_read": summaries.iter().map(LogSummary::json).collect::<Vec<_>>(),
        "notes": [],
    });
    Built {
        text: out.join("\n"),
        data,
    }
}

fn hhmm(time: SystemTime) -> String {
    let stamp = clock::local(time);
    format!("{:02}:{:02}", stamp.hour, stamp.minute)
}

fn text_line(time: SystemTime, label: &str, detail: &str, count: usize, last: SystemTime) -> Line {
    let text = if detail.is_empty() {
        format!("{}  {label}", hhmm(time))
    } else {
        format!("{}  {label}: {detail}", hhmm(time))
    };
    Line {
        time,
        label: label.into(),
        detail: detail.into(),
        count,
        last,
        text,
    }
}

struct Burst {
    label: String,
    items: usize,
    first: SystemTime,
    last: SystemTime,
    names: Vec<String>,
    members: Vec<SystemTime>,
}

/// More than this many changes of one kind within an hour read as one burst.
const BURST_ITEMS: usize = 5;

/// Runs of more than `BURST_ITEMS` same-kind changes starting within one hour of the
/// run's first change, from entries in time order.
fn bursts(entries: &[&Entry]) -> Vec<Burst> {
    let mut found = Vec::new();
    let mut labels: Vec<&str> = Vec::new();
    for entry in entries {
        if !labels.contains(&entry.label.as_str()) {
            labels.push(&entry.label);
        }
    }
    for label in labels {
        let kind: Vec<&&Entry> = entries.iter().filter(|e| e.label == label).collect();
        let mut start = 0;
        while start < kind.len() {
            let first = kind[start].time;
            let mut end = start;
            while end < kind.len()
                && kind[end].time.duration_since(first).unwrap_or_default()
                    <= Duration::from_secs(3600)
            {
                end += 1;
            }
            if end - start > BURST_ITEMS {
                let run = &kind[start..end];
                let mut names: Vec<String> = Vec::new();
                for entry in run {
                    if names.len() < 3 && !names.contains(&entry.detail) {
                        names.push(entry.detail.clone());
                    }
                }
                found.push(Burst {
                    label: label.into(),
                    items: run.len(),
                    first,
                    last: run[run.len() - 1].time,
                    names,
                    members: run.iter().map(|entry| entry.time).collect(),
                });
                start = end;
            } else {
                start += 1;
            }
        }
    }
    found
}

/// Every change, and failures either one by one or collapsed to one line per kind.
fn day_lines(entries: &[Entry], all: bool) -> Vec<Line> {
    let mut lines = Vec::new();
    let mut kinds: Vec<(&str, Vec<&Entry>)> = Vec::new();
    let mut repeats: Vec<(&Entry, usize, SystemTime)> = Vec::new();
    for entry in entries {
        if all {
            lines.push(text_line(
                entry.time,
                &entry.label,
                &entry.detail,
                1,
                entry.time,
            ));
        } else if entry.category == Category::Change {
            let same = |seen: &&mut (&Entry, usize, SystemTime)| {
                seen.0.label == entry.label && family(&seen.0.detail) == family(&entry.detail)
            };
            match repeats.iter_mut().find(same) {
                Some(seen) if !entry.detail.is_empty() => {
                    seen.1 += 1;
                    seen.2 = entry.time;
                }
                _ => repeats.push((entry, 1, entry.time)),
            }
        } else if let Some((_, group)) = kinds.iter_mut().find(|(label, _)| *label == entry.label) {
            group.push(entry);
        } else {
            kinds.push((&entry.label, vec![entry]));
        }
    }
    let singles: Vec<&Entry> = repeats
        .iter()
        .filter(|(entry, count, _)| *count == 1 && !entry.detail.is_empty())
        .map(|(entry, _, _)| *entry)
        .collect();
    let bursts = bursts(&singles);
    for burst in &bursts {
        let names = burst.names.join(", ");
        let more = burst.items - burst.names.len();
        let mut detail = format!(
            "{} items between {} and {}, including {names}",
            burst.items,
            hhmm(burst.first),
            hhmm(burst.last)
        );
        if more > 0 {
            detail.push_str(&format!(" and {more} more"));
        }
        lines.push(text_line(
            burst.first,
            &burst.label,
            &detail,
            burst.items,
            burst.last,
        ));
    }
    for (entry, count, last) in repeats {
        if bursts.iter().any(|burst| {
            burst.members.contains(&entry.time) && burst.label == entry.label && count == 1
        }) {
            continue;
        }
        if count == 1 {
            lines.push(text_line(
                entry.time,
                &entry.label,
                &entry.detail,
                1,
                entry.time,
            ));
        } else {
            let detail = format!(
                "{}, {count} times between {} and {}",
                family(&entry.detail),
                hhmm(entry.time),
                hhmm(last)
            );
            lines.push(text_line(entry.time, &entry.label, &detail, count, last));
        }
    }
    for (label, group) in kinds {
        let (first, last) = (group[0], group[group.len() - 1]);
        if group.len() == 1 {
            lines.push(text_line(first.time, label, &first.detail, 1, first.time));
            continue;
        }
        let mut names: Vec<&str> = Vec::new();
        for entry in &group {
            if !entry.detail.is_empty() && !names.contains(&entry.detail.as_str()) {
                names.push(&entry.detail);
            }
        }
        let shown = names.iter().take(3).copied().collect::<Vec<_>>().join(", ");
        let more = names.len().saturating_sub(3);
        let mut detail = format!("{} times", group.len());
        if !shown.is_empty() {
            detail.push_str(&format!(", {shown}"));
        }
        if more > 0 {
            detail.push_str(&format!(" and {more} more"));
        }
        detail.push_str(&format!(" (last at {})", hhmm(last.time)));
        lines.push(text_line(
            first.time,
            label,
            &detail,
            group.len(),
            last.time,
        ));
    }
    lines
}

/// One log's reads added up.
struct LogSummary {
    log: String,
    events: usize,
    unreadable: usize,
    reads: usize,
    /// How many reads were unavailable, and the first reason.
    failed: usize,
    reason: Option<String>,
    count_limit: bool,
    time_limit: bool,
}

impl LogSummary {
    fn json(&self) -> Value {
        let limits: Vec<&str> = [
            self.count_limit.then(|| limit_name(Limit::Count)),
            self.time_limit.then(|| limit_name(Limit::Time)),
        ]
        .into_iter()
        .flatten()
        .collect();
        json!({
            "log": self.log,
            "events_read": self.events,
            "unreadable": self.unreadable,
            "reads": self.reads,
            "unavailable_reads": self.failed,
            "unavailable": self.reason,
            "stopped_at_limit": limits,
            "event_limit": PER_LOG_LIMIT,
        })
    }
}

fn log_summaries(reads: &[LogRead]) -> Vec<LogSummary> {
    let mut logs: Vec<&str> = Vec::new();
    for read in reads {
        if !logs.contains(&read.log.as_str()) {
            logs.push(&read.log);
        }
    }
    logs.into_iter()
        .map(|log| {
            let parts: Vec<&LogRead> = reads.iter().filter(|read| read.log == log).collect();
            let failed: Vec<&str> = parts
                .iter()
                .filter_map(|read| read.unavailable.as_deref())
                .collect();
            LogSummary {
                log: log.into(),
                events: parts.iter().map(|read| read.events).sum(),
                unreadable: parts.iter().map(|read| read.unreadable).sum(),
                reads: parts.len(),
                failed: failed.len(),
                reason: failed.first().map(|reason| (*reason).into()),
                count_limit: parts.iter().any(|read| read.limit == Some(Limit::Count)),
                time_limit: parts.iter().any(|read| read.limit == Some(Limit::Time)),
            }
        })
        .collect()
}

/// One line per log, adding up the queries that read it.
fn read_lines(summaries: &[LogSummary]) -> Vec<String> {
    if summaries.is_empty() {
        return vec!["No log was read.".into()];
    }
    summaries
        .iter()
        .map(|summary| {
            let (log, events) = (&summary.log, summary.events);
            let mut text = format!("{log}: {events} events read");
            if let Some(reason) = &summary.reason {
                text = format!(
                    "{log}: unavailable in {} of {} reads ({reason}); {events} events read from the rest",
                    summary.failed, summary.reads
                );
            }
            if summary.count_limit {
                text.push_str(&format!(
                    "; stopped at the {PER_LOG_LIMIT}-event limit, older events are missing"
                ));
            }
            if summary.time_limit {
                text.push_str("; stopped at the time limit, older events are missing");
            }
            if summary.unreadable > 0 {
                text.push_str(&format!("; {} could not be rendered", summary.unreadable));
            }
            text.push('.');
            text
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(ymd: (i32, u32, u32), hm: (u32, u32)) -> SystemTime {
        // Local wall time to an instant, using the zone offset at that moment.
        let guess = clock::parse_utc(&format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:00Z",
            ymd.0, ymd.1, ymd.2, hm.0, hm.1
        ))
        .unwrap();
        let offset = i64::from(clock::local(guess).offset_minutes) * 60;
        if offset >= 0 {
            guess - Duration::from_secs(offset as u64)
        } else {
            guess + Duration::from_secs(offset.unsigned_abs())
        }
    }

    fn event(
        log: &str,
        provider: &str,
        id: u32,
        level: u8,
        time: SystemTime,
        message: &str,
    ) -> Event {
        Event {
            log: log.into(),
            provider: provider.into(),
            id,
            level,
            time,
            message: Some(message.into()),
        }
    }

    fn detail_of(provider: &str, id: u32, message: &str) -> String {
        let log = if provider == "MsiInstaller" {
            "Application"
        } else {
            "System"
        };
        classify(&event(log, provider, id, 4, SystemTime::now(), message))
            .unwrap()
            .detail
    }

    #[test]
    fn msi_product_is_named() {
        let text = "Product: Example Tool 2.1 -- Installation completed successfully.";
        assert_eq!(detail_of("MsiInstaller", 11707, text), "Example Tool 2.1");
        let text = "Product: Example Tool 2.1 -- Removal completed successfully.";
        assert_eq!(detail_of("MsiInstaller", 11724, text), "Example Tool 2.1");
    }

    #[test]
    fn update_title_is_named() {
        let provider = "Microsoft-Windows-WindowsUpdateClient";
        let ok = "Installation Successful: Windows successfully installed the following update: 2026-10 Cumulative Update (KB5099999)";
        assert_eq!(
            detail_of(provider, 19, ok),
            "2026-10 Cumulative Update (KB5099999)"
        );
        let bad = "Installation Failure: Windows failed to install the following update with error 0x80070643: 2026-10 Cumulative Update (KB5099999)";
        assert_eq!(
            detail_of(provider, 20, bad),
            "2026-10 Cumulative Update (KB5099999) (error 0x80070643)"
        );
    }

    #[test]
    fn driver_is_named() {
        let text = "Driver Management concluded the process to install driver oem42.inf for Device Instance ID PCI\\VEN_10DE&DEV_2705 with the following status: 0x0.";
        assert_eq!(
            detail_of("Microsoft-Windows-UserPnp", 20001, text),
            "oem42.inf for PCI\\VEN_10DE&DEV_2705"
        );
        let text = text.replace("0x0", "0x2");
        assert!(detail_of("Microsoft-Windows-UserPnp", 20001, &text).ends_with("(status 0x2)"));
    }

    #[test]
    fn services_are_named() {
        let new = "A service was installed in the system. Service Name: ExampleSvc Service File Name: C:\\Program Files\\Example\\svc.exe Service Type: user mode service";
        assert_eq!(
            detail_of("Service Control Manager", 7045, new),
            "ExampleSvc"
        );
        let start = "The start type of the Example Updater service was changed from demand start to disabled.";
        assert_eq!(
            detail_of("Service Control Manager", 7040, start),
            "Example Updater: demand start to disabled"
        );
    }

    #[test]
    fn failures_are_named_with_fallback() {
        let crash = event(
            "Application",
            "Application Error",
            1000,
            2,
            SystemTime::now(),
            "Faulting application name: example.exe, version: 1.0.0.0, time stamp: 0x1",
        );
        let entry = classify(&crash).unwrap();
        assert_eq!(
            (entry.label.as_str(), entry.detail.as_str()),
            ("App crash", "example.exe")
        );
        let service = event(
            "System",
            "Service Control Manager",
            7034,
            2,
            SystemTime::now(),
            "The Example Helper service terminated unexpectedly. It has done this 1 time(s).",
        );
        assert_eq!(classify(&service).unwrap().detail, "Example Helper");
        let long = event("System", "disk", 7, 2, SystemTime::now(), &"x".repeat(300));
        assert_eq!(classify(&long).unwrap().detail.chars().count(), 103);
        let none = event("System", "disk", 7, 2, SystemTime::now(), "");
        assert_eq!(classify(&none).unwrap().detail, "");
    }

    #[test]
    fn unknown_and_informational_events_are_dropped() {
        let now = SystemTime::now();
        assert!(classify(&event("System", "Nothing", 1, 2, now, "x")).is_none());
        assert!(classify(&event("System", "disk", 7, 4, now, "x")).is_none());
    }

    #[test]
    fn small_time_changes_are_skipped() {
        let provider = "Microsoft-Windows-Kernel-General";
        let small = event(
            "System",
            provider,
            1,
            4,
            SystemTime::now(),
            "The system time has changed to 2026-11-04T12:00:30.000000000Z from 2026-11-04T12:00:00.000000000Z.",
        );
        assert!(classify(&small).is_none());
        let big = event(
            "System",
            provider,
            1,
            4,
            SystemTime::now(),
            "The system time has changed to 2026-11-04T14:00:00.000000000Z from 2026-11-04T12:00:00.000000000Z.",
        );
        assert_eq!(classify(&big).unwrap().detail, "forward by 2 hours");
        let odd = event("System", provider, 1, 4, SystemTime::now(), "garbled");
        assert!(classify(&odd).is_none());
    }

    #[test]
    fn failures_collapse_by_kind_and_all_lists_each() {
        let day = (2026, 11, 3);
        let crash = |hm, name: &str| {
            event(
                "Application",
                "Application Error",
                1000,
                2,
                at(day, hm),
                &format!("Faulting application name: {name}, version: 1"),
            )
        };
        let events = vec![
            crash((9, 5), "a.exe"),
            crash((10, 5), "b.exe"),
            crash((11, 5), "a.exe"),
            event(
                "Application",
                "MsiInstaller",
                11707,
                4,
                at(day, (9, 30)),
                "Product: Thing -- Installation completed successfully.",
            ),
        ];
        let text = render(&events, &[], 14, false);
        assert!(text.contains("09:05  App crash: 3 times, a.exe, b.exe (last at 11:05)"));
        assert!(text.contains("09:30  Installed: Thing"));
        let text = render(&events, &[], 14, true);
        assert!(text.contains("09:05  App crash: a.exe"));
        assert!(text.contains("10:05  App crash: b.exe"));
        assert!(text.contains("11:05  App crash: a.exe"));
        assert!(!text.contains("times"));
    }

    #[test]
    fn repeated_changes_collapse_unless_all() {
        let day = (2026, 11, 3);
        let toggle = |hm, text: &str| {
            event(
                "System",
                "Service Control Manager",
                7040,
                4,
                at(day, hm),
                &format!("The start type of the Bits service was changed from {text}."),
            )
        };
        let mut events = vec![
            toggle((9, 0), "auto start to demand start"),
            toggle((9, 6), "demand start to auto start"),
            toggle((9, 30), "auto start to demand start"),
            toggle((10, 0), "auto start to demand start"),
        ];
        events.push(event("System", "EventLog", 6005, 4, at(day, (8, 0)), ""));
        events.push(event("System", "EventLog", 6005, 4, at(day, (8, 5)), ""));
        let text = render(&events, &[], 14, false);
        assert!(text.contains("09:00  Service start type changed: Bits: auto start to demand start, 3 times between 09:00 and 10:00"));
        assert!(
            text.contains("09:06  Service start type changed: Bits: demand start to auto start\n")
        );
        assert_eq!(text.matches("Boot").count(), 2);
        let text = render(&events, &[], 14, true);
        assert_eq!(text.matches("auto start to demand start").count(), 3);
        assert!(!text.contains("times between"));
    }

    #[test]
    fn versions_do_not_split_repeated_updates() {
        let update = |hm, version: &str| {
            event(
                "System",
                "Microsoft-Windows-WindowsUpdateClient",
                19,
                4,
                at((2026, 11, 3), hm),
                &format!(
                    "Installation Successful: Windows successfully installed the following update: Defender Update - KB1 (Version {version}) - Current"
                ),
            )
        };
        let events = [update((1, 0), "1.1"), update((13, 0), "1.2")];
        let text = render(&events, &[], 14, false);
        assert!(text.contains(
            "01:00  Update installed: Defender Update - KB1 - Current, 2 times between 01:00 and 13:00"
        ), "{text}");
    }

    #[test]
    fn bursts_of_one_kind_become_one_line() {
        let day = (2026, 11, 3);
        let install = |hm: (u32, u32), name: &str| {
            event(
                "Application",
                "MsiInstaller",
                11707,
                4,
                at(day, hm),
                &format!("Product: {name} -- Installation completed successfully."),
            )
        };
        let mut events: Vec<Event> = (0..8)
            .map(|n| install((9, n), &format!("Pkg{n}")))
            .collect();
        events.extend((0..5).map(|n| install((14, n), &format!("Few{n}"))));
        let text = render(&events, &[], 14, false);
        assert!(text.contains(
            "09:00  Installed: 8 items between 09:00 and 09:07, including Pkg0, Pkg1, Pkg2 and 5 more"
        ), "{text}");
        assert!(text.contains("14:00  Installed: Few0"));
        assert!(text.contains("14:04  Installed: Few4"));
        let text = render(&events, &[], 14, true);
        assert!(!text.contains("items between"));
        assert!(text.contains("09:07  Installed: Pkg7"));
    }

    #[test]
    fn start_type_query_has_its_own_small_limit() {
        let all = queries(Duration::from_secs(86_400));
        let small: Vec<_> = all
            .iter()
            .filter(|query| query.per_log_limit == START_TYPE_LIMIT)
            .collect();
        assert_eq!(small.len(), 1);
        assert_eq!(small[0].ids, vec![7040]);
        assert!(all.iter().filter(|q| q.ids.contains(&7040)).count() == 1);
        assert!(start_type_note("System", Limit::Count).contains("300-event limit"));
    }

    #[test]
    fn days_split_at_local_midnight_newest_first() {
        let boot = |day, hm| event("System", "EventLog", 6005, 4, at(day, hm), "");
        let events = vec![
            boot((2026, 11, 3), (23, 59)),
            boot((2026, 11, 4), (0, 1)),
            boot((2026, 11, 3), (8, 0)),
        ];
        let text = render(&events, &[], 14, false);
        let first = text.find("2026-11-04").unwrap();
        let second = text.find("2026-11-03").unwrap();
        assert!(first < second);
        let tail = &text[second..];
        assert!(tail.find("08:00  Boot").unwrap() < tail.find("23:59  Boot").unwrap());
        assert!(text[first..second].contains("00:01  Boot"));
    }

    #[test]
    fn empty_input_says_so() {
        let reads = [LogRead {
            log: "System".into(),
            events: 0,
            unreadable: 0,
            limit: None,
            unavailable: None,
        }];
        let text = render(&[], &reads, 14, false);
        assert!(text.contains("No changes, boots or known failures"));
        assert!(text.contains("System: 0 events read."));
        assert!(render(&[], &[], 14, false).contains("No log was read."));
    }

    #[test]
    fn unreadable_and_limited_logs_are_stated() {
        let read = |log: &str, events, limit, unavailable: Option<&str>| LogRead {
            log: log.into(),
            events,
            unreadable: 0,
            limit,
            unavailable: unavailable.map(Into::into),
        };
        let lines = read_lines(&log_summaries(&[
            read("System", 2000, Some(Limit::Count), None),
            read("System", 5, None, None),
            read("Setup", 0, None, Some("the log could not be opened")),
        ]));
        assert_eq!(
            lines[0],
            "System: 2005 events read; stopped at the 2000-event limit, older events are missing."
        );
        assert!(lines[1]
            .starts_with("Setup: unavailable in 1 of 1 reads (the log could not be opened)"));
    }

    #[test]
    fn queries_respect_engine_limits() {
        for query in queries(Duration::from_secs(86_400)) {
            assert!(events::xpath(&query).is_ok(), "{query:?}");
            let filter = events::xpath(&query).unwrap();
            assert!(filter.matches(" and ").count() + filter.matches(" or ").count() < 22);
        }
    }

    #[test]
    fn json_lines_agree_with_the_text() {
        let day = (2026, 11, 3);
        let crash = |hm, name: &str| {
            event(
                "Application",
                "Application Error",
                1000,
                2,
                at(day, hm),
                &format!("Faulting application name: {name}, version: 1"),
            )
        };
        let events = vec![crash((9, 5), "a.exe"), crash((11, 5), "b.exe")];
        let reads = [LogRead {
            log: "Application".into(),
            events: 2000,
            unreadable: 0,
            limit: Some(Limit::Count),
            unavailable: None,
        }];
        let built = build(&events, &reads, 14, false);
        let line = &built.data["days_listed"][0]["lines"][0];
        assert_eq!(line["label"], "App crash");
        assert_eq!(line["count"], 2);
        assert_eq!(line["time"], rfc3339(at(day, (9, 5))));
        assert_eq!(line["last_time"], rfc3339(at(day, (11, 5))));
        assert!(built.text.contains(line["text"].as_str().unwrap()));
        assert!(built
            .text
            .contains("09:05  App crash: 2 times, a.exe, b.exe"));
        let read = &built.data["logs_read"][0];
        assert_eq!(read["stopped_at_limit"][0], "event_count");
        assert!(built.text.contains("stopped at the 2000-event limit"));
        let empty = build(&[], &[], 14, false);
        assert_eq!(empty.data["days_listed"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn a_year_of_queries_stays_within_the_engine_limits() {
        for query in queries(Duration::from_secs(365 * 86_400)) {
            let filter = events::xpath(&query).unwrap();
            assert!(filter.matches(" and ").count() + filter.matches(" or ").count() < 22);
        }
        let args = Args::parse(&["--days".into(), "365".into()], TOOL.usage).unwrap();
        assert_eq!(args.number("--days", 14, 1, 365), Ok(365));
        assert!(Args::parse(&["--days".into(), "366".into()], TOOL.usage)
            .unwrap()
            .number("--days", 14, 1, 365)
            .is_err());
    }

    #[test]
    fn live_run_finishes() {
        let started = Instant::now();
        let args = Args::parse(&["--days".into(), "3".into()], TOOL.usage).unwrap();
        let output = (TOOL.run)(&args).unwrap();
        assert!(output.text.contains("Timeline for the last 3 days"));
        assert!(output.text.contains("events read") || output.text.contains("unavailable"));
        assert!(started.elapsed() < Duration::from_secs(15));
        let json =
            crate::tools::run("timeline", &["--days".into(), "1".into(), "--json".into()]).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["tool"], "timeline");
        assert!(parsed["logs_read"].is_array());
    }
}
