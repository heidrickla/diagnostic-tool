//! Windows Update state: when it last searched and installed, what it installed or failed
//! to install in a range of days, a pending restart, the two services it depends on, and
//! the Windows Update client's own error events. Read-only.
mod sys;

use std::time::{Duration, Instant, SystemTime};

use serde_json::{json, Value};

use super::hash::rfc3339;
use super::{Args, Output, Tool};
use crate::clock;
use crate::events::{self, Event};

pub const TOOL: Tool = Tool {
    name: "updates",
    summary: "Windows Update: last search and install, history, failures, pending restart",
    usage: "\
Usage: toolkit updates [--days N]
  --days N   time range for the history and events (default 30, 1 to 365)

Prints when Windows Update last searched for and installed updates, the updates installed
and the failures in the range (title, KB number, date, result, error code with its
meaning), whether a restart is pending, the state of the Windows Update and Background
Intelligent Transfer services, and the client's events 20, 25, 31 and 34 in the range.
Finishes within 30 seconds.",
    run,
};

const TIME_LIMIT: Duration = Duration::from_secs(28);
const INSTALL_LIMIT: usize = 25;
const FAILURE_LIMIT: usize = 25;
const EVENT_LIMIT: usize = 15;
/// The newest history entries the script returns.
pub const HISTORY_FETCH: usize = 400;
/// The client events asked for.
pub const EVENT_IDS: [u32; 4] = [20, 25, 31, 34];
pub const EVENT_LOG: &str = "Microsoft-Windows-WindowsUpdateClient/Operational";

/// One row of the update history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub time: SystemTime,
    /// 1 install, 2 uninstall, anything else is another operation.
    pub operation: u8,
    /// 0 not started, 1 in progress, 2 succeeded, 3 succeeded with errors, 4 failed, 5 aborted.
    pub result: u8,
    pub hresult: u32,
    pub title: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct History {
    /// Every entry Windows Update holds.
    pub total: usize,
    /// The newest ones, newest first.
    pub entries: Vec<Entry>,
}

/// The fixed script's whole output, parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptReading {
    pub search: Result<Option<SystemTime>, String>,
    pub install: Result<Option<SystemTime>, String>,
    pub history: History,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sign {
    Set,
    NotSet,
    Unreadable(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebootSign {
    pub label: &'static str,
    pub sign: Sign,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Service {
    pub display: &'static str,
    pub name: &'static str,
    /// State word and start type word, or why neither was read.
    pub reading: Result<(String, String), String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ClientEvents {
    pub events: Vec<Event>,
    /// The read stopped at the event count or the time limit.
    pub cut_short: bool,
}

pub struct Gathered {
    pub days: u64,
    pub now: SystemTime,
    pub script: Result<ScriptReading, String>,
    pub reboot: Vec<RebootSign>,
    pub services: Vec<Service>,
    pub events: Result<ClientEvents, String>,
}

fn run(args: &Args) -> Result<Output, String> {
    let days = args.number("--days", 30, 1, 365)?;
    let gathered = sys::gather(days, Instant::now() + TIME_LIMIT);
    Ok(Output {
        text: render(&gathered),
        data: to_json(&gathered),
    })
}

/// The fixed script's output: `COUNT`, `R` and `H` lines, tab separated. Anything else is
/// refused rather than guessed at.
pub fn parse_script(output: &str) -> Result<ScriptReading, String> {
    const BAD: &str = "Windows Update returned output this tool does not understand";
    let mut total = None;
    let mut search = Err("not reported".to_string());
    let mut install = Err("not reported".to_string());
    let mut entries = Vec::new();
    let mut seen_results = 0;
    for line in output.lines().filter(|l| !l.trim().is_empty()) {
        let fields: Vec<&str> = line.trim_end_matches('\r').split('\t').collect();
        match fields.as_slice() {
            ["ERROR", message] => {
                return Err(format!(
                    "the Windows Update service reported: {}",
                    events::redact(message, &events::local_names())
                ))
            }
            ["COUNT", count] if total.is_none() => {
                total = Some(count.parse::<usize>().map_err(|_| BAD.to_string())?);
            }
            ["R", which, value] if matches!(*which, "search" | "install") => {
                let reading = match *value {
                    "none" => Ok(None),
                    text => Ok(Some(parse_iso(text).ok_or(BAD)?)),
                };
                seen_results += 1;
                if *which == "search" {
                    search = reading;
                } else {
                    install = reading;
                }
            }
            ["RERR", which, message] if matches!(*which, "search" | "install") => {
                let reading = Err(events::redact(message, &events::local_names()));
                seen_results += 1;
                if *which == "search" {
                    search = reading;
                } else {
                    install = reading;
                }
            }
            ["H", time, operation, result, hresult, title] => {
                if hresult.len() != 8 {
                    return Err(BAD.into());
                }
                entries.push(Entry {
                    time: parse_iso(time).ok_or(BAD)?,
                    operation: operation.parse().map_err(|_| BAD.to_string())?,
                    result: result.parse().map_err(|_| BAD.to_string())?,
                    hresult: u32::from_str_radix(hresult, 16).map_err(|_| BAD.to_string())?,
                    title: title.trim().to_string(),
                });
            }
            _ => return Err(BAD.into()),
        }
    }
    let total = total.ok_or(BAD)?;
    if seen_results != 2 || entries.len() > total || entries.len() > HISTORY_FETCH {
        return Err(BAD.into());
    }
    Ok(ScriptReading {
        search,
        install,
        history: History { total, entries },
    })
}

/// `YYYY-MM-DDTHH:MM:SS` in UTC, as the script writes it.
fn parse_iso(text: &str) -> Option<SystemTime> {
    if text.len() != 19 {
        return None;
    }
    clock::parse_utc(&format!("{text}Z"))
}

/// A KB number in an update title, like `KB5044284`.
pub fn kb_of(title: &str) -> Option<String> {
    let mut rest = title;
    while let Some(index) = rest.find("KB") {
        let digits: String = rest[index + 2..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if (5..=8).contains(&digits.len()) {
            return Some(format!("KB{digits}"));
        }
        rest = &rest[index + 2..];
    }
    None
}

/// Antivirus definition updates arrive several times a day and are counted, not listed.
pub fn is_definition_update(title: &str) -> bool {
    let lower = title.to_ascii_lowercase();
    lower.contains("security intelligence update") || lower.contains("definition update")
}

pub fn result_word(result: u8) -> &'static str {
    match result {
        0 => "not started",
        1 => "in progress",
        2 => "succeeded",
        3 => "succeeded with errors",
        4 => "failed",
        5 => "aborted",
        _ => "unknown result",
    }
}

/// What a Windows Update or servicing error code means, for the codes seen in practice.
pub fn hresult_meaning(code: u32) -> Option<&'static str> {
    Some(match code {
        0x8000_4005 => "unspecified error",
        0x8007_0002 => "a file was not found",
        0x8007_0003 => "a path was not found",
        0x8007_0005 => "access denied",
        0x8007_000D => "data is invalid",
        0x8007_0020 => "a file is in use by another process",
        0x8007_0070 => "the disk is full",
        0x8007_0422 => "the Windows Update service is disabled",
        0x8007_0490 => "an element was not found (damaged servicing store)",
        0x8007_0643 => "fatal error during installation",
        0x8007_06BE => "the remote procedure call failed",
        0x8007_0BC9 => "a restart is required to finish a previous change",
        0x8007_2EE2 => "the connection to the update server timed out",
        0x8007_2EFD => "cannot connect to the update server",
        0x8007_371B => "a servicing transaction could not complete",
        0x8007_3701 => "a component's files are missing from the component store",
        0x8007_3712 => "a component store file is missing or damaged",
        0x8007_3D02 => "a file the update needs is in use",
        0x800F_081F => "the source files could not be found",
        0x800F_0831 => "a prerequisite update is missing",
        0x800F_0900 => "servicing error while processing a package",
        0x800F_0922 => "the update could not be installed (servicing or too little space on the system partition)",
        0x8024_000B => "the operation was canceled",
        0x8024_0016 => "another installation is already in progress",
        0x8024_0017 => "the update is not applicable to this PC",
        0x8024_001E => "the service is shutting down",
        0x8024_0022 => "every update in the batch failed",
        0x8024_0034 => "the download failed",
        0x8024_4022 => "the update server answered that it is unavailable (HTTP 503)",
        0x8024_402C => "the proxy or server name could not be resolved",
        0x8024_A105 => "Automatic Updates reported an error",
        0x8024_8007 => "the update information is missing from the Windows Update data store",
        0x8024_6007 => "the update was not downloaded",
        0xC190_0101 => "a driver caused an error during the upgrade",
        _ => return None,
    })
}

pub fn hex(code: u32) -> String {
    format!("0x{code:08X}")
}

/// Whether a range is covered and what the history says about it.
#[derive(Debug)]
pub struct Summary<'a> {
    pub installed: Vec<&'a Entry>,
    pub definitions: usize,
    pub uninstalled: Vec<&'a Entry>,
    pub failures: Vec<&'a Entry>,
    /// The fetched entries do not reach back to the start of the range.
    pub truncated: bool,
}

pub fn summarize(history: &History, now: SystemTime, days: u64) -> Summary<'_> {
    let start = now - Duration::from_secs(days * 86_400);
    let mut summary = Summary {
        installed: Vec::new(),
        definitions: 0,
        uninstalled: Vec::new(),
        failures: Vec::new(),
        truncated: false,
    };
    if let Some(oldest) = history.entries.last() {
        summary.truncated = history.entries.len() < history.total && oldest.time > start;
    }
    for entry in history.entries.iter().filter(|e| e.time >= start) {
        match (entry.operation, entry.result) {
            (_, 4 | 5) => summary.failures.push(entry),
            (1, 2 | 3) if is_definition_update(&entry.title) => summary.definitions += 1,
            (1, 2 | 3) => summary.installed.push(entry),
            (2, 2 | 3) => summary.uninstalled.push(entry),
            _ => {}
        }
    }
    summary
}

/// What the start type and state mean for updating, when it is worth saying.
pub fn service_note(state: &str, start: &str) -> Option<&'static str> {
    match (start, state) {
        ("disabled", _) => Some("disabled, so this service cannot run"),
        ("manual", "stopped") => Some("Windows starts it when it is needed"),
        ("automatic", "stopped") => Some("an automatic service that is not running"),
        _ => None,
    }
}

fn when(time: SystemTime) -> String {
    clock::local(time).long()
}

fn reading_line(label: &str, reading: &Result<Option<SystemTime>, String>) -> String {
    match reading {
        Ok(Some(time)) => format!("{label}: {}", when(*time)),
        Ok(None) => format!("{label}: never recorded"),
        Err(reason) => format!("{label}: unavailable, {reason}"),
    }
}

/// Entries with the same operation, title, result and error, newest first, with how many.
fn grouped<'a>(entries: &[&'a Entry]) -> Vec<(&'a Entry, usize)> {
    let mut groups: Vec<(&'a Entry, usize)> = Vec::new();
    for entry in entries {
        let same = |g: &(&Entry, usize)| {
            (g.0.operation, g.0.result, g.0.hresult, &g.0.title)
                == (entry.operation, entry.result, entry.hresult, &entry.title)
        };
        match groups.iter_mut().find(|g| same(g)) {
            Some(group) => group.1 += 1,
            None => groups.push((entry, 1)),
        }
    }
    groups
}

fn entry_line(entry: &Entry, times: usize, with_error: bool) -> String {
    let kb = kb_of(&entry.title)
        .map(|kb| format!("{kb} "))
        .unwrap_or_default();
    let mut line = format!("  {} {kb}{}", clock::local(entry.time).long(), entry.title);
    if times > 1 {
        line.push_str(&format!(" ({times} times, newest shown)"));
    }
    line.push_str(&format!(", {}", result_word(entry.result)));
    if with_error && entry.hresult != 0 {
        line.push_str(&format!(", error {}", hex(entry.hresult)));
        match hresult_meaning(entry.hresult) {
            Some(meaning) => line.push_str(&format!(" ({meaning})")),
            None => line.push_str(" (meaning not known to this tool)"),
        }
    }
    line
}

fn event_text(event: &Event) -> String {
    let known = events::known("Microsoft-Windows-WindowsUpdateClient", event.id)
        .map(|k| format!(" {}", k.short))
        .unwrap_or_default();
    format!(
        "  {} event {}{}: {}",
        clock::local(event.time).long(),
        event.id,
        known,
        event.message.as_deref().unwrap_or("no message")
    )
}

pub fn render(gathered: &Gathered) -> String {
    let mut lines = vec![format!("Windows Update, last {} days", gathered.days)];
    match &gathered.script {
        Ok(script) => {
            lines.push(reading_line(
                "Last successful search for updates",
                &script.search,
            ));
            lines.push(reading_line("Last successful install", &script.install));
            let summary = summarize(&script.history, gathered.now, gathered.days);
            lines.push(format!(
                "Updates installed in the range: {}{}",
                summary.installed.len(),
                if summary.definitions > 0 {
                    format!(
                        " (and {} antivirus definition updates)",
                        summary.definitions
                    )
                } else {
                    String::new()
                }
            ));
            for (entry, times) in grouped(&summary.installed).into_iter().take(INSTALL_LIMIT) {
                lines.push(entry_line(entry, times, true));
            }
            if grouped(&summary.installed).len() > INSTALL_LIMIT {
                lines.push(format!(
                    "  ... {} more not listed",
                    grouped(&summary.installed).len() - INSTALL_LIMIT
                ));
            }
            if !summary.uninstalled.is_empty() {
                lines.push(format!(
                    "Updates uninstalled in the range: {}",
                    summary.uninstalled.len()
                ));
                for (entry, times) in grouped(&summary.uninstalled)
                    .into_iter()
                    .take(INSTALL_LIMIT)
                {
                    lines.push(entry_line(entry, times, false));
                }
            }
            if summary.failures.is_empty() {
                lines.push("Failures in the range: none in the history".into());
            } else {
                lines.push(format!("Failures in the range: {}", summary.failures.len()));
                for (entry, times) in grouped(&summary.failures).into_iter().take(FAILURE_LIMIT) {
                    lines.push(entry_line(entry, times, true));
                }
                if grouped(&summary.failures).len() > FAILURE_LIMIT {
                    lines.push(format!(
                        "  ... {} more not listed",
                        grouped(&summary.failures).len() - FAILURE_LIMIT
                    ));
                }
            }
            if summary.truncated {
                lines.push(format!(
                    "The history was read only back to {} ({} of {} entries), so the range may hold more.",
                    script.history.entries.last().map_or_else(String::new, |e| when(e.time)),
                    script.history.entries.len(),
                    script.history.total
                ));
            }
        }
        Err(reason) => {
            lines.push(format!(
                "Last search, last install, history and failures: unavailable, {reason}"
            ));
        }
    }
    let set: Vec<&RebootSign> = gathered
        .reboot
        .iter()
        .filter(|s| s.sign == Sign::Set)
        .collect();
    let unreadable: Vec<&RebootSign> = gathered
        .reboot
        .iter()
        .filter(|s| matches!(s.sign, Sign::Unreadable(_)))
        .collect();
    if !set.is_empty() {
        lines.push("Restart pending: yes".into());
        for sign in &set {
            lines.push(format!("  set: {}", sign.label));
        }
    } else if unreadable.is_empty() {
        lines.push("Restart pending: no (none of the documented signs is set)".into());
    } else {
        lines.push("Restart pending: no sign set among those that could be read".into());
    }
    for sign in &unreadable {
        if let Sign::Unreadable(reason) = &sign.sign {
            lines.push(format!("  unavailable: {}, {reason}", sign.label));
        }
    }
    for service in &gathered.services {
        lines.push(match &service.reading {
            Ok((state, start)) => {
                let note = service_note(state, start)
                    .map(|n| format!(" ({n})"))
                    .unwrap_or_default();
                format!(
                    "{} ({}): {state}, start type {start}{note}",
                    service.display, service.name
                )
            }
            Err(reason) => format!(
                "{} ({}): unavailable, {reason}",
                service.display, service.name
            ),
        });
    }
    match &gathered.events {
        Ok(client) => {
            if client.events.is_empty() {
                lines.push("Windows Update client events 20, 25, 31, 34 in the range: none".into());
            } else {
                lines.push(format!(
                    "Windows Update client events 20, 25, 31, 34 in the range: {}{}",
                    client.events.len(),
                    if client.cut_short {
                        " or more (the read was cut short)"
                    } else {
                        ""
                    }
                ));
                for id in EVENT_IDS {
                    let count = client.events.iter().filter(|e| e.id == id).count();
                    if count > 0 {
                        lines.push(format!("  event {id}: {count}"));
                    }
                }
                for event in client.events.iter().take(EVENT_LIMIT) {
                    lines.push(event_text(event));
                }
                if client.events.len() > EVENT_LIMIT {
                    lines.push(format!(
                        "  ... {} older not listed",
                        client.events.len() - EVENT_LIMIT
                    ));
                }
            }
        }
        Err(reason) => lines.push(format!(
            "Windows Update client events: unavailable, {reason}"
        )),
    }
    lines.join("\n")
}

fn time_reading(reading: &Result<Option<SystemTime>, String>) -> Value {
    match reading {
        Ok(Some(time)) => json!(rfc3339(*time)),
        Ok(None) => json!({"unavailable": "never recorded"}),
        Err(reason) => json!({"unavailable": reason}),
    }
}

fn entry_json(entry: &Entry, times: usize) -> Value {
    json!({
        "times": times,
        "time": rfc3339(entry.time),
        "title": entry.title,
        "kb": kb_of(&entry.title),
        "result": result_word(entry.result),
        "error_code": (entry.hresult != 0).then(|| hex(entry.hresult)),
        "error_meaning": hresult_meaning(entry.hresult),
    })
}

pub fn to_json(gathered: &Gathered) -> Value {
    let history = match &gathered.script {
        Ok(script) => {
            let summary = summarize(&script.history, gathered.now, gathered.days);
            json!({
                "last_search_success": time_reading(&script.search),
                "last_install_success": time_reading(&script.install),
                "history_entries_total": script.history.total,
                "history_entries_read": script.history.entries.len(),
                "history_may_be_incomplete": summary.truncated,
                "installed_count": summary.installed.len(),
                "installed": grouped(&summary.installed).into_iter().take(INSTALL_LIMIT).map(|(e, n)| entry_json(e, n)).collect::<Vec<_>>(),
                "definition_updates_count": summary.definitions,
                "uninstalled": grouped(&summary.uninstalled).into_iter().take(INSTALL_LIMIT).map(|(e, n)| entry_json(e, n)).collect::<Vec<_>>(),
                "failure_count": summary.failures.len(),
                "failures": grouped(&summary.failures).into_iter().take(FAILURE_LIMIT).map(|(e, n)| entry_json(e, n)).collect::<Vec<_>>(),
            })
        }
        Err(reason) => json!({"unavailable": reason}),
    };
    let reboot: Vec<Value> = gathered
        .reboot
        .iter()
        .map(|s| match &s.sign {
            Sign::Set => json!({"sign": s.label, "set": true}),
            Sign::NotSet => json!({"sign": s.label, "set": false}),
            Sign::Unreadable(reason) => json!({"sign": s.label, "unavailable": reason}),
        })
        .collect();
    let services: Vec<Value> = gathered
        .services
        .iter()
        .map(|s| match &s.reading {
            Ok((state, start)) => json!({"name": s.name, "state": state, "start_type": start}),
            Err(reason) => json!({"name": s.name, "unavailable": reason}),
        })
        .collect();
    let events = match &gathered.events {
        Ok(client) => json!({
            "count": client.events.len(),
            "cut_short": client.cut_short,
            "listed": client.events.iter().take(EVENT_LIMIT).map(|e| json!({
                "time": rfc3339(e.time),
                "id": e.id,
                "message": e.message,
            })).collect::<Vec<_>>(),
        }),
        Err(reason) => json!({"unavailable": reason}),
    };
    json!({
        "range_days": gathered.days,
        "history": history,
        "restart_pending": if gathered.reboot.iter().any(|s| s.sign == Sign::Set) {
            json!(true)
        } else if gathered.reboot.iter().any(|s| matches!(s.sign, Sign::Unreadable(_))) {
            json!({"unavailable": "some signs could not be read; none of the others is set"})
        } else {
            json!(false)
        },
        "restart_signs": reboot,
        "services": services,
        "client_events": events,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    const NORMAL: &str = include_str!("../../tests/fixtures/updates/script_normal.txt");
    const PARTIAL: &str = include_str!("../../tests/fixtures/updates/script_partial.txt");
    const UNAVAILABLE: &str = include_str!("../../tests/fixtures/updates/script_error.txt");
    const MALFORMED: &str = include_str!("../../tests/fixtures/updates/script_malformed.txt");

    /// 2026-11-05T12:00:00Z, the "now" the fixtures are written against.
    fn now() -> SystemTime {
        clock::parse_utc("2026-11-05T12:00:00Z").unwrap()
    }

    fn gathered(script: Result<ScriptReading, String>) -> Gathered {
        Gathered {
            days: 30,
            now: now(),
            script,
            reboot: vec![
                RebootSign {
                    label: "Windows Update RebootRequired",
                    sign: Sign::NotSet,
                },
                RebootSign {
                    label: "Pending file renames",
                    sign: Sign::Set,
                },
                RebootSign {
                    label: "Component servicing RebootPending",
                    sign: Sign::Unreadable("needs administrator rights".into()),
                },
            ],
            services: vec![
                Service {
                    display: "Windows Update",
                    name: "wuauserv",
                    reading: Ok(("stopped".into(), "manual".into())),
                },
                Service {
                    display: "Background Intelligent Transfer Service",
                    name: "BITS",
                    reading: Err("access denied".into()),
                },
            ],
            events: Ok(ClientEvents {
                events: vec![],
                cut_short: false,
            }),
        }
    }

    #[test]
    fn the_normal_script_output_parses() {
        let script = parse_script(NORMAL).unwrap();
        assert_eq!(script.history.total, 901);
        assert_eq!(script.history.entries.len(), 7);
        assert_eq!(
            rfc3339(script.search.clone().unwrap().unwrap()),
            "2026-11-05T09:19:58Z"
        );
        assert_eq!(script.history.entries[3].hresult, 0x8007_0002);
        assert!(script.history.entries[0]
            .title
            .starts_with("Security Intelligence"));
    }

    #[test]
    fn the_summary_separates_installs_definitions_and_failures() {
        let script = parse_script(NORMAL).unwrap();
        let summary = summarize(&script.history, now(), 30);
        assert_eq!(summary.definitions, 1);
        assert_eq!(summary.installed.len(), 2);
        assert_eq!(summary.failures.len(), 2);
        assert_eq!(summary.uninstalled.len(), 1);
        assert!(
            summary.truncated,
            "the oldest entry read is inside the range"
        );
        let narrow = summarize(&script.history, now(), 3);
        assert_eq!(narrow.installed.len(), 1);
        assert_eq!(narrow.failures.len(), 0);
    }

    #[test]
    fn the_text_names_failures_with_their_meaning() {
        let text = render(&gathered(parse_script(NORMAL)));
        assert!(text.contains("Last successful search for updates: "));
        assert!(text.contains(" November 2026 at "));
        assert!(
            text.contains("Updates installed in the range: 2 (and 1 antivirus definition updates)")
        );
        assert!(text.contains("KB5044284"));
        assert!(text.contains("error 0x80070002 (a file was not found)"));
        assert!(text.contains("error 0x80FFFFFF (meaning not known to this tool)"));
        assert!(text.contains("The history was read only back to"));
        assert!(text.contains("Restart pending: yes"));
        assert!(text.contains(
            "unavailable: Component servicing RebootPending, needs administrator rights"
        ));
        assert!(text.contains("Windows Update (wuauserv): stopped, start type manual (Windows starts it when it is needed)"));
        assert!(text.contains(
            "Background Intelligent Transfer Service (BITS): unavailable, access denied"
        ));
    }

    #[test]
    fn partial_output_keeps_what_was_read() {
        let script = parse_script(PARTIAL).unwrap();
        assert_eq!(script.search, Ok(None));
        assert!(script
            .install
            .as_ref()
            .unwrap_err()
            .contains("not available"));
        assert!(script.history.entries.is_empty());
        let text = render(&gathered(Ok(script)));
        assert!(text.contains("Last successful search for updates: never recorded"));
        assert!(text
            .contains("Last successful install: unavailable, the update agent is not available"));
        assert!(text.contains("Updates installed in the range: 0"));
        assert!(text.contains("Failures in the range: none in the history"));
    }

    #[test]
    fn an_error_from_the_service_is_unavailable_not_empty() {
        let result = parse_script(UNAVAILABLE);
        let reason = result.clone().unwrap_err();
        assert!(reason.contains("Windows Update service reported"));
        let text = render(&gathered(result));
        assert!(text.contains("history and failures: unavailable"));
        assert!(!text.contains("Failures in the range: none"));
    }

    #[test]
    fn malformed_output_is_refused() {
        assert!(parse_script(MALFORMED).is_err());
        for bad in [
            "",
            "COUNT\tmany\n",
            "COUNT\t1\nCOUNT\t1\n",
            "COUNT\t0\nR\tsearch\tyesterday\nR\tinstall\tnone\n",
            "COUNT\t0\nR\tsearch\tnone\nR\tinstall\tnone\nH\t2026-11-01T00:00:00\t1\t2\t00000000\n",
            "COUNT\t0\nR\tsearch\tnone\nR\tinstall\tnone\nH\t2026-11-01T00:00:00\t1\t2\t00000000\tx\n",
            "COUNT\t0\nR\tsearch\tnone\nR\tinstall\tnone\nsurprise\n",
            "COUNT\t0\nR\tsearch\tnone\n",
        ] {
            assert!(parse_script(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn kb_numbers_and_definitions() {
        assert_eq!(
            kb_of("2026-10 Cumulative Update (KB5044284)").as_deref(),
            Some("KB5044284")
        );
        assert_eq!(
            kb_of("Security Intelligence Update - KB2267602 (Version 1.4)").as_deref(),
            Some("KB2267602")
        );
        assert_eq!(kb_of("KB12 is too short"), None);
        assert_eq!(kb_of("no number KB"), None);
        assert!(is_definition_update(
            "Definition Update for Windows Defender - KB915597"
        ));
        assert!(!is_definition_update(
            "2026-10 Cumulative Update for Windows 11"
        ));
    }

    #[test]
    fn known_error_codes_have_meanings() {
        for code in [
            0x8007_0002u32,
            0x800F_0922,
            0x8024_402C,
            0x8007_0422,
            0x800F_081F,
        ] {
            assert!(hresult_meaning(code).is_some(), "{code:08X}");
        }
        assert_eq!(hresult_meaning(0x1234_5678), None);
    }

    #[test]
    fn update_titles_survive_redaction_unchanged() {
        let title = "2026-10 Cumulative Update for Windows 11 Version 25H2 for x64-based Systems (KB5044284) (26200.1234)";
        assert_eq!(events::redact(title, &[]), title);
    }

    #[test]
    fn repeated_entries_are_grouped_with_a_count() {
        let entry = |secs: u64, title: &str| Entry {
            time: UNIX_EPOCH + Duration::from_secs(secs),
            operation: 1,
            result: 2,
            hresult: 0,
            title: title.into(),
        };
        let list = [entry(30, "App A"), entry(20, "App B"), entry(10, "App A")];
        let refs: Vec<&Entry> = list.iter().collect();
        let groups = grouped(&refs);
        assert_eq!(groups.len(), 2);
        assert_eq!((groups[0].0.title.as_str(), groups[0].1), ("App A", 2));
        assert_eq!(
            groups[0].0.time, list[0].time,
            "the newest of a group is kept"
        );
    }

    #[test]
    fn a_disabled_service_is_called_out() {
        assert_eq!(
            service_note("stopped", "disabled"),
            Some("disabled, so this service cannot run")
        );
        assert_eq!(service_note("running", "automatic"), None);
    }

    #[test]
    fn json_output_parses_and_names_unavailable_readings() {
        let ok = gathered(parse_script(NORMAL));
        let text = serde_json::to_string_pretty(&to_json(&ok)).unwrap();
        let back: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(back["history"]["failure_count"], 2);
        assert_eq!(back["history"]["failures"][0]["error_code"], "0x80FFFFFF");
        assert_eq!(back["restart_pending"], true);
        assert_eq!(back["services"][1]["unavailable"], "access denied");
        let bad = gathered(parse_script(MALFORMED));
        let back = to_json(&bad);
        assert!(back["history"]["unavailable"].is_string());
    }

    #[test]
    fn events_are_listed_newest_first_with_counts() {
        let event = |id, secs| Event {
            log: EVENT_LOG.into(),
            provider: "Microsoft-Windows-WindowsUpdateClient".into(),
            id,
            level: 2,
            time: UNIX_EPOCH + Duration::from_secs(secs),
            message: Some("Installation Failure: Windows failed to install the update.".into()),
        };
        let mut g = gathered(parse_script(NORMAL));
        g.events = Ok(ClientEvents {
            events: vec![
                event(20, 1_790_000_000),
                event(31, 1_780_000_000),
                event(31, 1_770_000_000),
            ],
            cut_short: false,
        });
        let text = render(&g);
        assert!(text.contains("events 20, 25, 31, 34 in the range: 3"));
        assert!(text.contains("  event 31: 2"));
        assert!(text.contains("event 20 Update failure: Installation Failure"));
        g.events = Err("the event log would not answer".into());
        assert!(render(&g).contains("client events: unavailable, the event log would not answer"));
    }

    #[test]
    fn the_tool_reads_this_pc() {
        let started = Instant::now();
        let gathered = sys::gather(30, Instant::now() + TIME_LIMIT);
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_secs(15), "{elapsed:?}");
        assert_eq!(gathered.services.len(), 2);
        assert_eq!(gathered.reboot.len(), 4);
        let text = render(&gathered);
        assert!(text.contains("Restart pending"));
        assert!(text.contains("Windows Update (wuauserv)"));
        let data = to_json(&gathered);
        assert!(serde_json::from_str::<Value>(&data.to_string()).is_ok());
        let script = gathered.script.as_ref().expect("the update history reads");
        assert!(script.history.total > 0 || script.history.entries.is_empty());
    }
}
