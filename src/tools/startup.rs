//! What starts with Windows: Run keys, Startup folders, scheduled tasks, services and
//! drivers, each with its publisher and flags for the things worth a second look.
mod parse;
mod sys;

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use windows_sys::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

use self::parse::{
    flags, is_microsoft, mask_sids, parse_shortcut, parse_tasks, publisher_text, run_once_name,
    startup_approved, target_of, target_of_command, Env, FileFacts, Flag, Section, Target, TaskRow,
    Trust,
};
use self::sys::{check_files, Key, Value};
use super::events::rfc3339;
use super::{Args, Output, Tool};
use crate::clock;
use crate::events::{local_names, redact};
use crate::runner::run_process_limited;
use serde_json::json;

pub const TOOL: Tool = Tool {
    name: "startup",
    summary: "what starts with Windows: Run keys, tasks, services, drivers, with signers",
    usage: "\
Usage: toolkit startup [--list] [--all]
  --list  also list the other entries not signed by Microsoft (default: flagged
          entries are listed, the rest counted per section)
  --all   list every entry, including those signed by Microsoft

Lists what starts with Windows and who published it: Run and RunOnce keys, Startup
folders, scheduled tasks outside \\Microsoft\\, services and kernel or file-system drivers
that are not disabled. An entry with a flag (unsigned, invalid signature, missing file,
runs from AppData, Temp or Downloads, script host) is always listed.",
    run,
};

/// The whole run, including the signature checks, stays within this.
const TIME_LIMIT: Duration = Duration::from_secs(30);
/// Entries listed per section, flagged ones first; `--all` allows more.
const SECTION_LIMIT: usize = 100;
const SECTION_LIMIT_ALL: usize = 400;

fn run(args: &Args) -> Result<Output, String> {
    let start = Instant::now();
    let report = gather(start + TIME_LIMIT - Duration::from_secs(1));
    let listing = if args.switch("--all") {
        Listing::All
    } else if args.switch("--list") {
        Listing::NonMicrosoft
    } else {
        Listing::Flagged
    };
    let built = build(&report, listing, &local_names(), start.elapsed());
    Ok(Output {
        text: built.text,
        data: built.data,
    })
}

/// Which entries are listed: always the flagged ones; with `--list` the other non-Microsoft
/// ones; with `--all` the Microsoft-signed ones too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Listing {
    Flagged,
    NonMicrosoft,
    All,
}

/// One thing that starts with Windows, before its file is judged.
#[derive(Debug, Clone)]
struct Entry {
    section: Section,
    name: String,
    origin: String,
    detail: String,
    command: String,
    target: Option<Target>,
}

#[derive(Default)]
struct Report {
    entries: Vec<Entry>,
    facts: HashMap<String, FileFacts>,
    /// Files the time limit stopped before they were checked.
    unchecked: usize,
    /// Disabled items per section, not examined.
    disabled: [usize; 5],
    /// Sources that could not be read, with the reason.
    unavailable: Vec<String>,
    checked_at: Option<SystemTime>,
}

/// This PC's program search path.
struct Pc {
    search: Vec<String>,
}

fn pc_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn pc_exists(path: &str) -> bool {
    Path::new(path).is_file()
}

impl Pc {
    fn new() -> Self {
        let root = pc_var("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        let mut search = vec![format!(r"{root}\System32"), root.clone()];
        if let Some(path) = pc_var("PATH") {
            search.extend(
                path.split(';')
                    .filter(|d| !d.is_empty())
                    .map(str::to_string),
            );
        }
        Pc { search }
    }

    fn env(&self) -> Env<'_> {
        Env {
            var: &pc_var,
            exists: &pc_exists,
            search: &self.search,
        }
    }
}

fn gather(deadline: Instant) -> Report {
    let mut report = Report {
        checked_at: Some(SystemTime::now()),
        ..Report::default()
    };
    let tasks_deadline = (Instant::now() + Duration::from_secs(14)).min(deadline);
    let tasks = std::thread::spawn(move || task_listing(tasks_deadline));
    let pc = Pc::new();
    run_keys(&pc, &mut report);
    startup_folders(&pc, &mut report);
    services_and_drivers(&pc, &mut report);
    match tasks.join() {
        Ok(Ok(rows)) => scheduled_tasks(&pc, rows, &mut report),
        Ok(Err(reason)) => report
            .unavailable
            .push(format!("Scheduled tasks: {reason}")),
        Err(_) => report
            .unavailable
            .push("Scheduled tasks: the reader stopped unexpectedly".into()),
    }
    let mut seen = HashSet::new();
    let paths: Vec<String> = report
        .entries
        .iter()
        .filter_map(|entry| entry.target.as_ref())
        .map(|target| target.file.clone())
        .filter(|file| seen.insert(file.to_ascii_lowercase()))
        .collect();
    let (facts, unchecked) = check_files(&paths, deadline);
    report.facts = facts;
    report.unchecked = unchecked;
    report
}

#[derive(Clone, Copy)]
enum Hive {
    Machine,
    User,
}

impl Hive {
    fn root(self) -> HKEY {
        match self {
            Hive::Machine => HKEY_LOCAL_MACHINE,
            Hive::User => HKEY_CURRENT_USER,
        }
    }
}

const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion";
const CURRENT_VERSION_32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion";

/// Hive, path under CurrentVersion (the 32-bit view when it starts with `32:`), label, and
/// Task Manager's approval key for the entries, if it keeps one.
const RUN_KEYS: [(Hive, &str, &str, Option<&str>); 6] = [
    (Hive::Machine, "Run", "HKLM Run", Some("Run")),
    (Hive::Machine, "RunOnce", "HKLM RunOnce", None),
    (Hive::Machine, "32:Run", "HKLM Run (32-bit)", Some("Run32")),
    (Hive::Machine, "32:RunOnce", "HKLM RunOnce (32-bit)", None),
    (Hive::User, "Run", "HKCU Run", Some("Run")),
    (Hive::User, "RunOnce", "HKCU RunOnce", None),
];

fn run_key_path(key: &str) -> String {
    match key.strip_prefix("32:") {
        Some(rest) => format!(r"{CURRENT_VERSION_32}\{rest}"),
        None => format!(r"{CURRENT_VERSION}\{key}"),
    }
}

/// Names Task Manager has turned off under one approval key.
fn disabled_names(hive: Hive, approval: &str) -> HashSet<String> {
    let path = format!(r"{CURRENT_VERSION}\Explorer\StartupApproved\{approval}");
    let Some(key) = Key::open(hive.root(), &path) else {
        return HashSet::new();
    };
    key.values()
        .into_iter()
        .filter_map(|(name, value)| match value {
            Value::Bytes(bytes) if !startup_approved(&bytes) => Some(name.to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

fn run_keys(pc: &Pc, report: &mut Report) {
    for (hive, key, label, approval) in RUN_KEYS {
        let Some(open) = Key::open(hive.root(), &run_key_path(key)) else {
            continue;
        };
        let off = approval
            .map(|a| disabled_names(hive, a))
            .unwrap_or_default();
        for (name, value) in open.values() {
            let Some(command) = value.text().filter(|c| !c.trim().is_empty()) else {
                continue;
            };
            let name = if approval.is_none() {
                run_once_name(&name).to_string()
            } else {
                name
            };
            if off.contains(&name.to_ascii_lowercase()) {
                report.disabled[Section::RunKeys.index()] += 1;
                continue;
            }
            report.entries.push(Entry {
                section: Section::RunKeys,
                name: if name.is_empty() {
                    "(default)".into()
                } else {
                    name
                },
                origin: label.into(),
                detail: String::new(),
                command: command.trim().to_string(),
                target: Some(target_of_command(command, &pc.env())),
            });
        }
    }
}

fn startup_folders(pc: &Pc, report: &mut Report) {
    let folders = [
        (Hive::User, "APPDATA", "Startup folder (this user)"),
        (Hive::Machine, "ProgramData", "Startup folder (all users)"),
    ];
    for (hive, variable, label) in folders {
        let Some(base) = pc_var(variable) else {
            continue;
        };
        let folder = format!(r"{base}\Microsoft\Windows\Start Menu\Programs\Startup");
        let Ok(items) = std::fs::read_dir(&folder) else {
            continue;
        };
        let off = disabled_names(hive, "StartupFolder");
        for item in items.flatten() {
            let file = item.file_name().to_string_lossy().into_owned();
            if file.eq_ignore_ascii_case("desktop.ini") || !item.path().is_file() {
                continue;
            }
            if off.contains(&file.to_ascii_lowercase()) {
                report.disabled[Section::StartupFolders.index()] += 1;
                continue;
            }
            let path = item.path().to_string_lossy().into_owned();
            let lower = file.to_ascii_lowercase();
            let (command, detail, target) = if lower.ends_with(".lnk") {
                shortcut_entry(&path, &folder, pc)
            } else if lower.ends_with(".url") {
                (path.clone(), "internet shortcut".into(), None)
            } else {
                let target = target_of(&path, "", &pc.env());
                (
                    path.clone(),
                    "file started from the folder".into(),
                    Some(target),
                )
            };
            report.entries.push(Entry {
                section: Section::StartupFolders,
                name: file,
                origin: label.into(),
                detail,
                command,
                target,
            });
        }
    }
}

/// The command, a note and the target of a shortcut file.
fn shortcut_entry(path: &str, folder: &str, pc: &Pc) -> (String, String, Option<Target>) {
    let unreadable = |why: &str| {
        (
            path.to_string(),
            format!("shortcut target not readable ({why})"),
            None,
        )
    };
    let Ok(metadata) = std::fs::metadata(path) else {
        return unreadable("file not readable");
    };
    if metadata.len() > 256 * 1024 {
        return unreadable("file too large");
    }
    let Ok(bytes) = std::fs::read(path) else {
        return unreadable("file not readable");
    };
    let shortcut = match parse_shortcut(&bytes) {
        Ok(shortcut) => shortcut,
        Err(reason) => return unreadable(&reason),
    };
    let target = shortcut.target.or_else(|| {
        let relative = shortcut.relative.as_deref()?;
        std::fs::canonicalize(format!(r"{folder}\{relative}"))
            .ok()
            .map(|p| p.to_string_lossy().trim_start_matches(r"\\?\").to_string())
    });
    let Some(program) = target else {
        return unreadable("it points at an installed app");
    };
    let args = shortcut.arguments.unwrap_or_default();
    let command = format!("{program} {args}").trim().to_string();
    let target = target_of(&program, &args, &pc.env());
    (command, "shortcut".into(), Some(target))
}

/// The script that lists scheduled tasks outside \Microsoft\, one tab-separated line each.
const TASK_SCRIPT: &str = "\
$ErrorActionPreference = 'Stop'; \
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); \
$tab = [char]9; \
function Clean($s) { if ($null -eq $s) { return '' } return ([string]$s -replace '[\\t\\r\\n]+', ' ') }; \
$rows = @(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' }); \
'STARTUP-TASKS-V1'; \
foreach ($t in $rows) { \
  $a = @($t.Actions)[0]; \
  $kind = ''; $exe = ''; $arg = ''; \
  if ($a) { \
    $kind = Clean (($a.CimClass.CimClassName -replace '^MSFT_Task', '') -replace 'Action$', ''); \
    if ($kind -eq 'Exec') { $exe = Clean $a.Execute; $arg = Clean $a.Arguments } \
  }; \
  $trig = Clean ((@($t.Triggers) | ForEach-Object { ($_.CimClass.CimClassName -replace '^MSFT_Task', '') -replace 'Trigger$', '' }) -join ','); \
  (@('T', (Clean $t.TaskPath), (Clean $t.TaskName), (Clean $t.State), $kind, $exe, $arg, $trig)) -join $tab \
}; \
'END ' + $rows.Count";

fn task_listing(deadline: Instant) -> Result<Vec<TaskRow>, String> {
    let output = run_process_limited(
        TASK_SCRIPT,
        deadline,
        Arc::new(AtomicBool::new(false)),
        1 << 20,
    )
    .map_err(|error| format!("could not be listed ({})", error.reason()))?;
    parse_tasks(&output)
}

fn scheduled_tasks(pc: &Pc, rows: Vec<TaskRow>, report: &mut Report) {
    for row in rows {
        if row.state.eq_ignore_ascii_case("disabled") {
            report.disabled[Section::Tasks.index()] += 1;
            continue;
        }
        let exec = row.action == "Exec" && !row.execute.is_empty();
        let command = if exec {
            format!("{} {}", row.execute, row.arguments)
                .trim()
                .to_string()
        } else if row.action.is_empty() {
            "(no action)".into()
        } else {
            format!("(action of type {})", row.action)
        };
        let triggers = if row.triggers.is_empty() {
            "no trigger".to_string()
        } else {
            row.triggers.join(", ").to_ascii_lowercase()
        };
        report.entries.push(Entry {
            section: Section::Tasks,
            name: format!("{}{}", row.path, row.name),
            origin: "task".into(),
            detail: format!("{}, triggers: {triggers}", row.state.to_ascii_lowercase()),
            command,
            target: exec.then(|| target_of(&row.execute, &row.arguments, &pc.env())),
        });
    }
}

fn start_word(start: u32, delayed: bool) -> &'static str {
    match (start, delayed) {
        (0, _) => "boot start",
        (1, _) => "system start",
        (2, true) => "automatic (delayed)",
        (2, false) => "automatic",
        (3, _) => "manual",
        (4, _) => "disabled",
        _ => "start type unknown",
    }
}

fn services_and_drivers(pc: &Pc, report: &mut Report) {
    const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";
    let Some(root) = Key::open(HKEY_LOCAL_MACHINE, SERVICES) else {
        report
            .unavailable
            .push("Services and Drivers: the services key could not be opened".into());
        return;
    };
    let states = match sys::service_states() {
        Ok(states) => states,
        Err(reason) => {
            report.unavailable.push(format!(
                "Services and Drivers: current state unavailable, {reason}"
            ));
            HashMap::new()
        }
    };
    for name in root.subkeys() {
        let Some(key) = Key::open(HKEY_LOCAL_MACHINE, &format!(r"{SERVICES}\{name}")) else {
            continue;
        };
        let number = |value: &str| key.value(value).and_then(|v| v.number());
        let kind = number("Type").unwrap_or(0);
        let driver = kind & 3 != 0;
        if !driver && kind & 0x30 == 0 {
            continue;
        }
        let section = if driver {
            Section::Drivers
        } else {
            Section::Services
        };
        let start = number("Start").unwrap_or(3);
        if start == 4 {
            report.disabled[section.index()] += 1;
            continue;
        }
        let image = key
            .value("ImagePath")
            .and_then(|v| v.text().map(str::to_string))
            .unwrap_or_default();
        let command = parse::normalize_image_path(&image, &name, driver);
        if command.is_empty() {
            continue;
        }
        let mut target = target_of_command(&command, &pc.env());
        let mut hosted = "";
        if target.exe_name() == "svchost.exe" {
            let dll = Key::open(
                HKEY_LOCAL_MACHINE,
                &format!(r"{SERVICES}\{name}\Parameters"),
            )
            .and_then(|p| p.value("ServiceDll"))
            .or_else(|| key.value("ServiceDll"))
            .and_then(|v| v.text().map(str::to_string));
            if let Some(dll) = dll {
                target.file = target_of(&dll, "", &pc.env()).exe;
                target.via_dll = true;
                hosted = "hosted in svchost; ";
            }
        }
        let state = states.get(&name.to_ascii_lowercase());
        let state_text = state.map_or("state unavailable", |(state, _)| state.as_str());
        let display = state
            .map(|(_, display)| display.clone())
            .filter(|d| !d.is_empty())
            .or_else(|| {
                key.value("DisplayName")
                    .and_then(|v| v.text().map(str::to_string))
                    .filter(|d| !d.starts_with('@') && !d.is_empty())
            })
            .filter(|d| !d.eq_ignore_ascii_case(&name));
        let delayed = number("DelayedAutostart") == Some(1);
        let mut detail = format!("{hosted}{}, {state_text}", start_word(start, delayed));
        if let Some(display) = display {
            detail.push_str(&format!("; display name {display}"));
        }
        report.entries.push(Entry {
            section,
            name,
            origin: if driver { "driver" } else { "service" }.into(),
            detail,
            command,
            target: Some(target),
        });
    }
}

fn date_text(time: SystemTime) -> String {
    let stamp = clock::local(time).file();
    format!("{}-{}-{}", &stamp[..4], &stamp[4..6], &stamp[6..8])
}

struct Judged<'a> {
    entry: &'a Entry,
    facts: Option<&'a FileFacts>,
    flags: Vec<Flag>,
    microsoft: bool,
}

fn judge<'a>(report: &'a Report, entry: &'a Entry) -> Judged<'a> {
    let facts = entry
        .target
        .as_ref()
        .and_then(|target| report.facts.get(&target.file.to_ascii_lowercase()));
    let flags = flags(entry.target.as_ref(), facts);
    let microsoft = flags.is_empty() && facts.is_some_and(is_microsoft);
    Judged {
        entry,
        facts,
        flags,
        microsoft,
    }
}

struct Built {
    text: String,
    data: serde_json::Value,
}

#[cfg(test)]
fn render(report: &Report, listing: Listing, names: &[String], elapsed: Duration) -> String {
    build(report, listing, names, elapsed).text
}

fn build(report: &Report, listing: Listing, names: &[String], elapsed: Duration) -> Built {
    let judged: Vec<Judged> = report.entries.iter().map(|e| judge(report, e)).collect();
    let mut lines = Vec::new();
    let when = report
        .checked_at
        .map(|t| clock::local(t).long())
        .unwrap_or_default();
    lines.push(format!(
        "Startup items on this PC, read {when}, in {} s.",
        elapsed.as_secs().max(1)
    ));
    let count = |section: Section| judged.iter().filter(|j| j.entry.section == section).count();
    let counts: Vec<String> = Section::ALL
        .iter()
        .map(|&s| format!("{} {}", s.title(), count(s)))
        .collect();
    let flagged = judged.iter().filter(|j| !j.flags.is_empty()).count();
    let microsoft = judged.iter().filter(|j| j.microsoft).count();
    let other = judged.len() - flagged - microsoft;
    lines.push(format!("Summary: {}.", counts.join(", ")));
    lines.push(format!(
        "Flagged entries: {flagged}, all listed. {}",
        match listing {
            Listing::Flagged => format!(
                "Other entries not signed by Microsoft: {other}, not listed (--list lists them). Microsoft-signed: {microsoft}, not listed (--all lists them)."
            ),
            Listing::NonMicrosoft => format!(
                "Other entries not signed by Microsoft: {other}, listed (--list). Microsoft-signed: {microsoft}, not listed (--all lists them)."
            ),
            Listing::All => format!(
                "Other entries not signed by Microsoft: {other}, listed. Microsoft-signed: {microsoft}, listed (--all)."
            ),
        }
    ));
    let disabled: Vec<String> = Section::ALL
        .iter()
        .filter(|s| report.disabled[s.index()] > 0)
        .map(|s| format!("{} {}", s.title(), report.disabled[s.index()]))
        .collect();
    if !disabled.is_empty() {
        lines.push(format!(
            "Disabled, so not examined: {}.",
            disabled.join(", ")
        ));
    }
    if report.unchecked > 0 {
        lines.push(format!(
            "Signatures not checked: {} files, because the {} s limit was reached.",
            report.unchecked,
            TIME_LIMIT.as_secs()
        ));
    }
    for reason in &report.unavailable {
        lines.push(format!("Unavailable: {reason}."));
    }
    let limit = if listing == Listing::All {
        SECTION_LIMIT_ALL
    } else {
        SECTION_LIMIT
    };
    let mut sections_json = Vec::new();
    for section in Section::ALL {
        let mut shown: Vec<&Judged> = judged
            .iter()
            .filter(|j| {
                j.entry.section == section
                    && match listing {
                        Listing::Flagged => !j.flags.is_empty(),
                        Listing::NonMicrosoft => !j.microsoft,
                        Listing::All => true,
                    }
            })
            .collect();
        shown.sort_by_key(|j| {
            (
                std::cmp::Reverse(j.flags.len()),
                j.entry.name.to_ascii_lowercase(),
            )
        });
        let total = count(section);
        let in_section = |test: fn(&Judged) -> bool| {
            judged
                .iter()
                .filter(|j| j.entry.section == section && test(j))
                .count()
        };
        let (flagged_here, microsoft_here) = (
            in_section(|j| !j.flags.is_empty()),
            in_section(|j| j.microsoft),
        );
        let other_here = total - flagged_here - microsoft_here;
        let hidden = total - shown.len();
        lines.push(String::new());
        lines.push(format!(
            "{} ({total}): {flagged_here} flagged, {other_here} other, {microsoft_here} Microsoft-signed{}",
            section.title(),
            if hidden > 0 {
                format!("; {hidden} not listed")
            } else {
                String::new()
            }
        ));
        if shown.is_empty() {
            lines.push(
                if hidden > 0 {
                    "  none flagged"
                } else {
                    "  none to list"
                }
                .into(),
            );
        }
        // A flagged entry is never cut: the limit applies to the unflagged ones.
        let flagged_listed = shown.iter().take_while(|j| !j.flags.is_empty()).count();
        let take = limit.max(flagged_listed);
        for item in shown.iter().take(take) {
            lines.extend(entry_lines(item, names));
        }
        if shown.len() > take {
            lines.push(format!(
                "  {} more entries not listed (limit of {limit} per section)",
                shown.len() - take
            ));
        }
        sections_json.push(json!({
            "section": section.title(),
            "total": total,
            "flagged": flagged_here,
            "other_not_microsoft": other_here,
            "microsoft_signed": microsoft_here,
            "not_listed": total - shown.len().min(take),
            "entries": shown.iter().take(take).map(|item| entry_json(item, names)).collect::<Vec<_>>(),
        }));
    }
    let data = json!({
        "tool": "startup",
        "read_at": report.checked_at.map(rfc3339),
        "listing": match listing {
            Listing::Flagged => "flagged",
            Listing::NonMicrosoft => "flagged_and_other_non_microsoft",
            Listing::All => "all",
        },
        "flagged": flagged,
        "other_not_microsoft": other,
        "microsoft_signed": microsoft,
        "disabled_not_examined": Section::ALL.iter().map(|s| (s.title().to_string(), json!(report.disabled[s.index()]))).collect::<serde_json::Map<_, _>>(),
        "signatures_not_checked_for_time": report.unchecked,
        "unavailable": report.unavailable.iter().map(|reason| plain(reason, names)).collect::<Vec<_>>(),
        "sections": sections_json,
    });
    Built {
        text: lines.join("\n"),
        data,
    }
}

fn signature_json(facts: Option<&FileFacts>) -> (&'static str, Option<String>) {
    let Some(facts) = facts else {
        return ("not_checked", None);
    };
    if !facts.exists {
        return ("file_missing", None);
    }
    match &facts.trust {
        Trust::Valid => ("valid", None),
        Trust::Unsigned => ("unsigned", None),
        Trust::Invalid(reason) => ("invalid", Some(reason.clone())),
        Trust::Unreadable(reason) => ("not_checked", Some(reason.clone())),
    }
}

fn entry_json(item: &Judged, names: &[String]) -> serde_json::Value {
    let entry = item.entry;
    let (signature, reason) = signature_json(item.facts);
    let publisher = if entry.target.is_some() {
        publisher_text(item.facts)
    } else {
        "no program to check".to_string()
    };
    let (file, program) = entry.target.as_ref().map_or((None, None), |t| {
        (Some(t.file.as_str()), Some(t.exe.as_str()))
    });
    json!({
        "name": plain(&entry.name, names),
        "origin": entry.origin,
        "detail": plain(&entry.detail, names),
        "command": plain(&entry.command, names),
        "program": program.map(|text| plain(text, names)),
        "file_checked": file.map(|text| plain(text, names)),
        "publisher": plain(&publisher, names),
        "signature": if entry.target.is_some() { json!(signature) } else { json!("no_program") },
        "signature_reason": reason.map(|text| plain(&text, names)),
        "signer": item.facts.and_then(|f| f.signer.clone()),
        "company": item.facts.and_then(|f| f.company.clone()),
        "version": item.facts.and_then(|f| f.version.clone()),
        "file_modified": item.facts.and_then(|f| f.modified).map(rfc3339),
        "flags": item.flags.iter().map(Flag::text).collect::<Vec<_>>(),
        "microsoft_signed": item.microsoft,
    })
}

/// Text with account SIDs, names and addresses redacted.
fn plain(text: &str, names: &[String]) -> String {
    redact(&mask_sids(text), names)
}

fn entry_lines(item: &Judged, names: &[String]) -> [String; 2] {
    let entry = item.entry;
    let mut first = format!(
        "{} [{}]: {}",
        entry.name,
        entry.origin,
        if entry.target.is_some() {
            publisher_text(item.facts)
        } else {
            "no program to check".to_string()
        }
    );
    if !item.flags.is_empty() {
        let flags: Vec<String> = item.flags.iter().map(Flag::text).collect();
        first.push_str(&format!(" -- FLAGGED: {}", flags.join("; ")));
    }
    let mut second = entry.detail.clone();
    if entry.section == Section::Drivers {
        if let Some(facts) = item.facts {
            let mut parts = Vec::new();
            if let Some(modified) = facts.modified {
                parts.push(format!("file dated {}", date_text(modified)));
            }
            if let Some(version) = &facts.version {
                parts.push(format!("version {version}"));
            }
            if !parts.is_empty() {
                if !second.is_empty() {
                    second.push_str("; ");
                }
                second.push_str(&parts.join(", "));
            }
        }
    }
    let mut command = entry.command.clone();
    if let Some(target) = &entry.target {
        if !target.file.eq_ignore_ascii_case(&target.exe) {
            command.push_str(&format!(" -> {}", target.file));
        }
    }
    if !second.is_empty() {
        second.push_str(" | ");
    }
    second.push_str(&command);
    [
        format!("- {}", plain(&first, names)),
        format!("    {}", plain(&second, names)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(section: Section, name: &str, file: &str) -> Entry {
        Entry {
            section,
            name: name.into(),
            origin: "HKCU Run".into(),
            detail: String::new(),
            command: file.into(),
            target: Some(Target {
                exe: file.into(),
                args: String::new(),
                file: file.into(),
                via_dll: false,
            }),
        }
    }

    fn signed(signer: &str) -> FileFacts {
        FileFacts {
            exists: true,
            trust: Trust::Valid,
            signer: Some(signer.into()),
            company: None,
            version: Some("1.2.3.4".into()),
            modified: None,
        }
    }

    fn unsigned() -> FileFacts {
        FileFacts {
            trust: Trust::Unsigned,
            signer: None,
            ..signed("x")
        }
    }

    fn report() -> Report {
        let mut report = Report::default();
        let items = [
            (
                Section::RunKeys,
                "OneDrive",
                r"C:\Program Files\Microsoft\od.exe",
                Some(signed("Microsoft Corporation")),
            ),
            (
                Section::RunKeys,
                "Updater",
                r"C:\Users\Pat\AppData\Local\Up\up.exe",
                Some(unsigned()),
            ),
            (
                Section::Services,
                "Contoso",
                r"C:\Program Files\Contoso\c.exe",
                Some(signed("Contoso Ltd")),
            ),
            (
                Section::Drivers,
                "ghost",
                r"C:\Windows\System32\drivers\ghost.sys",
                Some(FileFacts::missing()),
            ),
            (
                Section::Drivers,
                "late",
                r"C:\Windows\System32\drivers\late.sys",
                None,
            ),
        ];
        for (section, name, file, facts) in items {
            report.entries.push(entry(section, name, file));
            if let Some(facts) = facts {
                report.facts.insert(file.to_ascii_lowercase(), facts);
            }
        }
        report.disabled[Section::Services.index()] = 7;
        report.unchecked = 1;
        report
            .unavailable
            .push("Scheduled tasks: could not be listed (timed out)".into());
        report
    }

    #[test]
    fn the_summary_counts_hides_microsoft_entries_and_flags_the_rest() {
        let text = render(
            &report(),
            Listing::Flagged,
            &["Pat".to_string()],
            Duration::from_secs(4),
        );
        assert!(
            text.contains(
                "Summary: Run keys 2, Startup folders 0, Scheduled tasks 0, Services 1, Drivers 2."
            ),
            "{text}"
        );
        assert!(
            text.contains("Flagged entries: 2, all listed. Other entries not signed by Microsoft: 2, not listed (--list lists them). Microsoft-signed: 1, not listed (--all lists them)."),
            "{text}"
        );
        assert!(
            text.contains("Run keys (2): 1 flagged, 0 other, 1 Microsoft-signed; 1 not listed"),
            "{text}"
        );
        assert!(!text.contains("Contoso [service]"), "{text}");
        assert!(
            text.contains("Disabled, so not examined: Services 7."),
            "{text}"
        );
        assert!(text.contains("Signatures not checked: 1 files"), "{text}");
        assert!(
            text.contains("Unavailable: Scheduled tasks: could not be listed"),
            "{text}"
        );
        assert!(!text.contains("OneDrive"), "{text}");
        assert!(
            text.contains("Updater [HKCU Run]: not signed -- FLAGGED: unsigned; runs from AppData"),
            "{text}"
        );
        assert!(
            text.contains("ghost [HKCU Run]: file not found -- FLAGGED: file is missing"),
            "{text}"
        );
        assert!(!text.contains("late ["), "{text}");
        assert!(!text.contains("Contoso ["), "{text}");
        let listed = render(
            &report(),
            Listing::NonMicrosoft,
            &["Pat".to_string()],
            Duration::from_secs(4),
        );
        assert!(
            listed.contains("Contoso [HKCU Run]: signed by Contoso Ltd"),
            "{listed}"
        );
        assert!(!listed.contains("OneDrive"), "{listed}");
        assert!(
            listed.contains("late [HKCU Run]: signature not checked"),
            "{listed}"
        );
    }

    #[test]
    fn json_lists_what_the_text_lists_and_counts_the_rest() {
        let names = ["Pat".to_string()];
        let flagged = build(&report(), Listing::Flagged, &names, Duration::from_secs(4));
        assert_eq!(flagged.data["listing"], "flagged");
        assert_eq!(flagged.data["flagged"], 2);
        assert_eq!(flagged.data["microsoft_signed"], 1);
        assert_eq!(flagged.data["disabled_not_examined"]["Services"], 7);
        assert_eq!(flagged.data["signatures_not_checked_for_time"], 1);
        assert!(flagged.data["unavailable"][0]
            .as_str()
            .unwrap()
            .starts_with("Scheduled tasks"));
        let run_keys = &flagged.data["sections"][0];
        assert_eq!(run_keys["total"], 2);
        assert_eq!(run_keys["not_listed"], 1);
        let updater = &run_keys["entries"][0];
        assert_eq!(updater["name"], "Updater");
        assert_eq!(updater["signature"], "unsigned");
        assert_eq!(updater["flags"][0], "unsigned");
        assert_eq!(
            updater["file_checked"],
            r"C:\Users\[user]\AppData\Local\Up\up.exe"
        );
        assert!(flagged
            .text
            .contains(updater["publisher"].as_str().unwrap()));
        let drivers = &flagged.data["sections"][4];
        assert_eq!(drivers["entries"][0]["signature"], "file_missing");
        assert_eq!(drivers["total"], 2);
        let all = build(&report(), Listing::All, &names, Duration::from_secs(4));
        let listed: usize = all.data["sections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|section| section["entries"].as_array().unwrap().len())
            .sum();
        assert_eq!(listed, 5);
        let late = &all.data["sections"][4]["entries"][1];
        assert_eq!(late["signature"], "not_checked");
        assert_eq!(late["microsoft_signed"], false);
        assert!(!all.data.to_string().contains("Pat"));
    }

    #[test]
    fn the_default_listing_stays_short_however_many_entries_are_clean() {
        let mut report = Report::default();
        for index in 0..300 {
            let file = format!(r"C:\Program Files\V\{index:03}.exe");
            report
                .entries
                .push(entry(Section::Services, &format!("svc{index:03}"), &file));
            report
                .facts
                .insert(file.to_ascii_lowercase(), signed("Vendor"));
        }
        let bad = r"C:\Program Files\V\zzz.exe";
        report
            .entries
            .push(entry(Section::Services, "zzz-bad", bad));
        report.facts.insert(bad.to_ascii_lowercase(), unsigned());
        let text = render(&report, Listing::Flagged, &[], Duration::from_secs(1));
        assert!(text.lines().count() < 30, "{text}");
        assert!(text.contains("- zzz-bad [HKCU Run]"), "{text}");
        assert!(text
            .contains("Services (301): 1 flagged, 300 other, 0 Microsoft-signed; 300 not listed"));
    }

    #[test]
    fn every_flagged_entry_is_listed_even_beyond_the_section_limit() {
        let mut report = Report::default();
        for index in 0..(SECTION_LIMIT + 20) {
            let file = format!(r"C:\Users\x\AppData\{index:03}.exe");
            report
                .entries
                .push(entry(Section::RunKeys, &format!("bad{index:03}"), &file));
            report.facts.insert(file.to_ascii_lowercase(), unsigned());
        }
        let built = build(&report, Listing::Flagged, &[], Duration::from_secs(1));
        assert_eq!(built.text.matches("FLAGGED").count(), SECTION_LIMIT + 20);
        assert!(!built.text.contains("more entries not listed"));
        assert_eq!(built.data["sections"][0]["not_listed"], 0);
    }

    #[test]
    fn profile_names_never_reach_the_output() {
        let text = render(
            &report(),
            Listing::All,
            &["Pat".to_string()],
            Duration::from_secs(4),
        );
        assert!(!text.contains("Pat"), "{text}");
        assert!(
            text.contains(r"C:\Users\[user]\AppData\Local\Up\up.exe"),
            "{text}"
        );
        assert!(
            text.contains("OneDrive [HKCU Run]: signed by Microsoft Corporation"),
            "{text}"
        );
        assert!(
            text.contains("Microsoft-signed: 1, listed (--all)."),
            "{text}"
        );
    }

    #[test]
    fn odd_characters_ids_and_missing_targets_are_handled() {
        let mut report = Report::default();
        let file = "C:\\Program Files\\V\\odd.exe \u{ffff}";
        report
            .entries
            .push(entry(Section::Services, "odd\u{e9}", file));
        report.facts.insert(file.to_ascii_lowercase(), unsigned());
        let mut task = entry(
            Section::Tasks,
            r"\Brave UpdateS-1-5-21-111-222-333-1001Core",
            "",
        );
        task.target = None;
        report.entries.push(task);
        let text = render(&report, Listing::NonMicrosoft, &[], Duration::from_secs(1));
        assert!(text.contains("odd\u{e9} [HKCU Run]: not signed"), "{text}");
        assert!(text.contains("exe \u{ffff}"), "{text}");
        assert!(text.contains(r"\Brave Update[account]Core"), "{text}");
        assert!(text.contains("no program to check"), "{text}");
    }

    #[test]
    fn flagged_entries_come_first_and_a_long_section_is_cut_with_a_note() {
        let mut report = Report::default();
        for index in 0..(SECTION_LIMIT + 5) {
            let file = format!(r"C:\Program Files\V\{index:03}.exe");
            report
                .entries
                .push(entry(Section::Services, &format!("svc{index:03}"), &file));
            report
                .facts
                .insert(file.to_ascii_lowercase(), signed("Vendor"));
        }
        let bad = r"C:\Program Files\V\zzz.exe";
        report
            .entries
            .push(entry(Section::Services, "zzz-bad", bad));
        report.facts.insert(bad.to_ascii_lowercase(), unsigned());
        let text = render(&report, Listing::NonMicrosoft, &[], Duration::from_secs(1));
        let first = text
            .lines()
            .position(|l| l.starts_with("- zzz-bad"))
            .unwrap();
        let second = text
            .lines()
            .position(|l| l.starts_with("- svc000"))
            .unwrap();
        assert!(first < second, "{text}");
        assert!(text.contains("6 more entries not listed"), "{text}");
    }

    #[test]
    fn the_task_script_has_no_double_quotes_to_trip_the_command_line() {
        assert!(!TASK_SCRIPT.contains('"'));
        assert!(TASK_SCRIPT.contains(parse::TASK_HEADER));
    }

    #[test]
    fn the_tool_reads_this_pc() {
        let started = Instant::now();
        let report = gather(started + Duration::from_secs(10));
        let text = render(&report, Listing::Flagged, &local_names(), started.elapsed());
        for section in Section::ALL {
            assert!(text.contains(&format!("\n{} (", section.title())), "{text}");
        }
        assert!(text.contains("Summary: Run keys "), "{text}");
        assert!(!report.entries.is_empty());
        let built = build(&report, Listing::Flagged, &local_names(), started.elapsed());
        let parsed: serde_json::Value = serde_json::from_str(&built.data.to_string()).unwrap();
        assert_eq!(parsed["tool"], "startup");
        assert_eq!(parsed["sections"].as_array().unwrap().len(), 5);
        assert_eq!(
            parsed["flagged"].as_u64().unwrap() as usize,
            text.matches("FLAGGED").count()
        );
        assert!(started.elapsed() < Duration::from_secs(15));
    }
}
