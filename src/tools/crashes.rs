//! Blue screens: stop codes, their parameters, times and the driver the stop points at,
//! from System event 1001 (Microsoft-Windows-WER-SystemErrorReporting), Kernel-Power 41
//! and the headers of crash dump files. Dumps are never read whole: only the 8 KiB header
//! and, for small dumps, the driver list (see `dump`).
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime};

use serde_json::{json, Value};

use super::events::{limit_name, rfc3339};
use super::{Args, Output, Tool};
use crate::budget::{self, Budget};
use crate::clock;
use crate::events::{self, Event, Limit, LogRead, Query};

pub(crate) mod codes;
mod dump;

use dump::{Drivers, Dump};

pub const TOOL: Tool = Tool {
    name: "crashes",
    summary: "blue screens: stop codes and drivers from crash dumps and event 1001",
    usage: "\
Usage: toolkit crashes [--days N]
  --days N   time range in days, 1 to 365 (default 90)
Reads System events 1001 (stop recorded at the next start) and Kernel-Power 41
(unclean restart), and the headers of dump files in the Windows folder: Minidump,
MEMORY.DMP and LiveKernelReports. Dump folders usually need administrator rights.",
    run,
};

const WER: &str = "Microsoft-Windows-WER-SystemErrorReporting";
const KERNEL_POWER: &str = "Microsoft-Windows-Kernel-Power";
const VOLMGR: &str = "volmgr";
const DUMP_FAILURE_IDS: [u32; 3] = [45, 46, 161];
const DAY: Duration = Duration::from_secs(24 * 3600);
/// How close a stop event must be to an unclean restart to account for it.
const RESTART_WINDOW: Duration = Duration::from_secs(15 * 60);
const MAX_STOPS_LISTED: usize = 40;
const MAX_FILES: usize = 200;
const MAX_DEPTH: usize = 3;
const NOTE: &str = "from the stop parameters only; a full analysis reads the stack";

fn run(args: &Args) -> Result<Output, String> {
    let days = args.number("--days", 90, 1, 365)?;
    let now = SystemTime::now();
    let deadline = Instant::now() + Duration::from_secs(20);
    let events = read_event_log(days, deadline);
    let (places, dumps) = scan_places(&windows_directory()?);
    let reading = Reading {
        days,
        now,
        elevated: elevated(),
        events,
        places,
        dumps,
    };
    Ok(Output {
        text: report(&reading),
        data: report_json(&reading),
    })
}

/// Everything gathered, for `report` to interpret.
struct Reading {
    days: u64,
    now: SystemTime,
    elevated: Option<bool>,
    events: Result<EventReading, String>,
    places: Vec<Place>,
    dumps: Vec<DumpFile>,
}

pub(crate) struct EventReading {
    pub(crate) days: u64,
    pub(crate) stops: Vec<StopEvent>,
    pub(crate) restarts: Vec<SystemTime>,
    /// volmgr 45, 46 and 161: crash dumps could not be set up or written.
    pub(crate) dump_failures: Vec<SystemTime>,
    pub(crate) reads: Vec<LogRead>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StopEvent {
    pub(crate) time: SystemTime,
    pub(crate) stop: Option<(u32, [u64; 4])>,
    pub(crate) path: Option<String>,
}

#[derive(Debug, PartialEq)]
enum PlaceState {
    Missing,
    Denied,
    Failed(String),
    Listed { cut: bool },
}

struct Place {
    path: PathBuf,
    state: PlaceState,
}

struct DumpFile {
    path: PathBuf,
    size: u64,
    modified: Option<SystemTime>,
    live: bool,
    /// The dump's contents, or why the file could not be opened.
    reading: Result<Dump, String>,
}

impl DumpFile {
    fn header(&self) -> Option<&dump::Header> {
        match &self.reading {
            Ok(Dump::Kernel64 { header, .. }) => Some(header),
            _ => None,
        }
    }

    fn time(&self) -> Option<SystemTime> {
        self.header()
            .and_then(|header| header.time)
            .or(self.modified)
    }

    fn drivers(&self) -> Option<&Drivers> {
        match &self.reading {
            Ok(Dump::Kernel64 { drivers, .. }) => Some(drivers),
            _ => None,
        }
    }
}

/// The days of event log a range of `days` can read: at most `events::MAX_SINCE`.
fn event_days(days: u64) -> u64 {
    days.min(events::MAX_SINCE.as_secs() / DAY.as_secs())
}

pub(crate) fn read_event_log(days: u64, deadline: Instant) -> Result<EventReading, String> {
    let days = event_days(days);
    let query = Query {
        logs: vec!["System".into()],
        levels: Vec::new(),
        providers: vec![WER.into(), KERNEL_POWER.into(), VOLMGR.into()],
        ids: [1001, 41].into_iter().chain(DUMP_FAILURE_IDS).collect(),
        since: DAY * days as u32,
        include_noise: true,
        per_log_limit: 2000,
        messages: true,
    };
    let cancelled = AtomicBool::new(false);
    let (found, reads) =
        events::read_events(&query, deadline, &cancelled).map_err(super::events::message)?;
    Ok(sort_events(days, &found, reads))
}

fn sort_events(days: u64, found: &[Event], reads: Vec<LogRead>) -> EventReading {
    let mut reading = EventReading {
        days,
        stops: Vec::new(),
        restarts: Vec::new(),
        dump_failures: Vec::new(),
        reads,
    };
    for event in found {
        if event.id == 1001 && event.provider.eq_ignore_ascii_case(WER) {
            let text = event.message.as_deref().unwrap_or("");
            reading.stops.push(StopEvent {
                time: event.time,
                stop: parse_stop(text),
                path: dump_path(text),
            });
        } else if event.id == 41 && event.provider.eq_ignore_ascii_case(KERNEL_POWER) {
            reading.restarts.push(event.time);
        } else if DUMP_FAILURE_IDS.contains(&event.id)
            && event.provider.eq_ignore_ascii_case(VOLMGR)
        {
            reading.dump_failures.push(event.time);
        }
    }
    reading
}

/// Finds `0xCODE (0xP1, 0xP2, 0xP3, 0xP4)` in event 1001's text. The numbers are inserts,
/// so they read the same in every language.
fn parse_stop(text: &str) -> Option<(u32, [u64; 4])> {
    let lower = text.to_ascii_lowercase();
    let mut start = 0;
    while let Some(found) = lower[start..].find("0x") {
        let at = start + found;
        if let Some(stop) = stop_at(&lower[at..]) {
            return Some(stop);
        }
        start = at + 2;
    }
    None
}

fn stop_at(text: &str) -> Option<(u32, [u64; 4])> {
    let (code, rest) = hex(text)?;
    let code = u32::try_from(code).ok()?;
    let mut rest = rest.trim_start().strip_prefix('(')?;
    let mut parameters = [0; 4];
    for (index, value) in parameters.iter_mut().enumerate() {
        let (number, after) = hex(rest.trim_start())?;
        *value = number;
        let after = after.trim_start();
        rest = if index < 3 {
            after.strip_prefix(',')?
        } else {
            after.strip_prefix(')')?
        };
    }
    Some((code, parameters))
}

/// `0x` and 1 to 16 hex digits, and the text after them.
fn hex(text: &str) -> Option<(u64, &str)> {
    let digits = text.strip_prefix("0x")?;
    let length = digits
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(digits.len());
    if length == 0 || length > 16 {
        return None;
    }
    let value = u64::from_str_radix(&digits[..length], 16).ok()?;
    Some((value, &digits[length..]))
}

/// The dump path event 1001 names: the last `X:\` before `.dmp`.
fn dump_path(text: &str) -> Option<String> {
    let end = text.to_ascii_lowercase().find(".dmp")? + 4;
    let head = &text[..end];
    let bytes = head.as_bytes();
    let start = (0..head.len().saturating_sub(2)).rev().find(|&index| {
        bytes[index].is_ascii_alphabetic()
            && bytes[index + 1] == b':'
            && bytes[index + 2] == b'\\'
            && (index == 0 || !bytes[index - 1].is_ascii_alphanumeric())
    })?;
    Some(head[start..].to_string())
}

fn windows_directory() -> Result<PathBuf, String> {
    use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
    let mut buffer = [0u16; 520];
    // SAFETY: the buffer and its length in UTF-16 units match.
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 || length as usize >= buffer.len() {
        return Err("Unavailable: the Windows folder could not be found".into());
    }
    Ok(PathBuf::from(String::from_utf16_lossy(
        &buffer[..length as usize],
    )))
}

/// Whether this process runs with administrator rights; `None` if the token is unreadable.
pub(crate) fn elevated() -> Option<bool> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo handle needs no closing; `token` receives a handle closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0u32;
    // SAFETY: the buffer is a TOKEN_ELEVATION and its size is passed with it.
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    // SAFETY: the handle came from OpenProcessToken and is closed once.
    unsafe { CloseHandle(token) };
    (read != 0).then_some(elevation.TokenIsElevated != 0)
}

fn scan_places(windows: &Path) -> (Vec<Place>, Vec<DumpFile>) {
    let mut places = Vec::new();
    let mut dumps = Vec::new();
    for (name, live) in [
        ("Minidump", false),
        ("MEMORY.DMP", false),
        ("LiveKernelReports", true),
    ] {
        let path = windows.join(name);
        let state = match fs::metadata(&path) {
            Err(error) => state_of(&error),
            Ok(metadata) if metadata.is_file() => {
                dumps.push(open_dump(path.clone(), live));
                PlaceState::Listed { cut: false }
            }
            Ok(_) => {
                let mut files = Vec::new();
                let mut walk = Walk::new(None);
                let state = match list_dumps(&path, 0, MAX_FILES, &mut files, &mut walk) {
                    Ok(()) => PlaceState::Listed { cut: walk.cut },
                    Err(error) => state_of(&error),
                };
                dumps.extend(files.into_iter().map(|file| open_dump(file, live)));
                state
            }
        };
        places.push(Place { path, state });
    }
    (places, dumps)
}

fn state_of(error: &io::Error) -> PlaceState {
    match error.kind() {
        io::ErrorKind::NotFound => PlaceState::Missing,
        io::ErrorKind::PermissionDenied => PlaceState::Denied,
        _ => PlaceState::Failed(error.to_string()),
    }
}

/// The most folder entries one listing looks at, dump files or not, so a folder holding
/// many other files cannot hold a check up.
pub(crate) const MAX_ENTRIES: usize = 20_000;

/// What one listing of a dump folder may spend: `MAX_ENTRIES` folder entries looked at,
/// dump files or not, and folders followed `MAX_DEPTH` deep; nothing held but the paths of
/// the dump files, at most the listing's own limit of them; no clock, since it ends when
/// its flag is set.
pub(crate) const LIMITS: budget::Limits = budget::Limits {
    what: "the listing of the dump folder",
    unit: "folder entries",
    count: MAX_ENTRIES as u64,
    bytes: u64::MAX,
    memory: u64::MAX,
    depth: MAX_DEPTH as u32,
    nested: "folders",
    time: None,
};

/// One listing: its budget, and whether it was cut.
pub(crate) struct Walk<'a> {
    pub(crate) budget: Budget<'a>,
    /// The listing ended at a limit, left out folders past its depth, or was stopped, before
    /// its folders were read through.
    pub(crate) cut: bool,
}

impl<'a> Walk<'a> {
    pub(crate) fn new(stop: Option<&'a AtomicBool>) -> Self {
        Self {
            budget: Budget::new(LIMITS, stop),
            cut: false,
        }
    }
}

/// `*.dmp` files under `folder`, `limit` in all, within the walk's budget; the walk is
/// marked cut when any limit, the depth included, left something out.
pub(crate) fn list_dumps(
    folder: &Path,
    depth: usize,
    limit: usize,
    files: &mut Vec<PathBuf>,
    walk: &mut Walk<'_>,
) -> io::Result<()> {
    let full = list_within(folder, depth, limit, files, &mut walk.budget)?;
    let b = &walk.budget;
    walk.cut |= full || b.hit().is_some() || b.spent().too_deep > 0;
    Ok(())
}

/// The listing itself, within `budget`: true when it ended at `limit` dump files.
pub(crate) fn list_within(
    folder: &Path,
    depth: usize,
    limit: usize,
    files: &mut Vec<PathBuf>,
    budget: &mut Budget<'_>,
) -> io::Result<bool> {
    for entry in fs::read_dir(folder)? {
        if files.len() >= limit {
            return Ok(true);
        }
        if budget.item().is_err() {
            break;
        }
        let Ok(entry) = entry else { continue };
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if kind.is_dir() {
            // A folder past the depth is counted as left out; a denied subfolder leaves
            // the rest of the listing intact.
            if budget.within_depth(depth + 1) {
                if let Ok(true) = list_within(&path, depth + 1, limit, files, budget) {
                    return Ok(true);
                }
            }
        } else if kind.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("dmp"))
        {
            files.push(path);
        }
    }
    Ok(false)
}

fn open_dump(path: PathBuf, live: bool) -> DumpFile {
    let metadata = fs::metadata(&path).ok();
    let size = metadata.as_ref().map_or(0, |metadata| metadata.len());
    let modified = metadata.and_then(|metadata| metadata.modified().ok());
    let reading = match fs::File::open(&path) {
        Ok(mut file) => Ok(dump::read(&mut file, size)),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            Err("needs administrator rights".into())
        }
        Err(error) => Err(error.to_string()),
    };
    DumpFile {
        path,
        size,
        modified,
        live,
        reading,
    }
}

/// One stop to report: an event, a dump file, or both.
struct Stop<'a> {
    time: SystemTime,
    event: Option<&'a StopEvent>,
    dump: Option<&'a DumpFile>,
}

impl Stop<'_> {
    fn code(&self) -> Option<(u32, [u64; 4])> {
        self.event.and_then(|event| event.stop).or_else(|| {
            self.dump
                .and_then(DumpFile::header)
                .map(|header| (header.code, header.parameters))
        })
    }
}

/// Pairs each stop event with the dump holding the same stop, nearest in time; dumps in
/// the range with no event become stops of their own.
fn pair<'a>(events: &'a [StopEvent], dumps: &'a [DumpFile], since: SystemTime) -> Vec<Stop<'a>> {
    let mut used = vec![false; dumps.len()];
    let mut stops = Vec::new();
    for event in events {
        let mut best: Option<(usize, Duration)> = None;
        if let Some((code, parameters)) = event.stop {
            for (index, file) in dumps.iter().enumerate() {
                let same = file
                    .header()
                    .is_some_and(|header| header.code == code && header.parameters == parameters);
                if used[index] || file.live || !same {
                    continue;
                }
                let gap = file
                    .time()
                    .map_or(Duration::MAX, |time| distance(time, event.time));
                if best.is_none_or(|(_, nearest)| gap < nearest) {
                    best = Some((index, gap));
                }
            }
        }
        if let Some((index, _)) = best {
            used[index] = true;
        }
        stops.push(Stop {
            time: event.time,
            event: Some(event),
            dump: best.map(|(index, _)| &dumps[index]),
        });
    }
    for (index, file) in dumps.iter().enumerate() {
        if used[index] || file.header().is_none() {
            continue;
        }
        if let Some(time) = file.time().filter(|&time| time >= since) {
            stops.push(Stop {
                time,
                event: None,
                dump: Some(file),
            });
        }
    }
    stops.sort_by_key(|stop| std::cmp::Reverse(stop.time));
    stops
}

fn distance(a: SystemTime, b: SystemTime) -> Duration {
    a.duration_since(b)
        .or_else(|_| b.duration_since(a))
        .unwrap_or_default()
}

fn report(reading: &Reading) -> String {
    let since = reading.now - DAY * reading.days as u32;
    let mut lines = vec![format!(
        "Stop errors (blue screens) in the past {} days, newest first.",
        reading.days
    )];
    lines.push(match reading.elevated {
        Some(true) => "Running with administrator rights: yes.".into(),
        Some(false) => {
            "Running with administrator rights: no; dump folders usually need them.".into()
        }
        None => "Running with administrator rights: unknown.".into(),
    });
    let no_events = Vec::new();
    let stop_events = reading
        .events
        .as_ref()
        .map_or(&no_events, |events| &events.stops);
    let stops = pair(stop_events, &reading.dumps, since);
    if stops.is_empty() {
        lines.push("No stop errors found in the event log or in readable dump files.".into());
    }
    let (mut crash, mut live) = (0, 0);
    for stop in stops.iter().take(MAX_STOPS_LISTED) {
        lines.push(String::new());
        let when = clock::local(stop.time).long();
        lines.push(if stop.dump.is_some_and(|file| file.live) {
            live += 1;
            format!("Live kernel report {live}: {when} (Windows recovered; no restart)")
        } else {
            crash += 1;
            format!("Stop {crash}: {when}")
        });
        describe_stop(stop, reading, &mut lines);
    }
    if stops.len() > MAX_STOPS_LISTED {
        lines.push(format!(
            "{} older stops not listed.",
            stops.len() - MAX_STOPS_LISTED
        ));
    }
    lines.push(String::new());
    lines.push("Dump places:".into());
    for place in &reading.places {
        describe_place(place, reading, since, &mut lines);
    }
    lines.push(String::new());
    match &reading.events {
        Ok(events) => describe_events(events, reading.days, &mut lines),
        Err(reason) => lines.push(format!(
            "Event log: {reason}; stop events and unclean restarts could not be counted."
        )),
    }
    lines.join("\n")
}

/// The same readings as `report`, as JSON.
fn report_json(reading: &Reading) -> Value {
    let since = reading.now - DAY * reading.days as u32;
    let no_events = Vec::new();
    let stop_events = reading
        .events
        .as_ref()
        .map_or(&no_events, |events| &events.stops);
    let stops = pair(stop_events, &reading.dumps, since);
    json!({
        "tool": "crashes",
        "days": reading.days,
        "administrator_rights": reading.elevated,
        "stops": stops.iter().take(MAX_STOPS_LISTED).map(|stop| stop_json(stop, reading)).collect::<Vec<_>>(),
        "stops_not_listed": stops.len().saturating_sub(MAX_STOPS_LISTED),
        "dump_places": reading.places.iter().map(|place| place_json(place, reading, since)).collect::<Vec<_>>(),
        "event_log": match &reading.events {
            Ok(events) => events_json(events, reading.days),
            Err(reason) => super::events::unavailable(reason),
        },
    })
}

fn stop_json(stop: &Stop, reading: &Reading) -> Value {
    let live = stop.dump.is_some_and(|file| file.live);
    let source = match (stop.event.is_some(), stop.dump.is_some()) {
        (true, true) => "event_1001_and_dump_file",
        (true, false) => "event_1001",
        _ => "dump_file",
    };
    let code = stop.code().map(|(code, parameters)| {
        let known = codes::find(code);
        let pointer = points_at(stop, known, &parameters).map(|pointer| {
            let (result, driver) = match &pointer.result {
                PointsAt::ZeroAddress => ("address_is_zero", None),
                PointsAt::Driver(name) => ("driver", Some(name.clone())),
                PointsAt::NoDriver => ("no_driver_holds_address", None),
                PointsAt::NoDriverList => ("driver_list_not_available", None),
            };
            json!({
                "parameter": pointer.parameter,
                "address": format!("0x{:X}", pointer.address),
                "result": result,
                "driver": driver,
                "basis": NOTE,
            })
        });
        json!({
            "code": format!("0x{code:08X}"),
            "name": known.map(|entry| entry.name),
            "meaning": known.map(|entry| entry.meaning),
            "parameters": parameters.iter().map(|value| format!("0x{value:X}")).collect::<Vec<_>>(),
            "points_at": pointer,
        })
    });
    let dump_file = match (
        stop.dump,
        stop.event.and_then(|event| event.path.as_deref()),
    ) {
        (Some(file), _) => Some(dump_file_json(file)),
        (None, Some(path)) => Some(json!({
            "path": path,
            "named_by_event": true,
            "status": named_file_status(path, reading),
        })),
        (None, None) => None,
    };
    json!({
        "time": rfc3339(stop.time),
        "kind": if live { "live_kernel_report" } else { "stop" },
        "stop": code,
        "stop_text_unreadable": code_missing(stop),
        "dump_file": dump_file,
        "recorded_by": source,
    })
}

fn code_missing(stop: &Stop) -> bool {
    stop.code().is_none()
}

fn dump_file_json(file: &DumpFile) -> Value {
    let mut value = json!({
        "path": file.path.display().to_string(),
        "size_bytes": file.size,
        "written": file.modified.map(rfc3339),
    });
    match &file.reading {
        Ok(Dump::Kernel64 { header, drivers }) => {
            value["dump_type"] = dump::dump_type_name(header.dump_type).into();
            value["machine"] = machine_name(header.machine).into();
            value["processors"] = header.processors.into();
            value["windows_build"] = header.build.into();
            value["drivers"] = match drivers {
                Drivers::Read { list, skipped } => {
                    json!({ "listed": list.len(), "unreadable_entries": skipped })
                }
                Drivers::Unreadable(reason) => super::events::unavailable(reason),
                Drivers::NotTriage => json!({ "listed": null }),
            };
        }
        Ok(Dump::Unreadable(reason)) | Err(reason) => {
            value["unavailable"] = reason.clone().into();
        }
    }
    value
}

fn place_json(place: &Place, reading: &Reading, since: SystemTime) -> Value {
    let path = place.path.display().to_string();
    let cut = match &place.state {
        PlaceState::Missing => return json!({ "path": path, "state": "not_present" }),
        PlaceState::Denied => {
            return json!({ "path": path, "state": "unavailable", "unavailable": "needs administrator rights" })
        }
        PlaceState::Failed(reason) => {
            return json!({ "path": path, "state": "unavailable", "unavailable": reason })
        }
        PlaceState::Listed { cut } => *cut,
    };
    let files: Vec<&DumpFile> = reading
        .dumps
        .iter()
        .filter(|file| file.path.starts_with(&place.path))
        .collect();
    let read = files.iter().filter(|file| file.header().is_some()).count();
    let in_range = files
        .iter()
        .filter(|file| file.header().is_some() && file.time().is_some_and(|time| time >= since))
        .count();
    let unread: Vec<Value> = files
        .iter()
        .filter_map(|file| match &file.reading {
            Err(reason) | Ok(Dump::Unreadable(reason)) => Some(json!({
                "path": file.path.display().to_string(),
                "size_bytes": file.size,
                "written": file.modified.map(rfc3339),
                "unavailable": reason,
            })),
            Ok(Dump::Kernel64 { .. }) => None,
        })
        .collect();
    json!({
        "path": path,
        "state": "listed",
        "files": files.len(),
        "read": read,
        "in_range": in_range,
        "listing_cut_at": cut.then_some(MAX_FILES),
        "not_read": unread,
    })
}

fn events_json(events: &EventReading, days: u64) -> Value {
    let unparsed = events
        .stops
        .iter()
        .filter(|stop| stop.stop.is_none())
        .count();
    let unexplained = events
        .restarts
        .iter()
        .filter(|&&restart| {
            !events
                .stops
                .iter()
                .any(|stop| distance(stop.time, restart) <= RESTART_WINDOW)
        })
        .count();
    json!({
        "days_requested": days,
        "days_read": events.days,
        "logs_read": events.reads.iter().map(|read| json!({
            "log": read.log,
            "events_read": read.events,
            "stopped_at_limit": read.limit.map(limit_name),
            "unavailable": read.unavailable,
        })).collect::<Vec<_>>(),
        "stop_events": events.stops.len(),
        "stop_events_unreadable": unparsed,
        "unclean_restarts": events.restarts.len(),
        "unclean_restarts_without_stop_event": unexplained,
        "dump_setup_failures": {
            "count": events.dump_failures.len(),
            "last": events.dump_failures.iter().max().map(|time| rfc3339(*time)),
        },
    })
}

fn describe_stop(stop: &Stop, reading: &Reading, lines: &mut Vec<String>) {
    let Some((code, parameters)) = stop.code() else {
        lines.push("  Code: event 1001 recorded a stop, but its text could not be read.".into());
        describe_dump_file(stop, reading, lines);
        return;
    };
    let known = codes::find(code);
    lines.push(match known {
        Some(entry) => format!("  Code: 0x{code:08X} {}", entry.name),
        None => format!("  Code: 0x{code:08X} (not in this tool's table of common codes)"),
    });
    if let Some(entry) = known {
        lines.push(format!("  Meaning: {}", entry.meaning));
    }
    let shown: Vec<String> = parameters
        .iter()
        .map(|value| format!("0x{value:X}"))
        .collect();
    lines.push(format!("  Parameters: {}", shown.join(", ")));
    describe_dump_file(stop, reading, lines);
    let Some(pointer) = points_at(stop, known, &parameters) else {
        return;
    };
    let (position, address) = (pointer.parameter, pointer.address);
    lines.push(match &pointer.result {
        PointsAt::ZeroAddress => format!(
            "  Points at: unknown; parameter {position} (the failing code's address) is zero."
        ),
        PointsAt::Driver(name) => format!(
            "  Points at: {name} (parameter {position}, 0x{address:X}, lies inside it), {NOTE}."
        ),
        PointsAt::NoDriver => format!(
            "  Points at: no driver in the dump's list holds parameter {position} (0x{address:X}), {NOTE}."
        ),
        PointsAt::NoDriverList => format!(
            "  Points at: unknown; parameter {position} (0x{address:X}) is the failing code's address, and only a small dump's driver list can name its driver."
        ),
    });
}

enum PointsAt {
    ZeroAddress,
    Driver(String),
    NoDriver,
    NoDriverList,
}

struct Pointer {
    parameter: usize,
    address: u64,
    result: PointsAt,
}

/// The driver the failing code's address lies in, for codes that document that parameter.
fn points_at(
    stop: &Stop,
    known: Option<&codes::StopCode>,
    parameters: &[u64; 4],
) -> Option<Pointer> {
    let position = known?.code_address?;
    let address = parameters[position - 1];
    let list = match stop.dump.and_then(DumpFile::drivers) {
        Some(Drivers::Read { list, .. }) => Some(list),
        _ => None,
    };
    let result = match (address, list) {
        (0, _) => PointsAt::ZeroAddress,
        (_, Some(list)) => match dump::driver_at(list, address) {
            Some(driver) => PointsAt::Driver(events::redact(&driver.name, &[])),
            None => PointsAt::NoDriver,
        },
        (_, None) => PointsAt::NoDriverList,
    };
    Some(Pointer {
        parameter: position,
        address,
        result,
    })
}

fn machine_name(machine: u32) -> String {
    match machine {
        0x8664 => "x64".into(),
        0xAA64 => "ARM64".into(),
        other => format!("machine type 0x{other:X}"),
    }
}

fn describe_dump_file(stop: &Stop, reading: &Reading, lines: &mut Vec<String>) {
    let source = match (stop.event.is_some(), stop.dump.is_some()) {
        (true, true) => "event 1001 and the dump file",
        (true, false) => "event 1001",
        _ => "the dump file",
    };
    if let Some(file) = stop.dump {
        let mut text = format!(
            "  Dump file: {}, {}",
            file.path.display(),
            size_text(file.size)
        );
        if let Ok(Dump::Kernel64 { header, drivers }) = &file.reading {
            text.push_str(&format!(
                ", {}, {}, {} processors, Windows build {}",
                dump::dump_type_name(header.dump_type),
                machine_name(header.machine),
                header.processors,
                header.build
            ));
            match drivers {
                Drivers::Read { list, skipped } => {
                    text.push_str(&format!(", {} drivers listed", list.len()));
                    if *skipped > 0 {
                        text.push_str(&format!(" ({skipped} entries unreadable)"));
                    }
                }
                Drivers::Unreadable(reason) => {
                    text.push_str(&format!(", driver list not read: {reason}"));
                }
                Drivers::NotTriage => {}
            }
        }
        lines.push(text);
    } else if let Some(path) = stop.event.and_then(|event| event.path.as_deref()) {
        lines.push(format!(
            "  Dump file: {path} (named by the event); {}.",
            named_file_status(path, reading)
        ));
    } else {
        lines.push("  Dump file: none named.".into());
    }
    lines.push(format!("  Recorded by: {source}."));
}

fn same_path(a: &Path, b: &Path) -> bool {
    a.to_string_lossy()
        .eq_ignore_ascii_case(&b.to_string_lossy())
}

/// Why the dump an event names is not paired with it.
fn named_file_status(path: &str, reading: &Reading) -> String {
    let wanted = Path::new(path);
    if let Some(file) = reading
        .dumps
        .iter()
        .find(|file| same_path(&file.path, wanted))
    {
        return match &file.reading {
            Err(reason) | Ok(Dump::Unreadable(reason)) => format!("not read: {reason}"),
            Ok(Dump::Kernel64 { .. }) => "the file there now holds a different stop".into(),
        };
    }
    let place = reading.places.iter().find(|place| {
        same_path(&place.path, wanted)
            || wanted
                .parent()
                .is_some_and(|parent| same_path(&place.path, parent))
    });
    match place.map(|place| &place.state) {
        Some(PlaceState::Denied) => "not read: needs administrator rights".into(),
        Some(PlaceState::Failed(reason)) => format!("not read: {reason}"),
        Some(PlaceState::Listed { cut: true }) => "not among the files listed".into(),
        Some(_) => "no longer present".into(),
        None => "not read: outside the dump places this tool lists".into(),
    }
}

fn describe_place(place: &Place, reading: &Reading, since: SystemTime, lines: &mut Vec<String>) {
    let label = place.path.display();
    let cut = match &place.state {
        PlaceState::Missing => return lines.push(format!("  {label}: not present.")),
        PlaceState::Denied => return lines.push(format!("  {label}: needs administrator rights.")),
        PlaceState::Failed(reason) => {
            return lines.push(format!("  {label}: could not be read: {reason}."))
        }
        PlaceState::Listed { cut } => *cut,
    };
    let files: Vec<&DumpFile> = reading
        .dumps
        .iter()
        .filter(|file| file.path.starts_with(&place.path))
        .collect();
    if files.is_empty() {
        return lines.push(format!("  {label}: no dump files."));
    }
    let read = files.iter().filter(|file| file.header().is_some()).count();
    let in_range = files
        .iter()
        .filter(|file| file.header().is_some() && file.time().is_some_and(|time| time >= since))
        .count();
    let mut text = format!(
        "  {label}: {} {}, {read} read, {in_range} of them in the range",
        files.len(),
        if files.len() == 1 {
            "dump file"
        } else {
            "dump files"
        },
    );
    if cut {
        text.push_str(&format!("; listing stopped at {MAX_FILES} files"));
    }
    text.push('.');
    lines.push(text);
    for file in files {
        let reason = match &file.reading {
            Err(reason) | Ok(Dump::Unreadable(reason)) => reason,
            Ok(Dump::Kernel64 { .. }) => continue,
        };
        let written = file
            .modified
            .map(|time| format!(", written {}", clock::local(time).long()))
            .unwrap_or_default();
        lines.push(format!(
            "    {}: {}{written}; not read: {reason}.",
            file.path.display(),
            size_text(file.size)
        ));
    }
}

pub(crate) fn describe_events(events: &EventReading, days: u64, lines: &mut Vec<String>) {
    if days > events.days {
        lines.push(format!(
            "Event log: read for the past {} days only (the event engine's limit); dump files cover all {days}.",
            events.days
        ));
    }
    for read in &events.reads {
        match (&read.unavailable, read.limit) {
            (Some(reason), _) => {
                lines.push(format!("Event log {}: unavailable, {reason}.", read.log))
            }
            (None, Some(Limit::Count)) => lines.push(format!(
                "Event log {}: newest {} events read; older ones were not.",
                read.log, read.events
            )),
            (None, Some(Limit::Time)) => lines.push(format!(
                "Event log {}: {} events read before the time limit; older ones were not.",
                read.log, read.events
            )),
            (None, None) => {}
        }
    }
    let unparsed = events
        .stops
        .iter()
        .filter(|stop| stop.stop.is_none())
        .count();
    let mut text = format!(
        "Stop events (1001) in the past {} days: {}",
        events.days,
        events.stops.len()
    );
    if unparsed > 0 {
        text.push_str(&format!(", {unparsed} whose text could not be read"));
    }
    text.push('.');
    lines.push(text);
    let unexplained = events
        .restarts
        .iter()
        .filter(|&&restart| {
            !events
                .stops
                .iter()
                .any(|stop| distance(stop.time, restart) <= RESTART_WINDOW)
        })
        .count();
    let mut text = format!(
        "Unclean restarts (Kernel-Power 41) in the past {} days: {}",
        events.days,
        events.restarts.len()
    );
    if !events.restarts.is_empty() {
        text.push_str(&format!(
            "; {unexplained} with no stop event within 15 minutes, so no stop was recorded for them (power loss, a hang, a held power button, or a stop that could not be written)"
        ));
    }
    text.push('.');
    lines.push(text);
    if let Some(last) = events.dump_failures.iter().max() {
        lines.push(format!(
            "Crash dump setup failed (volmgr 45, 46 or 161) {} times in the past {} days, last on {}: a stop error on this PC may leave no dump file.",
            events.dump_failures.len(),
            events.days,
            clock::local(*last).long()
        ));
    }
}

fn size_text(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    if bytes >= 1024 * MIB {
        format!("{:.1} GiB", bytes as f64 / (1024 * MIB) as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else {
        format!("{} KiB", bytes.div_ceil(1024))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::UNIX_EPOCH;

    /// The guard: a dump listing looks at a bounded number of entries, dump files or not,
    /// and ends at once when its flag is set; either way it says it was cut. Closing the
    /// crash dump window waits for a set up or put back, never for a check's listing.
    #[test]
    fn a_dump_listing_is_bounded_and_stops_when_asked() {
        let base = std::env::temp_dir().join(format!("dump-walk-{}", std::process::id()));
        fs::create_dir(&base).unwrap();
        let names: Vec<String> = (0..10).map(|i| format!("other-{i}.txt")).collect();
        for name in &names {
            fs::write(base.join(name), b"x").unwrap();
        }
        fs::write(base.join("zz.dmp"), b"x").unwrap();
        let mut files = Vec::new();
        let mut walk = Walk::new(None);
        list_dumps(&base, 0, 100, &mut files, &mut walk).unwrap();
        assert_eq!((files.len(), walk.cut), (1, false));
        let mut files = Vec::new();
        let mut walk = Walk {
            budget: Budget::new(budget::Limits { count: 5, ..LIMITS }, None),
            cut: false,
        };
        list_dumps(&base, 0, 100, &mut files, &mut walk).unwrap();
        assert!(
            walk.cut && walk.budget.spent().count == 5,
            "the bound did not end it"
        );
        let stop = AtomicBool::new(true);
        let mut files = Vec::new();
        let mut walk = Walk::new(Some(&stop));
        list_dumps(&base, 0, 100, &mut files, &mut walk).unwrap();
        assert!(walk.cut && files.is_empty() && walk.budget.spent().count == 0);
        // Folders past the depth are left out and the listing is marked cut.
        let mut deep = base.clone();
        for d in 0..=MAX_DEPTH {
            deep = deep.join(format!("d{d}"));
        }
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("deep.dmp"), b"x").unwrap();
        let mut files = Vec::new();
        let mut walk = Walk::new(None);
        list_dumps(&base, 0, 100, &mut files, &mut walk).unwrap();
        assert_eq!((files.len(), walk.cut), (1, true));
        assert_eq!(
            walk.budget.said().unwrap(),
            "1 of its folders lay more than 3 deep and was not followed."
        );
        fs::remove_file(deep.join("deep.dmp")).unwrap();
        let mut deep = deep.as_path();
        while deep != base {
            fs::remove_dir(deep).unwrap();
            deep = deep.parent().unwrap();
        }
        for name in &names {
            fs::remove_file(base.join(name)).unwrap();
        }
        fs::remove_file(base.join("zz.dmp")).unwrap();
        fs::remove_dir(&base).unwrap();

        let view = include_str!("../gui/crashdump_view.rs");
        let drop = &view[view.find("impl Drop for CrashDumpView {").unwrap()..];
        let drop = &drop[..drop.find("\n}\n").unwrap()];
        assert!(
            drop.contains("if running.wait_on_close {\n                    let _ = worker.join();")
        );
        assert!(view.contains("self.start(false, |progress, cancel| {\n            Done::Check("));
        let readiness = include_str!("crash_dumps/readiness.rs");
        assert!(readiness.contains("r.m.dumps(&path, options.max_files as usize, r.stop)"));
        assert!(readiness.contains("stop: Some(cancel),"));
    }

    const ENGLISH: &str = "The computer has rebooted from a bugcheck. The bugcheck was: 0x00000116 (0xffffe000c2c404c0, 0xfffff8016470c14c, 0xffffffffc000009a, 0x0000000000000004). A dump was saved in: C:\\WINDOWS\\Minidump\\110326-9640-01.dmp. Report Id: 0d4c3b2a-1111-2222-3333-444455556666.";
    const PARAMETERS: [u64; 4] = [
        0xffffe000c2c404c0,
        0xfffff8016470c14c,
        0xffffffffc000009a,
        4,
    ];

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn event(provider: &str, id: u32, seconds: u64, message: Option<&str>) -> Event {
        Event {
            log: "System".into(),
            provider: provider.into(),
            id,
            level: 2,
            time: at(seconds),
            message: message.map(Into::into),
        }
    }

    #[test]
    fn an_english_message_gives_code_parameters_and_path() {
        assert_eq!(parse_stop(ENGLISH), Some((0x116, PARAMETERS)));
        assert_eq!(
            dump_path(ENGLISH).as_deref(),
            Some("C:\\WINDOWS\\Minidump\\110326-9640-01.dmp")
        );
    }

    #[test]
    fn a_localised_message_still_gives_the_numbers() {
        let german = "Der Computer wurde nach einem schwerwiegenden Fehler neu gestartet. Der Fehler war: 0x0000009f (0x0000000000000003, 0xffffb00123456789, 0xfffff80112345678, 0xffffb00198765432). Ein Speicherabbild wurde gespeichert in: D:\\Abbilder\\MEMORY.DMP. Bericht-ID: x.";
        assert_eq!(parse_stop(german).unwrap().0, 0x9F);
        assert_eq!(
            dump_path(german).as_deref(),
            Some("D:\\Abbilder\\MEMORY.DMP")
        );
    }

    #[test]
    fn a_malformed_message_gives_nothing() {
        for text in [
            "",
            "The bugcheck was: 0x0000009f (0x3, 0x4). No dump.",
            "The bugcheck was: 0x (0x1, 0x2, 0x3, 0x4).",
            "Code 0x123456789 (0x1, 0x2, 0x3, 0x4)",
            "%1",
        ] {
            assert_eq!(parse_stop(text), None, "{text}");
        }
        assert_eq!(dump_path("A dump was saved in: %2."), None);
    }

    fn file(bytes: Vec<u8>, path: &str, live: bool) -> DumpFile {
        let size = bytes.len() as u64;
        DumpFile {
            path: PathBuf::from(path),
            size,
            modified: Some(at(1_793_707_300)),
            live,
            reading: Ok(dump::read(&mut Cursor::new(bytes), size)),
        }
    }

    fn reading(found: &[Event], dumps: Vec<DumpFile>, denied: bool) -> Reading {
        let places = [
            "C:\\WINDOWS\\Minidump",
            "C:\\WINDOWS\\MEMORY.DMP",
            "C:\\WINDOWS\\LiveKernelReports",
        ]
        .into_iter()
        .map(|path| Place {
            path: PathBuf::from(path),
            state: if denied {
                PlaceState::Denied
            } else {
                PlaceState::Listed { cut: false }
            },
        })
        .collect();
        Reading {
            days: 90,
            now: at(1_794_000_000),
            elevated: Some(false),
            events: Ok(sort_events(90, found, Vec::new())),
            places,
            dumps,
        }
    }

    #[test]
    fn failed_crash_dump_setup_is_reported_with_its_last_time() {
        let found = [
            event(VOLMGR, 46, 1_793_900_000, None),
            event(VOLMGR, 45, 1_793_800_000, None),
            event(VOLMGR, 99, 1_793_700_000, None),
            event(WER, 45, 1_793_600_000, None),
        ];
        let text = report(&reading(&found, Vec::new(), true));
        let expected = format!(
            "Crash dump setup failed (volmgr 45, 46 or 161) 2 times in the past 90 days, last on {}: a stop error on this PC may leave no dump file.",
            clock::local(at(1_793_900_000)).long()
        );
        assert!(text.contains(&expected), "{text}");
        let quiet = report(&reading(&[], Vec::new(), true));
        assert!(!quiet.contains("Crash dump setup failed"), "{quiet}");
    }

    #[test]
    fn an_event_and_its_small_dump_name_the_driver() {
        let drivers = [
            ("ntoskrnl.exe", 0xFFFF_F802_4000_0000, 0x0104_5000),
            ("nvlddmkm.sys", 0xFFFF_F801_63EC_0000, 0x00AE_7000),
        ];
        let small = dump::tests::triage(0x116, PARAMETERS, &drivers, 0x90);
        let found = [
            event(WER, 1001, 1_793_707_400, Some(ENGLISH)),
            event(KERNEL_POWER, 41, 1_793_707_380, None),
            event(KERNEL_POWER, 41, 1_793_000_000, None),
        ];
        let dumps = vec![file(
            small,
            "C:\\WINDOWS\\Minidump\\110326-9640-01.dmp",
            false,
        )];
        let text = report(&reading(&found, dumps, false));
        for expected in [
            "Stop 1: ",
            "Code: 0x00000116 VIDEO_TDR_FAILURE",
            "Parameters: 0xFFFFE000C2C404C0, 0xFFFFF8016470C14C, 0xFFFFFFFFC000009A, 0x4",
            "small memory dump, x64, 16 processors, Windows build 26100, 2 drivers listed",
            "Points at: nvlddmkm.sys (parameter 2, 0xFFFFF8016470C14C, lies inside it)",
            NOTE,
            "Recorded by: event 1001 and the dump file.",
            "Minidump: 1 dump file, 1 read, 1 of them in the range.",
            "Unclean restarts (Kernel-Power 41) in the past 90 days: 2; 1 with no stop event",
        ] {
            assert!(text.contains(expected), "{expected}\n{text}");
        }
    }

    #[test]
    fn json_agrees_with_the_text_on_the_stop_and_its_driver() {
        let drivers = [("nvlddmkm.sys", 0xFFFF_F801_63EC_0000, 0x00AE_7000)];
        let small = dump::tests::triage(0x116, PARAMETERS, &drivers, 0x90);
        let found = [
            event(WER, 1001, 1_793_707_400, Some(ENGLISH)),
            event(KERNEL_POWER, 41, 1_793_000_000, None),
            event(VOLMGR, 46, 1_793_900_000, None),
        ];
        let dumps = vec![file(
            small,
            "C:\\WINDOWS\\Minidump\\110326-9640-01.dmp",
            false,
        )];
        let reading = reading(&found, dumps, false);
        let (text, data) = (report(&reading), report_json(&reading));
        let stop = &data["stops"][0];
        assert_eq!(stop["stop"]["code"], "0x00000116");
        assert_eq!(stop["stop"]["name"], "VIDEO_TDR_FAILURE");
        assert_eq!(stop["stop"]["points_at"]["driver"], "nvlddmkm.sys");
        assert_eq!(stop["stop"]["points_at"]["parameter"], 2);
        assert_eq!(stop["recorded_by"], "event_1001_and_dump_file");
        assert_eq!(stop["time"], rfc3339(at(1_793_707_400)));
        assert!(text.contains("Code: 0x00000116 VIDEO_TDR_FAILURE"));
        assert!(text.contains("Points at: nvlddmkm.sys"));
        assert_eq!(stop["dump_file"]["windows_build"], 26100);
        assert!(stop["dump_file"]["size_bytes"].as_u64().unwrap() > 0);
        assert_eq!(data["event_log"]["unclean_restarts"], 1);
        assert_eq!(data["event_log"]["dump_setup_failures"]["count"], 1);
        assert_eq!(data["dump_places"][0]["files"], 1);
    }

    #[test]
    fn json_says_denied_places_and_unreadable_events() {
        let found = [event(WER, 1001, 1_793_600_000, Some("garbled"))];
        let mut reading = reading(&found, Vec::new(), true);
        let data = report_json(&reading);
        assert_eq!(data["dump_places"][0]["state"], "unavailable");
        assert_eq!(
            data["dump_places"][0]["unavailable"],
            "needs administrator rights"
        );
        assert_eq!(data["stops"][0]["stop_text_unreadable"], true);
        assert_eq!(data["event_log"]["stop_events_unreadable"], 1);
        reading.events = Err("the log could not be opened".into());
        let data = report_json(&reading);
        assert_eq!(
            data["event_log"]["unavailable"],
            "the log could not be opened"
        );
    }

    #[test]
    fn denied_places_and_an_unreadable_message_are_said_plainly() {
        let found = [
            event(WER, 1001, 1_793_707_400, Some(ENGLISH)),
            event(WER, 1001, 1_793_600_000, Some("garbled")),
            event(WER, 1001, 1_793_500_000, None),
        ];
        let text = report(&reading(&found, Vec::new(), true));
        for expected in [
            "C:\\WINDOWS\\Minidump: needs administrator rights.",
            "(named by the event); not read: needs administrator rights.",
            "Points at: unknown; parameter 2 (0xFFFFF8016470C14C)",
            "Stop events (1001) in the past 90 days: 3, 2 whose text could not be read.",
            "Unclean restarts (Kernel-Power 41) in the past 90 days: 0.",
            "Running with administrator rights: no",
        ] {
            assert!(text.contains(expected), "{expected}\n{text}");
        }
        assert_eq!(
            text.matches("recorded a stop, but its text could not be read")
                .count(),
            2
        );
    }

    #[test]
    fn dumps_without_events_and_live_reports_are_listed_newest_first() {
        let parameters = [0xFFFF_0000_0000_0090, 0, 0xFFFF_F802_40D3_22F9, 2];
        let full = dump::tests::header(0x50, parameters, 2);
        let live = dump::tests::header(0x141, [0, 0xFFFF_F801_6470_C14C, 0, 0], 6);
        let mut thirty_two = full.clone();
        thirty_two[4..8].copy_from_slice(b"DUMP");
        let mut old_live = file(
            live.clone(),
            "C:\\WINDOWS\\LiveKernelReports\\WATCHDOG\\b.dmp",
            true,
        );
        if let Ok(Dump::Kernel64 { header, .. }) = &mut old_live.reading {
            header.time = Some(at(1_700_000_000));
        }
        let dumps = vec![
            file(full, "C:\\WINDOWS\\MEMORY.DMP", false),
            file(
                live,
                "C:\\WINDOWS\\LiveKernelReports\\WATCHDOG\\a.dmp",
                true,
            ),
            file(thirty_two, "C:\\WINDOWS\\Minidump\\old.dmp", false),
            old_live,
        ];
        let text = report(&reading(&[], dumps, false));
        for expected in [
            "Stop 1: ",
            "Live kernel report 1: ",
            "VIDEO_ENGINE_TIMEOUT_DETECTED",
            "Points at: unknown; parameter 3 (0xFFFFF80240D322F9)",
            "Recorded by: the dump file.",
            "old.dmp: 8 KiB",
            "not read: a 32-bit kernel dump",
            "LiveKernelReports: 2 dump files, 2 read, 1 of them in the range.",
        ] {
            assert!(text.contains(expected), "{expected}\n{text}");
        }
        assert_eq!(text.matches("Live kernel report ").count(), 1, "{text}");
    }

    #[test]
    fn an_empty_pc_says_nothing_was_found() {
        let text = report(&reading(&[], Vec::new(), false));
        assert!(text.contains("No stop errors found"), "{text}");
        assert!(text.contains("Minidump: no dump files."), "{text}");
    }

    #[test]
    fn days_beyond_the_event_limit_are_said() {
        let mut reading = reading(&[], Vec::new(), false);
        reading.days = 365;
        let limit = event_days(365);
        reading.events = Ok(sort_events(limit, &[], Vec::new()));
        let text = report(&reading);
        let said = format!("read for the past {limit} days only");
        assert_eq!(text.contains(&said), limit < 365, "{text}");
        reading.events = Ok(sort_events(30, &[], Vec::new()));
        let text = report(&reading);
        assert!(text.contains("read for the past 30 days only"), "{text}");
    }

    /// Reads this PC; passes whether it holds dumps, none, or denies the folders.
    #[test]
    fn live_reading_finishes_and_names_every_place() {
        let started = Instant::now();
        let args = Args::parse(&["--days".into(), "30".into()], TOOL.usage).unwrap();
        let output = run(&args).unwrap();
        let text = output.text;
        assert!(started.elapsed() < Duration::from_secs(15));
        let json =
            crate::tools::run("crashes", &["--days".into(), "30".into(), "--json".into()]).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["days"], 30);
        assert_eq!(parsed["dump_places"].as_array().unwrap().len(), 3);
        for place in ["Minidump", "MEMORY.DMP", "LiveKernelReports"] {
            assert!(text.contains(place), "{text}");
        }
        assert!(
            text.contains("Unclean restarts") || text.contains("Event log:"),
            "{text}"
        );
    }
}
