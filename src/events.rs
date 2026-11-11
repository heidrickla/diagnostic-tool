//! The event log engine. It reads Windows event logs in-process through the Event Log
//! API, groups events by log, source and event id, hides kinds listed in the noise
//! table and ranks the rest by known significance and recency. The survey's "Recent
//! system events" check and follow-up queries (`toolkit events`) use the same engine.
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_ACCESS_DENIED, ERROR_EVT_CHANNEL_NOT_FOUND, ERROR_EVT_INVALID_QUERY,
    ERROR_EVT_UNRESOLVED_PARAMETER_INSERT, ERROR_EVT_UNRESOLVED_VALUE_INSERT,
    ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT,
};
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtCreateRenderContext, EvtFormatMessage, EvtFormatMessageEvent, EvtNext,
    EvtOpenPublisherMetadata, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender,
    EvtRenderContextSystem, EvtRenderContextValues, EvtRenderEventValues, EvtSystemEventID,
    EvtSystemLevel, EvtSystemProviderName, EvtSystemTimeCreated, EvtVarTypeByte,
    EvtVarTypeFileTime, EvtVarTypeString, EvtVarTypeUInt16, EVT_HANDLE, EVT_VARIANT,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentThread, SetThreadPriority, THREAD_MODE_BACKGROUND_BEGIN, THREAD_MODE_BACKGROUND_END,
};

use crate::checks::{Finding, Grade, Outcome};
use crate::clock;

/// Raised whenever a noise rule is added, changed or removed; the report names it.
pub const NOISE_VERSION: u32 = 1;

/// How much a known kind of event matters for diagnosis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Worth a look when it recurs or matches a symptom.
    Notable,
    /// Points at a fault: unclean shutdowns, stop errors, hardware, drive and driver failures.
    Serious,
}

/// A kind of event with a known meaning. Providers match without regard to case.
#[derive(Debug, PartialEq)]
pub struct Known {
    pub providers: &'static [&'static str],
    pub ids: &'static [u32],
    pub tier: Tier,
    /// A few words for the window row.
    pub short: &'static str,
    /// One plain sentence for the report.
    pub meaning: &'static str,
}

pub const KNOWN: &[Known] = &[
    Known {
        providers: &["Microsoft-Windows-Kernel-Power"],
        ids: &[41],
        tier: Tier::Serious,
        short: "Unexpected restart",
        meaning: "Windows restarted without shutting down cleanly: power loss, a hang or a crash",
    },
    Known {
        providers: &["EventLog"],
        ids: &[6008],
        tier: Tier::Serious,
        short: "Unexpected shutdown",
        meaning: "the shutdown before this start was unexpected",
    },
    Known {
        providers: &["Microsoft-Windows-WER-SystemErrorReporting"],
        ids: &[1001],
        tier: Tier::Serious,
        short: "Blue screen",
        meaning: "Windows recovered from a stop error (blue screen)",
    },
    Known {
        providers: &["Microsoft-Windows-WHEA-Logger"],
        ids: &[1, 17, 18, 19, 20, 46, 47],
        tier: Tier::Serious,
        short: "Hardware error",
        meaning: "the processor, memory or PCIe bus reported a hardware error",
    },
    Known {
        providers: &["disk"],
        ids: &[7, 11, 51, 153, 154],
        tier: Tier::Serious,
        short: "Drive error",
        meaning: "a drive had read or write errors or a controller error",
    },
    Known {
        providers: &["disk"],
        ids: &[157],
        tier: Tier::Notable,
        short: "Drive removed",
        meaning: "Windows lost contact with a drive, as when it is unplugged; on an internal drive that points at a cable or power fault",
    },
    Known {
        providers: &["stornvme", "storahci", "iaStorAC", "iaStorA", "iaStorAVC"],
        ids: &[11, 129],
        tier: Tier::Serious,
        short: "Drive reset",
        meaning: "a drive or its controller stopped responding and was reset",
    },
    Known {
        providers: &["Ntfs", "Microsoft-Windows-Ntfs"],
        ids: &[55, 98, 130, 137, 140],
        tier: Tier::Serious,
        short: "File system error",
        meaning: "the file system found damage or could not write its records",
    },
    Known {
        providers: &["Display"],
        ids: &[4101],
        tier: Tier::Serious,
        short: "Graphics driver reset",
        meaning: "the graphics driver stopped responding and was restarted",
    },
    Known {
        providers: &["nvlddmkm"],
        ids: &[13, 14, 153],
        tier: Tier::Serious,
        short: "Graphics driver error",
        meaning: "the NVIDIA graphics driver reported an error",
    },
    Known {
        providers: &["Service Control Manager"],
        ids: &[7031, 7034],
        tier: Tier::Notable,
        short: "Service crash",
        meaning: "a Windows service stopped unexpectedly",
    },
    Known {
        providers: &["Service Control Manager"],
        ids: &[7000, 7001, 7009, 7011, 7023, 7024],
        tier: Tier::Notable,
        short: "Service failure",
        meaning: "a Windows service failed to start or to respond",
    },
    Known {
        providers: &["Application Error"],
        ids: &[1000],
        tier: Tier::Notable,
        short: "App crash",
        meaning: "an app crashed",
    },
    Known {
        providers: &["Application Hang"],
        ids: &[1002],
        tier: Tier::Notable,
        short: "App hang",
        meaning: "an app stopped responding and was closed",
    },
    Known {
        providers: &[".NET Runtime"],
        ids: &[1026],
        tier: Tier::Notable,
        short: "App error",
        meaning: "an app stopped on an unhandled .NET error",
    },
    Known {
        providers: &["Microsoft-Windows-WindowsUpdateClient"],
        ids: &[20],
        tier: Tier::Notable,
        short: "Update failure",
        meaning: "an update failed to install",
    },
    Known {
        providers: &["Microsoft-Windows-Resource-Exhaustion-Detector"],
        ids: &[2004],
        tier: Tier::Notable,
        short: "Low memory",
        meaning: "Windows ran low on memory and named the largest users",
    },
    Known {
        providers: &["volmgr"],
        ids: &[45, 46, 161],
        tier: Tier::Notable,
        short: "Crash dump failed",
        meaning: "crash dumps could not be set up or written, so a stop error leaves no dump",
    },
    Known {
        providers: &["Microsoft-Windows-TPM-WMI"],
        ids: &[1795, 1796],
        tier: Tier::Notable,
        short: "Secure Boot error",
        meaning: "a Secure Boot update could not be applied; the firmware may need an update",
    },
    Known {
        providers: &["Tcpip"],
        ids: &[4266],
        tier: Tier::Notable,
        short: "Network ports ran out",
        meaning: "the PC ran out of network ports for new connections, often from one app holding too many",
    },
    Known {
        providers: &["Volsnap"],
        ids: &[25, 35, 36],
        tier: Tier::Notable,
        short: "Restore points lost",
        meaning: "shadow copies, which hold restore points and backup snapshots, were deleted",
    },
    Known {
        providers: &["Microsoft-Windows-Kernel-Processor-Power"],
        ids: &[37],
        tier: Tier::Notable,
        short: "Processor slowed",
        meaning: "the firmware limited processor speed, often because of heat",
    },
    Known {
        providers: &["Microsoft-Windows-Kernel-PnP"],
        ids: &[219],
        tier: Tier::Notable,
        short: "Driver failed to load",
        meaning: "Windows could not load the driver for a device, which may then not work",
    },
    Known {
        providers: &["Microsoft-Windows-DriverFrameworks-UserMode"],
        ids: &[10110, 10111],
        tier: Tier::Notable,
        short: "Device driver problem",
        meaning: "a device driver had a problem and the device may have stopped",
    },
];

/// A kind of event that is routine on healthy PCs and is hidden unless asked for.
#[derive(Debug, PartialEq)]
pub struct Noise {
    pub provider: &'static str,
    pub id: u32,
    pub reason: &'static str,
}

pub const NOISE: &[Noise] = &[
    Noise {
        provider: "Microsoft-Windows-DistributedCOM",
        id: 10016,
        reason: "a COM permission warning that Microsoft documents as safe to ignore",
    },
    Noise {
        provider: "Microsoft-Windows-DistributedCOM",
        id: 10010,
        reason: "a background COM server registered late",
    },
    Noise {
        provider: "Microsoft-Windows-Perflib",
        id: 1008,
        reason: "a performance counter library did not load",
    },
    Noise {
        provider: "Microsoft-Windows-Perflib",
        id: 1023,
        reason: "a performance counter library did not load",
    },
    Noise {
        provider: "Microsoft-Windows-DNS-Client",
        id: 1014,
        reason: "a name lookup timed out",
    },
    Noise {
        provider: "Microsoft-Windows-Time-Service",
        id: 129,
        reason: "clock sync could not reach its server, usually before the network is up",
    },
    Noise {
        provider: "Microsoft-Windows-Security-SPP",
        id: 16385,
        reason: "the licensing service could not schedule its own restart",
    },
    Noise {
        provider: "Microsoft-Windows-User Profiles Service",
        id: 1534,
        reason: "a profile notification for a component that is not installed",
    },
];

pub fn known(provider: &str, id: u32) -> Option<&'static Known> {
    KNOWN.iter().find(|kind| {
        kind.ids.contains(&id)
            && kind
                .providers
                .iter()
                .any(|name| name.eq_ignore_ascii_case(provider))
    })
}

pub fn noise(provider: &str, id: u32) -> Option<&'static Noise> {
    NOISE
        .iter()
        .find(|rule| rule.id == id && rule.provider.eq_ignore_ascii_case(provider))
}

#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    pub log: String,
    pub provider: String,
    pub id: u32,
    /// 1 critical, 2 error, 3 warning, 4 or 0 information, 5 verbose.
    pub level: u8,
    pub time: SystemTime,
    /// The source's message, redacted and capped, when the query asked for messages.
    pub message: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Group {
    pub log: String,
    pub provider: String,
    pub id: u32,
    /// The most severe level seen in the group.
    pub level: u8,
    pub count: usize,
    pub first: SystemTime,
    pub last: SystemTime,
    pub known: Option<&'static Known>,
    pub noise: Option<&'static Noise>,
}

impl Group {
    pub fn tier(&self) -> Option<Tier> {
        self.known.map(|kind| kind.tier)
    }

    /// Known significance first, then recency, then how often it happened.
    fn score(&self, now: SystemTime) -> u64 {
        let base = match self.tier() {
            Some(Tier::Serious) => 1000,
            Some(Tier::Notable) => 300,
            None => match self.level {
                1 => 200,
                2 => 100,
                3 => 20,
                _ => 5,
            },
        };
        let age = now.duration_since(self.last).unwrap_or_default();
        let recency = if age <= HOUR * 24 {
            50
        } else if age <= HOUR * 72 {
            20
        } else {
            0
        };
        base + recency + self.count.min(50) as u64
    }
}

pub fn level_name(level: u8) -> &'static str {
    match level {
        1 => "critical",
        2 => "error",
        3 => "warning",
        5 => "verbose",
        _ => "information",
    }
}

const HOUR: Duration = Duration::from_secs(3600);

/// What to read. Empty provider, id and level lists match everything.
#[derive(Clone, Debug)]
pub struct Query {
    pub logs: Vec<String>,
    pub levels: Vec<u8>,
    pub providers: Vec<String>,
    pub ids: Vec<u32>,
    pub since: Duration,
    pub include_noise: bool,
    /// Newest events read per log; older ones are not read.
    pub per_log_limit: usize,
    /// Format each event's message (redacted). Costs a lookup per source; keep the
    /// query narrow.
    pub messages: bool,
}

impl Query {
    /// The survey's reading: critical, error and warning events of the past 7 days.
    pub fn survey() -> Self {
        Self {
            logs: vec!["System".into(), "Application".into()],
            levels: vec![1, 2, 3],
            providers: Vec::new(),
            ids: Vec::new(),
            since: HOUR * 24 * 7,
            include_noise: false,
            per_log_limit: 2000,
            messages: false,
        }
    }
}

pub const MAX_SINCE: Duration = Duration::from_secs(3600 * 24 * 365);

/// The XPath filter for a query. Names are checked against a narrow character set, so
/// no input can change the filter's structure.
pub fn xpath(query: &Query) -> Result<String, String> {
    if query.since.is_zero() || query.since > MAX_SINCE {
        return Err("the time range must be between 1 second and 365 days".into());
    }
    if query.providers.len() > 16 || query.ids.len() > 32 {
        return Err("at most 16 sources and 32 event ids".into());
    }
    let mut parts = Vec::new();
    if !query.providers.is_empty() {
        let mut names = Vec::new();
        for name in &query.providers {
            if !plain_name(name, false) {
                return Err(format!("not a source name: {name}"));
            }
            names.push(format!("@Name='{name}'"));
        }
        parts.push(format!("Provider[{}]", names.join(" or ")));
    }
    if !query.ids.is_empty() {
        if query.ids.iter().any(|&id| id > u32::from(u16::MAX)) {
            return Err("event ids are at most 65535".into());
        }
        let ids: Vec<_> = query.ids.iter().map(|id| format!("EventID={id}")).collect();
        parts.push(format!("({})", ids.join(" or ")));
    }
    if !query.levels.is_empty() {
        if query.levels.iter().any(|&level| level > 5) {
            return Err("levels run from 0 to 5".into());
        }
        let mut levels = query.levels.clone();
        if levels.contains(&4) && !levels.contains(&0) {
            levels.push(0);
        }
        levels.sort_unstable();
        levels.dedup();
        let levels: Vec<_> = levels
            .iter()
            .map(|level| format!("Level={level}"))
            .collect();
        parts.push(format!("({})", levels.join(" or ")));
    }
    parts.push(format!(
        "TimeCreated[timediff(@SystemTime) <= {}]",
        query.since.as_millis()
    ));
    Ok(format!("*[System[{}]]", parts.join(" and ")))
}

/// Letters, digits, spaces and `._-`, plus `/` in channel names; at most 128 characters.
fn plain_name(name: &str, channel: bool) -> bool {
    !name.trim().is_empty()
        && name.len() <= 128
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-') || (channel && c == '/')
        })
}

/// How reading one log ended.
#[derive(Clone, Debug, PartialEq)]
pub struct LogRead {
    pub log: String,
    pub events: usize,
    /// Events the API returned that could not be rendered; never silently dropped.
    pub unreadable: usize,
    pub limit: Option<Limit>,
    pub unavailable: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Limit {
    Count,
    Time,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Summary {
    /// Ranked, most significant first. Noise kinds appear only when the query asked.
    pub groups: Vec<Group>,
    pub noise_events: usize,
    pub noise_kinds: usize,
    pub reads: Vec<LogRead>,
}

/// Groups events, sets noise aside and ranks the rest.
pub fn summarize(
    events: &[Event],
    now: SystemTime,
    include_noise: bool,
    reads: Vec<LogRead>,
) -> Summary {
    let mut groups: HashMap<(String, String, u32), Group> = HashMap::new();
    for event in events {
        let key = (
            event.log.to_ascii_lowercase(),
            event.provider.to_ascii_lowercase(),
            event.id,
        );
        let group = groups.entry(key).or_insert_with(|| Group {
            log: event.log.clone(),
            provider: event.provider.clone(),
            id: event.id,
            level: event.level,
            count: 0,
            first: event.time,
            last: event.time,
            known: known(&event.provider, event.id),
            noise: noise(&event.provider, event.id),
        });
        group.count += 1;
        group.first = group.first.min(event.time);
        group.last = group.last.max(event.time);
        if severity(event.level) > severity(group.level) {
            group.level = event.level;
        }
    }
    let (mut noise_events, mut noise_kinds) = (0, 0);
    let mut ranked: Vec<Group> = groups
        .into_values()
        .filter(|group| {
            if group.noise.is_some() {
                noise_events += group.count;
                noise_kinds += 1;
            }
            include_noise || group.noise.is_none()
        })
        .collect();
    ranked.sort_by(|a, b| {
        b.score(now)
            .cmp(&a.score(now))
            .then(b.last.cmp(&a.last))
            .then_with(|| (&a.log, &a.provider, a.id).cmp(&(&b.log, &b.provider, b.id)))
    });
    Summary {
        groups: ranked,
        noise_events,
        noise_kinds,
        reads,
    }
}

/// Critical is the most severe; information and verbose the least.
fn severity(level: u8) -> u8 {
    match level {
        1 => 5,
        2 => 4,
        3 => 3,
        5 => 1,
        _ => 2,
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ReadError {
    Cancelled,
    Invalid(String),
    Unavailable(String),
}

struct Handle(EVT_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: the handle came from the Event Log API and is closed once.
            unsafe { EvtClose(self.0) };
        }
    }
}

/// Lowers this thread's CPU and I/O priority while the logs are read.
struct Background;

impl Background {
    fn enter() -> Self {
        // SAFETY: the pseudo handle for the current thread needs no closing.
        unsafe { SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN) };
        Self
    }
}

impl Drop for Background {
    fn drop(&mut self) {
        // SAFETY: as above; ends the mode this thread entered.
        unsafe { SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_END) };
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn describe(code: u32) -> String {
    match code {
        ERROR_ACCESS_DENIED => "this account may not read it".into(),
        ERROR_EVT_CHANNEL_NOT_FOUND => "no such log on this PC".into(),
        ERROR_EVT_INVALID_QUERY => "the filter was refused".into(),
        other => format!("the Event Log API returned error {other}"),
    }
}

/// Reads the query's logs, newest first, within the deadline. A log that cannot be read
/// is reported as unavailable in the summary; cancellation ends the whole read.
pub fn read(
    query: &Query,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Summary, ReadError> {
    let (events, reads) = read_events(query, deadline, cancelled)?;
    Ok(summarize(
        &events,
        SystemTime::now(),
        query.include_noise,
        reads,
    ))
}

/// The individual events behind `read`, newest first within each log, for tools that
/// need each occurrence rather than groups (the change timeline, the crash reader).
pub fn read_events(
    query: &Query,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<(Vec<Event>, Vec<LogRead>), ReadError> {
    let (events, reads) = read_events_with_data(query, &[], deadline, cancelled)?;
    Ok((events.into_iter().map(|(event, _)| event).collect(), reads))
}

/// `read_events` with messages kept up to `message_chars` characters instead of
/// `EXCERPT_CHARS`, for the event viewer. Messages are redacted as everywhere else.
pub fn read_events_long(
    query: &Query,
    message_chars: usize,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<(Vec<Event>, Vec<LogRead>), ReadError> {
    let (events, reads) = read_with(query, &[], message_chars, deadline, cancelled)?;
    Ok((events.into_iter().map(|(event, _)| event).collect(), reads))
}

/// An event with the `EventData/Data` values asked for, in the order asked. A value is
/// `None` when the event has no such item or it is not text.
pub type WithData = (Event, Vec<Option<String>>);

/// The most `EventData/Data` items one read can return per event.
pub const MAX_DATA_ITEMS: usize = 8;

/// `read_events` that also returns the `EventData` items with the names given: the
/// faulting app of event 1000 or the service of event 7031, which sit in the event's data
/// and read the same in every language. A name is letters, digits and underscores.
pub fn read_events_with_data(
    query: &Query,
    names: &[&str],
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<(Vec<WithData>, Vec<LogRead>), ReadError> {
    read_with(query, names, EXCERPT_CHARS, deadline, cancelled)
}

fn read_with(
    query: &Query,
    names: &[&str],
    message_chars: usize,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<(Vec<WithData>, Vec<LogRead>), ReadError> {
    let filter = xpath(query).map_err(ReadError::Invalid)?;
    if let Some(log) = query.logs.iter().find(|log| !plain_name(log, true)) {
        return Err(ReadError::Invalid(format!("not a log name: {log}")));
    }
    if names.len() > MAX_DATA_ITEMS
        || names.iter().any(|name| {
            name.is_empty()
                || name.len() > 32
                || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
    {
        return Err(ReadError::Invalid(
            "at most 8 data item names of letters, digits and underscores".into(),
        ));
    }
    let _background = Background::enter();
    // SAFETY: no value paths are passed; the system context needs none.
    let context =
        Handle(unsafe { EvtCreateRenderContext(0, std::ptr::null(), EvtRenderContextSystem) });
    if context.0 == 0 {
        return Err(ReadError::Unavailable(
            "the event log service did not answer".into(),
        ));
    }
    let data = if names.is_empty() {
        None
    } else {
        Some(data_context(names)?)
    };
    let mut reader = Reader {
        filter,
        limit: query.per_log_limit,
        context,
        data,
        deadline,
        cancelled,
        publishers: query.messages.then(HashMap::new),
        names: local_names(),
        message_chars,
    };
    let mut events = Vec::new();
    let mut reads = Vec::new();
    for log in &query.logs {
        reads.push(read_log(log, &mut reader, &mut events)?);
    }
    Ok((events, reads))
}

/// A render context for the named `Event/EventData/Data` values.
fn data_context(names: &[&str]) -> Result<DataContext, ReadError> {
    let paths: Vec<Vec<u16>> = names
        .iter()
        .map(|name| wide(&format!("Event/EventData/Data[@Name='{name}']")))
        .collect();
    let pointers: Vec<*const u16> = paths.iter().map(|path| path.as_ptr()).collect();
    // SAFETY: every pointer is a NUL-terminated string in `paths`, which outlives the call.
    let handle = Handle(unsafe {
        EvtCreateRenderContext(
            pointers.len() as u32,
            pointers.as_ptr(),
            EvtRenderContextValues,
        )
    });
    if handle.0 == 0 {
        // SAFETY: reads this thread's last error right after the failed call.
        return Err(ReadError::Unavailable(describe(unsafe { GetLastError() })));
    }
    Ok(DataContext { handle })
}

struct DataContext {
    handle: Handle,
}

/// What reading each log of one query shares.
struct Reader<'a> {
    filter: String,
    limit: usize,
    context: Handle,
    deadline: Instant,
    cancelled: &'a AtomicBool,
    /// Present when the caller asked for `EventData` items.
    data: Option<DataContext>,
    /// Publisher metadata by source, opened once; present only when messages are wanted.
    publishers: Option<HashMap<String, Option<Handle>>>,
    names: Vec<String>,
    message_chars: usize,
}

impl Reader<'_> {
    fn message(&mut self, provider: &str, event: &Handle) -> Option<String> {
        let publishers = self.publishers.as_mut()?;
        let publisher = publishers
            .entry(provider.to_ascii_lowercase())
            .or_insert_with(|| {
                let name = wide(provider);
                // SAFETY: the name is NUL-terminated; null path and locale 0 use defaults.
                let handle =
                    unsafe { EvtOpenPublisherMetadata(0, name.as_ptr(), std::ptr::null(), 0, 0) };
                (handle != 0).then_some(Handle(handle))
            })
            .as_ref()?;
        format_message(publisher, event)
            .map(|text| redact_to(&text, &self.names, self.message_chars))
    }
}

fn open(log: &str, filter: &str) -> Result<Handle, String> {
    let (path, filter) = (wide(log), wide(filter));
    // SAFETY: both strings are NUL-terminated and outlive the call.
    let results = unsafe {
        EvtQuery(
            0,
            path.as_ptr(),
            filter.as_ptr(),
            EvtQueryChannelPath | EvtQueryReverseDirection,
        )
    };
    if results == 0 {
        // SAFETY: reads this thread's last error right after the failed call.
        return Err(describe(unsafe { GetLastError() }));
    }
    Ok(Handle(results))
}

/// The next batch of event handles, empty at the end of the results.
fn next(results: &Handle, want: usize) -> Result<Vec<Handle>, String> {
    let mut raw = [0isize; 64];
    let want = want.min(raw.len()) as u32;
    loop {
        let mut returned = 0u32;
        // SAFETY: `raw` holds at least `want` handles and `returned` is a valid out pointer.
        let ok = unsafe { EvtNext(results.0, want, raw.as_mut_ptr(), 1000, 0, &mut returned) };
        if ok != 0 {
            return Ok(raw[..returned as usize]
                .iter()
                .map(|&h| Handle(h))
                .collect());
        }
        // SAFETY: as above.
        match unsafe { GetLastError() } {
            ERROR_NO_MORE_ITEMS => return Ok(Vec::new()),
            ERROR_TIMEOUT => continue,
            code => return Err(describe(code)),
        }
    }
}

fn read_log(
    log: &str,
    reader: &mut Reader,
    events: &mut Vec<WithData>,
) -> Result<LogRead, ReadError> {
    let mut read = LogRead {
        log: log.into(),
        events: 0,
        unreadable: 0,
        limit: None,
        unavailable: None,
    };
    let results = match open(log, &reader.filter) {
        Ok(results) => results,
        Err(reason) => {
            read.unavailable = Some(reason);
            return Ok(read);
        }
    };
    let mut buffer = vec![0u64; 512];
    loop {
        if reader.cancelled.load(Ordering::Relaxed) {
            return Err(ReadError::Cancelled);
        }
        if Instant::now() >= reader.deadline {
            read.limit = Some(Limit::Time);
            break;
        }
        let taken = read.events + read.unreadable;
        if taken >= reader.limit {
            read.limit = Some(Limit::Count);
            break;
        }
        let batch = match next(&results, reader.limit - taken) {
            Ok(batch) if batch.is_empty() => break,
            Ok(batch) => batch,
            Err(reason) => {
                read.unavailable = Some(reason);
                break;
            }
        };
        for handle in &batch {
            match render(&reader.context, handle, &mut buffer) {
                Some((provider, id, level, time)) => {
                    let message = reader.message(&provider, handle);
                    let data = reader.data.as_ref().map_or_else(Vec::new, |context| {
                        render_data(&context.handle, handle, &mut buffer)
                    });
                    events.push((
                        Event {
                            log: log.into(),
                            provider,
                            id,
                            level,
                            time,
                            message,
                        },
                        data,
                    ));
                    read.events += 1;
                }
                None => read.unreadable += 1,
            }
        }
    }
    Ok(read)
}

/// Renders an event's values into `buffer`, growing it once if needed. Returns the number
/// of values rendered; the buffer then holds that many `EVT_VARIANT`s and their strings.
fn render_values(context: &Handle, event: &Handle, buffer: &mut Vec<u64>) -> Option<usize> {
    let mut used = 0u32;
    let mut count = 0u32;
    for _ in 0..2 {
        // SAFETY: the buffer is 8-byte aligned and its byte size is passed.
        let ok = unsafe {
            EvtRender(
                context.0,
                event.0,
                EvtRenderEventValues,
                (buffer.len() * 8) as u32,
                buffer.as_mut_ptr().cast(),
                &mut used,
                &mut count,
            )
        };
        if ok != 0 {
            break;
        }
        // SAFETY: reads this thread's last error right after the failed call.
        if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
        buffer.resize((used as usize).div_ceil(8), 0);
        count = 0;
    }
    (count > 0 && used as usize <= buffer.len() * 8).then_some(count as usize)
}

/// The `EventData/Data` values a values context asks for, as text. A value that is
/// missing, is not text or cannot be rendered is `None`.
fn render_data(context: &Handle, event: &Handle, buffer: &mut Vec<u64>) -> Vec<Option<String>> {
    let Some(count) = render_values(context, event, buffer) else {
        return Vec::new();
    };
    // SAFETY: EvtRender wrote `count` variants at the start of the buffer, which is
    // aligned for EVT_VARIANT.
    let values =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<EVT_VARIANT>(), count) };
    let end = buffer.as_ptr_range().end.cast::<u16>();
    values
        .iter()
        .map(|value| {
            if value.Type != EvtVarTypeString as u32 {
                return None;
            }
            // SAFETY: the type is checked above and the string is read no further than
            // the end of the buffer.
            unsafe { bounded_string(value.Anonymous.StringVal, end) }
        })
        .collect()
}

/// The provider, id, level and time of one event, from the system render context.
fn render(
    context: &Handle,
    event: &Handle,
    buffer: &mut Vec<u64>,
) -> Option<(String, u32, u8, SystemTime)> {
    let count = render_values(context, event, buffer)?;
    if count < EvtSystemTimeCreated as usize + 1 {
        return None;
    }
    // SAFETY: EvtRender wrote `count` variants at the start of the buffer, which is
    // aligned for EVT_VARIANT; string values point into the same buffer.
    let values =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<EVT_VARIANT>(), count) };
    let provider = &values[EvtSystemProviderName as usize];
    let id = &values[EvtSystemEventID as usize];
    let level = &values[EvtSystemLevel as usize];
    let time = &values[EvtSystemTimeCreated as usize];
    if provider.Type != EvtVarTypeString as u32
        || id.Type != EvtVarTypeUInt16 as u32
        || time.Type != EvtVarTypeFileTime as u32
    {
        return None;
    }
    let end = buffer.as_ptr_range().end.cast::<u16>();
    // SAFETY: the union members read match the types checked above, and the string is
    // read no further than the end of the buffer.
    unsafe {
        let provider = bounded_string(provider.Anonymous.StringVal, end)?;
        let level = if level.Type == EvtVarTypeByte as u32 {
            level.Anonymous.ByteVal
        } else {
            0
        };
        Some((
            provider,
            u32::from(id.Anonymous.UInt16Val),
            level,
            from_filetime(time.Anonymous.FileTimeVal),
        ))
    }
}

/// # Safety
/// `start` must be null or point into a buffer of u16 that ends at `end`.
unsafe fn bounded_string(start: *const u16, end: *const u16) -> Option<String> {
    if start.is_null() || start >= end {
        return None;
    }
    // SAFETY: the caller guarantees both pointers lie in one buffer, start before end.
    let units = unsafe {
        let available = end.offset_from(start) as usize;
        std::slice::from_raw_parts(start, available.min(512))
    };
    let length = units.iter().position(|&unit| unit == 0)?;
    Some(String::from_utf16_lossy(&units[..length]))
}

/// FILETIME counts 100 ns intervals since 1601.
pub fn from_filetime(value: u64) -> SystemTime {
    const UNIX_OFFSET: u64 = 116_444_736_000_000_000;
    let since_unix = value.saturating_sub(UNIX_OFFSET);
    UNIX_EPOCH
        + Duration::new(
            since_unix / 10_000_000,
            (since_unix % 10_000_000) as u32 * 100,
        )
}

/// The newest event of one kind, its message formatted by its source and redacted, at
/// most `EXCERPT_CHARS` characters. `Ok(None)` means no such event in the time range.
pub fn excerpt(
    log: &str,
    provider: &str,
    id: u32,
    since: Duration,
    cancelled: &AtomicBool,
) -> Result<Option<String>, ReadError> {
    if !plain_name(log, true) {
        return Err(ReadError::Invalid(format!("not a log name: {log}")));
    }
    let filter = xpath(&Query {
        logs: vec![log.into()],
        levels: Vec::new(),
        providers: vec![provider.into()],
        ids: vec![id],
        since,
        include_noise: true,
        per_log_limit: 1,
        messages: false,
    })
    .map_err(ReadError::Invalid)?;
    let _background = Background::enter();
    let results = open(log, &filter).map_err(ReadError::Unavailable)?;
    if cancelled.load(Ordering::Relaxed) {
        return Err(ReadError::Cancelled);
    }
    let batch = next(&results, 1).map_err(ReadError::Unavailable)?;
    let Some(event) = batch.first() else {
        return Ok(None);
    };
    let name = wide(provider);
    // SAFETY: the name is NUL-terminated; a null log path and locale 0 use the defaults.
    let publisher =
        Handle(unsafe { EvtOpenPublisherMetadata(0, name.as_ptr(), std::ptr::null(), 0, 0) });
    if publisher.0 == 0 {
        return Err(ReadError::Unavailable(
            "this source has no message text registered on this PC".into(),
        ));
    }
    let text = format_message(&publisher, event).ok_or_else(|| {
        ReadError::Unavailable("the source's message text could not be formatted".into())
    })?;
    Ok(Some(redact(&text, &local_names())))
}

fn format_message(publisher: &Handle, event: &Handle) -> Option<String> {
    let mut buffer = vec![0u16; 1024];
    for _ in 0..2 {
        let mut used = 0u32;
        // SAFETY: the buffer's length in characters is passed with it.
        let ok = unsafe {
            EvtFormatMessage(
                publisher.0,
                event.0,
                0,
                0,
                std::ptr::null(),
                EvtFormatMessageEvent,
                buffer.len() as u32,
                buffer.as_mut_ptr(),
                &mut used,
            )
        };
        // SAFETY: reads this thread's last error right after the call.
        let code = if ok != 0 {
            0
        } else {
            unsafe { GetLastError() }
        };
        match code {
            ERROR_INSUFFICIENT_BUFFER => buffer.resize(used as usize, 0),
            // A missing insert still leaves the readable rest of the message.
            0 | ERROR_EVT_UNRESOLVED_VALUE_INSERT | ERROR_EVT_UNRESOLVED_PARAMETER_INSERT => {
                let length = buffer
                    .iter()
                    .position(|&unit| unit == 0)
                    .unwrap_or(buffer.len());
                return Some(String::from_utf16_lossy(&buffer[..length]));
            }
            _ => return None,
        }
    }
    None
}

pub const EXCERPT_CHARS: usize = 400;

/// This PC's computer and account names, removed from excerpts.
pub fn local_names() -> Vec<String> {
    ["COMPUTERNAME", "USERNAME", "USERDOMAIN"]
        .iter()
        .filter_map(|key| std::env::var(key).ok())
        .collect()
}

/// Removes names, profile folders, account SIDs, e-mail, IP and hardware addresses from
/// message text, folds whitespace and caps the length.
pub fn redact(text: &str, names: &[String]) -> String {
    redact_to(text, names, EXCERPT_CHARS)
}

/// `redact` with a cap of `limit` characters, at least 2.
pub fn redact_to(text: &str, names: &[String], limit: usize) -> String {
    let limit = limit.max(2);
    let text = redact_profiles(&text.split_whitespace().collect::<Vec<_>>().join(" "));
    let mut words: Vec<String> = Vec::new();
    for word in text.split(' ') {
        // "version: 1.0.0.0" is a version number, not an address.
        let after_version = words.last().is_some_and(|previous| {
            previous
                .trim_end_matches(':')
                .to_ascii_lowercase()
                .ends_with("version")
        });
        words.push(if after_version {
            word.into()
        } else {
            redact_word(word)
        });
    }
    let mut text = words.join(" ");
    for name in names.iter().filter(|name| name.chars().count() >= 3) {
        text = replace_ignoring_case(&text, name, "[name]");
    }
    if text.chars().count() > limit {
        let mut cut: String = text.chars().take(limit - 1).collect();
        cut.push('…');
        cut
    } else {
        text
    }
}

fn replace_ignoring_case(text: &str, name: &str, with: &str) -> String {
    let (haystack, needle) = (text.to_ascii_lowercase(), name.to_ascii_lowercase());
    let mut out = String::with_capacity(text.len());
    let mut rest = 0;
    while let Some(found) = haystack[rest..].find(&needle) {
        out.push_str(&text[rest..rest + found]);
        out.push_str(with);
        rest += found + needle.len();
    }
    out.push_str(&text[rest..]);
    out
}

/// `C:\Users\<name>\...` keeps its shape with the profile name removed.
fn redact_profiles(text: &str) -> String {
    const MARK: &str = "\\users\\";
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut rest = 0;
    while let Some(found) = lower[rest..].find(MARK) {
        let start = rest + found + MARK.len();
        out.push_str(&text[rest..start]);
        let tail = &text[start..];
        let end = match tail.find('\\') {
            Some(slash) if slash <= 64 => slash,
            _ => tail.find([' ', '"', '\'']).unwrap_or(tail.len()),
        };
        out.push_str("[user]");
        rest = start + end;
    }
    out.push_str(&text[rest..]);
    out
}

fn redact_word(word: &str) -> String {
    let core_start = word.find(|c: char| !is_wrapper(c)).unwrap_or(word.len());
    let core_end = word
        .rfind(|c: char| !is_wrapper(c))
        .map(|index| index + word[index..].chars().next().map_or(1, char::len_utf8))
        .map_or(core_start, |end| end.max(core_start));
    let core = &word[core_start..core_end];
    let replaced = if is_email(core) {
        Some("[email]")
    } else if is_sid(core) {
        Some("[account]")
    } else if is_mac(core) {
        Some("[hardware address]")
    } else if is_ipv4(core) || is_ipv6(core) {
        Some("[address]")
    } else {
        None
    };
    match replaced {
        Some(with) => format!("{}{with}{}", &word[..core_start], &word[core_end..]),
        None => word.into(),
    }
}

fn is_wrapper(c: char) -> bool {
    matches!(
        c,
        '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '.' | ':' | '<' | '>'
    )
}

fn is_email(word: &str) -> bool {
    word.split_once('@').is_some_and(|(user, host)| {
        !user.is_empty() && host.contains('.') && !host.starts_with('.')
    })
}

fn is_sid(word: &str) -> bool {
    let upper = word.to_ascii_uppercase();
    upper.starts_with("S-1-")
        && upper.len() > 6
        && upper[4..].chars().all(|c| c.is_ascii_digit() || c == '-')
}

fn is_mac(word: &str) -> bool {
    let parts: Vec<_> = word.split([':', '-']).collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|part| part.len() == 2 && part.chars().all(|c| c.is_ascii_hexdigit()))
}

fn is_ipv4(word: &str) -> bool {
    let address = word.rsplit_once(':').map_or(word, |(address, port)| {
        if port.chars().all(|c| c.is_ascii_digit()) {
            address
        } else {
            word
        }
    });
    let parts: Vec<_> = address.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.len() <= 3 && part.parse::<u8>().is_ok())
}

fn is_ipv6(word: &str) -> bool {
    let address = word.split('%').next().unwrap_or(word);
    (address.contains("::") || address.matches(':').count() >= 7)
        && address.chars().any(|c| c.is_ascii_hexdigit())
        && address
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
}

/// Kinds listed by name in the survey's report detail.
const SURVEY_LISTED: usize = 10;

/// The "Recent system events" check.
pub fn survey(cancelled: &AtomicBool, deadline: Instant) -> Outcome {
    let query = Query::survey();
    match read(&query, deadline, cancelled) {
        Ok(summary) => survey_outcome(&query, &summary),
        Err(error) => read_failure(error),
    }
}

pub fn survey_outcome(query: &Query, summary: &Summary) -> Outcome {
    if let Some(reasons) = all_unavailable(&summary.reads) {
        return Outcome::Unavailable(reasons);
    }
    let known: Vec<&Group> = summary
        .groups
        .iter()
        .filter(|g| g.known.is_some())
        .collect();
    let unread: Vec<&str> = summary
        .reads
        .iter()
        .filter(|read| read.unavailable.is_some())
        .map(|read| read.log.as_str())
        .collect();
    let errors = summary.groups.iter().any(|g| g.level <= 2);
    let brief = row_brief(&known, summary.groups.len(), errors, &unread);
    let grade = survey_grade(&summary.groups);
    let mut lines = report_lines(query, summary, SURVEY_LISTED);
    lines.push(match grade {
        Grade::Serious => "Serious: a kind listed as serious happened (unclean shutdowns, stop errors, hardware, drive, file system or graphics driver failures).",
        Grade::Flagged => "Flagged: a known kind, or an error or critical event of another kind, happened.",
        Grade::Clear => "Not flagged: no known kind and no error or critical event; warnings alone are not flagged.",
    }.into());
    Outcome::Found(Finding::graded(brief, lines.join("\n"), grade))
}

/// Serious when a serious kind happened; flagged for any other known kind or any error.
fn survey_grade(groups: &[Group]) -> Grade {
    if groups.iter().any(|g| g.tier() == Some(Tier::Serious)) {
        Grade::Serious
    } else if groups.iter().any(|g| g.known.is_some() || g.level <= 2) {
        Grade::Flagged
    } else {
        Grade::Clear
    }
}

/// The reasons when no log of a read could be read; `None` when at least one could.
fn all_unavailable(reads: &[LogRead]) -> Option<String> {
    if reads.iter().any(|read| read.unavailable.is_none()) {
        return None;
    }
    let reasons: Vec<_> = reads
        .iter()
        .map(|read| {
            format!(
                "{}: {}",
                read.log,
                read.unavailable.as_deref().unwrap_or("unread")
            )
        })
        .collect();
    Some(format!(
        "event logs could not be read ({})",
        reasons.join("; ")
    ))
}

/// The window row's text; `widest_briefs` feeds the test that it fits the row.
fn row_brief(known: &[&Group], kinds: usize, errors: bool, unread: &[&str]) -> String {
    let unread = unread.join(" and ");
    let kinds_text = format!("{kinds} {}", plural(kinds, "kind", "kinds"));
    match known
        .first()
        .and_then(|top| top.known.map(|kind| (top, kind)))
    {
        Some((top, kind)) if known.len() == 1 => {
            let count = if top.count > 99 {
                "many times".into()
            } else {
                times(top.count)
            };
            format!("{}, {count}", kind.short)
        }
        Some((_, kind)) => format!("{}, {} more", kind.short, (known.len() - 1).min(99)),
        None if kinds == 0 && unread.is_empty() => "No errors or warnings".into(),
        None if kinds == 0 => format!("None found, {unread} unread"),
        None if unread.is_empty() && errors => format!("{kinds_text}, none known"),
        None if unread.is_empty() => format!("{kinds_text}, warnings only"),
        None => format!("{kinds_text}, {unread} unread"),
    }
}

/// The longest row texts the survey can produce, for the window's width test.
pub fn widest_briefs() -> Vec<String> {
    let group = |kind: &'static Known, count: usize| Group {
        log: "System".into(),
        provider: kind.providers[0].into(),
        id: kind.ids[0],
        level: 2,
        count,
        first: UNIX_EPOCH,
        last: UNIX_EPOCH,
        known: Some(kind),
        noise: None,
    };
    let mut briefs = vec![
        row_brief(&[], 99, true, &[]),
        row_brief(&[], 99, false, &[]),
        row_brief(&[], 99, true, &["Application"]),
        row_brief(&[], 0, false, &["Application"]),
    ];
    for kind in KNOWN {
        briefs.push(row_brief(&[&group(kind, 100)], 1, true, &[]));
        briefs.push(row_brief(&[&group(kind, 99)], 1, true, &[]));
        briefs.push(row_brief(&[&group(kind, 1); 100], 100, true, &[]));
    }
    briefs.extend(kind_briefs());
    briefs
}

/// How far back the App crashes, Service failures and Hardware and driver events read.
pub const KIND_SPAN: Duration = Duration::from_secs(3600 * 24 * 7);
/// Newest events one kind query reads per log.
const KIND_LIMIT: usize = 1000;
/// Characters of an app or service name that fit the window row.
const ROW_NAME_CHARS: usize = 10;
/// Characters of a name from event data kept anywhere.
const NAME_CHARS: usize = 48;
/// Names listed one by one in a report detail.
const LISTED_NAMES: usize = 8;
/// Kinds listed one by one in the hardware report detail.
const LISTED_KINDS: usize = 10;
/// Shown for an event whose data has no readable name.
const UNNAMED: &str = "unnamed";

fn kind_query(log: &str, providers: &[&str], ids: &[u32], levels: &[u8]) -> Query {
    Query {
        logs: vec![log.into()],
        levels: levels.to_vec(),
        providers: providers.iter().map(|&name| name.into()).collect(),
        ids: ids.to_vec(),
        since: KIND_SPAN,
        include_noise: true,
        per_log_limit: KIND_LIMIT,
        messages: false,
    }
}

fn read_failure(error: ReadError) -> Outcome {
    match error {
        ReadError::Cancelled => Outcome::Stopped,
        ReadError::Invalid(reason) | ReadError::Unavailable(reason) => Outcome::Unavailable(reason),
    }
}

/// How each log of a read ended, one line each.
fn read_lines(reads: &[LogRead]) -> Vec<String> {
    let mut lines = Vec::new();
    for read in reads {
        lines.push(match (&read.unavailable, read.limit) {
            (Some(reason), _) => format!("{}: unavailable, {reason}.", read.log),
            (None, Some(Limit::Count)) => format!(
                "{}: newest {} events read; older ones were not.",
                read.log, read.events
            ),
            (None, Some(Limit::Time)) => format!(
                "{}: {} events read before the time limit; older ones were not.",
                read.log, read.events
            ),
            (None, None) => format!("{}: {} events read.", read.log, read.events),
        });
        if read.unreadable > 0 {
            lines.push(format!(
                "{}: {} events could not be read.",
                read.log, read.unreadable
            ));
        }
    }
    lines
}

/// An app, module or service name from event data, safe to show: the file part when it is
/// a file, names redacted, control characters dropped, capped.
fn clean_name(raw: Option<&str>, file: bool, names: &[String]) -> Option<String> {
    let raw = raw?.trim();
    let raw = if file {
        raw.rsplit(['\\', '/']).next().unwrap_or(raw)
    } else {
        raw
    };
    let text: String = raw.chars().filter(|c| !c.is_control()).collect();
    let text = redact(&text, names);
    let text = cap_chars(&text, NAME_CHARS);
    (!text.is_empty()).then_some(text)
}

fn cap_chars(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.into();
    }
    let mut cut: String = text.chars().take(limit.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

/// An exception code as `0x` and up to 8 hex digits, from event data like `c0000005`.
fn exception_code(raw: Option<&str>) -> Option<String> {
    let digits = raw?.trim().trim_start_matches("0x");
    (!digits.is_empty() && digits.len() <= 8 && digits.chars().all(|c| c.is_ascii_hexdigit()))
        .then(|| format!("0x{}", digits.to_ascii_lowercase()))
}

/// One event of an app or a service, with the names read from its data.
struct Occurrence {
    id: u32,
    time: SystemTime,
    name: String,
    module: Option<String>,
    code: Option<String>,
}

/// All the events of one app or service.
struct Subject {
    name: String,
    count: usize,
    /// Events in the 24 hours before the check.
    recent: usize,
    first: SystemTime,
    last: SystemTime,
    ids: std::collections::BTreeMap<u32, usize>,
    modules: HashMap<String, usize>,
    codes: HashMap<String, usize>,
}

/// Subjects by name without regard to case, most frequent first, then newest.
fn rank_subjects(occurrences: &[Occurrence], now: SystemTime) -> Vec<Subject> {
    let mut by_name: HashMap<String, Subject> = HashMap::new();
    for occurrence in occurrences {
        let subject = by_name
            .entry(occurrence.name.to_lowercase())
            .or_insert_with(|| Subject {
                name: occurrence.name.clone(),
                count: 0,
                recent: 0,
                first: occurrence.time,
                last: occurrence.time,
                ids: Default::default(),
                modules: HashMap::new(),
                codes: HashMap::new(),
            });
        subject.count += 1;
        if now.duration_since(occurrence.time).unwrap_or_default() <= HOUR * 24 {
            subject.recent += 1;
        }
        subject.first = subject.first.min(occurrence.time);
        subject.last = subject.last.max(occurrence.time);
        *subject.ids.entry(occurrence.id).or_default() += 1;
        if let Some(module) = &occurrence.module {
            *subject.modules.entry(module.clone()).or_default() += 1;
        }
        if let Some(code) = &occurrence.code {
            *subject.codes.entry(code.clone()).or_default() += 1;
        }
    }
    let mut list: Vec<Subject> = by_name.into_values().collect();
    list.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then(b.last.cmp(&a.last))
            .then_with(|| a.name.cmp(&b.name))
    });
    list
}

/// The most frequent entry, the first by name on a tie.
fn most_common(counts: &HashMap<String, usize>) -> Option<(&str, usize)> {
    counts
        .iter()
        .map(|(name, &count)| (name.as_str(), count))
        .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(a.0)))
}

fn newest(subjects: &[Subject]) -> Option<SystemTime> {
    subjects.iter().map(|subject| subject.last).max()
}

/// `99+` above 99, so a row never grows with the count.
fn count99(count: usize) -> String {
    if count > 99 {
        "99+".into()
    } else {
        count.to_string()
    }
}

/// Lines for the subjects of one list: how often, when, and what they most often hit.
fn subject_lines(
    heading: &str,
    subjects: &[Subject],
    noun: (&'static str, &'static str),
    extra: bool,
) -> Vec<String> {
    let mut lines = vec![format!("{heading}, most frequent first:")];
    for (rank, subject) in subjects.iter().take(LISTED_NAMES).enumerate() {
        let mut text = format!(
            "{}. {}: {} {}",
            rank + 1,
            subject.name,
            subject.count,
            plural(subject.count, noun.0, noun.1),
        );
        if subject.ids.len() > 1 || !extra {
            let ids: Vec<_> = subject
                .ids
                .iter()
                .map(|(id, count)| format!("event {id} {}", times(*count)))
                .collect();
            text.push_str(&format!(" ({})", ids.join(", ")));
        }
        text.push_str(&format!(", newest {}", clock::local(subject.last).long()));
        if subject.count > 1 {
            text.push_str(&format!(", first {}", clock::local(subject.first).long()));
        }
        if extra {
            if let Some((module, count)) = most_common(&subject.modules) {
                text.push_str(&format!("; faulting module {module} in {count}"));
            }
            if let Some((code, count)) = most_common(&subject.codes) {
                text.push_str(&format!(", exception code {code} in {count}"));
            }
        }
        text.push('.');
        lines.push(text);
    }
    if subjects.len() > LISTED_NAMES {
        let rest = &subjects[LISTED_NAMES..];
        let events: usize = rest.iter().map(|subject| subject.count).sum();
        lines.push(format!("Not listed: {} more, {events} events.", rest.len()));
    }
    lines
}

/// Why a subject list is or is not flagged, in words for the detail. Any event flags it.
fn flag_reason(lists: &[&[Subject]], noun: (&'static str, &'static str)) -> (bool, String) {
    let subjects = || lists.iter().flat_map(|l| l.iter());
    let total: usize = subjects().map(|s| s.count).sum();
    let recent: usize = subjects().map(|s| s.recent).sum();
    if total == 0 {
        return (false, "Not flagged: none in 7 days.".into());
    }
    (
        true,
        format!(
            "Flagged because of {total} {} in 7 days, {recent} in the past 24 hours (rule: any in 7 days).",
            plural(total, noun.0, noun.1)
        ),
    )
}

const CRASH_PROVIDER: &str = "Application Error";
const HANG_PROVIDER: &str = "Application Hang";

/// Whether an event is a crash (Application Error 1000) or a hang (Application Hang 1002):
/// the crash query crosses sources and ids, so it can return a pair that is neither.
pub fn is_crash_or_hang(event: &Event) -> bool {
    is_crash(event) || is_hang(event)
}

fn is_crash(event: &Event) -> bool {
    event.id == 1000 && event.provider.eq_ignore_ascii_case(CRASH_PROVIDER)
}

fn is_hang(event: &Event) -> bool {
    event.id == 1002 && event.provider.eq_ignore_ascii_case(HANG_PROVIDER)
}

/// Application Error 1000 (a crash) and Application Hang 1002.
pub fn crash_query() -> Query {
    kind_query(
        "Application",
        &[CRASH_PROVIDER, HANG_PROVIDER],
        &[1000, 1002],
        &[],
    )
}

/// Data items read for each event: app name, and for a crash the faulting module and
/// the exception code.
const CRASH_DATA: [&str; 3] = ["AppName", "ModuleName", "ExceptionCode"];

/// The "App crashes" check.
pub fn app_crashes(cancelled: &AtomicBool, deadline: Instant) -> Outcome {
    match read_events_with_data(&crash_query(), &CRASH_DATA, deadline, cancelled) {
        Ok((events, reads)) => crashes_outcome(&events, &reads, SystemTime::now(), &local_names()),
        Err(error) => read_failure(error),
    }
}

pub fn crashes_outcome(
    events: &[WithData],
    reads: &[LogRead],
    now: SystemTime,
    names: &[String],
) -> Outcome {
    if let Some(reasons) = all_unavailable(reads) {
        return Outcome::Unavailable(reasons);
    }
    let (mut crashes, mut hangs) = (Vec::new(), Vec::new());
    for (event, data) in events {
        if !is_crash_or_hang(event) {
            continue;
        }
        let crash = is_crash(event);
        let item = |index: usize| data.get(index).and_then(|value| value.as_deref());
        let occurrence = Occurrence {
            id: event.id,
            time: event.time,
            name: clean_name(item(0), true, names).unwrap_or_else(|| UNNAMED.into()),
            module: if crash {
                clean_name(item(1), true, names)
            } else {
                None
            },
            code: if crash { exception_code(item(2)) } else { None },
        };
        if crash { &mut crashes } else { &mut hangs }.push(occurrence);
    }
    let (crash_names, hang_names) = (rank_subjects(&crashes, now), rank_subjects(&hangs, now));
    let (flagged, why) = flag_reason(
        &[&crash_names, &hang_names],
        ("crash or hang", "crashes or hangs"),
    );
    let brief = crash_brief(
        crashes.len(),
        hangs.len(),
        crash_names
            .first()
            .or(hang_names.first())
            .map(|subject| subject.name.as_str()),
    );
    let mut lines = vec![format!(
        "Application log; Application Error 1000 (crash) and Application Hang 1002 (hang) events of any level from the past {}.",
        span(KIND_SPAN)
    )];
    for (label, list, count) in [
        ("Crashes", &crash_names, crashes.len()),
        ("Hangs", &hang_names, hangs.len()),
    ] {
        let recent: usize = list.iter().map(|subject| subject.recent).sum();
        lines.push(match newest(list) {
            Some(time) => format!(
                "{label}: {count} ({recent} in the past 24 hours), newest {}.",
                clock::local(time).long()
            ),
            None => format!("{label}: none."),
        });
    }
    if !crash_names.is_empty() {
        lines.extend(subject_lines(
            "Crashes by app",
            &crash_names,
            ("crash", "crashes"),
            true,
        ));
    }
    if !hang_names.is_empty() {
        lines.extend(subject_lines(
            "Hangs by app",
            &hang_names,
            ("hang", "hangs"),
            false,
        ));
    }
    if !crashes.is_empty() || !hangs.is_empty() {
        lines.push(why);
    } else {
        lines.push("Not flagged: no crash or hang events in 7 days.".into());
    }
    lines.extend(read_lines(reads));
    Outcome::Found(Finding::new(brief, lines.join("\n"), flagged))
}

/// The window row for the app crashes check.
fn crash_brief(crashes: usize, hangs: usize, top: Option<&str>) -> String {
    let name = top.map_or_else(String::new, |name| {
        // ".exe" tells nothing in a row that has room for ten characters.
        let bare = match name.len().checked_sub(4).and_then(|at| name.get(at..)) {
            Some(tail) if tail.eq_ignore_ascii_case(".exe") && name.len() > 4 => {
                &name[..name.len() - 4]
            }
            _ => name,
        };
        format!(": {}", cap_chars(bare, ROW_NAME_CHARS))
    });
    match (crashes, hangs) {
        (0, 0) => "None in 7 days".into(),
        (0, hangs) => format!(
            "{} {}{name}",
            count99(hangs),
            plural(hangs, "hang", "hangs")
        ),
        (crashes, _) => format!(
            "{} {}{name}",
            count99(crashes),
            plural(crashes, "crash", "crashes")
        ),
    }
}

/// Service Control Manager events for a service that stopped or would not start.
const SERVICE_IDS: [u32; 8] = [7000, 7001, 7009, 7011, 7023, 7024, 7031, 7034];
const SERVICE_PROVIDER: &str = "Service Control Manager";

/// Whether an event is one the Service failures check counts.
pub fn is_service_failure(event: &Event) -> bool {
    SERVICE_IDS.contains(&event.id) && event.provider.eq_ignore_ascii_case(SERVICE_PROVIDER)
}

pub fn service_query() -> Query {
    kind_query("System", &[SERVICE_PROVIDER], &SERVICE_IDS, &[])
}

/// Data items read for each event: the first two, one of which names the service.
const SERVICE_DATA: [&str; 2] = ["param1", "param2"];

/// The "Service failures" check.
pub fn service_failures(cancelled: &AtomicBool, deadline: Instant) -> Outcome {
    match read_events_with_data(&service_query(), &SERVICE_DATA, deadline, cancelled) {
        Ok((events, reads)) => services_outcome(&events, &reads, SystemTime::now(), &local_names()),
        Err(error) => read_failure(error),
    }
}

pub fn services_outcome(
    events: &[WithData],
    reads: &[LogRead],
    now: SystemTime,
    names: &[String],
) -> Outcome {
    if let Some(reasons) = all_unavailable(reads) {
        return Outcome::Unavailable(reasons);
    }
    let mut occurrences = Vec::new();
    for (event, data) in events {
        if !is_service_failure(event) {
            continue;
        }
        // The timeout events put the milliseconds first and the service second.
        let index = if matches!(event.id, 7009 | 7011) {
            1
        } else {
            0
        };
        let raw = data.get(index).and_then(|value| value.as_deref());
        occurrences.push(Occurrence {
            id: event.id,
            time: event.time,
            name: clean_name(raw, false, names).unwrap_or_else(|| UNNAMED.into()),
            module: None,
            code: None,
        });
    }
    let services = rank_subjects(&occurrences, now);
    let (flagged, why) = flag_reason(&[&services], ("failure", "failures"));
    let brief = service_brief(occurrences.len(), services.first().map(|s| s.name.as_str()));
    let mut lines = vec![format!(
        "System log; Service Control Manager events 7031 and 7034 (a service stopped unexpectedly) and 7000, 7001, 7009, 7011, 7023, 7024 (a service failed to start or respond), any level, from the past {}.",
        span(KIND_SPAN)
    )];
    match newest(&services) {
        Some(time) => {
            let recent: usize = services.iter().map(|subject| subject.recent).sum();
            lines.push(format!(
                "Failures: {} across {} {} ({recent} in the past 24 hours), newest {}.",
                occurrences.len(),
                services.len(),
                plural(services.len(), "service", "services"),
                clock::local(time).long()
            ));
            lines.extend(subject_lines(
                "Failures by service",
                &services,
                ("failure", "failures"),
                false,
            ));
            lines.push(why);
        }
        None => {
            lines.push("Failures: none.".into());
            lines.push("Not flagged: no matching service events in 7 days.".into());
        }
    }
    lines.extend(read_lines(reads));
    Outcome::Found(Finding::new(brief, lines.join("\n"), flagged))
}

fn service_brief(failures: usize, top: Option<&str>) -> String {
    match (failures, top) {
        (0, _) => "None in 7 days".into(),
        (n, Some(name)) => format!(
            "{} {}: {}",
            count99(n),
            plural(n, "failure", "failures"),
            cap_chars(name, ROW_NAME_CHARS)
        ),
        (n, None) => format!("{} {}", count99(n), plural(n, "failure", "failures")),
    }
}

/// A group of hardware and driver events read together by one narrow query.
#[derive(Debug)]
pub struct Category {
    pub label: &'static str,
    /// Sources and ids the query reads, for the report.
    pub scope: &'static str,
    pub providers: &'static [&'static str],
    /// Empty reads every id of the sources.
    pub ids: &'static [u32],
    pub levels: &'static [u8],
    /// Every event of the sources counts as serious, whatever the id.
    pub all_serious: bool,
}

pub const HARDWARE: &[Category] = &[
    Category {
        label: "Hardware error",
        scope: "WHEA-Logger, any event id",
        providers: &["Microsoft-Windows-WHEA-Logger"],
        ids: &[],
        levels: &[],
        all_serious: true,
    },
    Category {
        label: "Drive error",
        scope: "disk 7, 11, 51, 153, 154, 157; stornvme, storahci and iaStor 11, 129",
        providers: &[
            "disk",
            "stornvme",
            "storahci",
            "iaStorAC",
            "iaStorA",
            "iaStorAVC",
        ],
        ids: &[7, 11, 51, 129, 153, 154, 157],
        levels: &[],
        all_serious: false,
    },
    Category {
        label: "File system error",
        scope: "Ntfs 55, 98, 130, 137, 140, errors and warnings only",
        providers: &["Ntfs", "Microsoft-Windows-Ntfs"],
        ids: &[55, 98, 130, 137, 140],
        levels: &[1, 2, 3],
        all_serious: false,
    },
    Category {
        label: "Graphics driver",
        scope: "Display 4101; nvlddmkm 13, 14, 153",
        providers: &["Display", "nvlddmkm"],
        ids: &[13, 14, 153, 4101],
        levels: &[],
        all_serious: false,
    },
    Category {
        label: "Driver load failure",
        scope: "Kernel-PnP 219",
        providers: &["Microsoft-Windows-Kernel-PnP"],
        ids: &[219],
        levels: &[],
        all_serious: false,
    },
];

pub fn hardware_query(category: &Category) -> Query {
    kind_query("System", category.providers, category.ids, category.levels)
}

impl Category {
    /// Whether an event the query returned is one of this category's kinds: a query
    /// that crosses sources and ids can return a pair that is neither.
    pub fn owns(&self, event: &Event) -> bool {
        self.providers
            .iter()
            .any(|name| name.eq_ignore_ascii_case(&event.provider))
            && (self.ids.is_empty() || known(&event.provider, event.id).is_some())
    }
}

/// What one category's query returned.
pub struct CategoryRead {
    pub category: &'static Category,
    pub events: Vec<Event>,
    pub read: LogRead,
}

/// The "Hardware and driver events" check: one narrow query per category, all within the
/// same deadline.
pub fn hardware_events(cancelled: &AtomicBool, deadline: Instant) -> Outcome {
    let mut reads = Vec::new();
    for category in HARDWARE {
        match read_events(&hardware_query(category), deadline, cancelled) {
            Ok((events, mut logs)) => {
                let Some(read) = logs.pop() else {
                    return Outcome::Unavailable("the event log returned no read".into());
                };
                reads.push(CategoryRead {
                    category,
                    events,
                    read,
                });
            }
            Err(error) => return read_failure(error),
        }
    }
    hardware_outcome(&reads, SystemTime::now())
}

pub fn hardware_outcome(reads: &[CategoryRead], now: SystemTime) -> Outcome {
    let unread: Vec<&CategoryRead> = reads
        .iter()
        .filter(|read| read.read.unavailable.is_some())
        .collect();
    if unread.len() == reads.len() {
        let reasons: Vec<_> = unread
            .iter()
            .filter_map(|read| read.read.unavailable.as_deref())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        return Outcome::Unavailable(format!(
            "the System log could not be read ({})",
            reasons.join("; ")
        ));
    }
    let mut all = Vec::new();
    let mut found: Vec<(&Category, usize, bool)> = Vec::new();
    let mut flagged_by = Vec::new();
    let mut lines = vec![format!(
        "System log, past {}; sources and event ids that point at hardware and drivers, read one kind at a time. Zero events do not prove the hardware is healthy.",
        span(KIND_SPAN)
    )];
    for read in reads {
        let category = read.category;
        if let Some(reason) = &read.read.unavailable {
            lines.push(format!(
                "{} ({}): unavailable, {reason}.",
                category.label, category.scope
            ));
            continue;
        }
        let own: Vec<Event> = read
            .events
            .iter()
            .filter(|event| category.owns(event))
            .cloned()
            .collect();
        if own.is_empty() {
            lines.push(format!("{} ({}): none.", category.label, category.scope));
            continue;
        }
        let summary = summarize(&own, now, true, Vec::new());
        let mut serious = false;
        for group in &summary.groups {
            let tier = group.tier().unwrap_or(if category.all_serious {
                Tier::Serious
            } else {
                Tier::Notable
            });
            serious |= tier == Tier::Serious;
            flagged_by.push(format!(
                "{} {} event {} {}{}",
                category.label,
                group.provider,
                group.id,
                times(group.count),
                if tier == Tier::Serious {
                    ", serious"
                } else {
                    ""
                }
            ));
        }
        let last = own
            .iter()
            .map(|event| event.time)
            .max()
            .unwrap_or(UNIX_EPOCH);
        lines.push(format!(
            "{} ({}): {} {}, newest {}.",
            category.label,
            category.scope,
            own.len(),
            plural(own.len(), "event", "events"),
            clock::local(last).long()
        ));
        found.push((category, own.len(), serious));
        all.extend(own);
    }
    if !all.is_empty() {
        let summary = summarize(&all, now, true, Vec::new());
        lines.push("Kinds, most significant first:".into());
        for (rank, group) in summary.groups.iter().take(LISTED_KINDS).enumerate() {
            lines.push(format!("{}. {}", rank + 1, describe_group(group)));
        }
        if summary.groups.len() > LISTED_KINDS {
            lines.push(format!(
                "Not listed: {} more kinds.",
                summary.groups.len() - LISTED_KINDS
            ));
        }
    }
    let grade = if found.iter().any(|(_, _, serious)| *serious) {
        Grade::Serious
    } else if flagged_by.is_empty() {
        Grade::Clear
    } else {
        Grade::Flagged
    };
    lines.push(match grade {
        Grade::Clear => "Not flagged: no matching events in 7 days.".into(),
        Grade::Flagged => format!(
            "Flagged because of {} (rule: any event in 7 days; serious kinds are marked serious).",
            flagged_by.join("; ")
        ),
        Grade::Serious => format!(
            "Serious because of {} (rule: any event in 7 days; serious kinds are marked serious).",
            flagged_by.join("; ")
        ),
    });
    for read in reads {
        let data = &read.read;
        if data.unavailable.is_none() {
            if let Some(limit) = data.limit {
                lines.push(format!(
                    "{}: {}; older ones were not read.",
                    read.category.label,
                    match limit {
                        Limit::Count => format!("newest {} events read", data.events),
                        Limit::Time => format!("{} events read before the time limit", data.events),
                    }
                ));
            }
            if data.unreadable > 0 {
                lines.push(format!(
                    "{}: {} events could not be read.",
                    read.category.label, data.unreadable
                ));
            }
        }
    }
    found.sort_by(|a, b| b.2.cmp(&a.2).then(b.1.cmp(&a.1)));
    let brief = hardware_brief(
        found
            .first()
            .map(|(category, count, _)| (category.label, *count)),
        found.len(),
        unread.len(),
        reads.len(),
    );
    Outcome::Found(Finding::graded(brief, lines.join("\n"), grade))
}

/// The window row for the hardware check: the leading category and how many others.
fn hardware_brief(
    top: Option<(&str, usize)>,
    categories: usize,
    unread: usize,
    of: usize,
) -> String {
    match top {
        None if unread > 0 => format!("None found, {unread} of {of} unread"),
        None => "None in 7 days".into(),
        Some((label, count)) if categories == 1 => format!("{label}, {}", count_times(count)),
        Some((label, count)) => format!("{label} {}, {} more", count99(count), categories - 1),
    }
}

fn count_times(count: usize) -> String {
    if count > 99 {
        "many times".into()
    } else {
        times(count)
    }
}

/// The longest row texts of the three kind checks, for the window's width test.
fn kind_briefs() -> Vec<String> {
    let wide = "W".repeat(NAME_CHARS);
    let mut briefs = Vec::new();
    for count in [1, 2, 99, 100, 5000] {
        briefs.push(crash_brief(count, 0, Some(&wide)));
        briefs.push(crash_brief(0, count, Some(&wide)));
        briefs.push(crash_brief(count, count, None));
        briefs.push(service_brief(count, Some(&wide)));
        briefs.push(service_brief(count, None));
        for category in HARDWARE {
            briefs.push(hardware_brief(
                Some((category.label, count)),
                1,
                0,
                HARDWARE.len(),
            ));
            briefs.push(hardware_brief(
                Some((category.label, count)),
                HARDWARE.len(),
                HARDWARE.len() - 1,
                HARDWARE.len(),
            ));
        }
    }
    briefs.push(crash_brief(0, 0, None));
    briefs.push(service_brief(0, None));
    briefs.push(hardware_brief(None, 0, 0, HARDWARE.len()));
    briefs.push(hardware_brief(None, 0, HARDWARE.len() - 1, HARDWARE.len()));
    briefs
}

/// The report text for a summary: scope, the first `listed` groups, what was left out
/// or hidden, and how each log was read.
pub fn report_lines(query: &Query, summary: &Summary, listed: usize) -> Vec<String> {
    let mut lines = vec![format!(
        "{} {}; {} events from the past {}, ranked by known significance and recency.",
        query.logs.join(" and "),
        plural(query.logs.len(), "log", "logs"),
        level_list(&query.levels),
        span(query.since),
    )];
    for (rank, group) in summary.groups.iter().take(listed).enumerate() {
        lines.push(format!("{}. {}", rank + 1, describe_group(group)));
    }
    let rest = &summary.groups[summary.groups.len().min(listed)..];
    if !rest.is_empty() {
        let events: usize = rest.iter().map(|group| group.count).sum();
        lines.push(format!(
            "Not listed: {} more {}, {} {}.",
            rest.len(),
            plural(rest.len(), "kind", "kinds"),
            events,
            plural(events, "event", "events")
        ));
    }
    if summary.noise_kinds > 0 {
        lines.push(format!(
            "Hidden as routine: {} {} of {} {} (noise rules version {NOISE_VERSION}).",
            summary.noise_events,
            plural(summary.noise_events, "event", "events"),
            summary.noise_kinds,
            plural(summary.noise_kinds, "kind", "kinds"),
        ));
    }
    lines.extend(read_lines(&summary.reads));
    lines
}

fn span(since: Duration) -> String {
    let hours = since.as_secs().div_ceil(3600).max(1);
    match (hours % 24, hours / 24) {
        (0, 1) => "day".into(),
        (0, days) => format!("{days} days"),
        _ if hours == 1 => "hour".into(),
        _ => format!("{hours} hours"),
    }
}

/// One line for a group: meaning, source and id, log, level, count and times.
pub fn describe_group(group: &Group) -> String {
    let what = match (group.known, group.noise) {
        (Some(kind), _) => format!("{}: {}. ", kind.short, kind.meaning),
        (None, Some(rule)) => format!("Routine: {}. ", rule.reason),
        (None, None) => String::new(),
    };
    let mut text = format!(
        "{what}{} event {} ({}), {}, {}, last {}",
        group.provider,
        group.id,
        group.log,
        level_name(group.level),
        times(group.count),
        clock::local(group.last).long()
    );
    if group.count > 1 {
        text.push_str(&format!(", first {}", clock::local(group.first).long()));
    }
    text.push('.');
    text
}

fn level_list(levels: &[u8]) -> String {
    if levels.is_empty() {
        return "all".into();
    }
    let names: Vec<_> = levels.iter().map(|&level| level_name(level)).collect();
    match names.split_last() {
        Some((last, [])) => (*last).into(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
        None => String::new(),
    }
}

fn times(count: usize) -> String {
    match count {
        1 => "once".into(),
        2 => "twice".into(),
        n => format!("{n} times"),
    }
}

fn plural(count: usize, one: &'static str, many: &'static str) -> &'static str {
    if count == 1 {
        one
    } else {
        many
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_793_000_000;

    fn at(hours_ago: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(NOW) - HOUR * hours_ago as u32
    }

    fn event(log: &str, provider: &str, id: u32, level: u8, hours_ago: u64) -> Event {
        Event {
            log: log.into(),
            provider: provider.into(),
            id,
            level,
            time: at(hours_ago),
            message: None,
        }
    }

    fn read(log: &str, events: usize) -> LogRead {
        LogRead {
            log: log.into(),
            events,
            unreadable: 0,
            limit: None,
            unavailable: None,
        }
    }

    fn now() -> SystemTime {
        at(0)
    }

    fn found(outcome: Outcome) -> Finding {
        match outcome {
            Outcome::Found(finding) => finding,
            other => panic!("expected a finding, got {other:?}"),
        }
    }

    #[test]
    fn every_noise_rule_hides_its_kind_and_counts_it() {
        for rule in NOISE {
            let events = [
                event("System", rule.provider, rule.id, 3, 2),
                event("System", &rule.provider.to_ascii_uppercase(), rule.id, 3, 1),
                event("System", "Test-Provider", 42, 2, 1),
            ];
            let summary = summarize(&events, now(), false, vec![read("System", 3)]);
            assert_eq!(
                summary.groups.len(),
                1,
                "{} {} was not hidden",
                rule.provider,
                rule.id
            );
            assert_eq!((summary.noise_events, summary.noise_kinds), (2, 1));
            let shown = summarize(&events, now(), true, vec![read("System", 3)]);
            assert!(shown.groups.iter().any(|g| g.noise == Some(rule)));
            assert!(
                known(rule.provider, rule.id).is_none(),
                "{} {} is both noise and known",
                rule.provider,
                rule.id
            );
        }
    }

    #[test]
    fn every_known_kind_is_recognised_for_each_source_and_id() {
        for kind in KNOWN {
            for provider in kind.providers {
                for &id in kind.ids {
                    assert_eq!(known(provider, id), Some(kind));
                    assert_eq!(known(&provider.to_ascii_lowercase(), id), Some(kind));
                    assert!(noise(provider, id).is_none());
                }
            }
        }
        assert!(known("Microsoft-Windows-Kernel-Power", 42).is_none());
        assert!(known("Unknown-Provider", 41).is_none());
    }

    #[test]
    fn serious_kinds_outrank_frequent_unknown_errors_and_recent_beats_old() {
        let mut events = vec![event(
            "System",
            "Microsoft-Windows-Kernel-Power",
            41,
            1,
            100,
        )];
        for _ in 0..40 {
            events.push(event("Application", "Chatty-App", 7, 2, 1));
        }
        events.push(event("Application", "Application Error", 1000, 2, 150));
        events.push(event("Application", "Application Hang", 1002, 2, 2));
        let summary = summarize(&events, now(), false, vec![]);
        let order: Vec<_> = summary
            .groups
            .iter()
            .map(|g| (g.provider.as_str(), g.id))
            .collect();
        assert_eq!(
            order,
            [
                ("Microsoft-Windows-Kernel-Power", 41),
                ("Application Hang", 1002),
                ("Application Error", 1000),
                ("Chatty-App", 7),
            ]
        );
        let chatty = &summary.groups[3];
        assert_eq!(
            (chatty.count, chatty.first, chatty.last),
            (40, at(1), at(1))
        );
    }

    #[test]
    fn a_group_keeps_its_most_severe_level_and_its_time_span() {
        let events = [
            event("System", "Test-Provider", 5, 3, 30),
            event("System", "Test-Provider", 5, 1, 20),
            event("System", "test-provider", 5, 2, 10),
        ];
        let summary = summarize(&events, now(), false, vec![]);
        let group = &summary.groups[0];
        assert_eq!(
            (group.level, group.count, group.first, group.last),
            (1, 3, at(30), at(10))
        );
    }

    #[test]
    fn the_filter_takes_only_plain_names_and_bounded_ranges() {
        let mut query = Query::survey();
        assert_eq!(
            xpath(&query).unwrap(),
            "*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[timediff(@SystemTime) <= 604800000]]]"
        );
        query.providers = vec!["Service Control Manager".into()];
        query.ids = vec![7031, 7034];
        query.levels = vec![4];
        assert_eq!(
            xpath(&query).unwrap(),
            "*[System[Provider[@Name='Service Control Manager'] and (EventID=7031 or EventID=7034) and (Level=0 or Level=4) and TimeCreated[timediff(@SystemTime) <= 604800000]]]"
        );
        for bad in ["x' or '1'='1", "a]b", "", "a\u{0}b"] {
            query.providers = vec![bad.into()];
            assert!(xpath(&query).is_err(), "{bad:?} was accepted");
        }
        query.providers.clear();
        query.ids = vec![70000];
        assert!(xpath(&query).is_err());
        query.ids.clear();
        query.since = MAX_SINCE + Duration::from_secs(1);
        assert!(xpath(&query).is_err());
        assert!(plain_name(
            "Microsoft-Windows-Kernel-Power/Thermal-Operational",
            true
        ));
        assert!(!plain_name(
            "Microsoft-Windows-Kernel-Power/Thermal-Operational",
            false
        ));
    }

    #[test]
    fn words_ending_in_non_ascii_characters_are_redacted_without_panicking() {
        assert_eq!(
            redact("Café path\u{FFFF} naïve.", &[]),
            "Café path\u{FFFF} naïve."
        );
        assert_eq!(redact("10.0.0.1, café", &[]), "[address], café");
    }

    #[test]
    fn excerpts_lose_names_profiles_accounts_and_addresses() {
        let names = vec![
            "WORKSTATION01".to_string(),
            "alex".to_string(),
            "ab".to_string(),
        ];
        let text = "The  program\r\nC:\\Users\\Alex Smith\\AppData\\app.exe on Workstation01 for S-1-5-21-111-222-333-1001 \
                    (alex@example.com) at 10.0.0.20:445, fe80::1%12 and 00-1A-2B-3C-4D-5E at 12:30:45 ab. \
                    App version: 1.0.0.0";
        let out = redact(text, &names);
        assert_eq!(
            out,
            "The program C:\\Users\\[user]\\AppData\\app.exe on [name] for [account] ([email]) at [address], [address] and [hardware address] at 12:30:45 ab. App version: 1.0.0.0"
        );
        let long = "word ".repeat(200);
        let cut = redact(&long, &[]);
        assert_eq!(cut.chars().count(), EXCERPT_CHARS);
        assert!(cut.ends_with('…'));
    }

    #[test]
    fn the_survey_names_the_serious_kind_and_counts_the_hidden_noise() {
        let events = [
            event("System", "Microsoft-Windows-Kernel-Power", 41, 1, 30),
            event("System", "Microsoft-Windows-Kernel-Power", 41, 1, 5),
            event("System", "Microsoft-Windows-DistributedCOM", 10016, 3, 1),
            event("Application", "Chatty-App", 7, 3, 1),
        ];
        let query = Query::survey();
        let summary = summarize(
            &events,
            now(),
            false,
            vec![read("System", 3), read("Application", 1)],
        );
        let finding = found(survey_outcome(&query, &summary));
        assert_eq!(finding.brief, "Unexpected restart, twice");
        assert_eq!(finding.grade, Grade::Serious);
        assert!(finding
            .detail
            .contains("1. Unexpected restart: Windows restarted without shutting down cleanly"));
        assert!(finding
            .detail
            .contains("Hidden as routine: 1 event of 1 kind (noise rules version 1)."));
        assert!(!finding.detail.contains("DistributedCOM"));
        assert!(finding.detail.starts_with(
            "System and Application logs; critical, error and warning events from the past 7 days"
        ));
    }

    #[test]
    fn the_survey_reads_quiet_partial_and_unreadable_logs_honestly() {
        let query = Query::survey();
        let quiet = summarize(
            &[],
            now(),
            false,
            vec![read("System", 0), read("Application", 0)],
        );
        let finding = found(survey_outcome(&query, &quiet));
        assert_eq!(finding.brief, "No errors or warnings");
        assert_eq!(finding.grade, Grade::Clear);

        let mut denied = read("Application", 0);
        denied.unavailable = Some("this account may not read it".into());
        let mut capped = read("System", 2000);
        capped.limit = Some(Limit::Count);
        capped.unreadable = 3;
        let events = [
            event("System", "Chatty-App", 7, 2, 1),
            event("System", "Other-App", 9, 3, 1),
        ];
        let partial = summarize(&events, now(), false, vec![capped, denied.clone()]);
        let finding = found(survey_outcome(&query, &partial));
        assert_eq!(finding.brief, "2 kinds, Application unread");
        assert!(finding
            .detail
            .contains("System: newest 2000 events read; older ones were not."));
        assert!(finding
            .detail
            .contains("System: 3 events could not be read."));
        assert!(finding
            .detail
            .contains("Application: unavailable, this account may not read it."));
        assert_eq!(finding.grade, Grade::Flagged, "an error of an unknown kind");

        let mut system = read("System", 0);
        system.unavailable = Some("no such log on this PC".into());
        let none = summarize(&[], now(), false, vec![system, denied]);
        assert_eq!(
            survey_outcome(&query, &none),
            Outcome::Unavailable("event logs could not be read (System: no such log on this PC; Application: this account may not read it)".into())
        );
    }

    #[test]
    fn notable_kinds_and_unknown_errors_flag_the_survey_and_warnings_alone_do_not() {
        let events = [
            event("Application", "Application Error", 1000, 2, 3),
            event("Application", "Application Error", 1000, 2, 4),
            event("System", "Service Control Manager", 7031, 2, 5),
        ];
        let summary = summarize(
            &events,
            now(),
            false,
            vec![read("System", 1), read("Application", 2)],
        );
        let finding = found(survey_outcome(&Query::survey(), &summary));
        assert_eq!(finding.brief, "App crash, 1 more");
        assert_eq!(finding.grade, Grade::Flagged);
        assert!(finding.detail.ends_with(
            "Flagged: a known kind, or an error or critical event of another kind, happened."
        ));

        let unknown = [
            event("System", "Chatty-App", 7, 2, 1),
            event("System", "Other-App", 9, 3, 1),
        ];
        let reads = || vec![read("System", 2), read("Application", 0)];
        let errors = found(survey_outcome(
            &Query::survey(),
            &summarize(&unknown, now(), false, reads()),
        ));
        assert_eq!(errors.brief, "2 kinds, none known");
        assert_eq!(errors.grade, Grade::Flagged);

        let warnings = found(survey_outcome(
            &Query::survey(),
            &summarize(&unknown[1..], now(), false, reads()),
        ));
        assert_eq!(warnings.brief, "1 kind, warnings only");
        assert_eq!(warnings.grade, Grade::Clear);
    }

    #[test]
    fn filetimes_convert_to_system_time() {
        assert_eq!(from_filetime(116_444_736_000_000_000), UNIX_EPOCH);
        assert_eq!(
            from_filetime(116_444_736_000_000_000 + 15_000_000),
            UNIX_EPOCH + Duration::from_millis(1500)
        );
        assert_eq!(from_filetime(0), UNIX_EPOCH);
    }

    /// Reads this PC's own logs; the survey's query must parse and come back with
    /// counts, whatever the logs hold.
    #[test]
    fn the_survey_query_reads_this_pcs_logs() {
        let cancelled = AtomicBool::new(false);
        let summary = super::read(
            &Query::survey(),
            Instant::now() + Duration::from_secs(30),
            &cancelled,
        )
        .expect("the survey query is accepted");
        assert_eq!(summary.reads.len(), 2);
        assert!(
            summary.reads.iter().any(|read| read.unavailable.is_none()),
            "neither log could be read: {:?}",
            summary.reads
        );
        assert!(summary.groups.iter().all(|group| group.noise.is_none()));
    }

    fn with_data(
        log: &str,
        provider: &str,
        id: u32,
        level: u8,
        hours_ago: u64,
        data: &[Option<&str>],
    ) -> WithData {
        (
            event(log, provider, id, level, hours_ago),
            data.iter().map(|value| value.map(String::from)).collect(),
        )
    }

    fn crash(hours_ago: u64, data: &[Option<&str>]) -> WithData {
        with_data("Application", "Application Error", 1000, 2, hours_ago, data)
    }

    fn operators(query: &Query) -> usize {
        let filter = xpath(query).unwrap();
        filter.matches(" and ").count() + filter.matches(" or ").count()
    }

    #[test]
    fn the_new_kinds_are_known_with_their_tier() {
        let removed = known("disk", 157).unwrap();
        assert_eq!(
            (removed.short, removed.tier),
            ("Drive removed", Tier::Notable)
        );
        assert_eq!(known("DISK", 7).unwrap().short, "Drive error");
        let load = known("Microsoft-Windows-Kernel-PnP", 219).unwrap();
        assert_eq!(
            (load.short, load.tier),
            ("Driver failed to load", Tier::Notable)
        );
        assert!(known("Microsoft-Windows-Kernel-PnP", 411).is_none());
    }

    #[test]
    fn each_kind_query_stays_under_the_filter_operator_limit() {
        let mut queries = vec![crash_query(), service_query()];
        queries.extend(HARDWARE.iter().map(hardware_query));
        for query in &queries {
            let count = operators(query);
            assert!(count < 22, "{query:?} has {count} operators");
            assert!(count < 20, "{query:?} leaves too little headroom: {count}");
            assert_eq!(query.since, KIND_SPAN);
        }
        let drive = hardware_query(&HARDWARE[1]);
        assert_eq!(
            xpath(&drive).unwrap(),
            "*[System[Provider[@Name='disk' or @Name='stornvme' or @Name='storahci' or @Name='iaStorAC' or @Name='iaStorA' or @Name='iaStorAVC'] and (EventID=7 or EventID=11 or EventID=51 or EventID=129 or EventID=153 or EventID=154 or EventID=157) and TimeCreated[timediff(@SystemTime) <= 604800000]]]"
        );
        assert_eq!(operators(&drive), 13);
    }

    #[test]
    fn app_crashes_name_the_most_frequent_app_its_module_and_exception() {
        let events = vec![
            crash(
                2,
                &[Some("chrome.exe"), Some("ntdll.dll"), Some("c0000005")],
            ),
            crash(
                30,
                &[Some("Chrome.exe"), Some("ntdll.dll"), Some("c0000005")],
            ),
            crash(
                50,
                &[Some("chrome.exe"), Some("KERNELBASE.dll"), Some("e0434352")],
            ),
            crash(
                60,
                &[Some(r"C:\Users\alex\AppData\other.exe"), None, Some("zz")],
            ),
            with_data(
                "Application",
                "Application Hang",
                1002,
                2,
                70,
                &[Some("other.exe")],
            ),
            with_data(
                "Application",
                "Other Source",
                1000,
                2,
                5,
                &[Some("ignored.exe")],
            ),
        ];
        let finding = found(crashes_outcome(
            &events,
            &[read("Application", 6)],
            now(),
            &["alex".to_string()],
        ));
        assert_eq!(finding.brief, "4 crashes: chrome");
        assert!(finding.flagged());
        let detail = &finding.detail;
        assert!(
            detail.contains("Crashes: 4 (1 in the past 24 hours), newest"),
            "{detail}"
        );
        assert!(detail.contains("Hangs: 1 (0 in the past 24 hours), newest"));
        assert!(detail.contains("1. chrome.exe: 3 crashes, newest"));
        assert!(detail.contains("faulting module ntdll.dll in 2, exception code 0xc0000005 in 2"));
        assert!(detail.contains("2. other.exe: 1 crash"));
        assert!(detail.contains("Hangs by app, most frequent first:\n1. other.exe: 1 hang"));
        assert!(detail.contains(
            "Flagged because of 5 crashes or hangs in 7 days, 1 in the past 24 hours (rule: any in 7 days)."
        ));
        assert!(!detail.contains("alex"));
        assert!(detail.ends_with("Application: 6 events read."));
    }

    #[test]
    fn app_crashes_any_crash_flags_and_quiet_and_unnamed_cases_are_honest() {
        let one = found(crashes_outcome(
            &[crash(
                100,
                &[Some("a.exe"), Some("b.dll"), Some("c0000374")],
            )],
            &[read("Application", 1)],
            now(),
            &[],
        ));
        assert_eq!(one.brief, "1 crash: a");
        assert_eq!(
            one.grade,
            Grade::Flagged,
            "a single crash 4 days ago is still a crash"
        );
        assert!(one
            .detail
            .contains("Flagged because of 1 crash or hang in 7 days, 0 in the past 24 hours"));
        let quiet = found(crashes_outcome(&[], &[read("Application", 0)], now(), &[]));
        assert_eq!(quiet.brief, "None in 7 days");
        assert_eq!(quiet.grade, Grade::Clear);
        assert!(quiet.detail.contains("Crashes: none."));
        assert!(quiet.detail.contains("Application: 0 events read."));
        let unnamed = found(crashes_outcome(
            &[crash(1, &[None, None, Some("not hex")])],
            &[read("Application", 1)],
            now(),
            &[],
        ));
        assert_eq!(unnamed.brief, "1 crash: unnamed");
        assert!(unnamed.flagged());
        assert!(!unnamed.detail.contains("exception code"));
        let hangs = found(crashes_outcome(
            &[with_data(
                "Application",
                "Application Hang",
                1002,
                2,
                3,
                &[Some("x.exe")],
            )],
            &[read("Application", 1)],
            now(),
            &[],
        ));
        assert_eq!(hangs.brief, "1 hang: x");
    }

    #[test]
    fn app_crashes_unreadable_log_is_unavailable_and_a_long_name_is_cut() {
        let mut denied = read("Application", 0);
        denied.unavailable = Some("this account may not read it".into());
        assert_eq!(
            crashes_outcome(&[], &[denied], now(), &[]),
            Outcome::Unavailable(
                "event logs could not be read (Application: this account may not read it)".into()
            )
        );
        let long = "VeryLongApplicationNameThatKeepsGoing.exe";
        let finding = found(crashes_outcome(
            &[crash(1, &[Some(long)])],
            &[read("Application", 1)],
            now(),
            &[],
        ));
        assert_eq!(finding.brief, "1 crash: VeryLongA…");
        assert!(finding.detail.contains(long));
    }

    #[test]
    fn services_are_named_from_the_right_data_item() {
        let scm = |id: u32, hours: u64, data: &[Option<&str>]| {
            with_data("System", "Service Control Manager", id, 2, hours, data)
        };
        let events = vec![
            scm(7031, 30, &[Some("Print Spooler"), Some("1"), Some("5000")]),
            scm(7034, 40, &[Some("print spooler"), Some("1")]),
            scm(7009, 50, &[Some("30000"), Some("Steam Client Service")]),
            scm(7000, 60, &[Some("Sample daemon (alex)"), Some("%%2")]),
            scm(7036, 5, &[Some("Print Spooler"), Some("running")]),
            with_data("System", "Other Source", 7031, 2, 3, &[Some("ignored")]),
        ];
        let finding = found(services_outcome(
            &events,
            &[read("System", 6)],
            now(),
            &["alex".to_string()],
        ));
        assert_eq!(finding.brief, "4 failures: Print Spo…");
        assert_eq!(
            finding.grade,
            Grade::Flagged,
            "old failures still flag the row"
        );
        let detail = &finding.detail;
        assert!(
            detail.contains("Failures: 4 across 3 services (0 in the past 24 hours)"),
            "{detail}"
        );
        assert!(detail.contains("1. Print Spooler: 2 failures (event 7031 once, event 7034 once)"));
        assert!(detail.contains("2. Steam Client Service: 1 failure"));
        assert!(detail.contains("Sample daemon ([name])"));
        assert!(!detail.contains("alex"));
        let recent = found(services_outcome(
            &[scm(7023, 3, &[Some("Windows Update"), Some("%%32")])],
            &[read("System", 1)],
            now(),
            &[],
        ));
        assert!(recent.flagged());
        assert!(recent
            .detail
            .contains("Flagged because of 1 failure in 7 days, 1 in the past 24 hours"));
        let none = found(services_outcome(&[], &[read("System", 0)], now(), &[]));
        assert_eq!(none.brief, "None in 7 days");
        assert_eq!(none.grade, Grade::Clear);
        assert!(none.detail.contains("Failures: none."));
        assert!(matches!(
            services_outcome(
                &[],
                &[{
                    let mut r = read("System", 0);
                    r.unavailable = Some("no such log on this PC".into());
                    r
                }],
                now(),
                &[]
            ),
            Outcome::Unavailable(_)
        ));
    }

    fn category_reads(events: &[Event]) -> Vec<CategoryRead> {
        HARDWARE
            .iter()
            .map(|category| CategoryRead {
                category,
                events: events
                    .iter()
                    .filter(|event| {
                        category
                            .providers
                            .iter()
                            .any(|name| name.eq_ignore_ascii_case(&event.provider))
                    })
                    .cloned()
                    .collect(),
                read: read("System", 0),
            })
            .collect()
    }

    #[test]
    fn hardware_events_flag_serious_kinds_and_rank_them_first() {
        let events = [
            event("System", "Microsoft-Windows-WHEA-Logger", 17, 3, 5),
            event("System", "Microsoft-Windows-WHEA-Logger", 99, 3, 6),
            event("System", "disk", 7, 2, 20),
            event("System", "disk", 129, 2, 21),
            event("System", "Microsoft-Windows-Kernel-PnP", 219, 3, 3),
            event("System", "Microsoft-Windows-Kernel-PnP", 219, 3, 4),
        ];
        let finding = found(hardware_outcome(&category_reads(&events), now()));
        assert_eq!(finding.brief, "Hardware error 2, 2 more");
        assert_eq!(finding.grade, Grade::Serious);
        let detail = &finding.detail;
        assert!(
            detail.contains("Hardware error (WHEA-Logger, any event id): 2 events"),
            "{detail}"
        );
        assert!(detail.contains("Drive error ("));
        assert!(detail.contains("): 1 event, newest"), "{detail}");
        assert!(detail.contains(
            "File system error (Ntfs 55, 98, 130, 137, 140, errors and warnings only): none."
        ));
        assert!(detail.contains("1. Hardware error: the processor, memory or PCIe bus"));
        assert!(detail.contains("Microsoft-Windows-WHEA-Logger event 99 (System), warning"));
        assert!(
            !detail.contains("event 129"),
            "a source and id pair that is not a known kind is dropped"
        );
        assert!(detail.contains(
            "Serious because of Hardware error Microsoft-Windows-WHEA-Logger event 17 once, serious"
        ));
        assert!(detail.contains("Zero events do not prove the hardware is healthy."));
    }

    #[test]
    fn hardware_notable_kinds_flag_on_any_event_and_serious_kinds_are_serious() {
        let pnp = |hours: u64| event("System", "Microsoft-Windows-Kernel-PnP", 219, 3, hours);
        let one = found(hardware_outcome(&category_reads(&[pnp(1)]), now()));
        assert_eq!(one.brief, "Driver load failure, once");
        assert_eq!(one.grade, Grade::Flagged);
        assert!(one.detail.contains(
            "Flagged because of Driver load failure Microsoft-Windows-Kernel-PnP event 219 once (rule: any event in 7 days"
        ));
        let removed = found(hardware_outcome(
            &category_reads(&[event("System", "disk", 157, 2, 1)]),
            now(),
        ));
        assert_eq!(removed.brief, "Drive error, once");
        assert_eq!(removed.grade, Grade::Flagged, "a removed drive is notable");
        let reset = found(hardware_outcome(
            &category_reads(&[event("System", "stornvme", 129, 3, 1)]),
            now(),
        ));
        assert_eq!(reset.grade, Grade::Serious, "a drive reset is serious");
    }

    #[test]
    fn hardware_quiet_partial_and_unreadable_reads_are_honest() {
        let quiet = found(hardware_outcome(&category_reads(&[]), now()));
        assert_eq!(quiet.brief, "None in 7 days");
        assert_eq!(quiet.grade, Grade::Clear);
        assert!(quiet
            .detail
            .contains("Not flagged: no matching events in 7 days."));
        let mut partial = category_reads(&[]);
        partial[1].read.unavailable = Some("the filter was refused".into());
        let partial = found(hardware_outcome(&partial, now()));
        assert_eq!(partial.brief, "None found, 1 of 5 unread");
        assert!(!partial.flagged());
        assert!(partial.detail.contains("Drive error (disk 7, 11"));
        assert!(partial
            .detail
            .contains("unavailable, the filter was refused."));
        let mut all = category_reads(&[]);
        for part in &mut all {
            part.read.unavailable = Some("this account may not read it".into());
        }
        assert_eq!(
            hardware_outcome(&all, now()),
            Outcome::Unavailable(
                "the System log could not be read (this account may not read it)".into()
            )
        );
        let mut capped = category_reads(&[event("System", "disk", 7, 2, 1)]);
        capped[1].read.limit = Some(Limit::Count);
        capped[1].read.events = 1000;
        assert!(found(hardware_outcome(&capped, now()))
            .detail
            .contains("Drive error: newest 1000 events read; older ones were not read."));
    }

    #[test]
    fn data_items_of_real_events_are_read_and_bad_requests_refused() {
        let mut query = Query::survey();
        query.logs = vec!["System".into()];
        query.levels = Vec::new();
        query.providers = vec!["Service Control Manager".into()];
        query.ids = vec![7040];
        query.since = MAX_SINCE;
        query.per_log_limit = 5;
        let cancelled = AtomicBool::new(false);
        let (events, reads) = read_events_with_data(
            &query,
            &["param1", "param2"],
            Instant::now() + Duration::from_secs(10),
            &cancelled,
        )
        .unwrap();
        assert!(reads[0].unavailable.is_none(), "{reads:?}");
        for (event, data) in &events {
            assert_eq!(event.id, 7040);
            assert_eq!(data.len(), 2);
            assert!(
                data[0].as_deref().is_some_and(|name| !name.is_empty()),
                "{data:?}"
            );
        }
        for bad in [
            &[""][..],
            &["a']"],
            &["Data[1]"],
            &["a", "b", "c", "d", "e", "f", "g", "h", "i"],
        ] {
            assert!(matches!(
                read_events_with_data(&query, bad, Instant::now(), &cancelled),
                Err(ReadError::Invalid(_))
            ));
        }
    }

    #[test]
    fn the_kind_queries_read_this_pcs_logs() {
        let cancelled = AtomicBool::new(false);
        for query in [crash_query(), service_query()]
            .into_iter()
            .chain(HARDWARE.iter().map(hardware_query))
        {
            let (_, reads) =
                read_events(&query, Instant::now() + Duration::from_secs(10), &cancelled).unwrap();
            assert!(reads[0].unavailable.is_none(), "{query:?}: {reads:?}");
        }
        let deadline = Instant::now() + Duration::from_secs(12);
        for outcome in [
            app_crashes(&cancelled, deadline),
            service_failures(&cancelled, deadline),
            hardware_events(&cancelled, deadline),
        ] {
            let finding = found(outcome);
            assert!(!finding.brief.is_empty() && !finding.detail.is_empty());
        }
    }
}
