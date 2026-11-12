//! The live sampler engine: `run(&MonitorOptions, on_event, cancel) -> Summary` reads CPU and
//! memory figures at a fixed interval and hands each one over as a typed `Sample`, plain data
//! with its units in the field names so it can travel as JSON. It has no window in it; the
//! window, and later the technician's live monitor, only show what it sends.
//!
//! Sources, all readable as the current user: PDH's Processor Information counters for the
//! use of each logical processor and the clock (% Processor Performance against Processor
//! Frequency), GlobalMemoryStatusEx and GetPerformanceInfo for memory, commit, pools and the
//! process, thread and handle counts, and PDH's Memory counters for the page lists.
use std::collections::VecDeque;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::System::Performance::{
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterArrayW,
    PdhGetFormattedCounterValue, PdhOpenQueryW, PDH_FMT_COUNTERVALUE, PDH_FMT_COUNTERVALUE_ITEM_W,
    PDH_FMT_DOUBLE,
};

/// PDH_FMT_NOCAP100: % Processor Performance passes 100 while the processor boosts.
const PDH_FMT_NOCAP100: u32 = 0x8000;

/// The interval's bounds and default, in milliseconds.
pub const MIN_INTERVAL_MS: u32 = 250;
pub const MAX_INTERVAL_MS: u32 = 10_000;
pub const DEFAULT_INTERVAL_MS: u32 = 1_000;
/// Samples a `History` keeps: 30 minutes at one a second.
pub const HISTORY: usize = 1_800;

/// Which figures to read; reading fewer costs less.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Series {
    /// Total CPU use.
    pub cpu: bool,
    /// The use of each logical processor.
    pub per_processor: bool,
    /// The clock measured from the processor's performance counter.
    pub clock: bool,
    /// Memory in use, the page lists, commit and pools.
    pub memory: bool,
    /// Process, thread and handle counts, and the time since Windows started.
    pub system: bool,
}

impl Series {
    pub const ALL: Series = Series {
        cpu: true,
        per_processor: true,
        clock: true,
        memory: true,
        system: true,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorOptions {
    /// Milliseconds between samples, `MIN_INTERVAL_MS` to `MAX_INTERVAL_MS`.
    pub interval_ms: u32,
    pub series: Series,
    /// Stop after this many samples; None runs until cancelled.
    pub max_samples: Option<u64>,
}

impl Default for MonitorOptions {
    fn default() -> Self {
        Self {
            interval_ms: DEFAULT_INTERVAL_MS,
            series: Series::ALL,
            max_samples: None,
        }
    }
}

impl MonitorOptions {
    /// Refuses an interval out of bounds or a run of zero samples.
    pub fn check(&self) -> Result<(), String> {
        if !(MIN_INTERVAL_MS..=MAX_INTERVAL_MS).contains(&self.interval_ms) {
            return Err(format!(
                "the interval must be {MIN_INTERVAL_MS} to {MAX_INTERVAL_MS} ms, not {}",
                self.interval_ms
            ));
        }
        if self.max_samples == Some(0) {
            return Err("a run needs at least one sample".into());
        }
        Ok(())
    }
}

/// Physical memory and its page lists, in bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct MemorySample {
    /// What Windows can use.
    pub total_bytes: u64,
    /// Total less the modified, standby and free lists; total less available when the lists
    /// cannot be read.
    pub in_use_bytes: u64,
    /// Standby and free: what can be handed out without writing anything.
    pub available_bytes: u64,
    /// Changed pages waiting to be written before reuse. None when the counter is unreadable.
    pub modified_bytes: Option<u64>,
    /// Cached pages that can be reused at once.
    pub standby_bytes: Option<u64>,
    /// Free and zeroed pages.
    pub free_bytes: Option<u64>,
    /// Standby plus modified.
    pub cached_bytes: Option<u64>,
    pub committed_bytes: u64,
    pub commit_limit_bytes: u64,
    pub paged_pool_bytes: u64,
    pub nonpaged_pool_bytes: u64,
}

/// One reading.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Sample {
    /// 0 for the first sample of a run.
    pub index: u64,
    /// Milliseconds since the run started.
    pub elapsed_ms: u64,
    /// Milliseconds since 1970-01-01 UTC.
    pub unix_ms: u64,
    /// Share of all logical processors busy over the last interval, 0 to 100.
    pub cpu_percent: Option<f64>,
    /// Each logical processor's busy share, 0 to 100, in Windows' processor order; None for
    /// one whose counter gave no valid value this time.
    pub per_processor_percent: Vec<Option<f64>>,
    /// The average clock over the last interval, in MHz.
    pub clock_mhz: Option<f64>,
    pub memory: Option<MemorySample>,
    pub processes: Option<u32>,
    pub threads: Option<u32>,
    pub handles: Option<u32>,
    pub uptime_s: Option<u64>,
}

/// What the run sends while it runs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Event {
    /// Once, before the first sample: the fixed figures.
    Started {
        logical_processors: u32,
        /// The processor's rated clock in MHz, as PDH gives it.
        base_mhz: Option<f64>,
        /// Series asked for that cannot be read here, with the reason.
        unavailable: Vec<String>,
    },
    Sample(Sample),
}

/// Minimum, average and maximum of one series over a run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Stat {
    pub min: f64,
    pub avg: f64,
    pub max: f64,
    pub count: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct Acc {
    min: f64,
    max: f64,
    sum: f64,
    count: u64,
}

impl Acc {
    fn add(&mut self, v: f64) {
        if !v.is_finite() {
            return;
        }
        if self.count == 0 {
            self.min = v;
            self.max = v;
        } else {
            self.min = self.min.min(v);
            self.max = self.max.max(v);
        }
        self.sum += v;
        self.count += 1;
    }

    fn stat(&self) -> Option<Stat> {
        (self.count > 0).then(|| Stat {
            min: self.min,
            avg: self.sum / self.count as f64,
            max: self.max,
            count: self.count,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ended {
    Cancelled,
    Reached,
}

/// The run's result: how it ended and each series' minimum, average and maximum.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    pub samples: u64,
    pub elapsed_ms: u64,
    pub ended: Option<Ended>,
    pub cpu_percent: Option<Stat>,
    pub per_processor_percent: Vec<Option<Stat>>,
    pub clock_mhz: Option<Stat>,
    pub memory_in_use_bytes: Option<Stat>,
    pub committed_bytes: Option<Stat>,
    pub processes: Option<Stat>,
    pub threads: Option<Stat>,
    pub handles: Option<Stat>,
}

/// Accumulates samples into a `Summary`.
#[derive(Default)]
pub struct Totals {
    samples: u64,
    elapsed_ms: u64,
    cpu: Acc,
    per: Vec<Acc>,
    clock: Acc,
    in_use: Acc,
    commit: Acc,
    processes: Acc,
    threads: Acc,
    handles: Acc,
}

impl Totals {
    pub fn add(&mut self, s: &Sample) {
        self.samples += 1;
        self.elapsed_ms = s.elapsed_ms;
        if let Some(v) = s.cpu_percent {
            self.cpu.add(v);
        }
        if self.per.len() < s.per_processor_percent.len() {
            self.per
                .resize(s.per_processor_percent.len(), Acc::default());
        }
        for (acc, v) in self.per.iter_mut().zip(&s.per_processor_percent) {
            if let Some(v) = v {
                acc.add(*v);
            }
        }
        if let Some(v) = s.clock_mhz {
            self.clock.add(v);
        }
        if let Some(m) = &s.memory {
            self.in_use.add(m.in_use_bytes as f64);
            self.commit.add(m.committed_bytes as f64);
        }
        for (acc, v) in [
            (&mut self.processes, s.processes),
            (&mut self.threads, s.threads),
            (&mut self.handles, s.handles),
        ] {
            if let Some(v) = v {
                acc.add(f64::from(v));
            }
        }
    }

    pub fn summary(&self, ended: Option<Ended>) -> Summary {
        Summary {
            samples: self.samples,
            elapsed_ms: self.elapsed_ms,
            ended,
            cpu_percent: self.cpu.stat(),
            per_processor_percent: self.per.iter().map(Acc::stat).collect(),
            clock_mhz: self.clock.stat(),
            memory_in_use_bytes: self.in_use.stat(),
            committed_bytes: self.commit.stat(),
            processes: self.processes.stat(),
            threads: self.threads.stat(),
            handles: self.handles.stat(),
        }
    }
}

// ---- readings ----------------------------------------------------------------------------

pub fn logical_processors() -> u32 {
    crate::live::reading("the processor count");
    // SAFETY: a plain query; 0xFFFF means all processor groups.
    unsafe { windows_sys::Win32::System::Threading::GetActiveProcessorCount(0xFFFF) }.max(1)
}

/// Memory and commit totals, and the counts GetPerformanceInfo gives.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct MemoryStatus {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub committed_bytes: u64,
    pub commit_limit_bytes: u64,
    pub paged_pool_bytes: u64,
    pub nonpaged_pool_bytes: u64,
    pub processes: u32,
    pub threads: u32,
    pub handles: u32,
}

pub fn memory_status() -> Option<MemoryStatus> {
    use windows_sys::Win32::System::ProcessStatus::{GetPerformanceInfo, PERFORMANCE_INFORMATION};
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    // SAFETY: plain integers; the length is set before the call.
    let mut status: MEMORYSTATUSEX = unsafe { zeroed() };
    status.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
    // SAFETY: a valid out pointer with its length set.
    if unsafe { GlobalMemoryStatusEx(&mut status) } == 0 {
        return None;
    }
    // SAFETY: plain integers; the size is given.
    let mut info: PERFORMANCE_INFORMATION = unsafe { zeroed() };
    info.cb = size_of::<PERFORMANCE_INFORMATION>() as u32;
    // SAFETY: a valid out pointer with its size given.
    if unsafe { GetPerformanceInfo(&mut info, info.cb) } == 0 {
        return None;
    }
    let page = info.PageSize as u64;
    Some(MemoryStatus {
        total_bytes: status.ullTotalPhys,
        available_bytes: status.ullAvailPhys,
        committed_bytes: info.CommitTotal as u64 * page,
        commit_limit_bytes: info.CommitLimit as u64 * page,
        paged_pool_bytes: info.KernelPaged as u64 * page,
        nonpaged_pool_bytes: info.KernelNonpaged as u64 * page,
        processes: info.ProcessCount,
        threads: info.ThreadCount,
        handles: info.HandleCount,
    })
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

const PROCESSOR_TIME: &str = r"\Processor Information(*)\% Processor Time";
const PERFORMANCE: &str = r"\Processor Information(_Total)\% Processor Performance";
const FREQUENCY: &str = r"\Processor Information(_Total)\Processor Frequency";
const MEMORY: [&str; 5] = [
    r"\Memory\Modified Page List Bytes",
    r"\Memory\Standby Cache Core Bytes",
    r"\Memory\Standby Cache Normal Priority Bytes",
    r"\Memory\Standby Cache Reserve Bytes",
    r"\Memory\Free & Zero Page List Bytes",
];

/// One PDH query holding the counters a run reads.
struct Pdh {
    query: *mut c_void,
    processors: Option<*mut c_void>,
    performance: Option<*mut c_void>,
    frequency: Option<*mut c_void>,
    memory: [Option<*mut c_void>; 5],
}

impl Pdh {
    fn open(series: &Series) -> Option<Self> {
        let mut query = null_mut();
        // SAFETY: a null source means live data; `query` is a valid out pointer.
        if unsafe { PdhOpenQueryW(null(), 0, &mut query) } != 0 {
            return None;
        }
        let add = |path: &str| {
            let path = wide(path);
            let mut counter = null_mut();
            // SAFETY: `path` is NUL-terminated; `counter` is a valid out pointer.
            (unsafe { PdhAddEnglishCounterW(query, path.as_ptr(), 0, &mut counter) } == 0)
                .then_some(counter)
        };
        let pdh = Pdh {
            query,
            processors: (series.cpu || series.per_processor)
                .then(|| add(PROCESSOR_TIME))
                .flatten(),
            performance: series.clock.then(|| add(PERFORMANCE)).flatten(),
            frequency: series.clock.then(|| add(FREQUENCY)).flatten(),
            memory: if series.memory {
                MEMORY.map(add)
            } else {
                [None; 5]
            },
        };
        // The rate counters need a first collection to compare against.
        // SAFETY: the query is open.
        unsafe { PdhCollectQueryData(query) };
        Some(pdh)
    }

    fn collect(&self) -> bool {
        // SAFETY: the query is open.
        unsafe { PdhCollectQueryData(self.query) == 0 }
    }

    fn value(counter: Option<*mut c_void>, format: u32) -> Option<f64> {
        let counter = counter?;
        // SAFETY: an all-zero value is valid.
        let mut out: PDH_FMT_COUNTERVALUE = unsafe { zeroed() };
        // SAFETY: the counter belongs to the open query; `out` is a valid out pointer.
        let status = unsafe {
            PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE | format, null_mut(), &mut out)
        };
        if status != 0 || out.CStatus > 1 {
            return None;
        }
        // SAFETY: a double was asked for.
        let v = unsafe { out.Anonymous.doubleValue };
        v.is_finite().then_some(v)
    }

    /// Every instance of the processor counter, "_Total" and the per-group totals apart.
    fn processors(&self) -> (Option<f64>, Vec<Option<f64>>) {
        let Some(counter) = self.processors else {
            return (None, Vec::new());
        };
        let (mut size, mut count) = (0u32, 0u32);
        // SAFETY: a size query with a null buffer.
        unsafe {
            PdhGetFormattedCounterArrayW(counter, PDH_FMT_DOUBLE, &mut size, &mut count, null_mut())
        };
        if size == 0 || size > 1 << 20 {
            return (None, Vec::new());
        }
        // u64 storage keeps the items aligned.
        let mut storage = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: the buffer holds `size` bytes, as asked.
        let status = unsafe {
            PdhGetFormattedCounterArrayW(
                counter,
                PDH_FMT_DOUBLE,
                &mut size,
                &mut count,
                storage.as_mut_ptr().cast::<PDH_FMT_COUNTERVALUE_ITEM_W>(),
            )
        };
        if status != 0 {
            return (None, Vec::new());
        }
        let count =
            (count as usize).min(storage.len() * 8 / size_of::<PDH_FMT_COUNTERVALUE_ITEM_W>());
        // SAFETY: PDH wrote `count` items at the start of the buffer.
        let items = unsafe {
            std::slice::from_raw_parts(
                storage.as_ptr().cast::<PDH_FMT_COUNTERVALUE_ITEM_W>(),
                count,
            )
        };
        let read: Vec<(String, u32, f64)> = items
            .iter()
            .filter(|item| !item.szName.is_null())
            .map(|item| {
                // SAFETY: PDH's names are NUL-terminated strings inside the same buffer, and a
                // double was asked for.
                unsafe {
                    (
                        pwstr(item.szName),
                        item.FmtValue.CStatus,
                        item.FmtValue.Anonymous.doubleValue,
                    )
                }
            })
            .collect();
        processor_values(&read)
    }
}

/// The total and each processor's value, in processor order, from (instance name, status,
/// value) items. An item whose status is not valid data keeps its place as None, so
/// processor N stays at index N.
pub fn processor_values(items: &[(String, u32, f64)]) -> (Option<f64>, Vec<Option<f64>>) {
    let mut total = None;
    let mut each: Vec<((u32, u32), Option<f64>)> = Vec::new();
    for (name, status, v) in items {
        // Status 0 is valid data and 1 valid new data; anything else is no reading.
        let v = (*status <= 1 && v.is_finite()).then(|| v.clamp(0.0, 100.0));
        if name == "_Total" {
            total = v;
        } else if let Some(key) = processor_key(name) {
            each.push((key, v));
        }
    }
    each.sort_by_key(|(key, _)| *key);
    (total, each.into_iter().map(|(_, v)| v).collect())
}

impl Drop for Pdh {
    fn drop(&mut self) {
        // SAFETY: opened in `open` and closed once.
        unsafe { PdhCloseQuery(self.query) };
    }
}

/// Reads a NUL-terminated wide string, at most 256 characters.
unsafe fn pwstr(p: *const u16) -> String {
    let mut len = 0;
    while len < 256 && *p.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

/// "0,3" to (group 0, processor 3); None for "_Total", "0,_Total" and anything else.
pub fn processor_key(name: &str) -> Option<(u32, u32)> {
    let (group, number) = name.split_once(',')?;
    Some((group.trim().parse().ok()?, number.trim().parse().ok()?))
}

/// The memory sample from the totals and the page-list counters.
pub fn memory_sample(status: &MemoryStatus, lists: [Option<f64>; 5]) -> MemorySample {
    let bytes = |v: Option<f64>| v.filter(|v| *v >= 0.0).map(|v| v as u64);
    let modified = bytes(lists[0]);
    let standby = match (bytes(lists[1]), bytes(lists[2]), bytes(lists[3])) {
        (Some(a), Some(b), Some(c)) => Some(a + b + c),
        _ => None,
    };
    let free = bytes(lists[4]);
    let in_use = match (modified, standby, free) {
        (Some(m), Some(s), Some(f)) => status.total_bytes.saturating_sub(m + s + f),
        _ => status.total_bytes.saturating_sub(status.available_bytes),
    };
    MemorySample {
        total_bytes: status.total_bytes,
        in_use_bytes: in_use,
        available_bytes: status.available_bytes,
        modified_bytes: modified,
        standby_bytes: standby,
        free_bytes: free,
        cached_bytes: match (standby, modified) {
            (Some(s), Some(m)) => Some(s + m),
            _ => None,
        },
        committed_bytes: status.committed_bytes,
        commit_limit_bytes: status.commit_limit_bytes,
        paged_pool_bytes: status.paged_pool_bytes,
        nonpaged_pool_bytes: status.nonpaged_pool_bytes,
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn take(pdh: Option<&Pdh>, series: &Series, index: u64, start: Instant) -> Sample {
    let collected = pdh.is_some_and(Pdh::collect);
    let pdh = pdh.filter(|_| collected);
    let (total, each) = pdh.map(Pdh::processors).unwrap_or_default();
    let clock = pdh.and_then(|p| {
        let performance = Pdh::value(p.performance, PDH_FMT_NOCAP100)?;
        let frequency = Pdh::value(p.frequency, 0)?;
        (frequency > 0.0).then_some(frequency * performance / 100.0)
    });
    let status = (series.memory || series.system)
        .then(memory_status)
        .flatten();
    let lists = pdh.map_or([None; 5], |p| p.memory.map(|c| Pdh::value(c, 0)));
    // SAFETY: no arguments.
    let uptime = unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() } / 1000;
    Sample {
        index,
        elapsed_ms: start.elapsed().as_millis() as u64,
        unix_ms: unix_ms(),
        cpu_percent: if series.cpu { total } else { None },
        per_processor_percent: if series.per_processor {
            each
        } else {
            Vec::new()
        },
        clock_mhz: clock,
        memory: series
            .memory
            .then(|| status.map(|s| memory_sample(&s, lists)))
            .flatten(),
        processes: series.system.then(|| status.map(|s| s.processes)).flatten(),
        threads: series.system.then(|| status.map(|s| s.threads)).flatten(),
        handles: series.system.then(|| status.map(|s| s.handles)).flatten(),
        uptime_s: series.system.then_some(uptime),
    }
}

/// Samples until `cancel` is set or `max_samples` is reached, sending each sample through
/// `on_event`. The first sample comes one interval after the start, since use is measured
/// over an interval. Waits are cut into 50 ms steps so a cancel ends the run within that.
pub fn run(
    options: &MonitorOptions,
    on_event: &mut dyn FnMut(Event),
    cancel: &AtomicBool,
) -> Result<Summary, String> {
    crate::live::reading("the performance counters");
    options.check()?;
    let series = options.series;
    let pdh = Pdh::open(&series);
    let mut unavailable = Vec::new();
    match &pdh {
        None => unavailable.push("performance counters: Windows did not open a query".into()),
        Some(p) => {
            if (series.cpu || series.per_processor) && p.processors.is_none() {
                unavailable.push("processor use: the counter is missing".into());
            }
            if series.clock && (p.performance.is_none() || p.frequency.is_none()) {
                unavailable.push("clock: the counter is missing".into());
            }
            if series.memory && p.memory.iter().any(Option::is_none) {
                unavailable.push("memory page lists: a counter is missing".into());
            }
        }
    }
    let base = pdh.as_ref().and_then(|p| {
        p.collect();
        Pdh::value(p.frequency, 0)
    });
    on_event(Event::Started {
        logical_processors: logical_processors(),
        base_mhz: base,
        unavailable,
    });
    let start = Instant::now();
    let interval = Duration::from_millis(u64::from(options.interval_ms));
    let mut totals = Totals::default();
    let mut index = 0u64;
    loop {
        let due = start + interval * (index as u32 + 1);
        while Instant::now() < due {
            if cancel.load(Ordering::Relaxed) {
                return Ok(totals.summary(Some(Ended::Cancelled)));
            }
            let left = due.saturating_duration_since(Instant::now());
            std::thread::sleep(left.min(Duration::from_millis(50)));
        }
        if cancel.load(Ordering::Relaxed) {
            return Ok(totals.summary(Some(Ended::Cancelled)));
        }
        let sample = take(pdh.as_ref(), &series, index, start);
        totals.add(&sample);
        on_event(Event::Sample(sample));
        index += 1;
        if options.max_samples.is_some_and(|max| index >= max) {
            return Ok(totals.summary(Some(Ended::Reached)));
        }
    }
}

// ---- history -----------------------------------------------------------------------------

/// The last `capacity` samples, oldest first; never holds more.
#[derive(Clone, Debug)]
pub struct History {
    capacity: usize,
    samples: VecDeque<Sample>,
}

impl History {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            samples: VecDeque::with_capacity(capacity),
        }
    }

    pub fn push(&mut self, sample: Sample) {
        while self.samples.len() >= self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn last(&self) -> Option<&Sample> {
        self.samples.back()
    }

    /// The newest `n` samples, oldest first.
    pub fn newest(&self, n: usize) -> impl Iterator<Item = &Sample> {
        self.samples
            .iter()
            .skip(self.samples.len().saturating_sub(n))
    }

    /// Minimum, average and maximum of `value` over the newest `n` samples.
    pub fn stat(&self, n: usize, value: impl Fn(&Sample) -> Option<f64>) -> Option<Stat> {
        let mut acc = Acc::default();
        for s in self.newest(n) {
            if let Some(v) = value(s) {
                acc.add(v);
            }
        }
        acc.stat()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(index: u64, cpu: f64) -> Sample {
        Sample {
            index,
            elapsed_ms: (index + 1) * 1000,
            cpu_percent: Some(cpu),
            per_processor_percent: vec![Some(cpu), Some(100.0 - cpu)],
            ..Sample::default()
        }
    }

    #[test]
    fn a_history_never_grows_past_its_capacity() {
        let mut h = History::new(HISTORY);
        // Ten hours at one a second.
        for i in 0..36_000 {
            h.push(sample(i, (i % 100) as f64));
        }
        assert_eq!(h.len(), HISTORY);
        assert!(h.samples.capacity() < HISTORY * 2);
        assert_eq!(h.last().unwrap().index, 35_999);
        assert_eq!(h.newest(60).next().unwrap().index, 35_940);
        assert_eq!(h.newest(60).count(), 60);
        assert_eq!(h.newest(100_000).count(), HISTORY);
        let s = h.stat(100, |s| s.cpu_percent).unwrap();
        assert_eq!((s.min, s.max, s.count), (0.0, 99.0, 100));
        assert_eq!(History::new(0).capacity(), 1);
    }

    #[test]
    fn totals_give_minimum_average_and_maximum_per_series() {
        let mut t = Totals::default();
        for (i, v) in [10.0, 30.0, 20.0, f64::NAN].into_iter().enumerate() {
            t.add(&sample(i as u64, v));
        }
        let s = t.summary(Some(Ended::Reached));
        assert_eq!(s.samples, 4);
        let cpu = s.cpu_percent.unwrap();
        assert_eq!(
            (cpu.min, cpu.avg, cpu.max, cpu.count),
            (10.0, 20.0, 30.0, 3)
        );
        assert_eq!(s.per_processor_percent.len(), 2);
        assert_eq!(s.per_processor_percent[1].unwrap().max, 90.0);
        assert_eq!(s.memory_in_use_bytes, None);
    }

    #[test]
    fn options_out_of_bounds_are_refused() {
        let mut o = MonitorOptions::default();
        assert!(o.check().is_ok());
        o.interval_ms = 100;
        assert!(o.check().is_err());
        o.interval_ms = 20_000;
        assert!(o.check().is_err());
        o.interval_ms = 1000;
        o.max_samples = Some(0);
        assert!(o.check().is_err());
    }

    #[test]
    fn processor_names_sort_by_group_then_number() {
        assert_eq!(processor_key("0,12"), Some((0, 12)));
        assert_eq!(processor_key("1,0"), Some((1, 0)));
        assert_eq!(processor_key("0,_Total"), None);
        assert_eq!(processor_key("_Total"), None);
    }

    #[test]
    fn a_processor_without_a_valid_reading_keeps_its_place() {
        let item = |name: &str, status: u32, v: f64| (name.to_string(), status, v);
        let (total, each) = processor_values(&[
            item("0,1", 0, 20.0),
            item("_Total", 0, 15.0),
            item("0,_Total", 0, 15.0),
            item("0,2", 0xC000_0BC6, 0.0),
            item("0,0", 1, 140.0),
        ]);
        assert_eq!(total, Some(15.0));
        assert_eq!(each, vec![Some(100.0), Some(20.0), None]);
    }

    #[test]
    fn in_use_is_what_the_page_lists_leave() {
        let status = MemoryStatus {
            total_bytes: 100,
            available_bytes: 60,
            ..MemoryStatus::default()
        };
        let m = memory_sample(
            &status,
            [Some(5.0), Some(10.0), Some(20.0), Some(5.0), Some(25.0)],
        );
        assert_eq!(m.in_use_bytes, 35);
        assert_eq!((m.standby_bytes, m.cached_bytes), (Some(35), Some(40)));
        // Without the lists, in use is total less available.
        let m = memory_sample(&status, [None; 5]);
        assert_eq!((m.in_use_bytes, m.cached_bytes), (40, None));
    }

    #[test]
    fn a_run_on_this_pc_sends_samples_and_sums_them_up() {
        let options = MonitorOptions {
            interval_ms: 250,
            series: Series::ALL,
            max_samples: Some(3),
        };
        let mut events = Vec::new();
        let summary = run(&options, &mut |e| events.push(e), &AtomicBool::new(false)).unwrap();
        assert_eq!(summary.samples, 3);
        assert_eq!(summary.ended, Some(Ended::Reached));
        assert!(matches!(events[0], Event::Started { .. }));
        let Event::Sample(s) = &events[3] else {
            panic!("no sample last")
        };
        assert_eq!(
            s.per_processor_percent.len(),
            logical_processors() as usize,
            "{events:?}"
        );
        let m = s.memory.unwrap();
        assert!(m.in_use_bytes > 0 && m.in_use_bytes < m.total_bytes);
        assert!(s.processes.unwrap() > 10);
        let json = serde_json::to_string(s).unwrap();
        assert!(json.contains("\"cpu_percent\""));
        // A cancel ends a run that would otherwise not end.
        let cancel = AtomicBool::new(true);
        let o = MonitorOptions::default();
        let summary = run(&o, &mut |_| {}, &cancel).unwrap();
        assert_eq!(
            (summary.samples, summary.ended),
            (0, Some(Ended::Cancelled))
        );
    }
}
