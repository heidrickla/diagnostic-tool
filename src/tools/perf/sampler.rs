//! Win32 readings: processes, system times, memory and the PDH disk counters.
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Performance::{
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterValue,
    PdhOpenQueryW, PDH_FMT_COUNTERVALUE, PDH_FMT_DOUBLE,
};
use windows_sys::Win32::System::ProcessStatus::{
    GetPerformanceInfo, GetProcessMemoryInfo, PERFORMANCE_INFORMATION, PROCESS_MEMORY_COUNTERS,
    PROCESS_MEMORY_COUNTERS_EX,
};
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows_sys::Win32::System::Threading::{
    GetActiveProcessorCount, GetCurrentProcessId, GetCurrentThread, GetProcessIoCounters,
    GetProcessTimes, GetSystemTimes, OpenProcess, SetThreadPriority, IO_COUNTERS,
    PROCESS_QUERY_LIMITED_INFORMATION, THREAD_MODE_BACKGROUND_BEGIN, THREAD_MODE_BACKGROUND_END,
};

pub(super) struct Proc {
    /// Process id and creation time, so a reused id is a different process.
    pub key: (u32, u64),
    pub name: String,
    /// Kernel plus user time in 100 ns units.
    pub cpu: u64,
    /// Bytes read plus written (transfer counts, all devices).
    pub io: u64,
    pub private: u64,
    pub working_set: u64,
}

#[derive(Clone, Copy, Default)]
pub(super) struct MemReading {
    pub load: u32,
    pub avail: u64,
    pub total: u64,
    pub commit_used: u64,
    pub commit_limit: u64,
}

#[derive(Clone, Copy, Default)]
pub(super) struct DiskReading {
    pub idle_pct: Option<f64>,
    pub latency_secs: Option<f64>,
    pub queue: Option<f64>,
    pub bytes_per_sec: Option<f64>,
    pub page_reads_per_sec: Option<f64>,
}

pub(super) struct Sample {
    /// Seconds since the first reading.
    pub at: f64,
    /// Idle, kernel (includes idle) and user time in 100 ns units.
    pub times: (u64, u64, u64),
    pub mem: MemReading,
    pub disk: Option<DiskReading>,
    pub procs: Vec<Proc>,
    pub unopened: usize,
}

pub(super) fn logical_processors() -> u32 {
    // SAFETY: a plain query with no pointers; 0xFFFF means all processor groups.
    unsafe { GetActiveProcessorCount(0xFFFF) }.max(1)
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

fn ticks(time: FILETIME) -> u64 {
    (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
}

const COUNTER_PATHS: [&str; 5] = [
    r"\PhysicalDisk(_Total)\% Idle Time",
    r"\PhysicalDisk(_Total)\Avg. Disk sec/Transfer",
    r"\PhysicalDisk(_Total)\Current Disk Queue Length",
    r"\PhysicalDisk(_Total)\Disk Bytes/sec",
    r"\Memory\Page Reads/sec",
];

struct Pdh {
    query: *mut c_void,
    counters: [Option<*mut c_void>; 5],
}

impl Pdh {
    fn open() -> Option<Self> {
        let mut query: *mut c_void = null_mut();
        // SAFETY: a null source means live data; `query` is a valid out pointer.
        if unsafe { PdhOpenQueryW(null(), 0, &mut query) } != 0 {
            return None;
        }
        let mut pdh = Pdh {
            query,
            counters: [None; 5],
        };
        for (slot, path) in pdh.counters.iter_mut().zip(COUNTER_PATHS) {
            let path = wide(path);
            let mut counter: *mut c_void = null_mut();
            // SAFETY: `path` is NUL-terminated and `counter` a valid out pointer.
            if unsafe { PdhAddEnglishCounterW(query, path.as_ptr(), 0, &mut counter) } == 0 {
                *slot = Some(counter);
            }
        }
        if pdh.counters.iter().all(Option::is_none) {
            return None;
        }
        // The rate counters need a first collection to compare against.
        // SAFETY: `query` is open.
        unsafe { PdhCollectQueryData(query) };
        Some(pdh)
    }

    fn read(&self) -> Option<DiskReading> {
        // SAFETY: `self.query` is open.
        if unsafe { PdhCollectQueryData(self.query) } != 0 {
            return None;
        }
        let value = |index: usize| -> Option<f64> {
            let counter = self.counters[index]?;
            // SAFETY: an all-zero PDH_FMT_COUNTERVALUE is a valid out value.
            let mut out: PDH_FMT_COUNTERVALUE = unsafe { zeroed() };
            // SAFETY: `counter` belongs to the open query; `out` is a valid out pointer.
            let status = unsafe {
                PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, null_mut(), &mut out)
            };
            // CStatus 0 is valid data, 1 is valid new data.
            if status != 0 || out.CStatus > 1 {
                return None;
            }
            // SAFETY: PDH_FMT_DOUBLE was requested, so the double member is the one set.
            let v = unsafe { out.Anonymous.doubleValue };
            v.is_finite().then_some(v)
        };
        Some(DiskReading {
            idle_pct: value(0),
            latency_secs: value(1),
            queue: value(2),
            bytes_per_sec: value(3),
            page_reads_per_sec: value(4),
        })
    }
}

impl Drop for Pdh {
    fn drop(&mut self) {
        // SAFETY: the query was opened by `open` and is closed once.
        unsafe { PdhCloseQuery(self.query) };
    }
}

fn read_system_times() -> (u64, u64, u64) {
    // SAFETY: FILETIME is plain integers; zero is valid.
    let (mut idle, mut kernel, mut user): (FILETIME, FILETIME, FILETIME) =
        unsafe { (zeroed(), zeroed(), zeroed()) };
    // SAFETY: three valid out pointers.
    unsafe { GetSystemTimes(&mut idle, &mut kernel, &mut user) };
    (ticks(idle), ticks(kernel), ticks(user))
}

fn read_memory() -> MemReading {
    // SAFETY: MEMORYSTATUSEX is plain integers; dwLength is set before the call.
    let mut status: MEMORYSTATUSEX = unsafe { zeroed() };
    status.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
    // SAFETY: `status` is a valid out pointer with its length set.
    let ok = unsafe { GlobalMemoryStatusEx(&mut status) } != 0;
    // SAFETY: PERFORMANCE_INFORMATION is plain integers; cb is set before the call.
    let mut info: PERFORMANCE_INFORMATION = unsafe { zeroed() };
    info.cb = size_of::<PERFORMANCE_INFORMATION>() as u32;
    // SAFETY: `info` is a valid out pointer with its size given.
    let have_info = unsafe { GetPerformanceInfo(&mut info, info.cb) } != 0;
    let page = info.PageSize as u64;
    MemReading {
        load: if ok { status.dwMemoryLoad } else { 0 },
        avail: if ok { status.ullAvailPhys } else { 0 },
        total: if ok { status.ullTotalPhys } else { 0 },
        commit_used: if have_info {
            info.CommitTotal as u64 * page
        } else {
            0
        },
        commit_limit: if have_info {
            info.CommitLimit as u64 * page
        } else {
            0
        },
    }
}

/// Reads one process; None when it cannot be opened or its times cannot be read.
fn read_process(pid: u32, name: String) -> Option<Proc> {
    // SAFETY: a query-only open; the handle is closed below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    // SAFETY: FILETIME is plain integers; zero is valid.
    let (mut created, mut exited, mut kernel, mut user): (FILETIME, FILETIME, FILETIME, FILETIME) =
        unsafe { (zeroed(), zeroed(), zeroed(), zeroed()) };
    // SAFETY: `handle` is open; four valid out pointers.
    let times_ok =
        unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) } != 0;
    // SAFETY: IO_COUNTERS is plain integers; zero is valid.
    let mut io: IO_COUNTERS = unsafe { zeroed() };
    // SAFETY: `handle` is open and `io` a valid out pointer.
    let io_ok = unsafe { GetProcessIoCounters(handle, &mut io) } != 0;
    // SAFETY: PROCESS_MEMORY_COUNTERS_EX is plain integers; cb is set before the call.
    let mut mem: PROCESS_MEMORY_COUNTERS_EX = unsafe { zeroed() };
    mem.cb = size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
    // SAFETY: the EX struct begins with PROCESS_MEMORY_COUNTERS and `cb` gives its size.
    let mem_ok = unsafe {
        GetProcessMemoryInfo(
            handle,
            (&mut mem as *mut PROCESS_MEMORY_COUNTERS_EX).cast::<PROCESS_MEMORY_COUNTERS>(),
            mem.cb,
        )
    } != 0;
    // SAFETY: `handle` was opened above and is closed once.
    unsafe { CloseHandle(handle) };
    if !times_ok {
        return None;
    }
    Some(Proc {
        key: (pid, ticks(created)),
        name,
        cpu: ticks(kernel) + ticks(user),
        io: if io_ok {
            io.ReadTransferCount.saturating_add(io.WriteTransferCount)
        } else {
            0
        },
        private: if mem_ok { mem.PrivateUsage as u64 } else { 0 },
        working_set: if mem_ok { mem.WorkingSetSize as u64 } else { 0 },
    })
}

/// Names and ids from a ToolHelp snapshot; empty when the snapshot cannot be taken.
fn process_list() -> Vec<(u32, String)> {
    // SAFETY: a snapshot handle, closed below.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Vec::new();
    }
    let mut list = Vec::new();
    // SAFETY: PROCESSENTRY32W is plain integers; dwSize is set before use.
    let mut entry: PROCESSENTRY32W = unsafe { zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    // SAFETY: `snapshot` is open and `entry` has its size set.
    let mut more = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while more {
        let len = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        list.push((
            entry.th32ProcessID,
            String::from_utf16_lossy(&entry.szExeFile[..len]),
        ));
        // SAFETY: as for Process32FirstW.
        more = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    // SAFETY: `snapshot` was opened above and is closed once.
    unsafe { CloseHandle(snapshot) };
    list
}

fn take(start: Instant, pdh: Option<&Pdh>, own_pid: u32) -> Sample {
    let mut procs = Vec::new();
    let mut unopened = 0;
    for (pid, name) in process_list() {
        // The idle process is not a real process, and this tool leaves itself out.
        if pid == 0 || pid == own_pid {
            continue;
        }
        match read_process(pid, name) {
            Some(proc) => procs.push(proc),
            None => unopened += 1,
        }
    }
    Sample {
        at: start.elapsed().as_secs_f64(),
        times: read_system_times(),
        mem: read_memory(),
        disk: pdh.and_then(Pdh::read),
        procs,
        unopened,
    }
}

/// Takes a reading now and then once a second for `seconds`, on a background-priority thread.
pub(super) fn collect(seconds: u64) -> Result<Vec<Sample>, String> {
    std::thread::spawn(move || {
        // SAFETY: affects only this thread; the mode is ended before it returns.
        let background =
            unsafe { SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN) } != 0;
        // SAFETY: no arguments.
        let own_pid = unsafe { GetCurrentProcessId() };
        let pdh = Pdh::open();
        let start = Instant::now();
        let mut samples = Vec::new();
        for tick in 0..=seconds {
            samples.push(take(start, pdh.as_ref(), own_pid));
            if tick < seconds {
                let due = start + Duration::from_secs(tick + 1);
                std::thread::sleep(due.saturating_duration_since(Instant::now()));
            }
        }
        drop(pdh);
        if background {
            // SAFETY: ends the mode begun above on this thread.
            unsafe { SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_END) };
        }
        samples
    })
    .join()
    .map_err(|_| "the sampling thread failed".to_string())
}
